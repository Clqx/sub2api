-- Phase2-D: 人工解除结算屏障必须绑定最初 pending 的 epoch 与 request_id。
ALTER TABLE trusted_pool_settlement_resolutions
    ADD COLUMN IF NOT EXISTS expected_assignment_epoch BIGINT,
    ADD COLUMN IF NOT EXISTS expected_request_id VARCHAR(128);

ALTER TABLE trusted_pool_settlement_resolutions
    DROP CONSTRAINT IF EXISTS ck_trusted_pool_resolution_expected_binding;
ALTER TABLE trusted_pool_settlement_resolutions
    ADD CONSTRAINT ck_trusted_pool_resolution_expected_binding CHECK (
        (expected_assignment_epoch IS NULL AND expected_request_id IS NULL) OR
        (expected_assignment_epoch > 0 AND
         length(trim(expected_request_id)) BETWEEN 1 AND 128)
    );

-- 历史审计无法从已删除的 pending 可靠回填，保留 NULL 只读；所有新审计必须带完整绑定。
CREATE OR REPLACE FUNCTION require_trusted_pool_resolution_binding()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.expected_assignment_epoch IS NULL OR NEW.expected_assignment_epoch <= 0 OR
       NEW.expected_request_id IS NULL OR length(trim(NEW.expected_request_id)) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'trusted pool settlement resolution requires expected epoch and request id'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_resolution_require_binding
    ON trusted_pool_settlement_resolutions;
CREATE TRIGGER trg_trusted_pool_resolution_require_binding
    BEFORE INSERT ON trusted_pool_settlement_resolutions
    FOR EACH ROW EXECUTE FUNCTION require_trusted_pool_resolution_binding();

COMMENT ON COLUMN trusted_pool_settlement_resolutions.expected_assignment_epoch IS
    '人工核账时看到的 pending assignment epoch；删除屏障时必须精确匹配';
COMMENT ON COLUMN trusted_pool_settlement_resolutions.expected_request_id IS
    '人工核账时看到的 pending request_id；删除屏障时必须精确匹配';

-- settlement:resolve 必须使用只含该 scope 的独立活动身份，避免普通集成密钥越权。
UPDATE trusted_pool_integration_clients
SET status = 'disabled', updated_at = NOW()
WHERE status = 'active'
  AND 'settlement:resolve' = ANY(scopes)
  AND NOT (cardinality(scopes) = 1 AND scopes[1] = 'settlement:resolve');

ALTER TABLE trusted_pool_integration_clients
    DROP CONSTRAINT IF EXISTS ck_trusted_pool_resolve_scope_isolation;
ALTER TABLE trusted_pool_integration_clients
    ADD CONSTRAINT ck_trusted_pool_resolve_scope_isolation CHECK (
        status <> 'active' OR
        NOT ('settlement:resolve' = ANY(scopes)) OR
        (cardinality(scopes) = 1 AND scopes[1] = 'settlement:resolve')
    );
