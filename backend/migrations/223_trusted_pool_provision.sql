-- 可信池 Seat 原子开通幂等历史。
-- 同一集成客户端内 operation_id 唯一；请求摘要固定后不得复用于其他资源或额度。
CREATE TABLE IF NOT EXISTS trusted_pool_provision_operations (
    client_id          VARCHAR(64) NOT NULL REFERENCES trusted_pool_integration_clients(client_id),
    operation_id       VARCHAR(128) NOT NULL,
    external_pool_id   VARCHAR(128) NOT NULL,
    external_seat_id   VARCHAR(128) NOT NULL,
    request_hash       CHAR(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    credential_fingerprint CHAR(64) NOT NULL CHECK (credential_fingerprint ~ '^[0-9a-f]{64}$'),
    seat_id            BIGINT REFERENCES trusted_pool_seats(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ,
    PRIMARY KEY (client_id, operation_id),
    UNIQUE (client_id, operation_id, seat_id),
    CHECK ((seat_id IS NULL) = (completed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_trusted_pool_provision_operations_seat
    ON trusted_pool_provision_operations (seat_id);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_provision_operations_external_seat
    ON trusted_pool_provision_operations (external_seat_id);

COMMENT ON TABLE trusted_pool_provision_operations IS
    '可信池 Seat 原子开通幂等历史；精确重放返回原 Seat 与访问凭据，请求漂移必须冲突';

CREATE OR REPLACE FUNCTION guard_trusted_pool_provision_operation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'trusted_pool_provision_operations is immutable after completion'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.seat_id IS NOT NULL
       OR NEW.client_id <> OLD.client_id
       OR NEW.operation_id <> OLD.operation_id
       OR NEW.external_pool_id <> OLD.external_pool_id
       OR NEW.external_seat_id <> OLD.external_seat_id
       OR NEW.request_hash <> OLD.request_hash
       OR NEW.credential_fingerprint <> OLD.credential_fingerprint
       OR NEW.seat_id IS NULL OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'trusted_pool_provision_operations is immutable after completion'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_provision_operation_guard
    ON trusted_pool_provision_operations;
CREATE TRIGGER trg_trusted_pool_provision_operation_guard
    BEFORE UPDATE OR DELETE ON trusted_pool_provision_operations
    FOR EACH ROW EXECUTE FUNCTION guard_trusted_pool_provision_operation();

-- Ack 是 at-most-once 交付边界；Sub2API 不推断平台采用内存还是持久密文存储。
-- 确认后不再返回 credential，调用方若丢失本地副本或在确认响应后重启，将无法从 provision 恢复明文。
-- 领取确认独立追加且不可变，避免放宽 provision operation 的幂等历史约束。
CREATE TABLE IF NOT EXISTS trusted_pool_provision_credential_claims (
    client_id               VARCHAR(64) NOT NULL,
    provision_operation_id  VARCHAR(128) NOT NULL,
    seat_id                 BIGINT NOT NULL,
    claim_operation_id      VARCHAR(128) NOT NULL,
    claimed_by              VARCHAR(128) NOT NULL,
    credential_fingerprint  CHAR(64) NOT NULL CHECK (credential_fingerprint ~ '^[0-9a-f]{64}$'),
    claimed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, provision_operation_id),
    UNIQUE (client_id, claim_operation_id),
    FOREIGN KEY (client_id, provision_operation_id, seat_id)
        REFERENCES trusted_pool_provision_operations(client_id, operation_id, seat_id)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_provision_claims_seat
    ON trusted_pool_provision_credential_claims (seat_id);

CREATE OR REPLACE FUNCTION reject_trusted_pool_provision_claim_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'trusted_pool_provision_credential_claims is append-only'
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_provision_claim_immutable
    ON trusted_pool_provision_credential_claims;
CREATE TRIGGER trg_trusted_pool_provision_claim_immutable
    BEFORE UPDATE OR DELETE ON trusted_pool_provision_credential_claims
    FOR EACH ROW EXECUTE FUNCTION reject_trusted_pool_provision_claim_mutation();

COMMENT ON TABLE trusted_pool_provision_credential_claims IS
    '可信池 provision credential 一次性领取确认；确认后 provision 重放不得再次返回凭据';

-- Group 一旦绑定可信池，只能接受 trusted_pool_seat Principal 的订阅和 API Key。
-- BEFORE trigger 与 provision 对 Group 的 FOR UPDATE 锁共同闭合首次绑定时的并发写入窗口。
CREATE OR REPLACE FUNCTION enforce_trusted_pool_group_principal()
RETURNS TRIGGER AS $$
DECLARE
    bound_to_pool BOOLEAN;
    owner_principal_type VARCHAR(32);
BEGIN
    IF NEW.group_id IS NULL THEN
        RETURN NEW;
    END IF;
    -- 与 provision 的 SELECT ... FOR UPDATE 互锁：普通资源先写时，provision 醒来后
    -- 能在隔离复查中看到它；provision 先绑定时，本事务醒来后能看到 Pool binding。
    PERFORM 1 FROM groups WHERE id=NEW.group_id FOR SHARE;
    SELECT EXISTS (
        SELECT 1 FROM trusted_pool_groups WHERE group_id=NEW.group_id
    ) INTO bound_to_pool;
    IF NOT bound_to_pool THEN
        RETURN NEW;
    END IF;
    SELECT principal_type INTO owner_principal_type FROM users WHERE id=NEW.user_id;
    IF owner_principal_type IS DISTINCT FROM 'trusted_pool_seat' THEN
        RAISE EXCEPTION 'trusted pool group only accepts trusted pool seat principals'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_subscription_principal ON user_subscriptions;
CREATE TRIGGER trg_trusted_pool_subscription_principal
    BEFORE INSERT OR UPDATE OF user_id, group_id, deleted_at ON user_subscriptions
    FOR EACH ROW EXECUTE FUNCTION enforce_trusted_pool_group_principal();

DROP TRIGGER IF EXISTS trg_trusted_pool_api_key_principal ON api_keys;
CREATE TRIGGER trg_trusted_pool_api_key_principal
    BEFORE INSERT OR UPDATE OF user_id, group_id, deleted_at ON api_keys
    FOR EACH ROW EXECUTE FUNCTION enforce_trusted_pool_group_principal();
