-- 区分可交互登录用户与仅允许通过 API Key 网关调用的可信池席位主体。
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS principal_type VARCHAR(32) NOT NULL DEFAULT 'human';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_principal_type_check;

ALTER TABLE users
    ADD CONSTRAINT users_principal_type_check
    CHECK (principal_type IN ('human', 'trusted_pool_seat'));

CREATE INDEX IF NOT EXISTS idx_users_principal_type
    ON users (principal_type);

-- 服务层入口之外再做数据库兜底：Seat 可保留历史身份用于审计，但不能新增或更新登录身份。
CREATE OR REPLACE FUNCTION enforce_interactive_auth_identity_principal()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE id = NEW.user_id
          AND deleted_at IS NULL
          AND principal_type = 'human'
    ) THEN
        RAISE EXCEPTION 'auth identity requires a human principal'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_identities_human_principal ON auth_identities;
CREATE TRIGGER trg_auth_identities_human_principal
    BEFORE INSERT OR UPDATE ON auth_identities
    FOR EACH ROW
    EXECUTE FUNCTION enforce_interactive_auth_identity_principal();
