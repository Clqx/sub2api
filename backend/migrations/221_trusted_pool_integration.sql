-- 可信池窄集成层：独立调用方凭据、防重放 nonce 与稳定 Seat 绑定。
CREATE TABLE IF NOT EXISTS trusted_pool_integration_clients (
    id              BIGSERIAL PRIMARY KEY,
    client_id       VARCHAR(64) NOT NULL UNIQUE,
    secret_hash     CHAR(64) NOT NULL CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    scopes          TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    status          VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trusted_pool_integration_nonces (
    client_id       VARCHAR(64) NOT NULL REFERENCES trusted_pool_integration_clients(client_id) ON DELETE CASCADE,
    nonce           VARCHAR(128) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_nonces_expires_at
    ON trusted_pool_integration_nonces (expires_at);

-- 一个外部 Pool 独占一个 Sub2API Group；同一 Group 也不能被两个 Pool 共享。
CREATE TABLE IF NOT EXISTS trusted_pool_groups (
    external_pool_id    VARCHAR(128) PRIMARY KEY,
    group_id            BIGINT NOT NULL UNIQUE REFERENCES groups(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (external_pool_id, group_id)
);

CREATE TABLE IF NOT EXISTS trusted_pool_seats (
    id                  BIGSERIAL PRIMARY KEY,
    external_pool_id    VARCHAR(128) NOT NULL,
    external_seat_id    VARCHAR(128) NOT NULL UNIQUE,
    principal_user_id   BIGINT NOT NULL UNIQUE REFERENCES users(id),
    group_id            BIGINT NOT NULL REFERENCES groups(id),
    subscription_id     BIGINT NOT NULL UNIQUE REFERENCES user_subscriptions(id),
    api_key_id          BIGINT NOT NULL UNIQUE REFERENCES api_keys(id),
    state               VARCHAR(20) NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active', 'draining', 'frozen', 'rotating')),
    assignment_epoch    BIGINT NOT NULL DEFAULT 1 CHECK (assignment_epoch > 0),
    last_operation_id   VARCHAR(128) NOT NULL,
    suspended_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (external_pool_id, group_id)
        REFERENCES trusted_pool_groups(external_pool_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_seats_pool_id
    ON trusted_pool_seats (external_pool_id);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_seats_state
    ON trusted_pool_seats (state);

-- 每个命令独立保存 epoch，避免 last_operation_id 被后续 rotate 覆盖后，旧 suspend 重放误伤新 Key。
CREATE TABLE IF NOT EXISTS trusted_pool_operations (
    seat_id             BIGINT NOT NULL REFERENCES trusted_pool_seats(id) ON DELETE CASCADE,
    operation_type      VARCHAR(20) NOT NULL CHECK (operation_type IN ('suspend', 'freeze', 'rotate')),
    operation_id        VARCHAR(128) NOT NULL,
    assignment_epoch    BIGINT NOT NULL CHECK (assignment_epoch > 0),
    result_state        VARCHAR(20) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (seat_id, operation_type, operation_id)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_operations_created_at
    ON trusted_pool_operations (created_at);

-- 网关请求必须先持久化 pending，只有同步计费成功后才能删除；遗留行会持续阻断冻结。
CREATE TABLE IF NOT EXISTS trusted_pool_pending_settlements (
    seat_id             BIGINT NOT NULL REFERENCES trusted_pool_seats(id) ON DELETE CASCADE,
    settlement_id       VARCHAR(128) NOT NULL,
    request_id          VARCHAR(128) NOT NULL,
    billing_id          VARCHAR(128),
    assignment_epoch    BIGINT NOT NULL CHECK (assignment_epoch > 0),
    status              VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'failed')),
    last_error          TEXT,
    attempt_count       INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (seat_id, settlement_id)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_pending_settlements_seat_epoch
    ON trusted_pool_pending_settlements (seat_id, assignment_epoch, created_at);

-- 人工对账必须留下不可变证据，并以 operation_id 提供幂等重试。
CREATE TABLE IF NOT EXISTS trusted_pool_settlement_resolutions (
    id                  BIGSERIAL PRIMARY KEY,
    seat_id             BIGINT NOT NULL REFERENCES trusted_pool_seats(id),
    settlement_id       VARCHAR(128) NOT NULL,
    operation_id        VARCHAR(128) NOT NULL,
    actor_client_id     VARCHAR(64) NOT NULL,
    reason              VARCHAR(1000) NOT NULL,
    evidence            VARCHAR(4000) NOT NULL,
    resolved_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (seat_id, operation_id),
    UNIQUE (seat_id, settlement_id)
);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_settlement_resolutions_resolved_at
    ON trusted_pool_settlement_resolutions (resolved_at);

CREATE OR REPLACE FUNCTION reject_trusted_pool_resolution_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'trusted_pool_settlement_resolutions is append-only'
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_resolution_immutable
    ON trusted_pool_settlement_resolutions;
CREATE TRIGGER trg_trusted_pool_resolution_immutable
    BEFORE UPDATE OR DELETE ON trusted_pool_settlement_resolutions
    FOR EACH ROW EXECUTE FUNCTION reject_trusted_pool_resolution_mutation();

COMMENT ON COLUMN trusted_pool_integration_clients.secret_hash IS
    'SHA-256(raw secret) hex；HMAC 模式以解码后的摘要作为签名密钥';
COMMENT ON TABLE trusted_pool_seats IS
    '可信池外部 Seat 与 Sub2API 稳定 principal/subscription/API key 的绑定';
COMMENT ON TABLE trusted_pool_operations IS
    '可信池命令幂等历史；旧 epoch 命令只能返回冲突，禁止修改当前 Seat';
COMMENT ON TABLE trusted_pool_pending_settlements IS
    '可信池请求持久结算屏障；计费失败或完成删除失败时保留并阻断 drain/freeze';
COMMENT ON TABLE trusted_pool_settlement_resolutions IS
    '可信池 pending 人工对账审计；理由、证据、调用方与幂等操作永久保留';
