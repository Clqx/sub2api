-- 登录验证码 IP 风控记录。
-- 聚合同一安全客户端 IP 的 Turnstile 失败，支持自动临时封禁和管理员解除封禁。
CREATE TABLE IF NOT EXISTS login_captcha_ip_records (
    id BIGSERIAL PRIMARY KEY,
    client_ip VARCHAR(64) NOT NULL UNIQUE,
    failure_count INT NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    total_failures BIGINT NOT NULL DEFAULT 0 CHECK (total_failures >= 0),
    block_count INT NOT NULL DEFAULT 0 CHECK (block_count >= 0),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ,
    blocked_until TIMESTAMPTZ,
    last_user_agent VARCHAR(512) NOT NULL DEFAULT '',
    resolved_at TIMESTAMPTZ,
    resolved_by_user_id BIGINT,
    resolution_note VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_captcha_ip_records_last_failed
    ON login_captcha_ip_records (last_failed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_login_captcha_ip_records_blocked_until
    ON login_captcha_ip_records (blocked_until)
    WHERE blocked_until IS NOT NULL;
