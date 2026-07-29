CREATE TABLE redeem_codes (
  id UUID PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  code_mask TEXT NOT NULL,
  benefit_type TEXT NOT NULL CHECK (benefit_type IN ('balance', 'subscription')),
  value_micros BIGINT NOT NULL CHECK (value_micros > 0),
  group_id BIGINT,
  validity_days INTEGER,
  status TEXT NOT NULL DEFAULT 'unused'
    CHECK (status IN ('unused', 'processing', 'redeemed', 'failed', 'disabled')),
  campaign TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  claimed_by_user_id BIGINT,
  expires_at TIMESTAMPTZ,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  redeemed_at TIMESTAMPTZ,
  CHECK (
    (benefit_type = 'balance' AND group_id IS NULL AND validity_days IS NULL)
    OR
    (benefit_type = 'subscription' AND group_id > 0 AND validity_days > 0)
  )
);

CREATE TABLE redemptions (
  id UUID PRIMARY KEY,
  code_id UUID NOT NULL UNIQUE REFERENCES redeem_codes(id),
  user_id BIGINT NOT NULL,
  user_email TEXT NOT NULL DEFAULT '',
  benefit_type TEXT NOT NULL CHECK (benefit_type IN ('balance', 'subscription')),
  value_micros BIGINT NOT NULL,
  group_id BIGINT,
  validity_days INTEGER,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'retryable', 'succeeded', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT NOT NULL UNIQUE,
  upstream_code TEXT NOT NULL UNIQUE,
  upstream_http_status INTEGER,
  upstream_reason TEXT NOT NULL DEFAULT '',
  upstream_response JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_error TEXT NOT NULL DEFAULT '',
  retryable BOOLEAN NOT NULL DEFAULT TRUE,
  next_retry_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE redemption_attempts (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  redemption_id UUID NOT NULL REFERENCES redemptions(id),
  attempt_no INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'succeeded', 'failed')),
  http_status INTEGER,
  reason TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER,
  error_message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  UNIQUE (redemption_id, attempt_no)
);

CREATE TABLE audit_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_codes_status_created
  ON redeem_codes(status, created_at DESC);
CREATE INDEX idx_codes_campaign_created
  ON redeem_codes(campaign, created_at DESC);
CREATE INDEX idx_redemptions_status_retry
  ON redemptions(status, next_retry_at);
CREATE INDEX idx_redemptions_user_created
  ON redemptions(user_id, created_at DESC);
CREATE INDEX idx_redemptions_created
  ON redemptions(created_at DESC);
CREATE INDEX idx_attempts_redemption
  ON redemption_attempts(redemption_id, attempt_no DESC);
CREATE INDEX idx_audit_created
  ON audit_events(created_at DESC);
