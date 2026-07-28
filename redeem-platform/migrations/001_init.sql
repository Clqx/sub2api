PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS redeem_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  code_mask TEXT NOT NULL,
  benefit_type TEXT NOT NULL CHECK (benefit_type IN ('balance', 'subscription')),
  value_micros INTEGER NOT NULL CHECK (value_micros > 0),
  group_id INTEGER,
  validity_days INTEGER,
  status TEXT NOT NULL DEFAULT 'unused'
    CHECK (status IN ('unused', 'processing', 'redeemed', 'failed', 'disabled')),
  campaign TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  claimed_by_user_id INTEGER,
  expires_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  redeemed_at TEXT,
  CHECK (
    (benefit_type = 'balance' AND group_id IS NULL AND validity_days IS NULL)
    OR
    (benefit_type = 'subscription' AND group_id > 0 AND validity_days > 0)
  )
);

CREATE TABLE IF NOT EXISTS redemptions (
  id TEXT PRIMARY KEY,
  code_id TEXT NOT NULL UNIQUE REFERENCES redeem_codes(id),
  user_id INTEGER NOT NULL,
  user_email TEXT NOT NULL DEFAULT '',
  benefit_type TEXT NOT NULL CHECK (benefit_type IN ('balance', 'subscription')),
  value_micros INTEGER NOT NULL,
  group_id INTEGER,
  validity_days INTEGER,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'retryable', 'succeeded', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT NOT NULL UNIQUE,
  upstream_code TEXT NOT NULL UNIQUE,
  upstream_http_status INTEGER,
  upstream_reason TEXT NOT NULL DEFAULT '',
  upstream_response TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  retryable INTEGER NOT NULL DEFAULT 1 CHECK (retryable IN (0, 1)),
  next_retry_at TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS redemption_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  redemption_id TEXT NOT NULL REFERENCES redemptions(id),
  attempt_no INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'succeeded', 'failed')),
  http_status INTEGER,
  reason TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER,
  error_message TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_codes_status_created
  ON redeem_codes(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_codes_campaign_created
  ON redeem_codes(campaign, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_redemptions_status_retry
  ON redemptions(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_redemptions_user_created
  ON redemptions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_redemptions_created
  ON redemptions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_redemption
  ON redemption_attempts(redemption_id, attempt_no DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created
  ON audit_events(created_at DESC);

PRAGMA user_version = 1;
