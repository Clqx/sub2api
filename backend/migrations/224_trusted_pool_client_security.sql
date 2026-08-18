-- Require every active integration client to be explicitly bound to one pool,
-- and separate the Bearer verifier from recoverable HMAC signing material.
ALTER TABLE trusted_pool_integration_clients
    ADD COLUMN IF NOT EXISTS external_pool_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS hmac_secret_encrypted TEXT;

-- Pre-migration activity is not an authorization source: those writes happened
-- while clients were not pool-scoped and may include an exploited cross-pool
-- request. Every legacy client therefore remains unbound and is disabled until
-- an operator explicitly binds the intended pool and rotates both credentials.
UPDATE trusted_pool_integration_clients
SET status='disabled', updated_at=NOW()
WHERE status='active'
  AND (external_pool_id IS NULL OR BTRIM(external_pool_id)='');

CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_pool_clients_client_pool
    ON trusted_pool_integration_clients(client_id, external_pool_id);
CREATE INDEX IF NOT EXISTS idx_trusted_pool_clients_external_pool
    ON trusted_pool_integration_clients(external_pool_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='trusted_pool_clients_active_pool_check'
    ) THEN
        ALTER TABLE trusted_pool_integration_clients
            ADD CONSTRAINT trusted_pool_clients_active_pool_check
            CHECK (
                status <> 'active'
                OR (external_pool_id IS NOT NULL AND BTRIM(external_pool_id) <> '')
            );
    END IF;
END $$;

-- New provision writes are also constrained at the database boundary. NOT
-- VALID keeps ambiguous historical records available for audit while still
-- checking every new or updated row.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='trusted_pool_provision_client_pool_fkey'
    ) THEN
        ALTER TABLE trusted_pool_provision_operations
            ADD CONSTRAINT trusted_pool_provision_client_pool_fkey
            FOREIGN KEY (client_id, external_pool_id)
            REFERENCES trusted_pool_integration_clients(client_id, external_pool_id)
            NOT VALID;
    END IF;
END $$;

COMMENT ON COLUMN trusted_pool_integration_clients.secret_hash IS
    'SHA-256(raw Bearer secret) hex verifier; never valid HMAC signing material';
COMMENT ON COLUMN trusted_pool_integration_clients.external_pool_id IS
    'Only this external pool may be accessed by the integration client; active clients must be bound';
COMMENT ON COLUMN trusted_pool_integration_clients.hmac_secret_encrypted IS
    'Optional encrypted HMAC-only secret, independent from the Bearer credential; NULL disables HMAC until credential rotation';
