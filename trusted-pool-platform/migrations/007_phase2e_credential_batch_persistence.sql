BEGIN;

CREATE OR REPLACE FUNCTION credential_recovery_binding_hash(
    wrapper_domain text, wrap_algorithm text, key_ref text, bound_aad_hash bytea, wrapped_dek bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT digest(
        convert_to('trusted-pool/recovery-binding/v1', 'UTF8') ||
        int4send(octet_length(convert_to(wrapper_domain, 'UTF8'))) || convert_to(wrapper_domain, 'UTF8') ||
        int4send(octet_length(convert_to(wrap_algorithm, 'UTF8'))) || convert_to(wrap_algorithm, 'UTF8') ||
        int4send(octet_length(convert_to(key_ref, 'UTF8'))) || convert_to(key_ref, 'UTF8') ||
        int4send(octet_length(bound_aad_hash)) || bound_aad_hash ||
        int4send(octet_length(wrapped_dek)) || wrapped_dek,
        'sha256'
    );
$$;

-- 旧批次没有 wrapper domain/key ref、规范 AAD 版本和创建 operation，不能伪装成可恢复双包装。
ALTER TABLE credential_batches
    ADD COLUMN external_id varchar(128),
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT'
        CHECK (migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE')),
    ADD COLUMN seal_integration_operation_id uuid REFERENCES integration_operations(id) ON DELETE RESTRICT,
    ADD COLUMN aad_version smallint,
    ADD COLUMN kms_wrap_algorithm varchar(64),
    ADD COLUMN kms_key_ref varchar(512),
    ADD COLUMN kms_wrapper_domain varchar(128),
    ADD COLUMN recovery_wrap_algorithm varchar(64),
    ADD COLUMN recovery_key_ref varchar(512),
    ADD COLUMN recovery_wrapper_domain varchar(128),
    ADD COLUMN recovery_binding_hash bytea,
    ADD COLUMN sealed_at timestamptz,
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

UPDATE credential_batches
SET external_id = id::text,
    migration_state = 'LEGACY_UNRECOVERABLE';

ALTER TABLE credential_batches
    ALTER COLUMN external_id SET NOT NULL,
    ADD CONSTRAINT uq_credential_batches_external_id UNIQUE (external_id),
    ADD CONSTRAINT uq_credential_batches_seal_operation UNIQUE (seal_integration_operation_id),
    ADD CONSTRAINT ck_credential_batches_external_id CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    ADD CONSTRAINT ck_credential_batches_current_shape CHECK (
        migration_state = 'LEGACY_UNRECOVERABLE' OR (
            seal_integration_operation_id IS NOT NULL AND aad_version = 1 AND
            content_hash IS NOT NULL AND octet_length(content_hash) = 32 AND
            (
                (status IN ('PREPARED', 'FAILED') AND
                 encryption_algorithm IS NULL AND ciphertext IS NULL AND nonce IS NULL AND aad_hash IS NULL AND
                 encrypted_dek_kms IS NULL AND encrypted_dek_recovery IS NULL AND
                 kms_wrap_algorithm IS NULL AND kms_key_ref IS NULL AND kms_wrapper_domain IS NULL AND
                 recovery_wrap_algorithm IS NULL AND recovery_key_ref IS NULL AND
                 recovery_wrapper_domain IS NULL AND recovery_binding_hash IS NULL AND
                 sealed_at IS NULL AND activated_at IS NULL AND retired_at IS NULL) OR
                (status = 'SEALED' AND
                 encryption_algorithm = 'AES-256-GCM' AND ciphertext IS NOT NULL AND octet_length(ciphertext) > 0 AND
                 nonce IS NOT NULL AND octet_length(nonce) = 12 AND aad_hash IS NOT NULL AND octet_length(aad_hash) = 32 AND
                 encrypted_dek_kms IS NOT NULL AND octet_length(encrypted_dek_kms) > 0 AND
                 encrypted_dek_recovery IS NOT NULL AND octet_length(encrypted_dek_recovery) > 0 AND
                 kms_wrap_algorithm IS NOT NULL AND kms_key_ref IS NOT NULL AND kms_wrapper_domain IS NOT NULL AND
                 recovery_wrap_algorithm IS NOT NULL AND recovery_key_ref IS NOT NULL AND recovery_wrapper_domain IS NOT NULL AND
                 length(trim(kms_wrap_algorithm)) BETWEEN 1 AND 64 AND
                 length(trim(kms_key_ref)) BETWEEN 1 AND 512 AND
                 length(trim(kms_wrapper_domain)) BETWEEN 1 AND 128 AND
                 length(trim(recovery_wrap_algorithm)) BETWEEN 1 AND 64 AND
                 length(trim(recovery_key_ref)) BETWEEN 1 AND 512 AND
                 length(trim(recovery_wrapper_domain)) BETWEEN 1 AND 128 AND
                 kms_wrapper_domain <> recovery_wrapper_domain AND
                 encrypted_dek_kms <> encrypted_dek_recovery AND
                 recovery_binding_hash IS NOT NULL AND octet_length(recovery_binding_hash) = 32 AND
                 recovery_binding_hash = credential_recovery_binding_hash(
                     recovery_wrapper_domain, recovery_wrap_algorithm, recovery_key_ref,
                     aad_hash, encrypted_dek_recovery) AND
                 sealed_at IS NOT NULL AND activated_at IS NULL AND retired_at IS NULL) OR
                (status = 'ACTIVE' AND sealed_at IS NOT NULL AND activated_at IS NOT NULL AND retired_at IS NULL AND
                 encryption_algorithm = 'AES-256-GCM' AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND
                 octet_length(nonce) = 12 AND aad_hash IS NOT NULL AND octet_length(aad_hash) = 32 AND
                 encrypted_dek_kms IS NOT NULL AND octet_length(encrypted_dek_kms) > 0 AND
                 encrypted_dek_recovery IS NOT NULL AND octet_length(encrypted_dek_recovery) > 0 AND
                 kms_wrap_algorithm IS NOT NULL AND kms_key_ref IS NOT NULL AND kms_wrapper_domain IS NOT NULL AND
                 recovery_wrap_algorithm IS NOT NULL AND recovery_key_ref IS NOT NULL AND
                 recovery_wrapper_domain IS NOT NULL AND kms_wrapper_domain <> recovery_wrapper_domain AND
                 encrypted_dek_kms <> encrypted_dek_recovery AND
                 recovery_binding_hash IS NOT NULL AND octet_length(recovery_binding_hash) = 32 AND
                 recovery_binding_hash = credential_recovery_binding_hash(
                     recovery_wrapper_domain, recovery_wrap_algorithm, recovery_key_ref,
                     aad_hash, encrypted_dek_recovery)) OR
                (status = 'RETIRED' AND sealed_at IS NOT NULL AND activated_at IS NOT NULL AND retired_at IS NOT NULL AND
                 retired_at >= activated_at AND activated_at >= sealed_at AND
                 encryption_algorithm = 'AES-256-GCM' AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND
                 octet_length(nonce) = 12 AND aad_hash IS NOT NULL AND octet_length(aad_hash) = 32 AND
                 encrypted_dek_kms IS NOT NULL AND octet_length(encrypted_dek_kms) > 0 AND
                 encrypted_dek_recovery IS NOT NULL AND octet_length(encrypted_dek_recovery) > 0 AND
                 kms_wrap_algorithm IS NOT NULL AND kms_key_ref IS NOT NULL AND kms_wrapper_domain IS NOT NULL AND
                 recovery_wrap_algorithm IS NOT NULL AND recovery_key_ref IS NOT NULL AND
                 recovery_wrapper_domain IS NOT NULL AND kms_wrapper_domain <> recovery_wrapper_domain AND
                 encrypted_dek_kms <> encrypted_dek_recovery AND
                 recovery_binding_hash IS NOT NULL AND octet_length(recovery_binding_hash) = 32 AND
                 recovery_binding_hash = credential_recovery_binding_hash(
                     recovery_wrapper_domain, recovery_wrap_algorithm, recovery_key_ref,
                     aad_hash, encrypted_dek_recovery))
            )
        )
    );

COMMENT ON COLUMN credential_batches.migration_state IS
    '001/002 旧行缺少双包装来源证明，统一只读标记为 LEGACY_UNRECOVERABLE';
COMMENT ON COLUMN credential_batches.content_hash IS
    '调用层使用独立密钥生成的 payload HMAC-SHA-256 指纹；不得保存裸低熵摘要或明文';
COMMENT ON COLUMN credential_batches.recovery_wrapper_domain IS
    '独立 Recovery wrapper 的安全域标识；不得与 online KMS wrapper domain 相同';

CREATE INDEX idx_credential_batches_legacy_reconciliation
    ON credential_batches(pool_id, membership_epoch, status)
    WHERE migration_state = 'LEGACY_UNRECOVERABLE';
CREATE INDEX idx_integration_operations_batch_seal_recovery
    ON integration_operations(next_attempt_at, lease_expires_at, created_at)
    WHERE migration_state = 'CURRENT' AND operation_type = 'SEAL_CREDENTIAL_BATCH'
      AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED');

CREATE TABLE credential_batch_transitions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    credential_batch_id uuid NOT NULL REFERENCES credential_batches(id) ON DELETE RESTRICT,
    transition_type text NOT NULL CHECK (transition_type IN ('ACTIVATE', 'RETIRE')),
    from_status text NOT NULL CHECK (from_status IN ('SEALED', 'ACTIVE')),
    to_status text NOT NULL CHECK (to_status IN ('ACTIVE', 'RETIRED')),
    expected_batch_version bigint NOT NULL CHECK (expected_batch_version > 0),
    resulting_batch_version bigint NOT NULL CHECK (resulting_batch_version = expected_batch_version + 1),
    occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_batch_id, transition_type),
    UNIQUE (credential_batch_id, resulting_batch_version),
    CHECK ((transition_type = 'ACTIVATE' AND from_status = 'SEALED' AND to_status = 'ACTIVE') OR
           (transition_type = 'RETIRE' AND from_status = 'ACTIVE' AND to_status = 'RETIRED'))
);

CREATE OR REPLACE FUNCTION valid_credential_batch_seal_snapshot(
    snapshot jsonb, expected_operation_id text, expected_batch_id text, expected_pool_id text,
    expected_account_ref text, expected_batch_type text, expected_batch_version integer,
    expected_membership_epoch integer, expected_content_hash bytea
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (snapshot ?& ARRAY[
        'version', 'operation_id', 'batch_id', 'pool_id', 'account_ref', 'batch_type',
        'batch_version', 'membership_epoch', 'content_fingerprint'
    ]) THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN COALESCE((key_count = 9 AND snapshot -> 'version' = '1'::jsonb AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'batch_id' = expected_batch_id AND snapshot ->> 'pool_id' = expected_pool_id AND
           snapshot ->> 'account_ref' = expected_account_ref AND snapshot ->> 'batch_type' = expected_batch_type AND
           snapshot ->> 'batch_version' = expected_batch_version::text AND
           snapshot ->> 'membership_epoch' = expected_membership_epoch::text AND
           snapshot ->> 'content_fingerprint' = encode(expected_content_hash, 'hex')), false);
END;
$$;

CREATE OR REPLACE FUNCTION valid_credential_batch_response_snapshot(
    snapshot jsonb, expected_operation_id text, expected_batch_id text, expected_pool_id text,
    expected_account_ref text, expected_batch_type text, expected_batch_version integer,
    expected_membership_epoch integer, expected_state text, expected_record_version bigint,
    expected_content_hash bytea, expected_aad_hash bytea, expected_sealed_at timestamptz,
    expected_activated_at timestamptz, expected_retired_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (snapshot ?& ARRAY[
        'version', 'operation_id', 'batch_id', 'pool_id', 'account_ref', 'batch_type',
        'batch_version', 'membership_epoch', 'state', 'record_version', 'content_fingerprint',
        'aad_hash', 'sealed_at', 'activated_at', 'retired_at'
    ]) THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN COALESCE((key_count = 15 AND snapshot -> 'version' = '1'::jsonb AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'batch_id' = expected_batch_id AND snapshot ->> 'pool_id' = expected_pool_id AND
           snapshot ->> 'account_ref' = expected_account_ref AND snapshot ->> 'batch_type' = expected_batch_type AND
           snapshot ->> 'batch_version' = expected_batch_version::text AND
           snapshot ->> 'membership_epoch' = expected_membership_epoch::text AND
           snapshot ->> 'state' = expected_state AND snapshot ->> 'record_version' = expected_record_version::text AND
           snapshot ->> 'content_fingerprint' = encode(expected_content_hash, 'hex') AND
           snapshot ->> 'aad_hash' = encode(expected_aad_hash, 'hex') AND
           (snapshot ->> 'sealed_at')::timestamptz = expected_sealed_at AND
           ((expected_activated_at IS NULL AND snapshot -> 'activated_at' = 'null'::jsonb) OR
            (expected_activated_at IS NOT NULL AND (snapshot ->> 'activated_at')::timestamptz = expected_activated_at)) AND
           ((expected_retired_at IS NULL AND snapshot -> 'retired_at' = 'null'::jsonb) OR
            (expected_retired_at IS NOT NULL AND (snapshot ->> 'retired_at')::timestamptz = expected_retired_at))), false);
END;
$$;

CREATE OR REPLACE FUNCTION valid_credential_batch_transition_snapshot(
    snapshot jsonb, expected_operation_id text, expected_batch_id text,
    expected_action text, expected_record_version bigint
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (snapshot ?& ARRAY[
        'version', 'operation_id', 'batch_id', 'action', 'expected_record_version'
    ]) THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN COALESCE((key_count = 5 AND snapshot -> 'version' = '1'::jsonb AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'batch_id' = expected_batch_id AND
           snapshot ->> 'action' = expected_action AND
           snapshot ->> 'expected_record_version' = expected_record_version::text), false);
END;
$$;

CREATE OR REPLACE FUNCTION enforce_current_credential_batch_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_id text;
    operation_external_id text;
    operation_snapshot jsonb;
    pool_external_id text;
    pool_membership_epoch integer;
    pool_epoch_floor integer;
    bound_epoch_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'credential batch is an immutable ledger';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.migration_state = 'LEGACY_UNRECOVERABLE' THEN
        RAISE EXCEPTION 'legacy credential batch is read-only and unrecoverable';
    END IF;
    IF TG_OP = 'INSERT' AND (NEW.migration_state <> 'CURRENT' OR NEW.status <> 'PREPARED' OR NEW.version <> 1) THEN
        RAISE EXCEPTION 'new credential batch must be CURRENT PREPARED version one';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
           NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.membership_epoch IS DISTINCT FROM OLD.membership_epoch OR
           NEW.resource_account_ref IS DISTINCT FROM OLD.resource_account_ref OR NEW.batch_type IS DISTINCT FROM OLD.batch_type OR
           NEW.batch_version IS DISTINCT FROM OLD.batch_version OR NEW.content_hash IS DISTINCT FROM OLD.content_hash OR
           NEW.seal_integration_operation_id IS DISTINCT FROM OLD.seal_integration_operation_id OR
           NEW.migration_state IS DISTINCT FROM OLD.migration_state OR NEW.aad_version IS DISTINCT FROM OLD.aad_version OR
           NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'credential batch scope and seal intent are immutable';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'credential batch version must increase by exactly one';
        END IF;
        IF NOT ((OLD.status = 'PREPARED' AND NEW.status IN ('SEALED', 'FAILED')) OR
                (OLD.status = 'SEALED' AND NEW.status = 'ACTIVE') OR
                (OLD.status = 'ACTIVE' AND NEW.status = 'RETIRED')) THEN
            RAISE EXCEPTION 'illegal credential batch transition: % -> %', OLD.status, NEW.status;
        END IF;
        IF OLD.status <> 'PREPARED' AND (
            NEW.encryption_algorithm IS DISTINCT FROM OLD.encryption_algorithm OR
            NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR NEW.nonce IS DISTINCT FROM OLD.nonce OR
            NEW.aad_hash IS DISTINCT FROM OLD.aad_hash OR NEW.encrypted_dek_kms IS DISTINCT FROM OLD.encrypted_dek_kms OR
            NEW.encrypted_dek_recovery IS DISTINCT FROM OLD.encrypted_dek_recovery OR
            NEW.kms_wrap_algorithm IS DISTINCT FROM OLD.kms_wrap_algorithm OR NEW.kms_key_ref IS DISTINCT FROM OLD.kms_key_ref OR
            NEW.kms_wrapper_domain IS DISTINCT FROM OLD.kms_wrapper_domain OR
            NEW.recovery_wrap_algorithm IS DISTINCT FROM OLD.recovery_wrap_algorithm OR
            NEW.recovery_key_ref IS DISTINCT FROM OLD.recovery_key_ref OR
            NEW.recovery_wrapper_domain IS DISTINCT FROM OLD.recovery_wrapper_domain OR
            NEW.recovery_binding_hash IS DISTINCT FROM OLD.recovery_binding_hash OR NEW.sealed_at IS DISTINCT FROM OLD.sealed_at
        ) THEN RAISE EXCEPTION 'sealed credential batch cryptographic material is immutable'; END IF;
    END IF;

    SELECT io.operation_id, io.target_external_id, io.request_snapshot,
           pool.external_id, pool.membership_epoch, pool.credential_epoch_floor, epoch.status
    INTO operation_id, operation_external_id, operation_snapshot,
         pool_external_id, pool_membership_epoch, pool_epoch_floor, bound_epoch_status
    FROM integration_operations io
    JOIN pools pool ON pool.id = NEW.pool_id
    JOIN membership_epochs epoch ON epoch.pool_id = pool.id AND epoch.epoch = NEW.membership_epoch
    WHERE io.id = NEW.seal_integration_operation_id
      AND io.operation_type = 'SEAL_CREDENTIAL_BATCH' AND io.target_type = 'CREDENTIAL_BATCH'
      AND io.migration_state = 'CURRENT';
    IF operation_id IS NULL OR operation_external_id <> NEW.external_id OR
       NOT valid_credential_batch_seal_snapshot(operation_snapshot, operation_id, NEW.external_id,
           pool_external_id, NEW.resource_account_ref, NEW.batch_type, NEW.batch_version,
           NEW.membership_epoch, NEW.content_hash) THEN
        RAISE EXCEPTION 'credential batch is not bound to a canonical CURRENT seal operation';
    END IF;
    -- Begin 与 Seal/Activate 提交都重读 Pool，封闭加密期间 membership/floor 变化窗口。
    IF NEW.status IN ('PREPARED', 'SEALED', 'ACTIVE') AND
       (bound_epoch_status <> 'ACTIVE' OR pool_membership_epoch <> NEW.membership_epoch OR
        NEW.membership_epoch < pool_epoch_floor) THEN
        RAISE EXCEPTION 'credential batch membership epoch is no longer writable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER credential_batches_phase2e_invariants
BEFORE INSERT OR UPDATE OR DELETE ON credential_batches
FOR EACH ROW EXECUTE FUNCTION enforce_current_credential_batch_invariants();

CREATE OR REPLACE FUNCTION reject_credential_batch_transition_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'credential batch transition is append-only'; END;
$$;
CREATE TRIGGER credential_batch_transitions_append_only
BEFORE UPDATE OR DELETE ON credential_batch_transitions
FOR EACH ROW EXECUTE FUNCTION reject_credential_batch_transition_mutation();

CREATE OR REPLACE FUNCTION assert_credential_batch_operation_aggregate(target_operation_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE aggregate record;
BEGIN
    SELECT io.operation_id, io.operation_type, io.status AS operation_status, io.target_id, io.target_external_id,
           io.request_snapshot, io.response_snapshot, batch.id AS batch_id, batch.external_id, batch.status AS batch_status,
           batch.version AS batch_version, batch.seal_integration_operation_id,
           batch.resource_account_ref, batch.batch_type, batch.batch_version AS logical_batch_version,
           batch.membership_epoch, batch.content_hash, batch.aad_hash, batch.sealed_at,
           batch.activated_at, batch.retired_at, pool.external_id AS pool_external_id,
           transition.id AS transition_id, transition.credential_batch_id AS transition_batch_id,
           transition.transition_type, transition.from_status,
           transition.to_status, transition.expected_batch_version, transition.resulting_batch_version
    INTO aggregate
    FROM integration_operations io
    LEFT JOIN credential_batches batch ON batch.id = io.target_id OR batch.seal_integration_operation_id = io.id
    LEFT JOIN pools pool ON pool.id = batch.pool_id
    LEFT JOIN credential_batch_transitions transition ON transition.integration_operation_id = io.id
    WHERE io.id = target_operation_id
      AND io.migration_state = 'CURRENT'
      AND io.operation_type IN ('SEAL_CREDENTIAL_BATCH', 'ACTIVATE_CREDENTIAL_BATCH', 'RETIRE_CREDENTIAL_BATCH');
    IF aggregate.operation_type IS NULL THEN RETURN; END IF;
    IF aggregate.batch_id IS NULL OR aggregate.target_external_id <> aggregate.external_id OR
       aggregate.target_id IS DISTINCT FROM aggregate.batch_id THEN
        RAISE EXCEPTION 'credential batch operation target is inconsistent';
    END IF;
    IF aggregate.operation_type = 'SEAL_CREDENTIAL_BATCH' THEN
        IF aggregate.seal_integration_operation_id <> target_operation_id OR NOT (
            (aggregate.batch_status = 'PREPARED' AND aggregate.operation_status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') AND aggregate.response_snapshot IS NULL) OR
            (aggregate.batch_status = 'FAILED' AND aggregate.operation_status = 'FAILED' AND aggregate.response_snapshot IS NULL) OR
            (aggregate.batch_status IN ('SEALED', 'ACTIVE', 'RETIRED') AND aggregate.operation_status = 'SUCCEEDED' AND
             valid_credential_batch_response_snapshot(
                 aggregate.response_snapshot, aggregate.operation_id, aggregate.external_id,
                 aggregate.pool_external_id, aggregate.resource_account_ref, aggregate.batch_type,
                 aggregate.logical_batch_version, aggregate.membership_epoch, 'SEALED', 2,
                 aggregate.content_hash, aggregate.aad_hash, aggregate.sealed_at, NULL, NULL
             ))
        ) THEN RAISE EXCEPTION 'credential batch seal aggregate is inconsistent'; END IF;
    ELSE
        -- Activate/Retire 是纯数据库 CAS；不存在需要跨网络恢复的未决态。
        -- 因而 operation、transition、批次状态必须在同一事务一次提交，ledger 也没有藏入包络的机会。
        IF aggregate.operation_status <> 'SUCCEEDED' OR (
            aggregate.transition_id IS NULL OR aggregate.transition_batch_id <> aggregate.batch_id OR
            aggregate.transition_type <> CASE aggregate.operation_type
                WHEN 'ACTIVATE_CREDENTIAL_BATCH' THEN 'ACTIVATE' ELSE 'RETIRE' END OR
            aggregate.from_status <> CASE aggregate.operation_type
                WHEN 'ACTIVATE_CREDENTIAL_BATCH' THEN 'SEALED' ELSE 'ACTIVE' END OR
            aggregate.to_status <> CASE aggregate.operation_type
                WHEN 'ACTIVATE_CREDENTIAL_BATCH' THEN 'ACTIVE' ELSE 'RETIRED' END OR
            aggregate.resulting_batch_version <> aggregate.expected_batch_version + 1 OR
            NOT valid_credential_batch_transition_snapshot(
                aggregate.request_snapshot, aggregate.operation_id, aggregate.external_id,
                aggregate.transition_type, aggregate.expected_batch_version) OR
            (aggregate.operation_type = 'ACTIVATE_CREDENTIAL_BATCH' AND aggregate.batch_status NOT IN ('ACTIVE', 'RETIRED')) OR
            (aggregate.operation_type = 'RETIRE_CREDENTIAL_BATCH' AND aggregate.batch_status <> 'RETIRED') OR
            NOT valid_credential_batch_response_snapshot(
                aggregate.response_snapshot, aggregate.operation_id, aggregate.external_id,
                aggregate.pool_external_id, aggregate.resource_account_ref, aggregate.batch_type,
                aggregate.logical_batch_version, aggregate.membership_epoch, aggregate.to_status,
                aggregate.resulting_batch_version, aggregate.content_hash, aggregate.aad_hash,
                aggregate.sealed_at,
                CASE WHEN aggregate.transition_type = 'ACTIVATE' THEN aggregate.activated_at ELSE aggregate.activated_at END,
                CASE WHEN aggregate.transition_type = 'RETIRE' THEN aggregate.retired_at ELSE NULL END
            )
        ) THEN RAISE EXCEPTION 'credential batch transition aggregate is inconsistent'; END IF;
    END IF;
END;
$$;

-- 终态批次必须有完整的 append-only 版本链，阻止绕过专用 Store 直接改状态。
CREATE OR REPLACE FUNCTION assert_credential_batch_transition_history(target_batch_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    batch_row record;
    activate_row record;
    retire_row record;
BEGIN
    SELECT migration_state, status, version INTO batch_row
    FROM credential_batches WHERE id = target_batch_id;
    IF batch_row.migration_state IS NULL OR batch_row.migration_state <> 'CURRENT' THEN RETURN; END IF;

    SELECT * INTO activate_row FROM credential_batch_transitions
    WHERE credential_batch_id = target_batch_id AND transition_type = 'ACTIVATE';
    SELECT * INTO retire_row FROM credential_batch_transitions
    WHERE credential_batch_id = target_batch_id AND transition_type = 'RETIRE';

    IF batch_row.status = 'SEALED' AND (batch_row.version <> 2 OR activate_row.id IS NOT NULL OR retire_row.id IS NOT NULL) THEN
        RAISE EXCEPTION 'sealed credential batch has an invalid transition history';
    ELSIF batch_row.status = 'ACTIVE' AND (
        activate_row.id IS NULL OR retire_row.id IS NOT NULL OR
        activate_row.expected_batch_version <> 2 OR activate_row.resulting_batch_version <> batch_row.version
    ) THEN
        RAISE EXCEPTION 'active credential batch has an invalid transition history';
    ELSIF batch_row.status = 'RETIRED' AND (
        activate_row.id IS NULL OR retire_row.id IS NULL OR
        activate_row.expected_batch_version <> 2 OR
        retire_row.expected_batch_version <> activate_row.resulting_batch_version OR
        retire_row.resulting_batch_version <> batch_row.version OR retire_row.occurred_at < activate_row.occurred_at
    ) THEN
        RAISE EXCEPTION 'retired credential batch has an invalid transition history';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_credential_batch_operation_aggregate_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operation_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'integration_operations' THEN operation_id := NEW.id;
    ELSIF TG_TABLE_NAME = 'credential_batch_transitions' THEN operation_id := NEW.integration_operation_id;
    ELSE operation_id := NEW.seal_integration_operation_id; END IF;
    IF operation_id IS NOT NULL THEN PERFORM assert_credential_batch_operation_aggregate(operation_id); END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_credential_batch_history_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_credential_batch_transition_history(
        CASE WHEN TG_TABLE_NAME = 'credential_batch_transitions' THEN NEW.credential_batch_id ELSE NEW.id END
    );
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER integration_operations_batch_aggregate
AFTER INSERT OR UPDATE ON integration_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_credential_batch_operation_aggregate_deferred();
CREATE CONSTRAINT TRIGGER credential_batches_operation_aggregate
AFTER INSERT OR UPDATE ON credential_batches DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_credential_batch_operation_aggregate_deferred();
CREATE CONSTRAINT TRIGGER credential_batch_transitions_operation_aggregate
AFTER INSERT ON credential_batch_transitions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_credential_batch_operation_aggregate_deferred();
CREATE CONSTRAINT TRIGGER credential_batches_transition_history
AFTER INSERT OR UPDATE ON credential_batches DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_credential_batch_history_deferred();
CREATE CONSTRAINT TRIGGER credential_batch_transitions_history
AFTER INSERT ON credential_batch_transitions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_credential_batch_history_deferred();

COMMIT;
