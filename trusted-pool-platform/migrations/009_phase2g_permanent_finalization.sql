BEGIN;

-- Phase2-G 在 provider release 前只持久包络，不允许预生成或占位 token。
DO $$ DECLARE constraint_name text; BEGIN
  FOR constraint_name IN SELECT conname FROM pg_constraint
    WHERE conrelid = 'credential_claims'::regclass AND contype = 'c'
      AND (pg_get_constraintdef(oid) LIKE '%status%' OR pg_get_constraintdef(oid) LIKE '%expires_at%')
  LOOP EXECUTE format('ALTER TABLE credential_claims DROP CONSTRAINT %I', constraint_name); END LOOP;
END $$;
ALTER TABLE credential_claims ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE credential_claims ADD CONSTRAINT credential_claims_status_phase2g CHECK (status IN (
  'ISSUANCE_PENDING', 'READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED', 'CLAIMED', 'EXPIRED', 'REJECTED'
)), ADD CONSTRAINT credential_claims_shape_phase2g CHECK (
  (status = 'ISSUANCE_PENDING' AND claim_token_hash IS NULL AND expires_at IS NULL AND
   envelope_algorithm IS NOT NULL AND envelope_key_ref IS NOT NULL AND octet_length(envelope_ciphertext) > 0 AND
   octet_length(envelope_nonce) > 0 AND octet_length(envelope_aad_hash) = 32 AND octet_length(wrapped_dek_kms) > 0 AND
   terminal_at IS NULL AND claimed_at IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL) OR
  (status IN ('READY','ACK_PENDING','ACK_RECONCILE_REQUIRED') AND octet_length(claim_token_hash) = 32 AND
   expires_at > created_at AND envelope_algorithm IS NOT NULL AND envelope_key_ref IS NOT NULL AND
   octet_length(envelope_ciphertext) > 0 AND octet_length(envelope_nonce) > 0 AND
   octet_length(envelope_aad_hash) = 32 AND octet_length(wrapped_dek_kms) > 0 AND
   terminal_at IS NULL AND claimed_at IS NULL) OR
  (status IN ('CLAIMED','EXPIRED','REJECTED') AND claim_token_hash IS NULL AND envelope_algorithm IS NULL AND
   envelope_key_ref IS NULL AND envelope_ciphertext IS NULL AND envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND
   wrapped_dek_kms IS NULL AND expires_at > created_at AND terminal_at IS NOT NULL AND
   ((status = 'CLAIMED' AND claimed_at IS NOT NULL) OR
    (status IN ('EXPIRED','REJECTED') AND claimed_at IS NULL)))
), ADD CONSTRAINT credential_claims_lease_shape_phase2g CHECK (
  (lease_owner IS NULL AND lease_expires_at IS NULL) OR
  (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND
   length(trim(lease_owner)) BETWEEN 1 AND 128)
), ADD CONSTRAINT credential_claims_terminal_lease_phase2g CHECK (
  status NOT IN ('CLAIMED','EXPIRED','REJECTED') OR
  (lease_owner IS NULL AND lease_expires_at IS NULL)
);

-- Phase2-G 复用 008 的治理快照。执行协议是：逐 Seat prepare（上游保持禁用）→
-- Pool 全量原子 activate → 本地单一 Serializable 事务切 Epoch/owner/claims。
ALTER TABLE permanent_replacement_cases
    DROP CONSTRAINT permanent_replacement_cases_status_check,
    ADD CONSTRAINT permanent_replacement_cases_status_phase2g CHECK (status IN (
        'READY', 'ROTATING', 'RECONCILE_REQUIRED', 'OPERATOR_REVIEW_REQUIRED',
        'READY_TO_COMMIT', 'PROVIDER_COMMIT_PENDING', 'READY_TO_ISSUE', 'FINALIZED', 'FAILED'
    ));

ALTER TABLE recovery_seat_rotation_progress
    DROP CONSTRAINT recovery_seat_rotation_progress_status_check,
    DROP CONSTRAINT recovery_seat_rotation_progress_check,
    ADD COLUMN prepared_reference varchar(512),
    ADD COLUMN provider_result_digest bytea;

ALTER TABLE recovery_seat_rotation_progress
    ADD CONSTRAINT recovery_seat_rotation_progress_status_phase2g CHECK (status IN (
        'PREPARE_PENDING', 'PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED',
        'PREPARED', 'ACTIVATED', 'COMMITTED', 'FAILED'
    )),
    ADD CONSTRAINT recovery_seat_rotation_progress_shape_phase2g CHECK (
        (status IN ('PREPARE_PENDING', 'PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED', 'FAILED') AND
         principal_user_id IS NULL AND subscription_id IS NULL AND api_key_id IS NULL AND api_key_version IS NULL AND
         credential_fingerprint IS NULL AND claim_operation_id IS NULL AND claim_token_hash IS NULL AND
         claim_intent_hash IS NULL AND envelope_algorithm IS NULL AND envelope_key_ref IS NULL AND
         envelope_ciphertext IS NULL AND envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND
         wrapped_dek_kms IS NULL AND prepared_reference IS NULL AND provider_result_digest IS NULL AND
         claim_expires_at IS NULL AND credential_claim_id IS NULL) OR
        (status IN ('PREPARED', 'ACTIVATED') AND principal_user_id > 0 AND subscription_id > 0 AND
         api_key_id > 0 AND api_key_version > 0 AND octet_length(credential_fingerprint) = 32 AND
         claim_operation_id IS NULL AND claim_token_hash IS NULL AND claim_intent_hash IS NULL AND
         length(trim(envelope_algorithm)) BETWEEN 1 AND 64 AND length(trim(envelope_key_ref)) BETWEEN 1 AND 512 AND
         octet_length(envelope_ciphertext) > 0 AND octet_length(envelope_nonce) > 0 AND
         octet_length(envelope_aad_hash) = 32 AND octet_length(wrapped_dek_kms) > 0 AND
         length(trim(prepared_reference)) BETWEEN 1 AND 512 AND octet_length(provider_result_digest) = 32 AND
         claim_expires_at IS NULL AND credential_claim_id IS NULL AND
         error_code IS NULL AND error_detail IS NULL AND next_attempt_at IS NULL) OR
        (status = 'COMMITTED' AND principal_user_id > 0 AND subscription_id > 0 AND api_key_id > 0 AND
         api_key_version > 0 AND octet_length(credential_fingerprint) = 32 AND credential_claim_id IS NOT NULL AND
         claim_operation_id IS NULL AND claim_token_hash IS NULL AND claim_intent_hash IS NULL AND
         envelope_algorithm IS NULL AND envelope_key_ref IS NULL AND envelope_ciphertext IS NULL AND
         envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND wrapped_dek_kms IS NULL AND
         length(trim(prepared_reference)) BETWEEN 1 AND 512 AND octet_length(provider_result_digest) = 32 AND
         claim_expires_at IS NULL AND error_code IS NULL AND error_detail IS NULL AND next_attempt_at IS NULL)
    );

-- token hash 到最终事务才写；重复 token 在任何 Seat/operation 间都 fail closed。
CREATE UNIQUE INDEX uq_credential_claim_token_hash_phase2g
    ON credential_claims(claim_token_hash) WHERE claim_token_hash IS NOT NULL;
CREATE UNIQUE INDEX uq_recovery_prepared_reference_phase2g
    ON recovery_seat_rotation_progress(prepared_reference) WHERE prepared_reference IS NOT NULL;
CREATE UNIQUE INDEX uq_recovery_credential_fingerprint_phase2g
    ON recovery_seat_rotation_progress(credential_fingerprint) WHERE credential_fingerprint IS NOT NULL;
CREATE UNIQUE INDEX uq_recovery_api_key_version_phase2g
    ON recovery_seat_rotation_progress(api_key_id, api_key_version) WHERE api_key_id IS NOT NULL;

-- 002 的通用 claim 门禁不了解 recovery prepare child。保留原函数处理普通 workflow，
-- recovery 分支只把精确绑定后的 child 映射为可直领的永久换员语义。
ALTER FUNCTION validate_credential_claim_binding(uuid, uuid, uuid)
    RENAME TO validate_credential_claim_binding_phase2a;
CREATE OR REPLACE FUNCTION validate_credential_claim_binding(
    bound_operation_id uuid, bound_seat_id uuid, bound_target_member_id uuid
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE bound_operation_type text;
BEGIN
    SELECT operation_type INTO bound_operation_type FROM integration_operations WHERE id = bound_operation_id;
    IF bound_operation_type IS DISTINCT FROM 'PREPARE_PERMANENT_REPLACEMENT' THEN
        RETURN validate_credential_claim_binding_phase2a(
            bound_operation_id, bound_seat_id, bound_target_member_id
        );
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM integration_operations child
      JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id = child.id
      JOIN recovery_plan_seats planned
        ON planned.plan_id = progress.plan_id AND planned.seat_id = progress.seat_id
      JOIN permanent_replacement_cases replacement ON replacement.plan_id = progress.plan_id
      JOIN seats seat ON seat.id = progress.seat_id
      JOIN seat_assignments assignment ON assignment.seat_id = seat.id
      JOIN members target ON target.id = planned.to_member_id
      WHERE child.id = bound_operation_id AND progress.seat_id = bound_seat_id
        AND planned.to_member_id = bound_target_member_id
        AND child.target_type = 'SEAT' AND child.target_id = seat.id
        AND child.target_external_id = seat.external_id AND child.status = 'SUCCEEDED'
        AND progress.status IN ('ACTIVATED', 'COMMITTED')
        AND replacement.status IN ('READY_TO_COMMIT', 'FINALIZED')
        AND seat.status = 'ACTIVE' AND seat.owner_member_id = bound_target_member_id
        AND seat.assignment_epoch = planned.expected_assignment_epoch + 1
        AND seat.active_api_key_version = progress.api_key_version
        AND assignment.member_id = bound_target_member_id AND assignment.status = 'ACTIVE'
        AND target.status = 'ACTIVE'
    ) THEN RAISE EXCEPTION 'recovery credential claim lacks exact committed Seat binding'; END IF;
    RETURN 'REPLACE_PERMANENTLY';
END;
$$;

CREATE OR REPLACE FUNCTION enforce_credential_claim_insert_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE claim_operation_type text;
BEGIN
    claim_operation_type := validate_credential_claim_binding(
        NEW.integration_operation_id, NEW.seat_id, NEW.target_member_id
    );
    IF NEW.status IN ('ACK_PENDING','ACK_RECONCILE_REQUIRED','REJECTED') AND
       claim_operation_type IS DISTINCT FROM 'PROVISION' THEN
        RAISE EXCEPTION 'ACK and REJECTED claim states are reserved for Provision';
    END IF;
    IF NEW.status = 'ISSUANCE_PENDING' AND
       claim_operation_type IS DISTINCT FROM 'REPLACE_PERMANENTLY' THEN
        RAISE EXCEPTION 'ISSUANCE_PENDING is reserved for Phase2-G replacement claims';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE recovery_pool_preparation_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id uuid NOT NULL UNIQUE REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    intent_set_hash bytea NOT NULL CHECK (octet_length(intent_set_hash) = 32),
    status text NOT NULL CHECK (status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED', 'PREPARED', 'FAILED')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_recovery_pool_preparation_recovery_phase2g
    ON recovery_pool_preparation_attempts(updated_at)
    WHERE status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED');

CREATE TABLE recovery_pool_activation_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id uuid NOT NULL UNIQUE REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    prepared_set_hash bytea NOT NULL CHECK (octet_length(prepared_set_hash) = 32),
    status text NOT NULL CHECK (status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED', 'ACTIVATED', 'FAILED')),
    provider_attestation_ref varchar(512),
    provider_attestation_digest bytea,
    provider_attestation_issuer varchar(256),
    provider_attestation_key_id varchar(512),
    provider_attestation_version bigint,
    provider_attestation_signature bytea,
    old_credential_set_invalidated boolean,
    credential_fingerprint_gate_enforced boolean,
    authorization_cache_invalidated boolean,
    authorization_cache_durable_outbox boolean,
    auth_cache_minimum_events integer,
    activated_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider_attestation_digest),
    CHECK (
      (status <> 'ACTIVATED' AND provider_attestation_ref IS NULL AND provider_attestation_digest IS NULL AND
       provider_attestation_issuer IS NULL AND provider_attestation_key_id IS NULL AND
       provider_attestation_version IS NULL AND provider_attestation_signature IS NULL AND
       old_credential_set_invalidated IS NULL AND credential_fingerprint_gate_enforced IS NULL AND
       authorization_cache_invalidated IS NULL AND authorization_cache_durable_outbox IS NULL AND
       auth_cache_minimum_events IS NULL AND activated_at IS NULL) OR
      (status = 'ACTIVATED' AND length(trim(provider_attestation_ref)) BETWEEN 1 AND 512 AND
       octet_length(provider_attestation_digest) = 32 AND
       length(trim(provider_attestation_issuer)) BETWEEN 1 AND 256 AND
       length(trim(provider_attestation_key_id)) BETWEEN 1 AND 512 AND provider_attestation_version > 0 AND
       octet_length(provider_attestation_signature) > 0 AND old_credential_set_invalidated IS TRUE AND
       credential_fingerprint_gate_enforced IS TRUE AND authorization_cache_invalidated IS NOT NULL AND
       authorization_cache_durable_outbox IS TRUE AND auth_cache_minimum_events > 0 AND
       activated_at IS NOT NULL)
    )
);
CREATE INDEX idx_recovery_pool_activation_recovery_phase2g
    ON recovery_pool_activation_attempts(updated_at)
    WHERE status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED');

-- 该集合来自一次 Pool 原子 activation 的已验签响应。逐字段约束是 DB 权威；
-- prepared_set_hash 使用跨系统版本化 canonical 算法，DB 不用 jsonb 文本另算一套 hash。
CREATE TABLE recovery_pool_activation_seats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    activation_attempt_id uuid NOT NULL REFERENCES recovery_pool_activation_attempts(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    target_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    prepared_reference varchar(512) NOT NULL CHECK (length(trim(prepared_reference)) BETWEEN 1 AND 512),
    principal_user_id bigint NOT NULL CHECK (principal_user_id > 0),
    subscription_id bigint NOT NULL CHECK (subscription_id > 0),
    api_key_id bigint NOT NULL CHECK (api_key_id > 0),
    api_key_version integer NOT NULL CHECK (api_key_version > 0),
    credential_fingerprint bytea NOT NULL CHECK (octet_length(credential_fingerprint) = 32),
    current_concurrency bigint NOT NULL CHECK (current_concurrency = 0),
    pending_settlements bigint NOT NULL CHECK (pending_settlements = 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (activation_attempt_id, seat_id),
    UNIQUE (plan_id, seat_id)
);

CREATE TABLE recovery_pool_provider_commit_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id uuid NOT NULL UNIQUE REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    activation_attempt_id uuid NOT NULL UNIQUE REFERENCES recovery_pool_activation_attempts(id) ON DELETE RESTRICT,
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    prepared_set_hash bytea NOT NULL CHECK (octet_length(prepared_set_hash) = 32),
    status text NOT NULL CHECK (status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED', 'RELEASED', 'FAILED')),
    provider_attestation_ref varchar(512), provider_attestation_digest bytea,
    provider_attestation_issuer varchar(256), provider_attestation_key_id varchar(512),
    provider_attestation_version bigint, provider_attestation_signature bytea,
    all_credentials_enabled boolean, all_subscriptions_enabled boolean,
    old_credential_set_invalidated boolean, credential_fingerprint_gate_enforced boolean,
    authorization_cache_invalidated boolean, authorization_cache_durable_outbox boolean,
    auth_cache_minimum_events integer,
    result_snapshot jsonb,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((status <> 'RELEASED' AND provider_attestation_ref IS NULL AND provider_attestation_digest IS NULL AND
            provider_attestation_issuer IS NULL AND provider_attestation_key_id IS NULL AND
            provider_attestation_version IS NULL AND provider_attestation_signature IS NULL AND
            all_credentials_enabled IS NULL AND all_subscriptions_enabled IS NULL AND
            old_credential_set_invalidated IS NULL AND credential_fingerprint_gate_enforced IS NULL AND
            authorization_cache_invalidated IS NULL AND authorization_cache_durable_outbox IS NULL AND
            auth_cache_minimum_events IS NULL AND result_snapshot IS NULL) OR
           (status = 'RELEASED' AND length(trim(provider_attestation_ref)) BETWEEN 1 AND 512 AND
            octet_length(provider_attestation_digest) = 32 AND length(trim(provider_attestation_issuer)) > 0 AND
            length(trim(provider_attestation_key_id)) > 0 AND provider_attestation_version > 0 AND
            octet_length(provider_attestation_signature) > 0 AND all_credentials_enabled IS TRUE AND
            all_subscriptions_enabled IS TRUE AND old_credential_set_invalidated IS TRUE AND
            credential_fingerprint_gate_enforced IS TRUE AND authorization_cache_invalidated IS NOT NULL AND
            authorization_cache_durable_outbox IS TRUE AND auth_cache_minimum_events > 0 AND
            jsonb_typeof(result_snapshot) = 'object'))
);

CREATE OR REPLACE FUNCTION enforce_permanent_replacement_case_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'permanent replacement case is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'READY' OR NEW.version <> 1 OR NEW.finalized_at IS NOT NULL OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan JOIN integration_operations operation
              ON operation.id = NEW.integration_operation_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'READY' AND operation.target_type = 'POOL'
              AND operation.operation_type IN ('REPLACE_PERMANENTLY', 'FINALIZE_RECOVERY_BOOTSTRAP')
              AND operation.status = 'RUNNING'
        ) THEN RAISE EXCEPTION 'invalid permanent replacement case insert'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.plan_id IS DISTINCT FROM OLD.plan_id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.version <> OLD.version + 1 OR NOT (
          (OLD.status = 'READY' AND NEW.status = 'ROTATING') OR
          (OLD.status = 'ROTATING' AND NEW.status IN ('ROTATING', 'RECONCILE_REQUIRED', 'OPERATOR_REVIEW_REQUIRED', 'READY_TO_COMMIT')) OR
          (OLD.status IN ('RECONCILE_REQUIRED', 'OPERATOR_REVIEW_REQUIRED') AND NEW.status = 'ROTATING')
          OR (OLD.status = 'READY_TO_COMMIT' AND NEW.status = 'PROVIDER_COMMIT_PENDING')
          OR (OLD.status = 'PROVIDER_COMMIT_PENDING' AND NEW.status = 'READY_TO_ISSUE')
          OR (OLD.status = 'READY_TO_ISSUE' AND NEW.status = 'FINALIZED')
       ) OR ((NEW.status = 'FINALIZED') <> (NEW.finalized_at IS NOT NULL)) THEN
        RAISE EXCEPTION 'illegal permanent replacement case transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER permanent_replacement_cases_phase2g
BEFORE INSERT OR UPDATE OR DELETE ON permanent_replacement_cases
FOR EACH ROW EXECUTE FUNCTION enforce_permanent_replacement_case_phase2g();

CREATE OR REPLACE FUNCTION enforce_recovery_rotation_progress_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Seat prepare progress is append-preserving'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PREPARE_PENDING' OR NEW.attempt_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_plan_seats planned
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = planned.plan_id
            JOIN integration_operations child ON child.id = NEW.derived_operation_id
            JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
            JOIN seats seat ON seat.id = planned.seat_id JOIN members target ON target.id = planned.to_member_id
            JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
            WHERE planned.plan_id = NEW.plan_id AND planned.seat_id = NEW.seat_id
              AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND child.integration_client_id = finalization.integration_client_id
              AND child.operation_type = 'PREPARE_PERMANENT_REPLACEMENT' AND child.target_type = 'SEAT'
              AND child.target_id = seat.id AND child.target_external_id = seat.external_id
              AND child.status = 'RUNNING' AND child.fencing_token > 0
              AND child.lease_owner IS NOT NULL AND child.lease_expires_at > CURRENT_TIMESTAMP
              AND child.request_snapshot ->> 'protocol_version' = 'trusted-pool/permanent-seat-prepare/v1'
              AND child.request_snapshot ->> 'plan_id' = plan.external_id
              AND child.request_snapshot ->> 'pool_id' = (SELECT external_id FROM pools WHERE id = plan.pool_id)
              AND child.request_snapshot ->> 'seat_id' = seat.external_id
              AND child.request_snapshot ->> 'target_member_id' = target.external_id
              AND (child.request_snapshot ->> 'from_epoch')::bigint = plan.from_epoch
              AND (child.request_snapshot ->> 'to_epoch')::bigint = plan.to_epoch
              AND octet_length(child.request_hash) = 32
        ) THEN RAISE EXCEPTION 'prepare progress lacks exact leased child operation'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.plan_id IS DISTINCT FROM OLD.plan_id OR
       NEW.seat_id IS DISTINCT FROM OLD.seat_id OR NEW.derived_operation_id IS DISTINCT FROM OLD.derived_operation_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NOT (
          (OLD.status = 'PREPARE_PENDING' AND NEW.status IN
             ('PREPARE_PENDING', 'PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED', 'PREPARED', 'FAILED')) OR
          (OLD.status IN ('PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED') AND NEW.status = 'PREPARE_PENDING') OR
          (OLD.status = 'PREPARED' AND NEW.status = 'ACTIVATED') OR
          (OLD.status = 'ACTIVATED' AND NEW.status = 'COMMITTED')
       ) THEN RAISE EXCEPTION 'illegal Seat prepare/activate transition'; END IF;
    IF NEW.status = 'PREPARED' AND OLD.status IS DISTINCT FROM 'PREPARED' AND NOT EXISTS (
      SELECT 1 FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
      JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = planned.plan_id
      JOIN integration_operations preparation_operation
        ON preparation_operation.id = preparation.integration_operation_id
      WHERE planned.plan_id = NEW.plan_id AND planned.seat_id = NEW.seat_id
        AND preparation.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
        AND preparation_operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
        AND NEW.principal_user_id = seat.sub2api_principal_id
        AND NEW.subscription_id = seat.sub2api_subscription_id
        AND NEW.api_key_id = seat.sub2api_api_key_id
        AND NEW.api_key_version = planned.expected_active_api_key_version + 1
    ) THEN RAISE EXCEPTION 'PREPARED Seat is not bound to Pool preparation and stable provider IDs'; END IF;
    IF NEW.status = 'ACTIVATED' AND OLD.status = 'PREPARED' AND NOT EXISTS (
      SELECT 1 FROM recovery_pool_activation_attempts activation
      JOIN recovery_pool_activation_seats proof ON proof.activation_attempt_id = activation.id
      JOIN recovery_plan_seats planned
        ON planned.plan_id = proof.plan_id AND planned.seat_id = proof.seat_id
      WHERE activation.plan_id = NEW.plan_id AND proof.seat_id = NEW.seat_id
        AND activation.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
        AND proof.target_member_id = planned.to_member_id
        AND proof.prepared_reference = NEW.prepared_reference
        AND proof.principal_user_id = NEW.principal_user_id
        AND proof.subscription_id = NEW.subscription_id AND proof.api_key_id = NEW.api_key_id
        AND proof.api_key_version = NEW.api_key_version
        AND proof.credential_fingerprint = NEW.credential_fingerprint
        AND proof.current_concurrency = 0 AND proof.pending_settlements = 0
    ) THEN RAISE EXCEPTION 'ACTIVATED Seat lacks exact Pool activation proof'; END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER recovery_seat_rotation_progress_lifecycle ON recovery_seat_rotation_progress;
CREATE TRIGGER recovery_seat_rotation_progress_phase2g
BEFORE INSERT OR UPDATE OR DELETE ON recovery_seat_rotation_progress
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_rotation_progress_phase2g();

CREATE OR REPLACE FUNCTION enforce_pool_preparation_attempt_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Pool preparation attempt is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.version <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
            JOIN integration_operations preparation ON preparation.id = NEW.integration_operation_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND preparation.operation_type = 'PREPARE_PERMANENT_REPLACEMENT_SET'
              AND preparation.target_type = 'POOL' AND preparation.target_id = plan.pool_id
              AND preparation.status = 'RUNNING' AND preparation.fencing_token > 0
              AND preparation.request_snapshot ->> 'protocol_version' =
                    'trusted-pool/permanent-seat-rotation/v1'
              AND preparation.request_snapshot ->> 'child_set_hash' = encode(NEW.intent_set_hash, 'hex')
              AND (SELECT count(*) FROM recovery_plan_seats planned
                   JOIN recovery_seat_rotation_progress progress
                     ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
                   WHERE planned.plan_id = plan.id
                     AND progress.status = 'PREPARE_PENDING') =
                  (SELECT count(*) FROM recovery_plan_seats WHERE plan_id = plan.id)
        ) THEN RAISE EXCEPTION 'invalid Pool preparation attempt'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.plan_id IS DISTINCT FROM OLD.plan_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.intent_set_hash IS DISTINCT FROM OLD.intent_set_hash OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.version <> OLD.version + 1 OR NOT (
          (OLD.status = 'PENDING' AND NEW.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED', 'PREPARED', 'FAILED')) OR
          (OLD.status IN ('RETRYABLE', 'RECONCILE_REQUIRED') AND NEW.status IN ('PENDING', 'PREPARED', 'FAILED'))
       ) THEN RAISE EXCEPTION 'illegal Pool preparation transition'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_pool_preparation_attempts_phase2g
BEFORE INSERT OR UPDATE OR DELETE ON recovery_pool_preparation_attempts
FOR EACH ROW EXECUTE FUNCTION enforce_pool_preparation_attempt_phase2g();

CREATE OR REPLACE FUNCTION enforce_pool_activation_attempt_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Pool activation attempt is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.version <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
            JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = plan.id
            JOIN integration_operations activation ON activation.id = NEW.integration_operation_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND preparation.status = 'PREPARED'
              AND activation.operation_type = 'ACTIVATE_PERMANENT_REPLACEMENT'
              AND activation.target_type = 'POOL' AND activation.target_id = plan.pool_id
              AND activation.status = 'RUNNING' AND activation.fencing_token > 0
              AND activation.request_snapshot ->> 'prepared_set_hash' = encode(NEW.prepared_set_hash, 'hex')
              AND (SELECT count(*) FROM recovery_plan_seats planned
                   JOIN recovery_seat_rotation_progress progress
                     ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
                   WHERE planned.plan_id = plan.id AND progress.status = 'PREPARED') =
                  (SELECT count(*) FROM recovery_plan_seats WHERE plan_id = plan.id)
        ) THEN RAISE EXCEPTION 'invalid Pool activation attempt'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.plan_id IS DISTINCT FROM OLD.plan_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.prepared_set_hash IS DISTINCT FROM OLD.prepared_set_hash OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.version <> OLD.version + 1 OR NOT (
          (OLD.status = 'PENDING' AND NEW.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED', 'ACTIVATED', 'FAILED')) OR
          (OLD.status IN ('RETRYABLE', 'RECONCILE_REQUIRED') AND NEW.status IN ('PENDING', 'ACTIVATED', 'FAILED'))
       ) THEN RAISE EXCEPTION 'illegal Pool activation transition'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_pool_activation_attempts_phase2g
BEFORE INSERT OR UPDATE OR DELETE ON recovery_pool_activation_attempts
FOR EACH ROW EXECUTE FUNCTION enforce_pool_activation_attempt_phase2g();

CREATE OR REPLACE FUNCTION enforce_pool_activation_seat_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Pool activation Seat proof is append-only'; END IF;
    IF NOT EXISTS (
      SELECT 1 FROM recovery_pool_activation_attempts activation
      JOIN recovery_plan_seats planned ON planned.plan_id = activation.plan_id
      JOIN recovery_seat_rotation_progress progress
        ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
      WHERE activation.id = NEW.activation_attempt_id AND activation.plan_id = NEW.plan_id
        AND activation.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
        AND planned.seat_id = NEW.seat_id AND planned.to_member_id = NEW.target_member_id
        AND progress.status = 'PREPARED'
        AND progress.prepared_reference = NEW.prepared_reference
        AND progress.principal_user_id = NEW.principal_user_id
        AND progress.subscription_id = NEW.subscription_id
        AND progress.api_key_id = NEW.api_key_id AND progress.api_key_version = NEW.api_key_version
        AND progress.credential_fingerprint = NEW.credential_fingerprint
    ) THEN RAISE EXCEPTION 'activation Seat proof is not bound to exact PREPARED Seat'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_pool_activation_seats_phase2g
BEFORE INSERT OR UPDATE OR DELETE ON recovery_pool_activation_seats
FOR EACH ROW EXECUTE FUNCTION enforce_pool_activation_seat_phase2g();

CREATE OR REPLACE FUNCTION prevent_activated_recovery_plan_failure_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'FAILED' AND OLD.status IS DISTINCT FROM 'FAILED' AND (
       EXISTS (SELECT 1 FROM recovery_seat_rotation_progress progress
               WHERE progress.plan_id = NEW.id AND progress.status IN ('ACTIVATED', 'COMMITTED')) OR
       EXISTS (SELECT 1 FROM recovery_pool_activation_attempts activation
               WHERE activation.plan_id = NEW.id AND activation.status = 'ACTIVATED')
    ) THEN RAISE EXCEPTION 'activated recovery plan must remain frozen until atomic finalization'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_plan_activated_failure_phase2g
BEFORE UPDATE ON recovery_epoch_plans FOR EACH ROW
EXECUTE FUNCTION prevent_activated_recovery_plan_failure_phase2g();

CREATE OR REPLACE FUNCTION enforce_provider_commit_attempt_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'provider commit attempt is immutable'; END IF;
  IF TG_OP='INSERT' AND (NEW.status<>'PENDING' OR NOT EXISTS (
    SELECT 1 FROM recovery_epoch_plans plan JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
    JOIN recovery_pool_activation_attempts activation ON activation.id=NEW.activation_attempt_id
    JOIN integration_operations operation ON operation.id=NEW.integration_operation_id
    WHERE plan.id=NEW.plan_id AND plan.status='FINALIZED' AND replacement.status='PROVIDER_COMMIT_PENDING'
      AND activation.plan_id=plan.id AND activation.status='ACTIVATED'
      AND activation.prepared_set_hash=NEW.prepared_set_hash
      AND operation.operation_type='COMMIT_PERMANENT_REPLACEMENT_PROVIDER' AND operation.status='RUNNING')) THEN
    RAISE EXCEPTION 'invalid provider commit attempt'; END IF;
  IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.plan_id<>OLD.plan_id OR
    NEW.activation_attempt_id<>OLD.activation_attempt_id OR NEW.integration_operation_id<>OLD.integration_operation_id OR
    NEW.prepared_set_hash<>OLD.prepared_set_hash OR NEW.version<>OLD.version+1 OR NOT (
      (OLD.status='PENDING' AND NEW.status IN ('PENDING','RETRYABLE','RECONCILE_REQUIRED','RELEASED','FAILED')) OR
      (OLD.status IN ('RETRYABLE','RECONCILE_REQUIRED') AND NEW.status IN ('PENDING','RELEASED','FAILED')))) THEN
    RAISE EXCEPTION 'illegal provider commit transition'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER recovery_pool_provider_commit_attempts_phase2g BEFORE INSERT OR UPDATE OR DELETE
ON recovery_pool_provider_commit_attempts FOR EACH ROW EXECUTE FUNCTION enforce_provider_commit_attempt_phase2g();

CREATE OR REPLACE FUNCTION enforce_open_recovery_seat_inventory()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_pool_id uuid; blocking_plan_id uuid;
BEGIN
  target_pool_id := CASE WHEN TG_OP='DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
  PERFORM 1 FROM pools WHERE id=target_pool_id FOR UPDATE;
  SELECT plan.id INTO blocking_plan_id FROM recovery_epoch_plans plan
  LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
  WHERE plan.pool_id=target_pool_id AND (plan.status NOT IN ('FINALIZED','FAILED') OR
    replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')) LIMIT 1;
  IF blocking_plan_id IS NULL THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END; END IF;
  IF TG_OP='UPDATE' AND current_setting('trusted_pool.recovery_inventory_plan_id',true)=blocking_plan_id::text AND
     EXISTS (SELECT 1 FROM recovery_plan_seats planned JOIN recovery_epoch_plans plan ON plan.id=planned.plan_id
       JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
       JOIN recovery_seat_rotation_progress progress ON progress.plan_id=plan.id AND progress.seat_id=planned.seat_id
       WHERE plan.id=blocking_plan_id AND plan.status='READY' AND replacement.status='READY_TO_COMMIT'
        AND progress.status='ACTIVATED' AND planned.seat_id=OLD.id AND OLD.status='FROZEN' AND NEW.status='ACTIVE'
        AND NEW.owner_member_id=planned.to_member_id AND NEW.assignment_epoch=planned.expected_assignment_epoch+1
        AND NEW.active_api_key_version=planned.expected_active_api_key_version+1) THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'Seat inventory cannot drift while recovery provider commit or claim issuance is pending';
END; $$;

-- plan 已完成结构切换但 provider release/claim issuance 尚未闭合时，Pool 仍属于 recovery 执行态。
CREATE OR REPLACE FUNCTION recovery_pool_has_open_execution_phase2g(target_pool_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM recovery_epoch_plans plan
    LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
    WHERE plan.pool_id = target_pool_id AND
      (plan.status NOT IN ('FINALIZED','FAILED') OR
       replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
  );
$$;

CREATE OR REPLACE FUNCTION enforce_resource_account_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_pool_id uuid;
BEGIN
  target_pool_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
  PERFORM 1 FROM pools WHERE id = target_pool_id FOR UPDATE;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'resource account inventory is append-preserving'; END IF;
  IF TG_OP = 'INSERT' AND recovery_pool_has_open_execution_phase2g(NEW.pool_id) THEN
    RAISE EXCEPTION 'resource account cannot be added during recovery execution';
  END IF;
  IF TG_OP = 'UPDATE' AND (
     NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
     NEW.pool_id IS DISTINCT FROM OLD.pool_id OR
     NEW.registration_operation_id IS DISTINCT FROM OLD.registration_operation_id OR
     NEW.provider IS DISTINCT FROM OLD.provider OR
     NEW.provider_account_ref IS DISTINCT FROM OLD.provider_account_ref OR
     NEW.inventory_version IS DISTINCT FROM OLD.inventory_version OR
     NEW.provider_key_ref IS DISTINCT FROM OLD.provider_key_ref OR
     NEW.attestation_digest IS DISTINCT FROM OLD.attestation_digest OR
     NEW.attestation_signature IS DISTINCT FROM OLD.attestation_signature OR
     NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.version <> OLD.version + 1 OR
     OLD.status <> 'ACTIVE' OR NEW.status <> 'RETIRED' OR
     recovery_pool_has_open_execution_phase2g(OLD.pool_id)
  ) THEN RAISE EXCEPTION 'resource account cannot drift during recovery execution'; END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_resource_account_mapping_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_pool_id uuid;
BEGIN
  target_pool_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
  PERFORM 1 FROM pools WHERE id = target_pool_id FOR UPDATE;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'resource account Seat mapping is append-preserving'; END IF;
  IF TG_OP = 'INSERT' AND recovery_pool_has_open_execution_phase2g(NEW.pool_id) THEN
    RAISE EXCEPTION 'resource account Seat mapping cannot be added during recovery execution';
  END IF;
  IF TG_OP = 'UPDATE' AND (
     NEW.resource_account_id IS DISTINCT FROM OLD.resource_account_id OR
     NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
     NEW.mapping_operation_id IS DISTINCT FROM OLD.mapping_operation_id OR
     NEW.inventory_version IS DISTINCT FROM OLD.inventory_version OR
     OLD.status <> 'ACTIVE' OR NEW.status <> 'RETIRED' OR NEW.retired_at IS NULL OR
     recovery_pool_has_open_execution_phase2g(OLD.pool_id)
  ) THEN RAISE EXCEPTION 'resource account Seat mapping cannot drift during recovery execution'; END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION block_new_recovery_plan_during_phase2g_release()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM pools WHERE id = NEW.pool_id FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM recovery_epoch_plans plan
    JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
    WHERE plan.pool_id = NEW.pool_id AND plan.status = 'FINALIZED'
      AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')
  ) THEN
    RAISE EXCEPTION 'new recovery plan cannot begin before provider release and claim issuance close';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_plan_phase2g_release_barrier
BEFORE INSERT ON recovery_epoch_plans FOR EACH ROW
EXECUTE FUNCTION block_new_recovery_plan_during_phase2g_release();

CREATE OR REPLACE FUNCTION validate_recovery_seat_inventory_finalized()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- This constraint is recovery-specific. Ordinary Seat lifecycle updates (for example
  -- ACTIVE -> SUSPEND_PENDING) must not be forced to prove a permanent replacement.
  IF NOT EXISTS (SELECT 1 FROM recovery_plan_seats planned JOIN recovery_epoch_plans plan ON plan.id=planned.plan_id
    WHERE planned.seat_id=NEW.id AND plan.status <> 'FAILED'
      AND OLD.owner_member_id=planned.from_member_id AND OLD.status='FROZEN'
      AND OLD.assignment_epoch=planned.expected_assignment_epoch
      AND OLD.active_api_key_version=planned.expected_active_api_key_version
      AND NEW.owner_member_id=planned.to_member_id AND NEW.status='ACTIVE'
      AND NEW.assignment_epoch=planned.expected_assignment_epoch+1
      AND NEW.active_api_key_version=planned.expected_active_api_key_version+1
      AND NEW.id=OLD.id AND NEW.external_id=OLD.external_id AND NEW.pool_id=OLD.pool_id
      AND NEW.pool_id=planned.pool_id AND NEW.seat_no=OLD.seat_no
      AND NEW.sub2api_principal_id=OLD.sub2api_principal_id
      AND NEW.sub2api_subscription_id=OLD.sub2api_subscription_id
      AND NEW.sub2api_api_key_id=OLD.sub2api_api_key_id
      AND OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS NULL
      AND NEW.version=OLD.version+1 AND NEW.created_at=OLD.created_at) THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM recovery_plan_seats planned JOIN recovery_epoch_plans plan ON plan.id=planned.plan_id
    JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
    JOIN recovery_seat_rotation_progress progress ON progress.plan_id=plan.id AND progress.seat_id=planned.seat_id
    WHERE planned.seat_id=NEW.id AND plan.status='FINALIZED'
      AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE','FINALIZED')
      AND progress.status='COMMITTED' AND OLD.status='FROZEN' AND NEW.status='ACTIVE'
      AND OLD.owner_member_id=planned.from_member_id AND NEW.owner_member_id=planned.to_member_id
      AND NEW.assignment_epoch=planned.expected_assignment_epoch+1
      AND NEW.active_api_key_version=planned.expected_active_api_key_version+1) THEN
    RAISE EXCEPTION 'recovery Seat structural commit lacks exact durable aggregate';
  END IF; RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION assert_phase2g_execution_aggregate(target_plan_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE target recovery_epoch_plans%ROWTYPE; complete integer; drift integer;
BEGIN
    SELECT * INTO target FROM recovery_epoch_plans WHERE id = target_plan_id;
    IF target.id IS NULL THEN RETURN; END IF;
    IF EXISTS (
      SELECT 1 FROM recovery_seat_rotation_progress progress
      JOIN integration_operations prepare ON prepare.id = progress.derived_operation_id
      WHERE progress.plan_id = target.id AND NOT (
        (progress.status = 'PREPARE_PENDING' AND prepare.status = 'RUNNING') OR
        (progress.status IN ('PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED') AND
         prepare.status IN ('RETRYABLE', 'RECONCILE_REQUIRED')) OR
        (progress.status IN ('PREPARED', 'ACTIVATED', 'COMMITTED') AND prepare.status = 'SUCCEEDED') OR
        (progress.status = 'FAILED' AND prepare.status = 'FAILED')
      )
    ) THEN RAISE EXCEPTION 'Seat prepare progress and child operation diverged'; END IF;
    IF EXISTS (
      SELECT 1 FROM recovery_pool_provider_commit_attempts provider_commit
      JOIN integration_operations provider_operation
        ON provider_operation.id = provider_commit.integration_operation_id
      WHERE provider_commit.plan_id = target.id AND NOT (
        (provider_commit.status = 'PENDING' AND provider_operation.status = 'RUNNING') OR
        (provider_commit.status IN ('RETRYABLE','RECONCILE_REQUIRED') AND
         provider_operation.status = provider_commit.status) OR
        (provider_commit.status = 'RELEASED' AND provider_operation.status = 'SUCCEEDED') OR
        (provider_commit.status = 'FAILED' AND provider_operation.status = 'FAILED')
      )
    ) THEN RAISE EXCEPTION 'provider commit attempt and child operation diverged'; END IF;
    IF EXISTS (SELECT 1 FROM permanent_replacement_cases replacement
               WHERE replacement.plan_id = target.id AND replacement.status = 'READY_TO_COMMIT') OR
       EXISTS (SELECT 1 FROM recovery_seat_rotation_progress progress
               WHERE progress.plan_id = target.id AND progress.status = 'ACTIVATED') THEN
      SELECT count(*) INTO complete
      FROM permanent_replacement_cases replacement
      JOIN recovery_pool_activation_attempts activation ON activation.plan_id = replacement.plan_id
      JOIN integration_operations operation ON operation.id = activation.integration_operation_id
      WHERE replacement.plan_id = target.id AND replacement.status = 'READY_TO_COMMIT'
        AND activation.status = 'ACTIVATED' AND operation.status = 'SUCCEEDED'
        AND activation.old_credential_set_invalidated IS TRUE
        AND activation.credential_fingerprint_gate_enforced IS TRUE
        AND activation.authorization_cache_durable_outbox IS TRUE
        AND activation.auth_cache_minimum_events >= 2 * target.expected_seat_count
        AND (SELECT count(*) FROM recovery_plan_seats planned
             JOIN recovery_seat_rotation_progress progress
               ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
             JOIN recovery_pool_activation_seats proof
               ON proof.activation_attempt_id = activation.id AND proof.plan_id = planned.plan_id
              AND proof.seat_id = planned.seat_id AND proof.target_member_id = planned.to_member_id
             WHERE planned.plan_id = target.id AND progress.status IN ('ACTIVATED', 'COMMITTED')
               AND proof.prepared_reference = progress.prepared_reference
               AND proof.principal_user_id = progress.principal_user_id
               AND proof.subscription_id = progress.subscription_id
               AND proof.api_key_id = progress.api_key_id AND proof.api_key_version = progress.api_key_version
               AND proof.credential_fingerprint = progress.credential_fingerprint
               AND proof.current_concurrency = 0 AND proof.pending_settlements = 0)
            = target.expected_seat_count;
      IF complete <> 1 THEN RAISE EXCEPTION 'READY_TO_COMMIT lacks exact atomic Pool activation proof'; END IF;
    END IF;
    IF target.status = 'FINALIZED' AND EXISTS (SELECT 1 FROM permanent_replacement_cases replacement
       WHERE replacement.plan_id=target.id AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')) THEN
      SELECT count(*) INTO complete
      FROM permanent_replacement_cases replacement
      JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
      JOIN integration_operations ceremony ON ceremony.id = target.integration_operation_id
      JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = target.id
      JOIN recovery_pool_activation_attempts activation ON activation.plan_id = target.id
      JOIN integration_operations activation_operation ON activation_operation.id = activation.integration_operation_id
      JOIN pools pool ON pool.id = target.pool_id
      JOIN membership_epochs to_epoch ON to_epoch.recovery_plan_id = target.id AND to_epoch.epoch = target.to_epoch
      JOIN manifests to_manifest ON to_manifest.recovery_plan_id = target.id
      WHERE replacement.plan_id = target.id
        AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')
        AND finalization.status = 'RUNNING' AND ceremony.status = 'SUCCEEDED'
        AND preparation.status = 'PREPARED'
        AND activation.status = 'ACTIVATED' AND activation_operation.status = 'SUCCEEDED'
        AND activation.old_credential_set_invalidated IS TRUE
        AND activation.credential_fingerprint_gate_enforced IS TRUE
        AND activation.authorization_cache_durable_outbox IS TRUE
        AND activation.auth_cache_minimum_events >= 2 * target.expected_seat_count
        AND pool.membership_epoch = target.to_epoch AND pool.credential_epoch_floor = target.to_epoch
        AND to_epoch.status = 'ACTIVE' AND to_manifest.status = 'ACTIVE'
        AND ((replacement.status = 'PROVIDER_COMMIT_PENDING' AND NOT EXISTS (
               SELECT 1 FROM recovery_pool_provider_commit_attempts provider_commit
               WHERE provider_commit.plan_id = target.id AND provider_commit.status = 'RELEASED'))
             OR (replacement.status = 'READY_TO_ISSUE' AND EXISTS (
               SELECT 1 FROM recovery_pool_provider_commit_attempts provider_commit
               JOIN integration_operations provider_operation
                 ON provider_operation.id = provider_commit.integration_operation_id
               WHERE provider_commit.plan_id = target.id AND provider_commit.activation_attempt_id = activation.id
                 AND provider_commit.prepared_set_hash = activation.prepared_set_hash
                 AND provider_commit.status = 'RELEASED' AND provider_operation.status = 'SUCCEEDED'
                 AND provider_commit.all_credentials_enabled IS TRUE
                 AND provider_commit.all_subscriptions_enabled IS TRUE
                 AND provider_commit.old_credential_set_invalidated IS TRUE
                 AND provider_commit.credential_fingerprint_gate_enforced IS TRUE
                 AND provider_commit.authorization_cache_invalidated IS NOT NULL
                 AND provider_commit.authorization_cache_durable_outbox IS TRUE
                 AND provider_commit.auth_cache_minimum_events >= target.expected_seat_count)))
        AND (SELECT count(*) FROM recovery_plan_seats planned
             JOIN recovery_seat_rotation_progress progress
               ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
             JOIN recovery_pool_activation_seats activated
               ON activated.plan_id = planned.plan_id AND activated.seat_id = planned.seat_id
              AND activated.activation_attempt_id = activation.id
             JOIN credential_claims claim ON claim.id = progress.credential_claim_id
             JOIN seats seat ON seat.id = planned.seat_id
             JOIN seat_assignments assignment ON assignment.seat_id = seat.id
               AND assignment.member_id = planned.to_member_id AND assignment.status = 'ACTIVE'
             WHERE planned.plan_id = target.id AND progress.status = 'COMMITTED'
               AND activated.target_member_id = planned.to_member_id
               AND activated.prepared_reference = progress.prepared_reference
               AND activated.principal_user_id = progress.principal_user_id
               AND activated.subscription_id = progress.subscription_id
               AND activated.api_key_id = progress.api_key_id
               AND activated.api_key_version = progress.api_key_version
               AND activated.credential_fingerprint = progress.credential_fingerprint
               AND activated.current_concurrency = 0 AND activated.pending_settlements = 0
               AND claim.integration_operation_id = progress.derived_operation_id
               AND claim.seat_id = planned.seat_id AND claim.target_member_id = planned.to_member_id
               AND claim.status = 'ISSUANCE_PENDING' AND claim.claim_token_hash IS NULL
               AND claim.expires_at IS NULL
               AND seat.status = 'ACTIVE' AND seat.owner_member_id = planned.to_member_id
               AND seat.assignment_epoch = planned.expected_assignment_epoch + 1
               AND seat.active_api_key_version = planned.expected_active_api_key_version + 1
               AND seat.sub2api_principal_id = progress.principal_user_id
               AND seat.sub2api_subscription_id = progress.subscription_id
               AND seat.sub2api_api_key_id = progress.api_key_id) = target.expected_seat_count
        AND (SELECT count(*) FROM recovery_control_evidence evidence
             WHERE evidence.plan_id = target.id AND evidence.status = 'COMMITTED') = target.expected_resource_count
        AND (SELECT count(*) FROM recovery_plan_batch_bindings binding
             JOIN credential_batches batch ON batch.id = binding.credential_batch_id
             WHERE binding.plan_id = target.id AND binding.epoch_role = 'FROM' AND batch.status = 'RETIRED')
              = target.expected_control_batch_count
        AND (SELECT count(*) FROM recovery_plan_batch_bindings binding
             JOIN credential_batches batch ON batch.id = binding.credential_batch_id
             WHERE binding.plan_id = target.id AND binding.epoch_role = 'TO' AND batch.status = 'ACTIVE')
              = target.expected_control_batch_count;
      IF complete<>1 THEN RAISE EXCEPTION 'provider-pending local commit lacks exact sealed claim set'; END IF;
      IF target.ceremony_type = 'ROTATE' AND NOT EXISTS (
        SELECT 1 FROM membership_epochs epoch JOIN manifests manifest ON manifest.epoch_id = epoch.id
        WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.from_epoch
          AND epoch.status = 'RETIRED' AND manifest.status = 'RETIRED'
      ) THEN RAISE EXCEPTION 'provider-pending ROTATE source Epoch/Manifest was not retired atomically'; END IF;
      RETURN;
    END IF;
    IF target.status = 'FINALIZED' THEN
      SELECT count(*) INTO complete
      FROM permanent_replacement_cases replacement
      JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
      JOIN integration_operations ceremony ON ceremony.id = target.integration_operation_id
      JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = target.id
      JOIN recovery_pool_activation_attempts activation ON activation.plan_id = target.id
      JOIN recovery_pool_provider_commit_attempts provider_commit ON provider_commit.plan_id=target.id
      JOIN integration_operations provider_operation ON provider_operation.id=provider_commit.integration_operation_id
      JOIN integration_operations activation_operation ON activation_operation.id = activation.integration_operation_id
      JOIN pools pool ON pool.id = target.pool_id
      JOIN membership_epochs to_epoch ON to_epoch.recovery_plan_id = target.id AND to_epoch.epoch = target.to_epoch
      JOIN manifests to_manifest ON to_manifest.recovery_plan_id = target.id
      WHERE replacement.plan_id = target.id AND replacement.status = 'FINALIZED'
        AND finalization.status = 'SUCCEEDED' AND ceremony.status = 'SUCCEEDED'
        AND preparation.status = 'PREPARED'
        AND activation.status = 'ACTIVATED' AND activation_operation.status = 'SUCCEEDED'
        AND provider_commit.status='RELEASED' AND provider_operation.status='SUCCEEDED'
        AND provider_commit.activation_attempt_id=activation.id
        AND provider_commit.prepared_set_hash=activation.prepared_set_hash
        AND provider_commit.all_credentials_enabled IS TRUE
        AND provider_commit.all_subscriptions_enabled IS TRUE
        AND provider_commit.old_credential_set_invalidated IS TRUE
        AND provider_commit.credential_fingerprint_gate_enforced IS TRUE
        AND provider_commit.authorization_cache_invalidated IS NOT NULL
        AND provider_commit.authorization_cache_durable_outbox IS TRUE
        AND provider_commit.auth_cache_minimum_events >= target.expected_seat_count
        AND activation.old_credential_set_invalidated IS TRUE
        AND activation.credential_fingerprint_gate_enforced IS TRUE
        AND activation.authorization_cache_durable_outbox IS TRUE
        AND activation.auth_cache_minimum_events >= 2 * target.expected_seat_count
        AND pool.membership_epoch = target.to_epoch AND pool.credential_epoch_floor = target.to_epoch
        AND to_epoch.status = 'ACTIVE' AND to_manifest.status = 'ACTIVE'
        AND (SELECT count(*) FROM recovery_plan_seats planned
             JOIN recovery_seat_rotation_progress progress
               ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
             JOIN recovery_pool_activation_seats activated
               ON activated.plan_id = planned.plan_id AND activated.seat_id = planned.seat_id
              AND activated.activation_attempt_id = activation.id
             WHERE planned.plan_id = target.id AND progress.status = 'COMMITTED'
               AND activated.target_member_id = planned.to_member_id
               AND activated.prepared_reference = progress.prepared_reference
               AND activated.principal_user_id = progress.principal_user_id
               AND activated.subscription_id = progress.subscription_id
               AND activated.api_key_id = progress.api_key_id
               AND activated.api_key_version = progress.api_key_version
               AND activated.credential_fingerprint = progress.credential_fingerprint
               AND activated.current_concurrency = 0 AND activated.pending_settlements = 0)
              = target.expected_seat_count
        AND (SELECT count(*) FROM recovery_plan_seats planned
             JOIN recovery_seat_rotation_progress progress
               ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
             JOIN credential_claims claim ON claim.id = progress.credential_claim_id
             JOIN seats seat ON seat.id = planned.seat_id
             JOIN seat_assignments assignment ON assignment.seat_id = seat.id
               AND assignment.member_id = planned.to_member_id AND assignment.status = 'ACTIVE'
             WHERE planned.plan_id = target.id AND progress.status = 'COMMITTED'
               AND claim.integration_operation_id = progress.derived_operation_id
               AND claim.seat_id = planned.seat_id AND claim.target_member_id = planned.to_member_id
               AND claim.status IN ('READY', 'CLAIMED', 'EXPIRED')
               AND claim.expires_at > claim.created_at
               AND seat.status = 'ACTIVE' AND seat.owner_member_id = planned.to_member_id
               AND seat.assignment_epoch = planned.expected_assignment_epoch + 1
               AND seat.active_api_key_version = planned.expected_active_api_key_version + 1
               AND seat.sub2api_principal_id = progress.principal_user_id
               AND seat.sub2api_subscription_id = progress.subscription_id
               AND seat.sub2api_api_key_id = progress.api_key_id) = target.expected_seat_count
        AND (SELECT count(*) FROM recovery_control_evidence evidence
             WHERE evidence.plan_id = target.id AND evidence.status = 'COMMITTED') = target.expected_resource_count
        AND (SELECT count(*) FROM recovery_plan_batch_bindings binding
             JOIN credential_batches batch ON batch.id = binding.credential_batch_id
             WHERE binding.plan_id = target.id AND binding.epoch_role = 'TO' AND batch.status = 'ACTIVE')
               = target.expected_control_batch_count;
      IF complete <> 1 THEN RAISE EXCEPTION 'FINALIZED plan lacks complete Phase2-G aggregate'; END IF;
      IF target.ceremony_type = 'ROTATE' AND NOT EXISTS (
        SELECT 1 FROM membership_epochs epoch JOIN manifests manifest ON manifest.epoch_id = epoch.id
        WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.from_epoch
          AND epoch.status = 'RETIRED' AND manifest.status = 'RETIRED'
      ) THEN RAISE EXCEPTION 'ROTATE source Epoch/Manifest was not retired atomically'; END IF;
    ELSE
      SELECT count(*) INTO drift FROM permanent_replacement_cases replacement
      JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
      JOIN pools pool ON pool.id = target.pool_id
      WHERE replacement.plan_id = target.id AND
        (replacement.status = 'FINALIZED' OR finalization.status = 'SUCCEEDED' OR
         pool.membership_epoch <> target.from_epoch OR pool.credential_epoch_floor > target.from_epoch OR
         EXISTS (SELECT 1 FROM recovery_seat_rotation_progress progress
                 WHERE progress.plan_id = target.id AND progress.status = 'COMMITTED') OR
         EXISTS (SELECT 1 FROM membership_epochs epoch WHERE epoch.recovery_plan_id = target.id
                 AND epoch.status = 'ACTIVE') OR
         EXISTS (SELECT 1 FROM manifests manifest WHERE manifest.recovery_plan_id = target.id
                 AND manifest.status = 'ACTIVE') OR
         EXISTS (SELECT 1 FROM recovery_plan_batch_bindings binding JOIN credential_batches batch
                   ON batch.id = binding.credential_batch_id
                 WHERE binding.plan_id = target.id AND binding.epoch_role = 'TO' AND batch.status = 'ACTIVE') OR
         EXISTS (SELECT 1 FROM recovery_control_evidence evidence
                 WHERE evidence.plan_id = target.id AND evidence.status = 'COMMITTED') OR
         EXISTS (SELECT 1 FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
                 WHERE planned.plan_id = target.id AND seat.status = 'ACTIVE'
                   AND seat.assignment_epoch = planned.expected_assignment_epoch + 1));
      IF drift <> 0 THEN RAISE EXCEPTION 'non-final plan contains partial finalization state'; END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_phase2g_execution_aggregate()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_plan_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'recovery_epoch_plans' THEN target_plan_id := NEW.id;
    ELSIF TG_TABLE_NAME IN ('permanent_replacement_cases', 'recovery_seat_rotation_progress',
                            'recovery_pool_preparation_attempts', 'recovery_pool_activation_attempts',
                            'recovery_pool_activation_seats', 'recovery_pool_provider_commit_attempts',
                            'recovery_control_evidence') THEN
      target_plan_id := NEW.plan_id;
    ELSIF TG_TABLE_NAME = 'integration_operations' THEN
      SELECT COALESCE(plan.id, replacement.plan_id, progress.plan_id, preparation.plan_id,
                      activation.plan_id, provider_commit.plan_id)
      INTO target_plan_id
      FROM (SELECT NEW.id AS operation_id) event
      LEFT JOIN recovery_epoch_plans plan ON plan.integration_operation_id = event.operation_id
      LEFT JOIN permanent_replacement_cases replacement ON replacement.integration_operation_id = event.operation_id
      LEFT JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id = event.operation_id
      LEFT JOIN recovery_pool_preparation_attempts preparation
        ON preparation.integration_operation_id = event.operation_id
      LEFT JOIN recovery_pool_activation_attempts activation ON activation.integration_operation_id = event.operation_id
      LEFT JOIN recovery_pool_provider_commit_attempts provider_commit
        ON provider_commit.integration_operation_id = event.operation_id;
    ELSIF TG_TABLE_NAME = 'credential_claims' THEN
      SELECT progress.plan_id INTO target_plan_id FROM recovery_seat_rotation_progress progress
      JOIN recovery_epoch_plans plan ON plan.id = progress.plan_id
      JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE progress.credential_claim_id = NEW.id AND
        (plan.status NOT IN ('FINALIZED', 'FAILED') OR
         replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'));
    ELSIF TG_TABLE_NAME = 'pools' THEN
      -- Pool 后续可进入下一轮 ceremony；只检查当前非终态计划，不能把历史 FINALIZED 钉成 live 状态。
      SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE plan.pool_id = NEW.id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
      ORDER BY plan.created_at DESC LIMIT 1;
    ELSIF TG_TABLE_NAME = 'membership_epochs' THEN
      SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE plan.id = NEW.recovery_plan_id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'));
      IF target_plan_id IS NULL THEN
        SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan
        LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
        WHERE plan.pool_id = NEW.pool_id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
          replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
          AND NEW.epoch IN (plan.from_epoch, plan.to_epoch)
        ORDER BY plan.created_at DESC LIMIT 1;
      END IF;
    ELSIF TG_TABLE_NAME = 'manifests' THEN
      SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE plan.id = NEW.recovery_plan_id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'));
      IF target_plan_id IS NULL THEN
        SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan JOIN membership_epochs epoch
          ON epoch.id = NEW.epoch_id AND epoch.pool_id = plan.pool_id
        LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
        WHERE (plan.status NOT IN ('FINALIZED', 'FAILED') OR
          replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
          AND epoch.epoch IN (plan.from_epoch, plan.to_epoch)
        ORDER BY plan.created_at DESC LIMIT 1;
      END IF;
    ELSIF TG_TABLE_NAME = 'credential_batches' THEN
      SELECT plan.id INTO target_plan_id FROM recovery_epoch_plans plan
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE plan.id = NEW.recovery_plan_id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'));
      IF target_plan_id IS NULL THEN
        SELECT binding.plan_id INTO target_plan_id FROM recovery_plan_batch_bindings binding
        JOIN recovery_epoch_plans plan ON plan.id = binding.plan_id
        LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
        WHERE binding.credential_batch_id = NEW.id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
          replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
        ORDER BY plan.created_at DESC LIMIT 1;
      END IF;
    ELSIF TG_TABLE_NAME = 'seat_assignments' THEN
      SELECT planned.plan_id INTO target_plan_id FROM recovery_plan_seats planned
      JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE planned.seat_id = NEW.seat_id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
      ORDER BY plan.created_at DESC LIMIT 1;
    ELSIF TG_TABLE_NAME = 'seats' THEN
      SELECT planned.plan_id INTO target_plan_id FROM recovery_plan_seats planned
      JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
      LEFT JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
      WHERE planned.seat_id = NEW.id AND (plan.status NOT IN ('FINALIZED', 'FAILED') OR
        replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE'))
      ORDER BY plan.created_at DESC LIMIT 1;
    END IF;
    IF target_plan_id IS NOT NULL THEN PERFORM assert_phase2g_execution_aggregate(target_plan_id); END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER recovery_plan_final_aggregate_phase2g AFTER UPDATE ON recovery_epoch_plans
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER replacement_case_final_aggregate_phase2g AFTER INSERT OR UPDATE ON permanent_replacement_cases
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER rotation_progress_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_seat_rotation_progress
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER pool_preparation_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_pool_preparation_attempts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER pool_activation_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_pool_activation_attempts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER pool_activation_seat_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_pool_activation_seats
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER provider_commit_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_pool_provider_commit_attempts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER replacement_operation_final_aggregate_phase2g AFTER UPDATE ON integration_operations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER replacement_claim_final_aggregate_phase2g AFTER INSERT OR UPDATE ON credential_claims
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_pool_final_aggregate_phase2g AFTER UPDATE ON pools
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_epoch_final_aggregate_phase2g AFTER INSERT OR UPDATE ON membership_epochs
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_manifest_final_aggregate_phase2g AFTER INSERT OR UPDATE ON manifests
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_batch_final_aggregate_phase2g AFTER INSERT OR UPDATE ON credential_batches
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_evidence_final_aggregate_phase2g AFTER INSERT OR UPDATE ON recovery_control_evidence
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_assignment_final_aggregate_phase2g AFTER INSERT OR UPDATE ON seat_assignments
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();
CREATE CONSTRAINT TRIGGER recovery_seat_final_aggregate_phase2g AFTER UPDATE ON seats
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_phase2g_execution_aggregate();

CREATE OR REPLACE FUNCTION enforce_credential_claim_update_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    claim_operation_type text;
BEGIN
    -- Provider release 已落库后，只有同步 finalization caller 可签发尚未披露的 recovery token。
    IF OLD.status = 'ISSUANCE_PENDING' AND NEW.status = 'READY' AND
       octet_length(NEW.claim_token_hash) = 32 AND OLD.claim_token_hash IS NULL AND
       NEW.claim_intent_hash IS DISTINCT FROM OLD.claim_intent_hash AND
       NEW.expires_at IS DISTINCT FROM OLD.expires_at AND
       NEW.version = OLD.version + 1 AND NEW.expires_at > CURRENT_TIMESTAMP AND
       NEW.expires_at <= CURRENT_TIMESTAMP + interval '30 minutes' AND
       NEW.integration_operation_id = OLD.integration_operation_id AND NEW.seat_id = OLD.seat_id AND
       NEW.target_member_id = OLD.target_member_id AND NEW.claim_operation_id = OLD.claim_operation_id AND
       NEW.credential_fingerprint = OLD.credential_fingerprint AND NEW.envelope_algorithm = OLD.envelope_algorithm AND
       NEW.envelope_key_ref = OLD.envelope_key_ref AND NEW.envelope_ciphertext = OLD.envelope_ciphertext AND
       NEW.envelope_nonce = OLD.envelope_nonce AND NEW.envelope_aad_hash = OLD.envelope_aad_hash AND
       NEW.wrapped_dek_kms = OLD.wrapped_dek_kms AND NEW.lease_owner IS NULL AND OLD.lease_owner IS NULL AND
       EXISTS (SELECT 1 FROM recovery_seat_rotation_progress progress
               JOIN permanent_replacement_cases replacement ON replacement.plan_id = progress.plan_id
               WHERE progress.credential_claim_id = OLD.id AND replacement.status = 'READY_TO_ISSUE') THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'credential_claims is an immutable delivery ledger';
    END IF;

    IF OLD.status IN ('CLAIMED', 'EXPIRED', 'REJECTED') THEN
        RAISE EXCEPTION 'terminal credential claim is immutable';
    END IF;
    IF NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
       NEW.target_member_id IS DISTINCT FROM OLD.target_member_id OR
       NEW.claim_operation_id IS DISTINCT FROM OLD.claim_operation_id OR
       NEW.claim_intent_hash IS DISTINCT FROM OLD.claim_intent_hash OR
       NEW.credential_fingerprint IS DISTINCT FROM OLD.credential_fingerprint OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'credential claim binding and audit metadata are immutable';
    END IF;
    IF NEW.status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED') AND
       (NEW.claim_token_hash IS DISTINCT FROM OLD.claim_token_hash OR
        NEW.envelope_algorithm IS DISTINCT FROM OLD.envelope_algorithm OR
        NEW.envelope_key_ref IS DISTINCT FROM OLD.envelope_key_ref OR
        NEW.envelope_ciphertext IS DISTINCT FROM OLD.envelope_ciphertext OR
        NEW.envelope_nonce IS DISTINCT FROM OLD.envelope_nonce OR
        NEW.envelope_aad_hash IS DISTINCT FROM OLD.envelope_aad_hash OR
        NEW.wrapped_dek_kms IS DISTINCT FROM OLD.wrapped_dek_kms) THEN
        RAISE EXCEPTION 'non-terminal credential claim secret envelope is immutable';
    END IF;
    IF OLD.status = 'ACK_PENDING' AND OLD.ack_response_snapshot IS NOT NULL AND
       NEW.ack_response_snapshot IS DISTINCT FROM OLD.ack_response_snapshot THEN
        RAISE EXCEPTION 'durable credential acknowledgement snapshot is immutable';
    END IF;
    IF OLD.status = 'ACK_PENDING' AND OLD.ack_response_snapshot IS NOT NULL AND
       NEW.status NOT IN ('ACK_PENDING', 'CLAIMED', 'EXPIRED') THEN
        -- 已持久确认成功的上游 ack 不得降级为未知或拒绝；TTL 到期仍可失败关闭并清密。
        RAISE EXCEPTION 'successful credential acknowledgement cannot be downgraded';
    END IF;
    IF NEW.status IN ('ACK_PENDING', 'ACK_RECONCILE_REQUIRED', 'REJECTED') THEN
        claim_operation_type := validate_credential_claim_binding(
            NEW.integration_operation_id, NEW.seat_id, NEW.target_member_id
        );
        IF claim_operation_type IS DISTINCT FROM 'PROVISION' THEN
            RAISE EXCEPTION 'ACK and REJECTED claim states are reserved for Provision';
        END IF;
    END IF;
    IF NEW.status IN ('ACK_PENDING', 'CLAIMED') THEN
        IF claim_operation_type IS NULL THEN
            claim_operation_type := validate_credential_claim_binding(
                NEW.integration_operation_id, NEW.seat_id, NEW.target_member_id
            );
        END IF;

        -- ACK_PENDING 先于上游调用持久化，允许 NULL；明确成功后写入非空快照时必须完整匹配。
        IF claim_operation_type = 'PROVISION' AND NEW.status = 'ACK_PENDING' AND
           NEW.ack_response_snapshot IS NOT NULL AND NOT
           credential_claim_ack_snapshot_matches(
               NEW.ack_response_snapshot, NEW.integration_operation_id, NEW.seat_id,
               NEW.target_member_id, NEW.claim_operation_id, NEW.credential_fingerprint
           ) THEN
            RAISE EXCEPTION 'provision ACK_PENDING requires a matching structured acknowledgement snapshot';
        END IF;
    END IF;
    IF NEW.status = 'CLAIMED' THEN

        IF claim_operation_type IS NULL OR claim_operation_type NOT IN (
            'PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY'
        ) THEN
            RAISE EXCEPTION 'operation type % cannot produce a credential claim',
                COALESCE(claim_operation_type, '<unknown>');
        END IF;
        -- Provision 只有在持久化明确 ack 快照后才能披露；三类换员无需该上游 ack。
        IF claim_operation_type = 'PROVISION' AND
           (OLD.status <> 'ACK_PENDING' OR NOT credential_claim_ack_snapshot_matches(
               OLD.ack_response_snapshot, OLD.integration_operation_id, OLD.seat_id,
               OLD.target_member_id, OLD.claim_operation_id, OLD.credential_fingerprint
           )) THEN
            RAISE EXCEPTION 'provision credential cannot be claimed before durable Sub2API ack';
        END IF;
        IF OLD.status = 'READY' AND claim_operation_type = 'PROVISION' THEN
            RAISE EXCEPTION 'provision credential cannot claim directly from READY';
        END IF;
    END IF;
    IF NOT (
        -- 首次 ack 结果未知可从 READY 进入 RECONCILE 并保留秘密；明确拒绝进入 REJECTED 后强制清密。
        -- 状态边允许换员直领；上面的操作类型门禁确保 Provision 和未知类型失败关闭。
        (OLD.status = 'READY' AND NEW.status IN (
            'READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED',
            'CLAIMED', 'EXPIRED', 'REJECTED'
        )) OR
        (OLD.status = 'ACK_PENDING' AND NEW.status IN (
            'ACK_PENDING', 'ACK_RECONCILE_REQUIRED', 'CLAIMED', 'EXPIRED', 'REJECTED'
        )) OR
        (OLD.status = 'ACK_RECONCILE_REQUIRED' AND NEW.status IN (
            'ACK_RECONCILE_REQUIRED', 'ACK_PENDING', 'CLAIMED', 'EXPIRED', 'REJECTED'
        ))
    ) THEN
        RAISE EXCEPTION 'illegal credential claim status transition: % -> %', OLD.status, NEW.status;
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'credential claim version must increase by exactly one';
    END IF;
    IF NEW.fencing_token < OLD.fencing_token OR
       (NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND NEW.lease_owner IS NOT NULL AND
        NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'credential claim fencing token is stale';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS credential_claims_invariants ON credential_claims;
CREATE TRIGGER credential_claims_invariants
BEFORE UPDATE OR DELETE ON credential_claims
FOR EACH ROW EXECUTE FUNCTION enforce_credential_claim_update_invariants();

-- 旧版本曾允许非 Provision claim 误入 ACK 状态；迁移时先清密终结，避免通用 worker 反复失败。
UPDATE credential_claims claim SET status = 'EXPIRED', claim_token_hash = NULL,
    envelope_algorithm = NULL, envelope_key_ref = NULL, envelope_ciphertext = NULL,
    envelope_nonce = NULL, envelope_aad_hash = NULL, wrapped_dek_kms = NULL,
    lease_owner = NULL, lease_expires_at = NULL, terminal_at = CURRENT_TIMESTAMP,
    version = claim.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations operation
WHERE operation.id = claim.integration_operation_id
  AND operation.operation_type <> 'PROVISION'
  AND claim.status IN ('ACK_PENDING','ACK_RECONCILE_REQUIRED');

CREATE OR REPLACE FUNCTION enforce_pool_credential_epoch_floor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.credential_epoch_floor < OLD.credential_epoch_floor THEN
        RAISE EXCEPTION 'pool credential_epoch_floor cannot decrease';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM credential_batches
        WHERE pool_id = NEW.id
          AND membership_epoch < NEW.credential_epoch_floor
          AND status IN ('SEALED', 'DISTRIBUTED', 'ACTIVE')
    ) THEN
        RAISE EXCEPTION 'pool credential_epoch_floor would strand a writable old credential batch';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS pools_credential_epoch_floor_monotonic ON pools;
CREATE TRIGGER pools_credential_epoch_floor_monotonic
BEFORE UPDATE OF credential_epoch_floor ON pools
FOR EACH ROW EXECUTE FUNCTION enforce_pool_credential_epoch_floor();

CREATE OR REPLACE FUNCTION enforce_credential_batch_epoch_floor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    epoch_floor integer;
BEGIN
    SELECT credential_epoch_floor INTO epoch_floor
    FROM pools
    WHERE id = NEW.pool_id
    FOR SHARE;

    IF NEW.status IN ('SEALED', 'DISTRIBUTED', 'ACTIVE') AND
       NEW.membership_epoch < epoch_floor THEN
        RAISE EXCEPTION 'credential batch epoch % is below pool floor %',
            NEW.membership_epoch, epoch_floor;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS credential_batches_epoch_floor ON credential_batches;
CREATE TRIGGER credential_batches_epoch_floor
BEFORE INSERT OR UPDATE OF pool_id, membership_epoch, status ON credential_batches
FOR EACH ROW EXECUTE FUNCTION enforce_credential_batch_epoch_floor();

CREATE OR REPLACE FUNCTION enforce_control_rotation_evidence_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'control rotation evidence is append-only';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.pool_id IS DISTINCT FROM OLD.pool_id OR
       NEW.resource_account_ref IS DISTINCT FROM OLD.resource_account_ref OR
       NEW.from_membership_epoch IS DISTINCT FROM OLD.from_membership_epoch OR
       NEW.to_membership_epoch IS DISTINCT FROM OLD.to_membership_epoch OR
       NEW.provider_attestation_ref IS DISTINCT FROM OLD.provider_attestation_ref OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'control rotation evidence scope is immutable';
    END IF;
    IF OLD.status <> 'ISSUED' OR NEW.status NOT IN ('COMMITTED', 'INVALIDATED') THEN
        RAISE EXCEPTION 'illegal control rotation evidence status transition: % -> %',
            OLD.status, NEW.status;
    END IF;
    IF NEW.status = 'COMMITTED' AND NOT EXISTS (
        SELECT 1
        FROM pools
        WHERE id = NEW.pool_id
          AND credential_epoch_floor >= NEW.to_membership_epoch
    ) THEN
        RAISE EXCEPTION 'control rotation evidence cannot commit before pool epoch floor advances';
    END IF;
    IF NEW.status = 'COMMITTED' THEN
        -- COMMIT 时重新读取批次现状，不能只信任签发时保存的状态快照。
        PERFORM assert_control_rotation_evidence_has_eight_batches(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS control_rotation_evidence_invariants ON control_rotation_evidence;
CREATE TRIGGER control_rotation_evidence_invariants
BEFORE UPDATE OR DELETE ON control_rotation_evidence
FOR EACH ROW EXECUTE FUNCTION enforce_control_rotation_evidence_invariants();

CREATE OR REPLACE FUNCTION reject_control_rotation_batch_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control rotation evidence batch references are immutable';
END;
$$;

DROP TRIGGER IF EXISTS control_rotation_evidence_batches_immutable ON control_rotation_evidence_batches;
CREATE TRIGGER control_rotation_evidence_batches_immutable
BEFORE UPDATE OR DELETE ON control_rotation_evidence_batches
FOR EACH ROW EXECUTE FUNCTION reject_control_rotation_batch_mutation();

CREATE OR REPLACE FUNCTION protect_issued_control_rotation_batch_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND EXISTS (
        SELECT 1
        FROM control_rotation_evidence_batches evidence_batch
        JOIN control_rotation_evidence evidence
          ON evidence.id = evidence_batch.evidence_id
        WHERE evidence_batch.credential_batch_id = OLD.id
          AND evidence.status = 'ISSUED'
          AND evidence_batch.required_batch_status IS DISTINCT FROM NEW.status
    ) THEN
        RAISE EXCEPTION 'credential batch status is pinned by issued control rotation evidence';
    END IF;
    RETURN NEW;
END;
$$;

-- ISSUED 证据尚可能被永久换员消费，因此临时固定当前状态；COMMITTED 后允许进入下一轮合法退休。
DROP TRIGGER IF EXISTS credential_batches_issued_evidence_status ON credential_batches;
CREATE TRIGGER credential_batches_issued_evidence_status
BEFORE UPDATE OF status ON credential_batches
FOR EACH ROW EXECUTE FUNCTION protect_issued_control_rotation_batch_status();

CREATE OR REPLACE FUNCTION assert_control_rotation_evidence_has_eight_batches(target_evidence_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    reference_count integer;
    valid_reference_count integer;
BEGIN
    SELECT count(*) INTO reference_count
    FROM control_rotation_evidence_batches
    WHERE evidence_id = target_evidence_id;

    IF reference_count <> 8 THEN
        RAISE EXCEPTION 'control rotation evidence % must reference exactly eight batches, got %',
            target_evidence_id, reference_count;
    END IF;

    SELECT count(*) INTO valid_reference_count
    FROM control_rotation_evidence_batches evidence_batch
    JOIN credential_batches batch
      ON batch.id = evidence_batch.credential_batch_id
     AND batch.pool_id = evidence_batch.pool_id
     AND batch.resource_account_ref = evidence_batch.resource_account_ref
     AND batch.membership_epoch = evidence_batch.batch_membership_epoch
     AND batch.batch_type = evidence_batch.batch_type
    WHERE evidence_batch.evidence_id = target_evidence_id
      AND batch.status = evidence_batch.required_batch_status;

    IF valid_reference_count <> 8 THEN
        RAISE EXCEPTION 'control rotation evidence % has batch status drift', target_evidence_id;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_rotation_evidence_parent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM assert_control_rotation_evidence_has_eight_batches(NEW.id);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_rotation_evidence_batch_set()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM assert_control_rotation_evidence_has_eight_batches(COALESCE(NEW.evidence_id, OLD.evidence_id));
    RETURN NULL;
END;
$$;

-- 延迟到事务提交，允许先插入证据主记录，再原子插入八条受约束引用。
DROP TRIGGER IF EXISTS control_rotation_evidence_complete ON control_rotation_evidence;
CREATE CONSTRAINT TRIGGER control_rotation_evidence_complete
AFTER INSERT ON control_rotation_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_rotation_evidence_parent();

DROP TRIGGER IF EXISTS control_rotation_evidence_batch_set_complete ON control_rotation_evidence_batches;
CREATE CONSTRAINT TRIGGER control_rotation_evidence_batch_set_complete
AFTER INSERT OR UPDATE OR DELETE ON control_rotation_evidence_batches
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_rotation_evidence_batch_set();

-- Phase 2-C permits a consumed freeze to outlive the Seat transition, but it
-- originally knew only assignment_cases. A finalized Pool recovery plan is the
-- corresponding atomic consumer for Phase 2-G. READY plans remain non-consuming
-- so a Seat cannot move before the structural finalization transaction commits.
CREATE OR REPLACE FUNCTION assert_suspend_aggregate(target_operation_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    operation_status text;
    operation_migration_state text;
    case_id uuid;
    case_status text;
    case_migration_state text;
    seat_status text;
    expected_assignment_epoch bigint;
    seat_assignment_epoch bigint;
    freeze_consumed boolean;
BEGIN
    SELECT io.status, io.migration_state, suspension.id, suspension.status, suspension.migration_state,
           seat.status, suspension.expected_assignment_epoch, seat.assignment_epoch
    INTO operation_status, operation_migration_state, case_id, case_status, case_migration_state,
         seat_status, expected_assignment_epoch, seat_assignment_epoch
    FROM integration_operations io
    LEFT JOIN suspension_cases suspension ON suspension.integration_operation_id = io.id
    LEFT JOIN seats seat ON seat.id = suspension.seat_id
    WHERE io.id = target_operation_id AND io.operation_type = 'SUSPEND';

    IF operation_status IS NULL OR operation_migration_state = 'LEGACY_UNRECOVERABLE' THEN RETURN; END IF;
    IF case_status IS NULL OR case_migration_state <> 'CURRENT' THEN
        RAISE EXCEPTION 'CURRENT SUSPEND operation requires one CURRENT suspension case';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM assignment_cases
        WHERE freeze_suspension_case_id = case_id AND status <> 'CANCELLED'
    ) OR EXISTS (
        SELECT 1
        FROM recovery_plan_seats planned
        JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
        WHERE planned.freeze_suspension_case_id = case_id
          AND plan.status = 'FINALIZED'
    )
    INTO freeze_consumed;
    IF NOT freeze_consumed AND expected_assignment_epoch IS DISTINCT FROM seat_assignment_epoch THEN
        RAISE EXCEPTION 'SUSPEND case assignment epoch does not match Seat';
    END IF;
    IF (case_status = 'SUSPEND_PENDING' AND
        (seat_status <> 'SUSPEND_PENDING' OR operation_status NOT IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED'))) OR
       (case_status = 'DRAINING' AND
        (seat_status <> 'DRAINING' OR operation_status <> 'RECONCILE_REQUIRED')) OR
       (case_status = 'FROZEN' AND
        (operation_status <> 'SUCCEEDED' OR (seat_status <> 'FROZEN' AND NOT freeze_consumed))) THEN
        RAISE EXCEPTION 'SUSPEND operation/case/Seat aggregate state is inconsistent';
    END IF;
END;
$$;

COMMIT;
