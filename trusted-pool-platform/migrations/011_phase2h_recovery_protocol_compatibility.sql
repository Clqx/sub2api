BEGIN;

-- ADD COLUMN materializes TRUE for rows that predate 011; changing the default
-- immediately afterwards makes every new operation FALSE. Row triggers are not
-- involved in this DDL backfill, and the marker is immutable once installed.
ALTER TABLE integration_operations
    ADD COLUMN legacy_snapshot_compatibility_phase2h boolean NOT NULL DEFAULT TRUE;
ALTER TABLE integration_operations
    ALTER COLUMN legacy_snapshot_compatibility_phase2h SET DEFAULT FALSE;

CREATE FUNCTION enforce_operation_compatibility_marker_phase2h()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.legacy_snapshot_compatibility_phase2h THEN
        RAISE EXCEPTION 'new integration operation cannot claim pre-011 compatibility';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.legacy_snapshot_compatibility_phase2h IS DISTINCT FROM
       OLD.legacy_snapshot_compatibility_phase2h THEN
        RAISE EXCEPTION 'pre-011 operation compatibility marker is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER integration_operations_compatibility_marker_phase2h
BEFORE INSERT OR UPDATE ON integration_operations
FOR EACH ROW EXECUTE FUNCTION enforce_operation_compatibility_marker_phase2h();

-- Go encodes fixed-size SHA-256 arrays as 32 JSON integers. Bind those bytes
-- back to the immutable ledger hash instead of trusting a duplicate text field.
CREATE OR REPLACE FUNCTION recovery_json_hash_matches_phase2h(value jsonb, expected_hash bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw_value text;
    item_position bigint;
    item_value integer;
    item_count integer := 0;
BEGIN
    IF expected_hash IS NULL OR octet_length(expected_hash) <> 32 OR
       jsonb_typeof(value) IS DISTINCT FROM 'array' OR jsonb_array_length(value) <> 32 THEN
        RETURN FALSE;
    END IF;
    FOR raw_value, item_position IN
        SELECT item.raw_value, item.item_position
        FROM jsonb_array_elements_text(value) WITH ORDINALITY AS item(raw_value, item_position)
    LOOP
        IF raw_value !~ '^(0|[1-9][0-9]{0,2})$' THEN RETURN FALSE; END IF;
        item_value := raw_value::integer;
        IF item_value > 255 OR get_byte(expected_hash, item_position::integer - 1) <> item_value THEN
            RETURN FALSE;
        END IF;
        item_count := item_count + 1;
    END LOOP;
    RETURN item_count = 32;
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION recovery_json_hash_value_phase2h(value bytea)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE WHEN octet_length(value) = 32 THEN (
        SELECT jsonb_agg(get_byte(value, position) ORDER BY position)
        FROM generate_series(0, 31) AS positions(position)
    ) END;
$$;

CREATE OR REPLACE FUNCTION recovery_seat_prepare_snapshot_matches_phase2h(
    snapshot jsonb,
    expected_operation_id text,
    expected_request_hash bytea,
    expected_plan_id text,
    expected_ceremony_type text,
    expected_pool_id text,
    expected_from_epoch bigint,
    expected_to_epoch bigint,
    expected_seat_id text,
    expected_target_member_id text,
    expected_assignment_epoch bigint,
    expected_principal_user_id bigint,
    expected_subscription_id bigint,
    expected_api_key_id bigint,
    expected_from_api_key_version bigint,
    allow_legacy boolean
) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF jsonb_typeof(snapshot) IS DISTINCT FROM 'object' THEN RETURN FALSE; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);

    -- Migration 009 accepted exactly these seven snake_case fields.
    -- The Store separately verifies their immutable domain hash against every
    -- omitted operation, ceremony, identity, and version field.
    IF allow_legacy AND key_count = 7 AND snapshot ?& ARRAY[
        'protocol_version', 'plan_id', 'pool_id', 'seat_id', 'target_member_id',
        'from_epoch', 'to_epoch'
    ] THEN
        RETURN snapshot ->> 'protocol_version' = 'trusted-pool/permanent-seat-prepare/v1' AND
               snapshot ->> 'plan_id' = expected_plan_id AND
               snapshot ->> 'pool_id' = expected_pool_id AND
               snapshot ->> 'seat_id' = expected_seat_id AND
               snapshot ->> 'target_member_id' = expected_target_member_id AND
               (snapshot ->> 'from_epoch')::bigint = expected_from_epoch AND
               (snapshot ->> 'to_epoch')::bigint = expected_to_epoch AND
               octet_length(expected_request_hash) = 32;
    END IF;

    -- Current Manager snapshots are the exact encoding/json field names of the
    -- typed request. Exact key count plus ?& rejects aliases and mixed shapes.
    IF key_count = 16 AND snapshot ?& ARRAY[
        'ProtocolVersion', 'OperationID', 'RequestHash', 'PlanID', 'CeremonyType',
        'PoolID', 'FromEpoch', 'ToEpoch', 'SeatID', 'TargetMemberID',
        'ExpectedAssignmentEpoch', 'PrincipalUserID', 'SubscriptionID', 'APIKeyID',
        'FromAPIKeyVersion', 'ToAPIKeyVersion'
    ] THEN
        RETURN snapshot ->> 'ProtocolVersion' = 'trusted-pool/permanent-seat-rotation/v1' AND
               snapshot ->> 'OperationID' = expected_operation_id AND
               recovery_json_hash_matches_phase2h(snapshot -> 'RequestHash', expected_request_hash) AND
               snapshot ->> 'PlanID' = expected_plan_id AND
               snapshot ->> 'CeremonyType' = expected_ceremony_type AND
               snapshot ->> 'PoolID' = expected_pool_id AND
               (snapshot ->> 'FromEpoch')::bigint = expected_from_epoch AND
               (snapshot ->> 'ToEpoch')::bigint = expected_to_epoch AND
               snapshot ->> 'SeatID' = expected_seat_id AND
               snapshot ->> 'TargetMemberID' = expected_target_member_id AND
               (snapshot ->> 'ExpectedAssignmentEpoch')::bigint = expected_assignment_epoch AND
               (snapshot ->> 'PrincipalUserID')::bigint = expected_principal_user_id AND
               (snapshot ->> 'SubscriptionID')::bigint = expected_subscription_id AND
               (snapshot ->> 'APIKeyID')::bigint = expected_api_key_id AND
               (snapshot ->> 'FromAPIKeyVersion')::bigint = expected_from_api_key_version AND
               (snapshot ->> 'ToAPIKeyVersion')::bigint = expected_from_api_key_version + 1;
    END IF;
    RETURN FALSE;
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION recovery_pool_prepare_snapshot_matches_phase2h(
    snapshot jsonb,
    expected_operation_id text,
    expected_request_hash bytea,
    expected_plan_id text,
    expected_ceremony_type text,
    expected_pool_id text,
    expected_from_epoch bigint,
    expected_to_epoch bigint,
    expected_child_set_hash bytea,
    expected_seat_count integer,
    expected_seats jsonb
) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF jsonb_typeof(snapshot) IS DISTINCT FROM 'object' THEN RETURN FALSE; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    IF key_count <> 11 OR NOT snapshot ?& ARRAY[
        'ProtocolVersion', 'OperationID', 'RequestHash', 'PlanID', 'CeremonyType',
        'PoolID', 'FromEpoch', 'ToEpoch', 'ChildSetHash', 'Seats', 'child_set_hash'
    ] THEN RETURN FALSE; END IF;
    RETURN snapshot ->> 'ProtocolVersion' = 'trusted-pool/permanent-seat-rotation/v1' AND
           snapshot ->> 'OperationID' = expected_operation_id AND
           recovery_json_hash_matches_phase2h(snapshot -> 'RequestHash', expected_request_hash) AND
           snapshot ->> 'PlanID' = expected_plan_id AND
           snapshot ->> 'CeremonyType' = expected_ceremony_type AND
           snapshot ->> 'PoolID' = expected_pool_id AND
           (snapshot ->> 'FromEpoch')::bigint = expected_from_epoch AND
           (snapshot ->> 'ToEpoch')::bigint = expected_to_epoch AND
           recovery_json_hash_matches_phase2h(snapshot -> 'ChildSetHash', expected_child_set_hash) AND
           snapshot ->> 'child_set_hash' = encode(expected_child_set_hash, 'hex') AND
           jsonb_typeof(snapshot -> 'Seats') = 'array' AND
           jsonb_array_length(snapshot -> 'Seats') = expected_seat_count AND
           snapshot -> 'Seats' = expected_seats;
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION recovery_pool_activation_snapshot_matches_phase2h(
    snapshot jsonb,
    expected_operation_id text,
    expected_prepare_operation_id text,
    expected_request_hash bytea,
    expected_plan_id text,
    expected_ceremony_type text,
    expected_pool_id text,
    expected_from_epoch bigint,
    expected_to_epoch bigint,
    expected_prepared_set_hash bytea,
    expected_seat_count integer,
    expected_seats jsonb
) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE key_count integer;
BEGIN
    IF jsonb_typeof(snapshot) IS DISTINCT FROM 'object' THEN RETURN FALSE; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    IF key_count <> 12 OR NOT snapshot ?& ARRAY[
        'ProtocolVersion', 'OperationID', 'PrepareOperationID', 'RequestHash', 'PlanID',
        'CeremonyType', 'PoolID', 'FromEpoch', 'ToEpoch', 'PreparedSetHash', 'Seats',
        'prepared_set_hash'
    ] THEN RETURN FALSE; END IF;
    RETURN snapshot ->> 'ProtocolVersion' = 'trusted-pool/permanent-seat-rotation/v1' AND
           snapshot ->> 'OperationID' = expected_operation_id AND
           snapshot ->> 'PrepareOperationID' = expected_prepare_operation_id AND
           recovery_json_hash_matches_phase2h(snapshot -> 'RequestHash', expected_request_hash) AND
           snapshot ->> 'PlanID' = expected_plan_id AND
           snapshot ->> 'CeremonyType' = expected_ceremony_type AND
           snapshot ->> 'PoolID' = expected_pool_id AND
           (snapshot ->> 'FromEpoch')::bigint = expected_from_epoch AND
           (snapshot ->> 'ToEpoch')::bigint = expected_to_epoch AND
           recovery_json_hash_matches_phase2h(snapshot -> 'PreparedSetHash', expected_prepared_set_hash) AND
           snapshot ->> 'prepared_set_hash' = encode(expected_prepared_set_hash, 'hex') AND
           jsonb_typeof(snapshot -> 'Seats') = 'array' AND
           jsonb_array_length(snapshot -> 'Seats') = expected_seat_count AND
           snapshot -> 'Seats' = expected_seats;
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN FALSE;
END;
$$;

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
            JOIN pools pool ON pool.id = plan.pool_id
            WHERE planned.plan_id = NEW.plan_id AND planned.seat_id = NEW.seat_id
              AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND child.integration_client_id = finalization.integration_client_id
              AND child.operation_type = 'PREPARE_PERMANENT_REPLACEMENT' AND child.target_type = 'SEAT'
              AND child.target_id = seat.id AND child.target_external_id = seat.external_id
              AND child.status = 'RUNNING' AND child.fencing_token > 0
              AND child.lease_owner IS NOT NULL AND child.lease_expires_at > CURRENT_TIMESTAMP
              AND recovery_seat_prepare_snapshot_matches_phase2h(
                    child.request_snapshot, child.operation_id, child.request_hash,
                    plan.external_id, plan.ceremony_type, pool.external_id,
                    plan.from_epoch, plan.to_epoch, seat.external_id, target.external_id,
                    planned.expected_assignment_epoch, seat.sub2api_principal_id,
                    seat.sub2api_subscription_id, seat.sub2api_api_key_id,
                    planned.expected_active_api_key_version,
                    child.legacy_snapshot_compatibility_phase2h)
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

CREATE OR REPLACE FUNCTION enforce_pool_preparation_attempt_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Pool preparation attempt is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.version <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
            JOIN integration_operations preparation ON preparation.id = NEW.integration_operation_id
            JOIN pools pool ON pool.id = plan.pool_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND preparation.operation_type = 'PREPARE_PERMANENT_REPLACEMENT_SET'
              AND preparation.target_type = 'POOL' AND preparation.target_id = plan.pool_id
              AND preparation.status = 'RUNNING' AND preparation.fencing_token > 0
              AND recovery_pool_prepare_snapshot_matches_phase2h(
                    preparation.request_snapshot, preparation.operation_id, preparation.request_hash,
                    plan.external_id, plan.ceremony_type, pool.external_id,
                    plan.from_epoch, plan.to_epoch, NEW.intent_set_hash, plan.expected_seat_count,
                    (SELECT jsonb_agg(jsonb_build_object(
                         'ProtocolVersion', 'trusted-pool/permanent-seat-rotation/v1',
                         'OperationID', child.operation_id,
                         'RequestHash', recovery_json_hash_value_phase2h(child.request_hash),
                         'PlanID', plan.external_id,
                         'CeremonyType', plan.ceremony_type,
                         'PoolID', pool.external_id,
                         'FromEpoch', plan.from_epoch,
                         'ToEpoch', plan.to_epoch,
                         'SeatID', seat.external_id,
                         'TargetMemberID', target.external_id,
                         'ExpectedAssignmentEpoch', planned.expected_assignment_epoch,
                         'PrincipalUserID', seat.sub2api_principal_id,
                         'SubscriptionID', seat.sub2api_subscription_id,
                         'APIKeyID', seat.sub2api_api_key_id,
                         'FromAPIKeyVersion', planned.expected_active_api_key_version,
                         'ToAPIKeyVersion', planned.expected_active_api_key_version + 1
                       ) ORDER BY seat.external_id)
                     FROM recovery_plan_seats planned
                     JOIN recovery_seat_rotation_progress progress
                       ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
                     JOIN integration_operations child ON child.id = progress.derived_operation_id
                     JOIN seats seat ON seat.id = planned.seat_id
                     JOIN members target ON target.id = planned.to_member_id
                     WHERE planned.plan_id = plan.id AND progress.status = 'PREPARE_PENDING'))
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

CREATE OR REPLACE FUNCTION enforce_pool_activation_attempt_phase2g()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Pool activation attempt is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.version <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
            JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = plan.id
            JOIN integration_operations preparation_operation
              ON preparation_operation.id = preparation.integration_operation_id
            JOIN integration_operations activation ON activation.id = NEW.integration_operation_id
            JOIN pools pool ON pool.id = plan.pool_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'READY' AND replacement.status = 'ROTATING'
              AND preparation.status = 'PREPARED'
              AND activation.operation_type = 'ACTIVATE_PERMANENT_REPLACEMENT'
              AND activation.target_type = 'POOL' AND activation.target_id = plan.pool_id
              AND activation.status = 'RUNNING' AND activation.fencing_token > 0
              AND recovery_pool_activation_snapshot_matches_phase2h(
                    activation.request_snapshot, activation.operation_id, preparation_operation.operation_id,
                    activation.request_hash, plan.external_id, plan.ceremony_type, pool.external_id,
                    plan.from_epoch, plan.to_epoch, NEW.prepared_set_hash, plan.expected_seat_count,
                    (SELECT jsonb_agg(jsonb_build_object(
                         'SeatID', seat.external_id,
                         'TargetMemberID', target.external_id,
                         'ExpectedAssignmentEpoch', planned.expected_assignment_epoch,
                         'PrincipalUserID', progress.principal_user_id,
                         'SubscriptionID', progress.subscription_id,
                         'APIKeyID', progress.api_key_id,
                         'ActiveAPIKeyVersion', progress.api_key_version,
                         'ChildOperationID', child.operation_id,
                         'ChildRequestHash', recovery_json_hash_value_phase2h(child.request_hash),
                         'CredentialFingerprint', recovery_json_hash_value_phase2h(progress.credential_fingerprint),
                         'PreparedRotationRef', progress.prepared_reference
                       ) ORDER BY seat.external_id)
                     FROM recovery_plan_seats planned
                     JOIN recovery_seat_rotation_progress progress
                       ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
                     JOIN integration_operations child ON child.id = progress.derived_operation_id
                     JOIN seats seat ON seat.id = planned.seat_id
                     JOIN members target ON target.id = planned.to_member_id
                     WHERE planned.plan_id = plan.id AND progress.status = 'PREPARED'
                       AND child.status = 'SUCCEEDED'
                       AND progress.api_key_version = planned.expected_active_api_key_version + 1))
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

COMMENT ON FUNCTION recovery_seat_prepare_snapshot_matches_phase2h(
    jsonb, text, bytea, text, text, text, bigint, bigint, text, text,
    bigint, bigint, bigint, bigint, bigint, boolean
) IS 'Exact typed Seat gate plus pre-011 legacy compatibility; domain hash remains immutable in integration_operations';

COMMIT;
