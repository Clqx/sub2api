BEGIN;

-- 平台只保存 resolve 的规范化 intent/result；不得落 HTTP 原始 body、header、令牌或上游错误正文。
CREATE TABLE settlement_resolution_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_operation_id uuid NOT NULL UNIQUE
        REFERENCES integration_operations(id) ON DELETE RESTRICT,
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    settlement_id varchar(128) NOT NULL CHECK (length(trim(settlement_id)) BETWEEN 1 AND 128),
    expected_request_id varchar(128) NOT NULL CHECK (length(trim(expected_request_id)) BETWEEN 1 AND 128),
    expected_assignment_epoch bigint NOT NULL CHECK (expected_assignment_epoch > 0),
    expected_actor_client_id varchar(128) NOT NULL
        CHECK (length(trim(expected_actor_client_id)) BETWEEN 1 AND 128),
    reason varchar(1000) NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1000),
    evidence varchar(4000) NOT NULL CHECK (length(trim(evidence)) BETWEEN 1 AND 4000),
    status text NOT NULL DEFAULT 'RESOLUTION_PENDING' CHECK (
        status IN ('RESOLUTION_PENDING', 'SUCCEEDED')
    ),
    error_code varchar(128) CHECK (error_code IS NULL OR length(trim(error_code)) BETWEEN 1 AND 128),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status = 'RESOLUTION_PENDING' OR error_code IS NULL)
);

CREATE UNIQUE INDEX uq_settlement_resolution_live_target
    ON settlement_resolution_cases(seat_id, settlement_id);
CREATE INDEX idx_integration_operations_settlement_recovery
    ON integration_operations(next_attempt_at, lease_expires_at, created_at)
    WHERE migration_state = 'CURRENT' AND operation_type = 'RESOLVE_SETTLEMENT'
      AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED');

CREATE TABLE settlement_resolutions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_operation_id uuid NOT NULL UNIQUE
        REFERENCES integration_operations(id) ON DELETE RESTRICT,
    settlement_resolution_case_id uuid NOT NULL UNIQUE
        REFERENCES settlement_resolution_cases(id) ON DELETE RESTRICT,
    trust_event_id uuid NOT NULL UNIQUE REFERENCES trust_events(id) ON DELETE RESTRICT,
    upstream_seat_id bigint NOT NULL CHECK (upstream_seat_id > 0),
    external_seat_id varchar(128) NOT NULL CHECK (length(trim(external_seat_id)) BETWEEN 1 AND 128),
    settlement_id varchar(128) NOT NULL CHECK (length(trim(settlement_id)) BETWEEN 1 AND 128),
    request_id varchar(128) NOT NULL CHECK (length(trim(request_id)) BETWEEN 1 AND 128),
    assignment_epoch bigint NOT NULL CHECK (assignment_epoch > 0),
    operation_id varchar(128) NOT NULL CHECK (length(trim(operation_id)) BETWEEN 1 AND 128),
    actor_client_id varchar(128) NOT NULL CHECK (length(trim(actor_client_id)) BETWEEN 1 AND 128),
    reason varchar(1000) NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1000),
    evidence varchar(4000) NOT NULL CHECK (length(trim(evidence)) BETWEEN 1 AND 4000),
    resolved_at timestamptz NOT NULL CHECK (isfinite(resolved_at)),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_settlement_resolutions_target
    ON settlement_resolutions(external_seat_id, settlement_id);

COMMENT ON TABLE settlement_resolution_cases IS
    '平台 settlement:resolve 可恢复 intent；reason/evidence 是人工输入，不保存上游原始响应正文';
COMMENT ON TABLE settlement_resolutions IS
    '成功 resolve 的十字段白名单结果；只追加且与 operation/case/trust event 一一绑定';

CREATE OR REPLACE FUNCTION settlement_trust_event_hash(previous_hash bytea, payload jsonb)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT digest(COALESCE(previous_hash, ''::bytea) || convert_to(payload::text, 'UTF8'), 'sha256');
$$;

CREATE OR REPLACE FUNCTION valid_settlement_request_snapshot(
    snapshot jsonb,
    expected_operation_id text,
    expected_seat_id text,
    expected_settlement_id text,
    expected_request_id text,
    expected_assignment_epoch bigint,
    expected_actor_client_id text,
    expected_reason text,
    expected_evidence text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (
        snapshot ?& ARRAY[
            'version', 'operation_id', 'seat_id', 'settlement_id',
            'expected_request_id', 'expected_assignment_epoch', 'expected_actor_client_id',
            'reason', 'evidence'
        ]
    ) THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN key_count = 9 AND snapshot -> 'version' = '1'::jsonb AND
           jsonb_typeof(snapshot -> 'operation_id') = 'string' AND
           jsonb_typeof(snapshot -> 'seat_id') = 'string' AND
           jsonb_typeof(snapshot -> 'settlement_id') = 'string' AND
           jsonb_typeof(snapshot -> 'expected_request_id') = 'string' AND
           jsonb_typeof(snapshot -> 'expected_assignment_epoch') = 'number' AND
           jsonb_typeof(snapshot -> 'expected_actor_client_id') = 'string' AND
           jsonb_typeof(snapshot -> 'reason') = 'string' AND
           jsonb_typeof(snapshot -> 'evidence') = 'string' AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'seat_id' = expected_seat_id AND
           snapshot ->> 'settlement_id' = expected_settlement_id AND
           snapshot ->> 'expected_request_id' = expected_request_id AND
           snapshot ->> 'expected_assignment_epoch' = expected_assignment_epoch::text AND
           snapshot ->> 'expected_actor_client_id' = expected_actor_client_id AND
           snapshot ->> 'reason' = expected_reason AND snapshot ->> 'evidence' = expected_evidence;
END;
$$;

CREATE OR REPLACE FUNCTION valid_settlement_response_snapshot(
    snapshot jsonb,
    expected_upstream_seat_id bigint,
    expected_external_seat_id text,
    expected_settlement_id text,
    expected_operation_id text,
    expected_actor_client_id text,
    expected_assignment_epoch bigint,
    expected_request_id text,
    expected_reason text,
    expected_evidence text,
    expected_resolved_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (
        snapshot ?& ARRAY[
            'seat_id', 'external_seat_id', 'settlement_id', 'operation_id', 'actor_client_id',
            'assignment_epoch', 'request_id', 'reason', 'evidence', 'resolved_at'
        ]
    ) THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN key_count = 10 AND
           jsonb_typeof(snapshot -> 'seat_id') = 'number' AND
           jsonb_typeof(snapshot -> 'external_seat_id') = 'string' AND
           jsonb_typeof(snapshot -> 'settlement_id') = 'string' AND
           jsonb_typeof(snapshot -> 'operation_id') = 'string' AND
           jsonb_typeof(snapshot -> 'actor_client_id') = 'string' AND
           jsonb_typeof(snapshot -> 'assignment_epoch') = 'number' AND
           jsonb_typeof(snapshot -> 'request_id') = 'string' AND
           jsonb_typeof(snapshot -> 'reason') = 'string' AND
           jsonb_typeof(snapshot -> 'evidence') = 'string' AND
           jsonb_typeof(snapshot -> 'resolved_at') = 'string' AND
           snapshot ->> 'seat_id' = expected_upstream_seat_id::text AND
           snapshot ->> 'external_seat_id' = expected_external_seat_id AND
           snapshot ->> 'settlement_id' = expected_settlement_id AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'actor_client_id' = expected_actor_client_id AND
           snapshot ->> 'assignment_epoch' = expected_assignment_epoch::text AND
           snapshot ->> 'request_id' = expected_request_id AND
           snapshot ->> 'reason' = expected_reason AND snapshot ->> 'evidence' = expected_evidence AND
           (snapshot ->> 'resolved_at')::timestamptz = expected_resolved_at;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_settlement_resolution_case_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_operation_id text;
    bound_seat_external_id text;
    bound_request_snapshot jsonb;
    bound_seat_epoch bigint;
    bound_seat_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'settlement resolution case is an immutable workflow ledger';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.status = 'SUCCEEDED' THEN
            RAISE EXCEPTION 'terminal settlement resolution case is immutable';
        END IF;
        IF NEW.id IS DISTINCT FROM OLD.id OR
           NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
           NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
           NEW.settlement_id IS DISTINCT FROM OLD.settlement_id OR
           NEW.expected_request_id IS DISTINCT FROM OLD.expected_request_id OR
           NEW.expected_assignment_epoch IS DISTINCT FROM OLD.expected_assignment_epoch OR
           NEW.expected_actor_client_id IS DISTINCT FROM OLD.expected_actor_client_id OR
           NEW.reason IS DISTINCT FROM OLD.reason OR NEW.evidence IS DISTINCT FROM OLD.evidence OR
           NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'settlement resolution intent and binding are immutable';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'settlement resolution case version must increase by exactly one';
        END IF;
        IF NOT (OLD.status = 'RESOLUTION_PENDING' AND
                NEW.status IN ('RESOLUTION_PENDING', 'SUCCEEDED')) THEN
            RAISE EXCEPTION 'illegal settlement resolution case transition: % -> %', OLD.status, NEW.status;
        END IF;
    ELSIF NEW.status <> 'RESOLUTION_PENDING' OR NEW.version <> 1 THEN
        RAISE EXCEPTION 'new settlement resolution case must begin pending at version one';
    END IF;

    SELECT io.operation_id, seat.external_id, io.request_snapshot, seat.assignment_epoch, seat.status
    INTO bound_operation_id, bound_seat_external_id, bound_request_snapshot, bound_seat_epoch, bound_seat_status
    FROM integration_operations io
    JOIN seats seat ON seat.id = NEW.seat_id
    WHERE io.id = NEW.integration_operation_id
      AND io.operation_type = 'RESOLVE_SETTLEMENT' AND io.target_type = 'SEAT'
      AND io.target_id = seat.id AND io.target_external_id = seat.external_id
      AND io.migration_state = 'CURRENT';
    IF bound_operation_id IS NULL OR bound_seat_epoch IS DISTINCT FROM NEW.expected_assignment_epoch OR
       NOT valid_settlement_request_snapshot(
           bound_request_snapshot, bound_operation_id, bound_seat_external_id,
           NEW.settlement_id, NEW.expected_request_id, NEW.expected_assignment_epoch,
           NEW.expected_actor_client_id,
           NEW.reason, NEW.evidence
       ) THEN
        RAISE EXCEPTION 'settlement resolution case is not bound to current Seat epoch and canonical intent';
    END IF;
    -- 新 intent 只能从已阻断且仍在排空的 Seat 发起；响应丢失后暂停流程可能先把 Seat 冻结，
    -- 因此恢复提交允许 DRAINING/FROZEN，但绝不允许 ACTIVE 重新进入结算流程。
    IF (TG_OP = 'INSERT' AND bound_seat_status <> 'DRAINING') OR
       (TG_OP = 'UPDATE' AND bound_seat_status NOT IN ('DRAINING', 'FROZEN')) THEN
        RAISE EXCEPTION 'settlement resolution requires a disabled Seat at the same assignment epoch';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER settlement_resolution_cases_invariants
BEFORE INSERT OR UPDATE OR DELETE ON settlement_resolution_cases
FOR EACH ROW EXECUTE FUNCTION enforce_settlement_resolution_case_invariants();

-- settlement resolve 结果未知期间，禁止换员流程把 Seat 从禁用态重新激活。
CREATE OR REPLACE FUNCTION block_assignment_during_settlement_reconciliation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('ASSIGNMENT_PENDING', 'ACTIVE') AND OLD.status IS DISTINCT FROM NEW.status AND EXISTS (
        SELECT 1
        FROM settlement_resolution_cases resolution_case
        JOIN integration_operations io ON io.id = resolution_case.integration_operation_id
        WHERE resolution_case.seat_id = NEW.id
          AND resolution_case.status = 'RESOLUTION_PENDING'
          AND io.migration_state = 'CURRENT'
          AND io.operation_type = 'RESOLVE_SETTLEMENT'
          AND io.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
    ) THEN
        RAISE EXCEPTION 'Seat has an unresolved settlement resolution operation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER seats_block_assignment_during_settlement_reconciliation
BEFORE UPDATE OF status ON seats
FOR EACH ROW EXECUTE FUNCTION block_assignment_during_settlement_reconciliation();

CREATE OR REPLACE FUNCTION reject_settlement_resolution_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'settlement resolution result is append-only';
END;
$$;

CREATE TRIGGER settlement_resolutions_append_only
BEFORE UPDATE OR DELETE ON settlement_resolutions
FOR EACH ROW EXECUTE FUNCTION reject_settlement_resolution_mutation();

CREATE OR REPLACE FUNCTION assert_settlement_resolution_aggregate(target_operation_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    aggregate record;
BEGIN
    SELECT io.status AS operation_status, io.migration_state, io.integration_client_id,
           io.error_code AS operation_error_code, io.error_detail AS operation_error_detail, io.next_attempt_at,
           io.response_snapshot AS operation_response_snapshot,
           resolution_case.id AS case_id, resolution_case.status AS case_status,
           resolution_case.seat_id, resolution_case.settlement_id AS case_settlement_id,
           resolution_case.expected_request_id,
           resolution_case.expected_assignment_epoch, resolution_case.expected_actor_client_id,
           resolution_case.error_code AS case_error_code, resolution_case.reason AS case_reason,
           resolution_case.evidence AS case_evidence, result.id AS result_id,
           result.settlement_resolution_case_id AS result_case_id,
           result.upstream_seat_id AS result_upstream_seat_id,
           result.external_seat_id, result.settlement_id AS result_settlement_id,
           result.request_id AS result_request_id, result.assignment_epoch AS result_assignment_epoch,
           result.operation_id AS result_operation_id, result.actor_client_id,
           result.reason AS result_reason, result.evidence AS result_evidence,
           result.resolved_at, trust.id AS trust_event_id, trust.actor_type, trust.actor_ref,
           trust.event_type, trust.event_payload, trust.previous_event_hash, trust.event_hash,
           trust.pool_id AS trust_pool_id, trust.seat_id AS trust_seat_id,
           trust.occurred_at AS trust_occurred_at,
           seat.external_id AS seat_external_id, seat.pool_id AS seat_pool_id
    INTO aggregate
    FROM integration_operations io
    LEFT JOIN settlement_resolution_cases resolution_case ON resolution_case.integration_operation_id = io.id
    LEFT JOIN seats seat ON seat.id = resolution_case.seat_id
    LEFT JOIN settlement_resolutions result ON result.integration_operation_id = io.id
    LEFT JOIN trust_events trust ON trust.id = result.trust_event_id
    WHERE io.id = target_operation_id AND io.operation_type = 'RESOLVE_SETTLEMENT';

    IF aggregate.operation_status IS NULL OR aggregate.migration_state = 'LEGACY_UNRECOVERABLE' THEN RETURN; END IF;
    IF aggregate.case_id IS NULL THEN
        RAISE EXCEPTION 'CURRENT settlement resolution operation requires one case';
    END IF;
    IF aggregate.case_status = 'RESOLUTION_PENDING' AND NOT (
        aggregate.operation_status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') AND
        aggregate.result_id IS NULL AND
        aggregate.operation_response_snapshot IS NULL AND
        aggregate.operation_error_detail IS NULL AND
        aggregate.case_error_code IS NOT DISTINCT FROM aggregate.operation_error_code AND
        (aggregate.case_error_code IS NULL OR
         (aggregate.case_error_code = 'OPERATOR_REVIEW_REQUIRED' AND aggregate.next_attempt_at IS NULL) OR
         (aggregate.case_error_code <> 'OPERATOR_REVIEW_REQUIRED' AND aggregate.next_attempt_at IS NOT NULL))
    ) THEN
        RAISE EXCEPTION 'pending settlement resolution aggregate is inconsistent';
    ELSIF aggregate.case_status = 'SUCCEEDED' AND NOT (
        aggregate.operation_status = 'SUCCEEDED' AND aggregate.result_id IS NOT NULL AND
        aggregate.operation_error_code IS NULL AND aggregate.operation_error_detail IS NULL AND
        aggregate.next_attempt_at IS NULL AND
        aggregate.result_case_id = aggregate.case_id AND
        aggregate.external_seat_id = aggregate.seat_external_id AND
        aggregate.result_settlement_id = aggregate.case_settlement_id AND
        aggregate.result_request_id = aggregate.expected_request_id AND
        aggregate.result_assignment_epoch = aggregate.expected_assignment_epoch AND
        aggregate.result_operation_id = (SELECT operation_id FROM integration_operations WHERE id = target_operation_id) AND
        aggregate.actor_client_id = aggregate.expected_actor_client_id AND
        aggregate.result_reason = aggregate.case_reason AND aggregate.result_evidence = aggregate.case_evidence AND
        valid_settlement_response_snapshot(
            aggregate.operation_response_snapshot, aggregate.result_upstream_seat_id,
            aggregate.external_seat_id, aggregate.result_settlement_id,
            aggregate.result_operation_id, aggregate.actor_client_id,
            aggregate.result_assignment_epoch, aggregate.result_request_id,
            aggregate.result_reason, aggregate.result_evidence, aggregate.resolved_at
        ) AND
        aggregate.trust_event_id IS NOT NULL AND aggregate.actor_type = 'SUB2API' AND
        aggregate.actor_ref = aggregate.expected_actor_client_id AND aggregate.event_type = 'SETTLEMENT_RESOLVED' AND
        aggregate.trust_seat_id = aggregate.seat_id AND aggregate.trust_pool_id = aggregate.seat_pool_id AND
        aggregate.trust_occurred_at = aggregate.resolved_at AND
        jsonb_typeof(aggregate.event_payload) = 'object' AND
        (SELECT count(*) FROM jsonb_object_keys(aggregate.event_payload)) = 11 AND
        aggregate.event_payload -> 'version' = '1'::jsonb AND
        aggregate.event_payload ->> 'operation_id' = aggregate.result_operation_id AND
        aggregate.event_payload ->> 'settlement_id' = aggregate.result_settlement_id AND
        aggregate.event_payload ->> 'request_id' = aggregate.result_request_id AND
        aggregate.event_payload ->> 'assignment_epoch' = aggregate.expected_assignment_epoch::text AND
        aggregate.event_payload ->> 'upstream_seat_id' = aggregate.result_upstream_seat_id::text AND
        aggregate.event_payload ->> 'external_seat_id' = aggregate.seat_external_id AND
        aggregate.event_payload ->> 'actor_client_id' = aggregate.expected_actor_client_id AND
        (aggregate.event_payload ->> 'resolved_at')::timestamptz = aggregate.resolved_at AND
        aggregate.event_payload ->> 'reason_sha256' = encode(digest(aggregate.case_reason, 'sha256'), 'hex') AND
        aggregate.event_payload ->> 'evidence_sha256' = encode(digest(aggregate.case_evidence, 'sha256'), 'hex') AND
        aggregate.event_hash = settlement_trust_event_hash(aggregate.previous_event_hash, aggregate.event_payload)
    ) THEN
        RAISE EXCEPTION 'succeeded settlement resolution aggregate is inconsistent';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_settlement_resolution_aggregate_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_operation_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'integration_operations' THEN
        IF NEW.operation_type <> 'RESOLVE_SETTLEMENT' THEN RETURN NULL; END IF;
        target_operation_id := NEW.id;
    ELSIF TG_TABLE_NAME = 'settlement_resolution_cases' THEN
        target_operation_id := NEW.integration_operation_id;
    ELSIF TG_TABLE_NAME = 'settlement_resolutions' THEN
        target_operation_id := NEW.integration_operation_id;
    ELSE
        SELECT integration_operation_id INTO target_operation_id
        FROM settlement_resolutions WHERE trust_event_id = NEW.id;
        IF target_operation_id IS NULL THEN RETURN NULL; END IF;
    END IF;
    PERFORM assert_settlement_resolution_aggregate(target_operation_id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER integration_operations_settlement_aggregate
AFTER INSERT OR UPDATE ON integration_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_settlement_resolution_aggregate_deferred();
CREATE CONSTRAINT TRIGGER settlement_resolution_cases_aggregate
AFTER INSERT OR UPDATE ON settlement_resolution_cases DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_settlement_resolution_aggregate_deferred();
CREATE CONSTRAINT TRIGGER settlement_resolutions_aggregate
AFTER INSERT ON settlement_resolutions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_settlement_resolution_aggregate_deferred();
CREATE CONSTRAINT TRIGGER trust_events_settlement_aggregate
AFTER INSERT ON trust_events DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_settlement_resolution_aggregate_deferred();

COMMIT;
