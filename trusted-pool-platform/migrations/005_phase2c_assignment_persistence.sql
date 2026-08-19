BEGIN;

-- Phase2-C 只实现临时换员和正式成员恢复；永久换员及 Membership Epoch 轮换不在本迁移范围内。
ALTER TABLE seats
    ADD COLUMN sub2api_api_key_id bigint UNIQUE
        CHECK (sub2api_api_key_id IS NULL OR sub2api_api_key_id > 0);

COMMENT ON COLUMN seats.sub2api_api_key_id IS
    '稳定 Sub2API API Key 资源 ID；换员只递增 active_api_key_version，不替换三项资源 ID';

-- 只从已经持久化且字段完整的成功 PROVISION 快照回填；旧版本未记录三项 ID 时保持 NULL 并禁止换员。
CREATE TEMP TABLE phase2c_provision_bindings ON COMMIT DROP AS
SELECT io.target_id AS seat_id,
       (io.response_snapshot ->> 'principal_user_id')::bigint AS principal_user_id,
       (io.response_snapshot ->> 'subscription_id')::bigint AS subscription_id,
       (io.response_snapshot ->> 'api_key_id')::bigint AS api_key_id,
       (io.response_snapshot ->> 'assignment_epoch')::integer AS api_key_version
FROM integration_operations io
WHERE io.migration_state = 'CURRENT' AND io.operation_type = 'PROVISION' AND io.status = 'SUCCEEDED'
  AND io.target_id IS NOT NULL AND io.response_snapshot IS NOT NULL
  AND io.response_snapshot ->> 'principal_user_id' ~ '^[1-9][0-9]*$'
  AND io.response_snapshot ->> 'subscription_id' ~ '^[1-9][0-9]*$'
  AND io.response_snapshot ->> 'api_key_id' ~ '^[1-9][0-9]*$'
  AND io.response_snapshot ->> 'assignment_epoch' ~ '^[1-9][0-9]*$';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM seats seat
        JOIN phase2c_provision_bindings binding ON binding.seat_id = seat.id
        WHERE (seat.sub2api_principal_id IS NOT NULL AND
               seat.sub2api_principal_id IS DISTINCT FROM binding.principal_user_id) OR
              (seat.sub2api_subscription_id IS NOT NULL AND
               seat.sub2api_subscription_id IS DISTINCT FROM binding.subscription_id) OR
              seat.active_api_key_version > binding.api_key_version
    ) THEN
        RAISE EXCEPTION 'historical Seat stable Sub2API binding conflicts with persisted PROVISION evidence';
    END IF;
END;
$$;

UPDATE seats seat
SET sub2api_principal_id = COALESCE(seat.sub2api_principal_id, binding.principal_user_id),
    sub2api_subscription_id = COALESCE(seat.sub2api_subscription_id, binding.subscription_id),
    sub2api_api_key_id = binding.api_key_id,
    active_api_key_version = binding.api_key_version,
    updated_at = CURRENT_TIMESTAMP
FROM phase2c_provision_bindings binding
WHERE binding.seat_id = seat.id;

CREATE INDEX idx_seats_missing_stable_sub2api_binding
    ON seats(updated_at)
    WHERE sub2api_principal_id IS NULL OR sub2api_subscription_id IS NULL OR sub2api_api_key_id IS NULL;

COMMENT ON INDEX idx_seats_missing_stable_sub2api_binding IS
    '历史 Seat 缺少可信上游资源绑定；必须受控对账或重新开通，Assignment Begin 会失败关闭';

CREATE TABLE assignment_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_operation_id uuid NOT NULL UNIQUE
        REFERENCES integration_operations(id) ON DELETE RESTRICT,
    seat_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    owner_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    previous_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    target_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    pending_assignment_id uuid NOT NULL UNIQUE REFERENCES seat_assignments(id) ON DELETE RESTRICT,
    freeze_suspension_case_id uuid NOT NULL REFERENCES suspension_cases(id) ON DELETE RESTRICT,
    operation_type text NOT NULL CHECK (operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')),
    status text NOT NULL DEFAULT 'ASSIGNMENT_PENDING' CHECK (
        status IN ('ASSIGNMENT_PENDING', 'SUCCEEDED', 'CANCELLED')
    ),
    expected_assignment_epoch bigint NOT NULL CHECK (expected_assignment_epoch > 0),
    next_assignment_epoch bigint NOT NULL CHECK (next_assignment_epoch > 1),
    membership_epoch integer NOT NULL CHECK (membership_epoch > 0),
    principal_user_id bigint NOT NULL CHECK (principal_user_id > 0),
    subscription_id bigint NOT NULL CHECK (subscription_id > 0),
    api_key_id bigint NOT NULL CHECK (api_key_id > 0),
    expected_api_key_version integer NOT NULL CHECK (expected_api_key_version > 0),
    next_api_key_version integer NOT NULL CHECK (next_api_key_version > 1),
    freeze_operation_id varchar(128) NOT NULL
        CHECK (length(trim(freeze_operation_id)) BETWEEN 1 AND 128),
    freeze_snapshot jsonb NOT NULL CHECK (jsonb_typeof(freeze_snapshot) = 'object'),
    error_code text CHECK (error_code IS NULL OR length(trim(error_code)) BETWEEN 1 AND 128),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (seat_id, pool_id) REFERENCES seats(id, pool_id) ON DELETE RESTRICT,
    CHECK (next_assignment_epoch = expected_assignment_epoch + 1),
    CHECK (next_api_key_version = expected_api_key_version + 1),
    CHECK (expected_api_key_version = expected_assignment_epoch),
    CHECK (next_api_key_version = next_assignment_epoch),
    CHECK (previous_member_id <> target_member_id),
    CHECK ((status = 'ASSIGNMENT_PENDING') OR error_code IS NULL)
);

CREATE UNIQUE INDEX uq_assignment_cases_open_seat
    ON assignment_cases(seat_id) WHERE status = 'ASSIGNMENT_PENDING';
CREATE UNIQUE INDEX uq_assignment_cases_consumed_freeze
    ON assignment_cases(freeze_suspension_case_id) WHERE status <> 'CANCELLED';
CREATE INDEX idx_assignment_cases_target_history
    ON assignment_cases(target_member_id, created_at DESC);
CREATE INDEX idx_integration_operations_assignment_recovery
    ON integration_operations(next_attempt_at, lease_expires_at, created_at)
    WHERE migration_state = 'CURRENT'
      AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')
      AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED');

-- 一个 Seat 同时最多有一个待提交的新 Assignment；旧 ACTIVE Assignment 在成功提交前保持审计连续性。
CREATE UNIQUE INDEX uq_seat_assignments_pending_seat
    ON seat_assignments(seat_id) WHERE status = 'PENDING';

COMMENT ON TABLE assignment_cases IS
    '临时换员/正式恢复的可恢复事务聚合；固定冻结证据、成员目标和代际，不承载永久换员';
COMMENT ON COLUMN assignment_cases.membership_epoch IS
    '换员开始时锁定的 Pool Membership Epoch；临时换员和恢复全程不得修改';
COMMENT ON COLUMN assignment_cases.freeze_suspension_case_id IS
    '唯一消费的 FROZEN suspension evidence；明确未应用并取消后才允许新 operation 重试';

CREATE OR REPLACE FUNCTION valid_assignment_request_snapshot(
    snapshot jsonb,
    expected_operation_id text,
    expected_seat_id text,
    expected_target_member_id text,
    expected_operation_type text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR NOT (
        snapshot ?& ARRAY['version', 'operation_id', 'seat_id', 'target_member_id', 'mode']
    ) THEN
        RETURN false;
    END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot);
    RETURN key_count = 5 AND
           snapshot -> 'version' = '1'::jsonb AND
           jsonb_typeof(snapshot -> 'operation_id') = 'string' AND
           jsonb_typeof(snapshot -> 'seat_id') = 'string' AND
           jsonb_typeof(snapshot -> 'target_member_id') = 'string' AND
           jsonb_typeof(snapshot -> 'mode') = 'string' AND
           snapshot ->> 'operation_id' = expected_operation_id AND
           snapshot ->> 'seat_id' = expected_seat_id AND
           snapshot ->> 'target_member_id' = expected_target_member_id AND
           snapshot ->> 'mode' = expected_operation_type;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_assignment_case_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_operation_type text;
    bound_operation_id text;
    bound_request_snapshot jsonb;
    bound_seat_external_id text;
    bound_target_external_id text;
    bound_owner_member_id uuid;
    bound_pool_membership_epoch integer;
    bound_freeze_operation_id text;
    bound_freeze_snapshot jsonb;
    bound_freeze_epoch bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'assignment case is an immutable workflow ledger';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.status IN ('SUCCEEDED', 'CANCELLED') THEN
            RAISE EXCEPTION 'terminal assignment case is immutable';
        END IF;
        IF NEW.id IS DISTINCT FROM OLD.id OR
           NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
           NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
           NEW.pool_id IS DISTINCT FROM OLD.pool_id OR
           NEW.owner_member_id IS DISTINCT FROM OLD.owner_member_id OR
           NEW.previous_member_id IS DISTINCT FROM OLD.previous_member_id OR
           NEW.target_member_id IS DISTINCT FROM OLD.target_member_id OR
           NEW.pending_assignment_id IS DISTINCT FROM OLD.pending_assignment_id OR
           NEW.freeze_suspension_case_id IS DISTINCT FROM OLD.freeze_suspension_case_id OR
           NEW.operation_type IS DISTINCT FROM OLD.operation_type OR
           NEW.expected_assignment_epoch IS DISTINCT FROM OLD.expected_assignment_epoch OR
           NEW.next_assignment_epoch IS DISTINCT FROM OLD.next_assignment_epoch OR
           NEW.membership_epoch IS DISTINCT FROM OLD.membership_epoch OR
           NEW.principal_user_id IS DISTINCT FROM OLD.principal_user_id OR
           NEW.subscription_id IS DISTINCT FROM OLD.subscription_id OR
           NEW.api_key_id IS DISTINCT FROM OLD.api_key_id OR
           NEW.expected_api_key_version IS DISTINCT FROM OLD.expected_api_key_version OR
           NEW.next_api_key_version IS DISTINCT FROM OLD.next_api_key_version OR
           NEW.freeze_operation_id IS DISTINCT FROM OLD.freeze_operation_id OR
           NEW.freeze_snapshot IS DISTINCT FROM OLD.freeze_snapshot OR
           NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'assignment case intent and frozen baseline are immutable';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'assignment case version must increase by exactly one';
        END IF;
        IF NOT (OLD.status = 'ASSIGNMENT_PENDING' AND
                NEW.status IN ('ASSIGNMENT_PENDING', 'SUCCEEDED', 'CANCELLED')) THEN
            RAISE EXCEPTION 'illegal assignment case transition: % -> %', OLD.status, NEW.status;
        END IF;
    ELSIF NEW.status <> 'ASSIGNMENT_PENDING' OR NEW.version <> 1 THEN
        RAISE EXCEPTION 'new assignment case must begin pending at version one';
    END IF;

    SELECT io.operation_type, io.operation_id, io.request_snapshot,
           seat.external_id, target.external_id, seat.owner_member_id, pool.membership_epoch,
           suspension.operation_id, suspension.freeze_snapshot, suspension.expected_assignment_epoch
    INTO bound_operation_type, bound_operation_id, bound_request_snapshot,
         bound_seat_external_id, bound_target_external_id, bound_owner_member_id, bound_pool_membership_epoch,
         bound_freeze_operation_id, bound_freeze_snapshot, bound_freeze_epoch
    FROM integration_operations io
    JOIN seats seat ON seat.id = NEW.seat_id AND seat.pool_id = NEW.pool_id
    JOIN pools pool ON pool.id = NEW.pool_id
    JOIN membership_epochs membership
      ON membership.pool_id = pool.id AND membership.epoch = NEW.membership_epoch
     AND membership.status = 'ACTIVE'
    JOIN membership_epoch_members snapshot_member
      ON snapshot_member.epoch_id = membership.id AND snapshot_member.member_id = NEW.target_member_id
    JOIN members target ON target.id = snapshot_member.member_id AND target.status = 'ACTIVE'
    JOIN suspension_cases suspension ON suspension.id = NEW.freeze_suspension_case_id
    WHERE io.id = NEW.integration_operation_id
      AND io.operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')
      AND io.target_type = 'SEAT' AND io.target_id = NEW.seat_id
      AND io.target_external_id = seat.external_id AND io.migration_state = 'CURRENT'
      AND suspension.seat_id = NEW.seat_id AND suspension.status = 'FROZEN'
      AND suspension.migration_state = 'CURRENT'
      AND NOT EXISTS (
          SELECT 1 FROM seat_assignments occupied
          WHERE occupied.pool_id = NEW.pool_id AND occupied.member_id = NEW.target_member_id
            AND occupied.status = 'ACTIVE' AND occupied.seat_id <> NEW.seat_id
      );

    IF bound_operation_type IS NULL OR bound_operation_type <> NEW.operation_type OR
       bound_owner_member_id IS DISTINCT FROM NEW.owner_member_id OR
       bound_pool_membership_epoch IS DISTINCT FROM NEW.membership_epoch OR
       bound_freeze_operation_id IS DISTINCT FROM NEW.freeze_operation_id OR
       bound_freeze_snapshot IS DISTINCT FROM NEW.freeze_snapshot OR
       bound_freeze_epoch IS DISTINCT FROM NEW.expected_assignment_epoch OR
       NOT valid_assignment_request_snapshot(
           bound_request_snapshot, bound_operation_id, bound_seat_external_id,
           bound_target_external_id, bound_operation_type
       ) THEN
        RAISE EXCEPTION 'assignment case is not bound to one recoverable frozen Seat operation';
    END IF;
    IF NEW.operation_type = 'RESTORE' AND NEW.target_member_id <> NEW.owner_member_id THEN
        RAISE EXCEPTION 'RESTORE target must be the immutable Seat owner';
    END IF;
    IF NEW.operation_type = 'ASSIGN_TEMPORARY' AND NEW.target_member_id = NEW.owner_member_id THEN
        RAISE EXCEPTION 'temporary assignment cannot change formal Seat ownership';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER assignment_cases_invariants
BEFORE INSERT OR UPDATE OR DELETE ON assignment_cases
FOR EACH ROW EXECUTE FUNCTION enforce_assignment_case_invariants();

CREATE OR REPLACE FUNCTION assert_assignment_aggregate(target_operation_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    aggregate record;
    claim_count integer;
BEGIN
    SELECT io.status AS operation_status, io.migration_state, assignment_case.status AS case_status,
           assignment_case.error_code, assignment_case.operation_type,
           assignment_case.expected_assignment_epoch, assignment_case.next_assignment_epoch,
           seat.status AS seat_status, seat.assignment_epoch AS seat_epoch,
           seat.sub2api_principal_id, assignment_case.principal_user_id,
           seat.sub2api_subscription_id, assignment_case.subscription_id,
           seat.sub2api_api_key_id, assignment_case.api_key_id,
           seat.active_api_key_version, assignment_case.expected_api_key_version,
           assignment_case.next_api_key_version,
           seat.owner_member_id AS current_owner_member_id, assignment_case.owner_member_id,
           pool.membership_epoch AS current_membership_epoch, assignment_case.membership_epoch,
           previous_assignment.status AS previous_assignment_status,
           previous_assignment.assignment_epoch AS previous_assignment_epoch,
           pending_assignment.status AS pending_assignment_status,
           pending_assignment.assignment_epoch AS pending_assignment_epoch,
           pending_assignment.member_id AS pending_member_id,
           pending_assignment.seat_id AS pending_seat_id,
           pending_assignment.pool_id AS pending_pool_id,
           pending_assignment.assignment_type AS pending_assignment_type,
           assignment_case.target_member_id, assignment_case.seat_id, assignment_case.pool_id
    INTO aggregate
    FROM integration_operations io
    LEFT JOIN assignment_cases assignment_case ON assignment_case.integration_operation_id = io.id
    LEFT JOIN seats seat ON seat.id = assignment_case.seat_id
    LEFT JOIN pools pool ON pool.id = assignment_case.pool_id
    LEFT JOIN seat_assignments previous_assignment
      ON previous_assignment.seat_id = assignment_case.seat_id
     AND previous_assignment.member_id = assignment_case.previous_member_id
     AND previous_assignment.assignment_epoch = assignment_case.expected_assignment_epoch
    LEFT JOIN seat_assignments pending_assignment ON pending_assignment.id = assignment_case.pending_assignment_id
    WHERE io.id = target_operation_id
      AND io.operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE');

    IF aggregate.operation_status IS NULL OR aggregate.migration_state = 'LEGACY_UNRECOVERABLE' THEN
        RETURN;
    END IF;
    IF aggregate.case_status IS NULL OR
       aggregate.current_owner_member_id IS DISTINCT FROM aggregate.owner_member_id OR
       aggregate.current_membership_epoch IS DISTINCT FROM aggregate.membership_epoch OR
       aggregate.sub2api_principal_id IS DISTINCT FROM aggregate.principal_user_id OR
       aggregate.sub2api_subscription_id IS DISTINCT FROM aggregate.subscription_id OR
       aggregate.sub2api_api_key_id IS DISTINCT FROM aggregate.api_key_id OR
       aggregate.pending_member_id IS DISTINCT FROM aggregate.target_member_id OR
       aggregate.pending_seat_id IS DISTINCT FROM aggregate.seat_id OR
       aggregate.pending_pool_id IS DISTINCT FROM aggregate.pool_id OR
       aggregate.pending_assignment_type IS DISTINCT FROM
           CASE aggregate.operation_type WHEN 'ASSIGN_TEMPORARY' THEN 'TEMPORARY' WHEN 'RESTORE' THEN 'PERMANENT' END OR
       aggregate.expected_api_key_version IS DISTINCT FROM aggregate.expected_assignment_epoch OR
       aggregate.next_api_key_version IS DISTINCT FROM aggregate.next_assignment_epoch OR
       aggregate.pending_assignment_epoch IS DISTINCT FROM aggregate.next_assignment_epoch THEN
        RAISE EXCEPTION 'assignment operation/case immutable binding is inconsistent';
    END IF;

    SELECT count(*) INTO claim_count
    FROM credential_claims claim
    WHERE claim.integration_operation_id = target_operation_id
      AND claim.seat_id = aggregate.seat_id
      AND claim.target_member_id = aggregate.target_member_id;

    IF aggregate.case_status = 'ASSIGNMENT_PENDING' AND NOT (
        aggregate.operation_status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') AND
        aggregate.seat_status = 'ASSIGNMENT_PENDING' AND
        aggregate.seat_epoch = aggregate.expected_assignment_epoch AND
        aggregate.active_api_key_version = aggregate.expected_api_key_version AND
        aggregate.previous_assignment_status = 'ACTIVE' AND
        aggregate.previous_assignment_epoch = aggregate.expected_assignment_epoch AND
        aggregate.pending_assignment_status = 'PENDING' AND claim_count = 0
    ) THEN
        RAISE EXCEPTION 'pending assignment aggregate is inconsistent';
    ELSIF aggregate.case_status = 'SUCCEEDED' AND NOT (
        aggregate.operation_status = 'SUCCEEDED' AND aggregate.error_code IS NULL AND
        aggregate.seat_status = 'ACTIVE' AND aggregate.seat_epoch = aggregate.next_assignment_epoch AND
        aggregate.active_api_key_version = aggregate.next_api_key_version AND
        aggregate.previous_assignment_status = 'ENDED' AND
        aggregate.previous_assignment_epoch = aggregate.expected_assignment_epoch AND
        aggregate.pending_assignment_status = 'ACTIVE' AND claim_count = 1
    ) THEN
        RAISE EXCEPTION 'succeeded assignment aggregate is inconsistent';
    ELSIF aggregate.case_status = 'CANCELLED' AND NOT (
        aggregate.operation_status = 'FAILED' AND aggregate.error_code IS NULL AND
        aggregate.seat_status = 'FROZEN' AND aggregate.seat_epoch = aggregate.expected_assignment_epoch AND
        aggregate.active_api_key_version = aggregate.expected_api_key_version AND
        aggregate.previous_assignment_status = 'ACTIVE' AND
        aggregate.previous_assignment_epoch = aggregate.expected_assignment_epoch AND
        aggregate.pending_assignment_status = 'CANCELLED' AND claim_count = 0
    ) THEN
        RAISE EXCEPTION 'cancelled assignment aggregate is inconsistent';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_assignment_aggregate_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_operation_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'integration_operations' THEN
        IF NEW.operation_type NOT IN ('ASSIGN_TEMPORARY', 'RESTORE') THEN RETURN NULL; END IF;
        target_operation_id := NEW.id;
    ELSIF TG_TABLE_NAME = 'assignment_cases' THEN
        target_operation_id := NEW.integration_operation_id;
    ELSIF TG_TABLE_NAME = 'credential_claims' THEN
        target_operation_id := NEW.integration_operation_id;
        IF NOT EXISTS (
            SELECT 1 FROM integration_operations io WHERE io.id = target_operation_id
              AND io.operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')
        ) THEN RETURN NULL; END IF;
    ELSIF TG_TABLE_NAME = 'pools' THEN
        FOR target_operation_id IN
            SELECT integration_operation_id FROM assignment_cases WHERE pool_id = NEW.id
        LOOP
            PERFORM assert_assignment_aggregate(target_operation_id);
        END LOOP;
        RETURN NULL;
    ELSIF TG_TABLE_NAME = 'seats' THEN
        FOR target_operation_id IN
            SELECT integration_operation_id FROM assignment_cases WHERE seat_id = NEW.id
        LOOP
            PERFORM assert_assignment_aggregate(target_operation_id);
        END LOOP;
        RETURN NULL;
    ELSE
        FOR target_operation_id IN
            SELECT integration_operation_id FROM assignment_cases
            WHERE pending_assignment_id = NEW.id OR seat_id = NEW.seat_id
        LOOP
            PERFORM assert_assignment_aggregate(target_operation_id);
        END LOOP;
        RETURN NULL;
    END IF;
    PERFORM assert_assignment_aggregate(target_operation_id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER integration_operations_assignment_aggregate
AFTER INSERT OR UPDATE ON integration_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();
CREATE CONSTRAINT TRIGGER assignment_cases_aggregate
AFTER INSERT OR UPDATE ON assignment_cases DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();
CREATE CONSTRAINT TRIGGER seats_assignment_aggregate
AFTER UPDATE OF status, assignment_epoch, owner_member_id, active_api_key_version ON seats DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();
CREATE CONSTRAINT TRIGGER pools_assignment_aggregate
AFTER UPDATE OF membership_epoch ON pools DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();
CREATE CONSTRAINT TRIGGER seat_assignments_assignment_aggregate
AFTER INSERT OR UPDATE ON seat_assignments DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();
CREATE CONSTRAINT TRIGGER credential_claims_assignment_aggregate
AFTER INSERT OR UPDATE ON credential_claims DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_assignment_aggregate_deferred();

CREATE OR REPLACE FUNCTION enforce_seat_sub2api_resource_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('ACTIVE', 'SUSPEND_PENDING', 'DRAINING', 'FROZEN', 'ASSIGNMENT_PENDING') AND
       NEW.active_api_key_version IS DISTINCT FROM NEW.assignment_epoch THEN
        RAISE EXCEPTION 'operable Seat API key version must equal assignment epoch';
    END IF;
    IF ((TG_OP = 'INSERT' AND NEW.status = 'ACTIVE') OR
        (TG_OP = 'UPDATE' AND (NEW.status = 'ASSIGNMENT_PENDING' OR
                              (NEW.status = 'ACTIVE' AND OLD.status <> 'ACTIVE')))) AND
       (NEW.sub2api_principal_id IS NULL OR NEW.sub2api_subscription_id IS NULL OR
        NEW.sub2api_api_key_id IS NULL OR NEW.active_api_key_version <= 0) THEN
        RAISE EXCEPTION 'operable Seat requires complete stable Sub2API resource IDs and API key version';
    END IF;
    IF TG_OP = 'UPDATE' AND (
       (OLD.sub2api_principal_id IS NOT NULL AND NEW.sub2api_principal_id IS DISTINCT FROM OLD.sub2api_principal_id) OR
       (OLD.sub2api_subscription_id IS NOT NULL AND NEW.sub2api_subscription_id IS DISTINCT FROM OLD.sub2api_subscription_id) OR
       (OLD.sub2api_api_key_id IS NOT NULL AND NEW.sub2api_api_key_id IS DISTINCT FROM OLD.sub2api_api_key_id) OR
       NEW.active_api_key_version < OLD.active_api_key_version) THEN
        RAISE EXCEPTION 'stable Sub2API Seat resource binding cannot change or regress';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER seats_sub2api_resource_binding
BEFORE INSERT OR UPDATE OF status, assignment_epoch, sub2api_principal_id, sub2api_subscription_id,
    sub2api_api_key_id, active_api_key_version ON seats
FOR EACH ROW EXECUTE FUNCTION enforce_seat_sub2api_resource_binding();

-- 004 的冻结证据一旦被 assignment case 消费，Seat 可进入换员聚合；证据本身仍保持终态不可变。
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
