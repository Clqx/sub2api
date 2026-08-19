BEGIN;

-- Phase2-B 只闭合暂停、排空、冻结；换员、恢复和永久替换仍由后续迁移实现。
ALTER TABLE suspension_cases
    ADD COLUMN integration_operation_id uuid,
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT' CHECK (
        migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE')
    ),
    ADD COLUMN current_concurrency integer CHECK (current_concurrency IS NULL OR current_concurrency >= 0),
    ADD COLUMN pending_settlements integer CHECK (pending_settlements IS NULL OR pending_settlements >= 0),
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

-- 001 遗留 case 没有完整 intent、双屏障和 fence，保留审计但禁止伪装为可恢复工作流。
UPDATE suspension_cases SET migration_state = 'LEGACY_UNRECOVERABLE';

-- 旧记录仅在 operation 身份、类型和 Seat 目标唯一匹配时建立审计外键；UUID 不使用 min 聚合。
UPDATE suspension_cases suspension
SET integration_operation_id = candidate.integration_operation_id
FROM (
    SELECT suspension_inner.id AS suspension_id,
           (array_agg(io.id ORDER BY io.id::text))[1] AS integration_operation_id
    FROM suspension_cases suspension_inner
    JOIN seats seat ON seat.id = suspension_inner.seat_id
    JOIN integration_operations io
      ON io.operation_id = suspension_inner.operation_id
     AND io.operation_type = 'SUSPEND'
     AND io.target_type = 'SEAT'
     AND io.migration_state = 'LEGACY_UNRECOVERABLE'
     AND (io.target_id = suspension_inner.seat_id OR io.target_external_id = seat.external_id)
    GROUP BY suspension_inner.id
    HAVING count(*) = 1
) candidate
WHERE candidate.suspension_id = suspension.id;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM suspension_cases WHERE integration_operation_id IS NULL) THEN
        RAISE EXCEPTION 'legacy suspension case cannot be bound to one legacy SUSPEND operation';
    END IF;
END;
$$;

-- 001 的全局 operation_id 唯一会错误阻止不同 integration client 使用各自命名空间。
ALTER TABLE suspension_cases
    DROP CONSTRAINT IF EXISTS suspension_cases_operation_id_key,
    ALTER COLUMN integration_operation_id SET NOT NULL,
    ADD CONSTRAINT uq_suspension_cases_integration_operation UNIQUE (integration_operation_id),
    ADD CONSTRAINT fk_suspension_cases_integration_operation
        FOREIGN KEY (integration_operation_id) REFERENCES integration_operations(id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION valid_suspend_freeze_snapshot(
    snapshot jsonb,
    observed_concurrency integer,
    observed_pending_settlements integer
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    parsed_time timestamptz;
    window_name text;
    key_count integer;
BEGIN
    IF snapshot IS NULL OR jsonb_typeof(snapshot) <> 'object' OR
       observed_concurrency IS DISTINCT FROM 0 OR observed_pending_settlements IS DISTINCT FROM 0 OR
       snapshot -> 'in_flight' IS DISTINCT FROM '0'::jsonb OR
       snapshot -> 'pending_settlements' IS DISTINCT FROM '0'::jsonb OR
       jsonb_typeof(snapshot -> 'captured_at') <> 'string' OR
       jsonb_typeof(snapshot -> 'usage') <> 'object' OR
       jsonb_typeof(snapshot -> 'window_starts') <> 'object' OR
       NOT ((snapshot -> 'usage') ?& ARRAY['hourly', 'daily', 'weekly', 'monthly']) OR
       NOT ((snapshot -> 'window_starts') ?& ARRAY['hourly', 'daily', 'weekly', 'monthly']) THEN
        RETURN false;
    END IF;

    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot -> 'usage');
    IF key_count <> 4 THEN RETURN false; END IF;
    SELECT count(*) INTO key_count FROM jsonb_object_keys(snapshot -> 'window_starts');
    IF key_count <> 4 THEN RETURN false; END IF;

    FOREACH window_name IN ARRAY ARRAY['hourly', 'daily', 'weekly', 'monthly'] LOOP
        IF jsonb_typeof(snapshot -> 'usage' -> window_name) <> 'number' OR
           jsonb_typeof(snapshot -> 'window_starts' -> window_name) NOT IN ('string', 'null') THEN
            RETURN false;
        END IF;
        IF jsonb_typeof(snapshot -> 'window_starts' -> window_name) = 'string' THEN
            BEGIN
                parsed_time := (snapshot -> 'window_starts' ->> window_name)::timestamptz;
            EXCEPTION WHEN OTHERS THEN
                RETURN false;
            END;
            IF parsed_time IS NULL OR NOT isfinite(parsed_time) THEN RETURN false; END IF;
        END IF;
        BEGIN
            IF (snapshot -> 'usage' ->> window_name)::numeric < 0 THEN RETURN false; END IF;
        EXCEPTION WHEN OTHERS THEN
            RETURN false;
        END;
    END LOOP;

    BEGIN
        parsed_time := (snapshot ->> 'captured_at')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN parsed_time IS NOT NULL AND isfinite(parsed_time);
END;
$$;

ALTER TABLE suspension_cases
    ADD CONSTRAINT ck_suspension_cases_current_shape CHECK (
        migration_state = 'LEGACY_UNRECOVERABLE' OR (
            expected_assignment_epoch > 0 AND blocked_at IS NOT NULL AND (
                (status = 'SUSPEND_PENDING' AND current_concurrency IS NULL AND
                 pending_settlements IS NULL AND frozen_at IS NULL AND freeze_snapshot IS NULL) OR
                (status = 'DRAINING' AND current_concurrency IS NOT NULL AND
                 pending_settlements IS NOT NULL AND frozen_at IS NULL AND freeze_snapshot IS NULL) OR
                (status = 'FROZEN' AND frozen_at IS NOT NULL AND
                 valid_suspend_freeze_snapshot(freeze_snapshot, current_concurrency, pending_settlements))
            )
        )
    );

CREATE UNIQUE INDEX uq_suspension_cases_open_seat
    ON suspension_cases(seat_id)
    WHERE migration_state = 'CURRENT' AND status IN ('SUSPEND_PENDING', 'DRAINING');

CREATE INDEX idx_integration_operations_suspend_recovery
    ON integration_operations(next_attempt_at, lease_expires_at, created_at)
    WHERE migration_state = 'CURRENT'
      AND operation_type = 'SUSPEND'
      AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED');

COMMENT ON COLUMN suspension_cases.integration_operation_id IS
    '暂停 case 与跨服务幂等 operation 的强绑定；租约和 fencing 以 operation 为唯一所有权来源';
COMMENT ON COLUMN suspension_cases.migration_state IS
    '001 遗留 case 缺少完整证据时标记 LEGACY_UNRECOVERABLE，只保留审计且禁止恢复扫描';
COMMENT ON COLUMN suspension_cases.current_concurrency IS
    '最近一次上游屏障观察；NULL 表示未观测，FROZEN 必须为明确的 0';
COMMENT ON COLUMN suspension_cases.pending_settlements IS
    '最近一次未决结算观察；NULL 表示未观测，FROZEN 必须为明确的 0';

CREATE OR REPLACE FUNCTION validate_suspension_case_binding(
    bound_operation_id uuid,
    bound_seat_id uuid,
    bound_operation_key text,
    bound_migration_state text,
    bound_assignment_epoch bigint
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM integration_operations io
        JOIN seats seat ON seat.id = bound_seat_id
        WHERE io.id = bound_operation_id
          AND io.operation_id = bound_operation_key
          AND io.operation_type = 'SUSPEND'
          AND io.target_type = 'SEAT'
          AND io.migration_state = bound_migration_state
          AND io.target_id = seat.id
          AND seat.assignment_epoch = bound_assignment_epoch
          AND (bound_migration_state = 'LEGACY_UNRECOVERABLE' OR io.target_external_id = seat.external_id)
    );
$$;

CREATE OR REPLACE FUNCTION enforce_suspension_case_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_operation_key text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'suspension case is an immutable audit aggregate';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.migration_state <> 'CURRENT' OR NOT validate_suspension_case_binding(
            NEW.integration_operation_id, NEW.seat_id, NEW.operation_id,
            NEW.migration_state, NEW.expected_assignment_epoch
        ) OR NEW.status <> 'SUSPEND_PENDING' THEN
            RAISE EXCEPTION 'new suspension case is not bound to a CURRENT SUSPEND Seat operation';
        END IF;
    ELSE
        IF OLD.migration_state = 'LEGACY_UNRECOVERABLE' THEN
            RAISE EXCEPTION 'legacy suspension case is unrecoverable and immutable';
        END IF;
        IF NEW.id IS DISTINCT FROM OLD.id OR
           NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
           NEW.migration_state IS DISTINCT FROM OLD.migration_state OR
           NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
           NEW.operation_id IS DISTINCT FROM OLD.operation_id OR
           NEW.reason_code IS DISTINCT FROM OLD.reason_code OR
           NEW.reason_detail IS DISTINCT FROM OLD.reason_detail OR
           NEW.evidence_refs IS DISTINCT FROM OLD.evidence_refs OR
           NEW.requested_by IS DISTINCT FROM OLD.requested_by OR
           NEW.expected_assignment_epoch IS DISTINCT FROM OLD.expected_assignment_epoch OR
           NEW.blocked_at IS DISTINCT FROM OLD.blocked_at OR
           NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'suspension case intent and binding are immutable';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'suspension case version must increase by exactly one';
        END IF;
        IF OLD.status = 'FROZEN' THEN
            RAISE EXCEPTION 'terminal suspension case is immutable';
        END IF;
        IF NOT (
            (OLD.status = 'SUSPEND_PENDING' AND NEW.status IN ('SUSPEND_PENDING', 'DRAINING', 'FROZEN')) OR
            (OLD.status = 'DRAINING' AND NEW.status IN ('DRAINING', 'FROZEN'))
        ) THEN
            RAISE EXCEPTION 'illegal suspension case transition: % -> %', OLD.status, NEW.status;
        END IF;
    END IF;

    IF NEW.expected_assignment_epoch <= 0 OR NEW.blocked_at IS NULL THEN
        RAISE EXCEPTION 'CURRENT suspension case requires positive epoch and blocked_at';
    END IF;
    IF NEW.status = 'FROZEN' THEN
        SELECT operation_id INTO expected_operation_key
        FROM integration_operations WHERE id = NEW.integration_operation_id;
        IF NOT valid_suspend_freeze_snapshot(
               NEW.freeze_snapshot, NEW.current_concurrency, NEW.pending_settlements
           ) OR
           NEW.freeze_snapshot ->> 'operation_id' IS DISTINCT FROM expected_operation_key OR
           NEW.freeze_snapshot ->> 'assignment_epoch' IS DISTINCT FROM NEW.expected_assignment_epoch::text OR
           NEW.frozen_at IS NULL THEN
            RAISE EXCEPTION 'FROZEN suspension requires matching zero-barrier snapshot';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER suspension_cases_invariants
BEFORE INSERT OR UPDATE OR DELETE ON suspension_cases
FOR EACH ROW EXECUTE FUNCTION enforce_suspension_case_invariants();

CREATE OR REPLACE FUNCTION assert_suspend_aggregate(target_operation_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    operation_status text;
    operation_migration_state text;
    case_status text;
    case_migration_state text;
    seat_status text;
    expected_assignment_epoch bigint;
    seat_assignment_epoch bigint;
BEGIN
    SELECT io.status, io.migration_state, suspension.status, suspension.migration_state, seat.status,
           suspension.expected_assignment_epoch, seat.assignment_epoch
    INTO operation_status, operation_migration_state, case_status, case_migration_state, seat_status,
         expected_assignment_epoch, seat_assignment_epoch
    FROM integration_operations io
    LEFT JOIN suspension_cases suspension ON suspension.integration_operation_id = io.id
    LEFT JOIN seats seat ON seat.id = suspension.seat_id
    WHERE io.id = target_operation_id AND io.operation_type = 'SUSPEND';

    IF operation_status IS NULL OR operation_migration_state = 'LEGACY_UNRECOVERABLE' THEN
        RETURN;
    END IF;
    IF case_status IS NULL OR case_migration_state <> 'CURRENT' THEN
        RAISE EXCEPTION 'CURRENT SUSPEND operation requires one CURRENT suspension case';
    END IF;
    IF expected_assignment_epoch IS DISTINCT FROM seat_assignment_epoch THEN
        RAISE EXCEPTION 'SUSPEND case assignment epoch does not match Seat';
    END IF;
    IF (case_status = 'SUSPEND_PENDING' AND
        (seat_status <> 'SUSPEND_PENDING' OR operation_status NOT IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED'))) OR
       (case_status = 'DRAINING' AND
        (seat_status <> 'DRAINING' OR operation_status <> 'RECONCILE_REQUIRED')) OR
       (case_status = 'FROZEN' AND
        (seat_status <> 'FROZEN' OR operation_status <> 'SUCCEEDED')) THEN
        RAISE EXCEPTION 'SUSPEND operation/case/Seat aggregate state is inconsistent';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_suspend_aggregate_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_operation_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'integration_operations' THEN
        target_operation_id := NEW.id;
        IF NEW.operation_type <> 'SUSPEND' THEN RETURN NULL; END IF;
    ELSIF TG_TABLE_NAME = 'suspension_cases' THEN
        target_operation_id := NEW.integration_operation_id;
    ELSE
        FOR target_operation_id IN
            SELECT integration_operation_id FROM suspension_cases
            WHERE seat_id = NEW.id AND migration_state = 'CURRENT'
        LOOP
            PERFORM assert_suspend_aggregate(target_operation_id);
        END LOOP;
        RETURN NULL;
    END IF;
    PERFORM assert_suspend_aggregate(target_operation_id);
    RETURN NULL;
END;
$$;

-- 延迟到提交时核对三表，允许 Store 在同一事务内按 case、Seat、operation 的顺序写入。
CREATE CONSTRAINT TRIGGER integration_operations_suspend_aggregate
AFTER INSERT OR UPDATE ON integration_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_suspend_aggregate_deferred();

CREATE CONSTRAINT TRIGGER suspension_cases_suspend_aggregate
AFTER INSERT OR UPDATE ON suspension_cases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_suspend_aggregate_deferred();

CREATE CONSTRAINT TRIGGER seats_suspend_aggregate
AFTER UPDATE OF status, assignment_epoch ON seats
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_suspend_aggregate_deferred();

COMMIT;
