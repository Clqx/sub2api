BEGIN;

-- Migration 005 was repaired in place so fresh installations can parse its
-- NULL-safe CASE comparison. Existing ledgers retain the published checksum,
-- so replace the function again in a forward migration to converge old and
-- fresh databases on the same aggregate invariant.
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
       aggregate.pending_assignment_type IS DISTINCT FROM (
           CASE aggregate.operation_type WHEN 'ASSIGN_TEMPORARY' THEN 'TEMPORARY' WHEN 'RESTORE' THEN 'PERMANENT' END
       ) OR
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

COMMIT;
