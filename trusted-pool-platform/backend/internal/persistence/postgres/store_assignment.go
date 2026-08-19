package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/domain"
)

const assignmentCaseColumns = `ac.id, ac.integration_operation_id, ac.seat_id, ac.pool_id,
ac.target_member_id, ac.previous_member_id, ac.pending_assignment_id, ac.freeze_suspension_case_id,
ac.operation_type, ac.status,
ac.expected_assignment_epoch, ac.next_assignment_epoch, ac.membership_epoch, ac.principal_user_id,
ac.subscription_id, ac.api_key_id, ac.expected_api_key_version, ac.next_api_key_version,
ac.freeze_operation_id, ac.freeze_snapshot, ac.error_code, ac.version, ac.created_at, ac.updated_at`

const assignmentTargetColumns = assignmentCaseColumns + `,
s.id, s.external_id, p.external_id, owner.external_id, current_member.external_id, target.external_id,
s.status, s.assignment_epoch, p.membership_epoch, s.sub2api_principal_id, s.sub2api_subscription_id,
s.sub2api_api_key_id, s.active_api_key_version`

const assignmentTargetFrom = `
FROM assignment_cases ac
JOIN integration_operations io ON io.id = ac.integration_operation_id
JOIN seats s ON s.id = ac.seat_id AND s.pool_id = ac.pool_id
JOIN pools p ON p.id = ac.pool_id
JOIN members owner ON owner.id = ac.owner_member_id
JOIN members target ON target.id = ac.target_member_id
JOIN seat_assignments current_assignment ON current_assignment.seat_id = s.id AND current_assignment.status = 'ACTIVE'
JOIN members current_member ON current_member.id = current_assignment.member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
  AND io.operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')
  AND io.target_type = 'SEAT' AND io.migration_state = 'CURRENT'`

type assignmentIdentity struct {
	SeatID, PoolID, OwnerMemberID, CurrentMemberID, TargetMemberID string
}

// BeginAssignment 先持久化可恢复 intent；事务提交后上层才可调用 Sub2API。
func (s *Store) BeginAssignment(ctx context.Context, input application.BeginAssignmentInput) (*application.AssignmentTarget, bool, error) {
	canonical, err := validateBeginAssignment(input)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin assignment transaction: %w", err)
	}
	defer tx.Rollback()

	identity, err := resolveAssignmentIdentity(ctx, tx, input.SeatExternalID, input.TargetMemberExternalID)
	if err != nil {
		return nil, false, err
	}
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, $3, 'SEAT', $4, $5, 'CURRENT', $6, $7::jsonb, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.Kind, identity.SeatID,
		input.SeatExternalID, input.RequestHash[:], canonical))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateAssignmentWriteError("begin assignment operation", scanErr)
	}
	if err := validateAssignmentOperationIntent(op, input, canonical); err != nil {
		return nil, false, err
	}

	poolExternalID, membershipEpoch, err := lockAssignmentPool(ctx, tx, identity.PoolID)
	if err != nil {
		return nil, false, err
	}
	if err := lockAssignmentTargetMembership(ctx, tx, identity.PoolID, membershipEpoch,
		identity.TargetMemberID, input.TargetMemberExternalID, identity.SeatID); err != nil {
		return nil, false, err
	}
	seat, err := lockAssignmentSeat(ctx, tx, identity)
	if err != nil {
		return nil, false, err
	}
	if op.Status == application.OperationSucceeded || op.Status == application.OperationFailed {
		target, loadErr := loadAssignmentTargetTx(ctx, tx, input.Key, op, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if loadErr = validateLoadedAssignmentTarget(input, target); loadErr != nil {
			return nil, false, loadErr
		}
		if loadErr = tx.Commit(); loadErr != nil {
			return nil, false, fmt.Errorf("commit terminal assignment replay: %w", loadErr)
		}
		return target, false, nil
	}
	if err := validateAssignmentStartState(input, identity, seat, poolExternalID, membershipEpoch, created); err != nil {
		return nil, false, err
	}

	if created {
		// Seat 已按统一顺序加锁；此处再检查未决结算，避免未知 resolve 与换员并发恢复授权。
		if err := ensureNoPendingSettlementResolution(ctx, tx, identity.SeatID); err != nil {
			return nil, false, err
		}
		freezeCaseID, freezeOperationID, freezeSnapshot, err := lockAvailableFreezeEvidence(
			ctx, tx, identity.SeatID, seat.AssignmentEpoch)
		if err != nil {
			return nil, false, err
		}
		assignmentType := "TEMPORARY"
		if input.Kind == application.OperationRestore {
			assignmentType = "PERMANENT"
		}
		var pendingAssignmentID string
		err = tx.QueryRowContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, created_at, updated_at
) VALUES ($1, $2, $3, $4, 'PENDING', $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id`, identity.SeatID, identity.PoolID, identity.TargetMemberID, assignmentType,
			seat.AssignmentEpoch+1).Scan(&pendingAssignmentID)
		if err != nil {
			return nil, false, translateAssignmentWriteError("create pending assignment", err)
		}
		result, err := tx.ExecContext(ctx, `UPDATE seats
SET status = 'ASSIGNMENT_PENDING', version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'FROZEN' AND assignment_epoch = $2
  AND owner_member_id = $3 AND sub2api_principal_id = $4
  AND sub2api_subscription_id = $5 AND sub2api_api_key_id = $6
  AND active_api_key_version = $7`, identity.SeatID, seat.AssignmentEpoch, identity.OwnerMemberID,
			seat.PrincipalUserID, seat.SubscriptionID, seat.APIKeyID, seat.ActiveAPIKeyVersion)
		if err != nil {
			return nil, false, fmt.Errorf("mark assignment pending Seat: %w", err)
		}
		if err := requireSingleFencedRow(result); err != nil {
			return nil, false, application.ErrWorkflowInvalidState
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO assignment_cases (
integration_operation_id, seat_id, pool_id, owner_member_id, previous_member_id, target_member_id,
pending_assignment_id, freeze_suspension_case_id, operation_type, status,
expected_assignment_epoch, next_assignment_epoch, membership_epoch,
principal_user_id, subscription_id, api_key_id, expected_api_key_version, next_api_key_version,
freeze_operation_id, freeze_snapshot, version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ASSIGNMENT_PENDING',
          $10, $11, $12, $13, $14, $15, $16, $17, $18, $19::jsonb, 1,
          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, op.AggregateID, identity.SeatID, identity.PoolID,
			identity.OwnerMemberID, identity.CurrentMemberID, identity.TargetMemberID, pendingAssignmentID,
			freezeCaseID, input.Kind, seat.AssignmentEpoch, seat.AssignmentEpoch+1, membershipEpoch,
			seat.PrincipalUserID, seat.SubscriptionID, seat.APIKeyID, seat.ActiveAPIKeyVersion,
			seat.ActiveAPIKeyVersion+1, freezeOperationID, freezeSnapshot)
		if err != nil {
			return nil, false, translateAssignmentWriteError("create assignment case", err)
		}
	}

	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
    fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, application.ErrWorkflowLeaseHeld
	}
	if err != nil {
		return nil, false, fmt.Errorf("acquire initial assignment lease: %w", err)
	}
	target, err := loadAssignmentTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, false, err
	}
	if err := validateLoadedAssignmentTarget(input, target); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin assignment: %w", err)
	}
	return target, created, nil
}

func (s *Store) LoadAssignmentTarget(ctx context.Context, key application.OperationKey) (*application.AssignmentTarget, error) {
	if !validKey(key.ClientID, key.OperationID) {
		return nil, application.ErrWorkflowInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND target_type = 'SEAT'
  AND migration_state = 'CURRENT'`, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load assignment operation", err)
	}
	target, err := scanAssignmentTarget(s.db.QueryRowContext(ctx, `SELECT `+assignmentTargetColumns+
		assignmentTargetFrom, key.ClientID, key.OperationID), op)
	if err != nil {
		return nil, translateNotFound("load assignment target", err)
	}
	return target, nil
}

// CommitAssignmentWithCredentialClaim 原子提交 Assignment、Seat、Operation 和加密 claim。
func (s *Store) CommitAssignmentWithCredentialClaim(ctx context.Context, input application.CommitAssignmentWithCredentialClaimInput) (*application.StoredOperation, *application.StoredCredentialClaim, *application.PersistedSeat, error) {
	if err := validateAssignmentSuccess(input); err != nil {
		return nil, nil, nil, err
	}
	intentHash, err := credentialClaimIntentHash(input.Claim)
	if err != nil {
		return nil, nil, nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("begin assignment commit transaction: %w", err)
	}
	defer tx.Rollback()
	locator, err := loadAssignmentLocator(ctx, tx, input.Key)
	if err != nil {
		return nil, nil, nil, err
	}
	op, err := lockAssignmentOperationFence(ctx, tx, input.Key, input.LeaseOwner, input.FencingToken)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, err := lockAssignmentPool(ctx, tx, locator.PoolID); err != nil {
		return nil, nil, nil, err
	}
	if err := lockAssignmentTargetMembership(ctx, tx, locator.PoolID, locator.MembershipEpoch,
		locator.TargetMemberID, input.Claim.TargetMemberExternalID, locator.SeatID); err != nil {
		return nil, nil, nil, err
	}
	seat, err := lockAssignmentSeat(ctx, tx, locator.assignmentIdentity)
	if err != nil {
		return nil, nil, nil, err
	}
	target, err := loadAssignmentTargetTx(ctx, tx, input.Key, op, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if target.Case.ExpectedAssignmentEpoch != input.ExpectedAssignmentEpoch ||
		seat.AssignmentEpoch != input.ExpectedAssignmentEpoch || target.Case.Status != application.AssignmentCasePending ||
		input.Claim.SeatExternalID != seat.SeatExternalID ||
		input.Claim.TargetMemberExternalID != target.Seat.TargetMemberID {
		return nil, nil, nil, application.ErrWorkflowInvalidState
	}

	if err := endPreviousAndActivatePending(ctx, tx, target.Case); err != nil {
		return nil, nil, nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE seats
SET status = 'ACTIVE', assignment_epoch = $2, active_api_key_version = $3,
    frozen_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'ASSIGNMENT_PENDING' AND assignment_epoch = $4
  AND owner_member_id = $5 AND sub2api_principal_id = $6
  AND sub2api_subscription_id = $7 AND sub2api_api_key_id = $8
  AND active_api_key_version = $9`, target.Case.SeatID, target.Case.NextAssignmentEpoch,
		target.Case.NextAPIKeyVersion, target.Case.ExpectedAssignmentEpoch, locator.OwnerMemberID,
		target.Case.PrincipalUserID, target.Case.SubscriptionID, target.Case.APIKeyID,
		target.Case.ExpectedAPIKeyVersion)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("activate assigned Seat: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, nil, nil, application.ErrWorkflowInvalidState
	}
	result, err = tx.ExecContext(ctx, `UPDATE assignment_cases
SET status = 'SUCCEEDED', error_code = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status = 'ASSIGNMENT_PENDING'`, op.AggregateID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("complete assignment case: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, nil, nil, application.ErrWorkflowInvalidState
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = 'SUCCEEDED', response_snapshot = $5::jsonb, error_code = NULL, error_detail = NULL,
    next_attempt_at = NULL, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, input.ResultSnapshot))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("complete assignment operation: %w", err)
	}
	if err := insertAssignmentCredentialClaim(ctx, tx, op, target.Case, input.Claim, intentHash); err != nil {
		return nil, nil, nil, err
	}
	claim, err := loadClaimTx(ctx, tx, input.Claim.Key, false)
	if err != nil {
		return nil, nil, nil, err
	}
	persistedSeat, err := loadPersistedSeatTx(ctx, tx, input.Claim.SeatExternalID)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, fmt.Errorf("commit assignment aggregate: %w", err)
	}
	return op, claim, persistedSeat, nil
}

// CommitAssignmentFailure 保持未知结果失败关闭；只有网关明确证明未应用时才撤销 pending。
func (s *Store) CommitAssignmentFailure(ctx context.Context, input application.CommitAssignmentFailureInput) (*application.AssignmentTarget, error) {
	if err := validateAssignmentFailure(input); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin assignment failure transaction: %w", err)
	}
	defer tx.Rollback()
	locator, err := loadAssignmentLocator(ctx, tx, input.Key)
	if err != nil {
		return nil, err
	}
	op, err := lockAssignmentOperationFence(ctx, tx, input.Key, input.LeaseOwner, input.FencingToken)
	if err != nil {
		return nil, err
	}
	if _, _, err := lockAssignmentPool(ctx, tx, locator.PoolID); err != nil {
		return nil, err
	}
	if err := lockAssignmentTargetMembership(ctx, tx, locator.PoolID, locator.MembershipEpoch,
		locator.TargetMemberID, locator.TargetMemberExternalID, locator.SeatID); err != nil {
		return nil, err
	}
	if _, err := lockAssignmentSeat(ctx, tx, locator.assignmentIdentity); err != nil {
		return nil, err
	}
	if _, err := loadAssignmentTargetTx(ctx, tx, input.Key, op, true); err != nil {
		return nil, err
	}

	operationStatus := application.OperationReconcileRequired
	caseStatus := application.AssignmentCasePending
	completed := false
	nextAttemptAt := input.NextAttemptAt
	if input.ConfirmedUnchanged {
		result, err := tx.ExecContext(ctx, `UPDATE seat_assignments
SET status = 'CANCELLED', ended_reason = 'UPSTREAM_REJECTED_UNCHANGED',
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'PENDING' AND assignment_epoch = $2`,
			locator.PendingAssignmentID, locator.NextAssignmentEpoch)
		if err != nil {
			return nil, fmt.Errorf("cancel pending assignment: %w", err)
		}
		if err := requireSingleFencedRow(result); err != nil {
			return nil, application.ErrWorkflowInvalidState
		}
		result, err = tx.ExecContext(ctx, `UPDATE seats
SET status = 'FROZEN', version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'ASSIGNMENT_PENDING' AND assignment_epoch = $2
  AND active_api_key_version = $3`, locator.SeatID, locator.ExpectedAssignmentEpoch,
			locator.ExpectedAPIKeyVersion)
		if err != nil {
			return nil, fmt.Errorf("restore rejected assignment Seat freeze: %w", err)
		}
		if err := requireSingleFencedRow(result); err != nil {
			return nil, application.ErrWorkflowInvalidState
		}
		operationStatus, caseStatus, completed, nextAttemptAt = application.OperationFailed,
			application.AssignmentCaseCancelled, true, nil
	}
	caseError := input.ErrorCode
	if caseStatus == application.AssignmentCaseCancelled {
		caseError = ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE assignment_cases
SET status = $2, error_code = NULLIF($3, ''), version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status = 'ASSIGNMENT_PENDING'`, op.AggregateID, caseStatus, caseError)
	if err != nil {
		return nil, fmt.Errorf("record assignment case failure: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, application.ErrWorkflowInvalidState
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = $5, response_snapshot = $6::jsonb, error_code = $7, error_detail = $8,
    next_attempt_at = $9, completed_at = CASE WHEN $10 THEN CURRENT_TIMESTAMP ELSE NULL END,
    lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, operationStatus, input.ResultSnapshot, input.ErrorCode, input.ErrorDetail,
		nextAttemptAt, completed))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("record assignment operation failure: %w", err)
	}
	target, err := loadAssignmentTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit assignment failure: %w", err)
	}
	return target, nil
}

func validateBeginAssignment(input application.BeginAssignmentInput) ([]byte, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) ||
		(input.Kind != application.OperationAssignTemp && input.Kind != application.OperationRestore) ||
		strings.TrimSpace(input.SeatExternalID) == "" || strings.TrimSpace(input.TargetMemberExternalID) == "" ||
		strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	canonical, err := canonicalJSONObject(input.RequestSnapshot)
	if err != nil {
		return nil, application.ErrWorkflowInvalidData
	}
	var snapshot struct {
		Version        int                       `json:"version"`
		OperationID    string                    `json:"operation_id"`
		SeatID         string                    `json:"seat_id"`
		TargetMemberID string                    `json:"target_member_id"`
		Mode           application.OperationKind `json:"mode"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(canonical, &snapshot) != nil || json.Unmarshal(canonical, &fields) != nil || len(fields) != 5 ||
		snapshot.Version != 1 || snapshot.OperationID != input.Key.OperationID ||
		snapshot.SeatID != input.SeatExternalID || snapshot.TargetMemberID != input.TargetMemberExternalID ||
		snapshot.Mode != input.Kind {
		return nil, application.ErrWorkflowInvalidData
	}
	for _, key := range []string{"version", "operation_id", "seat_id", "target_member_id", "mode"} {
		if _, ok := fields[key]; !ok {
			return nil, application.ErrWorkflowInvalidData
		}
	}
	return canonical, nil
}

func validateAssignmentOperationIntent(op *application.StoredOperation, input application.BeginAssignmentInput, canonical []byte) error {
	if op == nil || op.MigrationState != "CURRENT" || op.Kind != input.Kind || op.TargetType != "SEAT" ||
		op.TargetExternalID != input.SeatExternalID || !bytes.Equal(op.RequestHash[:], input.RequestHash[:]) {
		return application.ErrWorkflowHashDrift
	}
	stored, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || !bytes.Equal(stored, canonical) {
		return application.ErrWorkflowHashDrift
	}
	return nil
}

func validateAssignmentStartState(input application.BeginAssignmentInput, identity assignmentIdentity,
	seat application.AssignmentSeatTarget, poolExternalID string, membershipEpoch uint64, created bool) error {
	expectedStatus := domain.SeatAssignmentPending
	if created {
		expectedStatus = domain.SeatFrozen
	}
	if seat.SeatID != identity.SeatID || seat.PoolExternalID != poolExternalID ||
		seat.OwnerExternalID == "" || seat.CurrentMemberID == seat.TargetMemberID ||
		seat.Status != expectedStatus || seat.AssignmentEpoch == 0 || seat.MembershipEpoch != membershipEpoch ||
		seat.PrincipalUserID <= 0 || seat.SubscriptionID <= 0 || seat.APIKeyID <= 0 ||
		seat.ActiveAPIKeyVersion != seat.AssignmentEpoch {
		return application.ErrWorkflowInvalidState
	}
	if input.Kind == application.OperationRestore && identity.TargetMemberID != identity.OwnerMemberID {
		return application.ErrWorkflowInvalidState
	}
	if input.Kind == application.OperationAssignTemp && identity.TargetMemberID == identity.OwnerMemberID {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func validateLoadedAssignmentTarget(input application.BeginAssignmentInput, target *application.AssignmentTarget) error {
	if target == nil || target.Case.Kind != input.Kind || target.Seat.SeatExternalID != input.SeatExternalID ||
		target.Seat.TargetMemberID != input.TargetMemberExternalID {
		return application.ErrWorkflowHashDrift
	}
	return nil
}

func validateAssignmentSuccess(input application.CommitAssignmentWithCredentialClaimInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || input.ExpectedAssignmentEpoch == 0 || !validJSONObject(input.ResultSnapshot) ||
		input.Claim.Key.ClientID != input.Key.ClientID || input.Claim.Key.OperationID != input.Key.OperationID {
		return application.ErrWorkflowInvalidData
	}
	return validateCreateClaim(input.Claim)
}

func validateAssignmentFailure(input application.CommitAssignmentFailureInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || !validJSONObject(input.ResultSnapshot) ||
		strings.TrimSpace(input.ErrorCode) == "" ||
		(input.ConfirmedUnchanged && input.NextAttemptAt != nil) ||
		(!input.ConfirmedUnchanged && input.NextAttemptAt == nil) {
		return application.ErrWorkflowInvalidData
	}
	return nil
}

func resolveAssignmentIdentity(ctx context.Context, tx *sql.Tx, seatExternalID, targetExternalID string) (assignmentIdentity, error) {
	var identity assignmentIdentity
	err := tx.QueryRowContext(ctx, `SELECT s.id, s.pool_id, s.owner_member_id,
current_assignment.member_id, target.id
FROM seats s
JOIN seat_assignments current_assignment ON current_assignment.seat_id = s.id AND current_assignment.status = 'ACTIVE'
JOIN members target ON target.external_id = $2
WHERE s.external_id = $1`, seatExternalID, targetExternalID).Scan(&identity.SeatID, &identity.PoolID,
		&identity.OwnerMemberID, &identity.CurrentMemberID, &identity.TargetMemberID)
	if err != nil {
		return identity, translateNotFound("resolve assignment identity", err)
	}
	return identity, nil
}

func lockAssignmentPool(ctx context.Context, tx *sql.Tx, poolID string) (string, uint64, error) {
	var externalID string
	var epoch uint64
	err := tx.QueryRowContext(ctx, `SELECT external_id, membership_epoch FROM pools
WHERE id = $1 AND status = 'ACTIVE' AND membership_epoch > 0 FOR UPDATE`, poolID).Scan(&externalID, &epoch)
	if err != nil {
		return "", 0, translateNotFound("lock assignment pool", err)
	}
	return externalID, epoch, nil
}

func lockAssignmentTargetMembership(ctx context.Context, tx *sql.Tx, poolID string, epoch uint64,
	targetMemberID, targetExternalID, seatID string) error {
	var lockedID string
	err := tx.QueryRowContext(ctx, `SELECT member.id
FROM membership_epochs membership
JOIN membership_epoch_members snapshot_member ON snapshot_member.epoch_id = membership.id
JOIN members member ON member.id = snapshot_member.member_id
WHERE membership.pool_id = $1 AND membership.epoch = $2 AND membership.status = 'ACTIVE'
  AND member.id = $3 AND member.external_id = $4 AND member.status = 'ACTIVE'
  AND NOT EXISTS (SELECT 1 FROM seat_assignments occupied
      WHERE occupied.pool_id = $1 AND occupied.member_id = member.id AND occupied.status = 'ACTIVE'
        AND occupied.seat_id <> $5)
FOR UPDATE OF membership, snapshot_member, member`, poolID, epoch, targetMemberID, targetExternalID, seatID).Scan(&lockedID)
	if err != nil {
		return translateNotFound("lock assignment target membership", err)
	}
	return nil
}

func lockAssignmentSeat(ctx context.Context, tx *sql.Tx, identity assignmentIdentity) (application.AssignmentSeatTarget, error) {
	seat := application.AssignmentSeatTarget{TargetMemberID: ""}
	var principalID, subscriptionID, apiKeyID sql.NullInt64
	var apiKeyVersion uint64
	err := tx.QueryRowContext(ctx, `SELECT s.id, s.external_id, pool.external_id, owner.external_id,
current_member.external_id, target.external_id, s.status, s.assignment_epoch, pool.membership_epoch,
s.sub2api_principal_id, s.sub2api_subscription_id, s.sub2api_api_key_id, s.active_api_key_version
FROM seats s
JOIN pools pool ON pool.id = s.pool_id
JOIN members owner ON owner.id = s.owner_member_id
JOIN members target ON target.id = $5
JOIN seat_assignments current_assignment ON current_assignment.seat_id = s.id AND current_assignment.status = 'ACTIVE'
JOIN members current_member ON current_member.id = current_assignment.member_id
WHERE s.id = $1 AND s.pool_id = $2 AND s.owner_member_id = $3 AND current_assignment.member_id = $4
FOR UPDATE OF s, current_assignment`, identity.SeatID, identity.PoolID, identity.OwnerMemberID,
		identity.CurrentMemberID, identity.TargetMemberID).Scan(&seat.SeatID, &seat.SeatExternalID,
		&seat.PoolExternalID, &seat.OwnerExternalID, &seat.CurrentMemberID, &seat.TargetMemberID,
		&seat.Status, &seat.AssignmentEpoch, &seat.MembershipEpoch, &principalID,
		&subscriptionID, &apiKeyID, &apiKeyVersion)
	if err != nil {
		return seat, translateNotFound("lock assignment Seat", err)
	}
	if !principalID.Valid || !subscriptionID.Valid || !apiKeyID.Valid || apiKeyVersion == 0 {
		return seat, application.ErrWorkflowInvalidState
	}
	seat.PrincipalUserID, seat.SubscriptionID, seat.APIKeyID = principalID.Int64, subscriptionID.Int64, apiKeyID.Int64
	seat.ActiveAPIKeyVersion = apiKeyVersion
	return seat, nil
}

func ensureNoPendingSettlementResolution(ctx context.Context, tx *sql.Tx, seatID string) error {
	var clear bool
	err := tx.QueryRowContext(ctx, `SELECT NOT EXISTS (
    SELECT 1
    FROM settlement_resolution_cases resolution_case
    JOIN integration_operations io ON io.id = resolution_case.integration_operation_id
    WHERE resolution_case.seat_id = $1
      AND resolution_case.status = 'RESOLUTION_PENDING'
      AND io.migration_state = 'CURRENT'
      AND io.operation_type = 'RESOLVE_SETTLEMENT'
      AND io.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
)`, seatID).Scan(&clear)
	if err != nil {
		return fmt.Errorf("check pending settlement resolution before assignment: %w", err)
	}
	if !clear {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func lockAvailableFreezeEvidence(ctx context.Context, tx *sql.Tx, seatID string, epoch uint64) (string, string, []byte, error) {
	var caseID, operationID string
	var snapshot []byte
	err := tx.QueryRowContext(ctx, `SELECT suspension.id, suspension.operation_id, suspension.freeze_snapshot
FROM suspension_cases suspension
WHERE suspension.seat_id = $1 AND suspension.status = 'FROZEN'
  AND suspension.migration_state = 'CURRENT' AND suspension.expected_assignment_epoch = $2
  AND NOT EXISTS (SELECT 1 FROM assignment_cases existing
      WHERE existing.freeze_suspension_case_id = suspension.id AND existing.status <> 'CANCELLED')
ORDER BY suspension.frozen_at DESC, suspension.id::text
LIMIT 1 FOR UPDATE OF suspension`, seatID, epoch).Scan(&caseID, &operationID, &snapshot)
	if err != nil {
		return "", "", nil, translateNotFound("lock assignment freeze evidence", err)
	}
	return caseID, operationID, snapshot, nil
}

type assignmentLocator struct {
	assignmentIdentity
	TargetMemberExternalID  string
	PendingAssignmentID     string
	MembershipEpoch         uint64
	ExpectedAssignmentEpoch uint64
	NextAssignmentEpoch     uint64
	ExpectedAPIKeyVersion   uint64
}

func loadAssignmentLocator(ctx context.Context, tx *sql.Tx, key application.OperationKey) (assignmentLocator, error) {
	var locator assignmentLocator
	err := tx.QueryRowContext(ctx, `SELECT ac.seat_id, ac.pool_id, ac.owner_member_id, ac.previous_member_id,
ac.target_member_id, target.external_id, ac.pending_assignment_id, ac.membership_epoch,
ac.expected_assignment_epoch, ac.next_assignment_epoch, ac.expected_api_key_version
FROM assignment_cases ac
JOIN integration_operations io ON io.id = ac.integration_operation_id
JOIN members target ON target.id = ac.target_member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
  AND io.operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND ac.status = 'ASSIGNMENT_PENDING'`,
		key.ClientID, key.OperationID).Scan(&locator.SeatID, &locator.PoolID, &locator.OwnerMemberID,
		&locator.CurrentMemberID, &locator.TargetMemberID, &locator.TargetMemberExternalID,
		&locator.PendingAssignmentID, &locator.MembershipEpoch, &locator.ExpectedAssignmentEpoch,
		&locator.NextAssignmentEpoch, &locator.ExpectedAPIKeyVersion)
	if err != nil {
		return locator, translateNotFound("load assignment locator", err)
	}
	return locator, nil
}

func lockAssignmentOperationFence(ctx context.Context, tx *sql.Tx, key application.OperationKey,
	owner string, fence int64) (*application.StoredOperation, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE') AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
FOR UPDATE`, key.ClientID, key.OperationID, fence, owner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("lock assignment operation: %w", err)
	}
	return op, nil
}

func loadAssignmentTargetTx(ctx context.Context, tx *sql.Tx, key application.OperationKey,
	op *application.StoredOperation, forUpdate bool) (*application.AssignmentTarget, error) {
	query := `SELECT ` + assignmentTargetColumns + assignmentTargetFrom
	if forUpdate {
		query += ` FOR UPDATE OF ac`
	}
	target, err := scanAssignmentTarget(tx.QueryRowContext(ctx, query, key.ClientID, key.OperationID), op)
	if err != nil {
		return nil, translateNotFound("load assignment target transaction", err)
	}
	return target, nil
}

func scanAssignmentTarget(row scanner, op *application.StoredOperation) (*application.AssignmentTarget, error) {
	result := &application.AssignmentTarget{Operation: op}
	assignmentCase := &application.StoredAssignmentCase{}
	var errorCode sql.NullString
	var freezeSnapshot []byte
	err := row.Scan(&assignmentCase.ID, &assignmentCase.IntegrationOperationID, &assignmentCase.SeatID,
		&assignmentCase.PoolID, &assignmentCase.TargetMemberID, &assignmentCase.PreviousMemberID,
		&assignmentCase.PendingAssignmentID, &assignmentCase.FreezeSuspensionCaseID,
		&assignmentCase.Kind, &assignmentCase.Status,
		&assignmentCase.ExpectedAssignmentEpoch, &assignmentCase.NextAssignmentEpoch,
		&assignmentCase.MembershipEpoch, &assignmentCase.PrincipalUserID, &assignmentCase.SubscriptionID,
		&assignmentCase.APIKeyID, &assignmentCase.ExpectedAPIKeyVersion, &assignmentCase.NextAPIKeyVersion,
		&assignmentCase.FreezeOperationID, &freezeSnapshot, &errorCode, &assignmentCase.Version,
		&assignmentCase.CreatedAt, &assignmentCase.UpdatedAt,
		&result.Seat.SeatID, &result.Seat.SeatExternalID, &result.Seat.PoolExternalID,
		&result.Seat.OwnerExternalID, &result.Seat.CurrentMemberID, &result.Seat.TargetMemberID,
		&result.Seat.Status, &result.Seat.AssignmentEpoch, &result.Seat.MembershipEpoch,
		&result.Seat.PrincipalUserID, &result.Seat.SubscriptionID, &result.Seat.APIKeyID,
		&result.Seat.ActiveAPIKeyVersion)
	if err != nil {
		return nil, err
	}
	assignmentCase.FreezeSnapshot = append([]byte(nil), freezeSnapshot...)
	if errorCode.Valid {
		assignmentCase.ErrorCode = errorCode.String
	}
	result.Case = assignmentCase
	return result, nil
}

func endPreviousAndActivatePending(ctx context.Context, tx *sql.Tx, assignmentCase *application.StoredAssignmentCase) error {
	result, err := tx.ExecContext(ctx, `UPDATE seat_assignments
SET status = 'ENDED', ends_at = CURRENT_TIMESTAMP, ended_reason = $4, updated_at = CURRENT_TIMESTAMP
WHERE seat_id = $1 AND member_id = $2 AND status = 'ACTIVE' AND assignment_epoch = $3`,
		assignmentCase.SeatID, assignmentCase.PreviousMemberID, assignmentCase.ExpectedAssignmentEpoch,
		assignmentCase.Kind)
	if err != nil {
		return fmt.Errorf("end previous assignment: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return application.ErrWorkflowInvalidState
	}
	result, err = tx.ExecContext(ctx, `UPDATE seat_assignments
SET status = 'ACTIVE', starts_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND seat_id = $2 AND member_id = $3 AND status = 'PENDING'
  AND assignment_epoch = $4`, assignmentCase.PendingAssignmentID, assignmentCase.SeatID,
		assignmentCase.TargetMemberID, assignmentCase.NextAssignmentEpoch)
	if err != nil {
		return fmt.Errorf("activate pending assignment: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func insertAssignmentCredentialClaim(ctx context.Context, tx *sql.Tx, op *application.StoredOperation,
	assignmentCase *application.StoredAssignmentCase, claim application.CreateCredentialClaimInput,
	intentHash [32]byte) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_token_hash, credential_fingerprint, claim_intent_hash, envelope_algorithm, envelope_key_ref,
envelope_ciphertext, envelope_nonce, envelope_aad_hash, wrapped_dek_kms, expires_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, 'READY', $5, $6, $7, $8, $9, $10, $11, $12, $13,
          CURRENT_TIMESTAMP + make_interval(secs => $14), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		op.AggregateID, assignmentCase.SeatID, assignmentCase.TargetMemberID, claim.ClaimOperationID,
		claim.TokenHash[:], claim.CredentialFingerprint[:], intentHash[:], claim.Envelope.Algorithm,
		claim.Envelope.KeyRef, claim.Envelope.Ciphertext, claim.Envelope.Nonce, claim.Envelope.AADHash[:],
		claim.Envelope.WrappedDEK, claim.ClaimTTL.Seconds())
	if err != nil {
		return fmt.Errorf("insert assignment credential claim: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func translateAssignmentWriteError(action string, err error) error {
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" &&
		(strings.Contains(err.Error(), "uq_assignment_cases_open_seat") ||
			strings.Contains(err.Error(), "uq_assignment_cases_consumed_freeze") ||
			strings.Contains(err.Error(), "uq_seat_assignments_pending_seat") ||
			strings.Contains(err.Error(), "uq_seat_assignments_active_member_pool")) {
		return application.ErrWorkflowTargetConflict
	}
	return translateOperationWriteError(action, err)
}
