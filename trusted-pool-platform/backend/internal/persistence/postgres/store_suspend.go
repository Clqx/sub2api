package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/domain"
)

const suspendCaseTargetColumns = `sc.id, sc.integration_operation_id, sc.operation_id, sc.seat_id, sc.migration_state,
sc.status, sc.reason_code, sc.expected_assignment_epoch, sc.current_concurrency,
sc.pending_settlements, sc.blocked_at, sc.frozen_at, sc.freeze_snapshot, sc.error_code,
sc.version, sc.created_at, sc.updated_at,
s.id, s.external_id, p.external_id, owner.external_id, current_member.external_id,
s.status, s.assignment_epoch, p.membership_epoch`

const suspendCaseTargetFrom = `
FROM suspension_cases sc
JOIN integration_operations io ON io.id = sc.integration_operation_id
JOIN seats s ON s.id = sc.seat_id AND s.id = io.target_id AND s.external_id = io.target_external_id
JOIN pools p ON p.id = s.pool_id
JOIN members owner ON owner.id = s.owner_member_id
JOIN seat_assignments assignment ON assignment.seat_id = s.id AND assignment.status = 'ACTIVE'
JOIN members current_member ON current_member.id = assignment.member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
  AND io.operation_type = 'SUSPEND' AND io.target_type = 'SEAT'
  AND io.migration_state = 'CURRENT'
  AND sc.migration_state = 'CURRENT'
  AND (assignment.starts_at IS NULL OR assignment.starts_at <= CURRENT_TIMESTAMP)
  AND (assignment.ends_at IS NULL OR assignment.ends_at > CURRENT_TIMESTAMP)`

// BeginSuspend 在网络调用前一次性持久化暂停意图、case、Seat 状态和首个 fencing lease。
func (s *Store) BeginSuspend(ctx context.Context, input application.BeginSuspendInput) (*application.SuspendTarget, bool, error) {
	if err := validateBeginSuspend(input); err != nil {
		return nil, false, err
	}
	canonicalSnapshot, err := canonicalJSONObject(input.RequestSnapshot)
	if err != nil {
		return nil, false, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin suspend transaction: %w", err)
	}
	defer tx.Rollback()

	// 全部写路径统一先锁 operation、再锁 Seat/case，避免 Begin 重放与恢复提交形成锁环。
	seatID, err := resolveSuspendSeatID(ctx, tx, input.SeatExternalID)
	if err != nil {
		return nil, false, err
	}
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, 'SUSPEND', 'SEAT', $3, $4, 'CURRENT', $5, $6::jsonb,
          'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, seatID,
		input.SeatExternalID, input.RequestHash[:], canonicalSnapshot))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2
FOR UPDATE`, input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateSuspendWriteError("begin suspend operation", scanErr)
	}
	if err := validateSuspendOperationIntent(op, input, canonicalSnapshot); err != nil {
		return nil, false, err
	}
	seat, err := lockSuspendSeat(ctx, tx, input.SeatExternalID)
	if err != nil {
		return nil, false, err
	}
	if seat.SeatID != seatID {
		return nil, false, application.ErrWorkflowTargetConflict
	}
	if err := validateSuspendSnapshotBinding(canonicalSnapshot, input, seat); err != nil {
		return nil, false, err
	}

	if created {
		if seat.Status != domain.SeatActive {
			return nil, false, application.ErrWorkflowInvalidState
		}
		result, err := tx.ExecContext(ctx, `UPDATE seats
SET status = 'SUSPEND_PENDING', version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND external_id = $2 AND status = 'ACTIVE' AND assignment_epoch = $3`,
			seat.SeatID, seat.SeatExternalID, seat.AssignmentEpoch)
		if err != nil {
			return nil, false, fmt.Errorf("mark suspend pending seat: %w", err)
		}
		if err := requireSingleFencedRow(result); err != nil {
			return nil, false, application.ErrWorkflowInvalidState
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO suspension_cases (
integration_operation_id, seat_id, operation_id, status, reason_code, requested_by,
expected_assignment_epoch, blocked_at, version, created_at, updated_at
) VALUES ($1, $2, $3, 'SUSPEND_PENDING', $4, NULL, $5,
          CURRENT_TIMESTAMP, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			op.AggregateID, seat.SeatID, input.Key.OperationID, input.ReasonCode, seat.AssignmentEpoch)
		if err != nil {
			return nil, false, translateSuspendWriteError("create suspension case", err)
		}
	}

	if op.Status != application.OperationSucceeded && op.Status != application.OperationFailed {
		op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
    fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'SUSPEND' AND target_type = 'SEAT' AND migration_state = 'CURRENT'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID,
			input.LeaseOwner, input.LeaseDuration.Seconds()))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, application.ErrWorkflowLeaseHeld
		}
		if err != nil {
			return nil, false, fmt.Errorf("acquire initial suspend lease: %w", err)
		}
	}
	target, err := loadSuspendCaseTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, false, err
	}
	if created && target.Case.Status != application.SuspendCasePending {
		return nil, false, application.ErrWorkflowCorruptState
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin suspend: %w", err)
	}
	return target, created, nil
}

func (s *Store) LoadSuspendTarget(ctx context.Context, key application.OperationKey) (*application.SuspendTarget, error) {
	if !validKey(key.ClientID, key.OperationID) {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin load suspend target: %w", err)
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'SUSPEND' AND target_type = 'SEAT' AND migration_state = 'CURRENT'`,
		key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load suspend operation", err)
	}
	target, err := loadSuspendCaseTargetTx(ctx, tx, key, op, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit load suspend target: %w", err)
	}
	return target, nil
}

// CommitSuspendProgress 只提交网络调用结果；事务开始前不得持有任何外部请求。
func (s *Store) CommitSuspendProgress(ctx context.Context, input application.CommitSuspendProgressInput) (*application.SuspendTarget, error) {
	freezeSnapshot, err := validateAndMarshalSuspendProgress(input)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin suspend progress transaction: %w", err)
	}
	defer tx.Rollback()

	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'SUSPEND' AND target_type = 'SEAT' AND migration_state = 'CURRENT'
  AND fencing_token = $3 AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
FOR UPDATE`, input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("lock suspend operation: %w", err)
	}
	if err := lockSuspendPoolByOperation(ctx, tx, op.AggregateID); err != nil {
		return nil, err
	}
	target, err := loadSuspendCaseTargetTx(ctx, tx, input.Key, op, true)
	if err != nil {
		return nil, err
	}
	if target.Case.ExpectedAssignmentEpoch != input.ExpectedAssignmentEpoch ||
		target.Seat.AssignmentEpoch != input.ExpectedAssignmentEpoch {
		return nil, application.ErrWorkflowInvalidState
	}
	currentConcurrency, pendingSettlements, err := suspendObservations(input, target.Case)
	if err != nil {
		return nil, err
	}

	caseStatus, seatStatus := string(input.Progress), string(input.Progress)
	isFrozen := input.Progress == application.SuspendCaseFrozen
	result, err := tx.ExecContext(ctx, `UPDATE suspension_cases sc
SET status = $5, current_concurrency = $6, pending_settlements = $7,
    freeze_snapshot = NULLIF($8::text, '')::jsonb,
    frozen_at = CASE WHEN $9 THEN CURRENT_TIMESTAMP ELSE NULL END,
    error_code = NULLIF($11, ''), version = sc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io
WHERE io.id = sc.integration_operation_id
  AND io.integration_client_id = $1 AND io.operation_id = $2
  AND io.fencing_token = $3 AND io.lease_owner = $4
  AND io.lease_expires_at > CURRENT_TIMESTAMP
  AND sc.expected_assignment_epoch = $10
  AND sc.migration_state = 'CURRENT'
  AND ((sc.status = 'SUSPEND_PENDING' AND $5 IN ('SUSPEND_PENDING', 'DRAINING', 'FROZEN'))
       OR (sc.status = 'DRAINING' AND $5 IN ('DRAINING', 'FROZEN')))`,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner,
		caseStatus, nullableInt(currentConcurrency), nullableInt(pendingSettlements),
		string(freezeSnapshot), isFrozen, input.ExpectedAssignmentEpoch, input.ErrorCode)
	if err != nil {
		return nil, fmt.Errorf("update suspension case progress: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, application.ErrWorkflowStaleFence
	}

	result, err = tx.ExecContext(ctx, `UPDATE seats
SET status = $2,
    frozen_at = CASE WHEN $3 THEN CURRENT_TIMESTAMP ELSE NULL END,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND assignment_epoch = $4
  AND ((status = 'SUSPEND_PENDING' AND $2 IN ('SUSPEND_PENDING', 'DRAINING', 'FROZEN'))
       OR (status = 'DRAINING' AND $2 IN ('DRAINING', 'FROZEN')))`, target.Seat.SeatID, seatStatus,
		isFrozen, input.ExpectedAssignmentEpoch)
	if err != nil {
		return nil, fmt.Errorf("update suspended seat progress: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, application.ErrWorkflowInvalidState
	}

	operationStatus := application.OperationReconcileRequired
	errorCode, errorDetail := input.ErrorCode, input.ErrorDetail
	if errorCode == "" && input.Progress == application.SuspendCaseDraining {
		errorCode = "SUSPEND_DRAINING"
	}
	terminal := false
	nextAttemptAt := input.NextAttemptAt
	if input.Progress == application.SuspendCaseFrozen {
		operationStatus = application.OperationSucceeded
		errorCode = ""
		errorDetail = ""
		terminal = true
		nextAttemptAt = nil
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = $5, response_snapshot = NULLIF($6::text, '')::jsonb, error_code = NULLIF($7, ''),
    error_detail = NULLIF($8, ''), next_attempt_at = $9,
    completed_at = CASE WHEN $10 THEN CURRENT_TIMESTAMP ELSE NULL END,
    lease_owner = NULL, lease_expires_at = NULL,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND fencing_token = $3 AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND operation_type = 'SUSPEND' AND target_type = 'SEAT' AND migration_state = 'CURRENT'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, operationStatus, input.ResultSnapshot, errorCode, errorDetail, nextAttemptAt, terminal))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("commit suspend operation progress: %w", err)
	}
	target, err = loadSuspendCaseTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit suspend progress: %w", err)
	}
	return target, nil
}

func validateBeginSuspend(input application.BeginSuspendInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.SeatExternalID) == "" ||
		len(input.SeatExternalID) > 128 || input.ReasonCode != application.SuspendReasonManualPolicyBreach ||
		strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 ||
		!validJSONObject(input.RequestSnapshot) {
		return application.ErrWorkflowInvalidData
	}
	return nil
}

func validateSuspendOperationIntent(op *application.StoredOperation, input application.BeginSuspendInput, canonical []byte) error {
	if op == nil || op.MigrationState != "CURRENT" || op.Kind != application.OperationSuspend ||
		op.TargetType != "SEAT" || op.TargetExternalID != input.SeatExternalID {
		return application.ErrWorkflowHashDrift
	}
	if !bytes.Equal(op.RequestHash[:], input.RequestHash[:]) {
		return application.ErrWorkflowHashDrift
	}
	stored, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || !bytes.Equal(stored, canonical) {
		return application.ErrWorkflowHashDrift
	}
	return nil
}

type suspendIntentSnapshot struct {
	Version         int    `json:"version"`
	OperationID     string `json:"operation_id"`
	SeatID          string `json:"seat_id"`
	PoolID          string `json:"pool_id"`
	CurrentMemberID string `json:"current_member_id"`
	AssignmentEpoch uint64 `json:"assignment_epoch"`
	ReasonCode      string `json:"reason_code"`
	ReasonDetail    string `json:"reason_detail"`
}

func validateSuspendSnapshotBinding(canonical []byte, input application.BeginSuspendInput, seat application.SuspendSeatTarget) error {
	var snapshot suspendIntentSnapshot
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &snapshot); err != nil {
		return application.ErrWorkflowInvalidData
	}
	if err := json.Unmarshal(canonical, &fields); err != nil || len(fields) != 8 {
		return application.ErrWorkflowInvalidData
	}
	for _, name := range []string{
		"version", "operation_id", "seat_id", "pool_id", "current_member_id",
		"assignment_epoch", "reason_code", "reason_detail",
	} {
		if _, exists := fields[name]; !exists {
			return application.ErrWorkflowInvalidData
		}
	}
	if snapshot.Version != 1 || snapshot.OperationID != input.Key.OperationID ||
		snapshot.SeatID != input.SeatExternalID || snapshot.SeatID != seat.SeatExternalID ||
		snapshot.PoolID != seat.PoolExternalID || snapshot.CurrentMemberID != seat.CurrentMemberID ||
		snapshot.AssignmentEpoch != seat.AssignmentEpoch || snapshot.ReasonCode != input.ReasonCode ||
		snapshot.ReasonDetail != "operator requested suspension" {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func validateAndMarshalSuspendProgress(input application.CommitSuspendProgressInput) ([]byte, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || input.ExpectedAssignmentEpoch == 0 ||
		(input.CurrentConcurrency != nil && *input.CurrentConcurrency < 0) ||
		(input.PendingSettlements != nil && *input.PendingSettlements < 0) ||
		!validJSONOrEmpty(input.ResultSnapshot) {
		return nil, application.ErrWorkflowInvalidData
	}
	switch input.Progress {
	case application.SuspendCasePending:
		if input.Freeze != nil || input.CurrentConcurrency != nil || input.PendingSettlements != nil ||
			strings.TrimSpace(input.ErrorCode) == "" {
			return nil, application.ErrWorkflowInvalidData
		}
		return nil, nil
	case application.SuspendCaseDraining:
		if input.Freeze != nil || (input.CurrentConcurrency == nil) != (input.PendingSettlements == nil) ||
			(input.CurrentConcurrency == nil && strings.TrimSpace(input.ErrorCode) == "") || !validJSONObject(input.ResultSnapshot) {
			return nil, application.ErrWorkflowInvalidData
		}
		return nil, nil
	case application.SuspendCaseFrozen:
		freeze := input.Freeze
		if freeze == nil || input.CurrentConcurrency == nil || input.PendingSettlements == nil ||
			*input.CurrentConcurrency != 0 || *input.PendingSettlements != 0 ||
			freeze.OperationID != input.Key.OperationID || freeze.AssignmentEpoch != input.ExpectedAssignmentEpoch ||
			freeze.InFlight != 0 || freeze.PendingSettlements != 0 || freeze.CapturedAt.IsZero() ||
			!hasCanonicalFreezeWindows(freeze.Usage, freeze.WindowStarts) || !validJSONObject(input.ResultSnapshot) ||
			input.ErrorCode != "" || input.ErrorDetail != "" {
			return nil, application.ErrWorkflowInvalidData
		}
		encoded, err := json.Marshal(freeze)
		if err != nil || !validJSONObject(encoded) {
			return nil, application.ErrWorkflowInvalidData
		}
		return encoded, nil
	default:
		return nil, application.ErrWorkflowInvalidData
	}
}

func suspendObservations(input application.CommitSuspendProgressInput, record *application.StoredSuspensionCase) (*int, *int, error) {
	if input.Progress != application.SuspendCaseDraining || input.CurrentConcurrency != nil {
		return input.CurrentConcurrency, input.PendingSettlements, nil
	}
	// DRAINING 错误重试只能复用既有真实观察，不能用 nil/零值覆盖或降级回 PENDING。
	if record == nil || record.Status != application.SuspendCaseDraining ||
		record.CurrentConcurrency == nil || record.PendingSettlements == nil || strings.TrimSpace(input.ErrorCode) == "" {
		return nil, nil, application.ErrWorkflowInvalidState
	}
	return record.CurrentConcurrency, record.PendingSettlements, nil
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func hasCanonicalFreezeWindows(usage map[string]float64, starts map[string]*time.Time) bool {
	if len(usage) != 4 || len(starts) != 4 {
		return false
	}
	for _, name := range []string{"hourly", "daily", "weekly", "monthly"} {
		value, usageOK := usage[name]
		_, startOK := starts[name]
		if !usageOK || !startOK || value < 0 {
			return false
		}
	}
	return true
}

func lockSuspendSeat(ctx context.Context, tx *sql.Tx, externalID string) (application.SuspendSeatTarget, error) {
	// 先单独锁 Pool，和 Provision 使用同一公共锁序；之后才允许锁 Seat/Assignment。
	var poolID string
	if err := tx.QueryRowContext(ctx, `SELECT p.id
FROM seats s
JOIN pools p ON p.id = s.pool_id
WHERE s.external_id = $1
FOR UPDATE OF p`, externalID).Scan(&poolID); err != nil {
		return application.SuspendSeatTarget{}, translateNotFound("lock suspend pool", err)
	}
	row := tx.QueryRowContext(ctx, `SELECT s.id, s.external_id, p.external_id, owner.external_id,
current_member.external_id, s.status, s.assignment_epoch, p.membership_epoch
FROM seats s
JOIN pools p ON p.id = s.pool_id
JOIN members owner ON owner.id = s.owner_member_id AND owner.status = 'ACTIVE'
JOIN seat_assignments assignment ON assignment.seat_id = s.id AND assignment.status = 'ACTIVE'
JOIN members current_member ON current_member.id = assignment.member_id AND current_member.status = 'ACTIVE'
WHERE s.external_id = $1
	AND p.id = $2
  AND s.status IN ('ACTIVE', 'SUSPEND_PENDING', 'DRAINING', 'FROZEN')
  AND (assignment.starts_at IS NULL OR assignment.starts_at <= CURRENT_TIMESTAMP)
  AND (assignment.ends_at IS NULL OR assignment.ends_at > CURRENT_TIMESTAMP)
FOR UPDATE OF s, owner, assignment, current_member`, externalID, poolID)
	target := application.SuspendSeatTarget{}
	if err := row.Scan(&target.SeatID, &target.SeatExternalID, &target.PoolExternalID,
		&target.OwnerExternalID, &target.CurrentMemberID, &target.Status,
		&target.AssignmentEpoch, &target.MembershipEpoch); err != nil {
		return application.SuspendSeatTarget{}, translateNotFound("lock suspend seat", err)
	}
	return target, nil
}

func resolveSuspendSeatID(ctx context.Context, tx *sql.Tx, externalID string) (string, error) {
	var seatID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM seats WHERE external_id = $1`, externalID).Scan(&seatID); err != nil {
		return "", translateNotFound("resolve suspend seat", err)
	}
	return seatID, nil
}

func lockSuspendPoolByOperation(ctx context.Context, tx *sql.Tx, operationID string) error {
	var poolID string
	if err := tx.QueryRowContext(ctx, `SELECT p.id
FROM suspension_cases sc
JOIN seats s ON s.id = sc.seat_id
JOIN pools p ON p.id = s.pool_id
WHERE sc.integration_operation_id = $1 AND sc.migration_state = 'CURRENT'
FOR UPDATE OF p`, operationID).Scan(&poolID); err != nil {
		return translateNotFound("lock suspend progress pool", err)
	}
	return nil
}

func loadSuspendCaseTargetTx(ctx context.Context, tx *sql.Tx, key application.OperationKey,
	op *application.StoredOperation, forUpdate bool,
) (*application.SuspendTarget, error) {
	query := `SELECT ` + suspendCaseTargetColumns + suspendCaseTargetFrom
	if forUpdate {
		query += ` FOR UPDATE OF sc, s, owner, assignment, current_member`
	}
	caseRecord, seat, err := scanSuspendCaseTarget(tx.QueryRowContext(ctx, query, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load suspend case target", err)
	}
	if op.AggregateID != caseRecord.IntegrationOperationID || op.TargetExternalID != seat.SeatExternalID {
		return nil, application.ErrWorkflowCorruptState
	}
	return &application.SuspendTarget{Operation: op, Case: caseRecord, Seat: seat}, nil
}

func scanSuspendCaseTarget(row scanner) (*application.StoredSuspensionCase, application.SuspendSeatTarget, error) {
	record := &application.StoredSuspensionCase{}
	seat := application.SuspendSeatTarget{}
	var currentConcurrency, pendingSettlements sql.NullInt64
	var blockedAt, frozenAt sql.NullTime
	var freezeSnapshot []byte
	var errorCode sql.NullString
	if err := row.Scan(&record.ID, &record.IntegrationOperationID, &record.OperationID, &record.SeatID, &record.MigrationState,
		&record.Status, &record.ReasonCode, &record.ExpectedAssignmentEpoch, &currentConcurrency,
		&pendingSettlements, &blockedAt, &frozenAt, &freezeSnapshot, &errorCode,
		&record.Version, &record.CreatedAt, &record.UpdatedAt,
		&seat.SeatID, &seat.SeatExternalID, &seat.PoolExternalID, &seat.OwnerExternalID,
		&seat.CurrentMemberID, &seat.Status, &seat.AssignmentEpoch, &seat.MembershipEpoch); err != nil {
		return nil, application.SuspendSeatTarget{}, err
	}
	if currentConcurrency.Valid {
		value := int(currentConcurrency.Int64)
		record.CurrentConcurrency = &value
	}
	if pendingSettlements.Valid {
		value := int(pendingSettlements.Int64)
		record.PendingSettlements = &value
	}
	if blockedAt.Valid {
		record.BlockedAt = &blockedAt.Time
	}
	if frozenAt.Valid {
		record.FrozenAt = &frozenAt.Time
	}
	record.FreezeSnapshot = freezeSnapshot
	record.ErrorCode = errorCode.String
	return record, seat, nil
}

func translateSuspendWriteError(action string, err error) error {
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" &&
		strings.Contains(err.Error(), "uq_suspension_cases_open_seat") {
		return application.ErrWorkflowTargetConflict
	}
	return translateOperationWriteError(action, err)
}
