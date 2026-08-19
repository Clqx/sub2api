package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

const settlementCaseColumns = `src.id, src.integration_operation_id, src.seat_id, src.settlement_id,
src.expected_request_id, src.expected_assignment_epoch, src.expected_actor_client_id,
src.reason, src.evidence, src.status,
src.error_code, src.version, src.created_at, src.updated_at`

const settlementTargetColumns = settlementCaseColumns + `,
s.id, s.external_id, p.external_id, s.assignment_epoch, s.status`

const settlementTargetFrom = `
FROM settlement_resolution_cases src
JOIN integration_operations io ON io.id = src.integration_operation_id
JOIN seats s ON s.id = src.seat_id
JOIN pools p ON p.id = s.pool_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
  AND io.operation_type = 'RESOLVE_SETTLEMENT' AND io.target_type = 'SEAT'
  AND io.migration_state = 'CURRENT'`

const settlementResolutionColumns = `sr.id, sr.integration_operation_id, sr.settlement_resolution_case_id,
sr.trust_event_id, sr.upstream_seat_id, sr.external_seat_id, sr.settlement_id, sr.request_id,
sr.assignment_epoch, sr.operation_id, sr.actor_client_id, sr.reason, sr.evidence, sr.resolved_at, sr.created_at`

type settlementIdentity struct {
	SeatID, PoolID string
}

// BeginSettlementResolution 必须在 resolve 网络调用前提交 intent/case/lease。
func (s *Store) BeginSettlementResolution(ctx context.Context, input application.BeginSettlementResolutionInput) (*application.SettlementResolutionTarget, bool, error) {
	canonical, reason, evidence, err := validateBeginSettlementResolution(input)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin settlement resolution transaction: %w", err)
	}
	defer tx.Rollback()

	identity, err := resolveSettlementIdentity(ctx, tx, input.SeatExternalID)
	if err != nil {
		return nil, false, err
	}
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, 'RESOLVE_SETTLEMENT', 'SEAT', $3, $4, 'CURRENT', $5, $6::jsonb,
          'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, identity.SeatID,
		input.SeatExternalID, input.RequestHash[:], canonical))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateSettlementWriteError("begin settlement operation", scanErr)
	}
	if err := validateSettlementOperationIntent(op, input, canonical); err != nil {
		return nil, false, err
	}
	if !created && op.Status == application.OperationSucceeded {
		target, loadErr := loadSettlementTargetTx(ctx, tx, input.Key, op, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if loadErr = validateSettlementTargetReplay(input, target); loadErr != nil {
			return nil, false, loadErr
		}
		target.Resolution, loadErr = loadSettlementResolution(tx.QueryRowContext(ctx, `SELECT `+settlementResolutionColumns+`
FROM settlement_resolutions sr WHERE sr.integration_operation_id = $1`, op.AggregateID))
		if loadErr != nil {
			return nil, false, translateNotFound("load terminal settlement replay result", loadErr)
		}
		if loadErr = tx.Commit(); loadErr != nil {
			return nil, false, fmt.Errorf("commit terminal settlement replay: %w", loadErr)
		}
		return target, false, nil
	}
	if op.Status == application.OperationFailed {
		return nil, false, application.ErrWorkflowCorruptState
	}
	if err := lockSettlementPool(ctx, tx, identity.PoolID); err != nil {
		return nil, false, err
	}
	// 新 case 仅能从 DRAINING 发起；既有未决 case 在暂停流程先完成后可从 FROZEN 恢复。
	seat, err := lockSettlementSeat(ctx, tx, identity, input.ExpectedAssignmentEpoch, created)
	if err != nil {
		return nil, false, err
	}

	if created {
		_, err = tx.ExecContext(ctx, `INSERT INTO settlement_resolution_cases (
integration_operation_id, seat_id, settlement_id, expected_request_id, expected_assignment_epoch,
expected_actor_client_id, reason, evidence, status, version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'RESOLUTION_PENDING', 1,
          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, op.AggregateID, identity.SeatID, input.SettlementID,
			input.ExpectedRequestID, input.ExpectedAssignmentEpoch, input.ExpectedActorClientID, reason, evidence)
		if err != nil {
			return nil, false, translateSettlementWriteError("create settlement resolution case", err)
		}
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
    fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, application.ErrWorkflowLeaseHeld
	}
	if err != nil {
		return nil, false, fmt.Errorf("acquire initial settlement lease: %w", err)
	}
	target, err := loadSettlementTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, false, err
	}
	if target.Seat != seat || target.Case.SettlementID != input.SettlementID ||
		target.Case.ExpectedRequestID != input.ExpectedRequestID ||
		target.Case.ExpectedActorClientID != input.ExpectedActorClientID {
		return nil, false, application.ErrWorkflowCorruptState
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin settlement resolution: %w", err)
	}
	return target, created, nil
}

func (s *Store) LoadSettlementResolutionTarget(ctx context.Context, key application.OperationKey) (*application.SettlementResolutionTarget, error) {
	if !validKey(key.ClientID, key.OperationID) {
		return nil, application.ErrWorkflowInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
  AND migration_state = 'CURRENT'`, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load settlement resolution operation", err)
	}
	target, err := scanSettlementTarget(s.db.QueryRowContext(ctx, `SELECT `+settlementTargetColumns+
		settlementTargetFrom, key.ClientID, key.OperationID), op)
	if err != nil {
		return nil, translateNotFound("load settlement resolution target", err)
	}
	if op.Status == application.OperationSucceeded {
		resolution, loadErr := loadSettlementResolution(s.db.QueryRowContext(ctx, `SELECT `+settlementResolutionColumns+`
FROM settlement_resolutions sr WHERE sr.integration_operation_id = $1`, op.AggregateID))
		if loadErr != nil {
			return nil, translateNotFound("load stored settlement resolution", loadErr)
		}
		target.Resolution = resolution
	}
	return target, nil
}

// AcquireNextSettlementResolution 只扫描本工作流，避免恢复 worker 抢到无法处理的其他 operation。
func (s *Store) AcquireNextSettlementResolution(ctx context.Context, input application.AcquireNextSettlementResolutionInput) (*application.SettlementResolutionTarget, error) {
	if strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin settlement recovery lease: %w", err)
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, `WITH candidate AS (
    SELECT id FROM integration_operations
    WHERE operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
      AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
      AND (error_code IS NULL OR error_code <> 'OPERATOR_REVIEW_REQUIRED')
      AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
      AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
    ORDER BY COALESCE(next_attempt_at, created_at), created_at
    FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE integration_operations io
SET lease_owner = $1, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $2),
    fencing_token = io.fencing_token + 1, attempt_count = io.attempt_count + 1,
    version = io.version + 1, updated_at = CURRENT_TIMESTAMP
FROM candidate WHERE io.id = candidate.id
RETURNING `+operationColumns, input.LeaseOwner, input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("acquire next settlement resolution: %w", err)
	}
	target, err := loadSettlementTargetTx(ctx, tx, op.Key, op, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit settlement recovery lease: %w", err)
	}
	return target, nil
}

func (s *Store) CommitSettlementResolution(ctx context.Context, input application.CommitSettlementResolutionInput) (*application.StoredOperation, *application.StoredSettlementResolution, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin settlement success transaction: %w", err)
	}
	defer tx.Rollback()
	identity, err := resolveSettlementCaseIdentity(ctx, tx, input.Key)
	if err != nil {
		return nil, nil, err
	}
	op, err := lockSettlementOperation(ctx, tx, input.Key, input.LeaseOwner, input.FencingToken)
	if err != nil {
		return nil, nil, err
	}
	if err := lockSettlementPool(ctx, tx, identity.PoolID); err != nil {
		return nil, nil, err
	}
	seat, err := lockSettlementSeat(ctx, tx, identity.settlementIdentity, identity.ExpectedAssignmentEpoch, false)
	if err != nil {
		return nil, nil, err
	}
	target, err := loadSettlementTargetTx(ctx, tx, input.Key, op, true)
	if err != nil {
		return nil, nil, err
	}
	if err := validateSettlementSuccess(input, target, seat); err != nil {
		return nil, nil, err
	}
	resultSnapshot, err := json.Marshal(input.Result)
	if err != nil || !validJSONObject(resultSnapshot) {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	payload, err := settlementTrustPayload(target, input.Result)
	if err != nil {
		return nil, nil, err
	}
	var previousHash []byte
	err = tx.QueryRowContext(ctx, `SELECT event_hash FROM trust_events
WHERE seat_id = $1 ORDER BY recorded_at DESC, id::text DESC LIMIT 1`, identity.SeatID).Scan(&previousHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("load previous settlement trust hash: %w", err)
	}
	var trustEventID string
	err = tx.QueryRowContext(ctx, `INSERT INTO trust_events (
pool_id, seat_id, actor_type, actor_ref, event_type, event_payload,
previous_event_hash, event_hash, occurred_at, recorded_at
) VALUES ($1, $2, 'SUB2API', $3, 'SETTLEMENT_RESOLVED', $4::jsonb,
          $5, settlement_trust_event_hash($5, $4::jsonb), $6, CURRENT_TIMESTAMP)
RETURNING id`, identity.PoolID, identity.SeatID, target.Case.ExpectedActorClientID, payload, previousHash,
		input.Result.ResolvedAt.UTC()).Scan(&trustEventID)
	if err != nil {
		return nil, nil, fmt.Errorf("append settlement trust event: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE settlement_resolution_cases
SET status = 'SUCCEEDED', error_code = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status = 'RESOLUTION_PENDING'`, op.AggregateID)
	if err != nil {
		return nil, nil, fmt.Errorf("complete settlement resolution case: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, nil, application.ErrWorkflowInvalidState
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = 'SUCCEEDED', response_snapshot = $5::jsonb, error_code = NULL, error_detail = NULL,
    next_attempt_at = NULL, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, resultSnapshot))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, nil, fmt.Errorf("complete settlement resolution operation: %w", err)
	}
	var resolutionID string
	err = tx.QueryRowContext(ctx, `INSERT INTO settlement_resolutions (
integration_operation_id, settlement_resolution_case_id, trust_event_id, upstream_seat_id,
external_seat_id, settlement_id, request_id, assignment_epoch, operation_id, actor_client_id,
reason, evidence, resolved_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
RETURNING id`, op.AggregateID, target.Case.ID, trustEventID, input.Result.SeatID,
		input.Result.ExternalSeatID, input.Result.SettlementID, input.Result.RequestID,
		input.Result.AssignmentEpoch, input.Result.OperationID, input.Result.ActorClientID,
		input.Result.Reason, input.Result.Evidence, input.Result.ResolvedAt.UTC()).Scan(&resolutionID)
	if err != nil {
		return nil, nil, translateSettlementWriteError("insert settlement resolution result", err)
	}
	resolution, err := loadSettlementResolution(tx.QueryRowContext(ctx, `SELECT `+settlementResolutionColumns+`
FROM settlement_resolutions sr WHERE sr.id = $1`, resolutionID))
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit settlement resolution success: %w", err)
	}
	return op, resolution, nil
}

func (s *Store) CommitSettlementResolutionFailure(ctx context.Context, input application.CommitSettlementResolutionFailureInput) (*application.SettlementResolutionTarget, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || strings.TrimSpace(input.ErrorCode) == "" || len(input.ErrorCode) > 128 ||
		(input.ErrorCode == "OPERATOR_REVIEW_REQUIRED") != (input.NextAttemptAt == nil) {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin settlement failure transaction: %w", err)
	}
	defer tx.Rollback()
	identity, err := resolveSettlementCaseIdentity(ctx, tx, input.Key)
	if err != nil {
		return nil, err
	}
	op, err := lockSettlementOperation(ctx, tx, input.Key, input.LeaseOwner, input.FencingToken)
	if err != nil {
		return nil, err
	}
	if err := lockSettlementPool(ctx, tx, identity.PoolID); err != nil {
		return nil, err
	}
	if _, err := lockSettlementSeat(ctx, tx, identity.settlementIdentity, identity.ExpectedAssignmentEpoch, false); err != nil {
		return nil, err
	}
	if _, err := loadSettlementTargetTx(ctx, tx, input.Key, op, true); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE settlement_resolution_cases
SET status = $2, error_code = NULLIF($3, ''), version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status = 'RESOLUTION_PENDING'`, op.AggregateID,
		application.SettlementResolutionPending, input.ErrorCode)
	if err != nil {
		return nil, fmt.Errorf("record settlement resolution case failure: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, application.ErrWorkflowInvalidState
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = $5, response_snapshot = NULL, error_code = $6, error_detail = NULL,
    next_attempt_at = $7, completed_at = NULL,
    lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, application.OperationReconcileRequired, input.ErrorCode, input.NextAttemptAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("record settlement resolution operation failure: %w", err)
	}
	target, err := loadSettlementTargetTx(ctx, tx, input.Key, op, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit settlement resolution failure: %w", err)
	}
	return target, nil
}

func validateBeginSettlementResolution(input application.BeginSettlementResolutionInput) ([]byte, string, string, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.SeatExternalID) == "" ||
		strings.TrimSpace(input.SettlementID) == "" || strings.TrimSpace(input.ExpectedRequestID) == "" ||
		strings.TrimSpace(input.ExpectedActorClientID) == "" ||
		input.ExpectedAssignmentEpoch == 0 || strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 ||
		len(input.SeatExternalID) > 128 || len(input.SettlementID) > 128 || len(input.ExpectedRequestID) > 128 ||
		len(input.ExpectedActorClientID) > 128 {
		return nil, "", "", application.ErrWorkflowInvalidData
	}
	canonical, err := canonicalJSONObject(input.RequestSnapshot)
	if err != nil {
		return nil, "", "", application.ErrWorkflowInvalidData
	}
	var snapshot struct {
		Version                 int    `json:"version"`
		OperationID             string `json:"operation_id"`
		SeatID                  string `json:"seat_id"`
		SettlementID            string `json:"settlement_id"`
		ExpectedRequestID       string `json:"expected_request_id"`
		ExpectedAssignmentEpoch uint64 `json:"expected_assignment_epoch"`
		ExpectedActorClientID   string `json:"expected_actor_client_id"`
		Reason                  string `json:"reason"`
		Evidence                string `json:"evidence"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(canonical, &snapshot) != nil || json.Unmarshal(canonical, &fields) != nil || len(fields) != 9 ||
		snapshot.Version != 1 || snapshot.OperationID != input.Key.OperationID ||
		snapshot.SeatID != input.SeatExternalID || snapshot.SettlementID != input.SettlementID ||
		snapshot.ExpectedRequestID != input.ExpectedRequestID ||
		snapshot.ExpectedAssignmentEpoch != input.ExpectedAssignmentEpoch ||
		snapshot.ExpectedActorClientID != input.ExpectedActorClientID ||
		strings.TrimSpace(snapshot.Reason) == "" || strings.TrimSpace(snapshot.Evidence) == "" ||
		len(snapshot.Reason) > 1000 || len(snapshot.Evidence) > 4000 {
		return nil, "", "", application.ErrWorkflowInvalidData
	}
	for _, key := range []string{"version", "operation_id", "seat_id", "settlement_id", "expected_request_id", "expected_assignment_epoch", "expected_actor_client_id", "reason", "evidence"} {
		if _, ok := fields[key]; !ok {
			return nil, "", "", application.ErrWorkflowInvalidData
		}
	}
	return canonical, snapshot.Reason, snapshot.Evidence, nil
}

func validateSettlementOperationIntent(op *application.StoredOperation, input application.BeginSettlementResolutionInput, canonical []byte) error {
	if op == nil || op.Kind != application.OperationResolveSettlement || op.TargetType != "SEAT" ||
		op.TargetExternalID != input.SeatExternalID || op.MigrationState != "CURRENT" ||
		!bytes.Equal(op.RequestHash[:], input.RequestHash[:]) {
		return application.ErrWorkflowHashDrift
	}
	stored, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || !bytes.Equal(stored, canonical) {
		return application.ErrWorkflowHashDrift
	}
	return nil
}

func validateSettlementTargetReplay(input application.BeginSettlementResolutionInput, target *application.SettlementResolutionTarget) error {
	if target == nil || target.Seat.SeatExternalID != input.SeatExternalID ||
		target.Case.SettlementID != input.SettlementID || target.Case.ExpectedRequestID != input.ExpectedRequestID ||
		target.Case.ExpectedAssignmentEpoch != input.ExpectedAssignmentEpoch ||
		target.Case.ExpectedActorClientID != input.ExpectedActorClientID {
		return application.ErrWorkflowHashDrift
	}
	return nil
}

func validateSettlementSuccess(input application.CommitSettlementResolutionInput,
	target *application.SettlementResolutionTarget, seat application.SettlementResolutionSeat) error {
	result := input.Result
	if target == nil || target.Case.Status != application.SettlementResolutionPending ||
		seat.AssignmentEpoch != target.Case.ExpectedAssignmentEpoch || result.SeatID <= 0 || result.ResolvedAt.IsZero() ||
		result.ExternalSeatID != seat.SeatExternalID || result.SettlementID != target.Case.SettlementID ||
		result.RequestID != target.Case.ExpectedRequestID || result.AssignmentEpoch == 0 ||
		uint64(result.AssignmentEpoch) != target.Case.ExpectedAssignmentEpoch ||
		result.OperationID != input.Key.OperationID || result.ActorClientID != target.Case.ExpectedActorClientID ||
		result.Reason != target.Case.Reason || result.Evidence != target.Case.Evidence {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

func resolveSettlementIdentity(ctx context.Context, tx *sql.Tx, externalSeatID string) (settlementIdentity, error) {
	var identity settlementIdentity
	err := tx.QueryRowContext(ctx, `SELECT id, pool_id FROM seats WHERE external_id = $1`, externalSeatID).
		Scan(&identity.SeatID, &identity.PoolID)
	if err != nil {
		return identity, translateNotFound("resolve settlement Seat", err)
	}
	return identity, nil
}

func lockSettlementPool(ctx context.Context, tx *sql.Tx, poolID string) error {
	var lockedID string
	err := tx.QueryRowContext(ctx, `SELECT id FROM pools WHERE id = $1 AND status <> 'CLOSED' FOR UPDATE`, poolID).Scan(&lockedID)
	if err != nil {
		return translateNotFound("lock settlement Pool", err)
	}
	return nil
}

func lockSettlementSeat(ctx context.Context, tx *sql.Tx, identity settlementIdentity, expectedEpoch uint64,
	requireDraining bool) (application.SettlementResolutionSeat, error) {
	seat := application.SettlementResolutionSeat{}
	allowedStatuses := "('DRAINING', 'FROZEN')"
	if requireDraining {
		allowedStatuses = "('DRAINING')"
	}
	err := tx.QueryRowContext(ctx, `SELECT s.id, s.external_id, p.external_id, s.assignment_epoch, s.status
FROM seats s JOIN pools p ON p.id = s.pool_id
WHERE s.id = $1 AND s.pool_id = $2 AND s.assignment_epoch = $3
  AND s.status IN `+allowedStatuses+`
FOR UPDATE OF s`, identity.SeatID, identity.PoolID, expectedEpoch).Scan(&seat.SeatID,
		&seat.SeatExternalID, &seat.PoolExternalID, &seat.AssignmentEpoch, &seat.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return seat, application.ErrWorkflowInvalidState
	}
	if err != nil {
		return seat, fmt.Errorf("lock settlement Seat: %w", err)
	}
	return seat, nil
}

type settlementCaseIdentity struct {
	settlementIdentity
	ExpectedAssignmentEpoch uint64
}

func resolveSettlementCaseIdentity(ctx context.Context, tx *sql.Tx, key application.OperationKey) (settlementCaseIdentity, error) {
	var identity settlementCaseIdentity
	err := tx.QueryRowContext(ctx, `SELECT src.seat_id, s.pool_id, src.expected_assignment_epoch
FROM settlement_resolution_cases src
JOIN integration_operations io ON io.id = src.integration_operation_id
JOIN seats s ON s.id = src.seat_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
  AND io.operation_type = 'RESOLVE_SETTLEMENT' AND src.status = 'RESOLUTION_PENDING'`,
		key.ClientID, key.OperationID).Scan(&identity.SeatID, &identity.PoolID, &identity.ExpectedAssignmentEpoch)
	if err != nil {
		return identity, translateNotFound("resolve settlement case identity", err)
	}
	return identity, nil
}

func lockSettlementOperation(ctx context.Context, tx *sql.Tx, key application.OperationKey,
	owner string, fence int64) (*application.StoredOperation, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2
  AND operation_type = 'RESOLVE_SETTLEMENT' AND target_type = 'SEAT'
  AND migration_state = 'CURRENT' AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
FOR UPDATE`, key.ClientID, key.OperationID, fence, owner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("lock settlement operation: %w", err)
	}
	return op, nil
}

func loadSettlementTargetTx(ctx context.Context, tx *sql.Tx, key application.OperationKey,
	op *application.StoredOperation, forUpdate bool) (*application.SettlementResolutionTarget, error) {
	query := `SELECT ` + settlementTargetColumns + settlementTargetFrom
	if forUpdate {
		query += ` FOR UPDATE OF src`
	}
	target, err := scanSettlementTarget(tx.QueryRowContext(ctx, query, key.ClientID, key.OperationID), op)
	if err != nil {
		return nil, translateNotFound("load settlement target transaction", err)
	}
	return target, nil
}

func scanSettlementTarget(row scanner, op *application.StoredOperation) (*application.SettlementResolutionTarget, error) {
	target := &application.SettlementResolutionTarget{Operation: op, Case: &application.StoredSettlementResolutionCase{}}
	var errorCode sql.NullString
	err := row.Scan(&target.Case.ID, &target.Case.IntegrationOperationID, &target.Case.SeatID,
		&target.Case.SettlementID, &target.Case.ExpectedRequestID, &target.Case.ExpectedAssignmentEpoch,
		&target.Case.ExpectedActorClientID, &target.Case.Reason, &target.Case.Evidence, &target.Case.Status, &errorCode,
		&target.Case.Version, &target.Case.CreatedAt, &target.Case.UpdatedAt,
		&target.Seat.SeatID, &target.Seat.SeatExternalID, &target.Seat.PoolExternalID,
		&target.Seat.AssignmentEpoch, &target.Seat.Status)
	if err != nil {
		return nil, err
	}
	if errorCode.Valid {
		target.Case.ErrorCode = errorCode.String
	}
	return target, nil
}

func loadSettlementResolution(row scanner) (*application.StoredSettlementResolution, error) {
	resolution := &application.StoredSettlementResolution{}
	err := row.Scan(&resolution.ID, &resolution.IntegrationOperationID, &resolution.CaseID,
		&resolution.TrustEventID, &resolution.UpstreamSeatID, &resolution.ExternalSeatID,
		&resolution.SettlementID, &resolution.RequestID, &resolution.AssignmentEpoch,
		&resolution.OperationID, &resolution.ActorClientID, &resolution.Reason, &resolution.Evidence,
		&resolution.ResolvedAt, &resolution.CreatedAt)
	if err != nil {
		return nil, err
	}
	return resolution, nil
}

func settlementTrustPayload(target *application.SettlementResolutionTarget, result application.SettlementResolution) ([]byte, error) {
	reasonHash, evidenceHash := sha256.Sum256([]byte(result.Reason)), sha256.Sum256([]byte(result.Evidence))
	payload := struct {
		Version         int    `json:"version"`
		OperationID     string `json:"operation_id"`
		SettlementID    string `json:"settlement_id"`
		RequestID       string `json:"request_id"`
		AssignmentEpoch uint64 `json:"assignment_epoch"`
		UpstreamSeatID  int64  `json:"upstream_seat_id"`
		ExternalSeatID  string `json:"external_seat_id"`
		ActorClientID   string `json:"actor_client_id"`
		ResolvedAt      string `json:"resolved_at"`
		ReasonSHA256    string `json:"reason_sha256"`
		EvidenceSHA256  string `json:"evidence_sha256"`
	}{
		Version: 1, OperationID: result.OperationID, SettlementID: result.SettlementID,
		RequestID: result.RequestID, AssignmentEpoch: target.Case.ExpectedAssignmentEpoch,
		UpstreamSeatID: result.SeatID, ExternalSeatID: result.ExternalSeatID,
		ActorClientID: result.ActorClientID, ResolvedAt: result.ResolvedAt.UTC().Format(time.RFC3339Nano),
		ReasonSHA256: hex.EncodeToString(reasonHash[:]), EvidenceSHA256: hex.EncodeToString(evidenceHash[:]),
	}
	encoded, err := json.Marshal(payload)
	if err != nil || !validJSONObject(encoded) {
		return nil, application.ErrWorkflowInvalidData
	}
	return encoded, nil
}

func translateSettlementWriteError(action string, err error) error {
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" &&
		(strings.Contains(err.Error(), "uq_settlement_resolution_live_target") ||
			strings.Contains(err.Error(), "uq_settlement_resolutions_target")) {
		return application.ErrWorkflowTargetConflict
	}
	return translateOperationWriteError(action, err)
}
