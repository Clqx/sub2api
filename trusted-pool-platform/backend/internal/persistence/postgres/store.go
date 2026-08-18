package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

const operationColumns = `id, integration_client_id, operation_id, operation_type, target_type,
target_external_id, migration_state, request_hash, request_snapshot, status, attempt_count, response_snapshot,
error_code, error_detail, fencing_token, lease_owner, lease_expires_at, next_attempt_at,
created_at, updated_at, completed_at`

const claimColumns = `cc.id, cc.integration_operation_id, io.integration_client_id, io.operation_id, io.operation_type,
cc.seat_id, s.external_id, cc.target_member_id, m.external_id, cc.claim_operation_id, cc.claim_token_hash,
cc.credential_fingerprint, cc.claim_intent_hash, cc.envelope_algorithm, cc.envelope_key_ref, cc.envelope_ciphertext,
cc.envelope_nonce, cc.envelope_aad_hash, cc.wrapped_dek_kms, cc.status,
cc.ack_response_snapshot, cc.error_code, cc.fencing_token, cc.lease_owner, cc.lease_expires_at,
cc.expires_at, (cc.expires_at <= CURRENT_TIMESTAMP), cc.claimed_at, cc.terminal_at, cc.created_at, cc.updated_at`

// Store 只依赖 database/sql，由组合根注入已配置驱动的 DB。
type Store struct {
	db *sql.DB
}

var _ application.WorkflowStore = (*Store)(nil)

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, application.ErrWorkflowInvalidData
	}
	return &Store{db: db}, nil
}

func (s *Store) BeginOperation(ctx context.Context, input application.BeginOperationInput) (*application.StoredOperation, bool, error) {
	if err := validateBeginOperation(input); err != nil {
		return nil, false, err
	}
	canonicalSnapshot, err := canonicalJSONObject(input.RequestSnapshot)
	if err != nil {
		return nil, false, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin operation transaction: %w", err)
	}
	defer tx.Rollback()

	query := `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_external_id, migration_state,
request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, 'CURRENT', $6, $7::jsonb, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING
RETURNING ` + operationColumns
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, query,
		input.Key.ClientID, input.Key.OperationID, input.Kind, input.TargetType, input.TargetExternalID,
		input.RequestHash[:], canonicalSnapshot))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2
FOR UPDATE`, input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateOperationWriteError("begin operation", scanErr)
	}
	if op.MigrationState != "CURRENT" {
		return nil, false, application.ErrWorkflowInvalidState
	}
	if !bytes.Equal(op.RequestHash[:], input.RequestHash[:]) {
		return nil, false, application.ErrWorkflowHashDrift
	}
	storedSnapshot, canonicalErr := canonicalJSONObject(op.RequestSnapshot)
	if canonicalErr != nil || !bytes.Equal(storedSnapshot, canonicalSnapshot) {
		return nil, false, application.ErrWorkflowHashDrift
	}
	if op.Kind != input.Kind || op.TargetType != input.TargetType || op.TargetExternalID != input.TargetExternalID {
		return nil, false, application.ErrWorkflowHashDrift
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin operation: %w", err)
	}
	return op, created, nil
}

func (s *Store) LoadOperation(ctx context.Context, key application.OperationKey) (*application.StoredOperation, error) {
	if !validKey(key.ClientID, key.OperationID) {
		return nil, application.ErrWorkflowInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2`, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load operation", err)
	}
	return op, nil
}

func (s *Store) AcquireOperationLease(ctx context.Context, input application.AcquireOperationLeaseInput) (*application.OperationLease, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	query := `UPDATE integration_operations
SET lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
    fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND migration_state = 'CURRENT'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING ` + operationColumns
	op, err := scanOperation(s.db.QueryRowContext(ctx, query, input.Key.ClientID, input.Key.OperationID,
		input.LeaseOwner, input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowLeaseHeld
	}
	if err != nil {
		return nil, fmt.Errorf("acquire operation lease: %w", err)
	}
	return &application.OperationLease{Operation: op, FencingToken: op.FencingToken}, nil
}

// ValidateProvisionPreflight 在外部开通调用前核对数据库中的可信绑定。
// 这里不持有跨网络事务；CommitProvisionWithCredentialClaim 会在最终提交时再次加锁校验。
func (s *Store) ValidateProvisionPreflight(ctx context.Context, input application.ProvisionPreflightInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.PoolExternalID) == "" ||
		strings.TrimSpace(input.SeatExternalID) == "" || strings.TrimSpace(input.OwnerExternalID) == "" ||
		input.ExistingGroupID <= 0 || input.AssignmentEpoch == 0 {
		return application.ErrWorkflowInvalidData
	}
	var membershipEpoch uint64
	err := s.db.QueryRowContext(ctx, `SELECT p.membership_epoch
FROM pools p
JOIN membership_epochs me
  ON me.pool_id = p.id AND me.epoch = p.membership_epoch AND me.status = 'ACTIVE'
JOIN membership_epoch_members mem ON mem.epoch_id = me.id
JOIN members owner
  ON owner.id = mem.member_id AND owner.external_id = $2 AND owner.status = 'ACTIVE'
JOIN integration_operations io
  ON io.integration_client_id = $5 AND io.operation_id = $6
 AND io.migration_state = 'CURRENT' AND io.operation_type = 'PROVISION'
 AND io.target_type = 'SEAT' AND io.target_external_id = $4
WHERE p.external_id = $1 AND p.sub2api_group_id = $3 AND p.membership_epoch > 0
  AND p.status IN ('PROVISIONING', 'WAITING_MEMBERS', 'ACTIVE')
  AND NOT EXISTS (
    SELECT 1 FROM integration_operations other
    WHERE other.operation_type = 'PROVISION' AND other.target_type = 'SEAT'
      AND other.target_external_id = $4 AND other.status = 'SUCCEEDED'
      AND NOT (other.integration_client_id = $5 AND other.operation_id = $6)
  )
  AND NOT EXISTS (
    SELECT 1 FROM seats s
    WHERE s.external_id = $4 AND (
      s.pool_id <> p.id OR s.status NOT IN ('PROVISIONING', 'ACTIVE')
      OR s.assignment_epoch > $7
      OR (s.owner_member_id IS NOT NULL AND s.owner_member_id <> owner.id)
      OR (s.status = 'ACTIVE' AND (io.target_id IS NULL OR io.target_id <> s.id))
    )
  )`, input.PoolExternalID, input.OwnerExternalID, input.ExistingGroupID, input.SeatExternalID,
		input.Key.ClientID, input.Key.OperationID, input.AssignmentEpoch).Scan(&membershipEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return application.ErrWorkflowInvalidState
	}
	if err != nil {
		return fmt.Errorf("validate provision preflight: %w", err)
	}
	if membershipEpoch == 0 {
		return application.ErrWorkflowInvalidState
	}
	return nil
}

// AcquireNextOperationLease 供恢复 worker 原子发现并抢占到期工作；SKIP LOCKED 避免多副本互相等待。
func (s *Store) AcquireNextOperationLease(ctx context.Context, input application.AcquireNextOperationLeaseInput) (*application.OperationLease, error) {
	if strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	query := `WITH candidate AS (
    SELECT id FROM integration_operations
    WHERE status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
      AND migration_state = 'CURRENT'
      AND (error_code IS NULL OR error_code <> 'CALLER_REPLAY_REQUIRED')
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
RETURNING ` + operationColumns
	op, err := scanOperation(s.db.QueryRowContext(ctx, query, input.LeaseOwner, input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("acquire next operation lease: %w", err)
	}
	return &application.OperationLease{Operation: op, FencingToken: op.FencingToken}, nil
}

func (s *Store) CommitOperation(ctx context.Context, input application.CommitOperationInput) (*application.StoredOperation, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || !validCommitStatus(input.Status) || !validJSONOrEmpty(input.ResultSnapshot) {
		return nil, application.ErrWorkflowInvalidData
	}
	terminal := isOperationTerminal(input.Status)
	query := `UPDATE integration_operations
SET status = $5, response_snapshot = NULLIF($6::text, '')::jsonb,
    error_code = NULLIF($7, ''), error_detail = NULLIF($8, ''), next_attempt_at = $9,
    completed_at = CASE WHEN $10 THEN CURRENT_TIMESTAMP ELSE NULL END,
    lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND migration_state = 'CURRENT'
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND NOT ($5 = 'SUCCEEDED' AND operation_type IN (
      'PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY'
  ))
RETURNING ` + operationColumns
	op, err := scanOperation(s.db.QueryRowContext(ctx, query, input.Key.ClientID, input.Key.OperationID,
		input.FencingToken, input.LeaseOwner, input.Status, string(input.ResultSnapshot), input.ErrorCode, input.ErrorDetail,
		input.NextAttemptAt, terminal))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("commit operation: %w", err)
	}
	return op, nil
}

// CommitOperationWithCredentialClaim 将凭据型 operation 成功与 claim 建立放在同一事务中；任一绑定门禁失败都会整体回滚。
func (s *Store) CommitOperationWithCredentialClaim(ctx context.Context, input application.CommitOperationWithCredentialClaimInput) (*application.StoredOperation, *application.StoredCredentialClaim, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || !validJSONObject(input.ResultSnapshot) ||
		input.Claim.Key.ClientID != input.Key.ClientID || input.Claim.Key.OperationID != input.Key.OperationID {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	if err := validateCreateClaim(input.Claim); err != nil {
		return nil, nil, err
	}
	intentHash, err := credentialClaimIntentHash(input.Claim)
	if err != nil {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin operation and claim transaction: %w", err)
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = 'SUCCEEDED', response_snapshot = $5::jsonb, error_code = NULL, error_detail = NULL,
    next_attempt_at = NULL, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL,
    lease_expires_at = NULL,
    target_id = COALESCE(target_id, (
        SELECT s.id FROM seats s
        WHERE s.external_id = target_external_id AND s.external_id = $6 AND s.status = 'ACTIVE'
    )),
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND migration_state = 'CURRENT' AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND target_type = 'SEAT'
  AND EXISTS (SELECT 1 FROM seats s WHERE s.external_id = target_external_id
      AND s.external_id = $6 AND s.status = 'ACTIVE')
  AND operation_type IN ('PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, input.ResultSnapshot, input.Claim.SeatExternalID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, nil, fmt.Errorf("commit credential operation: %w", err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_token_hash, credential_fingerprint, claim_intent_hash, envelope_algorithm, envelope_key_ref,
envelope_ciphertext, envelope_nonce, envelope_aad_hash, wrapped_dek_kms, expires_at, created_at, updated_at
)
SELECT io.id, s.id, m.id, $5, 'READY', $6, $7, $8, $9, $10, $11, $12, $13, $14,
       CURRENT_TIMESTAMP + make_interval(secs => $15), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM integration_operations io
JOIN seats s ON s.external_id = io.target_external_id AND s.external_id = $3 AND s.status = 'ACTIVE'
JOIN members m ON m.external_id = $4 AND m.status = 'ACTIVE'
JOIN seat_assignments sa ON sa.seat_id = s.id AND sa.member_id = m.id AND sa.status = 'ACTIVE'
  AND (sa.starts_at IS NULL OR sa.starts_at <= CURRENT_TIMESTAMP)
  AND (sa.ends_at IS NULL OR sa.ends_at > CURRENT_TIMESTAMP)
WHERE io.integration_client_id = $1 AND io.operation_id = $2 AND io.migration_state = 'CURRENT'
  AND io.status = 'SUCCEEDED' AND io.target_type = 'SEAT'
  AND io.operation_type IN ('PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')
  AND (io.operation_type <> 'PROVISION' OR s.owner_member_id = m.id)
ON CONFLICT (integration_operation_id) DO NOTHING`, input.Key.ClientID, input.Key.OperationID,
		input.Claim.SeatExternalID, input.Claim.TargetMemberExternalID, input.Claim.ClaimOperationID,
		input.Claim.TokenHash[:], input.Claim.CredentialFingerprint[:], intentHash[:],
		input.Claim.Envelope.Algorithm, input.Claim.Envelope.KeyRef, input.Claim.Envelope.Ciphertext,
		input.Claim.Envelope.Nonce, input.Claim.Envelope.AADHash[:], input.Claim.Envelope.WrappedDEK,
		input.Claim.ClaimTTL.Seconds())
	if err != nil {
		return nil, nil, fmt.Errorf("insert atomic credential claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return nil, nil, application.ErrWorkflowInvalidState
	}
	claim, err := loadClaimTx(ctx, tx, input.Claim.Key, false)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit operation and claim transaction: %w", err)
	}
	return op, claim, nil
}

// CommitProvisionWithCredentialClaim 在一个事务内激活 Seat/owner Assignment、完成 Operation 并创建加密 claim。
func (s *Store) CommitProvisionWithCredentialClaim(ctx context.Context, input application.CommitProvisionWithCredentialClaimInput) (*application.StoredOperation, *application.StoredCredentialClaim, *application.PersistedSeat, error) {
	opInput := input.Operation
	if strings.TrimSpace(input.PoolExternalID) == "" || strings.TrimSpace(input.OwnerExternalID) == "" ||
		input.ExistingGroupID <= 0 || input.AssignmentEpoch == 0 || opInput.Claim.SeatExternalID == "" ||
		opInput.Claim.TargetMemberExternalID != input.OwnerExternalID {
		return nil, nil, nil, application.ErrWorkflowInvalidData
	}
	if err := validateCreateClaim(opInput.Claim); err != nil {
		return nil, nil, nil, err
	}
	intentHash, err := credentialClaimIntentHash(opInput.Claim)
	if err != nil {
		return nil, nil, nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("begin provision aggregate transaction: %w", err)
	}
	defer tx.Rollback()
	var poolID, ownerMemberID string
	var membershipEpoch uint64
	err = tx.QueryRowContext(ctx, `SELECT p.id, p.membership_epoch, m.id
FROM pools p
JOIN membership_epochs me
  ON me.pool_id = p.id AND me.epoch = p.membership_epoch AND me.status = 'ACTIVE'
JOIN membership_epoch_members mem ON mem.epoch_id = me.id
JOIN members m ON m.id = mem.member_id AND m.external_id = $2 AND m.status = 'ACTIVE'
WHERE p.external_id = $1 AND p.sub2api_group_id = $3 AND p.membership_epoch > 0
  AND p.status IN ('PROVISIONING', 'WAITING_MEMBERS', 'ACTIVE')
FOR UPDATE OF p, me, mem, m`, input.PoolExternalID, input.OwnerExternalID, input.ExistingGroupID).Scan(&poolID, &membershipEpoch, &ownerMemberID)
	if err != nil {
		return nil, nil, nil, translateNotFound("lock provision pool and owner", err)
	}
	var targetOccupied bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM integration_operations
    WHERE operation_type = 'PROVISION' AND target_type = 'SEAT'
      AND target_external_id = $1 AND status = 'SUCCEEDED'
      AND NOT (integration_client_id = $2 AND operation_id = $3)
)`, opInput.Claim.SeatExternalID, opInput.Key.ClientID, opInput.Key.OperationID).Scan(&targetOccupied)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("check provision seat ownership: %w", err)
	}
	if targetOccupied {
		return nil, nil, nil, application.ErrWorkflowTargetConflict
	}
	var operationTargetID sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT target_id FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2 AND migration_state = 'CURRENT'
  AND operation_type = 'PROVISION' AND target_external_id = $3
FOR UPDATE`, opInput.Key.ClientID, opInput.Key.OperationID, opInput.Claim.SeatExternalID).Scan(&operationTargetID)
	if err != nil {
		return nil, nil, nil, translateNotFound("lock provision operation", err)
	}
	var seatID string
	var existingAssignmentEpoch uint64
	var existingOwner, existingSeatStatus sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, assignment_epoch, owner_member_id, status FROM seats
WHERE external_id = $1 AND pool_id = $2 AND status IN ('PROVISIONING', 'ACTIVE')
FOR UPDATE`, opInput.Claim.SeatExternalID, poolID).Scan(&seatID, &existingAssignmentEpoch, &existingOwner, &existingSeatStatus)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `INSERT INTO seats (
external_id, pool_id, seat_no, status, assignment_epoch, owner_member_id, created_at, updated_at
)
SELECT $1, $2, COALESCE(MAX(seat_no), 0) + 1, 'ACTIVE', $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM seats WHERE pool_id = $2
RETURNING id`, opInput.Claim.SeatExternalID, poolID, input.AssignmentEpoch, ownerMemberID).Scan(&seatID)
	} else if err == nil {
		if existingSeatStatus.String == "ACTIVE" && (!operationTargetID.Valid || operationTargetID.String != seatID) {
			return nil, nil, nil, application.ErrWorkflowTargetConflict
		}
		if existingAssignmentEpoch > input.AssignmentEpoch || (existingOwner.Valid && existingOwner.String != ownerMemberID) {
			return nil, nil, nil, application.ErrWorkflowInvalidState
		}
		var seatResult sql.Result
		seatResult, err = tx.ExecContext(ctx, `UPDATE seats
SET status = 'ACTIVE', assignment_epoch = $2, owner_member_id = $3,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND (owner_member_id IS NULL OR owner_member_id = $3)`, seatID, input.AssignmentEpoch, ownerMemberID)
		if err == nil {
			if rows, rowsErr := seatResult.RowsAffected(); rowsErr != nil || rows != 1 {
				return nil, nil, nil, application.ErrWorkflowInvalidState
			}
		}
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("activate provision seat: %w", err)
	}
	assignmentResult, err := tx.ExecContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, starts_at, created_at, updated_at
)
SELECT $1, $2, $3, 'PERMANENT', 'ACTIVE', $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM seat_assignments WHERE seat_id = $1 AND status = 'ACTIVE')`,
		seatID, poolID, ownerMemberID, input.AssignmentEpoch)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create provision assignment: %w", err)
	}
	assignmentRows, err := assignmentResult.RowsAffected()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read provision assignment result: %w", err)
	}
	if assignmentRows == 0 {
		result, updateErr := tx.ExecContext(ctx, `UPDATE seat_assignments
SET assignment_epoch = $3, starts_at = COALESCE(starts_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP
WHERE seat_id = $1 AND member_id = $2 AND status = 'ACTIVE'`, seatID, ownerMemberID, input.AssignmentEpoch)
		if updateErr != nil {
			return nil, nil, nil, fmt.Errorf("validate existing provision assignment: %w", updateErr)
		}
		if err := requireSingleFencedRow(result); err != nil {
			return nil, nil, nil, application.ErrWorkflowInvalidState
		}
	}
	op, err := scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET status = 'SUCCEEDED', target_id = $6, response_snapshot = $5::jsonb,
    error_code = NULL, error_detail = NULL, next_attempt_at = NULL,
    completed_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND migration_state = 'CURRENT' AND operation_type = 'PROVISION' AND target_type = 'SEAT'
  AND target_external_id = $7 AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, opInput.Key.ClientID, opInput.Key.OperationID, opInput.FencingToken,
		opInput.LeaseOwner, opInput.ResultSnapshot, seatID, opInput.Claim.SeatExternalID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, application.ErrWorkflowStaleFence
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("commit provision operation: %w", err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_token_hash, credential_fingerprint, claim_intent_hash, envelope_algorithm, envelope_key_ref,
envelope_ciphertext, envelope_nonce, envelope_aad_hash, wrapped_dek_kms, expires_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, 'READY', $5, $6, $7, $8, $9, $10, $11, $12, $13,
        CURRENT_TIMESTAMP + make_interval(secs => $14), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		op.AggregateID, seatID, ownerMemberID, opInput.Claim.ClaimOperationID,
		opInput.Claim.TokenHash[:], opInput.Claim.CredentialFingerprint[:], intentHash[:],
		opInput.Claim.Envelope.Algorithm, opInput.Claim.Envelope.KeyRef, opInput.Claim.Envelope.Ciphertext,
		opInput.Claim.Envelope.Nonce, opInput.Claim.Envelope.AADHash[:], opInput.Claim.Envelope.WrappedDEK,
		opInput.Claim.ClaimTTL.Seconds())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("insert provision credential claim: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, nil, nil, err
	}
	claim, err := loadClaimTx(ctx, tx, opInput.Claim.Key, false)
	if err != nil {
		return nil, nil, nil, err
	}
	seat, err := loadPersistedSeatTx(ctx, tx, opInput.Claim.SeatExternalID)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, fmt.Errorf("commit provision aggregate: %w", err)
	}
	return op, claim, seat, nil
}

func (s *Store) LoadPersistedSeat(ctx context.Context, externalID string) (*application.PersistedSeat, error) {
	if strings.TrimSpace(externalID) == "" {
		return nil, application.ErrWorkflowInvalidData
	}
	seat, err := scanPersistedSeat(s.db.QueryRowContext(ctx, persistedSeatQuery, externalID))
	if err != nil {
		return nil, translateNotFound("load persisted seat", err)
	}
	return seat, nil
}

const persistedSeatQuery = `SELECT s.id, s.external_id, p.external_id, owner.external_id,
current_member.external_id, s.assignment_epoch, p.membership_epoch, assignment.starts_at, s.updated_at
FROM seats s
JOIN pools p ON p.id = s.pool_id
JOIN members owner ON owner.id = s.owner_member_id
JOIN seat_assignments assignment ON assignment.seat_id = s.id AND assignment.status = 'ACTIVE'
JOIN members current_member ON current_member.id = assignment.member_id
WHERE s.external_id = $1 AND s.status = 'ACTIVE'
  AND (assignment.starts_at IS NULL OR assignment.starts_at <= CURRENT_TIMESTAMP)
  AND (assignment.ends_at IS NULL OR assignment.ends_at > CURRENT_TIMESTAMP)`

func loadPersistedSeatTx(ctx context.Context, tx *sql.Tx, externalID string) (*application.PersistedSeat, error) {
	seat, err := scanPersistedSeat(tx.QueryRowContext(ctx, persistedSeatQuery, externalID))
	if err != nil {
		return nil, translateNotFound("load persisted seat transaction", err)
	}
	return seat, nil
}

func scanPersistedSeat(row scanner) (*application.PersistedSeat, error) {
	seat := &application.PersistedSeat{}
	var assignedAt sql.NullTime
	if err := row.Scan(&seat.SeatID, &seat.SeatExternalID, &seat.PoolExternalID, &seat.OwnerExternalID,
		&seat.CurrentMemberID, &seat.AssignmentEpoch, &seat.MembershipEpoch, &assignedAt, &seat.UpdatedAt); err != nil {
		return nil, err
	}
	if assignedAt.Valid {
		seat.AssignmentStarted = assignedAt.Time
	}
	return seat, nil
}

func (s *Store) CreateCredentialClaim(ctx context.Context, input application.CreateCredentialClaimInput) (*application.StoredCredentialClaim, bool, error) {
	if err := validateCreateClaim(input); err != nil {
		return nil, false, err
	}
	intentHash, err := credentialClaimIntentHash(input)
	if err != nil {
		return nil, false, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin credential claim transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_token_hash, credential_fingerprint, claim_intent_hash, envelope_algorithm, envelope_key_ref,
envelope_ciphertext, envelope_nonce, envelope_aad_hash, wrapped_dek_kms, expires_at,
created_at, updated_at
)
SELECT io.id, s.id, m.id, $5, 'READY', $6, $7, $8, $9, $10, $11, $12, $13, $14,
       CURRENT_TIMESTAMP + make_interval(secs => $15),
       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM integration_operations io
JOIN seats s ON s.external_id = io.target_external_id AND s.external_id = $3 AND s.status = 'ACTIVE'
JOIN members m ON m.external_id = $4 AND m.status = 'ACTIVE'
JOIN seat_assignments sa ON sa.seat_id = s.id AND sa.member_id = m.id AND sa.status = 'ACTIVE'
  AND (sa.starts_at IS NULL OR sa.starts_at <= CURRENT_TIMESTAMP)
  AND (sa.ends_at IS NULL OR sa.ends_at > CURRENT_TIMESTAMP)
WHERE io.integration_client_id = $1 AND io.operation_id = $2 AND io.migration_state = 'CURRENT'
  AND io.status = 'SUCCEEDED' AND io.target_type = 'SEAT'
  AND io.operation_type IN ('PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')
  AND (io.operation_type <> 'PROVISION' OR s.owner_member_id = m.id)
ON CONFLICT (integration_operation_id) DO NOTHING`, input.Key.ClientID, input.Key.OperationID,
		input.SeatExternalID, input.TargetMemberExternalID, input.ClaimOperationID, input.TokenHash[:],
		input.CredentialFingerprint[:], intentHash[:], input.Envelope.Algorithm, input.Envelope.KeyRef,
		input.Envelope.Ciphertext, input.Envelope.Nonce, input.Envelope.AADHash[:], input.Envelope.WrappedDEK,
		input.ClaimTTL.Seconds())
	if err != nil {
		return nil, false, fmt.Errorf("insert credential claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("read credential claim insert result: %w", err)
	}
	claim, err := scanClaim(tx.QueryRowContext(ctx, `SELECT `+claimColumns+`
FROM credential_claims cc
JOIN integration_operations io ON io.id = cc.integration_operation_id
JOIN seats s ON s.id = cc.seat_id
JOIN members m ON m.id = cc.target_member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2
FOR UPDATE OF cc`, input.Key.ClientID, input.Key.OperationID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var valid bool
			lookupErr := tx.QueryRowContext(ctx, `SELECT status = 'SUCCEEDED' AND operation_type IN (
'PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2`,
				input.Key.ClientID, input.Key.OperationID).Scan(&valid)
			if errors.Is(lookupErr, sql.ErrNoRows) {
				return nil, false, application.ErrWorkflowNotFound
			}
			if lookupErr != nil {
				return nil, false, fmt.Errorf("inspect credential claim operation: %w", lookupErr)
			}
			_ = valid
			return nil, false, application.ErrWorkflowInvalidState
		}
		return nil, false, translateNotFound("load created credential claim", err)
	}
	if !sameClaimIntent(claim, input) {
		return nil, false, application.ErrWorkflowHashDrift
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit credential claim creation: %w", err)
	}
	return claim, rows == 1, nil
}

func (s *Store) LoadCredentialClaim(ctx context.Context, key application.ClaimKey) (*application.StoredCredentialClaim, error) {
	if !validKey(key.ClientID, key.OperationID) {
		return nil, application.ErrWorkflowInvalidData
	}
	claim, err := scanClaim(s.db.QueryRowContext(ctx, `SELECT `+claimColumns+`
FROM credential_claims cc
JOIN integration_operations io ON io.id = cc.integration_operation_id
JOIN seats s ON s.id = cc.seat_id
JOIN members m ON m.id = cc.target_member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2`, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load credential claim", err)
	}
	return claim, nil
}

func (s *Store) AcquireCredentialClaimLease(ctx context.Context, input application.AcquireCredentialClaimLeaseInput) (*application.CredentialClaimLease, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin credential lease transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims cc
SET lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
    fencing_token = cc.fencing_token + 1, version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io
WHERE io.id = cc.integration_operation_id AND io.integration_client_id = $1 AND io.operation_id = $2
  AND cc.status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED')
  AND (cc.lease_expires_at IS NULL OR cc.lease_expires_at <= CURRENT_TIMESTAMP)`,
		input.Key.ClientID, input.Key.OperationID, input.LeaseOwner, input.LeaseDuration.Seconds())
	if err != nil {
		return nil, fmt.Errorf("acquire credential claim lease: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read credential lease result: %w", err)
	}
	if rows != 1 {
		return nil, application.ErrWorkflowLeaseHeld
	}
	claim, err := loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit credential lease: %w", err)
	}
	return &application.CredentialClaimLease{Claim: claim, FencingToken: claim.FencingToken}, nil
}

// AcquireNextCredentialClaimLease 只发现需过期清理或 ack 恢复的 claim；未到期 READY 仍由领取请求驱动。
func (s *Store) AcquireNextCredentialClaimLease(ctx context.Context, input application.AcquireNextCredentialClaimLeaseInput) (*application.CredentialClaimLease, error) {
	if strings.TrimSpace(input.LeaseOwner) == "" || input.LeaseDuration <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin next credential claim lease transaction: %w", err)
	}
	defer tx.Rollback()
	var integrationOperationID string
	err = tx.QueryRowContext(ctx, `WITH candidate AS (
    SELECT id FROM credential_claims
    WHERE status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED')
      AND (
          expires_at <= CURRENT_TIMESTAMP OR
          status = 'ACK_RECONCILE_REQUIRED' OR
          (status = 'ACK_PENDING' AND ack_response_snapshot IS NULL)
      )
      AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
    ORDER BY (expires_at <= CURRENT_TIMESTAMP) DESC, expires_at, created_at
    FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE credential_claims cc
SET lease_owner = $1, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $2),
    fencing_token = cc.fencing_token + 1, version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM candidate WHERE cc.id = candidate.id
RETURNING cc.integration_operation_id`, input.LeaseOwner, input.LeaseDuration.Seconds()).Scan(&integrationOperationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, application.ErrWorkflowNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("acquire next credential claim lease: %w", err)
	}
	claim, err := loadClaimByOperationIDTx(ctx, tx, integrationOperationID, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit next credential claim lease: %w", err)
	}
	return &application.CredentialClaimLease{Claim: claim, FencingToken: claim.FencingToken}, nil
}

// BeginCredentialAck 在调用 Sub2API 前持久化 ACK_PENDING，且保留租约；进程崩溃后由恢复 worker 接管。
func (s *Store) BeginCredentialAck(ctx context.Context, input application.BeginCredentialAckInput) (*application.StoredCredentialClaim, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" || input.FencingToken <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin credential ack marker transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims cc
SET status = 'ACK_PENDING', error_code = NULL, version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io
WHERE io.id = cc.integration_operation_id
  AND io.integration_client_id = $1 AND io.operation_id = $2
  AND io.migration_state = 'CURRENT' AND io.operation_type = 'PROVISION'
  AND cc.fencing_token = $3 AND cc.lease_owner = $4
  AND cc.lease_expires_at > CURRENT_TIMESTAMP
  AND cc.status IN ('READY', 'ACK_RECONCILE_REQUIRED')`,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner)
	if err != nil {
		return nil, fmt.Errorf("persist credential ack marker: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, err
	}
	claim, err := loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit credential ack marker: %w", err)
	}
	return claim, nil
}

func (s *Store) CommitCredentialAck(ctx context.Context, input application.CommitCredentialAckInput) (*application.StoredCredentialClaim, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" || input.FencingToken <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	evidenceSnapshot, fingerprint, err := validateAndMarshalAckEvidence(input.Key, input.Evidence)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin credential ack transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims cc
SET status = 'ACK_PENDING', ack_response_snapshot = COALESCE(cc.ack_response_snapshot, $9::jsonb), error_code = NULL,
    lease_owner = NULL, lease_expires_at = NULL, version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io, seats s, members m
WHERE io.id = cc.integration_operation_id AND io.integration_client_id = $1 AND io.operation_id = $2
  AND cc.fencing_token = $3 AND cc.lease_owner = $4 AND cc.lease_expires_at > CURRENT_TIMESTAMP
  AND io.migration_state = 'CURRENT' AND io.operation_type = 'PROVISION'
  AND s.id = cc.seat_id AND s.external_id = $5 AND io.target_external_id = $5
  AND cc.claim_operation_id = $6
  AND m.id = cc.target_member_id AND m.external_id = $7
  AND cc.credential_fingerprint = $8
  AND cc.status IN ('ACK_PENDING', 'ACK_RECONCILE_REQUIRED')
  AND (cc.ack_response_snapshot IS NULL OR cc.ack_response_snapshot = $9::jsonb)`,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner,
		input.Evidence.ExternalSeatID, input.Evidence.ClaimOperationID, input.Evidence.ClaimedBy,
		fingerprint, evidenceSnapshot)
	if err != nil {
		return nil, fmt.Errorf("commit credential acknowledgement: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, err
	}
	claim, err := loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit credential acknowledgement transaction: %w", err)
	}
	return claim, nil
}

// CommitCredentialAckFailure 持久化 ack 的失败分类：结果不明保留秘密供对账，明确拒绝则终态清密。
func (s *Store) CommitCredentialAckFailure(ctx context.Context, input application.CommitCredentialAckFailureInput) (*application.StoredCredentialClaim, error) {
	errorCode := strings.TrimSpace(input.ErrorCode)
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || errorCode == "" || len(errorCode) > 128 ||
		(input.Status != application.CredentialClaimReconcileRequired && input.Status != application.CredentialClaimRejected) {
		return nil, application.ErrWorkflowInvalidData
	}
	rejected := input.Status == application.CredentialClaimRejected
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin credential ack failure transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims cc
SET status = $5, error_code = $6,
    claim_token_hash = CASE WHEN $7 THEN NULL ELSE claim_token_hash END,
    envelope_algorithm = CASE WHEN $7 THEN NULL ELSE envelope_algorithm END,
    envelope_key_ref = CASE WHEN $7 THEN NULL ELSE envelope_key_ref END,
    envelope_ciphertext = CASE WHEN $7 THEN NULL ELSE envelope_ciphertext END,
    envelope_nonce = CASE WHEN $7 THEN NULL ELSE envelope_nonce END,
    envelope_aad_hash = CASE WHEN $7 THEN NULL ELSE envelope_aad_hash END,
    wrapped_dek_kms = CASE WHEN $7 THEN NULL ELSE wrapped_dek_kms END,
    terminal_at = CASE WHEN $7 THEN CURRENT_TIMESTAMP ELSE NULL END,
    lease_owner = NULL, lease_expires_at = NULL,
    version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io
WHERE io.id = cc.integration_operation_id
  AND io.integration_client_id = $1 AND io.operation_id = $2
  AND io.migration_state = 'CURRENT' AND io.operation_type = 'PROVISION'
  AND cc.fencing_token = $3 AND cc.lease_owner = $4
  AND cc.lease_expires_at > CURRENT_TIMESTAMP
  AND cc.ack_response_snapshot IS NULL
  AND cc.status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED')`,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner,
		input.Status, errorCode, rejected)
	if err != nil {
		return nil, fmt.Errorf("commit credential ack failure: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, err
	}
	claim, err := loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit credential ack failure transaction: %w", err)
	}
	return claim, nil
}

func (s *Store) ClaimCredential(ctx context.Context, input application.ClaimCredentialInput) (*application.StoredCredentialClaim, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" ||
		input.FencingToken <= 0 || strings.TrimSpace(input.TargetMemberExternalID) == "" {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim credential transaction: %w", err)
	}
	defer tx.Rollback()
	claim, err := loadClaimTx(ctx, tx, input.Key, true)
	if err != nil {
		return nil, err
	}
	if claim.FencingToken != input.FencingToken || claim.LeaseOwner != input.LeaseOwner ||
		!claimAllowsDelivery(claim) ||
		claim.TargetMemberExternalID != input.TargetMemberExternalID || len(claim.TokenHash) != len(input.TokenHash) ||
		subtle.ConstantTimeCompare(claim.TokenHash, input.TokenHash[:]) != 1 {
		return nil, application.ErrWorkflowStaleFence
	}
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims
SET status = 'CLAIMED', claim_token_hash = NULL, envelope_algorithm = NULL,
    envelope_key_ref = NULL, envelope_ciphertext = NULL, envelope_nonce = NULL,
    envelope_aad_hash = NULL, wrapped_dek_kms = NULL,
    claimed_at = CURRENT_TIMESTAMP, terminal_at = CURRENT_TIMESTAMP,
    lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND fencing_token = $2 AND lease_owner = $3
  AND lease_expires_at > CURRENT_TIMESTAMP AND status IN ('READY', 'ACK_PENDING')
  AND target_member_id = $4 AND expires_at > CURRENT_TIMESTAMP`, claim.IntegrationOperationID,
		input.FencingToken, input.LeaseOwner, claim.TargetMemberID)
	if err != nil {
		return nil, fmt.Errorf("claim credential: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, err
	}
	claim, err = loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim credential: %w", err)
	}
	return claim, nil
}

func (s *Store) ExpireCredentialClaim(ctx context.Context, input application.ExpireCredentialClaimInput) (*application.StoredCredentialClaim, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.LeaseOwner) == "" || input.FencingToken <= 0 {
		return nil, application.ErrWorkflowInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin expire credential transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE credential_claims cc
SET status = 'EXPIRED', claim_token_hash = NULL, envelope_algorithm = NULL,
    envelope_key_ref = NULL, envelope_ciphertext = NULL, envelope_nonce = NULL,
    envelope_aad_hash = NULL, wrapped_dek_kms = NULL, terminal_at = CURRENT_TIMESTAMP,
    lease_owner = NULL, lease_expires_at = NULL, version = cc.version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations io
WHERE io.id = cc.integration_operation_id AND io.integration_client_id = $1 AND io.operation_id = $2
  AND cc.fencing_token = $3 AND cc.lease_owner = $4 AND cc.lease_expires_at > CURRENT_TIMESTAMP
  AND cc.status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED')
  AND cc.expires_at <= CURRENT_TIMESTAMP`, input.Key.ClientID, input.Key.OperationID,
		input.FencingToken, input.LeaseOwner)
	if err != nil {
		return nil, fmt.Errorf("expire credential claim: %w", err)
	}
	if err := requireSingleFencedRow(result); err != nil {
		return nil, err
	}
	claim, err := loadClaimTx(ctx, tx, input.Key, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit expire credential claim: %w", err)
	}
	return claim, nil
}

type scanner interface {
	Scan(...any) error
}

func scanOperation(row scanner) (*application.StoredOperation, error) {
	op := &application.StoredOperation{}
	var requestHash []byte
	var targetExternalID, leaseOwner, errorCode, errorDetail sql.NullString
	var leaseExpiresAt, nextAttemptAt, completedAt sql.NullTime
	if err := row.Scan(&op.AggregateID, &op.Key.ClientID, &op.Key.OperationID, &op.Kind, &op.TargetType,
		&targetExternalID, &op.MigrationState, &requestHash, &op.RequestSnapshot, &op.Status, &op.AttemptCount, &op.ResultSnapshot,
		&errorCode, &errorDetail, &op.FencingToken, &leaseOwner, &leaseExpiresAt,
		&nextAttemptAt, &op.CreatedAt, &op.UpdatedAt, &completedAt); err != nil {
		return nil, err
	}
	if len(requestHash) != len(op.RequestHash) {
		return nil, fmt.Errorf("scan operation request hash: %w", application.ErrWorkflowInvalidData)
	}
	copy(op.RequestHash[:], requestHash)
	op.ErrorCode, op.ErrorDetail = errorCode.String, errorDetail.String
	op.TargetExternalID = targetExternalID.String
	op.LeaseOwner = leaseOwner.String
	if leaseExpiresAt.Valid {
		op.LeaseExpiresAt = &leaseExpiresAt.Time
	}
	if completedAt.Valid {
		op.CompletedAt = &completedAt.Time
	}
	if nextAttemptAt.Valid {
		op.NextAttemptAt = &nextAttemptAt.Time
	}
	return op, nil
}

func scanClaim(row scanner) (*application.StoredCredentialClaim, error) {
	claim := &application.StoredCredentialClaim{}
	var aadHash []byte
	var algorithm, keyRef, leaseOwner, errorCode sql.NullString
	var leaseExpiresAt, claimedAt, terminalAt sql.NullTime
	if err := row.Scan(&claim.ID, &claim.IntegrationOperationID, &claim.Key.ClientID, &claim.Key.OperationID,
		&claim.OperationKind, &claim.SeatID, &claim.SeatExternalID, &claim.TargetMemberID,
		&claim.TargetMemberExternalID, &claim.ClaimOperationID, &claim.TokenHash,
		&claim.CredentialFingerprint, &claim.IntentHash, &algorithm, &keyRef, &claim.Envelope.Ciphertext,
		&claim.Envelope.Nonce, &aadHash, &claim.Envelope.WrappedDEK, &claim.Status,
		&claim.AckResultSnapshot, &errorCode, &claim.FencingToken, &leaseOwner, &leaseExpiresAt,
		&claim.ExpiresAt, &claim.Expired, &claimedAt, &terminalAt, &claim.CreatedAt, &claim.UpdatedAt); err != nil {
		return nil, err
	}
	claim.Envelope.Algorithm, claim.Envelope.KeyRef = algorithm.String, keyRef.String
	claim.ErrorCode, claim.LeaseOwner = errorCode.String, leaseOwner.String
	if len(aadHash) != 0 && len(aadHash) != len(claim.Envelope.AADHash) {
		return nil, fmt.Errorf("scan credential envelope AAD hash: %w", application.ErrWorkflowInvalidData)
	}
	copy(claim.Envelope.AADHash[:], aadHash)
	if leaseExpiresAt.Valid {
		claim.LeaseExpiresAt = &leaseExpiresAt.Time
	}
	if claimedAt.Valid {
		claim.ClaimedAt = &claimedAt.Time
	}
	if terminalAt.Valid {
		claim.TerminalAt = &terminalAt.Time
	}
	return claim, nil
}

func loadClaimTx(ctx context.Context, tx *sql.Tx, key application.ClaimKey, forUpdate bool) (*application.StoredCredentialClaim, error) {
	query := `SELECT ` + claimColumns + `
FROM credential_claims cc
JOIN integration_operations io ON io.id = cc.integration_operation_id
JOIN seats s ON s.id = cc.seat_id
JOIN members m ON m.id = cc.target_member_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2`
	if forUpdate {
		query += ` FOR UPDATE OF cc`
	}
	claim, err := scanClaim(tx.QueryRowContext(ctx, query, key.ClientID, key.OperationID))
	if err != nil {
		return nil, translateNotFound("load credential claim transaction", err)
	}
	return claim, nil
}

func loadClaimByOperationIDTx(ctx context.Context, tx *sql.Tx, integrationOperationID string, forUpdate bool) (*application.StoredCredentialClaim, error) {
	query := `SELECT ` + claimColumns + `
FROM credential_claims cc
JOIN integration_operations io ON io.id = cc.integration_operation_id
JOIN seats s ON s.id = cc.seat_id
JOIN members m ON m.id = cc.target_member_id
WHERE cc.integration_operation_id = $1`
	if forUpdate {
		query += ` FOR UPDATE OF cc`
	}
	claim, err := scanClaim(tx.QueryRowContext(ctx, query, integrationOperationID))
	if err != nil {
		return nil, translateNotFound("load credential claim by operation id", err)
	}
	return claim, nil
}

func validateBeginOperation(input application.BeginOperationInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(string(input.Kind)) == "" ||
		strings.TrimSpace(input.TargetType) == "" || strings.TrimSpace(input.TargetExternalID) == "" ||
		len(input.RequestSnapshot) == 0 || !validJSONObject(input.RequestSnapshot) {
		return application.ErrWorkflowInvalidData
	}
	canonical, err := canonicalJSONObject(input.RequestSnapshot)
	if err != nil || string(canonical) == "{}" {
		return application.ErrWorkflowInvalidData
	}
	return nil
}

func validateCreateClaim(input application.CreateCredentialClaimInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || strings.TrimSpace(input.SeatExternalID) == "" ||
		strings.TrimSpace(input.TargetMemberExternalID) == "" || strings.TrimSpace(input.ClaimOperationID) == "" ||
		strings.TrimSpace(input.Envelope.Algorithm) == "" || strings.TrimSpace(input.Envelope.KeyRef) == "" ||
		len(input.Envelope.Ciphertext) == 0 || len(input.Envelope.Nonce) == 0 || len(input.Envelope.WrappedDEK) == 0 ||
		input.ClaimTTL <= 0 || input.ClaimTTL > 24*time.Hour {
		return application.ErrWorkflowInvalidData
	}
	return nil
}

func validKey(clientID, operationID string) bool {
	clientID, operationID = strings.TrimSpace(clientID), strings.TrimSpace(operationID)
	return clientID != "" && operationID != "" && len(clientID) <= 128 && len(operationID) <= 128
}

func validJSONOrEmpty(value []byte) bool {
	return len(value) == 0 || validJSONObject(value)
}

func validJSONObject(value []byte) bool {
	_, err := canonicalJSONObject(value)
	return err == nil
}

func canonicalJSONObject(value []byte) ([]byte, error) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, application.ErrWorkflowInvalidData
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, application.ErrWorkflowInvalidData
	}
	return json.Marshal(object)
}

func validateAndMarshalAckEvidence(key application.ClaimKey, evidence application.ProvisionCredentialAckResult) ([]byte, []byte, error) {
	if !evidence.CredentialClaimed || evidence.ClaimedAt.IsZero() ||
		evidence.ProvisionOperationID != key.OperationID || strings.TrimSpace(evidence.ExternalSeatID) == "" ||
		strings.TrimSpace(evidence.ClaimOperationID) == "" || strings.TrimSpace(evidence.ClaimedBy) == "" ||
		evidence.CredentialFingerprint != strings.ToLower(evidence.CredentialFingerprint) {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	fingerprint, err := hex.DecodeString(evidence.CredentialFingerprint)
	if err != nil || len(fingerprint) != 32 {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	evidence.ClaimedAt = evidence.ClaimedAt.UTC()
	snapshot, err := json.Marshal(evidence)
	if err != nil {
		return nil, nil, application.ErrWorkflowInvalidData
	}
	return snapshot, fingerprint, nil
}

func validCommitStatus(status application.OperationStatus) bool {
	switch status {
	case application.OperationSucceeded, application.OperationRetryable,
		application.OperationReconcileRequired, application.OperationFailed:
		return true
	default:
		return false
	}
}

func isOperationTerminal(status application.OperationStatus) bool {
	return status == application.OperationSucceeded || status == application.OperationFailed
}

func validAckStatus(status application.CredentialClaimStatus) bool {
	switch status {
	case application.CredentialClaimAckPending, application.CredentialClaimReconcileRequired,
		application.CredentialClaimRejected:
		return true
	default:
		return false
	}
}

func claimAllowsDelivery(claim *application.StoredCredentialClaim) bool {
	switch claim.OperationKind {
	case application.OperationProvision:
		return claim.Status == application.CredentialClaimAckPending && len(claim.AckResultSnapshot) != 0
	case application.OperationAssignTemp, application.OperationRestore, application.OperationReplace:
		return claim.Status == application.CredentialClaimReady || claim.Status == application.CredentialClaimAckPending
	default:
		return false
	}
}

func sameClaimIntent(claim *application.StoredCredentialClaim, input application.CreateCredentialClaimInput) bool {
	intentHash, err := credentialClaimIntentHash(input)
	return err == nil && bytes.Equal(claim.IntentHash, intentHash[:])
}

func credentialClaimIntentHash(input application.CreateCredentialClaimInput) ([32]byte, error) {
	payload := struct {
		Version                int                            `json:"version"`
		ClientID               string                         `json:"client_id"`
		OperationID            string                         `json:"operation_id"`
		SeatExternalID         string                         `json:"seat_external_id"`
		TargetMemberExternalID string                         `json:"target_member_external_id"`
		ClaimOperationID       string                         `json:"claim_operation_id"`
		TokenHash              [32]byte                       `json:"token_hash"`
		CredentialFingerprint  [32]byte                       `json:"credential_fingerprint"`
		Envelope               application.CredentialEnvelope `json:"envelope"`
		ClaimTTLNanoseconds    int64                          `json:"claim_ttl_nanoseconds"`
	}{
		Version: 1, ClientID: input.Key.ClientID, OperationID: input.Key.OperationID,
		SeatExternalID: input.SeatExternalID, TargetMemberExternalID: input.TargetMemberExternalID,
		ClaimOperationID: input.ClaimOperationID, TokenHash: input.TokenHash,
		CredentialFingerprint: input.CredentialFingerprint, Envelope: input.Envelope,
		ClaimTTLNanoseconds: input.ClaimTTL.Nanoseconds(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func requireSingleFencedRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read fenced update result: %w", err)
	}
	if rows != 1 {
		return application.ErrWorkflowStaleFence
	}
	return nil
}

func translateNotFound(action string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return application.ErrWorkflowNotFound
	}
	return fmt.Errorf("%s: %w", action, err)
}

type sqlStateError interface{ SQLState() string }

func translateOperationWriteError(action string, err error) error {
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" &&
		strings.Contains(err.Error(), "uq_integration_operations_current_provision_seat_target") {
		return application.ErrWorkflowTargetConflict
	}
	return translateNotFound(action, err)
}
