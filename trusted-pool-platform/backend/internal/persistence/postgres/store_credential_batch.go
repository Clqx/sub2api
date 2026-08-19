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
	"trusted-pool-platform/backend/internal/credentials"
)

const batchColumns = `b.id, b.external_id, b.pool_id, p.external_id, b.resource_account_ref,
b.batch_type, b.batch_version, b.membership_epoch, b.status, b.migration_state, b.aad_version,
b.encryption_algorithm, b.aad_hash, b.content_hash, b.kms_wrap_algorithm, b.kms_key_ref,
b.kms_wrapper_domain, b.recovery_wrap_algorithm, b.recovery_key_ref, b.recovery_wrapper_domain,
b.recovery_binding_hash, b.version, b.sealed_at, b.activated_at, b.retired_at, b.created_at, b.updated_at`

const (
	batchOperationSeal     = "SEAL_CREDENTIAL_BATCH"
	batchOperationActivate = "ACTIVATE_CREDENTIAL_BATCH"
	batchOperationRetire   = "RETIRE_CREDENTIAL_BATCH"
	batchTargetType        = "CREDENTIAL_BATCH"
)

var _ credentials.BatchStore = (*Store)(nil)

func (s *Store) BeginSealCredentialBatch(ctx context.Context, input credentials.BeginSealCredentialBatchInput) (*credentials.SealCredentialBatchTarget, bool, error) {
	canonical, err := validateSealBatchInput(input)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin credential batch seal transaction: %w", err)
	}
	defer tx.Rollback()

	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_external_id, migration_state,
request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, 'CURRENT', $6, $7::jsonb, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, batchOperationSeal,
		batchTargetType, input.BatchExternalID, input.RequestHash[:], canonical))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateBatchError("begin credential batch seal", scanErr)
	}
	if err := validateBatchOperationIntent(op, batchOperationSeal, input.BatchExternalID, input.RequestHash, canonical); err != nil {
		return nil, false, err
	}
	if op.Status == application.OperationSucceeded {
		batch, loadErr := loadBatchTx(ctx, tx, input.BatchExternalID, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if batch.MigrationState != credentials.BatchMigrationCurrent {
			return nil, false, credentials.ErrBatchLegacy
		}
		if loadErr = restoreHistoricalBatchResult(op, batch, credentials.BatchSealed, 2); loadErr != nil {
			return nil, false, loadErr
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit credential batch seal replay: %w", err)
		}
		return &credentials.SealCredentialBatchTarget{Operation: batchOperation(op), Batch: batch}, false, nil
	}
	if op.Status == application.OperationFailed {
		return nil, false, credentials.ErrBatchInvalidState
	}

	// 全局顺序固定为 operation -> Pool -> Batch；加密/KMS 调用必须发生在事务外。
	var poolID string
	if err := tx.QueryRowContext(ctx, `SELECT p.id
FROM pools p
JOIN membership_epochs me ON me.pool_id = p.id AND me.epoch = $2 AND me.status = 'ACTIVE'
WHERE p.external_id = $1 AND p.status = 'ACTIVE' AND p.membership_epoch = $2
  AND $2 >= p.credential_epoch_floor
FOR UPDATE OF p`, input.PoolExternalID, input.MembershipEpoch).Scan(&poolID); err != nil {
		return nil, false, translateBatchState("lock credential batch pool", err)
	}

	batch, loadErr := loadBatchTx(ctx, tx, input.BatchExternalID, true)
	if errors.Is(loadErr, credentials.ErrBatchNotFound) {
		_, loadErr = tx.ExecContext(ctx, `INSERT INTO credential_batches (
external_id, pool_id, membership_epoch, resource_account_ref, batch_type, batch_version,
status, content_hash, migration_state, seal_integration_operation_id, aad_version, version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, 'PREPARED', $7, 'CURRENT', $8, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			input.BatchExternalID, poolID, input.MembershipEpoch, input.AccountRef,
			string(input.Type), input.BatchVersion, input.ContentFingerprint[:], op.AggregateID)
		if loadErr == nil {
			batch, loadErr = loadBatchTx(ctx, tx, input.BatchExternalID, true)
		}
	} else if loadErr == nil {
		if batch.MigrationState != credentials.BatchMigrationCurrent {
			return nil, false, credentials.ErrBatchLegacy
		}
		if batch.PoolExternalID != input.PoolExternalID || batch.AccountRef != input.AccountRef ||
			batch.Type != input.Type || batch.BatchVersion != input.BatchVersion ||
			batch.MembershipEpoch != input.MembershipEpoch || batch.ContentFingerprint != input.ContentFingerprint ||
			batch.State != credentials.BatchState("PREPARED") {
			return nil, false, credentials.ErrBatchHashDrift
		}
	}
	if loadErr != nil {
		return nil, false, translateBatchError("persist credential batch seal intent", loadErr)
	}

	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations
SET target_id = $3, lease_owner = $4,
    lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $5),
    fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, batch.ID,
		input.LeaseOwner, input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, credentials.ErrBatchLeaseHeld
	}
	if err != nil {
		return nil, false, translateBatchError("acquire credential batch seal lease", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, translateBatchError("commit credential batch seal intent", err)
	}
	return &credentials.SealCredentialBatchTarget{Operation: batchOperation(op), Batch: batch}, created, nil
}

func (s *Store) CommitSealCredentialBatch(ctx context.Context, input credentials.CommitSealCredentialBatchInput) (*credentials.StoredCredentialBatch, error) {
	if err := validateSealEnvelopeInput(input); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin credential batch seal commit: %w", err)
	}
	defer tx.Rollback()

	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations
WHERE integration_client_id = $1 AND operation_id = $2 AND operation_type = $3
  AND migration_state = 'CURRENT' AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND fencing_token = $4 AND lease_owner = $5 AND lease_expires_at > CURRENT_TIMESTAMP
FOR UPDATE`, input.Key.ClientID, input.Key.OperationID, batchOperationSeal, input.FencingToken, input.LeaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, credentials.ErrBatchStaleFence
	}
	if err != nil {
		return nil, translateBatchError("lock credential batch seal operation", err)
	}

	var poolID string
	if err := tx.QueryRowContext(ctx, `SELECT b.pool_id FROM credential_batches b
WHERE b.seal_integration_operation_id = $1`, op.AggregateID).Scan(&poolID); err != nil {
		return nil, translateBatchError("resolve credential batch pool", err)
	}
	var ignored int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pools WHERE id = $1 FOR UPDATE`, poolID).Scan(&ignored); err != nil {
		return nil, translateBatchState("lock credential batch pool", err)
	}
	batch, err := loadBatchBySealOperationTx(ctx, tx, op.AggregateID, true)
	if err != nil {
		return nil, err
	}
	if batch.MigrationState != credentials.BatchMigrationCurrent || batch.State != credentials.BatchState("PREPARED") ||
		batch.ContentFingerprint != input.Envelope.ContentFingerprint {
		return nil, credentials.ErrBatchInvalidState
	}
	if err := validateEnvelopeBinding(input.Key.OperationID, batch, input.Envelope); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT 1
FROM pools p JOIN membership_epochs me ON me.pool_id = p.id AND me.epoch = $2 AND me.status = 'ACTIVE'
WHERE p.id = $1 AND p.status = 'ACTIVE' AND p.membership_epoch = $2
  AND $2 >= p.credential_epoch_floor`, poolID, batch.MembershipEpoch).Scan(&ignored); err != nil {
		return nil, translateBatchState("recheck credential batch epoch", err)
	}

	result, err := tx.ExecContext(ctx, `UPDATE credential_batches SET
status = 'SEALED', encryption_algorithm = $2, ciphertext = $3, nonce = $4, aad_hash = $5,
encrypted_dek_kms = $6, encrypted_dek_recovery = $7,
kms_wrap_algorithm = $8, kms_key_ref = $9, kms_wrapper_domain = $10,
recovery_wrap_algorithm = $11, recovery_key_ref = $12, recovery_wrapper_domain = $13,
recovery_binding_hash = $14, sealed_at = CURRENT_TIMESTAMP, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND migration_state = 'CURRENT' AND status = 'PREPARED' AND version = 1`,
		batch.ID, input.Envelope.EncryptionAlgorithm, input.Envelope.Ciphertext, input.Envelope.Nonce,
		input.Envelope.AADHash[:], input.Envelope.WrappedDEKKMS, input.Envelope.WrappedDEKRecovery,
		input.Envelope.KMSWrapAlgorithm, input.Envelope.KMSKeyRef, input.Envelope.KMSWrapperDomain,
		input.Envelope.RecoveryWrapAlgorithm, input.Envelope.RecoveryKeyRef, input.Envelope.RecoveryWrapperDomain,
		input.Envelope.RecoveryBindingHash[:])
	if err != nil {
		return nil, translateBatchError("seal credential batch", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		return nil, credentials.ErrBatchInvalidState
	}
	batch, err = loadBatchBySealOperationTx(ctx, tx, op.AggregateID, false)
	if err != nil {
		return nil, err
	}
	response, err := batchResponseSnapshot(input.Key.OperationID, batch, credentials.BatchSealed, 2, batch.SealedAt, nil, nil)
	if err != nil {
		return nil, credentials.ErrBatchInvalidData
	}
	result, err = tx.ExecContext(ctx, `UPDATE integration_operations
SET status = 'SUCCEEDED', response_snapshot = $6::jsonb, error_code = NULL, error_detail = NULL,
    next_attempt_at = NULL, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL,
    lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND operation_type = $5`, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, batchOperationSeal, response)
	if err != nil {
		return nil, translateBatchError("complete credential batch seal", err)
	}
	if err := requireSingleBatchFencedRow(result); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, translateBatchError("commit sealed credential batch", err)
	}
	return batch, nil
}

func (s *Store) GetCredentialBatch(ctx context.Context, externalID string) (*credentials.StoredCredentialBatch, error) {
	if !validBatchReference(externalID, 128) {
		return nil, credentials.ErrBatchInvalidData
	}
	batch, err := scanBatch(s.db.QueryRowContext(ctx, `SELECT `+batchColumns+`
FROM credential_batches b JOIN pools p ON p.id = b.pool_id WHERE b.external_id = $1`, externalID))
	if err != nil {
		return nil, translateBatchError("get credential batch metadata", err)
	}
	if batch.MigrationState != credentials.BatchMigrationCurrent {
		return nil, credentials.ErrBatchLegacy
	}
	return batch, nil
}

func (s *Store) ActivateCredentialBatch(ctx context.Context, input credentials.CredentialBatchTransitionInput) (*credentials.StoredCredentialBatch, bool, error) {
	return s.transitionCredentialBatch(ctx, input, batchOperationActivate, "ACTIVATE", credentials.BatchSealed, credentials.BatchActive)
}

func (s *Store) RetireCredentialBatch(ctx context.Context, input credentials.CredentialBatchTransitionInput) (*credentials.StoredCredentialBatch, bool, error) {
	return s.transitionCredentialBatch(ctx, input, batchOperationRetire, "RETIRE", credentials.BatchActive, credentials.BatchRetired)
}

func (s *Store) transitionCredentialBatch(ctx context.Context, input credentials.CredentialBatchTransitionInput,
	operationType, action string, fromState, toState credentials.BatchState) (*credentials.StoredCredentialBatch, bool, error) {
	canonical, err := validateTransitionInput(input, action)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin credential batch transition: %w", err)
	}
	defer tx.Rollback()

	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_external_id, migration_state,
request_hash, request_snapshot, status, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, 'CURRENT', $6, $7::jsonb, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (integration_client_id, operation_id) DO NOTHING RETURNING `+operationColumns,
		input.Key.ClientID, input.Key.OperationID, operationType, batchTargetType,
		input.BatchExternalID, input.RequestHash[:], canonical))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			input.Key.ClientID, input.Key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateBatchError("begin credential batch transition", scanErr)
	}
	if err := validateBatchOperationIntent(op, operationType, input.BatchExternalID, input.RequestHash, canonical); err != nil {
		return nil, false, err
	}
	if op.Status == application.OperationSucceeded {
		batch, loadErr := loadBatchTx(ctx, tx, input.BatchExternalID, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if batch.MigrationState != credentials.BatchMigrationCurrent {
			return nil, false, credentials.ErrBatchLegacy
		}
		if loadErr = restoreHistoricalBatchResult(op, batch, toState, input.ExpectedVersion+1); loadErr != nil {
			return nil, false, loadErr
		}
		if err := tx.Commit(); err != nil {
			return nil, false, translateBatchError("commit credential batch transition replay", err)
		}
		return batch, false, nil
	}
	if !created {
		return nil, false, credentials.ErrBatchInvalidState
	}

	var poolID string
	if err := tx.QueryRowContext(ctx, `SELECT pool_id FROM credential_batches WHERE external_id = $1`, input.BatchExternalID).Scan(&poolID); err != nil {
		return nil, false, translateBatchError("resolve credential batch pool", err)
	}
	var ignored int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pools WHERE id = $1 FOR UPDATE`, poolID).Scan(&ignored); err != nil {
		return nil, false, translateBatchState("lock credential batch transition pool", err)
	}
	batch, err := loadBatchTx(ctx, tx, input.BatchExternalID, true)
	if err != nil {
		return nil, false, err
	}
	if batch.MigrationState != credentials.BatchMigrationCurrent {
		return nil, false, credentials.ErrBatchLegacy
	}
	if batch.State != fromState || batch.Version != input.ExpectedVersion {
		return nil, false, credentials.ErrBatchInvalidState
	}
	if action == "ACTIVATE" {
		if err := tx.QueryRowContext(ctx, `SELECT 1
FROM pools p JOIN membership_epochs me ON me.pool_id = p.id AND me.epoch = $2 AND me.status = 'ACTIVE'
WHERE p.id = $1 AND p.status = 'ACTIVE' AND p.membership_epoch = $2
  AND $2 >= p.credential_epoch_floor`, poolID, batch.MembershipEpoch).Scan(&ignored); err != nil {
			return nil, false, translateBatchState("recheck credential batch activation epoch", err)
		}
	}

	timestampColumn := "activated_at"
	if action == "RETIRE" {
		timestampColumn = "retired_at"
	}
	result, err := tx.ExecContext(ctx, `UPDATE credential_batches SET status = $2, `+timestampColumn+` = CURRENT_TIMESTAMP,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND migration_state = 'CURRENT' AND status = $3 AND version = $4`,
		batch.ID, string(toState), string(fromState), input.ExpectedVersion)
	if err != nil {
		return nil, false, translateBatchError("transition credential batch", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		return nil, false, credentials.ErrBatchInvalidState
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO credential_batch_transitions (
integration_operation_id, credential_batch_id, transition_type, from_status, to_status,
expected_batch_version, resulting_batch_version, occurred_at
) VALUES ($1, $2, $3, $4, $5, $6, $6 + 1, CURRENT_TIMESTAMP)`,
		op.AggregateID, batch.ID, action, string(fromState), string(toState), input.ExpectedVersion)
	if err != nil {
		return nil, false, translateBatchError("record credential batch transition", err)
	}
	batch, err = loadBatchTx(ctx, tx, input.BatchExternalID, false)
	if err != nil {
		return nil, false, err
	}
	response, err := batchResponseSnapshot(input.Key.OperationID, batch, toState, input.ExpectedVersion+1,
		batch.SealedAt, batch.ActivatedAt, batch.RetiredAt)
	if err != nil {
		return nil, false, credentials.ErrBatchInvalidData
	}
	result, err = tx.ExecContext(ctx, `UPDATE integration_operations SET
target_id = $3, status = 'SUCCEEDED', response_snapshot = $4::jsonb, completed_at = CURRENT_TIMESTAMP,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'RUNNING' AND operation_type = $2`, op.AggregateID, operationType, batch.ID, response)
	if err != nil {
		return nil, false, translateBatchError("complete credential batch transition", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		return nil, false, credentials.ErrBatchInvalidState
	}
	if err := tx.Commit(); err != nil {
		return nil, false, translateBatchError("commit credential batch transition", err)
	}
	return batch, created, nil
}

func validateSealBatchInput(input credentials.BeginSealCredentialBatchInput) ([]byte, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || !validBatchReference(input.BatchExternalID, 128) ||
		!validBatchReference(input.PoolExternalID, 128) || !validBatchReference(input.AccountRef, 128) ||
		!validBatchType(input.Type) || input.BatchVersion == 0 || input.BatchVersion > uint64(^uint32(0)>>1) ||
		input.MembershipEpoch == 0 || input.MembershipEpoch > uint64(^uint32(0)>>1) ||
		!nonzeroBatchHash(input.ContentFingerprint) || !nonzeroBatchHash(input.RequestHash) ||
		!validBatchReference(input.LeaseOwner, 128) || input.LeaseDuration <= 0 || input.LeaseDuration > 24*time.Hour {
		return nil, credentials.ErrBatchInvalidData
	}
	expected, _ := json.Marshal(struct {
		Version            int    `json:"version"`
		OperationID        string `json:"operation_id"`
		BatchID            string `json:"batch_id"`
		PoolID             string `json:"pool_id"`
		AccountRef         string `json:"account_ref"`
		BatchType          string `json:"batch_type"`
		BatchVersion       uint64 `json:"batch_version"`
		MembershipEpoch    uint64 `json:"membership_epoch"`
		ContentFingerprint string `json:"content_fingerprint"`
	}{1, input.Key.OperationID, input.BatchExternalID, input.PoolExternalID, input.AccountRef,
		string(input.Type), input.BatchVersion, input.MembershipEpoch, hex.EncodeToString(input.ContentFingerprint[:])})
	if sha256.Sum256(expected) != input.RequestHash {
		return nil, credentials.ErrBatchHashDrift
	}
	return exactBatchSnapshot(input.RequestSnapshot, expected)
}

func validateTransitionInput(input credentials.CredentialBatchTransitionInput, action string) ([]byte, error) {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || !validBatchReference(input.BatchExternalID, 128) ||
		input.ExpectedVersion <= 0 || !nonzeroBatchHash(input.RequestHash) {
		return nil, credentials.ErrBatchInvalidData
	}
	expected, _ := json.Marshal(struct {
		Version               int    `json:"version"`
		OperationID           string `json:"operation_id"`
		BatchID               string `json:"batch_id"`
		Action                string `json:"action"`
		ExpectedRecordVersion int64  `json:"expected_record_version"`
	}{1, input.Key.OperationID, input.BatchExternalID, action, input.ExpectedVersion})
	if sha256.Sum256(expected) != input.RequestHash {
		return nil, credentials.ErrBatchHashDrift
	}
	return exactBatchSnapshot(input.RequestSnapshot, expected)
}

func exactBatchSnapshot(actual, expected []byte) ([]byte, error) {
	canonicalActual, err := canonicalJSONObject(actual)
	canonicalExpected, expectedErr := canonicalJSONObject(expected)
	if err != nil || expectedErr != nil || !bytes.Equal(canonicalActual, canonicalExpected) {
		return nil, credentials.ErrBatchInvalidData
	}
	return canonicalActual, nil
}

type storedBatchResponse struct {
	Version            int                    `json:"version"`
	OperationID        string                 `json:"operation_id"`
	BatchID            string                 `json:"batch_id"`
	PoolID             string                 `json:"pool_id"`
	AccountRef         string                 `json:"account_ref"`
	BatchType          credentials.BatchType  `json:"batch_type"`
	BatchVersion       uint64                 `json:"batch_version"`
	MembershipEpoch    uint64                 `json:"membership_epoch"`
	State              credentials.BatchState `json:"state"`
	RecordVersion      int64                  `json:"record_version"`
	ContentFingerprint string                 `json:"content_fingerprint"`
	AADHash            string                 `json:"aad_hash"`
	SealedAt           time.Time              `json:"sealed_at"`
	ActivatedAt        *time.Time             `json:"activated_at"`
	RetiredAt          *time.Time             `json:"retired_at"`
}

func restoreHistoricalBatchResult(op *application.StoredOperation, batch *credentials.StoredCredentialBatch,
	expectedState credentials.BatchState, expectedRecordVersion int64) error {
	var response storedBatchResponse
	decoder := json.NewDecoder(bytes.NewReader(op.ResultSnapshot))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Version != 1 || response.OperationID != op.Key.OperationID ||
		response.BatchID != batch.ExternalID || response.PoolID != batch.PoolExternalID ||
		response.AccountRef != batch.AccountRef || response.BatchType != batch.Type ||
		response.BatchVersion != batch.BatchVersion || response.MembershipEpoch != batch.MembershipEpoch ||
		response.State != expectedState || response.RecordVersion != expectedRecordVersion || response.SealedAt.IsZero() ||
		response.ContentFingerprint != hex.EncodeToString(batch.ContentFingerprint[:]) ||
		response.AADHash != hex.EncodeToString(batch.AADHash[:]) {
		return credentials.ErrBatchInvalidData
	}
	if expectedState == credentials.BatchSealed && (response.ActivatedAt != nil || response.RetiredAt != nil) ||
		expectedState == credentials.BatchActive && (response.ActivatedAt == nil || response.RetiredAt != nil) ||
		expectedState == credentials.BatchRetired && (response.ActivatedAt == nil || response.RetiredAt == nil) {
		return credentials.ErrBatchInvalidData
	}
	batch.State, batch.Version = response.State, response.RecordVersion
	sealedAt := response.SealedAt.UTC()
	batch.SealedAt, batch.ActivatedAt, batch.RetiredAt = &sealedAt, utcBatchTime(response.ActivatedAt), utcBatchTime(response.RetiredAt)
	return nil
}

func validateSealEnvelopeInput(input credentials.CommitSealCredentialBatchInput) error {
	if !validKey(input.Key.ClientID, input.Key.OperationID) || !validBatchReference(input.LeaseOwner, 128) ||
		input.FencingToken <= 0 || input.Envelope.EncryptionAlgorithm != "AES-256-GCM" ||
		len(input.Envelope.Ciphertext) == 0 || len(input.Envelope.Nonce) != 12 ||
		!nonzeroBatchHash(input.Envelope.AADHash) || !nonzeroBatchHash(input.Envelope.ContentFingerprint) ||
		!validBatchReference(input.Envelope.KMSWrapAlgorithm, 64) || !validBatchReference(input.Envelope.KMSKeyRef, 512) ||
		!validBatchReference(input.Envelope.KMSWrapperDomain, 128) || len(input.Envelope.WrappedDEKKMS) == 0 ||
		!validBatchReference(input.Envelope.RecoveryWrapAlgorithm, 64) || !validBatchReference(input.Envelope.RecoveryKeyRef, 512) ||
		!validBatchReference(input.Envelope.RecoveryWrapperDomain, 128) || len(input.Envelope.WrappedDEKRecovery) == 0 ||
		input.Envelope.KMSWrapperDomain == input.Envelope.RecoveryWrapperDomain ||
		bytes.Equal(input.Envelope.WrappedDEKKMS, input.Envelope.WrappedDEKRecovery) ||
		!nonzeroBatchHash(input.Envelope.RecoveryBindingHash) {
		return credentials.ErrBatchInvalidData
	}
	return nil
}

func validateEnvelopeBinding(operationID string, batch *credentials.StoredCredentialBatch, envelope credentials.DualWrappedBatchEnvelope) error {
	aad, err := credentials.CanonicalBatchAAD(operationID, batch.ExternalID, batch.PoolExternalID, batch.AccountRef,
		batch.Type, batch.BatchVersion, batch.MembershipEpoch, batch.ContentFingerprint)
	if err != nil || sha256.Sum256(aad) != envelope.AADHash {
		return credentials.ErrBatchInvalidData
	}
	expectedRecovery := credentials.RecoveryBindingHash(envelope.RecoveryWrapperDomain,
		envelope.RecoveryWrapAlgorithm, envelope.RecoveryKeyRef, envelope.AADHash, envelope.WrappedDEKRecovery)
	if expectedRecovery != envelope.RecoveryBindingHash {
		return credentials.ErrBatchInvalidData
	}
	return nil
}

func validateBatchOperationIntent(op *application.StoredOperation, kind, externalID string,
	hash [sha256.Size]byte, canonical []byte) error {
	if op.MigrationState != credentials.BatchMigrationCurrent || string(op.Kind) != kind ||
		op.TargetType != batchTargetType || op.TargetExternalID != externalID {
		return credentials.ErrBatchHashDrift
	}
	stored, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || !bytes.Equal(stored, canonical) || op.RequestHash != hash {
		return credentials.ErrBatchHashDrift
	}
	return nil
}

func validBatchReference(value string, max int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= max
}

func validBatchType(value credentials.BatchType) bool {
	switch value {
	case credentials.BatchOperational, credentials.BatchLogin, credentials.BatchMFA,
		credentials.BatchRecovery, credentials.BatchOwnership:
		return true
	default:
		return false
	}
}

func nonzeroBatchHash(value [sha256.Size]byte) bool {
	return value != [sha256.Size]byte{}
}

func loadBatchTx(ctx context.Context, tx *sql.Tx, externalID string, forUpdate bool) (*credentials.StoredCredentialBatch, error) {
	query := `SELECT ` + batchColumns + ` FROM credential_batches b JOIN pools p ON p.id = b.pool_id
WHERE b.external_id = $1`
	if forUpdate {
		query += ` FOR UPDATE OF b`
	}
	batch, err := scanBatch(tx.QueryRowContext(ctx, query, externalID))
	if err != nil {
		return nil, translateBatchError("load credential batch", err)
	}
	return batch, nil
}

func loadBatchBySealOperationTx(ctx context.Context, tx *sql.Tx, operationID string, forUpdate bool) (*credentials.StoredCredentialBatch, error) {
	query := `SELECT ` + batchColumns + ` FROM credential_batches b JOIN pools p ON p.id = b.pool_id
WHERE b.seal_integration_operation_id = $1`
	if forUpdate {
		query += ` FOR UPDATE OF b`
	}
	batch, err := scanBatch(tx.QueryRowContext(ctx, query, operationID))
	if err != nil {
		return nil, translateBatchError("load credential batch by seal operation", err)
	}
	return batch, nil
}

func scanBatch(row scanner) (*credentials.StoredCredentialBatch, error) {
	batch := &credentials.StoredCredentialBatch{}
	var aadVersion sql.NullInt64
	var algorithm, kmsAlgorithm, kmsKeyRef, kmsDomain sql.NullString
	var recoveryAlgorithm, recoveryKeyRef, recoveryDomain sql.NullString
	var aadHash, contentHash, recoveryHash []byte
	var sealedAt, activatedAt, retiredAt sql.NullTime
	if err := row.Scan(&batch.ID, &batch.ExternalID, &batch.PoolID, &batch.PoolExternalID, &batch.AccountRef,
		&batch.Type, &batch.BatchVersion, &batch.MembershipEpoch, &batch.State, &batch.MigrationState, &aadVersion,
		&algorithm, &aadHash, &contentHash, &kmsAlgorithm, &kmsKeyRef, &kmsDomain,
		&recoveryAlgorithm, &recoveryKeyRef, &recoveryDomain, &recoveryHash, &batch.Version,
		&sealedAt, &activatedAt, &retiredAt, &batch.CreatedAt, &batch.UpdatedAt); err != nil {
		return nil, err
	}
	if batch.MigrationState == credentials.BatchMigrationCurrent && len(contentHash) != sha256.Size {
		return nil, credentials.ErrBatchInvalidData
	}
	if len(aadHash) != 0 && len(aadHash) != sha256.Size || len(recoveryHash) != 0 && len(recoveryHash) != sha256.Size {
		return nil, credentials.ErrBatchInvalidData
	}
	batch.AADVersion = uint16(aadVersion.Int64)
	batch.EncryptionAlgorithm = algorithm.String
	batch.KMSWrapAlgorithm, batch.KMSKeyRef, batch.KMSWrapperDomain = kmsAlgorithm.String, kmsKeyRef.String, kmsDomain.String
	batch.RecoveryWrapAlgorithm, batch.RecoveryKeyRef, batch.RecoveryWrapperDomain = recoveryAlgorithm.String, recoveryKeyRef.String, recoveryDomain.String
	copy(batch.AADHash[:], aadHash)
	copy(batch.ContentFingerprint[:], contentHash)
	copy(batch.RecoveryBindingHash[:], recoveryHash)
	if sealedAt.Valid {
		batch.SealedAt = &sealedAt.Time
	}
	if activatedAt.Valid {
		batch.ActivatedAt = &activatedAt.Time
	}
	if retiredAt.Valid {
		batch.RetiredAt = &retiredAt.Time
	}
	return batch, nil
}

func batchOperation(op *application.StoredOperation) *credentials.StoredBatchOperation {
	if op == nil {
		return nil
	}
	return &credentials.StoredBatchOperation{
		AggregateID: op.AggregateID, Key: credentials.BatchOperationKey{ClientID: op.Key.ClientID, OperationID: op.Key.OperationID},
		Kind: string(op.Kind), Status: string(op.Status), FencingToken: op.FencingToken, LeaseOwner: op.LeaseOwner,
		LeaseExpiresAt: op.LeaseExpiresAt, RequestHash: op.RequestHash,
		RequestSnapshot: append([]byte(nil), op.RequestSnapshot...), ResponseSnapshot: append([]byte(nil), op.ResultSnapshot...),
		ErrorCode: op.ErrorCode, CreatedAt: op.CreatedAt, UpdatedAt: op.UpdatedAt,
	}
}

func batchResponseSnapshot(operationID string, batch *credentials.StoredCredentialBatch, state credentials.BatchState,
	recordVersion int64, sealedAt, activatedAt, retiredAt *time.Time) ([]byte, error) {
	if batch == nil || sealedAt == nil {
		return nil, credentials.ErrBatchInvalidData
	}
	return json.Marshal(struct {
		Version            int                    `json:"version"`
		OperationID        string                 `json:"operation_id"`
		BatchID            string                 `json:"batch_id"`
		PoolID             string                 `json:"pool_id"`
		AccountRef         string                 `json:"account_ref"`
		BatchType          credentials.BatchType  `json:"batch_type"`
		BatchVersion       uint64                 `json:"batch_version"`
		MembershipEpoch    uint64                 `json:"membership_epoch"`
		State              credentials.BatchState `json:"state"`
		RecordVersion      int64                  `json:"record_version"`
		ContentFingerprint string                 `json:"content_fingerprint"`
		AADHash            string                 `json:"aad_hash"`
		SealedAt           time.Time              `json:"sealed_at"`
		ActivatedAt        *time.Time             `json:"activated_at"`
		RetiredAt          *time.Time             `json:"retired_at"`
	}{1, operationID, batch.ExternalID, batch.PoolExternalID, batch.AccountRef, batch.Type,
		batch.BatchVersion, batch.MembershipEpoch, state, recordVersion,
		hex.EncodeToString(batch.ContentFingerprint[:]), hex.EncodeToString(batch.AADHash[:]),
		sealedAt.UTC(), utcBatchTime(activatedAt), utcBatchTime(retiredAt)})
}

func utcBatchTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func translateBatchState(action string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return credentials.ErrBatchInvalidState
	}
	return fmt.Errorf("%s: %w", action, err)
}

func translateBatchError(action string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return credentials.ErrBatchNotFound
	}
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" {
		if strings.Contains(err.Error(), "integration_operations") {
			return credentials.ErrBatchHashDrift
		}
		return credentials.ErrBatchTargetConflict
	}
	return fmt.Errorf("%s: %w", action, err)
}

func requireSingleBatchFencedRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read credential batch fenced result: %w", err)
	}
	if rows != 1 {
		return credentials.ErrBatchStaleFence
	}
	return nil
}
