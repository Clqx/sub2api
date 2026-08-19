package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const batchPrepared BatchState = "PREPARED"

type PersistentManagerConfig struct {
	ClientID      string
	LeaseOwner    string
	LeaseDuration time.Duration
}

// PersistentSealRequest 的 Payload 会被消费并清零，调用方不得复用该底层切片。
type PersistentSealRequest struct {
	OperationID     string
	BatchExternalID string
	PoolID          string
	AccountRef      string
	Type            BatchType
	Version         uint64
	MembershipEpoch uint64
	Payload         []byte
}

type PersistentBatchTransitionRequest struct {
	OperationID     string
	BatchExternalID string
	ExpectedVersion int64
}

// PersistentManager 只编排持久聚合和双包装，不提供任何解密/Open 能力。
type PersistentManager struct {
	store  BatchStore
	sealer *BatchDualEnvelopeSealer
	config PersistentManagerConfig
}

func NewPersistentManager(store BatchStore, sealer *BatchDualEnvelopeSealer, config PersistentManagerConfig) (*PersistentManager, error) {
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.LeaseOwner = strings.TrimSpace(config.LeaseOwner)
	if store == nil || sealer == nil || !validEnvelopeReference(config.ClientID) ||
		!validEnvelopeReference(config.LeaseOwner) || config.LeaseDuration <= 0 || config.LeaseDuration > 5*time.Minute {
		return nil, errors.New("batch store, dual-envelope sealer, client, lease owner and bounded lease are required")
	}
	return &PersistentManager{store: store, sealer: sealer, config: config}, nil
}

func (m *PersistentManager) Ready(ctx context.Context) error {
	if m == nil || m.store == nil || m.sealer == nil {
		return errors.New("persistent credential batch manager is not configured")
	}
	return m.sealer.Ready(ctx)
}

func (m *PersistentManager) Seal(ctx context.Context, request PersistentSealRequest) (*StoredCredentialBatch, error) {
	defer clear(request.Payload)
	if m == nil || m.store == nil || m.sealer == nil {
		return nil, errors.New("persistent credential batch manager is not configured")
	}
	request.OperationID = strings.TrimSpace(request.OperationID)
	request.BatchExternalID = strings.TrimSpace(request.BatchExternalID)
	request.PoolID = strings.TrimSpace(request.PoolID)
	request.AccountRef = strings.TrimSpace(request.AccountRef)
	if request.BatchExternalID == "" && validEnvelopeReference(request.OperationID) {
		request.BatchExternalID = deterministicBatchExternalID(m.config.ClientID, request.OperationID)
	}
	if !validEnvelopeReference(request.OperationID) || !validEnvelopeReference(request.BatchExternalID) ||
		!validEnvelopeReference(request.PoolID) || !validEnvelopeReference(request.AccountRef) ||
		!validBatchType(request.Type) || request.Version == 0 || request.MembershipEpoch == 0 ||
		len(bytes.TrimSpace(request.Payload)) == 0 || !json.Valid(request.Payload) {
		return nil, ErrBatchInvalidData
	}
	// 外部 wrapper 未就绪时不得先留下 PREPARED/RUNNING 记录；Seal 内仍会二次检查可用性。
	if err := m.sealer.Ready(ctx); err != nil {
		return nil, err
	}
	contentFingerprint, err := m.sealer.ContentFingerprint(request.Payload)
	if err != nil {
		return nil, ErrBatchInvalidData
	}
	snapshot, err := sealBatchRequestSnapshot(request, contentFingerprint)
	if err != nil {
		return nil, ErrBatchInvalidData
	}
	requestHash := sha256.Sum256(snapshot)
	key := BatchOperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID}
	target, _, err := m.store.BeginSealCredentialBatch(ctx, BeginSealCredentialBatchInput{
		Key: key, BatchExternalID: request.BatchExternalID, PoolExternalID: request.PoolID,
		AccountRef: request.AccountRef, Type: request.Type, BatchVersion: request.Version,
		MembershipEpoch: request.MembershipEpoch, ContentFingerprint: contentFingerprint,
		RequestHash: requestHash, RequestSnapshot: snapshot, LeaseOwner: m.config.LeaseOwner,
		LeaseDuration: m.config.LeaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if err := validateSealTarget(target, key, request, contentFingerprint, requestHash, m.config.LeaseOwner); err != nil {
		return nil, err
	}
	if target.Operation.Status == "SUCCEEDED" {
		return cloneStoredCredentialBatch(target.Batch), nil
	}
	envelope, err := m.sealer.Seal(ctx, BatchEnvelopeScope{
		BatchExternalID: request.BatchExternalID, SealOperationID: request.OperationID,
		PoolID: request.PoolID, AccountRef: request.AccountRef, Type: request.Type,
		Version: request.Version, MembershipEpoch: request.MembershipEpoch,
	}, request.Payload)
	if err != nil {
		return nil, err
	}
	batch, err := m.store.CommitSealCredentialBatch(ctx, CommitSealCredentialBatchInput{
		Key: key, LeaseOwner: m.config.LeaseOwner, FencingToken: target.Operation.FencingToken,
		Envelope: envelope,
	})
	clearEnvelope(&envelope)
	if err != nil {
		return nil, err
	}
	if err := validateCommittedSealBatch(batch, request, contentFingerprint); err != nil {
		return nil, err
	}
	return cloneStoredCredentialBatch(batch), nil
}

func (m *PersistentManager) Get(ctx context.Context, batchExternalID string) (*StoredCredentialBatch, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("persistent credential batch manager is not configured")
	}
	batchExternalID = strings.TrimSpace(batchExternalID)
	if !validEnvelopeReference(batchExternalID) {
		return nil, ErrBatchInvalidData
	}
	batch, err := m.store.GetCredentialBatch(ctx, batchExternalID)
	if err != nil {
		return nil, err
	}
	if batch == nil || batch.ExternalID != batchExternalID {
		return nil, ErrBatchInvalidData
	}
	if batch.MigrationState != BatchMigrationCurrent {
		return nil, ErrBatchLegacy
	}
	return cloneStoredCredentialBatch(batch), nil
}

func (m *PersistentManager) Activate(ctx context.Context, request PersistentBatchTransitionRequest) (*StoredCredentialBatch, error) {
	return m.transition(ctx, request, true)
}

func (m *PersistentManager) Retire(ctx context.Context, request PersistentBatchTransitionRequest) (*StoredCredentialBatch, error) {
	return m.transition(ctx, request, false)
}

func (m *PersistentManager) transition(ctx context.Context, request PersistentBatchTransitionRequest, activate bool) (*StoredCredentialBatch, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("persistent credential batch manager is not configured")
	}
	request.OperationID = strings.TrimSpace(request.OperationID)
	request.BatchExternalID = strings.TrimSpace(request.BatchExternalID)
	if !validEnvelopeReference(request.OperationID) || !validEnvelopeReference(request.BatchExternalID) || request.ExpectedVersion <= 0 {
		return nil, ErrBatchInvalidData
	}
	action := "RETIRE"
	if activate {
		action = "ACTIVATE"
	}
	snapshot, err := json.Marshal(struct {
		Version         int    `json:"version"`
		OperationID     string `json:"operation_id"`
		BatchID         string `json:"batch_id"`
		Action          string `json:"action"`
		ExpectedVersion int64  `json:"expected_record_version"`
	}{1, request.OperationID, request.BatchExternalID, action, request.ExpectedVersion})
	if err != nil {
		return nil, ErrBatchInvalidData
	}
	input := CredentialBatchTransitionInput{
		Key:             BatchOperationKey{ClientID: m.config.ClientID, OperationID: request.OperationID},
		BatchExternalID: request.BatchExternalID, ExpectedVersion: request.ExpectedVersion,
		RequestHash: sha256.Sum256(snapshot), RequestSnapshot: snapshot,
	}
	var batch *StoredCredentialBatch
	if activate {
		batch, _, err = m.store.ActivateCredentialBatch(ctx, input)
	} else {
		batch, _, err = m.store.RetireCredentialBatch(ctx, input)
	}
	if err != nil {
		return nil, err
	}
	wantState := BatchRetired
	if activate {
		wantState = BatchActive
	}
	if batch == nil || batch.ExternalID != request.BatchExternalID || batch.MigrationState != BatchMigrationCurrent ||
		batch.State != wantState || batch.Version != request.ExpectedVersion+1 {
		return nil, ErrBatchInvalidData
	}
	return cloneStoredCredentialBatch(batch), nil
}

func sealBatchRequestSnapshot(request PersistentSealRequest, fingerprint [sha256.Size]byte) ([]byte, error) {
	return json.Marshal(struct {
		Version            int       `json:"version"`
		OperationID        string    `json:"operation_id"`
		BatchID            string    `json:"batch_id"`
		PoolID             string    `json:"pool_id"`
		AccountRef         string    `json:"account_ref"`
		BatchType          BatchType `json:"batch_type"`
		BatchVersion       uint64    `json:"batch_version"`
		MembershipEpoch    uint64    `json:"membership_epoch"`
		ContentFingerprint string    `json:"content_fingerprint"`
	}{1, request.OperationID, request.BatchExternalID, request.PoolID, request.AccountRef, request.Type,
		request.Version, request.MembershipEpoch, hex.EncodeToString(fingerprint[:])})
}

func validateSealTarget(target *SealCredentialBatchTarget, key BatchOperationKey, request PersistentSealRequest,
	fingerprint, requestHash [sha256.Size]byte, leaseOwner string) error {
	if target == nil || target.Operation == nil || target.Batch == nil {
		return ErrBatchInvalidData
	}
	op, batch := target.Operation, target.Batch
	if op.Key != key || op.Kind != "SEAL_CREDENTIAL_BATCH" || op.RequestHash != requestHash ||
		batch.ExternalID != request.BatchExternalID || batch.PoolExternalID != request.PoolID ||
		batch.AccountRef != request.AccountRef || batch.Type != request.Type || batch.BatchVersion != request.Version ||
		batch.MembershipEpoch != request.MembershipEpoch || batch.ContentFingerprint != fingerprint ||
		batch.MigrationState != BatchMigrationCurrent {
		return ErrBatchHashDrift
	}
	switch op.Status {
	case "SUCCEEDED":
		if batch.State != BatchSealed && batch.State != BatchActive && batch.State != BatchRetired {
			return ErrBatchInvalidState
		}
		return nil
	case "RUNNING", "RETRYABLE", "RECONCILE_REQUIRED":
		if batch.State != batchPrepared || batch.Version != 1 || op.LeaseOwner != leaseOwner || op.LeaseExpiresAt == nil {
			return ErrBatchInvalidState
		}
		if op.FencingToken <= 0 {
			return ErrBatchStaleFence
		}
		return nil
	default:
		return ErrBatchInvalidState
	}
}

func validateCommittedSealBatch(batch *StoredCredentialBatch, request PersistentSealRequest,
	fingerprint [sha256.Size]byte) error {
	if batch == nil || batch.ExternalID != request.BatchExternalID || batch.PoolExternalID != request.PoolID ||
		batch.AccountRef != request.AccountRef || batch.Type != request.Type || batch.BatchVersion != request.Version ||
		batch.MembershipEpoch != request.MembershipEpoch || batch.ContentFingerprint != fingerprint ||
		batch.MigrationState != BatchMigrationCurrent || batch.State != BatchSealed || batch.Version != 2 ||
		batch.SealedAt == nil {
		return ErrBatchInvalidData
	}
	return nil
}

func deterministicBatchExternalID(clientID, operationID string) string {
	digest := sha256.Sum256([]byte(clientID + "\x00" + operationID))
	return "batch-" + hex.EncodeToString(digest[:16])
}

func clearEnvelope(envelope *DualWrappedBatchEnvelope) {
	if envelope == nil {
		return
	}
	clear(envelope.Ciphertext)
	clear(envelope.Nonce)
	clear(envelope.WrappedDEKKMS)
	clear(envelope.WrappedDEKRecovery)
	*envelope = DualWrappedBatchEnvelope{}
}

func cloneStoredCredentialBatch(batch *StoredCredentialBatch) *StoredCredentialBatch {
	if batch == nil {
		return nil
	}
	clone := *batch
	clone.SealedAt = cloneTimePointer(batch.SealedAt)
	clone.ActivatedAt = cloneTimePointer(batch.ActivatedAt)
	clone.RetiredAt = cloneTimePointer(batch.RetiredAt)
	return &clone
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
