package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"
)

type batchStoreStub struct {
	beginInput    BeginSealCredentialBatchInput
	beginTarget   *SealCredentialBatchTarget
	beginErr      error
	commitInput   CommitSealCredentialBatchInput
	commitBatch   *StoredCredentialBatch
	commitErr     error
	getBatch      *StoredCredentialBatch
	getErr        error
	activateInput CredentialBatchTransitionInput
	activateBatch *StoredCredentialBatch
	activateErr   error
	retireInput   CredentialBatchTransitionInput
	retireBatch   *StoredCredentialBatch
	retireErr     error
	onBegin       func(BeginSealCredentialBatchInput)
	onCommit      func(CommitSealCredentialBatchInput)
	beginCalls    int
	commitCalls   int
	activateCalls int
	retireCalls   int
}

func (s *batchStoreStub) BeginSealCredentialBatch(_ context.Context, input BeginSealCredentialBatchInput) (*SealCredentialBatchTarget, bool, error) {
	s.beginCalls++
	s.beginInput = input
	if s.onBegin != nil {
		s.onBegin(input)
	}
	return s.beginTarget, true, s.beginErr
}

func (s *batchStoreStub) CommitSealCredentialBatch(_ context.Context, input CommitSealCredentialBatchInput) (*StoredCredentialBatch, error) {
	s.commitCalls++
	s.commitInput = input
	s.commitInput.Envelope = cloneDualEnvelope(input.Envelope)
	if s.onCommit != nil {
		s.onCommit(input)
	}
	return s.commitBatch, s.commitErr
}

func (s *batchStoreStub) GetCredentialBatch(_ context.Context, _ string) (*StoredCredentialBatch, error) {
	return s.getBatch, s.getErr
}

func (s *batchStoreStub) ActivateCredentialBatch(_ context.Context, input CredentialBatchTransitionInput) (*StoredCredentialBatch, bool, error) {
	s.activateCalls++
	s.activateInput = input
	return s.activateBatch, true, s.activateErr
}

func (s *batchStoreStub) RetireCredentialBatch(_ context.Context, input CredentialBatchTransitionInput) (*StoredCredentialBatch, bool, error) {
	s.retireCalls++
	s.retireInput = input
	return s.retireBatch, true, s.retireErr
}

func TestPersistentManagerSealPersistsIntentBeforeDualWrapAndNoPlaintext(t *testing.T) {
	var sequence []string
	online := &onlineBatchWrapperStub{onWrap: func() { sequence = append(sequence, "online") }}
	recovery := &recoveryBatchWrapperStub{onWrap: func() { sequence = append(sequence, "recovery") }}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{8}, 32)),
		bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"password":"plaintext-canary","username":"member"}`)
	request := PersistentSealRequest{
		OperationID: "seal-op-1", PoolID: "pool-1", AccountRef: "account-1",
		Type: BatchLogin, Version: 3, MembershipEpoch: 7, Payload: payload,
	}
	store := &batchStoreStub{}
	store.onBegin = func(input BeginSealCredentialBatchInput) {
		sequence = append(sequence, "begin")
		if bytes.Contains(input.RequestSnapshot, []byte("plaintext-canary")) {
			t.Fatal("plaintext was persisted in operation request snapshot")
		}
		store.beginTarget = runningSealTarget(input)
	}
	store.onCommit = func(input CommitSealCredentialBatchInput) {
		sequence = append(sequence, "commit")
		store.commitBatch.ContentFingerprint = input.Envelope.ContentFingerprint
		if bytes.Contains(input.Envelope.Ciphertext, []byte("plaintext-canary")) ||
			input.Envelope.EncryptionAlgorithm != BatchEnvelopeAlgorithm {
			t.Fatal("commit contains plaintext or a schema-incompatible algorithm")
		}
	}
	now := time.Now().UTC()
	store.commitBatch = &StoredCredentialBatch{
		ExternalID: deterministicBatchExternalID("integration-a", request.OperationID), PoolExternalID: request.PoolID,
		AccountRef: request.AccountRef, Type: request.Type, BatchVersion: request.Version,
		MembershipEpoch: request.MembershipEpoch, State: BatchSealed, MigrationState: BatchMigrationCurrent,
		Version: 2, SealedAt: &now,
	}
	manager := newTestPersistentManager(t, store, sealer)
	batch, err := manager.Seal(context.Background(), request)
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if batch.ExternalID != store.commitBatch.ExternalID || !allZero(payload) {
		t.Fatalf("seal result mismatch or plaintext not cleared: batch=%+v payload=%v", batch, payload)
	}
	if !reflect.DeepEqual(sequence, []string{"begin", "online", "recovery", "commit"}) {
		t.Fatalf("unsafe call order: %v", sequence)
	}
	if store.beginInput.Key.OperationID != request.OperationID || store.beginInput.LeaseDuration != 20*time.Second ||
		store.commitInput.LeaseOwner != "batch-worker-1" || store.commitInput.FencingToken != 11 {
		t.Fatalf("persistent fencing contract was not propagated: begin=%+v commit=%+v", store.beginInput, store.commitInput)
	}
	wantFingerprint, _ := sealer.ContentFingerprint([]byte(`{"password":"plaintext-canary","username":"member"}`))
	if store.beginInput.ContentFingerprint != wantFingerprint ||
		!bytes.Contains(store.beginInput.RequestSnapshot, []byte(hex.EncodeToString(wantFingerprint[:]))) {
		t.Fatal("request snapshot does not contain the keyed content fingerprint")
	}
	if bytes.Contains(store.commitInput.Envelope.WrappedDEKKMS, []byte("plaintext-canary")) ||
		bytes.Contains(store.commitInput.Envelope.WrappedDEKRecovery, []byte("plaintext-canary")) {
		t.Fatal("wrapper output leaked plaintext")
	}
}

func TestPersistentManagerTerminalReplayDoesNotRewrap(t *testing.T) {
	online, recovery := &onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{2}, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"credential":"same"}`)
	request := PersistentSealRequest{OperationID: "seal-replay", PoolID: "pool-1", AccountRef: "account-1", Type: BatchMFA, Version: 1, MembershipEpoch: 2, Payload: payload}
	fingerprint, _ := sealer.ContentFingerprint(payload)
	snapshot, _ := sealBatchRequestSnapshot(PersistentSealRequest{
		OperationID: request.OperationID, BatchExternalID: deterministicBatchExternalID("integration-a", request.OperationID),
		PoolID: request.PoolID, AccountRef: request.AccountRef, Type: request.Type, Version: request.Version,
		MembershipEpoch: request.MembershipEpoch,
	}, fingerprint)
	batch := &StoredCredentialBatch{
		ExternalID: deterministicBatchExternalID("integration-a", request.OperationID), PoolExternalID: request.PoolID,
		AccountRef: request.AccountRef, Type: request.Type, BatchVersion: request.Version,
		MembershipEpoch: request.MembershipEpoch, State: BatchSealed, MigrationState: BatchMigrationCurrent,
		ContentFingerprint: fingerprint,
	}
	store := &batchStoreStub{beginTarget: &SealCredentialBatchTarget{
		Operation: &StoredBatchOperation{Key: BatchOperationKey{ClientID: "integration-a", OperationID: request.OperationID},
			Kind: "SEAL_CREDENTIAL_BATCH", Status: "SUCCEEDED", RequestHash: sha256.Sum256(snapshot)},
		Batch: batch,
	}}
	manager := newTestPersistentManager(t, store, sealer)
	got, err := manager.Seal(context.Background(), request)
	if err != nil {
		t.Fatalf("terminal replay: %v", err)
	}
	if got.ExternalID != batch.ExternalID || store.commitCalls != 0 || len(online.request.DEK) != 0 || len(recovery.request.DEK) != 0 {
		t.Fatal("terminal replay performed cryptography or commit")
	}
	if !allZero(payload) {
		t.Fatal("terminal replay did not clear plaintext")
	}
}

func TestPersistentManagerWrapFailureNeverCommits(t *testing.T) {
	online := &onlineBatchWrapperStub{}
	recovery := &recoveryBatchWrapperStub{wrapErr: errors.New("recovery offline")}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{7}, 32)),
		bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"canary":"never-persist"}`)
	store := &batchStoreStub{}
	store.onBegin = func(input BeginSealCredentialBatchInput) { store.beginTarget = runningSealTarget(input) }
	manager := newTestPersistentManager(t, store, sealer)
	_, err = manager.Seal(context.Background(), PersistentSealRequest{
		OperationID: "seal-fails", PoolID: "pool-1", AccountRef: "account-1", Type: BatchRecovery,
		Version: 1, MembershipEpoch: 1, Payload: payload,
	})
	if !errors.Is(err, ErrRecoveryRootUnavailable) || store.beginCalls != 1 || store.commitCalls != 0 || !allZero(payload) {
		t.Fatalf("wrapper failure escaped fail-close contract: err=%v begin=%d commit=%d payload=%v", err, store.beginCalls, store.commitCalls, payload)
	}
}

func TestPersistentManagerUnavailableWrapperDoesNotBegin(t *testing.T) {
	online := &onlineBatchWrapperStub{}
	recovery := &recoveryBatchWrapperStub{readyErr: errors.New("recovery root unavailable")}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{7}, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &batchStoreStub{}
	manager := newTestPersistentManager(t, store, sealer)
	payload := []byte(`{"canary":"never-begin"}`)
	_, err = manager.Seal(context.Background(), PersistentSealRequest{
		OperationID: "seal-not-ready", PoolID: "pool-1", AccountRef: "account-1", Type: BatchRecovery,
		Version: 1, MembershipEpoch: 1, Payload: payload,
	})
	if !errors.Is(err, ErrRecoveryRootUnavailable) || store.beginCalls != 0 || !allZero(payload) {
		t.Fatalf("unready wrapper mutated persistence: err=%v begin=%d payload=%v", err, store.beginCalls, payload)
	}
}

func TestPersistentManagerRejectsCorruptTargetBeforeWrapping(t *testing.T) {
	online, recovery := &onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{}
	sealer, err := NewBatchDualEnvelopeSealer(online, recovery, testDualEnvelopeConfig(bytes.Repeat([]byte{6}, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &batchStoreStub{}
	store.onBegin = func(input BeginSealCredentialBatchInput) {
		store.beginTarget = runningSealTarget(input)
		store.beginTarget.Operation.LeaseOwner = "another-worker"
	}
	manager := newTestPersistentManager(t, store, sealer)
	payload := []byte(`{"secret":true}`)
	_, err = manager.Seal(context.Background(), PersistentSealRequest{
		OperationID: "seal-corrupt", PoolID: "pool-1", AccountRef: "account-1", Type: BatchLogin,
		Version: 1, MembershipEpoch: 1, Payload: payload,
	})
	if !errors.Is(err, ErrBatchInvalidState) || store.commitCalls != 0 || len(online.request.DEK) != 0 {
		t.Fatalf("corrupt target reached cryptography: err=%v", err)
	}
}

func TestPersistentManagerGetActivateAndRetireUseStore(t *testing.T) {
	sealer, err := NewBatchDualEnvelopeSealer(&onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{},
		testDualEnvelopeConfig(bytes.Repeat([]byte{1}, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &batchStoreStub{
		getBatch:      &StoredCredentialBatch{ExternalID: "batch-1", State: BatchSealed, MigrationState: BatchMigrationCurrent},
		activateBatch: &StoredCredentialBatch{ExternalID: "batch-1", State: BatchActive, MigrationState: BatchMigrationCurrent, Version: 5},
		retireBatch:   &StoredCredentialBatch{ExternalID: "batch-1", State: BatchRetired, MigrationState: BatchMigrationCurrent, Version: 6},
	}
	manager := newTestPersistentManager(t, store, sealer)
	if got, err := manager.Get(context.Background(), "batch-1"); err != nil || got.State != BatchSealed {
		t.Fatalf("Get(): got=%+v err=%v", got, err)
	}
	if got, err := manager.Activate(context.Background(), PersistentBatchTransitionRequest{OperationID: "activate-1", BatchExternalID: "batch-1", ExpectedVersion: 4}); err != nil || got.State != BatchActive {
		t.Fatalf("Activate(): got=%+v err=%v", got, err)
	}
	if got, err := manager.Retire(context.Background(), PersistentBatchTransitionRequest{OperationID: "retire-1", BatchExternalID: "batch-1", ExpectedVersion: 5}); err != nil || got.State != BatchRetired {
		t.Fatalf("Retire(): got=%+v err=%v", got, err)
	}
	if store.activateCalls != 1 || store.retireCalls != 1 || store.activateInput.Key.ClientID != "integration-a" ||
		store.retireInput.Key.OperationID != "retire-1" || store.activateInput.RequestHash == ([32]byte{}) ||
		bytes.Contains(store.activateInput.RequestSnapshot, []byte("ciphertext")) {
		t.Fatalf("transition intent mismatch: activate=%+v retire=%+v", store.activateInput, store.retireInput)
	}
	wantActivate := []byte(`{"version":1,"operation_id":"activate-1","batch_id":"batch-1","action":"ACTIVATE","expected_record_version":4}`)
	if !bytes.Equal(store.activateInput.RequestSnapshot, wantActivate) ||
		store.activateInput.RequestHash != sha256.Sum256(wantActivate) {
		t.Fatalf("activate intent is not encoded with the shared canonical order: %s", store.activateInput.RequestSnapshot)
	}
}

func TestPersistentManagerGetRejectsLegacyMetadata(t *testing.T) {
	sealer, err := NewBatchDualEnvelopeSealer(&onlineBatchWrapperStub{}, &recoveryBatchWrapperStub{},
		testDualEnvelopeConfig(bytes.Repeat([]byte{1}, 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &batchStoreStub{getBatch: &StoredCredentialBatch{
		ExternalID: "batch-legacy", State: BatchActive, MigrationState: BatchMigrationLegacy,
	}}
	manager := newTestPersistentManager(t, store, sealer)
	if _, err := manager.Get(context.Background(), "batch-legacy"); !errors.Is(err, ErrBatchLegacy) {
		t.Fatalf("legacy metadata was exposed as current: %v", err)
	}
}

func TestStoredCredentialBatchMetadataProjectionDoesNotExposeEnvelopeMaterial(t *testing.T) {
	typeOfBatch := reflect.TypeOf(StoredCredentialBatch{})
	for _, forbidden := range []string{"Ciphertext", "Nonce", "WrappedDEKKMS", "WrappedDEKRecovery"} {
		if _, found := typeOfBatch.FieldByName(forbidden); found {
			t.Fatalf("public stored batch projection exposes %s", forbidden)
		}
	}
}

func newTestPersistentManager(t *testing.T, store BatchStore, sealer *BatchDualEnvelopeSealer) *PersistentManager {
	t.Helper()
	manager, err := NewPersistentManager(store, sealer, PersistentManagerConfig{
		ClientID: "integration-a", LeaseOwner: "batch-worker-1", LeaseDuration: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func runningSealTarget(input BeginSealCredentialBatchInput) *SealCredentialBatchTarget {
	leaseExpiry := time.Now().UTC().Add(time.Minute)
	return &SealCredentialBatchTarget{
		Operation: &StoredBatchOperation{
			Key: input.Key, Kind: "SEAL_CREDENTIAL_BATCH", Status: "RUNNING", FencingToken: 11,
			LeaseOwner: input.LeaseOwner, LeaseExpiresAt: &leaseExpiry, RequestHash: input.RequestHash,
		},
		Batch: &StoredCredentialBatch{
			ExternalID: input.BatchExternalID, PoolExternalID: input.PoolExternalID, AccountRef: input.AccountRef,
			Type: input.Type, BatchVersion: input.BatchVersion, MembershipEpoch: input.MembershipEpoch,
			State: batchPrepared, MigrationState: BatchMigrationCurrent, ContentFingerprint: input.ContentFingerprint, Version: 1,
		},
	}
}

func cloneDualEnvelope(envelope DualWrappedBatchEnvelope) DualWrappedBatchEnvelope {
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	envelope.Nonce = append([]byte(nil), envelope.Nonce...)
	envelope.WrappedDEKKMS = append([]byte(nil), envelope.WrappedDEKKMS...)
	envelope.WrappedDEKRecovery = append([]byte(nil), envelope.WrappedDEKRecovery...)
	return envelope
}
