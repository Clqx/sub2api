package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
)

func TestGetCredentialBatchFailsClosedForLegacyMetadata(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{"FROM credential_batches b", "b.external_id = $1"},
		columns: batchColumnNames(), rows: [][]driver.Value{{
			"11111111-1111-1111-1111-111111111111", "batch-legacy", "22222222-2222-2222-2222-222222222222", "pool-1", "account-1",
			"LOGIN", int64(1), int64(1), "ACTIVE", credentials.BatchMigrationLegacy, nil,
			"AES-256-GCM", nil, nil, nil, nil, nil, nil, nil, nil, nil,
			int64(1), nil, nil, nil, now, now,
		}},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, err := store.GetCredentialBatch(context.Background(), "batch-legacy")
	if !errors.Is(err, credentials.ErrBatchLegacy) {
		t.Fatalf("expected legacy fail-close, got %v", err)
	}
	script.assertDone(t)
}

func TestValidateSealBatchInputAcceptsCanonicalObjectRegardlessOfKeyOrder(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("fingerprint"))
	expected := []byte(`{"version":1,"operation_id":"seal-1","batch_id":"batch-1","pool_id":"pool-1","account_ref":"account-1","batch_type":"LOGIN","batch_version":3,"membership_epoch":4,"content_fingerprint":"` + hex.EncodeToString(fingerprint[:]) + `"}`)
	snapshot := []byte(`{"content_fingerprint":"` + hex.EncodeToString(fingerprint[:]) + `","membership_epoch":4,"batch_version":3,"batch_type":"LOGIN","account_ref":"account-1","pool_id":"pool-1","batch_id":"batch-1","operation_id":"seal-1","version":1}`)
	requestHash := sha256.Sum256(expected)
	canonical, err := validateSealBatchInput(credentials.BeginSealCredentialBatchInput{
		Key:             credentials.BatchOperationKey{ClientID: "client-1", OperationID: "seal-1"},
		BatchExternalID: "batch-1", PoolExternalID: "pool-1", AccountRef: "account-1",
		Type: credentials.BatchLogin, BatchVersion: 3, MembershipEpoch: 4,
		ContentFingerprint: fingerprint, RequestHash: requestHash, RequestSnapshot: snapshot,
		LeaseOwner: "worker-1", LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("validateSealBatchInput(): %v", err)
	}
	if !strings.Contains(string(canonical), `"operation_id":"seal-1"`) {
		t.Fatalf("unexpected canonical snapshot: %s", canonical)
	}
}

func TestValidateTransitionInputRejectsExtraSensitiveField(t *testing.T) {
	expected := []byte(`{"version":1,"operation_id":"activate-1","batch_id":"batch-1","action":"ACTIVATE","expected_record_version":2}`)
	requestHash := sha256.Sum256(expected)
	_, err := validateTransitionInput(credentials.CredentialBatchTransitionInput{
		Key:             credentials.BatchOperationKey{ClientID: "client-1", OperationID: "activate-1"},
		BatchExternalID: "batch-1", ExpectedVersion: 2, RequestHash: requestHash,
		RequestSnapshot: []byte(`{"version":1,"operation_id":"activate-1","batch_id":"batch-1","action":"ACTIVATE","expected_record_version":2,"wrapped_dek":"must-not-persist"}`),
	}, "ACTIVATE")
	if !errors.Is(err, credentials.ErrBatchInvalidData) {
		t.Fatalf("expected redaction failure, got %v", err)
	}
}

func TestValidateTransitionInputRejectsRequestHashDrift(t *testing.T) {
	snapshot := []byte(`{"version":1,"operation_id":"retire-1","batch_id":"batch-1","action":"RETIRE","expected_record_version":3}`)
	_, err := validateTransitionInput(credentials.CredentialBatchTransitionInput{
		Key:             credentials.BatchOperationKey{ClientID: "client-1", OperationID: "retire-1"},
		BatchExternalID: "batch-1", ExpectedVersion: 3,
		RequestHash: sha256.Sum256([]byte("different intent")), RequestSnapshot: snapshot,
	}, "RETIRE")
	if !errors.Is(err, credentials.ErrBatchHashDrift) {
		t.Fatalf("expected request hash drift, got %v", err)
	}
}

func TestRestoreHistoricalBatchResultDoesNotReturnLaterState(t *testing.T) {
	fingerprint, aadHash := sha256.Sum256([]byte("fingerprint")), sha256.Sum256([]byte("aad"))
	sealedAt := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	batch := &credentials.StoredCredentialBatch{
		ExternalID: "batch-1", PoolExternalID: "pool-1", AccountRef: "account-1", Type: credentials.BatchLogin,
		BatchVersion: 3, MembershipEpoch: 4, State: credentials.BatchRetired, Version: 4,
		ContentFingerprint: fingerprint, AADHash: aadHash,
	}
	response, err := batchResponseSnapshot("seal-1", batch, credentials.BatchSealed, 2, &sealedAt, nil, nil)
	if err != nil {
		t.Fatalf("batchResponseSnapshot(): %v", err)
	}
	op := &application.StoredOperation{Key: application.OperationKey{OperationID: "seal-1"}, ResultSnapshot: response}
	if err := restoreHistoricalBatchResult(op, batch, credentials.BatchSealed, 2); err != nil {
		t.Fatalf("restoreHistoricalBatchResult(): %v", err)
	}
	if batch.State != credentials.BatchSealed || batch.Version != 2 || batch.RetiredAt != nil {
		t.Fatalf("terminal replay returned later state: %+v", batch)
	}
}

func TestPhase2ECredentialBatchMigrationHasFailCloseGuards(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "migrations", "007_phase2e_credential_batch_persistence.sql")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration 007: %v", err)
	}
	sql := string(contents)
	guards := []string{
		"migration_state = 'LEGACY_UNRECOVERABLE'",
		"recovery_binding_hash = credential_recovery_binding_hash(",
		"encrypted_dek_kms <> encrypted_dek_recovery",
		"UNIQUE (credential_batch_id, transition_type)",
		"valid_credential_batch_transition_snapshot(",
		"assert_credential_batch_transition_history(",
		"aggregate.operation_status <> 'SUCCEEDED'",
		"NEW.membership_epoch < pool_epoch_floor",
	}
	for _, guard := range guards {
		if !strings.Contains(sql, guard) {
			t.Errorf("migration 007 is missing fail-close guard %q", guard)
		}
	}
}

func TestBatchStoreSourceHasLeaseFenceAndEpochDoubleChecks(t *testing.T) {
	contents, err := os.ReadFile("store_credential_batch.go")
	if err != nil {
		t.Fatalf("read batch store source: %v", err)
	}
	source := string(contents)
	guards := []string{
		"fencing_token = $4 AND lease_owner = $5 AND lease_expires_at > CURRENT_TIMESTAMP",
		"AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)",
		"p.membership_epoch = $2",
		"$2 >= p.credential_epoch_floor",
		"validateEnvelopeBinding(input.Key.OperationID, batch, input.Envelope)",
	}
	for _, guard := range guards {
		if !strings.Contains(source, guard) {
			t.Errorf("batch Store is missing guard %q", guard)
		}
	}
	if strings.Contains(source, "OR lease_owner = $4") {
		t.Fatal("active batch seal lease permits same-owner fence invalidation")
	}
}

func batchColumnNames() []string {
	return []string{
		"id", "external_id", "pool_id", "pool_external_id", "resource_account_ref",
		"batch_type", "batch_version", "membership_epoch", "status", "migration_state", "aad_version",
		"encryption_algorithm", "aad_hash", "content_hash", "kms_wrap_algorithm", "kms_key_ref",
		"kms_wrapper_domain", "recovery_wrap_algorithm", "recovery_key_ref", "recovery_wrapper_domain",
		"recovery_binding_hash", "version", "sealed_at", "activated_at", "retired_at", "created_at", "updated_at",
	}
}
