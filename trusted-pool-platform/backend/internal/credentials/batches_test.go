package credentials

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	wrapper, err := NewLocalKeyWrapper([]byte(strings.Repeat("w", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(wrapper, nil, func() time.Time {
		return time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestCredentialBatchRoundTripAndLifecycle(t *testing.T) {
	manager := newTestManager(t)
	plaintext := []byte(`{"username":"member@example.com","password":"secret"}`)
	batch, err := manager.Seal(context.Background(), SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
		Version: 1, MembershipEpoch: 2, KeyRef: "local-kek-v1", Plaintext: plaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if batch.State != BatchSealed || bytes.Contains(batch.Ciphertext, []byte("secret")) {
		t.Fatalf("plaintext leaked into batch: %+v", batch)
	}
	opened, err := manager.Open(context.Background(), batch.ID)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("round trip failed: plaintext=%q err=%v", opened, err)
	}
	if _, err := manager.Retire(batch.ID); err == nil {
		t.Fatal("retired a batch before activation")
	}
	if _, err := manager.Activate(batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Retire(batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Open(context.Background(), batch.ID); err == nil {
		t.Fatal("opened a retired credential batch")
	}
}

func TestCredentialBatchDetectsCiphertextAndMetadataTampering(t *testing.T) {
	manager := newTestManager(t)
	batch, err := manager.Seal(context.Background(), SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchMFA,
		Version: 1, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("totp-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.batches[batch.ID].Ciphertext[0] ^= 0xff
	manager.mu.Unlock()
	if _, err := manager.Open(context.Background(), batch.ID); err == nil {
		t.Fatal("ciphertext tampering was not detected")
	}

	metadataBatch, err := manager.Seal(context.Background(), SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchRecovery,
		Version: 2, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("recovery-code"),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.batches[metadataBatch.ID].MembershipEpoch = 2
	manager.mu.Unlock()
	if _, err := manager.Open(context.Background(), metadataBatch.ID); err == nil {
		t.Fatal("AAD metadata tampering was not detected")
	}
}

func TestCredentialBatchRejectsDuplicateVersion(t *testing.T) {
	manager := newTestManager(t)
	request := SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
		Version: 1, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("first"),
	}
	if _, err := manager.Seal(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Plaintext = []byte("second")
	if _, err := manager.Seal(context.Background(), request); err == nil {
		t.Fatal("accepted duplicate credential batch version")
	}
}

func TestCredentialBatchRejectsOversizedPublicReference(t *testing.T) {
	manager := newTestManager(t)
	_, err := manager.Seal(context.Background(), SealRequest{
		PoolID: strings.Repeat("p", 129), AccountRef: "account-9", Type: BatchLogin,
		Version: 1, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("secret"),
	})
	if err == nil {
		t.Fatal("accepted a pool id that Phase 2 cannot persist")
	}
}

func TestCredentialBatchAllowsOnlyOneActiveVersionPerMembershipEpoch(t *testing.T) {
	manager := newTestManager(t)
	seal := func(version, epoch uint64) *Batch {
		t.Helper()
		batch, err := manager.Seal(context.Background(), SealRequest{
			PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
			Version: version, MembershipEpoch: epoch, KeyRef: "local-kek-v1", Plaintext: []byte("secret"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return batch
	}
	first := seal(1, 1)
	second := seal(2, 1)
	if _, err := manager.Activate(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(second.ID); err == nil {
		t.Fatal("activated two credential versions in the same membership epoch")
	}
	third := seal(1, 2)
	if _, err := manager.Activate(third.ID); err != nil {
		t.Fatalf("new membership epoch should allow its own active batch: %v", err)
	}
}

func TestCredentialBatchVersionUniquenessIncludesMembershipEpoch(t *testing.T) {
	manager := newTestManager(t)
	for _, epoch := range []uint64{1, 2} {
		_, err := manager.Seal(context.Background(), SealRequest{
			PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
			Version: 1, MembershipEpoch: epoch, KeyRef: "local-kek-v1", Plaintext: []byte("secret"),
		})
		if err != nil {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
	}
}

func TestControlRotationEvidenceRequiresRetiredOldAndActiveNewBatches(t *testing.T) {
	manager := newTestManager(t)
	for _, batchType := range controlBatchTypes {
		oldBatch, err := manager.Seal(context.Background(), SealRequest{
			PoolID: "pool-1", AccountRef: "account-9", Type: batchType,
			Version: 1, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("old"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Activate(oldBatch.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Retire(oldBatch.ID); err != nil {
			t.Fatal(err)
		}
		newBatch, err := manager.Seal(context.Background(), SealRequest{
			PoolID: "pool-1", AccountRef: "account-9", Type: batchType,
			Version: 2, MembershipEpoch: 2, KeyRef: "local-kek-v1", Plaintext: []byte("new"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Activate(newBatch.ID); err != nil {
			t.Fatal(err)
		}
	}
	evidence, err := manager.IssueControlRotationEvidence("pool-1", "account-9", 1, 2, "provider-ticket-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidateControlRotationEvidence(evidence.ID, "pool-1", 1, 2); err != nil {
		t.Fatalf("issued evidence did not validate: %v", err)
	}
	if err := manager.ValidateControlRotationEvidence(evidence.ID, "other-pool", 1, 2); err == nil {
		t.Fatal("control rotation evidence was reusable across pools")
	}
	if err := manager.CommitControlRotationEvidence(evidence.ID, "pool-1", 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(evidence.RetiredBatchIDs[BatchLogin]); err == nil {
		t.Fatal("reactivated a control batch from a committed old membership epoch")
	}
	if _, err := manager.Seal(context.Background(), SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
		Version: 3, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("stale"),
	}); err == nil {
		t.Fatal("created a credential batch for a committed old membership epoch")
	}
}

func TestControlRotationEvidenceRejectsIncompleteRotation(t *testing.T) {
	manager := newTestManager(t)
	batch, err := manager.Seal(context.Background(), SealRequest{
		PoolID: "pool-1", AccountRef: "account-9", Type: BatchLogin,
		Version: 2, MembershipEpoch: 2, KeyRef: "local-kek-v1", Plaintext: []byte("new"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IssueControlRotationEvidence("pool-1", "account-9", 1, 2, "provider-ticket-1"); err == nil {
		t.Fatal("incomplete control credential rotation produced evidence")
	}
}
