package exporter

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/offline"
)

type fakeStore struct {
	beginInput  recovery.BeginVerificationExportInput
	commitInput recovery.CommitVerificationExportInput
	renewInput  recovery.RenewVerificationExportLeaseInput
	loadInputs  []recovery.LoadPublicEvidenceSnapshotInput
	target      *recovery.VerificationExportTarget
	snapshot    *recovery.PublicEvidenceSnapshot
	commit      *recovery.StoredVerificationExport
	committed   bool
	renewErr    error
	commitErr   error
	onCommit    func(recovery.CommitVerificationExportInput)
	calls       []string
}

func (store *fakeStore) RenewVerificationExportLease(_ context.Context,
	input recovery.RenewVerificationExportLeaseInput) (*recovery.StoredOperation, error) {
	store.calls = append(store.calls, "renew")
	store.renewInput = input
	if store.renewErr != nil {
		return nil, store.renewErr
	}
	return store.target.Operation, nil
}

func (store *fakeStore) BeginVerificationExport(_ context.Context,
	input recovery.BeginVerificationExportInput) (*recovery.VerificationExportTarget, bool, error) {
	store.calls = append(store.calls, "begin")
	store.beginInput = input
	return store.target, true, nil
}

func (store *fakeStore) LoadPublicEvidenceSnapshot(_ context.Context,
	input recovery.LoadPublicEvidenceSnapshotInput) (*recovery.PublicEvidenceSnapshot, error) {
	store.calls = append(store.calls, "load")
	store.loadInputs = append(store.loadInputs, input)
	return store.snapshot, nil
}

func (store *fakeStore) CommitVerificationExport(_ context.Context,
	input recovery.CommitVerificationExportInput) (*recovery.StoredVerificationExport, bool, error) {
	store.calls = append(store.calls, "commit")
	store.commitInput = input
	if store.onCommit != nil {
		store.onCommit(input)
	}
	return store.commit, store.committed, store.commitErr
}

func (store *fakeStore) GetVerificationExport(context.Context, string) (*recovery.StoredVerificationExport, error) {
	if store.commit != nil {
		clone := *store.commit
		return &clone, nil
	}
	if store.target != nil && store.target.Export != nil {
		clone := *store.target.Export
		return &clone, nil
	}
	return nil, recovery.ErrNotFound
}

type fakeSigner struct {
	calls    []string
	requests []SignRequest
	signErr  error
	forbid   bool
	block    bool
	deadline time.Time
}

func (signer *fakeSigner) Ready(context.Context) error {
	if signer.forbid {
		panic("terminal replay called signer Ready")
	}
	signer.calls = append(signer.calls, "ready")
	return nil
}

func (signer *fakeSigner) Sign(ctx context.Context, request SignRequest) (Signature, error) {
	if signer.forbid {
		panic("terminal replay called signer Sign")
	}
	signer.calls = append(signer.calls, "sign")
	signer.requests = append(signer.requests, request)
	if deadline, ok := ctx.Deadline(); ok {
		signer.deadline = deadline
	}
	if signer.block {
		<-ctx.Done()
		return Signature{}, ctx.Err()
	}
	if signer.signErr != nil {
		return Signature{}, signer.signErr
	}
	digest := sha256.Sum256(request.Message)
	return Signature{Algorithm: offline.SignatureAlgorithmEd25519, KeyID: "export-key-1", Bytes: digest[:]}, nil
}

func (signer *fakeSigner) Verify(_ context.Context, request SignRequest, signature Signature) error {
	if signer.forbid {
		panic("terminal replay called signer Verify")
	}
	signer.calls = append(signer.calls, "verify")
	digest := sha256.Sum256(request.Message)
	if string(digest[:]) != string(signature.Bytes) {
		return errors.New("signature mismatch")
	}
	return nil
}

func TestManagerExportPersistsIntentBeforeSigningAndCommitsExactDigests(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 3, 4, 123456789, time.FixedZone("offset", 8*60*60))
	store, signer, manager := newTestManager(t, now)

	result, err := manager.Export(context.Background(), testCommand())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !result.FirstDelivery || len(result.Bundle) == 0 {
		t.Fatalf("result = %+v", result)
	}
	if got, want := store.calls, []string{"begin", "load", "renew", "commit"}; !equalStrings(got, want) {
		t.Fatalf("store calls = %v, want %v", got, want)
	}
	if got, want := signer.calls, []string{"ready", "sign", "verify"}; !equalStrings(got, want) {
		t.Fatalf("signer calls = %v, want %v", got, want)
	}
	if len(store.beginInput.RequestSnapshot) == 0 || store.beginInput.RequestHash == ([sha256.Size]byte{}) {
		t.Fatal("durable request intent was not populated")
	}
	if store.renewInput.ExpectedFencingToken != 7 || store.renewInput.ExportExternalID != "export-1" {
		t.Fatalf("renew input = %+v", store.renewInput)
	}
	if len(store.loadInputs) != 1 || store.loadInputs[0].LeaseOwner != "export-worker" ||
		store.loadInputs[0].FencingToken != 7 {
		t.Fatalf("active snapshot input = %+v", store.loadInputs)
	}
	if got := sha256.Sum256(result.Bundle); got != store.commitInput.BundleDigest {
		t.Fatal("committed bundle digest does not cover delivered bytes")
	}
	if store.commitInput.GeneratedAt.Format(time.RFC3339Nano) != "2026-08-20T18:03:04.123456Z" ||
		store.commitInput.SignerDomain != recovery.VerificationExportSignatureDomainV1 {
		t.Fatalf("commit metadata = %+v", store.commitInput)
	}
	if len(signer.requests) != 1 ||
		signer.requests[0].IdempotencyKey != verificationExportIdempotencyKey(store.beginInput) {
		t.Fatalf("signer idempotency request = %+v", signer.requests)
	}
}

func TestVerificationExportIdempotencyKeyIsUnambiguousAndClientScoped(t *testing.T) {
	build := func(clientID, operationID, exportID string) string {
		t.Helper()
		input := recovery.BeginVerificationExportInput{Key: recovery.OperationKey{
			ClientID: clientID, OperationID: operationID}, ExportExternalID: exportID,
			PlanExternalID: "plan-1", FormatVersion: offline.BundleProtocolVersion}
		_, input.RequestHash, _ = recovery.BuildVerificationExportRequestSnapshot(input)
		return verificationExportIdempotencyKey(input)
	}

	first := build("client-1", "a:b", "c")
	if second := build("client-1", "a", "b:c"); first == second {
		t.Fatal("delimiter-ambiguous operation/export identities shared an idempotency key")
	}
	if otherClient := build("client-2", "a:b", "c"); first == otherClient {
		t.Fatal("different integration clients shared an idempotency key")
	}
	if len(first) != sha256.Size*2 {
		t.Fatalf("idempotency key length = %d", len(first))
	}
}

func TestManagerExportSanitizesSignerFailureAndDoesNotCommit(t *testing.T) {
	store, signer, manager := newTestManager(t, time.Now())
	signer.signErr = errors.New("provider echoed secret evidence: canary")

	_, err := manager.Export(context.Background(), testCommand())
	if !errors.Is(err, recovery.ErrProviderUnavailable) || err.Error() != recovery.ErrProviderUnavailable.Error() {
		t.Fatalf("error = %v", err)
	}
	if len(store.calls) != 3 || store.calls[0] != "begin" || store.calls[1] != "load" || store.calls[2] != "renew" {
		t.Fatalf("store calls after signer failure = %v", store.calls)
	}
}

func TestManagerExportBoundsAllSignerWorkByHalfLease(t *testing.T) {
	store, signer, manager := newTestManager(t, time.Now())
	signer.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := manager.Export(ctx, testCommand())
	if !errors.Is(err, recovery.ErrProviderUnavailable) || time.Since(started) > time.Second {
		t.Fatalf("bounded signer error = %v after %s", err, time.Since(started))
	}
	if signer.deadline.IsZero() || signer.deadline.After(started.Add(15*time.Second+time.Second)) {
		t.Fatalf("signer deadline %s is not bounded by half of the 30s lease", signer.deadline)
	}
	if len(store.calls) != 3 {
		t.Fatalf("timed out signer reached commit: %v", store.calls)
	}
}

func TestManagerExportTerminalReplayRebuildsWithoutSignerOrLiveLease(t *testing.T) {
	generatedAt := time.Date(2026, 8, 21, 1, 2, 3, 456789000, time.UTC)
	store, signer, manager := newTestManager(t, generatedAt.Add(time.Hour))
	built, err := offline.BuildPublicEvidenceBundle(*store.snapshot, generatedAt)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	store.target.Operation.Status = "SUCCEEDED"
	store.target.Operation.LeaseOwner = ""
	store.target.Operation.LeaseExpiresAt = nil
	store.target.Export.Status = recovery.VerificationExportAvailable
	store.target.Export.GeneratedAt = &generatedAt
	store.target.Export.InventoryDigest = built.InventoryDigest
	store.target.Export.BundleDigest = built.BundleDigest
	signer.forbid = true

	result, err := manager.Export(context.Background(), testCommand())
	if err != nil {
		t.Fatalf("terminal replay: %v", err)
	}
	if result.FirstDelivery || string(result.Bundle) != string(built.CanonicalBytes) {
		t.Fatalf("terminal result = %+v", result)
	}
	if got, want := store.calls, []string{"begin", "load"}; !equalStrings(got, want) {
		t.Fatalf("store calls = %v, want %v", got, want)
	}
	if len(store.loadInputs) != 1 || store.loadInputs[0].LeaseOwner != "" ||
		store.loadInputs[0].FencingToken != 0 {
		t.Fatalf("terminal snapshot input = %+v", store.loadInputs)
	}
}

func TestManagerExportCommitResponseLossReplaysWithoutResigning(t *testing.T) {
	generatedAt := time.Date(2026, 8, 21, 1, 2, 3, 456789000, time.UTC)
	store, signer, manager := newTestManager(t, generatedAt)
	responseLost := errors.New("connection lost after durable commit")
	store.commitErr = responseLost
	store.onCommit = func(input recovery.CommitVerificationExportInput) {
		store.target.Operation.Status = "SUCCEEDED"
		store.target.Operation.LeaseOwner = ""
		store.target.Operation.LeaseExpiresAt = nil
		store.target.Export.OperationKey = input.Key
		store.target.Export.Status = recovery.VerificationExportAvailable
		store.target.Export.InventoryDigest = input.InventoryDigest
		store.target.Export.BundleDigest = input.BundleDigest
		store.target.Export.SignerDomain = input.SignerDomain
		store.target.Export.SignerAlgorithm = input.SignerAlgorithm
		store.target.Export.SignerKeyID = input.SignerKeyID
		store.target.Export.Signature = append([]byte(nil), input.Signature...)
		store.target.Export.GeneratedAt = &input.GeneratedAt
	}

	result, err := manager.Export(context.Background(), testCommand())
	if result != nil || !errors.Is(err, responseLost) {
		t.Fatalf("lost commit response = result %+v, err %v", result, err)
	}
	if got, want := signer.calls, []string{"ready", "sign", "verify"}; !equalStrings(got, want) {
		t.Fatalf("first signer calls = %v, want %v", got, want)
	}

	store.calls = nil
	store.commitErr = nil
	store.onCommit = nil
	signer.forbid = true
	result, err = manager.Export(context.Background(), testCommand())
	if err != nil {
		t.Fatalf("replay after response loss: %v", err)
	}
	if result.FirstDelivery || len(result.Bundle) == 0 {
		t.Fatalf("replayed result = %+v", result)
	}
	if got, want := store.calls, []string{"begin", "load"}; !equalStrings(got, want) {
		t.Fatalf("replay store calls = %v, want %v", got, want)
	}
}

func TestManagerExportTakeoverBeforeSigningFailsClosed(t *testing.T) {
	store, signer, manager := newTestManager(t, time.Now())
	store.renewErr = recovery.ErrStaleFence

	result, err := manager.Export(context.Background(), testCommand())
	if result != nil || !errors.Is(err, recovery.ErrStaleFence) {
		t.Fatalf("stale fence = result %+v, err %v", result, err)
	}
	if len(signer.calls) != 0 {
		t.Fatalf("stale owner reached signer: %v", signer.calls)
	}
	if got, want := store.calls, []string{"begin", "load", "renew"}; !equalStrings(got, want) {
		t.Fatalf("store calls = %v, want %v", got, want)
	}
}

func TestManagerExportRetryBeforeCommitUsesStableSignerRequest(t *testing.T) {
	generatedAt := time.Date(2026, 8, 21, 1, 2, 3, 456789000, time.UTC)
	store, signer, manager := newTestManager(t, generatedAt)
	store.commitErr = errors.New("database unavailable before commit")

	if _, err := manager.Export(context.Background(), testCommand()); err == nil {
		t.Fatal("first failed commit returned success")
	}
	store.commitErr = nil
	if _, err := manager.Export(context.Background(), testCommand()); err != nil {
		t.Fatalf("retry export: %v", err)
	}
	if len(signer.requests) != 2 || signer.requests[0].IdempotencyKey != signer.requests[1].IdempotencyKey ||
		string(signer.requests[0].Message) != string(signer.requests[1].Message) {
		t.Fatalf("signer retry drifted: %+v", signer.requests)
	}
}

func TestManagerExportTerminalReplayRejectsDigestDrift(t *testing.T) {
	generatedAt := time.Now().UTC().Truncate(time.Microsecond)
	store, signer, manager := newTestManager(t, generatedAt)
	store.target.Operation.Status = "SUCCEEDED"
	store.target.Export.Status = recovery.VerificationExportAvailable
	store.target.Export.GeneratedAt = &generatedAt
	store.target.Export.InventoryDigest[0] = 1
	store.target.Export.BundleDigest[0] = 1
	signer.forbid = true

	_, err := manager.Export(context.Background(), testCommand())
	if !errors.Is(err, recovery.ErrHashDrift) {
		t.Fatalf("error = %v", err)
	}
}

func TestManagerDownloadRebuildsPersistedExportWithoutSigner(t *testing.T) {
	generatedAt := time.Date(2026, 8, 21, 1, 2, 3, 456789000, time.UTC)
	store, signer, manager := newTestManager(t, generatedAt.Add(time.Hour))
	built, err := offline.BuildPublicEvidenceBundle(*store.snapshot, generatedAt)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	store.commit.OperationKey = store.target.Operation.Key
	store.commit.Status = recovery.VerificationExportAvailable
	store.commit.GeneratedAt = &generatedAt
	store.commit.InventoryDigest = built.InventoryDigest
	store.commit.BundleDigest = built.BundleDigest
	signer.forbid = true

	result, err := manager.Download(context.Background(), "plan-1", "export-1")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if result.FirstDelivery || string(result.Bundle) != string(built.CanonicalBytes) {
		t.Fatalf("download result = %+v", result)
	}
	if got, want := store.calls, []string{"load"}; !equalStrings(got, want) {
		t.Fatalf("store calls = %v, want %v", got, want)
	}
	if len(store.loadInputs) != 1 || store.loadInputs[0].LeaseOwner != "" ||
		store.loadInputs[0].FencingToken != 0 {
		t.Fatalf("download snapshot input = %+v", store.loadInputs)
	}
}

func TestManagerDownloadRejectsPlanAndDigestDrift(t *testing.T) {
	generatedAt := time.Now().UTC().Truncate(time.Microsecond)
	store, _, manager := newTestManager(t, generatedAt)
	built, err := offline.BuildPublicEvidenceBundle(*store.snapshot, generatedAt)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	store.commit.OperationKey = store.target.Operation.Key
	store.commit.Status = recovery.VerificationExportAvailable
	store.commit.GeneratedAt = &generatedAt
	store.commit.InventoryDigest = built.InventoryDigest
	store.commit.BundleDigest = built.BundleDigest

	if _, err := manager.Download(context.Background(), "other-plan", "export-1"); !errors.Is(err, recovery.ErrInvalidState) {
		t.Fatalf("wrong plan error = %v", err)
	}
	store.commit.BundleDigest[0] ^= 0xff
	if _, err := manager.Download(context.Background(), "plan-1", "export-1"); !errors.Is(err, recovery.ErrHashDrift) {
		t.Fatalf("digest drift error = %v", err)
	}
}

func newTestManager(t *testing.T, now time.Time) (*fakeStore, *fakeSigner, *Manager) {
	t.Helper()
	command := testCommand()
	leaseExpiry := now.Add(time.Minute)
	export := &recovery.StoredVerificationExport{ExternalID: command.ExportID, PlanExternalID: command.PlanID,
		FormatVersion: offline.BundleProtocolVersion, Status: recovery.VerificationExportPending, CreatedAt: now}
	begin := recovery.BeginVerificationExportInput{Key: recovery.OperationKey{ClientID: "export-client",
		OperationID: command.OperationID}, ExportExternalID: command.ExportID, PlanExternalID: command.PlanID,
		FormatVersion: offline.BundleProtocolVersion}
	_, requestHash, err := recovery.BuildVerificationExportRequestSnapshot(begin)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{committed: true, target: &recovery.VerificationExportTarget{
		Operation: &recovery.StoredOperation{Key: begin.Key, Kind: "EXPORT_RECOVERY_VERIFICATION", Status: "RUNNING",
			FencingToken: 7, LeaseOwner: "export-worker", LeaseExpiresAt: &leaseExpiry, RequestHash: requestHash},
		Export: export}, snapshot: testSnapshot(export)}
	store.commit = &recovery.StoredVerificationExport{ExternalID: command.ExportID, PlanExternalID: command.PlanID,
		FormatVersion: offline.BundleProtocolVersion, Status: recovery.VerificationExportAvailable}
	signer := &fakeSigner{}
	manager, err := NewManager(store, signer, Config{ClientID: "export-client", LeaseOwner: "export-worker",
		LeaseDuration: time.Minute})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return store, signer, manager
}

func testCommand() Command {
	return Command{OperationID: "export-operation-1", ExportID: "export-1", PlanID: "plan-1"}
}

func testSnapshot(export *recovery.StoredVerificationExport) *recovery.PublicEvidenceSnapshot {
	var manifestHash [sha256.Size]byte
	manifestHash[0] = 1
	return &recovery.PublicEvidenceSnapshot{Export: export, ProtocolVersion: offline.BundleProtocolVersion,
		CanonicalManifest: []byte(`{"protocol_version":"trusted-pool/recovery-governance/v1"}`),
		ManifestHash:      manifestHash, PlatformSignature: recovery.PublicPlatformSignature{
			Domain: offline.PlatformSignatureDomainV2, Algorithm: offline.SignatureAlgorithmEd25519,
			KeyID: "platform-key", Signature: []byte{1}}}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
