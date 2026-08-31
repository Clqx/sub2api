package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/credentials"

	_ "github.com/lib/pq"
)

// PHASE2H_TEST_POSTGRES_DSN must reference a disposable database where the
// caller can create and remove schemas.
func TestCredentialBatchFenceAndCASOnTwoRealPostgresConnections(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_batch_fence_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create credential batch fence schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	workerA := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerA.Close()
	if err := Migrate(ctx, workerA, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for credential batch fence test: %v", err)
	}
	workerB := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerB.Close()
	assertDifferentWorkflowBackends(t, ctx, workerA, workerB)
	insertCredentialBatchFenceFixture(t, ctx, workerA)

	storeA, err := NewStore(workerA)
	if err != nil {
		t.Fatalf("create credential batch worker A Store: %v", err)
	}
	storeB, err := NewStore(workerB)
	if err != nil {
		t.Fatalf("create credential batch worker B Store: %v", err)
	}

	inputA := credentialBatchSealInput("batch-seal-a", "batch-fence-a", 1, "batch-worker-a", 30*time.Second)
	sealedA := raceExpiredCredentialBatchSealLease(t, ctx, workerA, storeA, storeB, inputA)
	if sealedA.State != credentials.BatchSealed || sealedA.Version != 2 {
		t.Fatalf("unexpected winning sealed batch: %+v", sealedA)
	}
	inputB := credentialBatchSealInput("batch-seal-b", "batch-fence-b", 2, "batch-worker-b", 10*time.Second)
	sealedB := sealCredentialBatchWithoutContention(t, ctx, storeB, inputB)
	if sealedB.State != credentials.BatchSealed || sealedB.Version != 2 {
		t.Fatalf("unexpected second sealed batch: %+v", sealedB)
	}

	active := raceSameScopeCredentialBatchActivation(t, ctx, storeA, storeB, inputA.BatchExternalID, inputB.BatchExternalID)
	if active.batch == nil || active.batch.State != credentials.BatchActive || active.batch.Version != 3 {
		t.Fatalf("unexpected active credential batch winner: %+v", active.batch)
	}
	assertCredentialBatchAggregateCounts(t, ctx, workerA, 1, 1, 0, 1, 0)

	staleActivate := credentialBatchTransitionInput("batch-activate-stale", active.input.BatchExternalID, "ACTIVATE", 2)
	if _, _, err := active.store.ActivateCredentialBatch(ctx, staleActivate); !errors.Is(err, credentials.ErrBatchInvalidState) {
		t.Fatalf("stale credential batch activation version was not rejected: %v", err)
	}
	assertCredentialBatchAggregateCounts(t, ctx, workerA, 1, 1, 0, 1, 0)

	retired := raceCredentialBatchRetirement(t, ctx, storeA, storeB, active.input.BatchExternalID)
	if retired.batch == nil || retired.batch.State != credentials.BatchRetired || retired.batch.Version != 4 {
		t.Fatalf("unexpected retired credential batch winner: %+v", retired.batch)
	}
	assertCredentialBatchAggregateCounts(t, ctx, workerA, 0, 1, 1, 1, 1)

	staleRetire := credentialBatchTransitionInput("batch-retire-stale", active.input.BatchExternalID, "RETIRE", 3)
	if _, _, err := retired.store.RetireCredentialBatch(ctx, staleRetire); !errors.Is(err, credentials.ErrBatchInvalidState) {
		t.Fatalf("stale credential batch retirement version was not rejected: %v", err)
	}
	assertCredentialBatchAggregateCounts(t, ctx, workerA, 0, 1, 1, 1, 1)
}

type credentialBatchTransitionResult struct {
	input credentials.CredentialBatchTransitionInput
	store *Store
	batch *credentials.StoredCredentialBatch
	err   error
}

func raceExpiredCredentialBatchSealLease(t *testing.T, ctx context.Context, db *sql.DB,
	storeA, storeB *Store, input credentials.BeginSealCredentialBatchInput) *credentials.StoredCredentialBatch {
	t.Helper()
	first, created, err := storeA.BeginSealCredentialBatch(ctx, input)
	if err != nil || !created || first == nil || first.Operation == nil {
		t.Fatalf("begin first credential batch seal: created=%t target=%+v err=%v", created, first, err)
	}
	contended := input
	contended.LeaseOwner = "batch-worker-b"
	contended.LeaseDuration = time.Second
	if _, _, err := storeB.BeginSealCredentialBatch(ctx, contended); !errors.Is(err, credentials.ErrBatchLeaseHeld) {
		t.Fatalf("active credential batch seal lease was not exclusive: %v", err)
	}
	expireCredentialBatchLease(t, ctx, db, input.Key)

	type result struct {
		owner  string
		store  *Store
		target *credentials.SealCredentialBatchTarget
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	acquire := func(owner string, store *Store) {
		<-start
		candidate := input
		candidate.LeaseOwner = owner
		candidate.LeaseDuration = 10 * time.Second
		target, _, acquireErr := store.BeginSealCredentialBatch(ctx, candidate)
		results <- result{owner: owner, store: store, target: target, err: acquireErr}
	}
	go acquire("batch-worker-b", storeA)
	go acquire("batch-worker-c", storeB)
	close(start)
	resultOne, resultTwo := <-results, <-results

	var winner result
	for _, contender := range []result{resultOne, resultTwo} {
		if contender.err == nil {
			if winner.target != nil {
				t.Fatal("both PostgreSQL workers acquired the same expired credential batch seal lease")
			}
			winner = contender
			continue
		}
		if !errors.Is(contender.err, credentials.ErrBatchLeaseHeld) {
			t.Fatalf("credential batch seal contender %s returned %v", contender.owner, contender.err)
		}
	}
	if winner.target == nil || winner.target.Operation == nil {
		t.Fatal("neither PostgreSQL worker acquired the expired credential batch seal lease")
	}
	if got, want := winner.target.Operation.FencingToken, first.Operation.FencingToken+1; got != want {
		t.Fatalf("credential batch seal takeover fence=%d, want %d", got, want)
	}

	envelope := credentialBatchEnvelope(t, input)
	if _, err := storeA.CommitSealCredentialBatch(ctx, credentials.CommitSealCredentialBatchInput{
		Key: input.Key, LeaseOwner: input.LeaseOwner,
		FencingToken: first.Operation.FencingToken, Envelope: envelope,
	}); !errors.Is(err, credentials.ErrBatchStaleFence) {
		t.Fatalf("old credential batch seal fence was not rejected: %v", err)
	}
	sealed, err := winner.store.CommitSealCredentialBatch(ctx, credentials.CommitSealCredentialBatchInput{
		Key: input.Key, LeaseOwner: winner.owner,
		FencingToken: winner.target.Operation.FencingToken, Envelope: envelope,
	})
	if err != nil {
		t.Fatalf("commit winning credential batch seal fence: %v", err)
	}
	return sealed
}

func insertCredentialBatchFenceFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var poolID string
	if err := db.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, credential_epoch_floor
) VALUES ('batch-fence-pool', 'Batch Fence Pool', 'ACTIVE', 2, 1, 1) RETURNING id`).Scan(&poolID); err != nil {
		t.Fatalf("insert credential batch Pool: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold, activated_at
) VALUES ($1, 1, 'ACTIVE', 1, 1, CURRENT_TIMESTAMP)`, poolID); err != nil {
		t.Fatalf("insert credential batch Epoch: %v", err)
	}
}

func credentialBatchSealInput(operationID, batchID string, batchVersion uint64, owner string,
	duration time.Duration) credentials.BeginSealCredentialBatchInput {
	fingerprint := sha256.Sum256([]byte("credential-batch-fingerprint/" + batchID))
	snapshot, _ := json.Marshal(struct {
		Version            int    `json:"version"`
		OperationID        string `json:"operation_id"`
		BatchID            string `json:"batch_id"`
		PoolID             string `json:"pool_id"`
		AccountRef         string `json:"account_ref"`
		BatchType          string `json:"batch_type"`
		BatchVersion       uint64 `json:"batch_version"`
		MembershipEpoch    uint64 `json:"membership_epoch"`
		ContentFingerprint string `json:"content_fingerprint"`
	}{
		Version: 1, OperationID: operationID, BatchID: batchID, PoolID: "batch-fence-pool",
		AccountRef: "batch-fence-account", BatchType: string(credentials.BatchLogin),
		BatchVersion: batchVersion, MembershipEpoch: 1, ContentFingerprint: hex.EncodeToString(fingerprint[:]),
	})
	return credentials.BeginSealCredentialBatchInput{
		Key:             credentials.BatchOperationKey{ClientID: "batch-fence-client", OperationID: operationID},
		BatchExternalID: batchID, PoolExternalID: "batch-fence-pool", AccountRef: "batch-fence-account",
		Type: credentials.BatchLogin, BatchVersion: batchVersion, MembershipEpoch: 1,
		ContentFingerprint: fingerprint, RequestHash: sha256.Sum256(snapshot), RequestSnapshot: snapshot,
		LeaseOwner: owner, LeaseDuration: duration,
	}
}

func credentialBatchEnvelope(t *testing.T, input credentials.BeginSealCredentialBatchInput) credentials.DualWrappedBatchEnvelope {
	t.Helper()
	aad, err := credentials.CanonicalBatchAAD(input.Key.OperationID, input.BatchExternalID,
		input.PoolExternalID, input.AccountRef, input.Type, input.BatchVersion,
		input.MembershipEpoch, input.ContentFingerprint)
	if err != nil {
		t.Fatalf("build credential batch AAD: %v", err)
	}
	aadHash := sha256.Sum256(aad)
	recoveryWrapped := []byte("batch-recovery-wrapped/" + input.BatchExternalID)
	return credentials.DualWrappedBatchEnvelope{
		EncryptionAlgorithm: "AES-256-GCM", Ciphertext: []byte("batch-ciphertext/" + input.BatchExternalID),
		Nonce: []byte("123456789012"), AADHash: aadHash, ContentFingerprint: input.ContentFingerprint,
		KMSWrapAlgorithm: "AES-KWP", KMSKeyRef: "kms://batch-fence/online",
		KMSWrapperDomain: "batch/online/v1", WrappedDEKKMS: []byte("batch-kms-wrapped/" + input.BatchExternalID),
		RecoveryWrapAlgorithm: "AES-KWP", RecoveryKeyRef: "recovery://batch-fence/root",
		RecoveryWrapperDomain: "batch/recovery/v1", WrappedDEKRecovery: recoveryWrapped,
		RecoveryBindingHash: credentials.RecoveryBindingHash("batch/recovery/v1", "AES-KWP",
			"recovery://batch-fence/root", aadHash, recoveryWrapped),
	}
}

func sealCredentialBatchWithoutContention(t *testing.T, ctx context.Context, store *Store,
	input credentials.BeginSealCredentialBatchInput) *credentials.StoredCredentialBatch {
	t.Helper()
	target, created, err := store.BeginSealCredentialBatch(ctx, input)
	if err != nil || !created || target == nil || target.Operation == nil {
		t.Fatalf("begin uncontended credential batch seal: created=%t target=%+v err=%v", created, target, err)
	}
	batch, err := store.CommitSealCredentialBatch(ctx, credentials.CommitSealCredentialBatchInput{
		Key: input.Key, LeaseOwner: input.LeaseOwner,
		FencingToken: target.Operation.FencingToken, Envelope: credentialBatchEnvelope(t, input),
	})
	if err != nil {
		t.Fatalf("commit uncontended credential batch seal: %v", err)
	}
	return batch
}

func raceSameScopeCredentialBatchActivation(t *testing.T, ctx context.Context, storeA, storeB *Store,
	batchA, batchB string) credentialBatchTransitionResult {
	t.Helper()
	inputA := credentialBatchTransitionInput("batch-activate-a", batchA, "ACTIVATE", 2)
	inputB := credentialBatchTransitionInput("batch-activate-b", batchB, "ACTIVATE", 2)
	start := make(chan struct{})
	results := make(chan credentialBatchTransitionResult, 2)
	activate := func(store *Store, input credentials.CredentialBatchTransitionInput) {
		<-start
		batch, _, err := store.ActivateCredentialBatch(ctx, input)
		results <- credentialBatchTransitionResult{input: input, store: store, batch: batch, err: err}
	}
	go activate(storeA, inputA)
	go activate(storeB, inputB)
	close(start)
	resultOne, resultTwo := <-results, <-results

	var winner credentialBatchTransitionResult
	for _, contender := range []credentialBatchTransitionResult{resultOne, resultTwo} {
		if contender.err == nil {
			if winner.batch != nil {
				t.Fatal("both same-scope credential batches became ACTIVE")
			}
			winner = contender
			continue
		}
		if !errors.Is(contender.err, credentials.ErrBatchTargetConflict) {
			t.Fatalf("same-scope activation loser returned %v", contender.err)
		}
	}
	if winner.batch == nil {
		t.Fatal("neither same-scope credential batch became ACTIVE")
	}
	return winner
}

func raceCredentialBatchRetirement(t *testing.T, ctx context.Context, storeA, storeB *Store,
	batchID string) credentialBatchTransitionResult {
	t.Helper()
	inputA := credentialBatchTransitionInput("batch-retire-a", batchID, "RETIRE", 3)
	inputB := credentialBatchTransitionInput("batch-retire-b", batchID, "RETIRE", 3)
	start := make(chan struct{})
	results := make(chan credentialBatchTransitionResult, 2)
	retire := func(store *Store, input credentials.CredentialBatchTransitionInput) {
		<-start
		batch, _, err := store.RetireCredentialBatch(ctx, input)
		results <- credentialBatchTransitionResult{input: input, store: store, batch: batch, err: err}
	}
	go retire(storeA, inputA)
	go retire(storeB, inputB)
	close(start)
	resultOne, resultTwo := <-results, <-results

	var winner credentialBatchTransitionResult
	for _, contender := range []credentialBatchTransitionResult{resultOne, resultTwo} {
		if contender.err == nil {
			if winner.batch != nil {
				t.Fatal("both PostgreSQL workers retired the same credential batch version")
			}
			winner = contender
			continue
		}
		if !errors.Is(contender.err, credentials.ErrBatchInvalidState) {
			t.Fatalf("credential batch retirement loser returned %v", contender.err)
		}
	}
	if winner.batch == nil {
		t.Fatal("neither PostgreSQL worker retired the credential batch")
	}
	return winner
}

func credentialBatchTransitionInput(operationID, batchID, action string,
	expectedVersion int64) credentials.CredentialBatchTransitionInput {
	snapshot, _ := json.Marshal(struct {
		Version               int    `json:"version"`
		OperationID           string `json:"operation_id"`
		BatchID               string `json:"batch_id"`
		Action                string `json:"action"`
		ExpectedRecordVersion int64  `json:"expected_record_version"`
	}{1, operationID, batchID, action, expectedVersion})
	return credentials.CredentialBatchTransitionInput{
		Key:             credentials.BatchOperationKey{ClientID: "batch-fence-client", OperationID: operationID},
		BatchExternalID: batchID, ExpectedVersion: expectedVersion,
		RequestHash: sha256.Sum256(snapshot), RequestSnapshot: snapshot,
	}
}

func expireCredentialBatchLease(t *testing.T, ctx context.Context, db *sql.DB,
	key credentials.BatchOperationKey) {
	t.Helper()
	result, err := db.ExecContext(ctx, `UPDATE integration_operations
SET lease_expires_at=CURRENT_TIMESTAMP-interval '1 second',
    version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE integration_client_id=$1 AND operation_id=$2
  AND lease_expires_at > CURRENT_TIMESTAMP`, key.ClientID, key.OperationID)
	if err != nil {
		t.Fatalf("expire credential batch lease: %v", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		t.Fatalf("expire credential batch lease affected=%d err=%v", affected, affectedErr)
	}
}

func assertCredentialBatchAggregateCounts(t *testing.T, ctx context.Context, db *sql.DB,
	active, sealed, retired, activateTransitions, retireTransitions int) {
	t.Helper()
	var gotActive, gotSealed, gotRetired int
	if err := db.QueryRowContext(ctx, `SELECT
count(*) FILTER (WHERE status = 'ACTIVE'),
count(*) FILTER (WHERE status = 'SEALED'),
count(*) FILTER (WHERE status = 'RETIRED')
FROM credential_batches WHERE resource_account_ref = 'batch-fence-account'`).Scan(
		&gotActive, &gotSealed, &gotRetired); err != nil {
		t.Fatalf("inspect credential batch states: %v", err)
	}
	if gotActive != active || gotSealed != sealed || gotRetired != retired {
		t.Fatalf("credential batch states active=%d sealed=%d retired=%d, want %d/%d/%d",
			gotActive, gotSealed, gotRetired, active, sealed, retired)
	}

	var gotActivate, gotRetire int
	if err := db.QueryRowContext(ctx, `SELECT
count(*) FILTER (WHERE transition_type = 'ACTIVATE'),
count(*) FILTER (WHERE transition_type = 'RETIRE')
FROM credential_batch_transitions`).Scan(&gotActivate, &gotRetire); err != nil {
		t.Fatalf("inspect credential batch transition ledger: %v", err)
	}
	if gotActivate != activateTransitions || gotRetire != retireTransitions {
		t.Fatalf("credential batch transitions activate=%d retire=%d, want %d/%d",
			gotActivate, gotRetire, activateTransitions, retireTransitions)
	}

	var operations, incomplete int
	if err := db.QueryRowContext(ctx, `SELECT count(*),
count(*) FILTER (WHERE status <> 'SUCCEEDED' OR target_id IS NULL OR response_snapshot IS NULL)
FROM integration_operations
WHERE operation_type IN ('ACTIVATE_CREDENTIAL_BATCH', 'RETIRE_CREDENTIAL_BATCH')`).Scan(
		&operations, &incomplete); err != nil {
		t.Fatalf("inspect credential batch operation aggregate: %v", err)
	}
	if operations != activateTransitions+retireTransitions || incomplete != 0 {
		t.Fatalf("credential batch aggregate operations=%d incomplete=%d, want operations=%d incomplete=0",
			operations, incomplete, activateTransitions+retireTransitions)
	}
}
