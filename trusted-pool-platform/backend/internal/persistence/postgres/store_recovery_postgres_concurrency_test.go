package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

// PHASE2H_TEST_POSTGRES_DSN must reference a disposable database where the
// caller can create and remove schemas.
func TestRecoveryPlanAndFinalizationFenceOnTwoRealPostgresConnections(t *testing.T) {
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
	schema := fmt.Sprintf("phase2h_recovery_fence_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create Recovery fence schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	workerA := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer workerA.Close()
	if err := Migrate(ctx, workerA, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for Recovery fence test: %v", err)
	}
	workerB := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer workerB.Close()
	assertRecoveryFenceConnectionsDiffer(t, ctx, workerA, workerB)
	storeA, err := NewStore(workerA)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := NewStore(workerB)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("plan takeover", func(t *testing.T) {
		fixture := insertRecoveryLeaseFixture(t, ctx, workerA, "plan", false)
		winner := raceRecoveryPlanLease(t, ctx, storeA, storeB, fixture)
		if winner.operation.FencingToken != fixture.initialFence+1 {
			t.Fatalf("plan takeover fence=%d, want %d", winner.operation.FencingToken, fixture.initialFence+1)
		}
		input := validRecoveryFenceRootInput(fixture.planKey, fixture.oldOwner, fixture.initialFence)
		if _, err := storeA.CommitRootArtifact(ctx, input); !errors.Is(err, recovery.ErrStaleFence) {
			t.Fatalf("old plan fence advanced the plan: %v", err)
		}
		var status string
		var roots, version int
		if err := workerA.QueryRowContext(ctx, `SELECT plan.status, plan.version,
(SELECT count(*) FROM recovery_root_artifacts root WHERE root.plan_id=plan.id)
FROM recovery_epoch_plans plan WHERE plan.external_id=$1`, fixture.planExternalID).
			Scan(&status, &version, &roots); err != nil {
			t.Fatal(err)
		}
		if status != "PLANNED" || version != 1 || roots != 0 {
			t.Fatalf("stale plan write changed aggregate: status=%s version=%d roots=%d", status, version, roots)
		}
	})

	t.Run("finalization takeover", func(t *testing.T) {
		fixture := insertRecoveryLeaseFixture(t, ctx, workerA, "finalize", true)
		winner := raceRecoveryFinalizationLease(t, ctx, storeA, storeB, fixture)
		if winner.target.Operation.FencingToken != fixture.initialFence+1 {
			t.Fatalf("finalization takeover fence=%d, want %d", winner.target.Operation.FencingToken,
				fixture.initialFence+1)
		}
		_, committed, err := storeA.CommitBootstrapFinalization(ctx, recovery.CommitBootstrapFinalizationInput{
			Key: fixture.finalizationKey, LeaseOwner: fixture.oldOwner, FencingToken: fixture.initialFence,
			ClaimIntents: []recovery.ReplacementClaimIntent{{
				SeatExternalID: "fixture-seat", ClaimOperationID: "stale-claim-operation",
			}},
			ResultSnapshot: []byte(`{"status":"must-not-commit"}`),
		})
		if !errors.Is(err, recovery.ErrStaleFence) || committed {
			t.Fatalf("old finalization fence result: committed=%t err=%v", committed, err)
		}
		var planStatus, caseStatus, operationStatus, leaseOwner string
		var membershipEpoch, epochFloor, claims int
		var fence int64
		if err := workerA.QueryRowContext(ctx, `SELECT plan.status, replacement.status,
pool.membership_epoch, pool.credential_epoch_floor, operation.status,
COALESCE(operation.lease_owner,''), operation.fencing_token,
(SELECT count(*) FROM credential_claims)
FROM recovery_epoch_plans plan
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
JOIN integration_operations operation ON operation.id=replacement.integration_operation_id
JOIN pools pool ON pool.id=plan.pool_id
WHERE plan.external_id=$1`, fixture.planExternalID).Scan(&planStatus, &caseStatus,
			&membershipEpoch, &epochFloor, &operationStatus, &leaseOwner, &fence, &claims); err != nil {
			t.Fatal(err)
		}
		if planStatus != "READY" || caseStatus != "READY" || membershipEpoch != 1 || epochFloor != 1 ||
			operationStatus != "RUNNING" || leaseOwner != winner.owner || fence != fixture.initialFence+1 || claims != 0 {
			t.Fatalf("stale finalization changed aggregate: plan=%s case=%s epochs=%d/%d op=%s lease=%s/%d claims=%d",
				planStatus, caseStatus, membershipEpoch, epochFloor, operationStatus, leaseOwner, fence, claims)
		}
	})
}

type recoveryLeaseFixture struct {
	planKey, finalizationKey recovery.OperationKey
	planExternalID           string
	oldOwner                 string
	initialFence             int64
}

type planLeaseRaceResult struct {
	owner     string
	operation *recovery.StoredOperation
	err       error
}

func raceRecoveryPlanLease(t *testing.T, ctx context.Context, storeA, storeB *Store,
	fixture recoveryLeaseFixture) planLeaseRaceResult {
	t.Helper()
	start := make(chan struct{})
	results := make(chan planLeaseRaceResult, 2)
	run := func(owner string, store *Store) {
		<-start
		op, err := store.AcquireEpochPlanLease(ctx, recovery.AcquireEpochPlanLeaseInput{
			Key: fixture.planKey, LeaseOwner: owner, ExpectedFencingToken: fixture.initialFence,
			LeaseDuration: 30 * time.Second,
		})
		results <- planLeaseRaceResult{owner: owner, operation: op, err: err}
	}
	go run("plan-worker-a", storeA)
	go run("plan-worker-b", storeB)
	close(start)
	first, second := <-results, <-results
	var winner planLeaseRaceResult
	for _, result := range []planLeaseRaceResult{first, second} {
		if result.err == nil {
			if winner.operation != nil {
				t.Fatal("both workers acquired the expired plan lease")
			}
			winner = result
		} else if !errors.Is(result.err, recovery.ErrStaleFence) {
			t.Fatalf("plan contender %s: %v", result.owner, result.err)
		}
	}
	if winner.operation == nil {
		t.Fatal("no worker acquired the expired plan lease")
	}
	return winner
}

type finalizationLeaseRaceResult struct {
	owner  string
	target *recovery.PermanentReplacementTarget
	err    error
}

func raceRecoveryFinalizationLease(t *testing.T, ctx context.Context, storeA, storeB *Store,
	fixture recoveryLeaseFixture) finalizationLeaseRaceResult {
	t.Helper()
	start := make(chan struct{})
	results := make(chan finalizationLeaseRaceResult, 2)
	run := func(owner string, store *Store) {
		<-start
		target, err := store.AcquireNextPermanentReplacementLease(ctx,
			recovery.AcquireNextPermanentReplacementLeaseInput{LeaseOwner: owner, LeaseDuration: 30 * time.Second})
		results <- finalizationLeaseRaceResult{owner: owner, target: target, err: err}
	}
	go run("finalize-worker-a", storeA)
	go run("finalize-worker-b", storeB)
	close(start)
	first, second := <-results, <-results
	var winner finalizationLeaseRaceResult
	for _, result := range []finalizationLeaseRaceResult{first, second} {
		if result.err == nil {
			if winner.target != nil {
				t.Fatal("both workers acquired the expired finalization lease")
			}
			winner = result
		} else if !errors.Is(result.err, recovery.ErrNotFound) {
			t.Fatalf("finalization contender %s: %v", result.owner, result.err)
		}
	}
	if winner.target == nil || winner.target.Operation == nil || winner.target.Operation.Key != fixture.finalizationKey {
		t.Fatalf("unexpected finalization winner: %+v", winner.target)
	}
	return winner
}

func validRecoveryFenceRootInput(key recovery.OperationKey, owner string, fence int64) recovery.RootArtifactInput {
	vssCommitment := []byte("recovery-fence-vss-commitment")
	vssProof := []byte("recovery-fence-vss-proof")
	privateCommitment := []byte("recovery-fence-private-commitment")
	return recovery.RootArtifactInput{
		Key: key, LeaseOwner: owner, FencingToken: fence, ExternalID: "stale-root-artifact",
		Provider: "recovery-fence-provider", ProviderKeyRef: "provider-key-ref",
		RootHandle: "root-handle", RootKeyVersion: "root-key-version",
		EpochRecoveryAlgorithm: "X25519", EpochRecoveryKeyID: "epoch-recovery-key",
		EpochRecoveryKeyFingerprint: sha256.Sum256([]byte("epoch-recovery-key")),
		WrapDomain:                  "recovery-fence-wrap", WrapAlgorithm: "AES-256-GCM", VSSAlgorithm: "FROST-v1",
		VSSCommitment: vssCommitment, VSSCommitmentHash: sha256.Sum256(vssCommitment),
		VSSProof: vssProof, VSSProofHash: sha256.Sum256(vssProof),
		PrivateKeyCommitment:     privateCommitment,
		PrivateKeyCommitmentHash: sha256.Sum256(privateCommitment),
		RootCommitmentHash:       sha256.Sum256([]byte("root-commitment")),
		RecoveryPackageHash:      sha256.Sum256([]byte("recovery-package")),
		RequestIntentHash:        sha256.Sum256([]byte("request-intent")),
		ProviderAttestationRef:   "provider-attestation", AttestationDigest: sha256.Sum256([]byte("attestation")),
		AttestationSignature: []byte("provider-signature"), AttestationKeyID: "provider-key",
		PortableAttestationAlgorithm: "Ed25519", PortableAttestationIssuer: "recovery-fence-provider",
		PortableAttestationKeyID:           "portable-provider-key",
		PortableAttestationProtocolVersion: "trusted-pool/provider-proof-statement/v1",
		PortableAttestationSignature:       make([]byte, 64),
	}
}

func openRecoveryFenceConnection(t *testing.T, ctx context.Context, dsn, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open Recovery PostgreSQL schema connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		_ = db.Close()
		t.Fatalf("select Recovery PostgreSQL schema: %v", err)
	}
	return db
}

func assertRecoveryFenceConnectionsDiffer(t *testing.T, ctx context.Context, workerA, workerB *sql.DB) {
	t.Helper()
	var pidA, pidB int
	if err := workerA.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidA); err != nil {
		t.Fatal(err)
	}
	if err := workerB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidB); err != nil {
		t.Fatal(err)
	}
	if pidA == pidB {
		t.Fatalf("expected independent PostgreSQL connections, both used backend %d", pidA)
	}
}

// The fixture bypasses domain triggers only while inserting a minimal already-existing
// aggregate. The lease takeover and every assertion under test run with all triggers enabled.
func insertRecoveryLeaseFixture(t *testing.T, ctx context.Context, db *sql.DB, suffix string,
	readyForFinalization bool) recoveryLeaseFixture {
	t.Helper()
	fixture := recoveryLeaseFixture{
		planKey:        recovery.OperationKey{ClientID: "recovery-fence-client", OperationID: "plan-op-" + suffix},
		planExternalID: "recovery-plan-" + suffix, oldOwner: "expired-worker-" + suffix, initialFence: 7,
	}
	fixture.finalizationKey = recovery.OperationKey{
		ClientID: fixture.planKey.ClientID, OperationID: "finalization-op-" + suffix,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{
		"integration_operations", "membership_epochs", "recovery_epoch_plans", "permanent_replacement_cases",
	} {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
			t.Fatalf("disable %s fixture triggers: %v", table, err)
		}
	}

	poolExternalID := "recovery-pool-" + suffix
	var poolID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, credential_epoch_floor
) VALUES ($1, $2, 'ACTIVE', 2, 1, 1) RETURNING id`, poolExternalID,
		"Recovery Fence Pool "+suffix).Scan(&poolID); err != nil {
		t.Fatalf("insert Recovery fixture Pool: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold, recovery_governance_state, activated_at
) VALUES ($1, 1, 'ACTIVE', 1, 1, 'LEGACY_UNVERIFIED', CURRENT_TIMESTAMP),
         ($1, 2, 'PREPARING', 1, 1, 'LEGACY_UNVERIFIED', NULL)`, poolID); err != nil {
		t.Fatalf("insert Recovery fixture Epochs: %v", err)
	}

	var planOperationID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count
) VALUES ($1, $2, 'BOOTSTRAP_RECOVERY_EPOCH', 'POOL', $3, $4, 'CURRENT',
decode(repeat('41',32),'hex'), jsonb_build_object('fixture',$5::text), 'RUNNING', $6, $7,
CURRENT_TIMESTAMP - interval '1 second', 1) RETURNING id`, fixture.planKey.ClientID,
		fixture.planKey.OperationID, poolID, poolExternalID, suffix, fixture.initialFence,
		fixture.oldOwner).Scan(&planOperationID); err != nil {
		t.Fatalf("insert Recovery fixture plan operation: %v", err)
	}
	status := "PLANNED"
	readyAt := any(nil)
	if readyForFinalization {
		status = "READY"
		readyAt = time.Now().UTC()
	}
	var planID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO recovery_epoch_plans (
external_id, integration_operation_id, ceremony_type, pool_id, from_epoch, to_epoch, status,
governance_threshold, recovery_threshold, required_share_ack_count,
expected_member_count, expected_seat_count, expected_resource_count, expected_control_batch_count,
provider_attestation_set_hash, previous_manifest_hash, from_epoch_status, from_governance_state,
bootstrap_attestation_ref, bootstrap_attestation_digest, bootstrap_attestation_issuer,
bootstrap_attestation_key_id, bootstrap_attestation_signature, bootstrap_attestation_version,
ready_at, version
) VALUES ($1, $2, 'BOOTSTRAP', $3, 1, 2, $4, 1, 1, 1, 1, 1, 1, 4,
decode(repeat('42',32),'hex'), decode(repeat('00',32),'hex'), 'ACTIVE', 'LEGACY_UNVERIFIED',
$5, decode(repeat('43',32),'hex'), 'test-issuer', 'test-key', decode('44','hex'), 1, $6, 1)
RETURNING id`, fixture.planExternalID, planOperationID, poolID, status,
		"bootstrap-attestation-"+suffix, readyAt).Scan(&planID); err != nil {
		t.Fatalf("insert Recovery fixture plan: %v", err)
	}

	if readyForFinalization {
		var finalizationOperationID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count
) VALUES ($1, $2, 'FINALIZE_RECOVERY_BOOTSTRAP', 'POOL', $3, $4, 'CURRENT',
decode(repeat('51',32),'hex'), jsonb_build_object('fixture',$5::text), 'RUNNING', $6, $7,
CURRENT_TIMESTAMP - interval '1 second', 1) RETURNING id`, fixture.finalizationKey.ClientID,
			fixture.finalizationKey.OperationID, poolID, poolExternalID, suffix,
			fixture.initialFence, fixture.oldOwner).Scan(&finalizationOperationID); err != nil {
			t.Fatalf("insert Recovery fixture finalization operation: %v", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO permanent_replacement_cases (
external_id, integration_operation_id, plan_id, status, version
) VALUES ($1, $2, $3, 'READY', 1)`, "recovery-case-"+suffix, finalizationOperationID, planID); err != nil {
			t.Fatalf("insert Recovery fixture finalization case: %v", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		t.Fatalf("flush Recovery fixture deferred constraints: %v", err)
	}
	for _, table := range []string{
		"permanent_replacement_cases", "recovery_epoch_plans", "membership_epochs", "integration_operations",
	} {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` ENABLE TRIGGER USER`); err != nil {
			t.Fatalf("enable %s fixture triggers: %v", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit Recovery lease fixture: %v", err)
	}
	return fixture
}
