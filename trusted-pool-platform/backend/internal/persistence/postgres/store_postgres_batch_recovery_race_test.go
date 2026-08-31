package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/recovery"

	"github.com/lib/pq"
)

const (
	crossPoolExternalID = "batch-recovery-race-pool"
	crossPlanExternalID = "batch-recovery-race-plan"
	crossSeatExternalID = "batch-recovery-race-seat"
	crossFinalClientID  = "batch-recovery-race-client"
	crossFinalOperation = "batch-recovery-race-finalize"
	crossFinalOwner     = "batch-recovery-finalizer"
	crossFinalFence     = int64(11)
	crossSourceVersion  = int64(3)
	crossBatchCount     = 4
)

func TestCredentialBatchAndRecoveryFinalizationSerializeOnSamePool(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	for _, test := range []struct {
		name       string
		finalFirst bool
	}{
		{name: "finalization wins the Pool lock", finalFirst: true},
		{name: "batch retirement makes finalization fail closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runBatchRecoveryRace(t, dsn, test.finalFirst)
		})
	}
}

type crossFinalResult struct {
	committed bool
	err       error
}

type crossBatchResult struct {
	batch *credentials.StoredCredentialBatch
	err   error
}

func runBatchRecoveryRace(t *testing.T, dsn string, finalFirst bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_batch_recovery_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create Batch/Recovery race schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	finalDB := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer finalDB.Close()
	if err := Migrate(ctx, finalDB, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for Batch/Recovery race: %v", err)
	}
	batchDB := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer batchDB.Close()
	gateDB := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer gateDB.Close()
	observerDB := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer observerDB.Close()
	assertRecoveryFenceConnectionsDiffer(t, ctx, finalDB, batchDB)
	insertBatchRecoveryRaceFixture(t, ctx, finalDB)
	assertReadyRecoveryPlanDoesNotConsumeFreeze(t, ctx, observerDB)

	finalStore, err := NewStore(finalDB)
	if err != nil {
		t.Fatal(err)
	}
	batchStore, err := NewStore(batchDB)
	if err != nil {
		t.Fatal(err)
	}
	var finalPID, batchPID int
	if err := finalDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&finalPID); err != nil {
		t.Fatal(err)
	}
	if err := batchDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&batchPID); err != nil {
		t.Fatal(err)
	}

	gate, err := gateDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	var lockedBatchID string
	if err := gate.QueryRowContext(ctx, `SELECT id FROM credential_batches
WHERE external_id='batch-recovery-from-login' FOR UPDATE`).Scan(&lockedBatchID); err != nil {
		t.Fatalf("lock source Batch race gate: %v", err)
	}

	finalResults := make(chan crossFinalResult, 1)
	batchResults := make(chan crossBatchResult, 1)
	runFinal := func() {
		_, committed, commitErr := finalStore.CommitBootstrapFinalization(ctx,
			recovery.CommitBootstrapFinalizationInput{
				Key:        recovery.OperationKey{ClientID: crossFinalClientID, OperationID: crossFinalOperation},
				LeaseOwner: crossFinalOwner, FencingToken: crossFinalFence,
				ClaimIntents: []recovery.ReplacementClaimIntent{{
					SeatExternalID: crossSeatExternalID, ClaimOperationID: "batch-recovery-race-claim",
				}},
				ResultSnapshot: []byte(`{"status":"structural-committed"}`),
			})
		finalResults <- crossFinalResult{committed: committed, err: commitErr}
	}
	retireInput := credentialBatchTransitionInput("batch-recovery-race-retire",
		"batch-recovery-from-login", "RETIRE", crossSourceVersion)
	runBatch := func() {
		batch, _, retireErr := batchStore.RetireCredentialBatch(ctx, retireInput)
		batchResults <- crossBatchResult{batch: batch, err: retireErr}
	}

	if finalFirst {
		go runFinal()
		waitForBackendBlocked(t, ctx, observerDB, finalPID)
		go runBatch()
		waitForBackendBlocked(t, ctx, observerDB, batchPID)
	} else {
		go runBatch()
		waitForBackendBlocked(t, ctx, observerDB, batchPID)
		go runFinal()
		waitForBackendBlocked(t, ctx, observerDB, finalPID)
	}
	if err := gate.Commit(); err != nil {
		t.Fatalf("release source Batch race gate: %v", err)
	}
	finalResult, batchResult := <-finalResults, <-batchResults
	assertNoDeadlockOrTimeout(t, finalResult.err)
	assertNoDeadlockOrTimeout(t, batchResult.err)

	if finalFirst {
		if finalResult.err != nil || !finalResult.committed {
			t.Fatalf("first finalization did not commit: committed=%t err=%v",
				finalResult.committed, finalResult.err)
		}
		if !errors.Is(batchResult.err, credentials.ErrBatchInvalidState) || batchResult.batch != nil {
			t.Fatalf("Batch loser was not rejected: batch=%+v err=%v", batchResult.batch, batchResult.err)
		}
		assertFinalizationWonRace(t, ctx, observerDB)
		return
	}
	if batchResult.err != nil || batchResult.batch == nil ||
		batchResult.batch.State != credentials.BatchRetired ||
		batchResult.batch.Version != crossSourceVersion+1 {
		t.Fatalf("first Batch retirement did not commit: batch=%+v err=%v", batchResult.batch, batchResult.err)
	}
	if finalResult.committed || !isFailClosedFinalizationError(finalResult.err) {
		t.Fatalf("finalization did not fail closed: committed=%t err=%v",
			finalResult.committed, finalResult.err)
	}
	assertBatchWonRace(t, ctx, observerDB)
}

func assertReadyRecoveryPlanDoesNotConsumeFreeze(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var authorizedPlanID string
	if err := tx.QueryRowContext(ctx, `SELECT set_config('trusted_pool.recovery_inventory_plan_id',
id::text,true) FROM recovery_epoch_plans WHERE external_id=$1`, crossPlanExternalID).
		Scan(&authorizedPlanID); err != nil || authorizedPlanID == "" {
		t.Fatalf("authorize test-only structural Seat move: id=%q err=%v", authorizedPlanID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE seats SET status='ACTIVE',
owner_member_id=(SELECT id FROM members WHERE external_id='batch-recovery-target-member'),
assignment_epoch=2, active_api_key_version=2, frozen_at=NULL, version=version+1
WHERE external_id=$1`, crossSeatExternalID); err != nil {
		t.Fatalf("stage premature Seat move: %v", err)
	}
	_, err = tx.ExecContext(ctx, `SELECT assert_suspend_aggregate($1)`,
		"20000000-0000-0000-0000-000000000009")
	if err == nil || !strings.Contains(err.Error(), "SUSPEND case assignment epoch does not match Seat") {
		t.Fatalf("READY Recovery plan consumed its freeze before finalization: %v", err)
	}
}

func waitForBackendBlocked(t *testing.T, ctx context.Context, db *sql.DB, pid int) {
	t.Helper()
	for {
		var blocked bool
		if err := db.QueryRowContext(ctx,
			`SELECT COALESCE(cardinality(pg_blocking_pids($1)),0)>0`, pid).Scan(&blocked); err != nil {
			t.Fatalf("inspect blocker for backend %d: %v", pid, err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d never reached controlled lock boundary: %v", pid, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func assertNoDeadlockOrTimeout(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("cross-workflow contender timed out: %v", err)
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && (pqErr.Code == "40P01" || pqErr.Code == "57014") {
		t.Fatalf("cross-workflow contender hit PostgreSQL %s: %v", pqErr.Code, err)
	}
}

func isFailClosedFinalizationError(err error) bool {
	if errors.Is(err, recovery.ErrInvalidState) {
		return true
	}
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "40001"
}

func assertFinalizationWonRace(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var plan, replacement, final, ceremony, fromEpoch, toEpoch, finalOwner string
	var epoch, floor, fromRetired, toActive, claims, loserOps int
	var finalFence, finalVersion int64
	err := db.QueryRowContext(ctx, `SELECT plan.status,replacement.status,finalization.status,
ceremony.status,pool.membership_epoch,pool.credential_epoch_floor,
(SELECT status FROM membership_epochs WHERE pool_id=pool.id AND epoch=1),
(SELECT status FROM membership_epochs WHERE pool_id=pool.id AND epoch=2),
(SELECT count(*) FROM recovery_plan_batch_bindings b JOIN credential_batches c
 ON c.id=b.credential_batch_id WHERE b.plan_id=plan.id AND b.epoch_role='FROM' AND c.status='RETIRED'),
(SELECT count(*) FROM recovery_plan_batch_bindings b JOIN credential_batches c
 ON c.id=b.credential_batch_id WHERE b.plan_id=plan.id AND b.epoch_role='TO' AND c.status='ACTIVE'),
(SELECT count(*) FROM credential_claims WHERE status='ISSUANCE_PENDING'),
(SELECT count(*) FROM integration_operations WHERE operation_id='batch-recovery-race-retire'),
finalization.fencing_token,finalization.lease_owner,finalization.version
FROM recovery_epoch_plans plan
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
JOIN integration_operations finalization ON finalization.id=replacement.integration_operation_id
JOIN integration_operations ceremony ON ceremony.id=plan.integration_operation_id
JOIN pools pool ON pool.id=plan.pool_id WHERE plan.external_id=$1`, crossPlanExternalID).
		Scan(&plan, &replacement, &final, &ceremony, &epoch, &floor, &fromEpoch, &toEpoch,
			&fromRetired, &toActive, &claims, &loserOps, &finalFence, &finalOwner, &finalVersion)
	if err != nil {
		t.Fatal(err)
	}
	if plan != "FINALIZED" || replacement != "PROVIDER_COMMIT_PENDING" || final != "RUNNING" ||
		ceremony != "SUCCEEDED" || epoch != 2 || floor != 2 || fromEpoch != "RETIRED" ||
		toEpoch != "ACTIVE" || fromRetired != crossBatchCount || toActive != crossBatchCount ||
		claims != 1 || loserOps != 0 || finalFence != crossFinalFence ||
		finalOwner != crossFinalOwner || finalVersion != 2 {
		t.Fatalf("inconsistent finalization winner: plan=%s case=%s final=%s ceremony=%s "+
			"epoch=%d/%d states=%s/%s batches=%d/%d claims=%d loser_ops=%d final_fence=%d/%s/v%d",
			plan, replacement, final, ceremony, epoch, floor, fromEpoch, toEpoch,
			fromRetired, toActive, claims, loserOps, finalFence, finalOwner, finalVersion)
	}
}

func assertBatchWonRace(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var plan, replacement, final, ceremony, seat, evidence, manifest, fromEpoch, toEpoch, finalOwner string
	var epoch, floor, fromActive, fromRetired, toStaged, claims, retires, batchOps int
	var finalFence, finalVersion int64
	err := db.QueryRowContext(ctx, `SELECT plan.status,replacement.status,finalization.status,
ceremony.status,seat.status,evidence.status,manifest.status,pool.membership_epoch,pool.credential_epoch_floor,
(SELECT status FROM membership_epochs WHERE pool_id=pool.id AND epoch=1),
(SELECT status FROM membership_epochs WHERE pool_id=pool.id AND epoch=2),
(SELECT count(*) FROM recovery_plan_batch_bindings b JOIN credential_batches c
 ON c.id=b.credential_batch_id WHERE b.plan_id=plan.id AND b.epoch_role='FROM' AND c.status='ACTIVE'),
(SELECT count(*) FROM recovery_plan_batch_bindings b JOIN credential_batches c
 ON c.id=b.credential_batch_id WHERE b.plan_id=plan.id AND b.epoch_role='FROM' AND c.status='RETIRED'),
(SELECT count(*) FROM recovery_plan_batch_bindings b JOIN credential_batches c
 ON c.id=b.credential_batch_id WHERE b.plan_id=plan.id AND b.epoch_role='TO' AND c.status='STAGED'),
(SELECT count(*) FROM credential_claims),
(SELECT count(*) FROM credential_batch_transitions WHERE transition_type='RETIRE'),
(SELECT count(*) FROM integration_operations WHERE operation_id='batch-recovery-race-retire'
 AND status='SUCCEEDED'),finalization.fencing_token,finalization.lease_owner,finalization.version
FROM recovery_epoch_plans plan
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
JOIN integration_operations finalization ON finalization.id=replacement.integration_operation_id
JOIN integration_operations ceremony ON ceremony.id=plan.integration_operation_id
JOIN recovery_plan_seats planned ON planned.plan_id=plan.id JOIN seats seat ON seat.id=planned.seat_id
JOIN recovery_control_evidence evidence ON evidence.plan_id=plan.id
JOIN manifests manifest ON manifest.recovery_plan_id=plan.id
JOIN pools pool ON pool.id=plan.pool_id WHERE plan.external_id=$1`, crossPlanExternalID).
		Scan(&plan, &replacement, &final, &ceremony, &seat, &evidence, &manifest, &epoch, &floor,
			&fromEpoch, &toEpoch, &fromActive, &fromRetired, &toStaged, &claims, &retires,
			&batchOps, &finalFence, &finalOwner, &finalVersion)
	if err != nil {
		t.Fatal(err)
	}
	if plan != "READY" || replacement != "READY_TO_COMMIT" || final != "RUNNING" ||
		ceremony != "RUNNING" || seat != "FROZEN" || evidence != "VERIFIED" || manifest != "DRAFT" ||
		epoch != 1 || floor != 1 || fromActive != crossBatchCount-1 || fromRetired != 1 ||
		fromEpoch != "ACTIVE" || toEpoch != "PREPARING" || toStaged != crossBatchCount ||
		claims != 0 || retires != 1 || batchOps != 1 || finalFence != crossFinalFence ||
		finalOwner != crossFinalOwner || finalVersion != 1 {
		t.Fatalf("partial Recovery aggregate after Batch winner: plan=%s case=%s final=%s "+
			"ceremony=%s seat=%s evidence=%s manifest=%s epoch=%d/%d states=%s/%s "+
			"batches=%d/%d/%d claims=%d retires=%d batch_ops=%d final_fence=%d/%s/v%d",
			plan, replacement, final, ceremony, seat, evidence, manifest, epoch, floor,
			fromEpoch, toEpoch, fromActive, fromRetired, toStaged, claims, retires, batchOps,
			finalFence, finalOwner, finalVersion)
	}
}

func insertBatchRecoveryRaceFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tables := []string{
		"integration_operations", "pools", "members", "seats", "seat_assignments", "suspension_cases",
		"membership_epochs", "membership_epoch_members", "pool_resource_accounts",
		"pool_resource_account_seats", "recovery_epoch_plans", "recovery_plan_seats",
		"recovery_plan_resource_accounts", "recovery_plan_account_seats", "recovery_root_artifacts",
		"manifests", "credential_batches", "credential_batch_transitions",
		"recovery_plan_batch_bindings", "recovery_control_evidence", "recovery_seat_rotation_progress",
		"permanent_replacement_cases", "recovery_pool_preparation_attempts",
		"recovery_pool_activation_attempts", "recovery_pool_activation_seats",
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
			t.Fatalf("disable %s fixture triggers: %v", table, err)
		}
	}
	fixture, err := os.ReadFile("testdata/batch_recovery_race_fixture.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatalf("insert Batch/Recovery fixture: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		t.Fatalf("flush fixture constraints: %v", err)
	}
	for index := len(tables) - 1; index >= 0; index-- {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+tables[index]+` ENABLE TRIGGER USER`); err != nil {
			t.Fatalf("enable %s fixture triggers: %v", tables[index], err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit Batch/Recovery fixture: %v", err)
	}
}
