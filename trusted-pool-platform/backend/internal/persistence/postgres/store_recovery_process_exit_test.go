package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"

	_ "github.com/lib/pq"
)

const (
	recoveryProcessHelperMode   = "PHASE2H_RECOVERY_PROCESS_HELPER"
	recoveryProcessHelperDSN    = "PHASE2H_RECOVERY_PROCESS_DSN"
	recoveryProcessHelperSchema = "PHASE2H_RECOVERY_PROCESS_SCHEMA"
	recoveryProcessHelperNonce  = "PHASE2H_RECOVERY_PROCESS_NONCE"
	recoveryProcessExitCode     = 73
)

func TestRecoveryFinalizationFenceSurvivesProcessExit(t *testing.T) {
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
	schema := fmt.Sprintf("phase2h_recovery_process_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create Recovery process schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	worker := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer worker.Close()
	if err := Migrate(ctx, worker, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for Recovery process test: %v", err)
	}
	fixture := insertRecoveryLeaseFixture(t, ctx, worker, "process-exit", true)

	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryFinalizationLeaseProcessHelper$", "-test.v")
	helperNonce := schema + ":" + strconv.Itoa(os.Getpid())
	command.Env = append(os.Environ(), recoveryProcessHelperMode+"=1", recoveryProcessHelperDSN+"="+dsn,
		recoveryProcessHelperSchema+"="+schema, recoveryProcessHelperNonce+"="+helperNonce)
	output, commandErr := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(commandErr, &exitErr) || exitErr.ExitCode() != recoveryProcessExitCode {
		t.Fatalf("helper process did not exit at the durable boundary: err=%v output=%s", commandErr, output)
	}

	childOwner := "process-worker-before-exit"
	var status, persistedOwner string
	var childFence int64
	if err := worker.QueryRowContext(ctx, `SELECT status, COALESCE(lease_owner,''), fencing_token
FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, fixture.finalizationKey.ClientID,
		fixture.finalizationKey.OperationID).Scan(&status, &persistedOwner, &childFence); err != nil {
		t.Fatalf("inspect lease persisted by exited process: %v", err)
	}
	if status != "RUNNING" || persistedOwner != childOwner || childFence != fixture.initialFence+1 {
		t.Fatalf("unexpected durable process boundary: status=%s owner=%s fence=%d", status, persistedOwner, childFence)
	}
	waitForRecoveryFinalizationLeaseExpiry(t, ctx, worker, fixture.finalizationKey)

	restarted, err := NewStore(worker)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.AcquireNextPermanentReplacementLease(ctx,
		recovery.AcquireNextPermanentReplacementLeaseInput{LeaseOwner: "process-worker-after-restart",
			LeaseDuration: 30 * time.Second})
	if err != nil {
		t.Fatalf("take over finalization after process exit: %v", err)
	}
	if resumed == nil || resumed.Operation == nil || resumed.Operation.Key != fixture.finalizationKey ||
		resumed.Operation.FencingToken != childFence+1 || resumed.Operation.LeaseOwner != "process-worker-after-restart" {
		t.Fatalf("unexpected process-exit takeover: %+v", resumed)
	}

	_, committed, err := restarted.CommitBootstrapFinalization(ctx, recovery.CommitBootstrapFinalizationInput{
		Key: fixture.finalizationKey, LeaseOwner: childOwner, FencingToken: childFence,
		ClaimIntents: []recovery.ReplacementClaimIntent{{SeatExternalID: "fixture-seat",
			ClaimOperationID: "process-exit-stale-claim"}}, ResultSnapshot: []byte(`{"status":"must-not-commit"}`),
	})
	if !errors.Is(err, recovery.ErrStaleFence) || committed {
		t.Fatalf("exited process fence advanced finalization: committed=%t err=%v", committed, err)
	}
	var planStatus, caseStatus, operationStatus, leaseOwner string
	var claims, membershipEpoch, credentialEpochFloor int
	var fence int64
	var leaseActive bool
	if err := worker.QueryRowContext(ctx, `SELECT plan.status, replacement.status,
operation.status, COALESCE(operation.lease_owner,''), operation.fencing_token,
operation.lease_expires_at > CURRENT_TIMESTAMP, pool.membership_epoch, pool.credential_epoch_floor,
(SELECT count(*) FROM credential_claims)
FROM recovery_epoch_plans plan
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
JOIN integration_operations operation ON operation.id=replacement.integration_operation_id
JOIN pools pool ON pool.id=plan.pool_id
WHERE plan.external_id=$1`, fixture.planExternalID).Scan(&planStatus, &caseStatus, &operationStatus,
		&leaseOwner, &fence, &leaseActive, &membershipEpoch, &credentialEpochFloor, &claims); err != nil {
		t.Fatal(err)
	}
	if planStatus != "READY" || caseStatus != "READY" || operationStatus != "RUNNING" ||
		leaseOwner != "process-worker-after-restart" || fence != childFence+1 || !leaseActive ||
		membershipEpoch != 1 || credentialEpochFloor != 1 || claims != 0 {
		t.Fatalf("stale process changed finalization aggregate: plan=%s case=%s operation=%s lease=%s/%d active=%t epochs=%d/%d claims=%d",
			planStatus, caseStatus, operationStatus, leaseOwner, fence, leaseActive,
			membershipEpoch, credentialEpochFloor, claims)
	}
}

func TestRecoveryFinalizationLeaseProcessHelper(t *testing.T) {
	if os.Getenv(recoveryProcessHelperMode) != "1" {
		t.Skip("subprocess helper")
	}
	dsn := strings.TrimSpace(os.Getenv(recoveryProcessHelperDSN))
	schema := strings.TrimSpace(os.Getenv(recoveryProcessHelperSchema))
	nonce := strings.TrimSpace(os.Getenv(recoveryProcessHelperNonce))
	if dsn == "" || schema == "" || nonce != schema+":"+strconv.Itoa(os.Getppid()) {
		t.Fatal("subprocess helper configuration is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.AcquireNextPermanentReplacementLease(ctx,
		recovery.AcquireNextPermanentReplacementLeaseInput{LeaseOwner: "process-worker-before-exit",
			LeaseDuration: 2 * time.Second})
	if err != nil {
		t.Fatalf("subprocess acquire finalization lease: %v", err)
	}
	if target == nil || target.Operation == nil || target.Operation.FencingToken == 0 {
		t.Fatalf("subprocess acquired invalid finalization target: %+v", target)
	}
	var leaseActive bool
	if err := db.QueryRowContext(ctx, `SELECT lease_expires_at > CURRENT_TIMESTAMP
FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, target.Operation.Key.ClientID,
		target.Operation.Key.OperationID).Scan(&leaseActive); err != nil || !leaseActive {
		t.Fatalf("subprocess did not hold an active durable lease before exit: active=%t err=%v", leaseActive, err)
	}
	os.Exit(recoveryProcessExitCode)
}

func waitForRecoveryFinalizationLeaseExpiry(t *testing.T, ctx context.Context, db *sql.DB,
	key recovery.OperationKey) {
	t.Helper()
	for {
		var expired bool
		if err := db.QueryRowContext(ctx, `SELECT lease_expires_at <= CURRENT_TIMESTAMP
FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, key.ClientID, key.OperationID).Scan(&expired); err != nil {
			t.Fatalf("inspect Recovery finalization lease expiry: %v", err)
		}
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for Recovery finalization lease expiry: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
