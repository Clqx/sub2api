package postgres

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/domain"
)

func TestBeginSuspendAtomicallyPersistsCaseSeatAndInitialFence(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	operation := suspendOperationRow(hash[:], "RUNNING", 0, nil, nil, now)
	leasedOperation := suspendOperationRow(hash[:], "RUNNING", 1, "worker-1", now.Add(time.Minute), now)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT id FROM seats", "external_id = $1"}, columns: []string{"id"},
			rows: [][]driver.Value{{"11111111-1111-1111-1111-111111111111"}}},
		{kind: "query", contains: []string{"INSERT INTO integration_operations", "'SUSPEND'", "target_id", "request_snapshot"},
			columns: operationColumnNames(), rows: [][]driver.Value{operation}},
		{kind: "query", contains: []string{"SELECT p.id", "FOR UPDATE OF p"}, columns: []string{"pool_id"},
			rows: [][]driver.Value{{"22222222-2222-2222-2222-222222222222"}}},
		{kind: "query", contains: []string{"FROM seats s", "FOR UPDATE OF s", "assignment.status = 'ACTIVE'"},
			columns: suspendSeatColumnNames(), rows: [][]driver.Value{suspendSeatRow("ACTIVE", now)}},
		{kind: "exec", contains: []string{"status = 'SUSPEND_PENDING'", "status = 'ACTIVE'", "assignment_epoch = $3"}, affected: 1},
		{kind: "exec", contains: []string{"INSERT INTO suspension_cases", "reason_code", "requested_by"}, affected: 1},
		{kind: "query", contains: []string{"fencing_token = fencing_token + 1", "lease_expires_at <= CURRENT_TIMESTAMP", "operation_type = 'SUSPEND'"},
			columns: operationColumnNames(), rows: [][]driver.Value{leasedOperation}},
		{kind: "query", contains: []string{"FROM suspension_cases sc", "sc.migration_state = 'CURRENT'"},
			columns: suspendCaseTargetColumnNames(), rows: [][]driver.Value{suspendCaseTargetRow("SUSPEND_PENDING", nil, nil, nil, now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	target, created, err := store.BeginSuspend(context.Background(), application.BeginSuspendInput{
		Key:            application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		SeatExternalID: "seat-1", RequestHash: hash,
		RequestSnapshot: []byte(`{"version":1,"operation_id":"op-1","seat_id":"seat-1","pool_id":"pool-1","current_member_id":"member-1","assignment_epoch":3,"reason_code":"MANUAL_POLICY_BREACH","reason_detail":"operator requested suspension"}`),
		ReasonCode:      application.SuspendReasonManualPolicyBreach,
		LeaseOwner:      "worker-1", LeaseDuration: time.Minute,
	})
	if err != nil || !created || target.Operation.FencingToken != 1 ||
		target.Case.Status != application.SuspendCasePending || target.Seat.Status != domain.SeatSuspendPending {
		t.Fatalf("BeginSuspend() target=%+v created=%v err=%v", target, created, err)
	}
	script.assertDone(t)
}

func TestBeginSuspendRollsBackWhenLockedSeatDriftsAfterIntentResolution(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	operation := suspendOperationRow(hash[:], "RUNNING", 0, nil, nil, now)
	driftedSeat := suspendSeatRow("ACTIVE", now)
	driftedSeat[4] = "member-2"
	driftedSeat[6] = int64(4)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT id FROM seats", "external_id = $1"}, columns: []string{"id"},
			rows: [][]driver.Value{{"11111111-1111-1111-1111-111111111111"}}},
		{kind: "query", contains: []string{"INSERT INTO integration_operations", "'SUSPEND'"},
			columns: operationColumnNames(), rows: [][]driver.Value{operation}},
		{kind: "query", contains: []string{"SELECT p.id", "FOR UPDATE OF p"}, columns: []string{"pool_id"},
			rows: [][]driver.Value{{"22222222-2222-2222-2222-222222222222"}}},
		{kind: "query", contains: []string{"FROM seats s", "FOR UPDATE OF s"},
			columns: suspendSeatColumnNames(), rows: [][]driver.Value{driftedSeat}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, err := store.BeginSuspend(context.Background(), application.BeginSuspendInput{
		Key:            application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		SeatExternalID: "seat-1", RequestHash: hash,
		RequestSnapshot: []byte(`{"version":1,"operation_id":"op-1","seat_id":"seat-1","pool_id":"pool-1","current_member_id":"member-1","assignment_epoch":3,"reason_code":"MANUAL_POLICY_BREACH","reason_detail":"operator requested suspension"}`),
		ReasonCode:      application.SuspendReasonManualPolicyBreach,
		LeaseOwner:      "worker-1", LeaseDuration: time.Minute,
	})
	if !errors.Is(err, application.ErrWorkflowInvalidState) {
		t.Fatalf("locked Seat drift was accepted: %v", err)
	}
	// 脚本没有 Seat UPDATE/case INSERT；消费到 rollback 即证明漂移在任何聚合写入前失败。
	script.assertDone(t)
}

func TestCommitSuspendProgressPersistsDrainingObservationAndReleasesLease(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	concurrency, settlements := 2, 1
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"fencing_token = $3", "lease_expires_at > CURRENT_TIMESTAMP", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{suspendOperationRow(hash[:], "RUNNING", 4, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"sc.integration_operation_id = $1", "FOR UPDATE OF p"},
			columns: []string{"pool_id"}, rows: [][]driver.Value{{"22222222-2222-2222-2222-222222222222"}}},
		{kind: "query", contains: []string{"FROM suspension_cases sc", "FOR UPDATE OF sc"},
			columns: suspendCaseTargetColumnNames(), rows: [][]driver.Value{suspendCaseTargetRow("SUSPEND_PENDING", nil, nil, nil, now)}},
		{kind: "exec", contains: []string{"current_concurrency = $6", "pending_settlements = $7", "sc.migration_state = 'CURRENT'"}, affected: 1},
		{kind: "exec", contains: []string{"SET status = $2", "assignment_epoch = $4"}, affected: 1},
		{kind: "query", contains: []string{"status = $5", "error_detail = NULLIF($8", "lease_owner = NULL"},
			columns: operationColumnNames(), rows: [][]driver.Value{suspendOperationRow(hash[:], "RECONCILE_REQUIRED", 4, nil, nil, now)}},
		{kind: "query", contains: []string{"FROM suspension_cases sc"}, columns: suspendCaseTargetColumnNames(),
			rows: [][]driver.Value{suspendCaseTargetRow("DRAINING", concurrency, settlements, nil, now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	target, err := store.CommitSuspendProgress(context.Background(), application.CommitSuspendProgressInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-1",
		FencingToken: 4, Progress: application.SuspendCaseDraining, ExpectedAssignmentEpoch: 3,
		CurrentConcurrency: &concurrency, PendingSettlements: &settlements,
		ResultSnapshot: []byte(`{"state":"DRAINING","current_concurrency":2,"pending_settlements":1}`),
		NextAttemptAt:  timePointer(now.Add(time.Minute)),
	})
	if err != nil || target.Case.Status != application.SuspendCaseDraining ||
		target.Operation.Status != application.OperationReconcileRequired {
		t.Fatalf("CommitSuspendProgress() target=%+v err=%v", target, err)
	}
	script.assertDone(t)
}

func TestCommitSuspendProgressRequiresExplicitZeroBarrierBeforeFrozen(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	store, cleanup := newFakeStore(t, &fakeScript{})
	defer cleanup()
	_, err := store.CommitSuspendProgress(context.Background(), application.CommitSuspendProgressInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-1",
		FencingToken: 4, Progress: application.SuspendCaseFrozen, ExpectedAssignmentEpoch: 3,
		Freeze: canonicalFreeze("op-1", 3, now), ResultSnapshot: []byte(`{"state":"FROZEN"}`),
	})
	if !errors.Is(err, application.ErrWorkflowInvalidData) {
		t.Fatalf("nil barrier observations were accepted: %v", err)
	}
}

func TestCommitSuspendProgressRejectsStaleFenceBeforeAggregateMutation(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	zero := 0
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"fencing_token = $3", "lease_expires_at > CURRENT_TIMESTAMP"}, columns: operationColumnNames()},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, err := store.CommitSuspendProgress(context.Background(), application.CommitSuspendProgressInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "old-worker",
		FencingToken: 3, Progress: application.SuspendCaseFrozen, ExpectedAssignmentEpoch: 3,
		CurrentConcurrency: &zero, PendingSettlements: &zero, Freeze: canonicalFreeze("op-1", 3, now),
		ResultSnapshot: []byte(`{"state":"FROZEN"}`),
	})
	if !errors.Is(err, application.ErrWorkflowStaleFence) {
		t.Fatalf("expected stale fence, got %v", err)
	}
	script.assertDone(t)
}

func TestPhase2BSuspendMigrationClosesDatabaseBypasses(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "migrations", "004_phase2b_suspend_persistence.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sqlText := string(content)
	for _, fragment := range []string{
		"LEGACY_UNRECOVERABLE", "array_agg(io.id ORDER BY io.id::text)",
		"DROP CONSTRAINT IF EXISTS suspension_cases_operation_id_key",
		"valid_suspend_freeze_snapshot", "hourly", "daily", "weekly", "monthly",
		"seat.assignment_epoch = bound_assignment_epoch", "CURRENT suspension case requires positive epoch and blocked_at",
		"CREATE CONSTRAINT TRIGGER integration_operations_suspend_aggregate",
		"CREATE CONSTRAINT TRIGGER suspension_cases_suspend_aggregate",
		"CREATE CONSTRAINT TRIGGER seats_suspend_aggregate", "DEFERRABLE INITIALLY DEFERRED",
		"expected_assignment_epoch IS DISTINCT FROM seat_assignment_epoch",
	} {
		if !strings.Contains(sqlText, fragment) {
			t.Errorf("004 migration missing %q", fragment)
		}
	}
	if strings.Contains(sqlText, "min(io.id)") {
		t.Error("004 migration uses unsupported min(uuid)")
	}
	storeSource, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(storeSource), "'PROVISION', 'SUSPEND', 'ASSIGN_TEMPORARY'") {
		t.Error("generic CommitOperation can bypass atomic SUSPEND completion")
	}
}

func canonicalFreeze(operationID string, epoch uint64, now time.Time) *domain.FreezeSnapshot {
	return &domain.FreezeSnapshot{
		OperationID: operationID, AssignmentEpoch: epoch, InFlight: 0, PendingSettlements: 0,
		CapturedAt: now, Usage: map[string]float64{"hourly": 0, "daily": 1, "weekly": 1, "monthly": 1},
		WindowStarts: map[string]*time.Time{"hourly": nil, "daily": timePointer(now.Add(-time.Hour)), "weekly": nil, "monthly": nil},
	}
}

func suspendOperationRow(hash []byte, status string, fence int64, owner any, leaseExpiry any, now time.Time) []driver.Value {
	row := operationRow(hash, status, fence, owner, leaseExpiry, now)
	row[3] = "SUSPEND"
	row[8] = []byte(`{"version":1,"operation_id":"op-1","seat_id":"seat-1","pool_id":"pool-1","current_member_id":"member-1","assignment_epoch":3,"reason_code":"MANUAL_POLICY_BREACH","reason_detail":"operator requested suspension"}`)
	return row
}

func suspendSeatColumnNames() []string {
	return []string{"seat_id", "seat_external_id", "pool_external_id", "owner_external_id", "current_member_id", "status", "assignment_epoch", "membership_epoch"}
}

func suspendSeatRow(status string, now time.Time) []driver.Value {
	_ = now
	return []driver.Value{"11111111-1111-1111-1111-111111111111", "seat-1", "pool-1", "owner-1", "member-1", status, int64(3), int64(2)}
}

func suspendCaseTargetColumnNames() []string {
	return []string{"case_id", "integration_operation_id", "operation_id", "seat_id", "migration_state", "status", "reason_code",
		"expected_assignment_epoch", "current_concurrency", "pending_settlements", "blocked_at", "frozen_at", "freeze_snapshot",
		"error_code", "version", "created_at", "updated_at", "seat_id", "seat_external_id", "pool_external_id",
		"owner_external_id", "current_member_id", "seat_status", "assignment_epoch", "membership_epoch"}
}

func suspendCaseTargetRow(status string, concurrency, settlements any, freeze *domain.FreezeSnapshot, now time.Time) []driver.Value {
	var frozenAt any
	var snapshot any
	seatStatus := status
	if freeze != nil {
		frozenAt = now
		snapshot, _ = json.Marshal(freeze)
	}
	return []driver.Value{
		"22222222-2222-2222-2222-222222222222", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "op-1",
		"11111111-1111-1111-1111-111111111111", "CURRENT", status, "MANUAL_POLICY_BREACH", int64(3),
		concurrency, settlements, now, frozenAt, snapshot, nil, int64(2), now, now,
		"11111111-1111-1111-1111-111111111111", "seat-1", "pool-1", "owner-1", "member-1", seatStatus, int64(3), int64(2),
	}
}

func timePointer(value time.Time) *time.Time { return &value }
