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

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/domain"

	"github.com/lib/pq"
)

// PHASE2H_TEST_POSTGRES_DSN must reference a disposable database where the
// caller can create and remove schemas.
func TestSuspendAndProvisionSerializeOnSamePoolAcrossTwoRealPostgresConnections(t *testing.T) {
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
	schema := fmt.Sprintf("phase2h_cross_workflow_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create cross-workflow schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	suspendDB := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer suspendDB.Close()
	if err := Migrate(ctx, suspendDB, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for cross-workflow test: %v", err)
	}
	provisionDB := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer provisionDB.Close()
	assertDifferentWorkflowBackends(t, ctx, suspendDB, provisionDB)
	gateDB := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer gateDB.Close()

	insertSuspendProvisionConcurrencyFixture(t, ctx, suspendDB)
	suspendStore, err := NewStore(suspendDB)
	if err != nil {
		t.Fatal(err)
	}
	provisionStore, err := NewStore(provisionDB)
	if err != nil {
		t.Fatal(err)
	}

	provisionInput := suspendProvisionCommitInput()
	provisionSnapshot := []byte(`{"version":1,"operation_id":"cross-provision","seat_id":"cross-provision-seat"}`)
	provisionKey := provisionInput.Operation.Key
	if _, created, err := provisionStore.BeginOperation(ctx, application.BeginOperationInput{
		Key: provisionKey, Kind: application.OperationProvision, TargetType: "SEAT",
		TargetExternalID: provisionInput.Operation.Claim.SeatExternalID,
		RequestHash:      sha256.Sum256(provisionSnapshot), RequestSnapshot: provisionSnapshot,
	}); err != nil || !created {
		t.Fatalf("begin cross-workflow provision operation: created=%t err=%v", created, err)
	}
	lease, err := provisionStore.AcquireOperationLease(ctx, application.AcquireOperationLeaseInput{
		Key: provisionKey, LeaseOwner: provisionInput.Operation.LeaseOwner, LeaseDuration: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("acquire cross-workflow provision lease: %v", err)
	}
	provisionInput.Operation.FencingToken = lease.FencingToken

	var suspendPID, provisionPID int
	if err := suspendDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&suspendPID); err != nil {
		t.Fatal(err)
	}
	if err := provisionDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&provisionPID); err != nil {
		t.Fatal(err)
	}
	gateTx, err := gateDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateReleased := false
	defer func() {
		if !gateReleased {
			_ = gateTx.Rollback()
		}
	}()
	var poolID string
	if err := gateTx.QueryRowContext(ctx, `SELECT id FROM pools WHERE external_id = $1 FOR UPDATE`,
		"cross-workflow-pool").Scan(&poolID); err != nil {
		t.Fatalf("acquire cross-workflow Pool gate: %v", err)
	}

	type suspendResult struct {
		target  *application.SuspendTarget
		created bool
		err     error
	}
	type provisionResult struct {
		operation *application.StoredOperation
		claim     *application.StoredCredentialClaim
		seat      *application.PersistedSeat
		err       error
	}
	raceCtx, raceCancel := context.WithTimeout(ctx, 20*time.Second)
	defer raceCancel()
	start := make(chan struct{})
	suspendResults := make(chan suspendResult, 1)
	provisionResults := make(chan provisionResult, 1)
	go func() {
		<-start
		target, created, callErr := suspendStore.BeginSuspend(raceCtx, suspendProvisionSuspendInput())
		suspendResults <- suspendResult{target: target, created: created, err: callErr}
	}()
	go func() {
		<-start
		operation, claim, seat, callErr := provisionStore.CommitProvisionWithCredentialClaim(raceCtx, provisionInput)
		provisionResults <- provisionResult{operation: operation, claim: claim, seat: seat, err: callErr}
	}()
	close(start)

	bothBlocked := waitForCrossWorkflowPoolWaiters(t, raceCtx, admin, suspendPID, provisionPID)
	if err := gateTx.Commit(); err != nil {
		t.Fatalf("release cross-workflow Pool gate: %v", err)
	}
	gateReleased = true
	suspended, provisioned := <-suspendResults, <-provisionResults
	if !bothBlocked {
		t.Fatal("both workers did not reach the shared Pool lock before the gate was released")
	}
	requireCrossWorkflowSuccess(t, "suspend", suspended.err)
	requireCrossWorkflowSuccess(t, "provision", provisioned.err)
	if !suspended.created || suspended.target == nil || suspended.target.Operation == nil ||
		suspended.target.Case == nil || suspended.target.Case.Status != application.SuspendCasePending ||
		suspended.target.Seat.Status != domain.SeatSuspendPending {
		t.Fatalf("unexpected completed Suspend aggregate: created=%t target=%+v", suspended.created, suspended.target)
	}
	if provisioned.operation == nil || provisioned.operation.Status != application.OperationSucceeded ||
		provisioned.claim == nil || provisioned.claim.Status != application.CredentialClaimReady ||
		provisioned.seat == nil || provisioned.seat.State != domain.SeatActive {
		t.Fatalf("unexpected completed Provision aggregate: operation=%+v claim=%+v seat=%+v",
			provisioned.operation, provisioned.claim, provisioned.seat)
	}
	assertSuspendProvisionAggregates(t, ctx, suspendDB)
}

func insertSuspendProvisionConcurrencyFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	var suspendedMemberID, provisionedMemberID, poolID, epochID, suspendedSeatID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO members (external_id, sub2api_user_id, display_name, status)
VALUES ('cross-suspended-member', 81001, 'Cross Suspended Member', 'ACTIVE') RETURNING id`).
		Scan(&suspendedMemberID); err != nil {
		t.Fatalf("insert suspended member: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO members (external_id, sub2api_user_id, display_name, status)
VALUES ('cross-provisioned-member', 81002, 'Cross Provisioned Member', 'ACTIVE') RETURNING id`).
		Scan(&provisionedMemberID); err != nil {
		t.Fatalf("insert provisioned member: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, sub2api_group_id, credential_epoch_floor
) VALUES ('cross-workflow-pool', 'Cross Workflow Pool', 'ACTIVE', 3, 1, 82001, 1) RETURNING id`).
		Scan(&poolID); err != nil {
		t.Fatalf("insert cross-workflow Pool: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold, recovery_governance_state, activated_at
) VALUES ($1, 1, 'ACTIVE', 1, 1, 'LEGACY_UNVERIFIED', CURRENT_TIMESTAMP) RETURNING id`, poolID).
		Scan(&epochID); err != nil {
		t.Fatalf("insert cross-workflow Epoch: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO seats (
external_id, pool_id, seat_no, status, assignment_epoch, owner_member_id,
sub2api_principal_id, sub2api_subscription_id, sub2api_api_key_id, active_api_key_version
) VALUES ('cross-suspend-seat', $1, 1, 'ACTIVE', 1, $2, 83001, 83002, 83003, 1) RETURNING id`,
		poolID, suspendedMemberID).Scan(&suspendedSeatID); err != nil {
		t.Fatalf("insert suspended Seat: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, starts_at
) VALUES ($1, $2, $3, 'PERMANENT', 'ACTIVE', 1, CURRENT_TIMESTAMP)`,
		suspendedSeatID, poolID, suspendedMemberID); err != nil {
		t.Fatalf("insert suspended Seat assignment: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO membership_epoch_members (
epoch_id, member_id, member_role, signing_public_key, share_index, migration_state
) VALUES ($1, $2, 'OWNER', decode('01','hex'), 1, 'LEGACY_UNVERIFIED'),
         ($1, $3, 'MEMBER', decode('02','hex'), 2, 'LEGACY_UNVERIFIED')`,
		epochID, suspendedMemberID, provisionedMemberID); err != nil {
		t.Fatalf("insert cross-workflow Epoch members: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit cross-workflow fixture: %v", err)
	}
}

func suspendProvisionSuspendInput() application.BeginSuspendInput {
	snapshot := []byte(`{"version":1,"operation_id":"cross-suspend","seat_id":"cross-suspend-seat","pool_id":"cross-workflow-pool","current_member_id":"cross-suspended-member","assignment_epoch":1,"reason_code":"MANUAL_POLICY_BREACH","reason_detail":"operator requested suspension"}`)
	return application.BeginSuspendInput{
		Key:            application.OperationKey{ClientID: "cross-workflow-client", OperationID: "cross-suspend"},
		SeatExternalID: "cross-suspend-seat", RequestHash: sha256.Sum256(snapshot), RequestSnapshot: snapshot,
		ReasonCode: application.SuspendReasonManualPolicyBreach, LeaseOwner: "cross-suspend-worker",
		LeaseDuration: 30 * time.Second,
	}
}

func suspendProvisionCommitInput() application.CommitProvisionWithCredentialClaimInput {
	claim := application.CreateCredentialClaimInput{
		Key:            application.ClaimKey{ClientID: "cross-workflow-client", OperationID: "cross-provision"},
		SeatExternalID: "cross-provision-seat", TargetMemberExternalID: "cross-provisioned-member",
		ClaimOperationID: "cross-provision-claim", TokenHash: bytes32(0x31),
		CredentialFingerprint: bytes32(0x32),
		Envelope: application.CredentialEnvelope{
			Algorithm: "AES-256-GCM", KeyRef: "kms://cross-workflow/provision", Ciphertext: []byte("ciphertext"),
			Nonce: []byte("123456789012"), AADHash: bytes32(0x33), WrappedDEK: []byte("wrapped-dek"),
		},
		ClaimTTL: 10 * time.Minute,
	}
	return application.CommitProvisionWithCredentialClaimInput{
		Operation: application.CommitOperationWithCredentialClaimInput{
			Key:        application.OperationKey{ClientID: "cross-workflow-client", OperationID: "cross-provision"},
			LeaseOwner: "cross-provision-worker", ResultSnapshot: []byte(`{"applied":true}`), Claim: claim,
		},
		PoolExternalID: "cross-workflow-pool", OwnerExternalID: "cross-provisioned-member",
		ExistingGroupID: 82001, AssignmentEpoch: 1,
		PrincipalUserID: 84001, SubscriptionID: 84002, APIKeyID: 84003,
	}
}

func waitForCrossWorkflowPoolWaiters(t *testing.T, ctx context.Context, db *sql.DB,
	suspendPID, provisionPID int,
) bool {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := db.QueryRowContext(waitCtx, `SELECT count(*) FROM pg_stat_activity
WHERE pid IN ($1, $2) AND wait_event_type = 'Lock'`, suspendPID, provisionPID).Scan(&waiting); err != nil {
			if waitCtx.Err() != nil {
				return false
			}
			t.Fatalf("inspect cross-workflow Pool waiters: %v", err)
		}
		if waiting == 2 {
			return true
		}
		select {
		case <-waitCtx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func requireCrossWorkflowSuccess(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var postgresErr *pq.Error
	if errors.As(err, &postgresErr) && postgresErr.Code == "40P01" {
		t.Fatalf("%s workflow deadlocked: %v", name, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("%s workflow timed out while contending on the Pool: %v", name, err)
	}
	t.Fatalf("%s workflow failed: %v", name, err)
}

func assertSuspendProvisionAggregates(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var completeSuspend int
	if err := db.QueryRowContext(ctx, `SELECT count(*)
FROM integration_operations operation
JOIN suspension_cases suspension ON suspension.integration_operation_id = operation.id
JOIN seats seat ON seat.id = suspension.seat_id AND seat.id = operation.target_id
JOIN seat_assignments assignment ON assignment.seat_id = seat.id AND assignment.status = 'ACTIVE'
JOIN members member ON member.id = assignment.member_id
WHERE operation.integration_client_id = 'cross-workflow-client'
  AND operation.operation_id = 'cross-suspend' AND operation.operation_type = 'SUSPEND'
  AND operation.status = 'RUNNING' AND operation.fencing_token = 1
  AND operation.lease_owner = 'cross-suspend-worker' AND operation.lease_expires_at > CURRENT_TIMESTAMP
  AND suspension.status = 'SUSPEND_PENDING' AND suspension.expected_assignment_epoch = 1
  AND seat.external_id = 'cross-suspend-seat' AND seat.status = 'SUSPEND_PENDING'
  AND seat.assignment_epoch = 1 AND member.external_id = 'cross-suspended-member'`).Scan(&completeSuspend); err != nil {
		t.Fatalf("inspect completed Suspend aggregate: %v", err)
	}
	if completeSuspend != 1 {
		t.Fatalf("completed Suspend aggregates=%d, want 1", completeSuspend)
	}

	var completeProvision int
	if err := db.QueryRowContext(ctx, `SELECT count(*)
FROM integration_operations operation
JOIN seats seat ON seat.id = operation.target_id
JOIN seat_assignments assignment ON assignment.seat_id = seat.id AND assignment.status = 'ACTIVE'
JOIN members member ON member.id = assignment.member_id AND member.id = seat.owner_member_id
JOIN credential_claims claim ON claim.integration_operation_id = operation.id
  AND claim.seat_id = seat.id AND claim.target_member_id = member.id
WHERE operation.integration_client_id = 'cross-workflow-client'
  AND operation.operation_id = 'cross-provision' AND operation.operation_type = 'PROVISION'
  AND operation.status = 'SUCCEEDED' AND operation.response_snapshot IS NOT NULL
  AND operation.completed_at IS NOT NULL AND operation.lease_owner IS NULL AND operation.lease_expires_at IS NULL
  AND seat.external_id = 'cross-provision-seat' AND seat.status = 'ACTIVE'
  AND seat.assignment_epoch = 1 AND seat.active_api_key_version = 1
  AND seat.sub2api_principal_id = 84001 AND seat.sub2api_subscription_id = 84002
  AND seat.sub2api_api_key_id = 84003 AND member.external_id = 'cross-provisioned-member'
  AND claim.status = 'READY' AND claim.claim_token_hash IS NOT NULL
  AND claim.envelope_ciphertext IS NOT NULL AND claim.wrapped_dek_kms IS NOT NULL
  AND claim.expires_at > claim.created_at`).Scan(&completeProvision); err != nil {
		t.Fatalf("inspect completed Provision aggregate: %v", err)
	}
	if completeProvision != 1 {
		t.Fatalf("completed Provision aggregates=%d, want 1", completeProvision)
	}

	var operations, suspensionCases, claims, activeAssignments int
	var membershipEpoch, credentialEpochFloor int
	if err := db.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM integration_operations WHERE integration_client_id = 'cross-workflow-client'
 AND operation_id IN ('cross-suspend', 'cross-provision')),
(SELECT count(*) FROM suspension_cases suspension JOIN integration_operations operation
 ON operation.id = suspension.integration_operation_id WHERE operation.operation_id = 'cross-suspend'),
(SELECT count(*) FROM credential_claims claim JOIN integration_operations operation
 ON operation.id = claim.integration_operation_id WHERE operation.operation_id = 'cross-provision'),
(SELECT count(*) FROM seat_assignments assignment JOIN pools assignment_pool ON assignment_pool.id = assignment.pool_id
 WHERE assignment_pool.external_id = 'cross-workflow-pool' AND assignment.status = 'ACTIVE'),
pool.membership_epoch, pool.credential_epoch_floor
FROM pools pool WHERE pool.external_id = 'cross-workflow-pool'`).Scan(
		&operations, &suspensionCases, &claims, &activeAssignments, &membershipEpoch, &credentialEpochFloor); err != nil {
		t.Fatalf("inspect cross-workflow aggregate counts: %v", err)
	}
	if operations != 2 || suspensionCases != 1 || claims != 1 || activeAssignments != 2 ||
		membershipEpoch != 1 || credentialEpochFloor != 1 {
		t.Fatalf("partial cross-workflow aggregate: operations=%d suspension_cases=%d claims=%d assignments=%d epochs=%d/%d",
			operations, suspensionCases, claims, activeAssignments, membershipEpoch, credentialEpochFloor)
	}
}
