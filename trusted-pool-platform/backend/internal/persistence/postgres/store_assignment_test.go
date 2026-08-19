package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

func TestBeginAssignmentPersistsFrozenIntentBeforeReturningLease(t *testing.T) {
	now := time.Date(2026, 8, 18, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT s.id, s.pool_id", "current_assignment.member_id", "target.id"},
			columns: []string{"seat_id", "pool_id", "owner_id", "current_id", "target_id"},
			rows:    [][]driver.Value{{assignmentSeatUUID, assignmentPoolUUID, assignmentOwnerUUID, assignmentOwnerUUID, assignmentTargetUUID}}},
		{kind: "query", contains: []string{"INSERT INTO integration_operations", "'SEAT'", "request_snapshot"},
			columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "query", contains: []string{"FROM pools", "status = 'ACTIVE'", "FOR UPDATE"},
			columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}},
		{kind: "query", contains: []string{"FROM membership_epochs", "membership_epoch_members", "FOR UPDATE OF membership, snapshot_member, member"},
			columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}},
		{kind: "query", contains: []string{"FROM seats s", "sub2api_api_key_id", "FOR UPDATE OF s, current_assignment"},
			columns: assignmentSeatColumnNames(), rows: [][]driver.Value{assignmentSeatRow("FROZEN", "member-1", 3, 5)}},
		{kind: "query", contains: []string{"SELECT NOT EXISTS", "settlement_resolution_cases", "RESOLUTION_PENDING"},
			columns: []string{"clear"}, rows: [][]driver.Value{{true}}},
		{kind: "query", contains: []string{"FROM suspension_cases suspension", "status = 'FROZEN'", "LIMIT 1 FOR UPDATE"},
			columns: []string{"case_id", "operation_id", "freeze_snapshot"},
			rows:    [][]driver.Value{{assignmentFreezeCaseUUID, "suspend-1", []byte(`{"operation_id":"suspend-1","assignment_epoch":3}`)}}},
		{kind: "query", contains: []string{"INSERT INTO seat_assignments", "'PENDING'", "RETURNING id"},
			columns: []string{"id"}, rows: [][]driver.Value{{assignmentPendingUUID}}},
		{kind: "exec", contains: []string{"status = 'ASSIGNMENT_PENDING'", "sub2api_api_key_id = $6"}, affected: 1},
		{kind: "exec", contains: []string{"INSERT INTO assignment_cases", "freeze_suspension_case_id", "expected_api_key_version"}, affected: 1},
		{kind: "query", contains: []string{"fencing_token = fencing_token + 1", "operation_type IN ('ASSIGN_TEMPORARY', 'RESTORE')"},
			columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 1, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"FROM assignment_cases ac", "current_assignment.status = 'ACTIVE'"},
			columns: assignmentTargetColumnNames(), rows: [][]driver.Value{assignmentTargetRow("ASSIGNMENT_PENDING", "ASSIGNMENT_PENDING", "member-1", nil, now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	target, created, err := store.BeginAssignment(context.Background(), beginTemporaryAssignmentInput(hash))
	if err != nil || !created || target.Operation.FencingToken != 1 ||
		target.Case.Status != application.AssignmentCasePending || target.Case.NextAssignmentEpoch != 4 ||
		target.Seat.PrincipalUserID != 101 || target.Seat.ActiveAPIKeyVersion != 3 {
		t.Fatalf("BeginAssignment() target=%+v created=%v err=%v", target, created, err)
	}
	script.assertDone(t)
}

func TestBeginAssignmentRejectsPendingSettlementResolutionAfterSeatLock(t *testing.T) {
	now := time.Date(2026, 8, 19, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", columns: []string{"seat_id", "pool_id", "owner_id", "current_id", "target_id"},
			rows: [][]driver.Value{{assignmentSeatUUID, assignmentPoolUUID, assignmentOwnerUUID, assignmentOwnerUUID, assignmentTargetUUID}}},
		{kind: "query", columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "query", columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}},
		{kind: "query", columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}},
		{kind: "query", contains: []string{"FOR UPDATE OF s, current_assignment"},
			columns: assignmentSeatColumnNames(), rows: [][]driver.Value{assignmentSeatRow("FROZEN", "member-1", 3, 5)}},
		{kind: "query", contains: []string{"SELECT NOT EXISTS", "operation_type = 'RESOLVE_SETTLEMENT'"},
			columns: []string{"clear"}, rows: [][]driver.Value{{false}}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, err := store.BeginAssignment(context.Background(), beginTemporaryAssignmentInput(hash))
	if !errors.Is(err, application.ErrWorkflowInvalidState) {
		t.Fatalf("pending settlement resolution did not block assignment: %v", err)
	}
	script.assertDone(t)
}

func TestBeginAssignmentFailsClosedForLegacySeatWithoutStableResourceIDs(t *testing.T) {
	now := time.Date(2026, 8, 18, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	legacy := assignmentSeatRow("FROZEN", "member-1", 3, 5)
	legacy[9], legacy[10], legacy[11], legacy[12] = nil, nil, nil, int64(0)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", columns: []string{"seat_id", "pool_id", "owner_id", "current_id", "target_id"},
			rows: [][]driver.Value{{assignmentSeatUUID, assignmentPoolUUID, assignmentOwnerUUID, assignmentOwnerUUID, assignmentTargetUUID}}},
		{kind: "query", columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "query", columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}},
		{kind: "query", columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}},
		{kind: "query", columns: assignmentSeatColumnNames(), rows: [][]driver.Value{legacy}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, err := store.BeginAssignment(context.Background(), beginTemporaryAssignmentInput(hash))
	if !errors.Is(err, application.ErrWorkflowInvalidState) {
		t.Fatalf("legacy Seat resource gap was accepted: %v", err)
	}
	script.assertDone(t)
}

func TestBeginAssignmentRejectsAPIKeyVersionEpochDriftBeforeAggregateWrites(t *testing.T) {
	now := time.Date(2026, 8, 18, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	drifted := assignmentSeatRow("FROZEN", "member-1", 3, 5)
	drifted[12] = int64(9)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", columns: []string{"seat_id", "pool_id", "owner_id", "current_id", "target_id"},
			rows: [][]driver.Value{{assignmentSeatUUID, assignmentPoolUUID, assignmentOwnerUUID, assignmentOwnerUUID, assignmentTargetUUID}}},
		{kind: "query", columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "query", columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}},
		{kind: "query", columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}},
		{kind: "query", columns: assignmentSeatColumnNames(), rows: [][]driver.Value{drifted}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, err := store.BeginAssignment(context.Background(), beginTemporaryAssignmentInput(hash))
	if !errors.Is(err, application.ErrWorkflowInvalidState) {
		t.Fatalf("Seat API key version/epoch drift was accepted: %v", err)
	}
	script.assertDone(t)
}

func TestCommitAssignmentWithCredentialClaimIsOneFencedAggregate(t *testing.T) {
	now := time.Date(2026, 8, 18, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	claim := assignmentClaimInput()
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"FROM assignment_cases ac", "ac.status = 'ASSIGNMENT_PENDING'"},
			columns: assignmentLocatorColumnNames(), rows: [][]driver.Value{assignmentLocatorRow()}},
		{kind: "query", contains: []string{"fencing_token = $3", "lease_owner = $4", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 4, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"FROM pools", "FOR UPDATE"}, columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}},
		{kind: "query", contains: []string{"FROM membership_epochs", "occupied.seat_id <> $5"}, columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}},
		{kind: "query", contains: []string{"FROM seats s", "FOR UPDATE OF s, current_assignment"}, columns: assignmentSeatColumnNames(), rows: [][]driver.Value{assignmentSeatRow("ASSIGNMENT_PENDING", "member-1", 3, 5)}},
		{kind: "query", contains: []string{"FROM assignment_cases ac", "FOR UPDATE OF ac"}, columns: assignmentTargetColumnNames(), rows: [][]driver.Value{assignmentTargetRow("ASSIGNMENT_PENDING", "ASSIGNMENT_PENDING", "member-1", nil, now)}},
		{kind: "exec", contains: []string{"status = 'ENDED'", "ended_reason = $4"}, affected: 1},
		{kind: "exec", contains: []string{"status = 'ACTIVE'", "id = $1", "status = 'PENDING'"}, affected: 1},
		{kind: "exec", contains: []string{"assignment_epoch = $2", "active_api_key_version = $3", "sub2api_api_key_id = $8"}, affected: 1},
		{kind: "exec", contains: []string{"UPDATE assignment_cases", "status = 'SUCCEEDED'"}, affected: 1},
		{kind: "query", contains: []string{"UPDATE integration_operations", "status = 'SUCCEEDED'", "lease_expires_at > CURRENT_TIMESTAMP"},
			columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "SUCCEEDED", 4, nil, nil, now)}},
		{kind: "exec", contains: []string{"INSERT INTO credential_claims", "claim_intent_hash", "'READY'"}, affected: 1},
		{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(),
			rows: [][]driver.Value{claimRow("ASSIGN_TEMPORARY", "READY", claim.TokenHash[:], claim.CredentialFingerprint[:], claim.Envelope.AADHash[:], 0, nil, now)}},
		{kind: "query", contains: []string{"s.sub2api_api_key_id", "assignment.starts_at"}, columns: persistedAssignmentSeatColumnNames(), rows: [][]driver.Value{persistedAssignmentSeatRow(now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	op, storedClaim, seat, err := store.CommitAssignmentWithCredentialClaim(context.Background(), application.CommitAssignmentWithCredentialClaimInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "assign-1"}, LeaseOwner: "worker-1",
		FencingToken: 4, ExpectedAssignmentEpoch: 3, ResultSnapshot: []byte(`{"applied":true}`), Claim: claim,
	})
	if err != nil || op.Status != application.OperationSucceeded || storedClaim.Status != application.CredentialClaimReady ||
		seat.AssignmentEpoch != 4 || seat.ActiveAPIKeyVersion != 4 || seat.CurrentMemberID != "member-2" ||
		seat.CurrentAssignmentKind != "TEMPORARY" {
		t.Fatalf("CommitAssignmentWithCredentialClaim() op=%+v claim=%+v seat=%+v err=%v", op, storedClaim, seat, err)
	}
	script.assertDone(t)
}

func TestCommitAssignmentFailureKeepsUnknownPendingAndCancelsOnlyConfirmedUnchanged(t *testing.T) {
	now := time.Date(2026, 8, 18, 4, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	for _, tc := range []struct {
		name      string
		confirmed bool
	}{
		{name: "ambiguous"},
		{name: "confirmed unchanged", confirmed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := []fakeStep{
				{kind: "begin"},
				{kind: "query", columns: assignmentLocatorColumnNames(), rows: [][]driver.Value{assignmentLocatorRow()}},
				{kind: "query", columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], "RUNNING", 4, "worker-1", now.Add(time.Minute), now)}},
				{kind: "query", columns: []string{"external_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-1", int64(5)}}, contains: []string{"FOR UPDATE"}},
				{kind: "query", columns: []string{"member_id"}, rows: [][]driver.Value{{assignmentTargetUUID}}, contains: []string{"FOR UPDATE OF membership"}},
				{kind: "query", columns: assignmentSeatColumnNames(), rows: [][]driver.Value{assignmentSeatRow("ASSIGNMENT_PENDING", "member-1", 3, 5)}, contains: []string{"FOR UPDATE OF s"}},
				{kind: "query", columns: assignmentTargetColumnNames(), rows: [][]driver.Value{assignmentTargetRow("ASSIGNMENT_PENDING", "ASSIGNMENT_PENDING", "member-1", nil, now)}, contains: []string{"FOR UPDATE OF ac"}},
			}
			caseStatus, seatStatus, operationStatus := "ASSIGNMENT_PENDING", "ASSIGNMENT_PENDING", "RECONCILE_REQUIRED"
			caseError := any("GATEWAY_UNKNOWN")
			if tc.confirmed {
				steps = append(steps,
					fakeStep{kind: "exec", contains: []string{"status = 'CANCELLED'", "UPSTREAM_REJECTED_UNCHANGED"}, affected: 1},
					fakeStep{kind: "exec", contains: []string{"status = 'FROZEN'", "active_api_key_version = $3"}, affected: 1})
				caseStatus, seatStatus, operationStatus, caseError = "CANCELLED", "FROZEN", "FAILED", nil
			}
			steps = append(steps,
				fakeStep{kind: "exec", contains: []string{"UPDATE assignment_cases", "error_code = NULLIF"}, affected: 1},
				fakeStep{kind: "query", contains: []string{"UPDATE integration_operations", "lease_owner = NULL"}, columns: operationColumnNames(), rows: [][]driver.Value{assignmentOperationRow(hash[:], operationStatus, 4, nil, nil, now)}},
				fakeStep{kind: "query", contains: []string{"FROM assignment_cases ac"}, columns: assignmentTargetColumnNames(), rows: [][]driver.Value{assignmentTargetRow(caseStatus, seatStatus, "member-1", caseError, now)}},
				fakeStep{kind: "commit"})
			script := &fakeScript{steps: steps}
			store, cleanup := newFakeStore(t, script)
			defer cleanup()
			var nextAttempt *time.Time
			if !tc.confirmed {
				next := now.Add(time.Minute)
				nextAttempt = &next
			}
			target, err := store.CommitAssignmentFailure(context.Background(), application.CommitAssignmentFailureInput{
				Key: application.OperationKey{ClientID: "client-1", OperationID: "assign-1"}, LeaseOwner: "worker-1",
				FencingToken: 4, ResultSnapshot: []byte(`{"applied":false}`), ErrorCode: "GATEWAY_UNKNOWN",
				ErrorDetail: "upstream unavailable", NextAttemptAt: nextAttempt, ConfirmedUnchanged: tc.confirmed,
			})
			if err != nil || string(target.Case.Status) != caseStatus || string(target.Seat.Status) != seatStatus || string(target.Operation.Status) != operationStatus {
				t.Fatalf("CommitAssignmentFailure() target=%+v err=%v", target, err)
			}
			script.assertDone(t)
		})
	}
}

func TestPhase2CAssignmentMigrationClosesAggregateBypasses(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "005_phase2c_assignment_persistence.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sqlText := string(content)
	for _, fragment := range []string{
		"ADD COLUMN sub2api_api_key_id", "uq_assignment_cases_consumed_freeze",
		"phase2c_provision_bindings", "idx_seats_missing_stable_sub2api_binding",
		"WHERE status <> 'CANCELLED'", "valid_assignment_request_snapshot",
		"membership_epoch_members", "occupied.seat_id <> NEW.seat_id",
		"expected_api_key_version = expected_assignment_epoch", "next_api_key_version = next_assignment_epoch",
		"active_api_key_version IS DISTINCT FROM NEW.assignment_epoch",
		"UPDATE OF status, assignment_epoch, sub2api_principal_id",
		"CREATE CONSTRAINT TRIGGER integration_operations_assignment_aggregate",
		"CREATE CONSTRAINT TRIGGER credential_claims_assignment_aggregate",
		"AFTER UPDATE OF status, assignment_epoch, owner_member_id, active_api_key_version ON seats",
		"CREATE OR REPLACE FUNCTION assert_suspend_aggregate", "freeze_consumed",
	} {
		if !strings.Contains(sqlText, fragment) {
			t.Errorf("005 migration missing %q", fragment)
		}
	}
	storeSource, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storeSource), "operation_type IN ('PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')\nRETURNING") {
		t.Error("generic credential commit can still complete assignment workflows")
	}
}

const (
	assignmentSeatUUID       = "11111111-1111-1111-1111-111111111111"
	assignmentPoolUUID       = "22222222-2222-2222-2222-222222222222"
	assignmentOwnerUUID      = "33333333-3333-3333-3333-333333333333"
	assignmentTargetUUID     = "44444444-4444-4444-4444-444444444444"
	assignmentPendingUUID    = "55555555-5555-5555-5555-555555555555"
	assignmentFreezeCaseUUID = "66666666-6666-6666-6666-666666666666"
)

func beginTemporaryAssignmentInput(hash [32]byte) application.BeginAssignmentInput {
	return application.BeginAssignmentInput{
		Key:  application.OperationKey{ClientID: "client-1", OperationID: "assign-1"},
		Kind: application.OperationAssignTemp, SeatExternalID: "seat-1", TargetMemberExternalID: "member-2",
		RequestHash:     hash,
		RequestSnapshot: []byte(`{"version":1,"operation_id":"assign-1","seat_id":"seat-1","target_member_id":"member-2","mode":"ASSIGN_TEMPORARY"}`),
		LeaseOwner:      "worker-1", LeaseDuration: time.Minute,
	}
}

func assignmentClaimInput() application.CreateCredentialClaimInput {
	return application.CreateCredentialClaimInput{
		Key:            application.ClaimKey{ClientID: "client-1", OperationID: "assign-1"},
		SeatExternalID: "seat-1", TargetMemberExternalID: "member-2", ClaimOperationID: "claim-assign-1",
		TokenHash: bytes32(3), CredentialFingerprint: bytes32(4),
		Envelope: application.CredentialEnvelope{Algorithm: "AES-256-GCM", KeyRef: "kms/key/1", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), AADHash: bytes32(5), WrappedDEK: []byte("wrapped")},
		ClaimTTL: 10 * time.Minute,
	}
}

func assignmentOperationRow(hash []byte, status string, fence int64, owner any, leaseExpiry any, now time.Time) []driver.Value {
	row := operationRow(hash, status, fence, owner, leaseExpiry, now)
	row[2], row[3] = "assign-1", "ASSIGN_TEMPORARY"
	row[8] = []byte(`{"version":1,"operation_id":"assign-1","seat_id":"seat-1","target_member_id":"member-2","mode":"ASSIGN_TEMPORARY"}`)
	return row
}

func assignmentSeatColumnNames() []string {
	return []string{"seat_id", "seat_external_id", "pool_external_id", "owner_external_id", "current_member_id", "target_member_id",
		"status", "assignment_epoch", "membership_epoch", "principal_id", "subscription_id", "api_key_id", "api_key_version"}
}

func assignmentSeatRow(status, currentMember string, assignmentEpoch, membershipEpoch int64) []driver.Value {
	return []driver.Value{assignmentSeatUUID, "seat-1", "pool-1", "member-1", currentMember, "member-2", status,
		assignmentEpoch, membershipEpoch, int64(101), int64(201), int64(301), assignmentEpoch}
}

func assignmentTargetColumnNames() []string {
	return []string{"case_id", "integration_operation_id", "seat_id", "pool_id", "target_member_id", "previous_member_id",
		"pending_assignment_id", "freeze_case_id", "operation_type", "case_status", "expected_epoch", "next_epoch", "membership_epoch",
		"principal_id", "subscription_id", "api_key_id", "expected_key_version", "next_key_version", "freeze_operation_id",
		"freeze_snapshot", "error_code", "version", "created_at", "updated_at",
		"seat_id", "seat_external_id", "pool_external_id", "owner_external_id", "current_member_id", "target_member_external_id",
		"seat_status", "seat_epoch", "pool_epoch", "seat_principal_id", "seat_subscription_id", "seat_api_key_id", "seat_api_key_version"}
}

func assignmentTargetRow(caseStatus, seatStatus, currentMember string, errorCode any, now time.Time) []driver.Value {
	return []driver.Value{
		"77777777-7777-7777-7777-777777777777", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", assignmentSeatUUID, assignmentPoolUUID,
		assignmentTargetUUID, assignmentOwnerUUID, assignmentPendingUUID, assignmentFreezeCaseUUID, "ASSIGN_TEMPORARY", caseStatus,
		int64(3), int64(4), int64(5), int64(101), int64(201), int64(301), int64(3), int64(4), "suspend-1",
		[]byte(`{"operation_id":"suspend-1","assignment_epoch":3}`), errorCode, int64(1), now, now,
		assignmentSeatUUID, "seat-1", "pool-1", "member-1", currentMember, "member-2", seatStatus, int64(3), int64(5),
		int64(101), int64(201), int64(301), int64(3),
	}
}

func assignmentLocatorColumnNames() []string {
	return []string{"seat_id", "pool_id", "owner_member_id", "previous_member_id", "target_member_id", "target_external_id",
		"pending_assignment_id", "membership_epoch", "expected_assignment_epoch", "next_assignment_epoch", "expected_api_key_version"}
}

func assignmentLocatorRow() []driver.Value {
	return []driver.Value{assignmentSeatUUID, assignmentPoolUUID, assignmentOwnerUUID, assignmentOwnerUUID,
		assignmentTargetUUID, "member-2", assignmentPendingUUID, int64(5), int64(3), int64(4), int64(3)}
}

func persistedAssignmentSeatColumnNames() []string {
	return []string{"seat_id", "seat_external_id", "pool_external_id", "status", "owner_external_id", "current_member_id",
		"assignment_type", "assignment_epoch", "membership_epoch", "principal_id", "subscription_id", "api_key_id", "api_key_version", "starts_at", "updated_at"}
}

func persistedAssignmentSeatRow(now time.Time) []driver.Value {
	return []driver.Value{assignmentSeatUUID, "seat-1", "pool-1", "ACTIVE", "member-1", "member-2",
		"TEMPORARY", int64(4), int64(5), int64(101), int64(201), int64(301), int64(4), now, now}
}
