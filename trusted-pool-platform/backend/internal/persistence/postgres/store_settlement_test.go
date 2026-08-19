package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

const (
	settlementOperationUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	settlementCaseUUID      = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	settlementSeatUUID      = "11111111-1111-1111-1111-111111111111"
	settlementPoolUUID      = "22222222-2222-2222-2222-222222222222"
	settlementTrustUUID     = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	settlementResultUUID    = "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

func TestBeginSettlementResolutionPersistsNineFieldIntentBeforeNetwork(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	input := settlementBeginInput()
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT id, pool_id FROM seats"},
			columns: []string{"id", "pool_id"}, rows: [][]driver.Value{{settlementSeatUUID, settlementPoolUUID}}},
		{kind: "query", contains: []string{"INSERT INTO integration_operations", "'RESOLVE_SETTLEMENT'", "request_snapshot"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "RUNNING", 0, nil, nil, now)}},
		{kind: "query", contains: []string{"FROM pools", "FOR UPDATE"},
			columns: []string{"id"}, rows: [][]driver.Value{{settlementPoolUUID}}},
		{kind: "query", contains: []string{"s.status IN ('DRAINING')", "FOR UPDATE OF s"},
			columns: settlementSeatColumnNames(), rows: [][]driver.Value{settlementSeatRow("DRAINING")}},
		{kind: "exec", contains: []string{"INSERT INTO settlement_resolution_cases", "expected_actor_client_id"}, affected: 1},
		{kind: "query", contains: []string{"fencing_token = fencing_token + 1", "operation_type = 'RESOLVE_SETTLEMENT'"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "RUNNING", 1, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases", "src.expected_actor_client_id"},
			columns: settlementTargetColumnNames(), rows: [][]driver.Value{settlementTargetRow("DRAINING", now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	target, created, err := store.BeginSettlementResolution(context.Background(), input)
	if err != nil || !created || target.Operation.FencingToken != 1 ||
		target.Case.ExpectedActorClientID != "settlement-client-1" {
		t.Fatalf("BeginSettlementResolution() target=%+v created=%v err=%v", target, created, err)
	}
	script.assertDone(t)
}

func TestBeginSettlementResolutionRejectsMissingActorBindingBeforeTransaction(t *testing.T) {
	input := settlementBeginInput()
	input.ExpectedActorClientID = ""
	store, cleanup := newFakeStore(t, &fakeScript{})
	defer cleanup()
	_, _, err := store.BeginSettlementResolution(context.Background(), input)
	if !errors.Is(err, application.ErrWorkflowInvalidData) {
		t.Fatalf("missing independent settlement actor was accepted: %v", err)
	}
}

func TestCommitSettlementResolutionPersistsTypedResultAndSub2APIAudit(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	input := settlementBeginInput()
	resolution := application.SettlementResolution{
		SeatID: 301, ExternalSeatID: "seat-1", SettlementID: "settlement-1",
		OperationID: "resolve-1", ActorClientID: "settlement-client-1",
		AssignmentEpoch: 3, RequestID: "request-1", Reason: "manual review",
		Evidence: "ticket-42", ResolvedAt: now,
	}
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases", "src.status = 'RESOLUTION_PENDING'"},
			columns: []string{"seat_id", "pool_id", "expected_assignment_epoch"},
			rows:    [][]driver.Value{{settlementSeatUUID, settlementPoolUUID, int64(3)}}},
		{kind: "query", contains: []string{"fencing_token = $3", "lease_owner = $4", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "RUNNING", 4, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"FROM pools", "FOR UPDATE"},
			columns: []string{"id"}, rows: [][]driver.Value{{settlementPoolUUID}}},
		{kind: "query", contains: []string{"s.status IN ('DRAINING', 'FROZEN')", "FOR UPDATE OF s"},
			columns: settlementSeatColumnNames(), rows: [][]driver.Value{settlementSeatRow("FROZEN")}},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases", "FOR UPDATE OF src"},
			columns: settlementTargetColumnNames(), rows: [][]driver.Value{settlementTargetRow("FROZEN", now)}},
		{kind: "query", contains: []string{"SELECT event_hash FROM trust_events"}, columns: []string{"event_hash"}},
		{kind: "query", contains: []string{"'SUB2API'", "settlement_trust_event_hash"},
			columns: []string{"id"}, rows: [][]driver.Value{{settlementTrustUUID}}},
		{kind: "exec", contains: []string{"UPDATE settlement_resolution_cases", "status = 'SUCCEEDED'"}, affected: 1},
		{kind: "query", contains: []string{"UPDATE integration_operations", "status = 'SUCCEEDED'", "response_snapshot"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "SUCCEEDED", 4, nil, nil, now)}},
		{kind: "query", contains: []string{"INSERT INTO settlement_resolutions", "request_id", "assignment_epoch"},
			columns: []string{"id"}, rows: [][]driver.Value{{settlementResultUUID}}},
		{kind: "query", contains: []string{"FROM settlement_resolutions sr"},
			columns: settlementResolutionColumnNames(), rows: [][]driver.Value{settlementResolutionRow(now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	op, stored, err := store.CommitSettlementResolution(context.Background(), application.CommitSettlementResolutionInput{
		Key: input.Key, LeaseOwner: "worker-1", FencingToken: 4, Result: resolution,
	})
	if err != nil || op.Status != application.OperationSucceeded || stored.RequestID != "request-1" ||
		stored.AssignmentEpoch != 3 || stored.ActorClientID != "settlement-client-1" {
		t.Fatalf("CommitSettlementResolution() op=%+v stored=%+v err=%v", op, stored, err)
	}
	script.assertDone(t)
}

func TestCommitSettlementResolutionFailureAlwaysRemainsRecoverable(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	next := now.Add(time.Minute)
	input := settlementBeginInput()
	pendingWithError := settlementTargetRow("DRAINING", now)
	pendingWithError[10] = "GATEWAY_UNKNOWN"
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases", "src.status = 'RESOLUTION_PENDING'"},
			columns: []string{"seat_id", "pool_id", "expected_assignment_epoch"},
			rows:    [][]driver.Value{{settlementSeatUUID, settlementPoolUUID, int64(3)}}},
		{kind: "query", contains: []string{"fencing_token = $3", "lease_owner = $4", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "RUNNING", 4, "worker-1", now.Add(time.Minute), now)}},
		{kind: "query", contains: []string{"FROM pools", "FOR UPDATE"}, columns: []string{"id"}, rows: [][]driver.Value{{settlementPoolUUID}}},
		{kind: "query", contains: []string{"s.status IN ('DRAINING', 'FROZEN')"},
			columns: settlementSeatColumnNames(), rows: [][]driver.Value{settlementSeatRow("DRAINING")}},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases", "FOR UPDATE OF src"},
			columns: settlementTargetColumnNames(), rows: [][]driver.Value{settlementTargetRow("DRAINING", now)}},
		{kind: "exec", contains: []string{"UPDATE settlement_resolution_cases", "status = $2"}, affected: 1},
		{kind: "query", contains: []string{"UPDATE integration_operations", "completed_at = NULL", "lease_owner = NULL"},
			columns: operationColumnNames(), rows: [][]driver.Value{settlementOperationRow(input, "RECONCILE_REQUIRED", 4, nil, nil, now)}},
		{kind: "query", contains: []string{"FROM settlement_resolution_cases"},
			columns: settlementTargetColumnNames(), rows: [][]driver.Value{pendingWithError}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	target, err := store.CommitSettlementResolutionFailure(context.Background(), application.CommitSettlementResolutionFailureInput{
		Key: input.Key, LeaseOwner: "worker-1", FencingToken: 4,
		ErrorCode: "GATEWAY_UNKNOWN", NextAttemptAt: &next,
	})
	if err != nil || target.Case.Status != application.SettlementResolutionPending ||
		target.Operation.Status != application.OperationReconcileRequired {
		t.Fatalf("ambiguous resolve did not remain recoverable: target=%+v err=%v", target, err)
	}
	script.assertDone(t)
}

func TestPhase2DSettlementMigrationClosesDatabaseBypasses(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "006_phase2d_settlement_persistence.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sqlText := string(content)
	for _, fragment := range []string{
		"expected_actor_client_id varchar(128) NOT NULL", "key_count = 9",
		"valid_settlement_response_snapshot", "key_count = 10",
		"bound_seat_status <> 'DRAINING'", "bound_seat_status NOT IN ('DRAINING', 'FROZEN')",
		"seats_block_assignment_during_settlement_reconciliation", "NEW.status IN ('ASSIGNMENT_PENDING', 'ACTIVE')",
		"io.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')",
		"aggregate.actor_client_id = aggregate.expected_actor_client_id", "aggregate.actor_type = 'SUB2API'",
		"aggregate.trust_seat_id = aggregate.seat_id", "aggregate.trust_pool_id = aggregate.seat_pool_id",
		"aggregate.trust_occurred_at = aggregate.resolved_at", "DEFERRABLE INITIALLY DEFERRED",
	} {
		if !strings.Contains(sqlText, fragment) {
			t.Errorf("006 migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"raw_body", "response_body", "authorization_header"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("006 migration persists forbidden upstream material %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "'CANCELLED'") {
		t.Error("006 migration must not expose an unprovable confirmed-unchanged terminal path")
	}
}

func settlementBeginInput() application.BeginSettlementResolutionInput {
	snapshot := map[string]any{
		"version": 1, "operation_id": "resolve-1", "seat_id": "seat-1",
		"settlement_id": "settlement-1", "expected_request_id": "request-1",
		"expected_assignment_epoch": 3, "expected_actor_client_id": "settlement-client-1",
		"reason": "manual review", "evidence": "ticket-42",
	}
	encoded, _ := json.Marshal(snapshot)
	return application.BeginSettlementResolutionInput{
		Key:            application.OperationKey{ClientID: "platform-client-1", OperationID: "resolve-1"},
		SeatExternalID: "seat-1", SettlementID: "settlement-1", ExpectedRequestID: "request-1",
		ExpectedAssignmentEpoch: 3, ExpectedActorClientID: "settlement-client-1",
		RequestHash: sha256.Sum256(encoded), RequestSnapshot: encoded, LeaseOwner: "worker-1", LeaseDuration: time.Minute,
	}
}

func settlementOperationRow(input application.BeginSettlementResolutionInput, status string, fence int64,
	owner any, leaseExpiry any, now time.Time) []driver.Value {
	completedAt := any(nil)
	response := any(nil)
	if status == "SUCCEEDED" {
		completedAt = now
		response = []byte(`{"seat_id":301}`)
	}
	return []driver.Value{
		settlementOperationUUID, input.Key.ClientID, input.Key.OperationID, "RESOLVE_SETTLEMENT", "SEAT",
		input.SeatExternalID, "CURRENT", input.RequestHash[:], input.RequestSnapshot, status, int64(1), response,
		nil, nil, fence, owner, leaseExpiry, nil, now, now, completedAt,
	}
}

func settlementSeatColumnNames() []string {
	return []string{"id", "external_id", "pool_external_id", "assignment_epoch", "status"}
}

func settlementSeatRow(status string) []driver.Value {
	return []driver.Value{settlementSeatUUID, "seat-1", "pool-1", int64(3), status}
}

func settlementTargetColumnNames() []string {
	return []string{"case_id", "integration_operation_id", "seat_id", "settlement_id", "expected_request_id",
		"expected_assignment_epoch", "expected_actor_client_id", "reason", "evidence", "case_status", "error_code",
		"version", "created_at", "updated_at", "seat_id", "seat_external_id", "pool_external_id",
		"assignment_epoch", "seat_status"}
}

func settlementTargetRow(seatStatus string, now time.Time) []driver.Value {
	return []driver.Value{
		settlementCaseUUID, settlementOperationUUID, settlementSeatUUID, "settlement-1", "request-1", int64(3),
		"settlement-client-1", "manual review", "ticket-42", "RESOLUTION_PENDING", nil, int64(1), now, now,
		settlementSeatUUID, "seat-1", "pool-1", int64(3), seatStatus,
	}
}

func settlementResolutionColumnNames() []string {
	return []string{"id", "integration_operation_id", "case_id", "trust_event_id", "upstream_seat_id",
		"external_seat_id", "settlement_id", "request_id", "assignment_epoch", "operation_id",
		"actor_client_id", "reason", "evidence", "resolved_at", "created_at"}
}

func settlementResolutionRow(now time.Time) []driver.Value {
	return []driver.Value{
		settlementResultUUID, settlementOperationUUID, settlementCaseUUID, settlementTrustUUID, int64(301),
		"seat-1", "settlement-1", "request-1", int64(3), "resolve-1", "settlement-client-1",
		"manual review", "ticket-42", now, now,
	}
}
