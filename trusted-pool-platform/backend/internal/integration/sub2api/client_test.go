package sub2api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

func TestClientSuspendDrainFreezeContract(t *testing.T) {
	freezeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Integration-Client-ID") != "pool-client" || request.Header.Get("Authorization") != "Bearer integration-secret" {
			t.Fatalf("missing integration authentication: %+v", request.Header)
		}
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			if request.Header.Get("Idempotency-Key") != "op-1" {
				t.Fatal("missing idempotency key")
			}
			writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 3})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 3, "current_concurrency": 0, "pending_settlements": 0})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/freeze":
			freezeCalls++
			writeEnvelope(t, writer, map[string]any{"state": "frozen", "assignment_epoch": 3, "current_concurrency": 0, "pending_settlements": 0,
				"usage_snapshot": quotaSnapshot()})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 3})
	if err != nil || !result.Draining {
		t.Fatalf("expected draining: result=%+v err=%v", result, err)
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Applied || status.Freeze == nil || status.Freeze.AssignmentEpoch != 3 ||
		status.Freeze.PendingSettlements != 0 || freezeCalls != 1 {
		t.Fatalf("unexpected freeze reconciliation: result=%+v calls=%d err=%v", status, freezeCalls, err)
	}
}

func TestClientProvisionSeatContract(t *testing.T) {
	expiresAt := time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/integrations/trusted-pools/seats/provision" {
			t.Fatalf("unexpected provision request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "provision-1" {
			t.Fatal("provision omitted idempotency key")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["external_pool_id"] != "pool-1" || body["external_seat_id"] != "seat-1" || body["existing_group_id"] != float64(7) ||
			body["principal_concurrency"] != float64(2) || body["api_key_rate_limit_5h"] != float64(25) {
			t.Fatalf("unexpected provision body: %+v", body)
		}
		if _, exists := body["owner_user_id"]; exists {
			t.Fatal("platform owner identity must not be injected into Sub2API principal fields")
		}
		writeEnvelope(t, writer, map[string]any{
			"seat": map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 1,
			},
			"credential": "provisioned-key",
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := client.ProvisionSeat(context.Background(), application.ProvisionSeatCommand{
		OperationID: "provision-1", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, AssignmentEpoch: 1, PrincipalConcurrency: 2,
		SubscriptionExpiresAt: expiresAt, APIKeyRateLimit5h: 25,
	})
	if err != nil || result.Credential != "provisioned-key" || result.ExternalSeatID != "seat-1" {
		t.Fatalf("unexpected provision result: result=%+v err=%v", result, err)
	}
}

func TestClientAcknowledgesProvisionCredentialWithoutReturningSecret(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/integrations/trusted-pools/seats/seat-1/provision-credential/ack" {
			t.Fatalf("unexpected ack request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "claim-1" {
			t.Fatal("credential ack omitted idempotency key")
		}
		var body application.ProvisionCredentialAckCommand
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.ProvisionOperationID != "provision-1" || body.ClaimOperationID != "claim-1" ||
			body.ClaimedBy != "owner-1" || body.CredentialFingerprint != strings.Repeat("a", 64) {
			t.Fatalf("unexpected credential ack body: %+v", body)
		}
		writeEnvelope(t, writer, map[string]any{
			"external_seat_id": "seat-1", "provision_operation_id": "provision-1",
			"claim_operation_id": "claim-1", "claimed_by": "owner-1",
			"credential_fingerprint": strings.Repeat("a", 64),
			"credential_claimed":     true, "claimed_at": now,
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := client.AcknowledgeProvisionCredential(context.Background(), application.ProvisionCredentialAckCommand{
		SeatID: "seat-1", ProvisionOperationID: "provision-1", ClaimOperationID: "claim-1",
		ClaimedBy: "owner-1", CredentialFingerprint: strings.Repeat("a", 64),
	})
	if err != nil || !result.CredentialClaimed || result.ClaimOperationID != "claim-1" {
		t.Fatalf("unexpected ack result: result=%+v err=%v", result, err)
	}
}

func TestClientKeepsDrainingWhileConcurrencyIsNonZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 1})
			return
		}
		writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 1, "current_concurrency": 2, "pending_settlements": 0})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, _ = client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || status.Applied {
		t.Fatalf("unexpected status: %+v err=%v", status, err)
	}
}

func TestClientKeepsDrainingWhileSettlementIsPending(t *testing.T) {
	freezeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 1})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{
				"state": "draining", "assignment_epoch": 1,
				"current_concurrency": 0, "pending_settlements": 1,
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/freeze":
			freezeCalls++
			t.Fatal("pending settlement 未清零时不得调用 freeze")
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, _ = client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || status.Applied || freezeCalls != 0 {
		t.Fatalf("unexpected settlement barrier status: status=%+v freeze_calls=%d err=%v", status, freezeCalls, err)
	}
}

func TestClientPendingSettlementManagementContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Integration-Client-ID") != "pool-client" || request.Header.Get("Authorization") != "Bearer integration-secret" {
			t.Fatal("pending request omitted integration authentication")
		}
		switch request.Method + " " + request.URL.Path {
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/settlements":
			if request.URL.Query().Get("limit") != "25" {
				t.Fatalf("unexpected pending limit %q", request.URL.RawQuery)
			}
			writeEnvelope(t, writer, []map[string]any{{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "request_id": "request-1",
				"assignment_epoch": 2, "status": "failed", "attempt_count": 1, "created_at": now, "updated_at": now,
			}})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/settlements/settlement-1":
			writeEnvelope(t, writer, map[string]any{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "request_id": "request-1",
				"assignment_epoch": 2, "status": "failed", "attempt_count": 1, "created_at": now, "updated_at": now,
				"credential": "must-not-cross-platform-contract",
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/settlements/settlement-1/resolve":
			if request.Header.Get("Idempotency-Key") != "resolve-1" {
				t.Fatal("resolve omitted operation idempotency key")
			}
			var command application.ResolvePendingSettlementCommand
			if err := json.NewDecoder(request.Body).Decode(&command); err != nil {
				t.Fatal(err)
			}
			if command.OperationID != "resolve-1" || command.Reason != "usage verified" || command.Evidence != "ticket-123" {
				t.Fatalf("unexpected resolve command: %+v", command)
			}
			writeEnvelope(t, writer, map[string]any{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "operation_id": "resolve-1",
				"actor_client_id": "pool-client", "reason": "usage verified", "evidence": "ticket-123", "resolved_at": now,
				"credential": "must-not-cross-platform-contract",
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	items, err := client.ListPendingSettlements(context.Background(), "seat-1", 25)
	if err != nil || len(items) != 1 || items[0].SettlementID != "settlement-1" {
		t.Fatalf("unexpected pending list: items=%+v err=%v", items, err)
	}
	detail, err := client.GetPendingSettlement(context.Background(), "seat-1", "settlement-1")
	if err != nil || detail.RequestID != "request-1" {
		t.Fatalf("unexpected pending detail: item=%+v err=%v", detail, err)
	}
	resolution, err := client.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", application.ResolvePendingSettlementCommand{
		OperationID: "resolve-1", Reason: "usage verified", Evidence: "ticket-123",
	})
	if err != nil || resolution.OperationID != "resolve-1" {
		t.Fatalf("unexpected resolution: resolution=%+v err=%v", resolution, err)
	}
	encoded, _ := json.Marshal(struct {
		Detail     *application.PendingSettlement    `json:"detail"`
		Resolution *application.SettlementResolution `json:"resolution"`
	}{Detail: detail, Resolution: resolution})
	if strings.Contains(string(encoded), "credential") || strings.Contains(string(encoded), "must-not-cross-platform-contract") {
		t.Fatalf("pending DTO leaked upstream credential field: %s", encoded)
	}
}

func TestClientMapsAssignmentToRotateContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/integrations/trusted-pools/seats/seat-1/rotate" {
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		var body struct {
			TargetEpoch uint64 `json:"target_epoch"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.TargetEpoch != 4 {
			t.Fatalf("unexpected target epoch %d", body.TargetEpoch)
		}
		writeEnvelope(t, writer, map[string]any{"seat": map[string]any{"state": "active", "assignment_epoch": 4},
			"credential": "must-not-be-retained", "access_credential_rotated": true})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := client.Assign(context.Background(), application.AssignmentCommand{OperationID: "op-rotate", SeatID: "seat-1", AssignmentEpoch: 3})
	if err != nil || !result.AccessCredentialRotationComplete || result.Credential != "must-not-be-retained" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
}

func TestClientReplaysAmbiguousAssignmentFromOriginalFrozenEpoch(t *testing.T) {
	rotateCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/rotate":
			rotateCalls++
			if rotateCalls == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 503, "reason": "TEMPORARY"})
				return
			}
			writeEnvelope(t, writer, map[string]any{
				"seat":       map[string]any{"state": "active", "assignment_epoch": 2},
				"credential": "replayed-key", "access_credential_rotated": true,
			})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{"state": "frozen", "assignment_epoch": 1, "current_concurrency": 0, "usage_snapshot": quotaSnapshot()})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Assign(context.Background(), application.AssignmentCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	if err == nil {
		t.Fatal("expected ambiguous first assignment result")
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Applied || status.Credential != "replayed-key" || rotateCalls != 2 {
		t.Fatalf("ambiguous assignment was not safely replayed: status=%+v calls=%d err=%v", status, rotateCalls, err)
	}
}

func TestClientReplaysAmbiguousSuspendStillAtActiveEpoch(t *testing.T) {
	suspendCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			suspendCalls++
			if suspendCalls == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 503, "reason": "TEMPORARY"})
				return
			}
			writeEnvelope(t, writer, map[string]any{"state": "draining", "assignment_epoch": 1})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{"state": "active", "assignment_epoch": 1, "current_concurrency": 0, "usage_snapshot": quotaSnapshot()})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	if err == nil {
		t.Fatal("expected ambiguous first suspend result")
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || suspendCalls != 2 {
		t.Fatalf("ambiguous suspend was not safely replayed: status=%+v calls=%d err=%v", status, suspendCalls, err)
	}
}

func TestClientRejectsFrozenResponseWithoutQuotaEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, map[string]any{"state": "frozen", "assignment_epoch": 1, "current_concurrency": 0})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	if _, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1}); err == nil {
		t.Fatal("accepted frozen response without quota freeze snapshot")
	}
}

func TestClientRejectsFrozenResponseWithPendingSettlement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeEnvelope(t, writer, map[string]any{
			"state": "frozen", "assignment_epoch": 1,
			"current_concurrency": 0, "pending_settlements": 1,
			"usage_snapshot": quotaSnapshot(),
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	if err == nil {
		t.Fatal("expected frozen response with pending settlement to be rejected")
	}
}

func TestClientClassifiesExplicitAndAmbiguousFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		reason    string
		ambiguous bool
		retryable bool
	}{
		{name: "validation", status: 400, reason: "INVALID_REQUEST"},
		{name: "rate limited", status: 429, reason: "RATE_LIMITED", retryable: true},
		{name: "server failure", status: 503, reason: "UPSTREAM_FAILED", retryable: true, ambiguous: true},
		{name: "idempotency in progress", status: 409, reason: "IDEMPOTENCY_IN_PROGRESS", retryable: true, ambiguous: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": test.status, "reason": test.reason})
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
			_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1"})
			gatewayErr, ok := err.(*application.GatewayError)
			if !ok || gatewayErr.Ambiguous != test.ambiguous || gatewayErr.Retryable != test.retryable || gatewayErr.StatusCode != test.status {
				t.Fatalf("unexpected error: %#v", err)
			}
		})
	}
}

func TestClientTreatsMalformedSuccessfulProvisionAsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, nil)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.ProvisionSeat(context.Background(), application.ProvisionSeatCommand{OperationID: "provision-1"})
	gatewayErr, ok := err.(*application.GatewayError)
	if !ok || !gatewayErr.Retryable || !gatewayErr.Ambiguous || gatewayErr.StatusCode != http.StatusOK {
		t.Fatalf("malformed committed response was not ambiguous: %#v", err)
	}
}

func TestClientRejectsUnsafeBaseURL(t *testing.T) {
	if _, err := NewClient("https://user:pass@example.com?token=secret", "client", "secret", nil); err == nil {
		t.Fatal("accepted unsafe base URL")
	}
}

func writeEnvelope(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": data}); err != nil {
		t.Fatal(err)
	}
}

func quotaSnapshot() map[string]any {
	return map[string]any{
		"captured_at":   time.Now().UTC(),
		"usage":         map[string]float64{"hourly": 0, "daily": 3.5, "weekly": 3.5, "monthly": 3.5},
		"window_starts": map[string]any{"hourly": nil, "daily": time.Now().UTC().Add(-time.Hour), "weekly": nil, "monthly": nil},
	}
}
