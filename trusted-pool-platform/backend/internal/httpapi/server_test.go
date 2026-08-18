package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/domain"
	"trusted-pool-platform/backend/internal/risk"
)

const testAPIKey = "test-platform-api-key-0123456789abcdef"
const testSettlementAPIKey = "test-settlement-api-key-0123456789abcdef"

func testTime(value time.Time) *time.Time { return &value }

func TestWriteDomainErrorPreservesGatewayConflictAndRetryableCategories(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		reason string
	}{
		{name: "conflict", err: &application.GatewayError{Reason: "conflict", StatusCode: http.StatusConflict}, status: http.StatusConflict, reason: "UPSTREAM_CONFLICT"},
		{name: "ambiguous", err: &application.GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}, status: http.StatusServiceUnavailable, reason: "UPSTREAM_RESULT_RETRYABLE"},
		{name: "rejected", err: &application.GatewayError{Reason: "api_key=upstream-secret", StatusCode: http.StatusForbidden}, status: http.StatusBadRequest, reason: "UPSTREAM_REJECTED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeDomainError(response, test.err)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.reason) {
				t.Fatalf("unexpected gateway error mapping: status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "upstream-secret") {
				t.Fatalf("upstream error detail leaked: %s", response.Body.String())
			}
		})
	}
}

func TestWriteDomainErrorMapsWorkflowErrorsAndRedactsUnknownDependencies(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		reason string
	}{
		{name: "not found", err: application.ErrWorkflowNotFound, status: http.StatusNotFound, reason: "WORKFLOW_NOT_FOUND"},
		{name: "hash drift", err: application.ErrWorkflowHashDrift, status: http.StatusConflict, reason: "WORKFLOW_INTENT_CONFLICT"},
		{name: "target conflict", err: application.ErrWorkflowTargetConflict, status: http.StatusConflict, reason: "WORKFLOW_TARGET_CONFLICT"},
		{name: "invalid state", err: application.ErrWorkflowInvalidState, status: http.StatusConflict, reason: "WORKFLOW_STATE_CONFLICT"},
		{name: "lease held", err: application.ErrWorkflowLeaseHeld, status: http.StatusConflict, reason: "WORKFLOW_LEASE_HELD"},
		{name: "stale fence", err: application.ErrWorkflowStaleFence, status: http.StatusConflict, reason: "WORKFLOW_STALE_FENCE"},
		{name: "corrupt state", err: application.ErrWorkflowCorruptState, status: http.StatusServiceUnavailable, reason: "WORKFLOW_CORRUPT_STATE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeDomainError(response, test.err)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.reason) {
				t.Fatalf("unexpected workflow mapping: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	response := httptest.NewRecorder()
	writeDomainError(response, errors.New("postgres password=secret internal detail"))
	body := response.Body.String()
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, "DEPENDENCY_UNAVAILABLE") {
		t.Fatalf("unexpected dependency mapping: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, "password=secret") || strings.Contains(body, "internal detail") {
		t.Fatalf("dependency detail leaked: %s", body)
	}
}

func TestWriteDomainErrorMapsPersistedOperationFailuresStably(t *testing.T) {
	tests := []struct {
		code   string
		status int
		reason string
	}{
		{code: "UPSTREAM_CONFLICT", status: http.StatusConflict, reason: "UPSTREAM_CONFLICT"},
		{code: "UPSTREAM_RESULT_AMBIGUOUS", status: http.StatusServiceUnavailable, reason: "UPSTREAM_RESULT_RETRYABLE"},
		{code: "UPSTREAM_RETRYABLE", status: http.StatusServiceUnavailable, reason: "UPSTREAM_RESULT_RETRYABLE"},
		{code: "UPSTREAM_REJECTED", status: http.StatusBadRequest, reason: "UPSTREAM_REJECTED"},
		{code: "UPSTREAM_GATEWAY_ERROR", status: http.StatusBadGateway, reason: "UPSTREAM_GATEWAY_ERROR"},
		{code: "PROVISION_GATEWAY_UNAVAILABLE", status: http.StatusServiceUnavailable, reason: "PROVISION_GATEWAY_UNAVAILABLE"},
		{code: "UPSTREAM_RESPONSE_INVALID", status: http.StatusBadGateway, reason: "UPSTREAM_RESPONSE_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeDomainError(response, &application.PersistentOperationError{Code: test.code})
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.reason) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

type apiGateway struct{}

type postgresModeCoordinator struct{ *application.Coordinator }

func (postgresModeCoordinator) StorageStatus() string { return "postgres" }

type failingReadCoordinator struct {
	*application.Coordinator
	err error
}

func (c failingReadCoordinator) Seat(context.Context, string) (*domain.Seat, error) {
	return nil, c.err
}

func (c failingReadCoordinator) Operation(context.Context, string) (*application.Operation, bool, error) {
	return nil, false, c.err
}

func (apiGateway) ProvisionSeat(_ context.Context, command application.ProvisionSeatCommand) (application.ProvisionGatewayResult, error) {
	return application.ProvisionGatewayResult{
		ExternalPoolID: command.PoolID, ExternalSeatID: command.SeatID,
		State: "active", AssignmentEpoch: command.AssignmentEpoch, Credential: "initial-access-key",
	}, nil
}

func (apiGateway) AcknowledgeProvisionCredential(_ context.Context, command application.ProvisionCredentialAckCommand) (application.ProvisionCredentialAckResult, error) {
	return application.ProvisionCredentialAckResult{
		ExternalSeatID: command.SeatID, ProvisionOperationID: command.ProvisionOperationID,
		ClaimOperationID: command.ClaimOperationID, ClaimedBy: command.ClaimedBy,
		CredentialFingerprint: command.CredentialFingerprint,
		CredentialClaimed:     true, ClaimedAt: time.Now().UTC(),
	}, nil
}

func (apiGateway) Suspend(_ context.Context, command application.SuspendCommand) (application.SuspendResult, error) {
	return application.SuspendResult{Freeze: &domain.FreezeSnapshot{
		OperationID: command.OperationID, AssignmentEpoch: command.AssignmentEpoch,
		Usage: map[string]float64{"daily": 1.25}, WindowStarts: map[string]*time.Time{"daily": testTime(time.Now().Add(-time.Hour))}, CapturedAt: time.Now(),
	}}, nil
}

func (apiGateway) Assign(_ context.Context, _ application.AssignmentCommand) (application.AssignmentResult, error) {
	return application.AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-access-key"}, nil
}

func (apiGateway) OperationStatus(context.Context, string) (application.GatewayOperationResult, error) {
	return application.GatewayOperationResult{}, nil
}

func (apiGateway) ListPendingSettlements(_ context.Context, seatID string, limit int) ([]application.PendingSettlement, error) {
	return []application.PendingSettlement{{
		SeatID: 7, ExternalSeatID: seatID, SettlementID: "settlement-1", RequestID: "request-1",
		AssignmentEpoch: 2, Status: "failed", AttemptCount: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}}, nil
}

func (apiGateway) GetPendingSettlement(_ context.Context, seatID, settlementID string) (*application.PendingSettlement, error) {
	return &application.PendingSettlement{
		SeatID: 7, ExternalSeatID: seatID, SettlementID: settlementID, RequestID: "request-1",
		AssignmentEpoch: 2, Status: "failed", AttemptCount: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}, nil
}

func (apiGateway) ResolvePendingSettlement(_ context.Context, seatID, settlementID string, command application.ResolvePendingSettlementCommand) (*application.SettlementResolution, error) {
	return &application.SettlementResolution{
		SeatID: 7, ExternalSeatID: seatID, SettlementID: settlementID, OperationID: command.OperationID,
		ActorClientID: "trusted-pool-platform", Reason: command.Reason, Evidence: command.Evidence, ResolvedAt: time.Now().UTC(),
	}, nil
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	aggregator, err := risk.NewAggregator([]byte(strings.Repeat("f", 32)), risk.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := credentials.NewLocalKeyWrapper([]byte(strings.Repeat("k", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := credentials.NewManager(wrapper, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(application.NewCoordinator(apiGateway{}, time.Now, manager), aggregator, manager, testAPIKey, testSettlementAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, body any, operationID string) *httptest.ResponseRecorder {
	return requestJSONWithKey(t, handler, method, path, body, operationID, testAPIKey)
}

func requestJSONWithKey(t *testing.T, handler http.Handler, method, path string, body any, operationID, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &payload)
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Content-Type", "application/json")
	if operationID != "" {
		request.Header.Set("Idempotency-Key", operationID)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestServerPendingSettlementManagementUsesIndependentResolveKey(t *testing.T) {
	server := newTestServer(t)
	list := requestJSON(t, server.Handler(), http.MethodGet, "/api/v1/seats/seat-1/settlements?limit=20", nil, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "settlement-1") {
		t.Fatalf("pending list failed: %d %s", list.Code, list.Body.String())
	}
	detail := requestJSON(t, server.Handler(), http.MethodGet, "/api/v1/seats/seat-1/settlements/settlement-1", nil, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "request-1") {
		t.Fatalf("pending detail failed: %d %s", detail.Code, detail.Body.String())
	}
	body := map[string]any{"operation_id": "resolve-1", "reason": "usage verified", "evidence": "ticket-123"}
	ordinary := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/settlements/settlement-1/resolve", body, "")
	if ordinary.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary API key resolved settlement: %d %s", ordinary.Code, ordinary.Body.String())
	}
	resolved := requestJSONWithKey(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/settlements/settlement-1/resolve", body, "", testSettlementAPIKey)
	if resolved.Code != http.StatusOK || !strings.Contains(resolved.Body.String(), "resolve-1") || strings.Contains(resolved.Body.String(), "credential") {
		t.Fatalf("unsafe settlement resolution response: %d %s", resolved.Code, resolved.Body.String())
	}
	invalid := requestJSONWithKey(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/settlements/settlement-1/resolve",
		map[string]any{"operation_id": "resolve-2", "reason": "", "evidence": "ticket-124"}, "", testSettlementAPIKey)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("incomplete settlement resolution accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestPostgresModeRejectsMemoryOnlyCredentialWorkflows(t *testing.T) {
	server := newTestServer(t)
	memoryCoordinator, ok := server.coordinator.(*application.Coordinator)
	if !ok {
		t.Fatalf("unexpected test coordinator %T", server.coordinator)
	}
	server.coordinator = postgresModeCoordinator{Coordinator: memoryCoordinator}
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/credential-batches"},
		{http.MethodGet, "/api/v1/credential-batches/batch-1"},
		{http.MethodPost, "/api/v1/credential-batches/batch-1/activate"},
		{http.MethodPost, "/api/v1/credential-batches/batch-1/retire"},
		{http.MethodPost, "/api/v1/control-rotation-evidence"},
	}
	for _, test := range tests {
		response := requestJSON(t, server.Handler(), test.method, test.path, nil, "")
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "PERSISTENT_WORKFLOW_UNSUPPORTED") {
			t.Errorf("%s %s: status=%d body=%s", test.method, test.path, response.Code, response.Body.String())
		}
	}
}

func TestServerReadDatabaseFailuresReturnRedacted503(t *testing.T) {
	server := newTestServer(t)
	server.coordinator = failingReadCoordinator{
		Coordinator: server.coordinator.(*application.Coordinator),
		err:         errors.New("postgres password=secret connection failure"),
	}
	for _, path := range []string{"/api/v1/seats/seat-1", "/api/v1/operations/op-1"} {
		response := requestJSON(t, server.Handler(), http.MethodGet, path, nil, "")
		body := response.Body.String()
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, "DEPENDENCY_UNAVAILABLE") {
			t.Errorf("%s: status=%d body=%s", path, response.Code, body)
		}
		if strings.Contains(body, "password=secret") || strings.Contains(body, "connection failure") {
			t.Errorf("%s leaked database detail: %s", path, body)
		}
	}
}

func TestServerHealthAndAuthentication(t *testing.T) {
	server := newTestServer(t)
	health := httptest.NewRecorder()
	server.Handler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status %d", health.Code)
	}

	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/seats", strings.NewReader(`{}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status %d", unauthorized.Code)
	}
}

func TestServerSeatWorkflowRequiresFreezeBeforeEveryChange(t *testing.T) {
	server := newTestServer(t)
	created := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats", map[string]any{
		"id": "seat-1", "pool_id": "pool-1", "owner_user_id": "owner-1", "operation_id": "provision-seat-1",
		"existing_group_id": 7, "subscription_expires_at": time.Now().Add(24 * time.Hour).UTC(),
	}, "")
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), "credential_claim_token") || strings.Contains(created.Body.String(), "initial-access-key") {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	beforeFreeze := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/actions/assign-temporary", map[string]any{
		"target_user_id": "temp-1",
	}, "op-temp-early")
	if beforeFreeze.Code != http.StatusConflict {
		t.Fatalf("assignment bypassed freeze: %d %s", beforeFreeze.Code, beforeFreeze.Body.String())
	}

	frozen := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/actions/suspend", nil, "op-freeze")
	if frozen.Code != http.StatusOK {
		t.Fatalf("freeze status=%d body=%s", frozen.Code, frozen.Body.String())
	}
	assigned := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/actions/assign-temporary", map[string]any{
		"target_user_id": "temp-1",
	}, "op-temp")
	if assigned.Code != http.StatusOK {
		t.Fatalf("assign status=%d body=%s", assigned.Code, assigned.Body.String())
	}

	restoreWithoutFreeze := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-1/actions/restore", nil, "op-restore")
	if restoreWithoutFreeze.Code != http.StatusConflict {
		t.Fatalf("restore bypassed second freeze: %d %s", restoreWithoutFreeze.Code, restoreWithoutFreeze.Body.String())
	}
}

func TestServerRiskAndCredentialResponsesDoNotExposeSensitiveInput(t *testing.T) {
	server := newTestServer(t)
	riskResponse := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/risk-windows", map[string]any{
		"id": "obs-1", "seat_id": "seat-1", "assignment_epoch": 1,
		"fingerprint": "raw-device-secret", "concurrency": 2, "requests": 3,
		"observed_at": time.Now().UTC(),
	}, "")
	if riskResponse.Code != http.StatusAccepted || strings.Contains(riskResponse.Body.String(), "raw-device-secret") {
		t.Fatalf("unsafe risk response: %d %s", riskResponse.Code, riskResponse.Body.String())
	}

	batchResponse := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/credential-batches", map[string]any{
		"pool_id": "pool-1", "account_ref": "account-1", "batch_type": "LOGIN",
		"version": 1, "membership_epoch": 1, "key_ref": "local-kek-v1",
		"payload": map[string]any{"password": "credential-secret"},
	}, "")
	body := batchResponse.Body.String()
	if batchResponse.Code != http.StatusCreated || strings.Contains(body, "credential-secret") || strings.Contains(body, "ciphertext") || strings.Contains(body, "wrapped_dek") {
		t.Fatalf("unsafe credential response: %d %s", batchResponse.Code, body)
	}
}

func TestServerRequiresIdempotencyKeyForSeatActions(t *testing.T) {
	server := newTestServer(t)
	response := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/missing/actions/suspend", nil, "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "IDEMPOTENCY_KEY_REQUIRED") {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestServerCredentialClaimIsTargetBoundAndOneTime(t *testing.T) {
	server := newTestServer(t)
	_ = requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats", map[string]any{
		"id": "seat-claim", "pool_id": "pool-1", "owner_user_id": "owner-1", "operation_id": "provision-seat-claim",
		"existing_group_id": 7, "subscription_expires_at": time.Now().Add(24 * time.Hour).UTC(),
	}, "")
	_ = requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-claim/actions/suspend", nil, "freeze-claim")
	assigned := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/seats/seat-claim/actions/assign-temporary", map[string]any{
		"target_user_id": "temp-1",
	}, "assign-claim")
	var envelope struct {
		Data struct {
			ClaimToken string `json:"credential_claim_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(assigned.Body.Bytes(), &envelope); err != nil || envelope.Data.ClaimToken == "" {
		t.Fatalf("assignment omitted claim token: %s err=%v", assigned.Body.String(), err)
	}
	status := requestJSON(t, server.Handler(), http.MethodGet, "/api/v1/operations/assign-claim", nil, "")
	if strings.Contains(status.Body.String(), envelope.Data.ClaimToken) || strings.Contains(status.Body.String(), "rotated-access-key") {
		t.Fatalf("operation status exposed credential material: %s", status.Body.String())
	}
	wrongTarget := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/operations/assign-claim/credential-ack", map[string]any{
		"target_user_id": "other-user", "claim_token": envelope.Data.ClaimToken,
	}, "")
	if wrongTarget.Code == http.StatusOK {
		t.Fatal("credential was delivered to a different target member")
	}
	delivered := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/operations/assign-claim/credential-ack", map[string]any{
		"target_user_id": "temp-1", "claim_token": envelope.Data.ClaimToken,
	}, "")
	if delivered.Code != http.StatusOK || !strings.Contains(delivered.Body.String(), "rotated-access-key") {
		t.Fatalf("credential claim failed: %d %s", delivered.Code, delivered.Body.String())
	}
	replayed := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/operations/assign-claim/credential-ack", map[string]any{
		"target_user_id": "temp-1", "claim_token": envelope.Data.ClaimToken,
	}, "")
	if replayed.Code == http.StatusOK || strings.Contains(replayed.Body.String(), "rotated-access-key") {
		t.Fatalf("credential claim was replayable: %d %s", replayed.Code, replayed.Body.String())
	}
}

func TestServerIssuesVerifiableControlRotationEvidence(t *testing.T) {
	server := newTestServer(t)
	batchTypes := []credentials.BatchType{
		credentials.BatchLogin, credentials.BatchMFA, credentials.BatchRecovery, credentials.BatchOwnership,
	}
	for _, batchType := range batchTypes {
		oldBatch, err := server.credentials.Seal(context.Background(), credentials.SealRequest{
			PoolID: "pool-1", AccountRef: "account-1", Type: batchType,
			Version: 1, MembershipEpoch: 1, KeyRef: "local-kek-v1", Plaintext: []byte("old"),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = server.credentials.Activate(oldBatch.ID)
		_, _ = server.credentials.Retire(oldBatch.ID)
		newBatch, err := server.credentials.Seal(context.Background(), credentials.SealRequest{
			PoolID: "pool-1", AccountRef: "account-1", Type: batchType,
			Version: 2, MembershipEpoch: 2, KeyRef: "local-kek-v1", Plaintext: []byte("new"),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = server.credentials.Activate(newBatch.ID)
	}
	response := requestJSON(t, server.Handler(), http.MethodPost, "/api/v1/control-rotation-evidence", map[string]any{
		"pool_id": "pool-1", "account_ref": "account-1",
		"from_membership_epoch": 1, "to_membership_epoch": 2,
		"provider_attestation_ref": "provider-ticket-1",
	}, "")
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), "retired_batch_ids") || !strings.Contains(response.Body.String(), "active_batch_ids") {
		t.Fatalf("control rotation evidence was not issued: %d %s", response.Code, response.Body.String())
	}
}
