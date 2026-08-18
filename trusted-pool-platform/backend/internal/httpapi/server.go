package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/domain"
	"trusted-pool-platform/backend/internal/risk"
)

const maxRequestBytes = 1 << 20

type Server struct {
	coordinator          Coordinator
	risk                 *risk.Aggregator
	credentials          *credentials.Manager
	apiKeyHash           [32]byte
	settlementAPIKeyHash [32]byte
	handler              http.Handler
}

type Coordinator interface {
	ProvisionSeat(context.Context, application.ProvisionSeatCommand) (*application.ProvisionSeatResult, error)
	Seat(context.Context, string) (*domain.Seat, error)
	ListPendingSettlements(context.Context, string, int) ([]application.PendingSettlement, error)
	GetPendingSettlement(context.Context, string, string) (*application.PendingSettlement, error)
	ResolvePendingSettlement(context.Context, string, string, application.ResolvePendingSettlementCommand) (*application.SettlementResolution, error)
	Suspend(context.Context, string, string) (*application.Operation, error)
	AssignTemporary(context.Context, string, string, string) (*application.Operation, error)
	Restore(context.Context, string, string) (*application.Operation, error)
	ReplacePermanently(context.Context, string, string, string, string) (*application.Operation, error)
	Operation(context.Context, string) (*application.Operation, bool, error)
	Reconcile(context.Context, string) (*application.Operation, error)
	AcknowledgeCredential(context.Context, string, string, string) (*application.CredentialDelivery, error)
}

func NewServer(coordinator Coordinator, riskAggregator *risk.Aggregator, credentialManager *credentials.Manager, apiKey, settlementAPIKey string) (*Server, error) {
	if coordinator == nil || riskAggregator == nil || credentialManager == nil {
		return nil, errors.New("coordinator, risk aggregator and credential manager are required")
	}
	if len(apiKey) < 32 {
		return nil, errors.New("API key must contain at least 32 characters")
	}
	if len(settlementAPIKey) < 32 {
		return nil, errors.New("settlement API key must contain at least 32 characters")
	}
	apiKeyHash := sha256.Sum256([]byte(apiKey))
	settlementAPIKeyHash := sha256.Sum256([]byte(settlementAPIKey))
	if subtle.ConstantTimeCompare(apiKeyHash[:], settlementAPIKeyHash[:]) == 1 {
		return nil, errors.New("settlement API key must differ from the regular API key")
	}
	server := &Server{
		coordinator:          coordinator,
		risk:                 riskAggregator,
		credentials:          credentialManager,
		apiKeyHash:           apiKeyHash,
		settlementAPIKeyHash: settlementAPIKeyHash,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.health)
	mux.HandleFunc("POST /api/v1/seats", server.createSeat)
	mux.HandleFunc("GET /api/v1/seats/{id}", server.getSeat)
	mux.HandleFunc("GET /api/v1/seats/{id}/settlements", server.listPendingSettlements)
	mux.HandleFunc("GET /api/v1/seats/{id}/settlements/{settlement_id}", server.getPendingSettlement)
	mux.HandleFunc("POST /api/v1/seats/{id}/settlements/{settlement_id}/resolve", server.resolvePendingSettlement)
	mux.HandleFunc("POST /api/v1/seats/{id}/actions/suspend", server.suspendSeat)
	mux.HandleFunc("POST /api/v1/seats/{id}/actions/assign-temporary", server.assignTemporary)
	mux.HandleFunc("POST /api/v1/seats/{id}/actions/restore", server.restore)
	mux.HandleFunc("POST /api/v1/seats/{id}/actions/replace", server.replace)
	mux.HandleFunc("GET /api/v1/operations/{id}", server.getOperation)
	mux.HandleFunc("POST /api/v1/operations/{id}/reconcile", server.reconcile)
	mux.HandleFunc("POST /api/v1/operations/{id}/credential-ack", server.ackCredential)
	mux.HandleFunc("POST /api/v1/risk-windows", server.recordRisk)
	mux.HandleFunc("GET /api/v1/seats/{id}/risk-summary", server.riskSummary)
	mux.HandleFunc("POST /api/v1/credential-batches", server.sealBatch)
	mux.HandleFunc("GET /api/v1/credential-batches/{id}", server.getBatch)
	mux.HandleFunc("POST /api/v1/credential-batches/{id}/activate", server.activateBatch)
	mux.HandleFunc("POST /api/v1/credential-batches/{id}/retire", server.retireBatch)
	mux.HandleFunc("POST /api/v1/control-rotation-evidence", server.issueControlRotationEvidence)
	server.handler = server.authenticate(mux)
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			next.ServeHTTP(writer, request)
			return
		}
		header := request.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(writer, http.StatusUnauthorized, "UNAUTHORIZED", "缺少服务访问凭据")
			return
		}
		provided := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))))
		expected := s.apiKeyHash
		if isSettlementResolveRequest(request) {
			// 人工解除结算屏障使用独立平台密钥，普通服务密钥不能取得该权限。
			expected = s.settlementAPIKeyHash
		}
		if subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
			writeError(writer, http.StatusUnauthorized, "UNAUTHORIZED", "服务访问凭据无效")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func isSettlementResolveRequest(request *http.Request) bool {
	if request == nil || request.Method != http.MethodPost {
		return false
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	return len(parts) == 7 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "seats" &&
		parts[4] == "settlements" && parts[6] == "resolve"
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	storage := "memory"
	if provider, ok := s.coordinator.(interface{ StorageStatus() string }); ok {
		storage = provider.StorageStatus()
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "storage": storage})
}

func (s *Server) createSeat(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID                    string    `json:"id"`
		PoolID                string    `json:"pool_id"`
		OwnerUserID           string    `json:"owner_user_id"`
		OperationID           string    `json:"operation_id"`
		ExistingGroupID       int64     `json:"existing_group_id"`
		PrincipalConcurrency  int       `json:"principal_concurrency"`
		PrincipalRPMLimit     int       `json:"principal_rpm_limit"`
		SubscriptionExpiresAt time.Time `json:"subscription_expires_at"`
		APIKeyQuota           float64   `json:"api_key_quota"`
		APIKeyRateLimit5h     float64   `json:"api_key_rate_limit_5h"`
		APIKeyRateLimit1d     float64   `json:"api_key_rate_limit_1d"`
		APIKeyRateLimit7d     float64   `json:"api_key_rate_limit_7d"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	result, err := s.coordinator.ProvisionSeat(request.Context(), application.ProvisionSeatCommand{
		OperationID: body.OperationID, SeatID: body.ID, PoolID: body.PoolID, OwnerUserID: body.OwnerUserID,
		ExistingGroupID: body.ExistingGroupID, PrincipalConcurrency: body.PrincipalConcurrency,
		PrincipalRPMLimit: body.PrincipalRPMLimit, SubscriptionExpiresAt: body.SubscriptionExpiresAt,
		APIKeyQuota: body.APIKeyQuota, APIKeyRateLimit5h: body.APIKeyRateLimit5h,
		APIKeyRateLimit1d: body.APIKeyRateLimit1d, APIKeyRateLimit7d: body.APIKeyRateLimit7d,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, result)
}

func (s *Server) getSeat(writer http.ResponseWriter, request *http.Request) {
	seat, err := s.coordinator.Seat(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, seat)
}

func (s *Server) listPendingSettlements(writer http.ResponseWriter, request *http.Request) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	items, err := s.coordinator.ListPendingSettlements(request.Context(), request.PathValue("id"), limit)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, items)
}

func (s *Server) getPendingSettlement(writer http.ResponseWriter, request *http.Request) {
	item, err := s.coordinator.GetPendingSettlement(request.Context(), request.PathValue("id"), request.PathValue("settlement_id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (s *Server) resolvePendingSettlement(writer http.ResponseWriter, request *http.Request) {
	var command application.ResolvePendingSettlementCommand
	if !decodeJSON(writer, request, &command) {
		return
	}
	resolution, err := s.coordinator.ResolvePendingSettlement(
		request.Context(), request.PathValue("id"), request.PathValue("settlement_id"), command,
	)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, resolution)
}

func (s *Server) suspendSeat(writer http.ResponseWriter, request *http.Request) {
	s.runOperation(writer, request, func(operationID string) (*application.Operation, error) {
		return s.coordinator.Suspend(request.Context(), operationID, request.PathValue("id"))
	})
}

func (s *Server) assignTemporary(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		TargetUserID string `json:"target_user_id"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	s.runOperation(writer, request, func(operationID string) (*application.Operation, error) {
		return s.coordinator.AssignTemporary(request.Context(), operationID, request.PathValue("id"), body.TargetUserID)
	})
}

func (s *Server) restore(writer http.ResponseWriter, request *http.Request) {
	s.runOperation(writer, request, func(operationID string) (*application.Operation, error) {
		return s.coordinator.Restore(request.Context(), operationID, request.PathValue("id"))
	})
}

func (s *Server) replace(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		TargetUserID               string `json:"target_user_id"`
		ControlRotationEvidenceRef string `json:"control_rotation_evidence_ref"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	s.runOperation(writer, request, func(operationID string) (*application.Operation, error) {
		return s.coordinator.ReplacePermanently(request.Context(), operationID, request.PathValue("id"), body.TargetUserID, body.ControlRotationEvidenceRef)
	})
}

func (s *Server) runOperation(writer http.ResponseWriter, request *http.Request, run func(string) (*application.Operation, error)) {
	operationID := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if operationID == "" || len(operationID) > 128 {
		writeError(writer, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key 必填且不能超过 128 字符")
		return
	}
	operation, err := run(operationID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	status := http.StatusOK
	if operation.Status == application.OperationRunning || operation.Status == application.OperationReconcileRequired {
		status = http.StatusAccepted
	}
	writeJSON(writer, status, operation)
}

func (s *Server) getOperation(writer http.ResponseWriter, request *http.Request) {
	operation, ok, err := s.coordinator.Operation(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !ok {
		writeError(writer, http.StatusNotFound, "OPERATION_NOT_FOUND", "操作不存在")
		return
	}
	writeJSON(writer, http.StatusOK, operation)
}

func (s *Server) reconcile(writer http.ResponseWriter, request *http.Request) {
	operation, err := s.coordinator.Reconcile(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, operation)
}

func (s *Server) ackCredential(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		TargetUserID string `json:"target_user_id"`
		ClaimToken   string `json:"claim_token"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	delivery, err := s.coordinator.AcknowledgeCredential(request.Context(), request.PathValue("id"), body.TargetUserID, body.ClaimToken)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, delivery)
}

func (s *Server) recordRisk(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID              string    `json:"id"`
		SeatID          string    `json:"seat_id"`
		AssignmentEpoch uint64    `json:"assignment_epoch"`
		Fingerprint     string    `json:"fingerprint"`
		Concurrency     int       `json:"concurrency"`
		Requests        int       `json:"requests"`
		ObservedAt      time.Time `json:"observed_at"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	summary, err := s.risk.Record(risk.Observation{
		ID: body.ID, SeatID: body.SeatID, AssignmentEpoch: body.AssignmentEpoch,
		Fingerprint: body.Fingerprint, Concurrency: body.Concurrency, Requests: body.Requests, ObservedAt: body.ObservedAt,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, summary)
}

func (s *Server) riskSummary(writer http.ResponseWriter, request *http.Request) {
	epoch, err := strconv.ParseUint(request.URL.Query().Get("assignment_epoch"), 10, 64)
	if err != nil || epoch == 0 {
		writeError(writer, http.StatusBadRequest, "INVALID_ASSIGNMENT_EPOCH", "assignment_epoch 必须为正整数")
		return
	}
	writeJSON(writer, http.StatusOK, s.risk.Summaries(request.PathValue("id"), epoch))
}

func (s *Server) sealBatch(writer http.ResponseWriter, request *http.Request) {
	if s.rejectPersistentMemoryWorkflow(writer) {
		return
	}
	var body struct {
		PoolID          string                `json:"pool_id"`
		AccountRef      string                `json:"account_ref"`
		Type            credentials.BatchType `json:"batch_type"`
		Version         uint64                `json:"version"`
		MembershipEpoch uint64                `json:"membership_epoch"`
		KeyRef          string                `json:"key_ref"`
		Payload         json.RawMessage       `json:"payload"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	batch, err := s.credentials.Seal(request.Context(), credentials.SealRequest{
		PoolID: body.PoolID, AccountRef: body.AccountRef, Type: body.Type, Version: body.Version,
		MembershipEpoch: body.MembershipEpoch, KeyRef: body.KeyRef, Plaintext: body.Payload,
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, batchMetadata(batch))
}

func (s *Server) getBatch(writer http.ResponseWriter, request *http.Request) {
	if s.rejectPersistentMemoryWorkflow(writer) {
		return
	}
	batch, ok := s.credentials.Get(request.PathValue("id"))
	if !ok {
		writeError(writer, http.StatusNotFound, "CREDENTIAL_BATCH_NOT_FOUND", "凭据批次不存在")
		return
	}
	writeJSON(writer, http.StatusOK, batchMetadata(batch))
}

func (s *Server) activateBatch(writer http.ResponseWriter, request *http.Request) {
	if s.rejectPersistentMemoryWorkflow(writer) {
		return
	}
	batch, err := s.credentials.Activate(request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, batchMetadata(batch))
}

func (s *Server) retireBatch(writer http.ResponseWriter, request *http.Request) {
	if s.rejectPersistentMemoryWorkflow(writer) {
		return
	}
	batch, err := s.credentials.Retire(request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, batchMetadata(batch))
}

func (s *Server) issueControlRotationEvidence(writer http.ResponseWriter, request *http.Request) {
	if s.rejectPersistentMemoryWorkflow(writer) {
		return
	}
	var body struct {
		PoolID                 string `json:"pool_id"`
		AccountRef             string `json:"account_ref"`
		FromEpoch              uint64 `json:"from_membership_epoch"`
		ToEpoch                uint64 `json:"to_membership_epoch"`
		ProviderAttestationRef string `json:"provider_attestation_ref"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	evidence, err := s.credentials.IssueControlRotationEvidence(body.PoolID, body.AccountRef, body.FromEpoch, body.ToEpoch, body.ProviderAttestationRef)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, evidence)
}

func (s *Server) rejectPersistentMemoryWorkflow(writer http.ResponseWriter) bool {
	provider, ok := s.coordinator.(interface{ StorageStatus() string })
	if !ok || !strings.EqualFold(strings.TrimSpace(provider.StorageStatus()), "postgres") {
		return false
	}
	writeDomainError(writer, application.ErrPersistentWorkflowUnsupported)
	return true
}

func batchMetadata(batch *credentials.Batch) map[string]any {
	return map[string]any{
		"id": batch.ID, "pool_id": batch.PoolID, "account_ref": batch.AccountRef,
		"batch_type": batch.Type, "version": batch.Version, "membership_epoch": batch.MembershipEpoch,
		"state": batch.State, "algorithm": batch.Algorithm, "key_ref": batch.KeyRef,
		"aad_hash": batch.AADHash, "created_at": batch.CreatedAt,
		"activated_at": batch.ActivatedAt, "retired_at": batch.RetiredAt,
	}
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_JSON", "请求 JSON 无效")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(writer, http.StatusBadRequest, "INVALID_JSON", "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

func writeDomainError(writer http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	reason := "DEPENDENCY_UNAVAILABLE"
	message := "持久化或密钥服务暂时不可用"
	var operationErr *application.PersistentOperationError
	switch {
	case errors.As(err, &operationErr):
		status, reason, message = persistentOperationHTTPError(operationErr.Code)
	case errors.Is(err, application.ErrSeatNotFound):
		status, reason = http.StatusNotFound, "SEAT_NOT_FOUND"
	case errors.Is(err, application.ErrOperationConflict):
		status, reason = http.StatusConflict, "IDEMPOTENCY_KEY_CONFLICT"
		message = err.Error()
	case errors.Is(err, application.ErrWorkflowNotFound):
		status, reason, message = http.StatusNotFound, "WORKFLOW_NOT_FOUND", err.Error()
	case errors.Is(err, application.ErrWorkflowHashDrift):
		status, reason, message = http.StatusConflict, "WORKFLOW_INTENT_CONFLICT", err.Error()
	case errors.Is(err, application.ErrWorkflowTargetConflict):
		status, reason, message = http.StatusConflict, "WORKFLOW_TARGET_CONFLICT", err.Error()
	case errors.Is(err, application.ErrWorkflowInvalidState):
		status, reason, message = http.StatusConflict, "WORKFLOW_STATE_CONFLICT", err.Error()
	case errors.Is(err, application.ErrWorkflowLeaseHeld):
		status, reason, message = http.StatusConflict, "WORKFLOW_LEASE_HELD", err.Error()
	case errors.Is(err, application.ErrWorkflowStaleFence):
		status, reason, message = http.StatusConflict, "WORKFLOW_STALE_FENCE", err.Error()
	case errors.Is(err, application.ErrWorkflowInvalidData):
		status, reason, message = http.StatusBadRequest, "WORKFLOW_INVALID_DATA", err.Error()
	case errors.Is(err, application.ErrWorkflowCorruptState):
		status, reason, message = http.StatusServiceUnavailable, "WORKFLOW_CORRUPT_STATE", "持久化工作流状态不完整"
	case errors.Is(err, application.ErrPersistentWorkflowUnsupported):
		status, reason, message = http.StatusServiceUnavailable, "PERSISTENT_WORKFLOW_UNSUPPORTED", err.Error()
	case errors.Is(err, application.ErrSettlementGatewayUnavailable):
		status, reason = http.StatusServiceUnavailable, "SETTLEMENT_GATEWAY_UNAVAILABLE"
	case errors.Is(err, application.ErrInvalidSettlementRequest):
		status, reason = http.StatusBadRequest, "INVALID_SETTLEMENT_REQUEST"
	case errors.Is(err, application.ErrProvisionGatewayUnavailable):
		status, reason = http.StatusServiceUnavailable, "PROVISION_GATEWAY_UNAVAILABLE"
	case errors.Is(err, application.ErrInvalidProvisionRequest):
		status, reason = http.StatusBadRequest, "INVALID_PROVISION_REQUEST"
	case errors.Is(err, application.ErrCredentialClaimExpired):
		status, reason = http.StatusGone, "CREDENTIAL_CLAIM_EXPIRED"
	case errors.Is(err, application.ErrCredentialClaimPending):
		status, reason = http.StatusServiceUnavailable, "CREDENTIAL_CLAIM_RECONCILE_REQUIRED"
	case errors.Is(err, application.ErrCredentialClaimRejected):
		status, reason = http.StatusConflict, "CREDENTIAL_CLAIM_REJECTED"
	case errors.Is(err, domain.ErrFreezeRequired), errors.Is(err, domain.ErrInvalidTransition), errors.Is(err, domain.ErrStaleSnapshot), errors.Is(err, domain.ErrInvalidSnapshot):
		status, reason = http.StatusConflict, "INVALID_SEAT_STATE"
	default:
		var gatewayErr *application.GatewayError
		if errors.As(err, &gatewayErr) {
			switch {
			case gatewayErr.StatusCode == http.StatusConflict:
				status, reason, message = http.StatusConflict, "UPSTREAM_CONFLICT", "上游资源或幂等状态冲突"
			case gatewayErr.Retryable || gatewayErr.Ambiguous:
				status, reason, message = http.StatusServiceUnavailable, "UPSTREAM_RESULT_RETRYABLE", "上游结果未知或暂时不可用"
			case gatewayErr.StatusCode >= 500:
				status, reason, message = http.StatusBadGateway, "UPSTREAM_GATEWAY_ERROR", "上游服务返回错误"
			default:
				status, reason, message = http.StatusBadRequest, "UPSTREAM_REJECTED", "上游拒绝请求"
			}
		}
	}
	if reason != "DEPENDENCY_UNAVAILABLE" && message == "持久化或密钥服务暂时不可用" {
		message = err.Error()
	}
	writeError(writer, status, reason, message)
}

func persistentOperationHTTPError(code string) (int, string, string) {
	switch strings.TrimSpace(code) {
	case "UPSTREAM_CONFLICT":
		return http.StatusConflict, "UPSTREAM_CONFLICT", "上游目标状态冲突"
	case "UPSTREAM_RESULT_AMBIGUOUS", "UPSTREAM_RETRYABLE":
		return http.StatusServiceUnavailable, "UPSTREAM_RESULT_RETRYABLE", "上游结果暂不确定，请使用同一幂等键重试"
	case "UPSTREAM_REJECTED":
		return http.StatusBadRequest, "UPSTREAM_REJECTED", "上游拒绝了开通请求"
	case "UPSTREAM_GATEWAY_ERROR":
		return http.StatusBadGateway, "UPSTREAM_GATEWAY_ERROR", "上游网关暂时不可用"
	case "PROVISION_GATEWAY_UNAVAILABLE":
		return http.StatusServiceUnavailable, "PROVISION_GATEWAY_UNAVAILABLE", "席位开通网关不可用"
	case "UPSTREAM_RESPONSE_INVALID":
		return http.StatusBadGateway, "UPSTREAM_RESPONSE_INVALID", "上游开通结果未通过一致性校验"
	default:
		return http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "持久化或密钥服务暂时不可用"
	}
}

func writeError(writer http.ResponseWriter, status int, reason, message string) {
	writeJSON(writer, status, map[string]any{"reason": reason, "message": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"data": value})
}
