package sub2api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/domain"
)

const maxResponseBytes = 1 << 20

type operationRef struct {
	seatID      string
	poolID      string
	suspend     bool
	targetEpoch uint64
	assignment  *application.AssignmentCommand
}

type Client struct {
	baseURL           *url.URL
	clientID          string
	integrationSecret string
	httpClient        *http.Client
	mu                sync.Mutex
	operations        map[string]operationRef
}

// SettlementReadClient 只暴露只读对账能力，不能被误用为 resolve 客户端。
type SettlementReadClient struct{ client *Client }

// SettlementResolveClient 只暴露高权限 resolve，凭据必须与普通控制面及只读客户端分离。
type SettlementResolveClient struct {
	client  *Client
	actorID string
}

func NewClient(baseURL, clientID, integrationSecret string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("Sub2API base URL is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("Sub2API base URL must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Sub2API base URL cannot contain credentials, query or fragment")
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(integrationSecret) == "" {
		return nil, errors.New("Sub2API integration client id and secret are required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		baseURL: parsed, clientID: clientID, integrationSecret: integrationSecret,
		httpClient: &clientCopy, operations: make(map[string]operationRef),
	}, nil
}

func NewSettlementReadClient(baseURL, clientID, secret string, httpClient *http.Client) (*SettlementReadClient, error) {
	client, err := NewClient(baseURL, clientID, secret, httpClient)
	if err != nil {
		return nil, err
	}
	return &SettlementReadClient{client: client}, nil
}

func NewSettlementResolveClient(baseURL, clientID, secret string, httpClient *http.Client) (*SettlementResolveClient, error) {
	client, err := NewClient(baseURL, clientID, secret, httpClient)
	if err != nil {
		return nil, err
	}
	return &SettlementResolveClient{client: client, actorID: strings.TrimSpace(clientID)}, nil
}

func (c *Client) Suspend(ctx context.Context, command application.SuspendCommand) (application.SuspendResult, error) {
	c.remember(command.OperationID, operationRef{
		seatID: command.SeatID, poolID: command.PoolID, suspend: true, targetEpoch: command.AssignmentEpoch,
	})
	var data seatResponse
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/suspend",
		command.OperationID, map[string]string{"operation_id": command.OperationID}, &data)
	if err != nil {
		return application.SuspendResult{}, err
	}
	if err := validateSuspendSeatResponse(command, data); err != nil {
		return application.SuspendResult{}, err
	}
	switch strings.ToLower(data.State) {
	case "draining":
		currentConcurrency, pendingSettlements, countersErr := observedDrainCounters(data)
		if countersErr != nil {
			return application.SuspendResult{}, &application.GatewayError{
				Reason: "Sub2API draining response omitted barrier counters", Retryable: true, Ambiguous: true,
			}
		}
		return application.SuspendResult{
			Draining: true, CurrentConcurrency: currentConcurrency,
			PendingSettlements: pendingSettlements,
		}, nil
	case "frozen":
		snapshot, err := freezeSnapshot(command.OperationID, data)
		if err != nil {
			return application.SuspendResult{}, err
		}
		return application.SuspendResult{Freeze: snapshot}, nil
	default:
		return application.SuspendResult{}, fmt.Errorf("unexpected Sub2API suspend state %q", data.State)
	}
}

func (c *Client) ProvisionSeat(ctx context.Context, command application.ProvisionSeatCommand) (application.ProvisionGatewayResult, error) {
	var data struct {
		Seat       seatResponse `json:"seat"`
		Credential string       `json:"credential"`
	}
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/provision",
		command.OperationID, command, &data)
	if err != nil {
		return application.ProvisionGatewayResult{}, err
	}
	if data.Seat.ExternalSeatID != command.SeatID || data.Seat.ExternalPoolID != command.PoolID ||
		strings.ToLower(data.Seat.State) != "active" || data.Seat.AssignmentEpoch != command.AssignmentEpoch ||
		data.Seat.PrincipalUserID <= 0 || data.Seat.SubscriptionID <= 0 || data.Seat.APIKeyID <= 0 ||
		data.Seat.LastOperationID != command.OperationID {
		return application.ProvisionGatewayResult{}, &application.GatewayError{
			Reason: "Sub2API provision response does not match requested seat", Retryable: true, Ambiguous: true,
		}
	}
	if data.Credential == "" {
		return application.ProvisionGatewayResult{}, &application.GatewayError{
			Reason: "Sub2API provision response omitted credential", Retryable: true, Ambiguous: true,
		}
	}
	return application.ProvisionGatewayResult{
		ExternalPoolID: data.Seat.ExternalPoolID, ExternalSeatID: data.Seat.ExternalSeatID,
		State: data.Seat.State, AssignmentEpoch: data.Seat.AssignmentEpoch,
		PrincipalUserID: data.Seat.PrincipalUserID, SubscriptionID: data.Seat.SubscriptionID,
		APIKeyID: data.Seat.APIKeyID, ActiveAPIKeyVersion: data.Seat.AssignmentEpoch,
		LastOperationID: data.Seat.LastOperationID,
		Credential:      data.Credential,
	}, nil
}

func (c *Client) AcknowledgeProvisionCredential(ctx context.Context, command application.ProvisionCredentialAckCommand) (application.ProvisionCredentialAckResult, error) {
	var result application.ProvisionCredentialAckResult
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/provision-credential/ack",
		command.ClaimOperationID, command, &result)
	if err != nil {
		return application.ProvisionCredentialAckResult{}, err
	}
	if result.ExternalSeatID != command.SeatID || result.ProvisionOperationID != command.ProvisionOperationID ||
		result.ClaimOperationID != command.ClaimOperationID || result.ClaimedBy != command.ClaimedBy ||
		result.CredentialFingerprint != command.CredentialFingerprint ||
		!result.CredentialClaimed || result.ClaimedAt.IsZero() {
		return application.ProvisionCredentialAckResult{}, &application.GatewayError{
			Reason: "Sub2API credential acknowledgement response is invalid", Retryable: true, Ambiguous: true,
		}
	}
	return result, nil
}

func (c *Client) Assign(ctx context.Context, command application.AssignmentCommand) (application.AssignmentResult, error) {
	if err := validateAssignmentCommand(command); err != nil {
		return application.AssignmentResult{}, err
	}
	commandCopy := command
	c.remember(command.OperationID, operationRef{
		seatID: command.SeatID, poolID: command.PoolID, targetEpoch: command.AssignmentEpoch + 1,
		assignment: &commandCopy,
	})
	return c.rotateAssignment(ctx, command)
}

func (c *Client) rotateAssignment(ctx context.Context, command application.AssignmentCommand) (application.AssignmentResult, error) {
	// Sub2API 当前以 rotate 原子轮换 Seat API Key；平台成员关系仍由本服务维护。
	targetEpoch := command.AssignmentEpoch + 1
	var data struct {
		Seat                    seatResponse `json:"seat"`
		Credential              string       `json:"credential"`
		AccessCredentialRotated bool         `json:"access_credential_rotated"`
	}
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/rotate",
		command.OperationID,
		struct {
			application.AssignmentCommand
			TargetEpoch uint64 `json:"target_epoch"`
		}{command, targetEpoch}, &data)
	if err != nil {
		return application.AssignmentResult{}, err
	}
	if err := validateAssignmentSeatResponse(command, data.Seat, true); err != nil ||
		data.Credential == "" || !data.AccessCredentialRotated {
		if err != nil {
			return application.AssignmentResult{}, err
		}
		return application.AssignmentResult{}, &application.GatewayError{
			Reason: "Sub2API rotation response omitted credential rotation evidence", Retryable: true, Ambiguous: true,
		}
	}
	return application.AssignmentResult{
		ExternalPoolID: data.Seat.ExternalPoolID, ExternalSeatID: data.Seat.ExternalSeatID,
		State: data.Seat.State, AssignmentEpoch: data.Seat.AssignmentEpoch,
		PrincipalUserID: data.Seat.PrincipalUserID, SubscriptionID: data.Seat.SubscriptionID,
		APIKeyID: data.Seat.APIKeyID, ActiveAPIKeyVersion: data.Seat.AssignmentEpoch,
		LastOperationID:                  data.Seat.LastOperationID,
		AccessCredentialRotationComplete: true, Credential: data.Credential,
	}, nil
}

func (c *SettlementReadClient) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]application.PendingSettlement, error) {
	query := url.Values{}
	query.Set("limit", fmt.Sprintf("%d", limit))
	items := make([]application.PendingSettlement, 0)
	err := c.client.doWithQuery(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements",
		query, "", nil, &items)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(items))
	for i := range items {
		if err := validatePendingSettlement(items[i], seatID, ""); err != nil {
			return nil, err
		}
		if _, duplicate := seen[items[i].SettlementID]; duplicate {
			return nil, invalidSettlementGatewayResponse("Sub2API settlement list contains duplicate ids")
		}
		seen[items[i].SettlementID] = struct{}{}
	}
	return items, nil
}

func (c *SettlementReadClient) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*application.PendingSettlement, error) {
	item := new(application.PendingSettlement)
	err := c.client.do(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements/"+url.PathEscape(settlementID),
		"", nil, item)
	if err != nil {
		return nil, err
	}
	if err := validatePendingSettlement(*item, seatID, settlementID); err != nil {
		return nil, err
	}
	return item, nil
}

func (c *SettlementResolveClient) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, command application.ResolvePendingSettlementCommand) (*application.SettlementResolution, error) {
	resolution := new(application.SettlementResolution)
	// operation_id 同时放入请求体和幂等头；上游用独立 settlement:resolve scope 鉴权并审计调用方。
	err := c.client.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements/"+url.PathEscape(settlementID)+"/resolve",
		command.OperationID, command, resolution)
	if err != nil {
		return nil, err
	}
	if resolution.SeatID <= 0 || resolution.ExternalSeatID != seatID || resolution.SettlementID != settlementID ||
		resolution.OperationID != command.OperationID || resolution.ActorClientID != c.actorID ||
		resolution.AssignmentEpoch != command.ExpectedAssignmentEpoch || resolution.RequestID != command.ExpectedRequestID ||
		resolution.Reason != command.Reason || resolution.Evidence != command.Evidence || resolution.ResolvedAt.IsZero() {
		return nil, invalidSettlementGatewayResponse("Sub2API settlement resolution response does not match intent")
	}
	return resolution, nil
}

func validatePendingSettlement(item application.PendingSettlement, seatID, settlementID string) error {
	if item.SeatID <= 0 || item.ExternalSeatID != seatID || item.AssignmentEpoch <= 0 ||
		strings.TrimSpace(item.SettlementID) == "" || (settlementID != "" && item.SettlementID != settlementID) ||
		strings.TrimSpace(item.RequestID) == "" || strings.TrimSpace(item.Status) == "" || item.AttemptCount < 0 ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
		return invalidSettlementGatewayResponse("Sub2API pending settlement response is invalid")
	}
	return nil
}

func invalidSettlementGatewayResponse(reason string) error {
	return &application.GatewayError{Reason: reason, Retryable: true, Ambiguous: true, StatusCode: http.StatusOK}
}

func (c *Client) OperationStatus(ctx context.Context, operationID string) (application.GatewayOperationResult, error) {
	reference, ok := c.operation(operationID)
	if !ok {
		return application.GatewayOperationResult{}, errors.New("Sub2API operation reference is unavailable")
	}
	if reference.suspend {
		return c.ReconcileSuspend(ctx, application.SuspendCommand{
			OperationID: operationID, SeatID: reference.seatID, PoolID: reference.poolID,
			AssignmentEpoch: reference.targetEpoch,
		})
	}
	if reference.assignment != nil {
		result, err := c.ReconcileAssignment(ctx, *reference.assignment)
		if err != nil {
			return application.GatewayOperationResult{}, err
		}
		return application.GatewayOperationResult{
			Applied: true, AccessCredentialRotationComplete: result.AccessCredentialRotationComplete,
			Credential: result.Credential,
		}, nil
	}
	data, err := c.drainStatus(ctx, reference.seatID)
	if err != nil {
		return application.GatewayOperationResult{}, err
	}
	state := strings.ToLower(data.State)
	if (state == "active" && data.AssignmentEpoch == reference.targetEpoch) ||
		(state == "frozen" && data.AssignmentEpoch+1 == reference.targetEpoch) {
		// 使用相同 operation_id 和 target_epoch 重放 rotate，Sub2API 会返回同一凭据。
		var rotated struct {
			Seat                    seatResponse `json:"seat"`
			Credential              string       `json:"credential"`
			AccessCredentialRotated bool         `json:"access_credential_rotated"`
		}
		err := c.do(ctx, http.MethodPost,
			"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(reference.seatID)+"/rotate",
			operationID, map[string]any{"operation_id": operationID, "target_epoch": reference.targetEpoch}, &rotated)
		if err != nil {
			return application.GatewayOperationResult{}, err
		}
		if rotated.Credential == "" || !rotated.AccessCredentialRotated {
			return application.GatewayOperationResult{}, errors.New("Sub2API rotation replay omitted credential")
		}
		return application.GatewayOperationResult{Applied: true, AccessCredentialRotationComplete: true, Credential: rotated.Credential}, nil
	}
	return application.GatewayOperationResult{}, nil
}

// ReconcileAssignment 仅依赖持久化 request/case 重建的显式命令，不读取进程内 operation map。
// FROZEN 源 epoch 与 ACTIVE 目标 epoch 都用相同 operation_id 重放 rotate，以取回同一凭据。
func (c *Client) ReconcileAssignment(ctx context.Context, command application.AssignmentCommand) (application.AssignmentResult, error) {
	if err := validateAssignmentCommand(command); err != nil {
		return application.AssignmentResult{}, err
	}
	seat, err := c.drainStatus(ctx, command.SeatID)
	if err != nil {
		return application.AssignmentResult{}, err
	}
	state := strings.ToLower(seat.State)
	switch state {
	case "frozen":
		if err := validateAssignmentSeatResponse(command, seat, false); err != nil {
			return application.AssignmentResult{}, err
		}
	case "active":
		if err := validateAssignmentSeatResponse(command, seat, true); err != nil {
			return application.AssignmentResult{}, err
		}
	default:
		return application.AssignmentResult{}, &application.GatewayError{
			Reason: "Sub2API assignment state is not safely replayable", Retryable: true, Ambiguous: true,
		}
	}
	return c.rotateAssignment(ctx, command)
}

// ReconcileSuspend 不依赖 Client 的进程内 operations map。持久化 worker 从 operation
// request_snapshot 重建 command，因此进程重启后仍能用相同幂等键继续 drain/freeze。
func (c *Client) ReconcileSuspend(ctx context.Context, command application.SuspendCommand) (application.GatewayOperationResult, error) {
	command.OperationID = strings.TrimSpace(command.OperationID)
	command.SeatID = strings.TrimSpace(command.SeatID)
	if command.OperationID == "" || command.SeatID == "" || command.AssignmentEpoch == 0 {
		return application.GatewayOperationResult{}, errors.New("suspend reconciliation command is invalid")
	}
	data, err := c.drainStatus(ctx, command.SeatID)
	if err != nil {
		return application.GatewayOperationResult{}, err
	}
	if err := validateSuspendSeatResponse(command, data); err != nil {
		return application.GatewayOperationResult{}, err
	}
	if strings.EqualFold(data.State, "active") && data.AssignmentEpoch == command.AssignmentEpoch {
		// 首次 suspend 结果不明且上游仍是原 active epoch 时，用同一幂等键安全重投。
		result, retryErr := c.Suspend(ctx, command)
		if retryErr != nil {
			return application.GatewayOperationResult{}, retryErr
		}
		return application.GatewayOperationResult{
			Applied: result.Freeze != nil, Draining: result.Draining,
			CurrentConcurrency: result.CurrentConcurrency, PendingSettlements: result.PendingSettlements,
			Freeze: result.Freeze,
		}, nil
	}
	if strings.EqualFold(data.State, "frozen") {
		snapshot, snapshotErr := freezeSnapshot(command.OperationID, data)
		if snapshotErr != nil {
			return application.GatewayOperationResult{}, snapshotErr
		}
		return application.GatewayOperationResult{Applied: true, Freeze: snapshot}, nil
	}
	if !strings.EqualFold(data.State, "draining") {
		return application.GatewayOperationResult{}, fmt.Errorf("unexpected drain state %q epoch=%d", data.State, data.AssignmentEpoch)
	}
	// 严格并发租约或持久结算屏障任一未清零，都必须继续排空，不能提前调用 freeze。
	currentConcurrency, pendingSettlements, countersErr := observedDrainCounters(data)
	if countersErr != nil {
		return application.GatewayOperationResult{}, &application.GatewayError{
			Reason: "Sub2API drain status omitted barrier counters", Retryable: true, Ambiguous: true,
		}
	}
	if currentConcurrency != 0 || pendingSettlements != 0 {
		return application.GatewayOperationResult{
			Draining: true, CurrentConcurrency: currentConcurrency,
			PendingSettlements: pendingSettlements,
		}, nil
	}
	var frozen seatResponse
	err = c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/freeze",
		command.OperationID, map[string]string{"operation_id": command.OperationID}, &frozen)
	if err != nil {
		return application.GatewayOperationResult{}, err
	}
	if err := validateSuspendSeatResponse(command, frozen); err != nil {
		return application.GatewayOperationResult{}, err
	}
	if !strings.EqualFold(frozen.State, "frozen") {
		return application.GatewayOperationResult{}, fmt.Errorf("unexpected freeze state %q epoch=%d", frozen.State, frozen.AssignmentEpoch)
	}
	snapshot, err := freezeSnapshot(command.OperationID, frozen)
	if err != nil {
		return application.GatewayOperationResult{}, err
	}
	return application.GatewayOperationResult{Applied: true, Freeze: snapshot}, nil
}

type seatResponse struct {
	ExternalPoolID     string                  `json:"external_pool_id"`
	ExternalSeatID     string                  `json:"external_seat_id"`
	State              string                  `json:"state"`
	AssignmentEpoch    uint64                  `json:"assignment_epoch"`
	PrincipalUserID    int64                   `json:"principal_user_id"`
	SubscriptionID     int64                   `json:"subscription_id"`
	APIKeyID           int64                   `json:"api_key_id"`
	LastOperationID    string                  `json:"last_operation_id"`
	CurrentConcurrency *int                    `json:"current_concurrency"`
	PendingSettlements *int                    `json:"pending_settlements"`
	FreezeSnapshot     *freezeSnapshotResponse `json:"freeze_snapshot"`
	UsageSnapshot      *usageSnapshotResponse  `json:"usage_snapshot"`
}

func validateAssignmentCommand(command application.AssignmentCommand) error {
	if strings.TrimSpace(command.OperationID) == "" || strings.TrimSpace(command.SeatID) == "" ||
		strings.TrimSpace(command.PoolID) == "" || strings.TrimSpace(command.TargetUser) == "" ||
		command.AssignmentEpoch == 0 || command.MembershipEpoch == 0 || strings.TrimSpace(command.FreezeOperationID) == "" ||
		command.PrincipalUserID <= 0 || command.SubscriptionID <= 0 || command.APIKeyID <= 0 ||
		command.ActiveAPIKeyVersion != command.AssignmentEpoch ||
		(command.Mode != application.OperationAssignTemp && command.Mode != application.OperationRestore) || command.Permanent {
		return application.ErrWorkflowInvalidData
	}
	return nil
}

func validateAssignmentSeatResponse(command application.AssignmentCommand, seat seatResponse, rotated bool) error {
	expectedEpoch := command.AssignmentEpoch
	expectedState := "frozen"
	if rotated {
		expectedEpoch++
		expectedState = "active"
	}
	if seat.ExternalSeatID != command.SeatID || seat.ExternalPoolID != command.PoolID ||
		!strings.EqualFold(seat.State, expectedState) || seat.AssignmentEpoch != expectedEpoch ||
		seat.PrincipalUserID != command.PrincipalUserID || seat.SubscriptionID != command.SubscriptionID ||
		seat.APIKeyID != command.APIKeyID || (rotated && seat.LastOperationID != command.OperationID) {
		return &application.GatewayError{
			Reason: "Sub2API assignment response does not match persisted seat binding", Retryable: true, Ambiguous: true,
		}
	}
	return nil
}

type freezeSnapshotResponse struct {
	AssignmentEpoch uint64                `json:"assignment_epoch"`
	CapturedAt      time.Time             `json:"captured_at"`
	InFlight        int                   `json:"in_flight"`
	Usages          map[string]float64    `json:"usages"`
	WindowStarts    map[string]*time.Time `json:"window_starts"`
}

type usageSnapshotResponse struct {
	Usage        map[string]float64    `json:"usage"`
	WindowStarts map[string]*time.Time `json:"window_starts"`
	CapturedAt   time.Time             `json:"captured_at"`
}

func validateSuspendSeatResponse(command application.SuspendCommand, seat seatResponse) error {
	seatID := strings.TrimSpace(seat.ExternalSeatID)
	poolID := strings.TrimSpace(seat.ExternalPoolID)
	if seatID == "" || seatID != command.SeatID || poolID == "" || poolID != strings.TrimSpace(command.PoolID) ||
		seat.AssignmentEpoch != command.AssignmentEpoch {
		return &application.GatewayError{
			Reason: "Sub2API suspend response does not match requested seat", Retryable: true, Ambiguous: true,
		}
	}
	return nil
}

func (c *Client) drainStatus(ctx context.Context, seatID string) (seatResponse, error) {
	var data seatResponse
	err := c.do(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/drain-status",
		"", nil, &data)
	return data, err
}

func freezeSnapshot(operationID string, seat seatResponse) (*domain.FreezeSnapshot, error) {
	// FROZEN 必须证明双屏障都已清零；上游异常响应不得被平台误判为可换员。
	currentConcurrency, pendingSettlements, err := observedDrainCounters(seat)
	if err != nil {
		return nil, errors.New("Sub2API frozen response omitted concurrency or settlement evidence")
	}
	if currentConcurrency != 0 || pendingSettlements != 0 {
		return nil, errors.New("Sub2API frozen response retained concurrency or pending settlements")
	}
	evidence := seat.FreezeSnapshot
	if evidence == nil && seat.UsageSnapshot != nil {
		evidence = &freezeSnapshotResponse{
			AssignmentEpoch: seat.AssignmentEpoch,
			CapturedAt:      seat.UsageSnapshot.CapturedAt,
			InFlight:        currentConcurrency,
			Usages:          seat.UsageSnapshot.Usage,
			WindowStarts:    seat.UsageSnapshot.WindowStarts,
		}
	}
	if evidence == nil || evidence.AssignmentEpoch == 0 || evidence.CapturedAt.IsZero() || evidence.InFlight != 0 ||
		!validQuotaFreezeEvidence(evidence) {
		return nil, errors.New("Sub2API frozen response omitted valid quota freeze snapshot")
	}
	if seat.AssignmentEpoch != 0 && evidence.AssignmentEpoch != seat.AssignmentEpoch {
		return nil, errors.New("Sub2API quota freeze snapshot assignment epoch mismatch")
	}
	windowStarts := make(map[string]*time.Time, len(evidence.WindowStarts))
	for name, value := range evidence.WindowStarts {
		if value != nil {
			utc := value.UTC()
			windowStarts[name] = &utc
		} else {
			windowStarts[name] = nil
		}
	}
	return &domain.FreezeSnapshot{
		OperationID: operationID, AssignmentEpoch: evidence.AssignmentEpoch,
		Usage: evidence.Usages, WindowStarts: windowStarts,
		InFlight: evidence.InFlight, PendingSettlements: pendingSettlements,
		CapturedAt: evidence.CapturedAt.UTC(),
	}, nil
}

func observedDrainCounters(seat seatResponse) (int, int, error) {
	if seat.CurrentConcurrency == nil || seat.PendingSettlements == nil ||
		*seat.CurrentConcurrency < 0 || *seat.PendingSettlements < 0 {
		return 0, 0, errors.New("Sub2API barrier counters are missing or invalid")
	}
	return *seat.CurrentConcurrency, *seat.PendingSettlements, nil
}

func validQuotaFreezeEvidence(evidence *freezeSnapshotResponse) bool {
	if evidence == nil || len(evidence.Usages) != 4 || len(evidence.WindowStarts) != 4 {
		return false
	}
	for _, window := range []string{"hourly", "daily", "weekly", "monthly"} {
		usage, usageOK := evidence.Usages[window]
		startedAt, windowOK := evidence.WindowStarts[window]
		if !usageOK || !windowOK || usage < 0 || math.IsNaN(usage) || math.IsInf(usage, 0) ||
			(startedAt != nil && startedAt.IsZero()) {
			return false
		}
	}
	return true
}

func (c *Client) remember(operationID string, reference operationRef) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operations[operationID] = reference
}

func (c *Client) operation(operationID string) (operationRef, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reference, ok := c.operations[operationID]
	return reference, ok
}

type envelope struct {
	Code    json.RawMessage `json:"code"`
	Message string          `json:"message"`
	Reason  string          `json:"reason"`
	Data    json.RawMessage `json:"data"`
}

func (c *Client) do(ctx context.Context, method, requestPath, operationID string, body, destination any) error {
	return c.doWithQuery(ctx, method, requestPath, nil, operationID, body, destination)
}

func (c *Client) doWithQuery(ctx context.Context, method, requestPath string, query url.Values, operationID string, body, destination any) error {
	requestURL := *c.baseURL
	requestURL.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), requestPath)
	if len(query) != 0 {
		requestURL.RawQuery = query.Encode()
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), payload)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Integration-Client-ID", c.clientID)
	request.Header.Set("Authorization", "Bearer "+c.integrationSecret)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if operationID != "" {
		request.Header.Set("Idempotency-Key", operationID)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		// 请求是否到达上游无法可靠判断，不能直接按“未执行”重试。
		return &application.GatewayError{Reason: err.Error(), Retryable: true, Ambiguous: true}
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	var decoded envelope
	if err := decoder.Decode(&decoded); err != nil {
		ambiguous := response.StatusCode >= 500 || (response.StatusCode >= 200 && response.StatusCode < 300)
		return &application.GatewayError{
			Reason: "invalid Sub2API response", Retryable: ambiguous, Ambiguous: ambiguous, StatusCode: response.StatusCode,
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !successCode(decoded.Code) {
		reason := decoded.Reason
		if reason == "" {
			reason = decoded.Message
		}
		if reason == "" {
			reason = response.Status
		}
		ambiguous := response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500 ||
			(response.StatusCode == http.StatusConflict && (decoded.Reason == "IDEMPOTENCY_IN_PROGRESS" || decoded.Reason == "IDEMPOTENCY_RETRY_BACKOFF"))
		retryable := ambiguous || response.StatusCode == http.StatusTooManyRequests
		return &application.GatewayError{Reason: reason, Retryable: retryable, Ambiguous: ambiguous, StatusCode: response.StatusCode}
	}
	if destination != nil {
		if len(decoded.Data) == 0 || string(decoded.Data) == "null" {
			return &application.GatewayError{Reason: "Sub2API response omitted data", Retryable: true, Ambiguous: true, StatusCode: response.StatusCode}
		}
		if err := json.Unmarshal(decoded.Data, destination); err != nil {
			return &application.GatewayError{Reason: "decode Sub2API data: " + err.Error(), Retryable: true, Ambiguous: true, StatusCode: response.StatusCode}
		}
	}
	return nil
}

func successCode(code json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(code))
	return trimmed == "0" || trimmed == `"0"`
}
