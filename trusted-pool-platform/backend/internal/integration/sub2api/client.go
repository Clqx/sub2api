package sub2api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	suspend     bool
	targetEpoch uint64
}

type Client struct {
	baseURL           *url.URL
	clientID          string
	integrationSecret string
	httpClient        *http.Client
	mu                sync.Mutex
	operations        map[string]operationRef
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
	return &Client{
		baseURL: parsed, clientID: clientID, integrationSecret: integrationSecret,
		httpClient: httpClient, operations: make(map[string]operationRef),
	}, nil
}

func (c *Client) Suspend(ctx context.Context, command application.SuspendCommand) (application.SuspendResult, error) {
	c.remember(command.OperationID, operationRef{seatID: command.SeatID, suspend: true, targetEpoch: command.AssignmentEpoch})
	var data seatResponse
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/suspend",
		command.OperationID, map[string]string{"operation_id": command.OperationID}, &data)
	if err != nil {
		return application.SuspendResult{}, err
	}
	switch strings.ToLower(data.State) {
	case "draining":
		return application.SuspendResult{Draining: true}, nil
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
		strings.ToLower(data.Seat.State) != "active" || data.Seat.AssignmentEpoch != command.AssignmentEpoch {
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
		State: data.Seat.State, AssignmentEpoch: data.Seat.AssignmentEpoch, Credential: data.Credential,
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
	// Sub2API 当前以 rotate 原子轮换 Seat API Key；平台成员关系仍由本服务维护。
	targetEpoch := command.AssignmentEpoch + 1
	c.remember(command.OperationID, operationRef{seatID: command.SeatID, targetEpoch: targetEpoch})
	var data struct {
		Seat                    seatResponse `json:"seat"`
		Credential              string       `json:"credential"`
		AccessCredentialRotated bool         `json:"access_credential_rotated"`
	}
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(command.SeatID)+"/rotate",
		command.OperationID,
		map[string]any{"operation_id": command.OperationID, "target_epoch": targetEpoch}, &data)
	if err != nil {
		return application.AssignmentResult{}, err
	}
	if strings.ToLower(data.Seat.State) != "active" || data.Seat.AssignmentEpoch != targetEpoch {
		return application.AssignmentResult{}, fmt.Errorf("unexpected Sub2API rotation result state=%q epoch=%d", data.Seat.State, data.Seat.AssignmentEpoch)
	}
	if data.Credential == "" {
		return application.AssignmentResult{}, errors.New("Sub2API rotation response omitted credential")
	}
	if !data.AccessCredentialRotated {
		return application.AssignmentResult{}, errors.New("Sub2API rotation response omitted access credential rotation evidence")
	}
	return application.AssignmentResult{AccessCredentialRotationComplete: true, Credential: data.Credential}, nil
}

func (c *Client) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]application.PendingSettlement, error) {
	query := url.Values{}
	query.Set("limit", fmt.Sprintf("%d", limit))
	items := make([]application.PendingSettlement, 0)
	err := c.doWithQuery(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements",
		query, "", nil, &items)
	return items, err
}

func (c *Client) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*application.PendingSettlement, error) {
	item := new(application.PendingSettlement)
	err := c.do(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements/"+url.PathEscape(settlementID),
		"", nil, item)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (c *Client) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, command application.ResolvePendingSettlementCommand) (*application.SettlementResolution, error) {
	resolution := new(application.SettlementResolution)
	// operation_id 同时放入请求体和幂等头；上游用独立 settlement:resolve scope 鉴权并审计调用方。
	err := c.do(ctx, http.MethodPost,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/settlements/"+url.PathEscape(settlementID)+"/resolve",
		command.OperationID, command, resolution)
	if err != nil {
		return nil, err
	}
	return resolution, nil
}

func (c *Client) OperationStatus(ctx context.Context, operationID string) (application.GatewayOperationResult, error) {
	reference, ok := c.operation(operationID)
	if !ok {
		return application.GatewayOperationResult{}, errors.New("Sub2API operation reference is unavailable")
	}
	data, err := c.drainStatus(ctx, reference.seatID)
	if err != nil {
		return application.GatewayOperationResult{}, err
	}
	if reference.suspend {
		if strings.ToLower(data.State) == "active" && data.AssignmentEpoch == reference.targetEpoch {
			// 首次 suspend 结果不明且上游仍是原 active epoch 时，用同一幂等键安全重投。
			result, retryErr := c.Suspend(ctx, application.SuspendCommand{
				OperationID: operationID, SeatID: reference.seatID, AssignmentEpoch: reference.targetEpoch,
			})
			if retryErr != nil {
				return application.GatewayOperationResult{}, retryErr
			}
			return application.GatewayOperationResult{Applied: result.Freeze != nil, Draining: result.Draining, Freeze: result.Freeze}, nil
		}
		if strings.ToLower(data.State) == "frozen" {
			snapshot, err := freezeSnapshot(operationID, data)
			if err != nil {
				return application.GatewayOperationResult{}, err
			}
			return application.GatewayOperationResult{Applied: true, Freeze: snapshot}, nil
		}
		if strings.ToLower(data.State) != "draining" {
			return application.GatewayOperationResult{}, fmt.Errorf("unexpected drain state %q", data.State)
		}
		// 严格并发租约或持久结算屏障任一未清零，都必须继续排空，不能提前调用 freeze。
		if data.CurrentConcurrency != 0 || data.PendingSettlements != 0 {
			return application.GatewayOperationResult{Draining: true}, nil
		}
		var frozen seatResponse
		err := c.do(ctx, http.MethodPost,
			"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(reference.seatID)+"/freeze",
			operationID, map[string]string{"operation_id": operationID}, &frozen)
		if err != nil {
			return application.GatewayOperationResult{}, err
		}
		if strings.ToLower(frozen.State) != "frozen" {
			return application.GatewayOperationResult{}, fmt.Errorf("unexpected freeze state %q", frozen.State)
		}
		snapshot, err := freezeSnapshot(operationID, frozen)
		if err != nil {
			return application.GatewayOperationResult{}, err
		}
		return application.GatewayOperationResult{Applied: true, Freeze: snapshot}, nil
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

type seatResponse struct {
	ExternalPoolID     string                  `json:"external_pool_id"`
	ExternalSeatID     string                  `json:"external_seat_id"`
	State              string                  `json:"state"`
	AssignmentEpoch    uint64                  `json:"assignment_epoch"`
	CurrentConcurrency int                     `json:"current_concurrency"`
	PendingSettlements int                     `json:"pending_settlements"`
	FreezeSnapshot     *freezeSnapshotResponse `json:"freeze_snapshot"`
	UsageSnapshot      *usageSnapshotResponse  `json:"usage_snapshot"`
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

func (c *Client) drainStatus(ctx context.Context, seatID string) (seatResponse, error) {
	var data seatResponse
	err := c.do(ctx, http.MethodGet,
		"/api/v1/integrations/trusted-pools/seats/"+url.PathEscape(seatID)+"/drain-status",
		"", nil, &data)
	return data, err
}

func freezeSnapshot(operationID string, seat seatResponse) (*domain.FreezeSnapshot, error) {
	// FROZEN 必须证明双屏障都已清零；上游异常响应不得被平台误判为可换员。
	if seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
		return nil, errors.New("Sub2API frozen response retained concurrency or pending settlements")
	}
	evidence := seat.FreezeSnapshot
	if evidence == nil && seat.UsageSnapshot != nil {
		evidence = &freezeSnapshotResponse{
			AssignmentEpoch: seat.AssignmentEpoch,
			CapturedAt:      seat.UsageSnapshot.CapturedAt,
			InFlight:        seat.CurrentConcurrency,
			Usages:          seat.UsageSnapshot.Usage,
			WindowStarts:    seat.UsageSnapshot.WindowStarts,
		}
	}
	if evidence == nil || evidence.AssignmentEpoch == 0 || evidence.CapturedAt.IsZero() || evidence.InFlight != 0 ||
		len(evidence.Usages) == 0 || len(evidence.WindowStarts) == 0 {
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
		InFlight: evidence.InFlight, PendingSettlements: seat.PendingSettlements,
		CapturedAt: evidence.CapturedAt.UTC(),
	}, nil
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
