package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

const (
	TrustedPoolSeatStateActive   = "active"
	TrustedPoolSeatStateDraining = "draining"
	TrustedPoolSeatStateFrozen   = "frozen"
	TrustedPoolSeatStateRotating = "rotating"
)

var (
	ErrTrustedPoolSeatNotFound       = infraerrors.NotFound("TRUSTED_POOL_SEAT_NOT_FOUND", "trusted pool seat not found")
	ErrTrustedPoolSeatConflict       = infraerrors.Conflict("TRUSTED_POOL_SEAT_CONFLICT", "trusted pool seat binding conflicts with existing data")
	ErrTrustedPoolInvalidState       = infraerrors.Conflict("TRUSTED_POOL_INVALID_STATE", "trusted pool seat state does not allow this operation")
	ErrTrustedPoolNotDrained         = infraerrors.Conflict("TRUSTED_POOL_NOT_DRAINED", "trusted pool seat still has active requests")
	ErrTrustedPoolEpochConflict      = infraerrors.Conflict("TRUSTED_POOL_EPOCH_CONFLICT", "trusted pool assignment epoch conflict")
	ErrTrustedPoolOperationIDMissing = infraerrors.BadRequest("TRUSTED_POOL_OPERATION_ID_REQUIRED", "operation_id is required")
	ErrTrustedPoolSeatSuspended      = infraerrors.Forbidden("TRUSTED_POOL_SEAT_SUSPENDED", "trusted pool seat is not active")
	ErrTrustedPoolSettlementNotFound = infraerrors.NotFound("TRUSTED_POOL_SETTLEMENT_NOT_FOUND", "trusted pool settlement not found")
	ErrTrustedPoolCredentialClaimed  = infraerrors.Conflict("TRUSTED_POOL_CREDENTIAL_ALREADY_CLAIMED", "trusted pool provision credential was already claimed")
)

type TrustedPoolSeat struct {
	ID                 int64                     `json:"id"`
	ExternalPoolID     string                    `json:"external_pool_id"`
	ExternalSeatID     string                    `json:"external_seat_id"`
	PrincipalUserID    int64                     `json:"principal_user_id"`
	GroupID            int64                     `json:"group_id"`
	SubscriptionID     int64                     `json:"subscription_id"`
	APIKeyID           int64                     `json:"api_key_id"`
	State              string                    `json:"state"`
	AssignmentEpoch    int64                     `json:"assignment_epoch"`
	LastOperationID    string                    `json:"last_operation_id"`
	SuspendedAt        *time.Time                `json:"suspended_at,omitempty"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
	CurrentConcurrency int                       `json:"current_concurrency"`
	UsageSnapshot      *TrustedPoolUsageSnapshot `json:"usage_snapshot,omitempty"`
	PendingSettlements int                       `json:"pending_settlements"`
}

// TrustedPoolUsageSnapshot 是冻结/排空响应中的稳定订阅用量快照。
type TrustedPoolUsageSnapshot struct {
	Usage        map[string]float64 `json:"usage"`
	WindowStarts map[string]*string `json:"window_starts"`
	CapturedAt   time.Time          `json:"captured_at"`
}

type RegisterTrustedPoolSeatInput struct {
	ExternalPoolID  string `json:"external_pool_id"`
	ExternalSeatID  string `json:"external_seat_id"`
	PrincipalUserID int64  `json:"principal_user_id"`
	GroupID         int64  `json:"group_id"`
	SubscriptionID  int64  `json:"subscription_id"`
	APIKeyID        int64  `json:"api_key_id"`
	AssignmentEpoch int64  `json:"assignment_epoch"`
	OperationID     string `json:"operation_id"`
	ActorClientID   string `json:"-"`
}

// ProvisionTrustedPoolSeatInput 只允许绑定管理员预先准备好的订阅分组。
// Principal、Subscription 和 API Key 均由 Sub2API 在同一事务内创建，调用方不能注入内部资源 ID。
type ProvisionTrustedPoolSeatInput struct {
	ExternalPoolID        string    `json:"external_pool_id"`
	ExternalSeatID        string    `json:"external_seat_id"`
	ExistingGroupID       int64     `json:"existing_group_id"`
	AssignmentEpoch       int64     `json:"assignment_epoch"`
	OperationID           string    `json:"operation_id"`
	PrincipalConcurrency  int       `json:"principal_concurrency"`
	PrincipalRPMLimit     int       `json:"principal_rpm_limit"`
	SubscriptionExpiresAt time.Time `json:"subscription_expires_at"`
	APIKeyQuota           float64   `json:"api_key_quota"`
	APIKeyRateLimit5h     float64   `json:"api_key_rate_limit_5h"`
	APIKeyRateLimit1d     float64   `json:"api_key_rate_limit_1d"`
	APIKeyRateLimit7d     float64   `json:"api_key_rate_limit_7d"`

	ActorClientID         string `json:"-"`
	RequestHash           string `json:"-"`
	Credential            string `json:"-"`
	CredentialFingerprint string `json:"-"`
	PrincipalEmail        string `json:"-"`
}

type TrustedPoolProvisionResult struct {
	Seat                  *TrustedPoolSeat `json:"seat"`
	Credential            string           `json:"credential"`
	CredentialFingerprint string           `json:"credential_fingerprint"`
}

type AckTrustedPoolProvisionCredentialInput struct {
	ProvisionOperationID  string `json:"provision_operation_id"`
	ClaimOperationID      string `json:"claim_operation_id"`
	ClaimedBy             string `json:"claimed_by"`
	CredentialFingerprint string `json:"credential_fingerprint"`
	ActorClientID         string `json:"-"`
	ExternalPoolID        string `json:"-"`
}

type TrustedPoolProvisionCredentialClaim struct {
	ExternalSeatID        string    `json:"external_seat_id"`
	ProvisionOperationID  string    `json:"provision_operation_id"`
	ClaimOperationID      string    `json:"claim_operation_id"`
	ClaimedBy             string    `json:"claimed_by"`
	CredentialFingerprint string    `json:"credential_fingerprint"`
	CredentialClaimed     bool      `json:"credential_claimed"`
	ClaimedAt             time.Time `json:"claimed_at"`
}

type TrustedPoolRotationResult struct {
	Seat                    *TrustedPoolSeat `json:"seat"`
	Credential              string           `json:"credential"`
	OldCredential           string           `json:"-"`
	AccessCredentialRotated bool             `json:"access_credential_rotated"`
}

type TrustedPoolUsageRisk struct {
	ExternalSeatID         string  `json:"external_seat_id"`
	WindowHours            int     `json:"window_hours"`
	RequestCount           int64   `json:"request_count"`
	DistinctIPCount        int64   `json:"distinct_ip_count"`
	DeviceFingerprintCount int64   `json:"device_fingerprint_count"`
	ActualCostUSD          float64 `json:"actual_cost_usd"`
	CurrentConcurrency     int     `json:"current_concurrency"`
}

type TrustedPoolPendingSettlement struct {
	SeatID          int64      `json:"seat_id"`
	ExternalSeatID  string     `json:"external_seat_id"`
	SettlementID    string     `json:"settlement_id"`
	RequestID       string     `json:"request_id"`
	BillingID       *string    `json:"billing_id,omitempty"`
	AssignmentEpoch int64      `json:"assignment_epoch"`
	Status          string     `json:"status"`
	LastError       *string    `json:"last_error,omitempty"`
	AttemptCount    int        `json:"attempt_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

type ResolveTrustedPoolSettlementInput struct {
	OperationID    string `json:"operation_id"`
	ActorClientID  string `json:"-"`
	ExternalPoolID string `json:"-"`
	Reason         string `json:"reason"`
	Evidence       string `json:"evidence"`
}

type TrustedPoolSettlementResolution struct {
	SeatID         int64     `json:"seat_id"`
	ExternalSeatID string    `json:"external_seat_id"`
	SettlementID   string    `json:"settlement_id"`
	OperationID    string    `json:"operation_id"`
	ActorClientID  string    `json:"actor_client_id"`
	Reason         string    `json:"reason"`
	Evidence       string    `json:"evidence"`
	ResolvedAt     time.Time `json:"resolved_at"`
}

type TrustedPoolRepository interface {
	ProvisionSeat(ctx context.Context, input ProvisionTrustedPoolSeatInput) (*TrustedPoolProvisionResult, error)
	AckProvisionCredential(ctx context.Context, externalSeatID string, input AckTrustedPoolProvisionCredentialInput) (*TrustedPoolProvisionCredentialClaim, error)
	RegisterSeat(ctx context.Context, input RegisterTrustedPoolSeatInput) (*TrustedPoolSeat, error)
	GetSeat(ctx context.Context, externalPoolID, externalSeatID string) (*TrustedPoolSeat, error)
	GetSeatByAPIKeyID(ctx context.Context, apiKeyID int64) (*TrustedPoolSeat, error)
	GetUsageSnapshot(ctx context.Context, subscriptionID int64) (*TrustedPoolUsageSnapshot, error)
	CreatePendingSettlement(ctx context.Context, seatID int64, settlementID, requestID string, assignmentEpoch int64) error
	CompletePendingSettlement(ctx context.Context, seatID int64, settlementID string) error
	MarkPendingSettlement(ctx context.Context, seatID int64, settlementID, status, billingID, lastError string) error
	CountPendingSettlements(ctx context.Context, seatID int64) (int, error)
	ListPendingSettlements(ctx context.Context, externalPoolID, externalSeatID string, limit int) ([]TrustedPoolPendingSettlement, error)
	GetPendingSettlement(ctx context.Context, externalPoolID, externalSeatID, settlementID string) (*TrustedPoolPendingSettlement, error)
	ResolvePendingSettlement(ctx context.Context, externalSeatID, settlementID string, input ResolveTrustedPoolSettlementInput) (*TrustedPoolSettlementResolution, error)
	SuspendSeat(ctx context.Context, externalPoolID, externalSeatID, operationID string) (*TrustedPoolSeat, error)
	FreezeSeat(ctx context.Context, externalPoolID, externalSeatID, operationID string) (*TrustedPoolSeat, error)
	RotateSeatCredential(ctx context.Context, externalPoolID, externalSeatID, operationID, credential string, targetEpoch int64) (*TrustedPoolRotationResult, error)
	GetUsageRisk(ctx context.Context, externalPoolID, externalSeatID string, since time.Time) (*TrustedPoolUsageRisk, error)
}

type trustedPoolSettlementContextKey struct{}

const (
	trustedPoolSettlementUnresolved int32 = iota
	trustedPoolSettlementSettled
	trustedPoolSettlementFailed
)

// TrustedPoolSettlementTracker 汇总一次可信请求的同步结算结果；任一计费分支失败后不可恢复为成功。
type TrustedPoolSettlementTracker struct {
	state     atomic.Int32
	mu        sync.Mutex
	billingID string
	lastError string
}

// WithTrustedPoolSettlementTracker 为 Guard 请求安装结算状态，供 service 与 detached usage context 共享。
func WithTrustedPoolSettlementTracker(ctx context.Context) (context.Context, *TrustedPoolSettlementTracker) {
	if ctx == nil {
		ctx = context.Background()
	}
	tracker := new(TrustedPoolSettlementTracker)
	return context.WithValue(ctx, trustedPoolSettlementContextKey{}, tracker), tracker
}

// PropagateTrustedPoolSettlementTracker 将结算状态复制到计费任务的 detached context。
func PropagateTrustedPoolSettlementTracker(parent, target context.Context) context.Context {
	if target == nil {
		target = context.Background()
	}
	if tracker := trustedPoolSettlementTrackerFromContext(parent); tracker != nil {
		return context.WithValue(target, trustedPoolSettlementContextKey{}, tracker)
	}
	return target
}

// MarkTrustedPoolSettlementFailed 标记本请求结算失败，Guard 将保留数据库 pending barrier。
func MarkTrustedPoolSettlementFailed(ctx context.Context) {
	MarkTrustedPoolSettlementFailure(ctx, errors.New("trusted pool settlement failed"))
}

// MarkTrustedPoolSettlementFailure 保留第一条失败上下文，后续成功不能覆盖失败状态。
func MarkTrustedPoolSettlementFailure(ctx context.Context, failure error) {
	if tracker := trustedPoolSettlementTrackerFromContext(ctx); tracker != nil {
		tracker.state.Store(trustedPoolSettlementFailed)
		if failure != nil {
			tracker.mu.Lock()
			if tracker.lastError == "" {
				tracker.lastError = failure.Error()
			}
			tracker.mu.Unlock()
		}
	}
}

// MarkTrustedPoolSettlementSucceeded 只能把默认 unresolved 推进到 settled，不能清除既有失败。
func MarkTrustedPoolSettlementSucceeded(ctx context.Context) {
	if tracker := trustedPoolSettlementTrackerFromContext(ctx); tracker != nil {
		tracker.state.CompareAndSwap(trustedPoolSettlementUnresolved, trustedPoolSettlementSettled)
	}
}

// SetTrustedPoolSettlementBillingID 保存上游/计费幂等 ID，便于人工核验 pending。
func SetTrustedPoolSettlementBillingID(ctx context.Context, billingID string) {
	if tracker := trustedPoolSettlementTrackerFromContext(ctx); tracker != nil && strings.TrimSpace(billingID) != "" {
		tracker.mu.Lock()
		tracker.billingID = strings.TrimSpace(billingID)
		tracker.mu.Unlock()
	}
}

// Failed 返回是否已有任一结算分支失败。
func (t *TrustedPoolSettlementTracker) Failed() bool {
	return t == nil || t.state.Load() == trustedPoolSettlementFailed
}

// IsTrustedPoolSettlementSucceeded 供 Guard 测试与诊断确认显式完成状态；unresolved 默认返回 false。
func IsTrustedPoolSettlementSucceeded(ctx context.Context) bool {
	tracker := trustedPoolSettlementTrackerFromContext(ctx)
	return tracker != nil && tracker.state.Load() == trustedPoolSettlementSettled
}

func (t *TrustedPoolSettlementTracker) snapshot() (state int32, billingID, lastError string) {
	if t == nil {
		return trustedPoolSettlementFailed, "", "trusted pool settlement tracker is unavailable"
	}
	state = t.state.Load()
	t.mu.Lock()
	billingID, lastError = t.billingID, t.lastError
	t.mu.Unlock()
	return state, billingID, lastError
}

func trustedPoolSettlementTrackerFromContext(ctx context.Context) *TrustedPoolSettlementTracker {
	if ctx == nil {
		return nil
	}
	tracker, _ := ctx.Value(trustedPoolSettlementContextKey{}).(*TrustedPoolSettlementTracker)
	return tracker
}

// trackTrustedPoolSettlementResult 统一捕获 RecordUsage 返回错误与 panic。
// panic 仍向上抛出，由 handler 既有恢复逻辑处理，但 pending barrier 会保留。
func trackTrustedPoolSettlementResult(ctx context.Context, err *error) {
	if recovered := recover(); recovered != nil {
		MarkTrustedPoolSettlementFailure(ctx, fmt.Errorf("record usage panic: %v", recovered))
		panic(recovered)
	}
	if err != nil && *err != nil {
		MarkTrustedPoolSettlementFailure(ctx, *err)
		return
	}
	MarkTrustedPoolSettlementSucceeded(ctx)
}

// AcquireGatewayAdmission 在读取 Seat gate 前先登记请求租约，闭合“读到 0 后又进入请求”的冻结竞态。
// 非可信池 Key 不改变原有网关行为。
func (s *TrustedPoolIntegrationService) AcquireGatewayAdmission(ctx context.Context, apiKeyID int64) (func(), bool, error) {
	if s == nil || s.repo == nil || apiKeyID <= 0 {
		return nil, false, nil
	}
	seat, err := s.repo.GetSeatByAPIKeyID(ctx, apiKeyID)
	if err != nil {
		if errors.Is(err, ErrTrustedPoolSeatNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if seat == nil {
		return nil, false, nil
	}
	if s.concurrency == nil {
		return nil, true, infraerrors.ServiceUnavailable("TRUSTED_POOL_GATE_UNAVAILABLE", "trusted pool gateway admission is unavailable")
	}
	release, err := s.concurrency.TrackAPIKeySlotStrict(ctx, apiKeyID)
	if err != nil {
		return nil, true, infraerrors.ServiceUnavailable("TRUSTED_POOL_GATE_UNAVAILABLE", "cannot register trusted pool request lease").WithCause(err)
	}
	// 租约登记后必须重读数据库，不能复用首次仅用于识别 Seat 的结果。
	latest, err := s.repo.GetSeatByAPIKeyID(ctx, apiKeyID)
	if err != nil {
		release()
		return nil, true, err
	}
	if latest == nil || latest.ID != seat.ID || latest.State != TrustedPoolSeatStateActive {
		release()
		return nil, true, ErrTrustedPoolSeatSuspended
	}
	tracker := trustedPoolSettlementTrackerFromContext(ctx)
	if tracker == nil {
		release()
		return nil, true, infraerrors.ServiceUnavailable("TRUSTED_POOL_GATE_UNAVAILABLE", "trusted pool settlement tracker is unavailable")
	}
	settlementID := generateRequestID()
	requestID, _ := ctx.Value(ctxkey.RequestID).(string)
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = settlementID
	}
	if err := s.repo.CreatePendingSettlement(ctx, latest.ID, settlementID, requestID, latest.AssignmentEpoch); err != nil {
		release()
		if errors.Is(err, ErrTrustedPoolSeatSuspended) {
			return nil, true, ErrTrustedPoolSeatSuspended
		}
		return nil, true, infraerrors.ServiceUnavailable("TRUSTED_POOL_GATE_UNAVAILABLE", "cannot create trusted pool settlement barrier").WithCause(err)
	}
	var finalizeOnce sync.Once
	return func() {
		finalizeOnce.Do(func() {
			completeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			state, billingID, lastError := tracker.snapshot()
			if state == trustedPoolSettlementSettled {
				if err := s.repo.CompletePendingSettlement(completeCtx, latest.ID, settlementID); err != nil {
					// 删除失败后必须回写失败证据和尝试次数；原 pending 仍会阻断 Freeze。
					logger.LegacyPrintf("service.trusted_pool", "failed to complete settlement %s for seat %d: %v", settlementID, latest.ID, err)
					markCtx, markCancel := context.WithTimeout(context.Background(), 2*time.Second)
					if markErr := s.repo.MarkPendingSettlement(markCtx, latest.ID, settlementID, "failed", billingID, "pending settlement completion failed"); markErr != nil {
						logger.LegacyPrintf("service.trusted_pool", "failed to record completion error for settlement %s on seat %d: %v", settlementID, latest.ID, markErr)
					}
					markCancel()
				}
			} else {
				status := "pending"
				if state == trustedPoolSettlementFailed {
					status = "failed"
				}
				if lastError == "" {
					lastError = "synchronous settlement was not completed"
				}
				if err := s.repo.MarkPendingSettlement(completeCtx, latest.ID, settlementID, status, billingID, lastError); err != nil {
					// 标记失败不影响 fail-close：原始 pending 行仍存在并被 DrainStatus 计数。
					logger.LegacyPrintf("service.trusted_pool", "failed to mark settlement %s for seat %d: %v", settlementID, latest.ID, err)
				}
			}
			release()
		})
	}, true, nil
}

type TrustedPoolIntegrationService struct {
	repo        TrustedPoolRepository
	concurrency *ConcurrencyService
	apiKeys     *APIKeyService
	subs        *SubscriptionService
}

func trustedPoolAuthorizedPrincipal(ctx context.Context, requestedPoolID string) (TrustedPoolIntegrationPrincipal, error) {
	principal, ok := TrustedPoolIntegrationPrincipalFromContext(ctx)
	if !ok {
		return TrustedPoolIntegrationPrincipal{}, ErrTrustedPoolUnauthorized
	}
	requestedPoolID = strings.TrimSpace(requestedPoolID)
	if requestedPoolID != "" && requestedPoolID != principal.ExternalPoolID {
		return TrustedPoolIntegrationPrincipal{}, ErrTrustedPoolForbidden
	}
	return principal, nil
}

func NewTrustedPoolIntegrationService(repo TrustedPoolRepository, concurrency *ConcurrencyService, apiKeys *APIKeyService, subs *SubscriptionService) *TrustedPoolIntegrationService {
	return &TrustedPoolIntegrationService{repo: repo, concurrency: concurrency, apiKeys: apiKeys, subs: subs}
}

func (s *TrustedPoolIntegrationService) ProvisionSeat(ctx context.Context, input ProvisionTrustedPoolSeatInput) (*TrustedPoolProvisionResult, error) {
	input.ExternalPoolID = strings.TrimSpace(input.ExternalPoolID)
	input.ExternalSeatID = strings.TrimSpace(input.ExternalSeatID)
	input.OperationID = strings.TrimSpace(input.OperationID)
	principal, err := trustedPoolAuthorizedPrincipal(ctx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	input.ActorClientID = principal.ClientID
	if input.OperationID == "" {
		return nil, ErrTrustedPoolOperationIDMissing
	}
	if input.ExternalPoolID == "" || input.ExternalSeatID == "" || input.ExistingGroupID <= 0 || input.ActorClientID == "" {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PROVISION_INVALID", "trusted pool provision input is incomplete")
	}
	if len(input.ExternalPoolID) > 128 || len(input.ExternalSeatID) > 128 || len(input.OperationID) > 128 || len(input.ActorClientID) > 64 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_IDENTIFIER_INVALID", "trusted pool identifier is too long")
	}
	if input.AssignmentEpoch <= 0 {
		input.AssignmentEpoch = 1
	}
	if input.PrincipalConcurrency <= 0 || input.PrincipalRPMLimit < 0 ||
		!input.SubscriptionExpiresAt.After(time.Now()) || input.SubscriptionExpiresAt.After(MaxExpiresAt) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PROVISION_INVALID", "trusted pool principal limits or subscription expiry are invalid")
	}
	for _, limit := range []float64{input.APIKeyQuota, input.APIKeyRateLimit5h, input.APIKeyRateLimit1d, input.APIKeyRateLimit7d} {
		if math.IsNaN(limit) || math.IsInf(limit, 0) || limit < 0 {
			return nil, infraerrors.BadRequest("TRUSTED_POOL_PROVISION_INVALID", "trusted pool API key limits must be finite and non-negative")
		}
	}

	hashPayload := struct {
		Version               int     `json:"version"`
		ExternalPoolID        string  `json:"external_pool_id"`
		ExternalSeatID        string  `json:"external_seat_id"`
		ExistingGroupID       int64   `json:"existing_group_id"`
		AssignmentEpoch       int64   `json:"assignment_epoch"`
		PrincipalConcurrency  int     `json:"principal_concurrency"`
		PrincipalRPMLimit     int     `json:"principal_rpm_limit"`
		SubscriptionExpiresAt string  `json:"subscription_expires_at"`
		APIKeyQuota           float64 `json:"api_key_quota"`
		APIKeyRateLimit5h     float64 `json:"api_key_rate_limit_5h"`
		APIKeyRateLimit1d     float64 `json:"api_key_rate_limit_1d"`
		APIKeyRateLimit7d     float64 `json:"api_key_rate_limit_7d"`
	}{
		Version: 1, ExternalPoolID: input.ExternalPoolID, ExternalSeatID: input.ExternalSeatID,
		ExistingGroupID: input.ExistingGroupID, AssignmentEpoch: input.AssignmentEpoch,
		PrincipalConcurrency: input.PrincipalConcurrency, PrincipalRPMLimit: input.PrincipalRPMLimit,
		SubscriptionExpiresAt: input.SubscriptionExpiresAt.UTC().Format(time.RFC3339Nano),
		APIKeyQuota:           input.APIKeyQuota, APIKeyRateLimit5h: input.APIKeyRateLimit5h,
		APIKeyRateLimit1d: input.APIKeyRateLimit1d, APIKeyRateLimit7d: input.APIKeyRateLimit7d,
	}
	canonical, err := json.Marshal(hashPayload)
	if err != nil {
		return nil, infraerrors.InternalServer("TRUSTED_POOL_PROVISION_FAILED", "failed to canonicalize trusted pool provision request").WithCause(err)
	}
	digest := sha256.Sum256(canonical)
	input.RequestHash = hex.EncodeToString(digest[:])
	identityDigest := sha256.Sum256([]byte(input.ExternalPoolID + "\x00" + input.ExternalSeatID))
	input.PrincipalEmail = "tp-" + hex.EncodeToString(identityDigest[:]) + "@principal.invalid"
	input.Credential, err = generateTrustedPoolCredential()
	if err != nil {
		return nil, infraerrors.InternalServer("TRUSTED_POOL_KEY_GENERATION_FAILED", "failed to generate trusted pool credential").WithCause(err)
	}
	credentialDigest := sha256.Sum256([]byte(input.Credential))
	input.CredentialFingerprint = hex.EncodeToString(credentialDigest[:])
	return s.repo.ProvisionSeat(ctx, input)
}

func (s *TrustedPoolIntegrationService) AckProvisionCredential(ctx context.Context, externalSeatID string, input AckTrustedPoolProvisionCredentialInput) (*TrustedPoolProvisionCredentialClaim, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	externalSeatID = strings.TrimSpace(externalSeatID)
	input.ProvisionOperationID = strings.TrimSpace(input.ProvisionOperationID)
	input.ClaimOperationID = strings.TrimSpace(input.ClaimOperationID)
	input.ClaimedBy = strings.TrimSpace(input.ClaimedBy)
	input.CredentialFingerprint = strings.TrimSpace(input.CredentialFingerprint)
	input.ActorClientID = principal.ClientID
	input.ExternalPoolID = principal.ExternalPoolID
	if externalSeatID == "" || input.ProvisionOperationID == "" || input.ClaimOperationID == "" ||
		input.ClaimedBy == "" || input.CredentialFingerprint == "" || input.ActorClientID == "" {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_CREDENTIAL_ACK_INVALID", "trusted pool credential acknowledgement is incomplete")
	}
	if len(externalSeatID) > 128 || len(input.ProvisionOperationID) > 128 || len(input.ClaimOperationID) > 128 ||
		len(input.ClaimedBy) > 128 || len(input.ActorClientID) > 64 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_CREDENTIAL_ACK_INVALID", "trusted pool credential acknowledgement is too long")
	}
	decodedFingerprint, decodeErr := hex.DecodeString(input.CredentialFingerprint)
	if decodeErr != nil || len(decodedFingerprint) != sha256.Size || input.CredentialFingerprint != strings.ToLower(input.CredentialFingerprint) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_CREDENTIAL_ACK_INVALID", "credential_fingerprint must be lowercase SHA-256 hex")
	}
	return s.repo.AckProvisionCredential(ctx, externalSeatID, input)
}

func (s *TrustedPoolIntegrationService) RegisterSeat(ctx context.Context, input RegisterTrustedPoolSeatInput) (*TrustedPoolSeat, error) {
	input.ExternalPoolID = strings.TrimSpace(input.ExternalPoolID)
	principal, err := trustedPoolAuthorizedPrincipal(ctx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	input.ActorClientID = principal.ClientID
	input.ExternalSeatID = strings.TrimSpace(input.ExternalSeatID)
	input.OperationID = strings.TrimSpace(input.OperationID)
	if input.OperationID == "" {
		return nil, ErrTrustedPoolOperationIDMissing
	}
	if len(input.OperationID) > 128 || len(input.ExternalPoolID) > 128 || len(input.ExternalSeatID) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_IDENTIFIER_INVALID", "trusted pool identifier is too long")
	}
	if input.ExternalPoolID == "" || input.ExternalSeatID == "" || input.PrincipalUserID <= 0 || input.GroupID <= 0 || input.SubscriptionID <= 0 || input.APIKeyID <= 0 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_INVALID_BINDING", "trusted pool seat binding is incomplete")
	}
	if input.AssignmentEpoch <= 0 {
		input.AssignmentEpoch = 1
	}
	return s.repo.RegisterSeat(ctx, input)
}

func (s *TrustedPoolIntegrationService) Suspend(ctx context.Context, seatID, operationID string) (*TrustedPoolSeat, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, ErrTrustedPoolOperationIDMissing
	}
	if len(strings.TrimSpace(operationID)) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_OPERATION_ID_INVALID", "operation_id is too long")
	}
	seat, err := s.repo.SuspendSeat(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID), strings.TrimSpace(operationID))
	if err != nil {
		return nil, err
	}
	// 数据库提交后同步清本实例缓存；数据库触发器负责跨实例的持久化失效。
	if s.apiKeys != nil {
		s.apiKeys.InvalidateAuthCacheByUserID(ctx, seat.PrincipalUserID)
	}
	if s.subs != nil {
		_ = s.subs.InvalidateSubscriptionCachesSync(seat.PrincipalUserID, seat.GroupID)
	}
	return seat, nil
}

func (s *TrustedPoolIntegrationService) DrainStatus(ctx context.Context, seatID string) (*TrustedPoolSeat, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	seat, err := s.repo.GetSeat(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID))
	if err != nil {
		return nil, err
	}
	if s.concurrency == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "trusted pool concurrency service is unavailable")
	}
	count, err := s.concurrency.GetAPIKeyConcurrencyStrict(ctx, seat.APIKeyID)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify trusted pool drain state").WithCause(err)
	}
	seat.CurrentConcurrency = count
	pending, err := s.repo.CountPendingSettlements(ctx, seat.ID)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify trusted pool settlements").WithCause(err)
	}
	seat.PendingSettlements = pending
	snapshot, err := s.repo.GetUsageSnapshot(ctx, seat.SubscriptionID)
	if err != nil {
		return nil, err
	}
	seat.UsageSnapshot = snapshot
	return seat, nil
}

func (s *TrustedPoolIntegrationService) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]TrustedPoolPendingSettlement, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	seatID = strings.TrimSpace(seatID)
	if seatID == "" || len(seatID) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_IDENTIFIER_INVALID", "trusted pool seat identifier is invalid")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	// 列表为空不能区分“Seat 不存在”和“没有 pending”，先显式验证 Seat。
	if _, err := s.repo.GetSeat(ctx, principal.ExternalPoolID, seatID); err != nil {
		return nil, err
	}
	return s.repo.ListPendingSettlements(ctx, principal.ExternalPoolID, seatID, limit)
}

func (s *TrustedPoolIntegrationService) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*TrustedPoolPendingSettlement, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	if seatID == "" || settlementID == "" || len(seatID) > 128 || len(settlementID) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_IDENTIFIER_INVALID", "trusted pool settlement identifier is invalid")
	}
	return s.repo.GetPendingSettlement(ctx, principal.ExternalPoolID, seatID, settlementID)
}

// ResolvePendingSettlement 是受控人工对账入口：只有完整理由、证据和幂等操作号才能解除冻结屏障。
func (s *TrustedPoolIntegrationService) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, input ResolveTrustedPoolSettlementInput) (*TrustedPoolSettlementResolution, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.ActorClientID = principal.ClientID
	input.ExternalPoolID = principal.ExternalPoolID
	input.Reason = strings.TrimSpace(input.Reason)
	input.Evidence = strings.TrimSpace(input.Evidence)
	if seatID == "" || settlementID == "" || input.OperationID == "" || input.ActorClientID == "" || input.Reason == "" || input.Evidence == "" {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_SETTLEMENT_RESOLUTION_INVALID", "operation_id, actor, reason and evidence are required")
	}
	if len(seatID) > 128 || len(settlementID) > 128 || len(input.OperationID) > 128 || len(input.ActorClientID) > 64 || len(input.Reason) > 1000 || len(input.Evidence) > 4000 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_SETTLEMENT_RESOLUTION_INVALID", "trusted pool settlement resolution is too long")
	}
	return s.repo.ResolvePendingSettlement(ctx, seatID, settlementID, input)
}

func (s *TrustedPoolIntegrationService) Freeze(ctx context.Context, seatID, operationID string) (*TrustedPoolSeat, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, ErrTrustedPoolOperationIDMissing
	}
	if len(strings.TrimSpace(operationID)) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_OPERATION_ID_INVALID", "operation_id is too long")
	}
	seat, err := s.DrainStatus(ctx, seatID)
	if err != nil {
		return nil, err
	}
	if seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
		return nil, trustedPoolNotDrainedError(seat)
	}
	// 连续两个心跳周期保持为零，才能覆盖 Redis 故障恢复后租约尚未重新登记的短暂窗口。
	timer := time.NewTimer(2 * trustedPoolLeaseHeartbeatInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	seat, err = s.DrainStatus(ctx, seatID)
	if err != nil {
		return nil, err
	}
	if seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
		return nil, trustedPoolNotDrainedError(seat)
	}
	return s.repo.FreezeSeat(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID), strings.TrimSpace(operationID))
}

func trustedPoolNotDrainedError(seat *TrustedPoolSeat) error {
	metadata := map[string]string{}
	if seat != nil {
		metadata["current_concurrency"] = intToString(seat.CurrentConcurrency)
		metadata["pending_settlements"] = intToString(seat.PendingSettlements)
	}
	return ErrTrustedPoolNotDrained.WithMetadata(metadata)
}

func (s *TrustedPoolIntegrationService) Rotate(ctx context.Context, seatID, operationID string, targetEpoch int64) (*TrustedPoolRotationResult, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, ErrTrustedPoolOperationIDMissing
	}
	if len(strings.TrimSpace(operationID)) > 128 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_OPERATION_ID_INVALID", "operation_id is too long")
	}
	seat, err := s.DrainStatus(ctx, seatID)
	if err != nil {
		return nil, err
	}
	// 同一 operation_id + epoch 的重试由仓储返回当前 credential，不再二次轮换。
	if seat.AssignmentEpoch == targetEpoch && seat.LastOperationID == strings.TrimSpace(operationID) {
		result, retryErr := s.repo.RotateSeatCredential(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID), strings.TrimSpace(operationID), "", targetEpoch)
		if retryErr == nil {
			result.AccessCredentialRotated = true
		}
		return result, retryErr
	}
	if seat.State != TrustedPoolSeatStateFrozen || seat.CurrentConcurrency != 0 {
		return nil, ErrTrustedPoolNotDrained
	}
	credential, err := generateTrustedPoolCredential()
	if err != nil {
		return nil, infraerrors.InternalServer("TRUSTED_POOL_KEY_GENERATION_FAILED", "failed to generate trusted pool credential").WithCause(err)
	}
	result, err := s.repo.RotateSeatCredential(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID), strings.TrimSpace(operationID), credential, targetEpoch)
	if err != nil {
		return nil, err
	}
	if s.apiKeys != nil {
		s.apiKeys.InvalidateAuthCacheByKey(ctx, result.OldCredential)
		s.apiKeys.InvalidateAuthCacheByKey(ctx, result.Credential)
		s.apiKeys.InvalidateAuthCacheByUserID(ctx, result.Seat.PrincipalUserID)
	}
	if s.subs != nil {
		_ = s.subs.InvalidateSubscriptionCachesSync(result.Seat.PrincipalUserID, result.Seat.GroupID)
	}
	result.AccessCredentialRotated = true
	return result, nil
}

func (s *TrustedPoolIntegrationService) UsageRisk(ctx context.Context, seatID string, hours int) (*TrustedPoolUsageRisk, error) {
	principal, err := trustedPoolAuthorizedPrincipal(ctx, "")
	if err != nil {
		return nil, err
	}
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	seat, err := s.repo.GetSeat(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID))
	if err != nil {
		return nil, err
	}
	risk, err := s.repo.GetUsageRisk(ctx, principal.ExternalPoolID, strings.TrimSpace(seatID), time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		return nil, err
	}
	risk.WindowHours = hours
	if s.concurrency == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_RISK_UNAVAILABLE", "trusted pool concurrency service is unavailable")
	}
	count, err := s.concurrency.GetAPIKeyConcurrencyStrict(ctx, seat.APIKeyID)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_RISK_UNAVAILABLE", "cannot read trusted pool concurrency").WithCause(err)
	}
	risk.CurrentConcurrency = count
	return risk, nil
}

func generateTrustedPoolCredential() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "sk-tp-" + hex.EncodeToString(raw), nil
}

func intToString(v int) string {
	if v == 0 {
		return "0"
	}
	digits := make([]byte, 0, 12)
	for v > 0 {
		digits = append(digits, byte('0'+v%10))
		v /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
