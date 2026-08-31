package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	TrustedPoolPermanentRotationProtocolV1    = "trusted-pool/permanent-seat-rotation/v1"
	TrustedPoolSeatStateActive                = "active"
	TrustedPoolSeatStateDraining              = "draining"
	TrustedPoolSeatStateFrozen                = "frozen"
	TrustedPoolSeatStateRotating              = "rotating"
	TrustedPoolSeatStateRotationPrepared      = "rotation_prepared"
	TrustedPoolSeatStateRotationPendingCommit = "rotation_activated_pending_commit"
)

var (
	ErrTrustedPoolSeatNotFound                      = infraerrors.NotFound("TRUSTED_POOL_SEAT_NOT_FOUND", "trusted pool seat not found")
	ErrTrustedPoolSeatConflict                      = infraerrors.Conflict("TRUSTED_POOL_SEAT_CONFLICT", "trusted pool seat binding conflicts with existing data")
	ErrTrustedPoolInvalidState                      = infraerrors.Conflict("TRUSTED_POOL_INVALID_STATE", "trusted pool seat state does not allow this operation")
	ErrTrustedPoolNotDrained                        = infraerrors.Conflict("TRUSTED_POOL_NOT_DRAINED", "trusted pool seat still has active requests")
	ErrTrustedPoolEpochConflict                     = infraerrors.Conflict("TRUSTED_POOL_EPOCH_CONFLICT", "trusted pool assignment epoch conflict")
	ErrTrustedPoolPermanentCommitReceiptUnavailable = infraerrors.Conflict(
		"TRUSTED_POOL_PERMANENT_COMMIT_RECEIPT_UNAVAILABLE",
		"permanent rotation commit receipt no longer matches the current credential generation",
	)
	ErrTrustedPoolPermanentCredentialEnvelopeUnavailable = infraerrors.ServiceUnavailable(
		"TRUSTED_POOL_PERMANENT_CREDENTIAL_ENVELOPE_UNAVAILABLE",
		"permanent rotation prepared credential is unavailable",
	)
	ErrTrustedPoolPermanentCredentialExpired = infraerrors.Conflict(
		"TRUSTED_POOL_PERMANENT_CREDENTIAL_EXPIRED",
		"permanent rotation prepared credential has expired",
	)
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

// TrustedPoolPermanentRotationSeatBinding 把平台计划中的 Seat 与 Sub2API 稳定资源逐项绑定。
// ChildRequestHash 是平台侧不可变子操作摘要，Sub2API 只校验格式并纳入父请求摘要。
type TrustedPoolPermanentRotationSeatBinding struct {
	ExternalSeatID          string `json:"external_seat_id"`
	TargetMemberID          string `json:"target_member_id"`
	ExpectedAssignmentEpoch int64  `json:"expected_assignment_epoch"`
	PrincipalUserID         int64  `json:"principal_user_id"`
	GroupID                 int64  `json:"group_id"`
	SubscriptionID          int64  `json:"subscription_id"`
	APIKeyID                int64  `json:"api_key_id"`
	FromAPIKeyVersion       int64  `json:"from_api_key_version"`
	ToAPIKeyVersion         int64  `json:"to_api_key_version"`
	ChildOperationID        string `json:"child_operation_id"`
	ChildRequestHash        string `json:"child_request_hash"`
}

type PrepareTrustedPoolPermanentRotationInput struct {
	ProtocolVersion      string                                    `json:"protocol_version"`
	OperationID          string                                    `json:"operation_id"`
	ExternalPoolID       string                                    `json:"external_pool_id"`
	PlanID               string                                    `json:"plan_id"`
	CeremonyType         string                                    `json:"ceremony_type"`
	FromEpoch            int64                                     `json:"from_epoch"`
	ToEpoch              int64                                     `json:"to_epoch"`
	ChildSetHash         string                                    `json:"child_set_hash"`
	Seats                []TrustedPoolPermanentRotationSeatBinding `json:"seats"`
	ActorClientID        string                                    `json:"-"`
	RequestHash          string                                    `json:"request_hash"`
	PreparedSetHash      string                                    `json:"-"`
	Credentials          []string                                  `json:"-"`
	PreparedRotationRefs []string                                  `json:"-"`
}

type TrustedPoolPermanentRotationPreparedSeat struct {
	TrustedPoolPermanentRotationSeatBinding
	Credential                 string    `json:"credential,omitempty"`
	CredentialFingerprint      string    `json:"credential_fingerprint"`
	ActiveAPIKeyVersion        int64     `json:"active_api_key_version"`
	PreparedRotationRef        string    `json:"prepared_rotation_ref"`
	State                      string    `json:"state"`
	CredentialEnabled          bool      `json:"credential_enabled"`
	SubscriptionEnabled        bool      `json:"subscription_enabled"`
	CredentialRotationComplete bool      `json:"credential_rotation_complete"`
	CompletedAt                time.Time `json:"completed_at"`
}

type TrustedPoolPermanentRotationPrepareResult struct {
	OperationID          string                                     `json:"operation_id"`
	ProtocolVersion      string                                     `json:"protocol_version"`
	ExternalPoolID       string                                     `json:"external_pool_id"`
	PlanID               string                                     `json:"plan_id"`
	CeremonyType         string                                     `json:"ceremony_type"`
	FromEpoch            int64                                      `json:"from_epoch"`
	ToEpoch              int64                                      `json:"to_epoch"`
	RequestHash          string                                     `json:"request_hash"`
	ChildSetHash         string                                     `json:"child_set_hash"`
	PreparedSetHash      string                                     `json:"prepared_set_hash"`
	Status               string                                     `json:"status"`
	CredentialsDisclosed bool                                       `json:"credentials_disclosed"`
	Seats                []TrustedPoolPermanentRotationPreparedSeat `json:"seats"`
	PreparedAt           time.Time                                  `json:"-"`
	Attestation          *TrustedPoolPermanentRotationAttestation   `json:"attestation"`
}

type ActivateTrustedPoolPermanentRotationSeat struct {
	ExternalSeatID          string `json:"external_seat_id"`
	TargetMemberID          string `json:"target_member_id"`
	ExpectedAssignmentEpoch int64  `json:"expected_assignment_epoch"`
	PrincipalUserID         int64  `json:"principal_user_id"`
	SubscriptionID          int64  `json:"subscription_id"`
	APIKeyID                int64  `json:"api_key_id"`
	ActiveAPIKeyVersion     int64  `json:"active_api_key_version"`
	ChildOperationID        string `json:"child_operation_id"`
	ChildRequestHash        string `json:"child_request_hash"`
	CredentialFingerprint   string `json:"credential_fingerprint"`
	PreparedRotationRef     string `json:"prepared_rotation_ref"`
}

type ActivateTrustedPoolPermanentRotationInput struct {
	ProtocolVersion     string                                     `json:"protocol_version"`
	OperationID         string                                     `json:"operation_id"`
	PrepareOperationID  string                                     `json:"prepare_operation_id"`
	ExternalPoolID      string                                     `json:"external_pool_id"`
	PlanID              string                                     `json:"plan_id"`
	CeremonyType        string                                     `json:"ceremony_type"`
	FromEpoch           int64                                      `json:"from_epoch"`
	ToEpoch             int64                                      `json:"to_epoch"`
	PreparedSetHash     string                                     `json:"prepared_set_hash"`
	Seats               []ActivateTrustedPoolPermanentRotationSeat `json:"seats"`
	ActorClientID       string                                     `json:"-"`
	RequestHash         string                                     `json:"request_hash"`
	ConcurrencyVerified bool                                       `json:"-"`
}

type TrustedPoolPermanentRotationActivatedSeat struct {
	ExternalSeatID          string `json:"external_seat_id"`
	TargetMemberID          string `json:"target_member_id"`
	ExpectedAssignmentEpoch int64  `json:"expected_assignment_epoch"`
	AssignmentEpoch         int64  `json:"assignment_epoch"`
	PrincipalUserID         int64  `json:"principal_user_id"`
	GroupID                 int64  `json:"group_id"`
	SubscriptionID          int64  `json:"subscription_id"`
	APIKeyID                int64  `json:"api_key_id"`
	ActiveAPIKeyVersion     int64  `json:"active_api_key_version"`
	CredentialFingerprint   string `json:"credential_fingerprint"`
	PreparedRotationRef     string `json:"prepared_rotation_ref"`
	ChildOperationID        string `json:"child_operation_id"`
	ChildRequestHash        string `json:"child_request_hash"`
	CurrentConcurrency      int    `json:"current_concurrency"`
	PendingSettlements      int    `json:"pending_settlements"`
}

type TrustedPoolPermanentRotationActivationResult struct {
	ProtocolVersion                   string                                      `json:"protocol_version"`
	OperationID                       string                                      `json:"operation_id"`
	RequestHash                       string                                      `json:"request_hash"`
	PrepareOperationID                string                                      `json:"prepare_operation_id"`
	ExternalPoolID                    string                                      `json:"external_pool_id"`
	PlanID                            string                                      `json:"plan_id"`
	CeremonyType                      string                                      `json:"ceremony_type"`
	FromEpoch                         int64                                       `json:"from_epoch"`
	ToEpoch                           int64                                       `json:"to_epoch"`
	PreparedSetHash                   string                                      `json:"prepared_set_hash"`
	Status                            string                                      `json:"status"`
	AllCredentialsEnabled             bool                                        `json:"all_credentials_enabled"`
	AllSubscriptionsEnabled           bool                                        `json:"all_subscriptions_enabled"`
	OldCredentialSetInvalidated       bool                                        `json:"old_credential_set_invalidated"`
	AuthorizationCacheInvalidated     bool                                        `json:"authorization_cache_invalidated"`
	CredentialFingerprintGateEnforced bool                                        `json:"credential_fingerprint_gate_enforced"`
	ObservedAt                        time.Time                                   `json:"observed_at"`
	Attestation                       *TrustedPoolPermanentRotationAttestation    `json:"attestation"`
	Seats                             []TrustedPoolPermanentRotationActivatedSeat `json:"seats"`
	AuthCacheBarrier                  struct {
		DurableOutbox bool `json:"durable_outbox"`
		MinimumEvents int  `json:"minimum_events"`
	} `json:"auth_cache_barrier"`
}

type CommitTrustedPoolPermanentRotationInput struct {
	ProtocolVersion       string                                     `json:"protocol_version"`
	OperationID           string                                     `json:"operation_id"`
	PrepareOperationID    string                                     `json:"prepare_operation_id"`
	ActivationOperationID string                                     `json:"activation_operation_id"`
	ActivationRequestHash string                                     `json:"activation_request_hash"`
	ExternalPoolID        string                                     `json:"external_pool_id"`
	PlanID                string                                     `json:"plan_id"`
	CeremonyType          string                                     `json:"ceremony_type"`
	FromEpoch             int64                                      `json:"from_epoch"`
	ToEpoch               int64                                      `json:"to_epoch"`
	PreparedSetHash       string                                     `json:"prepared_set_hash"`
	Seats                 []ActivateTrustedPoolPermanentRotationSeat `json:"seats"`
	ActorClientID         string                                     `json:"-"`
	RequestHash           string                                     `json:"request_hash"`
	ConcurrencyVerified   bool                                       `json:"-"`
}

type TrustedPoolPermanentRotationCommitResult struct {
	ProtocolVersion                   string                                      `json:"protocol_version"`
	OperationID                       string                                      `json:"operation_id"`
	RequestHash                       string                                      `json:"request_hash"`
	PrepareOperationID                string                                      `json:"prepare_operation_id"`
	ActivationOperationID             string                                      `json:"activation_operation_id"`
	ActivationRequestHash             string                                      `json:"activation_request_hash"`
	ExternalPoolID                    string                                      `json:"external_pool_id"`
	PlanID                            string                                      `json:"plan_id"`
	CeremonyType                      string                                      `json:"ceremony_type"`
	FromEpoch                         int64                                       `json:"from_epoch"`
	ToEpoch                           int64                                       `json:"to_epoch"`
	PreparedSetHash                   string                                      `json:"prepared_set_hash"`
	Status                            string                                      `json:"status"`
	AllCredentialsEnabled             bool                                        `json:"all_credentials_enabled"`
	AllSubscriptionsEnabled           bool                                        `json:"all_subscriptions_enabled"`
	OldCredentialSetInvalidated       bool                                        `json:"old_credential_set_invalidated"`
	AuthorizationCacheInvalidated     bool                                        `json:"authorization_cache_invalidated"`
	CredentialFingerprintGateEnforced bool                                        `json:"credential_fingerprint_gate_enforced"`
	ObservedAt                        time.Time                                   `json:"observed_at"`
	Attestation                       *TrustedPoolPermanentRotationAttestation    `json:"attestation"`
	Seats                             []TrustedPoolPermanentRotationActivatedSeat `json:"seats"`
	AuthCacheBarrier                  struct {
		DurableOutbox bool `json:"durable_outbox"`
		MinimumEvents int  `json:"minimum_events"`
	} `json:"auth_cache_barrier"`
}

type TrustedPoolPermanentRotationAttestation struct {
	Version   string `json:"version"`
	Issuer    string `json:"issuer"`
	KeyID     string `json:"key_id"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type trustedPoolPermanentRotationSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
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
	OperationID             string `json:"operation_id"`
	ExpectedAssignmentEpoch int64  `json:"expected_assignment_epoch"`
	ExpectedRequestID       string `json:"expected_request_id"`
	ActorClientID           string `json:"-"`
	ExternalPoolID          string `json:"-"`
	Reason                  string `json:"reason"`
	Evidence                string `json:"evidence"`
}

type TrustedPoolSettlementResolution struct {
	SeatID          int64     `json:"seat_id"`
	ExternalSeatID  string    `json:"external_seat_id"`
	SettlementID    string    `json:"settlement_id"`
	OperationID     string    `json:"operation_id"`
	ActorClientID   string    `json:"actor_client_id"`
	AssignmentEpoch int64     `json:"assignment_epoch"`
	RequestID       string    `json:"request_id"`
	Reason          string    `json:"reason"`
	Evidence        string    `json:"evidence"`
	ResolvedAt      time.Time `json:"resolved_at"`
}

type TrustedPoolRepository interface {
	ProvisionSeat(ctx context.Context, input ProvisionTrustedPoolSeatInput) (*TrustedPoolProvisionResult, error)
	AckProvisionCredential(ctx context.Context, externalSeatID string, input AckTrustedPoolProvisionCredentialInput) (*TrustedPoolProvisionCredentialClaim, error)
	RegisterSeat(ctx context.Context, input RegisterTrustedPoolSeatInput) (*TrustedPoolSeat, error)
	GetSeat(ctx context.Context, externalPoolID, externalSeatID string) (*TrustedPoolSeat, error)
	GetSeatByAPIKeyID(ctx context.Context, apiKeyID int64) (*TrustedPoolSeat, error)
	TrustedPoolCredentialMatches(ctx context.Context, apiKeyID int64, credentialFingerprint string) (bool, error)
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

type TrustedPoolPermanentRotationRepository interface {
	PreparePermanentRotation(ctx context.Context, input PrepareTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationPrepareResult, error)
	ActivatePermanentRotation(ctx context.Context, input ActivateTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationActivationResult, error)
	TryReplayPermanentRotationCommit(ctx context.Context, input CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, bool, error)
	CommitPermanentRotation(ctx context.Context, input CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, error)
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
func (s *TrustedPoolIntegrationService) AcquireGatewayAdmission(ctx context.Context, apiKeyID int64, credentialFingerprint string) (func(), bool, error) {
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
	// API Key 认证缓存可能仍持有轮换前的旧 credential。Seat 重新激活后必须逐请求
	// 与数据库当前 key 指纹核对，安全边界不能依赖异步 Pub/Sub 是否已经收敛。
	matches, err := s.repo.TrustedPoolCredentialMatches(ctx, apiKeyID, strings.TrimSpace(credentialFingerprint))
	if err != nil {
		release()
		return nil, true, infraerrors.ServiceUnavailable("TRUSTED_POOL_GATE_UNAVAILABLE", "cannot verify trusted pool credential generation").WithCause(err)
	}
	if !matches {
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
	repo                    TrustedPoolRepository
	concurrency             *ConcurrencyService
	apiKeys                 *APIKeyService
	subs                    *SubscriptionService
	permanentRotationSigner *trustedPoolPermanentRotationSigner
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
	return &TrustedPoolIntegrationService{
		repo: repo, concurrency: concurrency, apiKeys: apiKeys, subs: subs,
	}
}

// ConfigurePermanentRotationAttestation 供显式装配与测试注入独立签名键；请求认证密钥不得复用。
func (s *TrustedPoolIntegrationService) ConfigurePermanentRotationAttestation(keyID string, privateKey ed25519.PrivateKey) error {
	keyID = strings.TrimSpace(keyID)
	if s == nil || keyID == "" || len(keyID) > 128 || len(privateKey) != ed25519.PrivateKeySize {
		return infraerrors.BadRequest("TRUSTED_POOL_ATTESTATION_KEY_INVALID", "permanent rotation attestation key is invalid")
	}
	s.permanentRotationSigner = &trustedPoolPermanentRotationSigner{keyID: keyID, privateKey: append(ed25519.PrivateKey(nil), privateKey...)}
	return nil
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
	input.ExpectedRequestID = strings.TrimSpace(input.ExpectedRequestID)
	input.ActorClientID = principal.ClientID
	input.ExternalPoolID = principal.ExternalPoolID
	input.Reason = strings.TrimSpace(input.Reason)
	input.Evidence = strings.TrimSpace(input.Evidence)
	if seatID == "" || settlementID == "" || input.OperationID == "" || input.ExpectedAssignmentEpoch <= 0 ||
		input.ExpectedRequestID == "" || input.ActorClientID == "" || input.Reason == "" || input.Evidence == "" {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_SETTLEMENT_RESOLUTION_INVALID", "operation_id, expected pending binding, actor, reason and evidence are required")
	}
	if len(seatID) > 128 || len(settlementID) > 128 || len(input.OperationID) > 128 || len(input.ExpectedRequestID) > 128 ||
		len(input.ActorClientID) > 64 || len(input.Reason) > 1000 || len(input.Evidence) > 4000 {
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

// PreparePermanentRotation 在 Pool 全量集合上生成新凭据，但保持 API Key/订阅不可用。
// Seat 已 frozen，因此严格并发读为零后不会再出现新的网关入场。
func (s *TrustedPoolIntegrationService) PreparePermanentRotation(ctx context.Context, input PrepareTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationPrepareResult, error) {
	if s == nil || s.permanentRotationSigner == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "permanent rotation attestation signer is unavailable")
	}
	input.ProtocolVersion = strings.TrimSpace(input.ProtocolVersion)
	principal, err := trustedPoolAuthorizedPrincipal(ctx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.ExternalPoolID = strings.TrimSpace(input.ExternalPoolID)
	input.PlanID = strings.TrimSpace(input.PlanID)
	input.CeremonyType = strings.TrimSpace(input.CeremonyType)
	input.ChildSetHash = strings.TrimSpace(input.ChildSetHash)
	input.RequestHash = strings.TrimSpace(input.RequestHash)
	input.ActorClientID = principal.ClientID
	if input.ProtocolVersion != TrustedPoolPermanentRotationProtocolV1 || input.OperationID == "" || input.ExternalPoolID == "" || input.PlanID == "" ||
		(input.CeremonyType != "BOOTSTRAP" && input.CeremonyType != "ROTATE") || len(input.Seats) == 0 ||
		input.FromEpoch <= 0 || input.ToEpoch != input.FromEpoch+1 || !validTrustedPoolSHA256Hex(input.ChildSetHash) || !validTrustedPoolSHA256Hex(input.RequestHash) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ROTATION_INVALID", "permanent rotation request is incomplete")
	}
	if len(input.OperationID) > 128 || len(input.ExternalPoolID) > 128 || len(input.PlanID) > 128 || len(input.Seats) > 1000 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ROTATION_INVALID", "permanent rotation request exceeds limits")
	}
	if s.concurrency == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "trusted pool concurrency service is unavailable")
	}
	previousSeatID := ""
	for index := range input.Seats {
		seatInput := &input.Seats[index]
		seatInput.ExternalSeatID = strings.TrimSpace(seatInput.ExternalSeatID)
		seatInput.TargetMemberID = strings.TrimSpace(seatInput.TargetMemberID)
		seatInput.ChildOperationID = strings.TrimSpace(seatInput.ChildOperationID)
		seatInput.ChildRequestHash = strings.TrimSpace(seatInput.ChildRequestHash)
		if seatInput.ExternalSeatID == "" || seatInput.ExternalSeatID <= previousSeatID || len(seatInput.ExternalSeatID) > 128 ||
			seatInput.TargetMemberID == "" || len(seatInput.TargetMemberID) > 128 || seatInput.ExpectedAssignmentEpoch <= 0 ||
			seatInput.ChildOperationID == "" || len(seatInput.ChildOperationID) > 128 || !validTrustedPoolSHA256Hex(seatInput.ChildRequestHash) ||
			seatInput.PrincipalUserID <= 0 || seatInput.SubscriptionID <= 0 || seatInput.APIKeyID <= 0 ||
			seatInput.FromAPIKeyVersion <= 0 || seatInput.ToAPIKeyVersion != seatInput.FromAPIKeyVersion+1 ||
			seatInput.ToAPIKeyVersion != seatInput.ExpectedAssignmentEpoch+1 {
			return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ROTATION_INVALID", "seats must be complete, unique and strictly sorted")
		}
		previousSeatID = seatInput.ExternalSeatID
		seat, readErr := s.repo.GetSeat(ctx, principal.ExternalPoolID, seatInput.ExternalSeatID)
		if readErr != nil {
			return nil, readErr
		}
		if (seat.State != TrustedPoolSeatStateFrozen && seat.State != TrustedPoolSeatStateRotationPrepared) ||
			seat.AssignmentEpoch != seatInput.ExpectedAssignmentEpoch ||
			seat.PrincipalUserID != seatInput.PrincipalUserID || (seatInput.GroupID > 0 && seat.GroupID != seatInput.GroupID) ||
			seat.SubscriptionID != seatInput.SubscriptionID || seat.APIKeyID != seatInput.APIKeyID {
			return nil, ErrTrustedPoolSeatConflict
		}
		count, countErr := s.concurrency.GetAPIKeyConcurrencyStrict(ctx, seat.APIKeyID)
		if countErr != nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify permanent rotation drain state").WithCause(countErr)
		}
		pending, pendingErr := s.repo.CountPendingSettlements(ctx, seat.ID)
		if pendingErr != nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify permanent rotation settlements").WithCause(pendingErr)
		}
		if count != 0 || pending != 0 {
			return nil, ErrTrustedPoolNotDrained
		}
	}
	wantChildSetHash, hashErr := trustedPoolPermanentChildSetHash(input)
	if hashErr != nil || input.ChildSetHash != wantChildSetHash {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ROTATION_INVALID", "child set hash does not match canonical seats")
	}
	if input.RequestHash != trustedPoolPermanentPrepareRequestHash(input) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ROTATION_INVALID", "prepare request hash does not match canonical request")
	}
	input.Credentials = make([]string, len(input.Seats))
	input.PreparedRotationRefs = make([]string, len(input.Seats))
	setBindings := make([]ActivateTrustedPoolPermanentRotationSeat, len(input.Seats))
	for index := range input.Seats {
		credential, generationErr := generateTrustedPoolCredential()
		if generationErr != nil {
			return nil, infraerrors.InternalServer("TRUSTED_POOL_KEY_GENERATION_FAILED", "failed to generate trusted pool credential").WithCause(generationErr)
		}
		input.Credentials[index] = credential
		ref, refErr := generateTrustedPoolPreparedRotationRef()
		if refErr != nil {
			return nil, infraerrors.InternalServer("TRUSTED_POOL_KEY_GENERATION_FAILED", "failed to generate permanent rotation reference").WithCause(refErr)
		}
		input.PreparedRotationRefs[index] = ref
		digest := sha256.Sum256([]byte(credential))
		setBindings[index] = ActivateTrustedPoolPermanentRotationSeat{
			ExternalSeatID:          input.Seats[index].ExternalSeatID,
			TargetMemberID:          input.Seats[index].TargetMemberID,
			ExpectedAssignmentEpoch: input.Seats[index].ExpectedAssignmentEpoch,
			PrincipalUserID:         input.Seats[index].PrincipalUserID,
			SubscriptionID:          input.Seats[index].SubscriptionID,
			APIKeyID:                input.Seats[index].APIKeyID,
			ActiveAPIKeyVersion:     input.Seats[index].ToAPIKeyVersion,
			ChildOperationID:        input.Seats[index].ChildOperationID,
			ChildRequestHash:        input.Seats[index].ChildRequestHash,
			CredentialFingerprint:   hex.EncodeToString(digest[:]),
			PreparedRotationRef:     ref,
		}
	}
	input.PreparedSetHash, err = trustedPoolPermanentPreparedSetHash(setBindings)
	if err != nil {
		return nil, infraerrors.InternalServer("TRUSTED_POOL_PERMANENT_ROTATION_FAILED", "cannot hash prepared credential set").WithCause(err)
	}
	repo, ok := s.repo.(TrustedPoolPermanentRotationRepository)
	if !ok {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_PERMANENT_ROTATION_UNAVAILABLE", "permanent rotation store is unavailable")
	}
	result, err := repo.PreparePermanentRotation(ctx, input)
	if err != nil {
		return nil, err
	}
	result.Attestation, err = s.signPermanentPrepareResult(result)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "cannot attest permanent rotation preparation").WithCause(err)
	}
	return result, nil
}

// ActivatePermanentRotation 只在完整 prepared set 上执行一次 Pool 级事务，响应永不返回 credential。
func (s *TrustedPoolIntegrationService) ActivatePermanentRotation(ctx context.Context, input ActivateTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationActivationResult, error) {
	if s == nil || s.permanentRotationSigner == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "permanent rotation attestation signer is unavailable")
	}
	input.ProtocolVersion = strings.TrimSpace(input.ProtocolVersion)
	principal, err := trustedPoolAuthorizedPrincipal(ctx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.PrepareOperationID = strings.TrimSpace(input.PrepareOperationID)
	input.ExternalPoolID = strings.TrimSpace(input.ExternalPoolID)
	input.PlanID = strings.TrimSpace(input.PlanID)
	input.CeremonyType = strings.TrimSpace(input.CeremonyType)
	input.PreparedSetHash = strings.TrimSpace(input.PreparedSetHash)
	input.RequestHash = strings.TrimSpace(input.RequestHash)
	input.ActorClientID = principal.ClientID
	if input.ProtocolVersion != TrustedPoolPermanentRotationProtocolV1 || input.OperationID == "" || input.PrepareOperationID == "" ||
		input.ExternalPoolID == "" || input.PlanID == "" || (input.CeremonyType != "BOOTSTRAP" && input.CeremonyType != "ROTATE") ||
		len(input.Seats) == 0 || input.FromEpoch <= 0 || input.ToEpoch != input.FromEpoch+1 ||
		!validTrustedPoolSHA256Hex(input.PreparedSetHash) || !validTrustedPoolSHA256Hex(input.RequestHash) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ACTIVATION_INVALID", "permanent rotation activation is incomplete")
	}
	if len(input.OperationID) > 128 || len(input.PrepareOperationID) > 128 || len(input.PlanID) > 128 || len(input.ExternalPoolID) > 128 || len(input.Seats) > 1000 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ACTIVATION_INVALID", "permanent rotation activation exceeds limits")
	}
	previousSeatID := ""
	allPrepared := true
	for index := range input.Seats {
		seatInput := &input.Seats[index]
		seatInput.ExternalSeatID = strings.TrimSpace(seatInput.ExternalSeatID)
		seatInput.TargetMemberID = strings.TrimSpace(seatInput.TargetMemberID)
		seatInput.ChildOperationID = strings.TrimSpace(seatInput.ChildOperationID)
		seatInput.ChildRequestHash = strings.TrimSpace(seatInput.ChildRequestHash)
		seatInput.CredentialFingerprint = strings.TrimSpace(seatInput.CredentialFingerprint)
		seatInput.PreparedRotationRef = strings.TrimSpace(seatInput.PreparedRotationRef)
		if seatInput.ExternalSeatID == "" || seatInput.ExternalSeatID <= previousSeatID || len(seatInput.ExternalSeatID) > 128 ||
			seatInput.TargetMemberID == "" || len(seatInput.TargetMemberID) > 128 || seatInput.PrincipalUserID <= 0 ||
			seatInput.SubscriptionID <= 0 || seatInput.APIKeyID <= 0 || seatInput.ActiveAPIKeyVersion <= 0 ||
			seatInput.ExpectedAssignmentEpoch <= 0 || seatInput.ActiveAPIKeyVersion != seatInput.ExpectedAssignmentEpoch+1 ||
			seatInput.ChildOperationID == "" || len(seatInput.ChildOperationID) > 128 ||
			!validTrustedPoolSHA256Hex(seatInput.ChildRequestHash) || !validTrustedPoolSHA256Hex(seatInput.CredentialFingerprint) ||
			seatInput.PreparedRotationRef == "" || len(seatInput.PreparedRotationRef) > 128 {
			return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ACTIVATION_INVALID", "activation seats must be complete, unique and strictly sorted")
		}
		previousSeatID = seatInput.ExternalSeatID
		seat, readErr := s.repo.GetSeat(ctx, principal.ExternalPoolID, seatInput.ExternalSeatID)
		if readErr != nil {
			return nil, readErr
		}
		if seat.State != TrustedPoolSeatStateRotationPrepared {
			allPrepared = false // 可能是精确激活重放，交由仓储摘要判定。
			continue
		}
		if s.concurrency == nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "trusted pool concurrency service is unavailable")
		}
		count, countErr := s.concurrency.GetAPIKeyConcurrencyStrict(ctx, seat.APIKeyID)
		if countErr != nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify permanent activation drain state").WithCause(countErr)
		}
		if count != 0 {
			return nil, ErrTrustedPoolNotDrained
		}
	}
	input.ConcurrencyVerified = allPrepared
	wantSetHash, hashErr := trustedPoolPermanentPreparedSetHash(input.Seats)
	if hashErr != nil || wantSetHash != input.PreparedSetHash {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ACTIVATION_INVALID", "prepared set hash does not match canonical seats")
	}
	if input.RequestHash != trustedPoolPermanentActivateRequestHash(input) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_ACTIVATION_INVALID", "activation request hash does not match canonical request")
	}
	repo, ok := s.repo.(TrustedPoolPermanentRotationRepository)
	if !ok {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_PERMANENT_ROTATION_UNAVAILABLE", "permanent rotation store is unavailable")
	}
	result, err := repo.ActivatePermanentRotation(ctx, input)
	if err != nil {
		return nil, err
	}
	result.Attestation, err = s.signPermanentActivationResult(result)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "cannot attest permanent rotation activation").WithCause(err)
	}
	return result, nil
}

// CommitPermanentRotation 只释放已经完整安装且仍保持不可用的 Pool 集合。
// 平台必须先完成本地 final，再调用此端点；在此之前普通 suspend/freeze 无法穿透 held 状态。
func (s *TrustedPoolIntegrationService) CommitPermanentRotation(ctx context.Context, input CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, error) {
	if s == nil || s.permanentRotationSigner == nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "permanent rotation attestation signer is unavailable")
	}
	input.ProtocolVersion = strings.TrimSpace(input.ProtocolVersion)
	principal, err := trustedPoolAuthorizedPrincipal(ctx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	input.PrepareOperationID = strings.TrimSpace(input.PrepareOperationID)
	input.ActivationOperationID = strings.TrimSpace(input.ActivationOperationID)
	input.ActivationRequestHash = strings.TrimSpace(input.ActivationRequestHash)
	input.ExternalPoolID = strings.TrimSpace(input.ExternalPoolID)
	input.PlanID = strings.TrimSpace(input.PlanID)
	input.CeremonyType = strings.TrimSpace(input.CeremonyType)
	input.PreparedSetHash = strings.TrimSpace(input.PreparedSetHash)
	input.RequestHash = strings.TrimSpace(input.RequestHash)
	input.ActorClientID = principal.ClientID
	if input.ProtocolVersion != TrustedPoolPermanentRotationProtocolV1 || input.OperationID == "" || input.PrepareOperationID == "" ||
		input.ActivationOperationID == "" || !validTrustedPoolSHA256Hex(input.ActivationRequestHash) || input.ExternalPoolID == "" || input.PlanID == "" ||
		(input.CeremonyType != "BOOTSTRAP" && input.CeremonyType != "ROTATE") || len(input.Seats) == 0 || input.FromEpoch <= 0 ||
		input.ToEpoch != input.FromEpoch+1 || !validTrustedPoolSHA256Hex(input.PreparedSetHash) || !validTrustedPoolSHA256Hex(input.RequestHash) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_COMMIT_INVALID", "permanent rotation commit is incomplete")
	}
	if len(input.OperationID) > 128 || len(input.PrepareOperationID) > 128 || len(input.ActivationOperationID) > 128 ||
		len(input.PlanID) > 128 || len(input.ExternalPoolID) > 128 || len(input.Seats) > 1000 {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_COMMIT_INVALID", "permanent rotation commit exceeds limits")
	}
	previousSeatID := ""
	for index := range input.Seats {
		seatInput := &input.Seats[index]
		seatInput.ExternalSeatID = strings.TrimSpace(seatInput.ExternalSeatID)
		seatInput.TargetMemberID = strings.TrimSpace(seatInput.TargetMemberID)
		seatInput.ChildOperationID = strings.TrimSpace(seatInput.ChildOperationID)
		seatInput.ChildRequestHash = strings.TrimSpace(seatInput.ChildRequestHash)
		seatInput.CredentialFingerprint = strings.TrimSpace(seatInput.CredentialFingerprint)
		seatInput.PreparedRotationRef = strings.TrimSpace(seatInput.PreparedRotationRef)
		if seatInput.ExternalSeatID == "" || seatInput.ExternalSeatID <= previousSeatID || len(seatInput.ExternalSeatID) > 128 ||
			seatInput.TargetMemberID == "" || len(seatInput.TargetMemberID) > 128 || seatInput.PrincipalUserID <= 0 ||
			seatInput.SubscriptionID <= 0 || seatInput.APIKeyID <= 0 || seatInput.ActiveAPIKeyVersion != seatInput.ExpectedAssignmentEpoch+1 ||
			seatInput.ExpectedAssignmentEpoch <= 0 || seatInput.ChildOperationID == "" || len(seatInput.ChildOperationID) > 128 ||
			!validTrustedPoolSHA256Hex(seatInput.ChildRequestHash) || !validTrustedPoolSHA256Hex(seatInput.CredentialFingerprint) ||
			seatInput.PreparedRotationRef == "" || len(seatInput.PreparedRotationRef) > 128 {
			return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_COMMIT_INVALID", "commit seats must be complete, unique and strictly sorted")
		}
		previousSeatID = seatInput.ExternalSeatID
	}
	wantSetHash, hashErr := trustedPoolPermanentPreparedSetHash(input.Seats)
	if hashErr != nil || wantSetHash != input.PreparedSetHash {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_COMMIT_INVALID", "prepared set hash does not match canonical seats")
	}
	if input.RequestHash != trustedPoolPermanentCommitRequestHash(input) {
		return nil, infraerrors.BadRequest("TRUSTED_POOL_PERMANENT_COMMIT_INVALID", "commit request hash does not match canonical request")
	}
	repo, ok := s.repo.(TrustedPoolPermanentRotationRepository)
	if !ok {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_PERMANENT_ROTATION_UNAVAILABLE", "permanent rotation store is unavailable")
	}
	replayed, found, replayErr := repo.TryReplayPermanentRotationCommit(ctx, input)
	if replayErr != nil {
		return nil, replayErr
	}
	if found {
		replayed.Attestation, err = s.signPermanentCommitResult(replayed)
		if err != nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "cannot attest permanent rotation commit").WithCause(err)
		}
		return replayed, nil
	}

	allHeld, allActive := true, true
	for index := range input.Seats {
		seatInput := &input.Seats[index]
		seat, readErr := s.repo.GetSeat(ctx, principal.ExternalPoolID, seatInput.ExternalSeatID)
		if readErr != nil {
			return nil, readErr
		}
		if seat.State != TrustedPoolSeatStateRotationPendingCommit {
			allHeld = false
			if seat.State != TrustedPoolSeatStateActive || seat.AssignmentEpoch != seatInput.ExpectedAssignmentEpoch+1 ||
				seat.PrincipalUserID != seatInput.PrincipalUserID || seat.SubscriptionID != seatInput.SubscriptionID ||
				seat.APIKeyID != seatInput.APIKeyID {
				return nil, ErrTrustedPoolInvalidState
			}
			continue
		}
		allActive = false
		if s.concurrency == nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "trusted pool concurrency service is unavailable")
		}
		count, countErr := s.concurrency.GetAPIKeyConcurrencyStrict(ctx, seat.APIKeyID)
		if countErr != nil {
			return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_DRAIN_UNAVAILABLE", "cannot verify permanent commit drain state").WithCause(countErr)
		}
		if count != 0 {
			return nil, ErrTrustedPoolNotDrained
		}
	}
	if !allHeld && !allActive {
		return nil, ErrTrustedPoolInvalidState
	}
	input.ConcurrencyVerified = allHeld
	result, err := repo.CommitPermanentRotation(ctx, input)
	if err != nil {
		return nil, err
	}
	result.Attestation, err = s.signPermanentCommitResult(result)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_ATTESTATION_UNAVAILABLE", "cannot attest permanent rotation commit").WithCause(err)
	}
	return result, nil
}

func validTrustedPoolSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func trustedPoolJSONHash(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func trustedPoolPermanentChildSetHash(input PrepareTrustedPoolPermanentRotationInput) (string, error) {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-rotation-child-set/v1")
	writeTrustedPoolSecurityUint32(&encoded, uint32(len(input.Seats)))
	for index := range input.Seats {
		seat := input.Seats[index]
		if seat.ChildRequestHash != trustedPoolPermanentChildRequestHash(input, seat) {
			return "", ErrTrustedPoolSeatConflict
		}
		writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
		writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
		digest, _ := hex.DecodeString(seat.ChildRequestHash)
		encoded.Write(digest)
	}
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func trustedPoolPermanentChildRequestHash(input PrepareTrustedPoolPermanentRotationInput, seat TrustedPoolPermanentRotationSeatBinding) string {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, TrustedPoolPermanentRotationProtocolV1)
	writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
	writeTrustedPoolSecurityString(&encoded, input.PlanID)
	writeTrustedPoolSecurityString(&encoded, input.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, input.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.ToEpoch))
	writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
	writeTrustedPoolSecurityString(&encoded, seat.TargetMemberID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ExpectedAssignmentEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.SubscriptionID))
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.APIKeyID))
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.FromAPIKeyVersion))
	writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ToAPIKeyVersion))
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:])
}

func trustedPoolPermanentPreparedSetHash(seats []ActivateTrustedPoolPermanentRotationSeat) (string, error) {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-prepared-seat-set/v1")
	writeTrustedPoolSecurityUint32(&encoded, uint32(len(seats)))
	for index := range seats {
		seat := seats[index]
		if index > 0 && seats[index-1].ExternalSeatID >= seat.ExternalSeatID || !validTrustedPoolSHA256Hex(seat.CredentialFingerprint) {
			return "", ErrTrustedPoolSeatConflict
		}
		writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
		writeTrustedPoolSecurityString(&encoded, seat.TargetMemberID)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ExpectedAssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ActiveAPIKeyVersion))
		fingerprint, _ := hex.DecodeString(seat.CredentialFingerprint)
		encoded.Write(fingerprint)
		writeTrustedPoolSecurityString(&encoded, seat.PreparedRotationRef)
		writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
		childHash, _ := hex.DecodeString(seat.ChildRequestHash)
		encoded.Write(childHash)
	}
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func trustedPoolPermanentPrepareRequestHash(input PrepareTrustedPoolPermanentRotationInput) string {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-prepare/v1")
	writeTrustedPoolSecurityString(&encoded, input.OperationID)
	writeTrustedPoolSecurityString(&encoded, input.PlanID)
	writeTrustedPoolSecurityString(&encoded, input.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, input.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.ToEpoch))
	childSetHash, _ := hex.DecodeString(input.ChildSetHash)
	encoded.Write(childSetHash)
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:])
}

func trustedPoolPermanentActivateRequestHash(input ActivateTrustedPoolPermanentRotationInput) string {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-activate/v1")
	writeTrustedPoolSecurityString(&encoded, input.OperationID)
	writeTrustedPoolSecurityString(&encoded, input.PrepareOperationID)
	writeTrustedPoolSecurityString(&encoded, input.PlanID)
	writeTrustedPoolSecurityString(&encoded, input.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, input.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.ToEpoch))
	setHash, _ := hex.DecodeString(input.PreparedSetHash)
	encoded.Write(setHash)
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:])
}

func trustedPoolPermanentCommitRequestHash(input CommitTrustedPoolPermanentRotationInput) string {
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-commit/v1")
	writeTrustedPoolSecurityString(&encoded, input.OperationID)
	writeTrustedPoolSecurityString(&encoded, input.PrepareOperationID)
	writeTrustedPoolSecurityString(&encoded, input.ActivationOperationID)
	writeTrustedPoolSecurityHex(&encoded, input.ActivationRequestHash)
	writeTrustedPoolSecurityString(&encoded, input.PlanID)
	writeTrustedPoolSecurityString(&encoded, input.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, input.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(input.ToEpoch))
	writeTrustedPoolSecurityHex(&encoded, input.PreparedSetHash)
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:])
}

func writeTrustedPoolSecurityString(target *bytes.Buffer, value string) {
	writeTrustedPoolSecurityUint32(target, uint32(len([]byte(value))))
	target.WriteString(value)
}

func writeTrustedPoolSecurityUint32(target *bytes.Buffer, value uint32) {
	_ = binary.Write(target, binary.BigEndian, value)
}

func writeTrustedPoolSecurityUint64(target *bytes.Buffer, value uint64) {
	_ = binary.Write(target, binary.BigEndian, value)
}

func generateTrustedPoolPreparedRotationRef() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "tpr-" + hex.EncodeToString(raw), nil
}

func (s *TrustedPoolIntegrationService) signPermanentPrepareResult(result *TrustedPoolPermanentRotationPrepareResult) (*TrustedPoolPermanentRotationAttestation, error) {
	if result == nil {
		return nil, errors.New("nil permanent rotation prepare result")
	}
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-prepare-attestation/v1")
	writeTrustedPoolSecurityString(&encoded, result.ProtocolVersion)
	writeTrustedPoolSecurityString(&encoded, result.OperationID)
	writeTrustedPoolSecurityHex(&encoded, result.RequestHash)
	writeTrustedPoolSecurityString(&encoded, result.PlanID)
	writeTrustedPoolSecurityString(&encoded, result.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, result.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.ToEpoch))
	writeTrustedPoolSecurityHex(&encoded, result.ChildSetHash)
	writeTrustedPoolSecurityHex(&encoded, result.PreparedSetHash)
	writeTrustedPoolSecurityString(&encoded, result.Status)
	writeTrustedPoolSecurityBool(&encoded, result.CredentialsDisclosed)
	writeTrustedPoolSecurityUint32(&encoded, uint32(len(result.Seats)))
	for _, seat := range result.Seats {
		writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
		writeTrustedPoolSecurityString(&encoded, seat.TargetMemberID)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ExpectedAssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ActiveAPIKeyVersion))
		writeTrustedPoolSecurityHex(&encoded, seat.CredentialFingerprint)
		writeTrustedPoolSecurityString(&encoded, seat.PreparedRotationRef)
		writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
		writeTrustedPoolSecurityHex(&encoded, seat.ChildRequestHash)
		writeTrustedPoolSecurityString(&encoded, seat.State)
		writeTrustedPoolSecurityBool(&encoded, seat.CredentialEnabled)
		writeTrustedPoolSecurityBool(&encoded, seat.SubscriptionEnabled)
		writeTrustedPoolSecurityBool(&encoded, seat.CredentialRotationComplete)
	}
	return s.signPermanentRotationBytes(encoded.Bytes())
}

func (s *TrustedPoolIntegrationService) signPermanentActivationResult(result *TrustedPoolPermanentRotationActivationResult) (*TrustedPoolPermanentRotationAttestation, error) {
	if result == nil {
		return nil, errors.New("nil permanent rotation activation result")
	}
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-activate-attestation/v1")
	writeTrustedPoolSecurityString(&encoded, result.ProtocolVersion)
	writeTrustedPoolSecurityString(&encoded, result.OperationID)
	writeTrustedPoolSecurityString(&encoded, result.PrepareOperationID)
	writeTrustedPoolSecurityHex(&encoded, result.RequestHash)
	writeTrustedPoolSecurityString(&encoded, result.PlanID)
	writeTrustedPoolSecurityString(&encoded, result.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, result.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.ToEpoch))
	writeTrustedPoolSecurityHex(&encoded, result.PreparedSetHash)
	writeTrustedPoolSecurityString(&encoded, result.Status)
	writeTrustedPoolSecurityBool(&encoded, result.AllCredentialsEnabled)
	writeTrustedPoolSecurityBool(&encoded, result.AllSubscriptionsEnabled)
	writeTrustedPoolSecurityBool(&encoded, result.OldCredentialSetInvalidated)
	writeTrustedPoolSecurityBool(&encoded, result.AuthorizationCacheInvalidated)
	writeTrustedPoolSecurityBool(&encoded, result.CredentialFingerprintGateEnforced)
	writeTrustedPoolSecurityBool(&encoded, result.AuthCacheBarrier.DurableOutbox)
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.AuthCacheBarrier.MinimumEvents))
	writeTrustedPoolSecurityString(&encoded, result.ObservedAt.UTC().Format(time.RFC3339Nano))
	writeTrustedPoolSecurityUint32(&encoded, uint32(len(result.Seats)))
	for _, seat := range result.Seats {
		writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
		writeTrustedPoolSecurityString(&encoded, seat.TargetMemberID)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ExpectedAssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.AssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ActiveAPIKeyVersion))
		writeTrustedPoolSecurityHex(&encoded, seat.CredentialFingerprint)
		writeTrustedPoolSecurityString(&encoded, seat.PreparedRotationRef)
		writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
		writeTrustedPoolSecurityHex(&encoded, seat.ChildRequestHash)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.CurrentConcurrency))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PendingSettlements))
	}
	return s.signPermanentRotationBytes(encoded.Bytes())
}

func (s *TrustedPoolIntegrationService) signPermanentCommitResult(result *TrustedPoolPermanentRotationCommitResult) (*TrustedPoolPermanentRotationAttestation, error) {
	if result == nil {
		return nil, errors.New("nil permanent rotation commit result")
	}
	var encoded bytes.Buffer
	writeTrustedPoolSecurityString(&encoded, "trusted-pool/permanent-pool-rotation-commit-attestation/v1")
	writeTrustedPoolSecurityString(&encoded, result.ProtocolVersion)
	writeTrustedPoolSecurityString(&encoded, result.OperationID)
	writeTrustedPoolSecurityString(&encoded, result.PrepareOperationID)
	writeTrustedPoolSecurityString(&encoded, result.ActivationOperationID)
	writeTrustedPoolSecurityHex(&encoded, result.RequestHash)
	writeTrustedPoolSecurityHex(&encoded, result.ActivationRequestHash)
	writeTrustedPoolSecurityString(&encoded, result.PlanID)
	writeTrustedPoolSecurityString(&encoded, result.CeremonyType)
	writeTrustedPoolSecurityString(&encoded, result.ExternalPoolID)
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.FromEpoch))
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.ToEpoch))
	writeTrustedPoolSecurityHex(&encoded, result.PreparedSetHash)
	writeTrustedPoolSecurityString(&encoded, result.Status)
	writeTrustedPoolSecurityBool(&encoded, result.AllCredentialsEnabled)
	writeTrustedPoolSecurityBool(&encoded, result.AllSubscriptionsEnabled)
	writeTrustedPoolSecurityBool(&encoded, result.OldCredentialSetInvalidated)
	writeTrustedPoolSecurityBool(&encoded, result.AuthorizationCacheInvalidated)
	writeTrustedPoolSecurityBool(&encoded, result.CredentialFingerprintGateEnforced)
	writeTrustedPoolSecurityBool(&encoded, result.AuthCacheBarrier.DurableOutbox)
	writeTrustedPoolSecurityUint64(&encoded, uint64(result.AuthCacheBarrier.MinimumEvents))
	writeTrustedPoolSecurityString(&encoded, result.ObservedAt.UTC().Format(time.RFC3339Nano))
	writeTrustedPoolSecurityUint32(&encoded, uint32(len(result.Seats)))
	for _, seat := range result.Seats {
		writeTrustedPoolSecurityString(&encoded, seat.ExternalSeatID)
		writeTrustedPoolSecurityString(&encoded, seat.TargetMemberID)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ExpectedAssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.AssignmentEpoch))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PrincipalUserID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.SubscriptionID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.APIKeyID))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.ActiveAPIKeyVersion))
		writeTrustedPoolSecurityHex(&encoded, seat.CredentialFingerprint)
		writeTrustedPoolSecurityString(&encoded, seat.PreparedRotationRef)
		writeTrustedPoolSecurityString(&encoded, seat.ChildOperationID)
		writeTrustedPoolSecurityHex(&encoded, seat.ChildRequestHash)
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.CurrentConcurrency))
		writeTrustedPoolSecurityUint64(&encoded, uint64(seat.PendingSettlements))
	}
	return s.signPermanentRotationBytes(encoded.Bytes())
}

func (s *TrustedPoolIntegrationService) signPermanentRotationBytes(payload []byte) (*TrustedPoolPermanentRotationAttestation, error) {
	if s == nil || s.permanentRotationSigner == nil || len(s.permanentRotationSigner.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("permanent rotation signer unavailable")
	}
	digest := sha256.Sum256(payload)
	signature := ed25519.Sign(s.permanentRotationSigner.privateKey, digest[:])
	digestHex := hex.EncodeToString(digest[:])
	return &TrustedPoolPermanentRotationAttestation{
		Version: "trusted-pool/permanent-rotation-attestation/v1", Issuer: "sub2api",
		KeyID: s.permanentRotationSigner.keyID, Reference: "tpra-" + digestHex[:32],
		Digest: digestHex, Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func writeTrustedPoolSecurityHex(target *bytes.Buffer, value string) {
	decoded, _ := hex.DecodeString(value)
	target.Write(decoded)
}

func writeTrustedPoolSecurityBool(target *bytes.Buffer, value bool) {
	if value {
		target.WriteByte(1)
		return
	}
	target.WriteByte(0)
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
