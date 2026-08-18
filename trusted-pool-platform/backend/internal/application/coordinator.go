package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"trusted-pool-platform/backend/internal/domain"
)

var (
	ErrSeatNotFound                 = errors.New("seat not found")
	ErrOperationConflict            = errors.New("operation id was reused for another command")
	ErrSettlementGatewayUnavailable = errors.New("pending settlement gateway is unavailable")
	ErrInvalidSettlementRequest     = errors.New("pending settlement request is invalid")
	ErrProvisionGatewayUnavailable  = errors.New("seat provision gateway is unavailable")
	ErrInvalidProvisionRequest      = errors.New("seat provision request is invalid")
	ErrCredentialClaimExpired       = errors.New("credential claim expired")
	ErrCredentialClaimPending       = errors.New("credential claim acknowledgement is pending")
	ErrCredentialClaimRejected      = errors.New("credential claim acknowledgement was rejected")
)

const defaultCredentialClaimTTL = 10 * time.Minute

const (
	credentialClaimReady             = "READY"
	credentialClaimAckPending        = "ACK_PENDING"
	credentialClaimReconcileRequired = "ACK_RECONCILE_REQUIRED"
	credentialClaimClaimed           = "CLAIMED"
	credentialClaimExpired           = "EXPIRED"
	credentialClaimRejected          = "REJECTED"
)

type OperationStatus string

const (
	OperationRunning           OperationStatus = "RUNNING"
	OperationSucceeded         OperationStatus = "SUCCEEDED"
	OperationRetryable         OperationStatus = "RETRYABLE"
	OperationReconcileRequired OperationStatus = "RECONCILE_REQUIRED"
	OperationFailed            OperationStatus = "FAILED"
)

type OperationKind string

const (
	OperationProvision  OperationKind = "PROVISION"
	OperationSuspend    OperationKind = "SUSPEND"
	OperationAssignTemp OperationKind = "ASSIGN_TEMPORARY"
	OperationRestore    OperationKind = "RESTORE"
	OperationReplace    OperationKind = "REPLACE_PERMANENTLY"
)

type Operation struct {
	ID                         string          `json:"id"`
	Kind                       OperationKind   `json:"kind"`
	SeatID                     string          `json:"seat_id"`
	TargetUser                 string          `json:"target_user_id,omitempty"`
	ControlRotationEvidenceRef string          `json:"control_rotation_evidence_ref,omitempty"`
	Status                     OperationStatus `json:"status"`
	Reason                     string          `json:"reason,omitempty"`
	CredentialClaimToken       string          `json:"credential_claim_token,omitempty"`
	CredentialClaimStatus      string          `json:"credential_claim_status,omitempty"`
	CredentialClaimExpiresAt   *time.Time      `json:"credential_claim_expires_at,omitempty"`
	CreatedAt                  time.Time       `json:"created_at"`
	UpdatedAt                  time.Time       `json:"updated_at"`
	credential                 string
	requestDigest              string
	credentialClaimTokenHash   [32]byte
	credentialClaimOperationID string
}

type CredentialDelivery struct {
	OperationID string `json:"operation_id"`
	TargetUser  string `json:"target_user_id"`
	Credential  string `json:"credential"`
}

type ProvisionSeatCommand struct {
	OperationID           string    `json:"operation_id"`
	SeatID                string    `json:"external_seat_id"`
	PoolID                string    `json:"external_pool_id"`
	OwnerUserID           string    `json:"-"`
	ExistingGroupID       int64     `json:"existing_group_id"`
	AssignmentEpoch       uint64    `json:"assignment_epoch"`
	PrincipalConcurrency  int       `json:"principal_concurrency"`
	PrincipalRPMLimit     int       `json:"principal_rpm_limit"`
	SubscriptionExpiresAt time.Time `json:"subscription_expires_at"`
	APIKeyQuota           float64   `json:"api_key_quota"`
	APIKeyRateLimit5h     float64   `json:"api_key_rate_limit_5h"`
	APIKeyRateLimit1d     float64   `json:"api_key_rate_limit_1d"`
	APIKeyRateLimit7d     float64   `json:"api_key_rate_limit_7d"`
}

type ProvisionGatewayResult struct {
	ExternalPoolID  string
	ExternalSeatID  string
	State           string
	AssignmentEpoch uint64
	Credential      string
}

type ProvisionSeatResult struct {
	Seat      *domain.Seat `json:"seat"`
	Operation *Operation   `json:"operation"`
}

type ProvisionCredentialAckCommand struct {
	SeatID                string `json:"-"`
	ProvisionOperationID  string `json:"provision_operation_id"`
	ClaimOperationID      string `json:"claim_operation_id"`
	ClaimedBy             string `json:"claimed_by"`
	CredentialFingerprint string `json:"credential_fingerprint"`
}

type ProvisionCredentialAckResult struct {
	ExternalSeatID        string    `json:"external_seat_id"`
	ProvisionOperationID  string    `json:"provision_operation_id"`
	ClaimOperationID      string    `json:"claim_operation_id"`
	ClaimedBy             string    `json:"claimed_by"`
	CredentialFingerprint string    `json:"credential_fingerprint"`
	CredentialClaimed     bool      `json:"credential_claimed"`
	ClaimedAt             time.Time `json:"claimed_at"`
}

type SuspendCommand struct {
	OperationID     string `json:"operation_id"`
	SeatID          string `json:"seat_id"`
	PoolID          string `json:"pool_id"`
	UserID          string `json:"user_id"`
	AssignmentEpoch uint64 `json:"assignment_epoch"`
}

type AssignmentCommand struct {
	OperationID                string        `json:"operation_id"`
	SeatID                     string        `json:"seat_id"`
	PoolID                     string        `json:"pool_id"`
	TargetUser                 string        `json:"target_user_id"`
	AssignmentEpoch            uint64        `json:"assignment_epoch"`
	MembershipEpoch            uint64        `json:"membership_epoch"`
	FreezeOperationID          string        `json:"freeze_operation_id"`
	Permanent                  bool          `json:"permanent"`
	Mode                       OperationKind `json:"mode"`
	ControlRotationEvidenceRef string        `json:"control_rotation_evidence_ref,omitempty"`
}

type AssignmentResult struct {
	AccessCredentialRotationComplete bool
	Credential                       string
}

type SuspendResult struct {
	Draining bool
	Freeze   *domain.FreezeSnapshot
}

type GatewayOperationResult struct {
	Applied                          bool
	Draining                         bool
	Freeze                           *domain.FreezeSnapshot
	AccessCredentialRotationComplete bool
	Credential                       string
}

type Gateway interface {
	Suspend(context.Context, SuspendCommand) (SuspendResult, error)
	Assign(context.Context, AssignmentCommand) (AssignmentResult, error)
	OperationStatus(context.Context, string) (GatewayOperationResult, error)
}

// ProvisionGateway 单独声明，避免旧的状态机测试桩被迫具备资源开通能力。
type ProvisionGateway interface {
	ProvisionSeat(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error)
}

type ProvisionCredentialAcknowledger interface {
	AcknowledgeProvisionCredential(context.Context, ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error)
}

// PendingSettlement 是平台可展示的待对账证据，不包含任何访问凭据或集成密钥。
type PendingSettlement struct {
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

type ResolvePendingSettlementCommand struct {
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason"`
	Evidence    string `json:"evidence"`
}

type SettlementResolution struct {
	SeatID         int64     `json:"seat_id"`
	ExternalSeatID string    `json:"external_seat_id"`
	SettlementID   string    `json:"settlement_id"`
	OperationID    string    `json:"operation_id"`
	ActorClientID  string    `json:"actor_client_id"`
	Reason         string    `json:"reason"`
	Evidence       string    `json:"evidence"`
	ResolvedAt     time.Time `json:"resolved_at"`
}

// PendingSettlementGateway 与成员变更 Gateway 分离，避免不支持人工对账的实现被误认为具备该能力。
type PendingSettlementGateway interface {
	ListPendingSettlements(context.Context, string, int) ([]PendingSettlement, error)
	GetPendingSettlement(context.Context, string, string) (*PendingSettlement, error)
	ResolvePendingSettlement(context.Context, string, string, ResolvePendingSettlementCommand) (*SettlementResolution, error)
}

type ControlRotationEvidenceVerifier interface {
	ValidateControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error
	CommitControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error
}

type GatewayError struct {
	Reason    string
	Retryable bool
	Ambiguous bool
	// StatusCode 保留上游 HTTP 类别，供平台稳定区分冲突、调用错误与结果不明。
	StatusCode int
}

type poolMemberOperation struct {
	SeatID string
	Kind   OperationKind
}

func (e *GatewayError) Error() string {
	if e.Reason == "" {
		return "gateway operation failed"
	}
	return e.Reason
}

type Coordinator struct {
	mu            sync.Mutex
	gateway       Gateway
	now           func() time.Time
	seats         map[string]*domain.Seat
	operations    map[string]*Operation
	evidence      ControlRotationEvidenceVerifier
	poolEpochs    map[string]uint64
	poolPending   map[string]string
	poolMemberOps map[string]map[string]poolMemberOperation
	provisioning  map[string]string
	claimToken    func() (string, error)
	claimTTL      time.Duration
	claimTimers   map[string]*time.Timer
}

func NewCoordinator(gateway Gateway, now func() time.Time, evidence ...ControlRotationEvidenceVerifier) *Coordinator {
	if now == nil {
		now = time.Now
	}
	coordinator := &Coordinator{
		gateway:       gateway,
		now:           now,
		seats:         make(map[string]*domain.Seat),
		operations:    make(map[string]*Operation),
		poolEpochs:    make(map[string]uint64),
		poolPending:   make(map[string]string),
		poolMemberOps: make(map[string]map[string]poolMemberOperation),
		provisioning:  make(map[string]string),
		claimToken:    newClaimToken,
		claimTTL:      defaultCredentialClaimTTL,
		claimTimers:   make(map[string]*time.Timer),
	}
	if len(evidence) > 0 {
		coordinator.evidence = evidence[0]
	}
	return coordinator
}

// ConfigureCredentialClaimTTL 设置 provision 凭据的短期领取窗口。
func (c *Coordinator) ConfigureCredentialClaimTTL(ttl time.Duration) error {
	if ttl <= 0 || ttl > 24*time.Hour {
		return errors.New("credential claim TTL must be between 1ns and 24h")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claimTTL = ttl
	return nil
}

// ProvisionSeat 先在 Sub2API 原子创建 Principal、Subscription 与 API Key，只有明确成功后才创建本地 ACTIVE Seat。
// 上游结果不明时保留同一 operation_id，调用方重放后由 Sub2API 幂等恢复原结果。
func (c *Coordinator) ProvisionSeat(ctx context.Context, command ProvisionSeatCommand) (*ProvisionSeatResult, error) {
	command.OperationID = strings.TrimSpace(command.OperationID)
	command.SeatID = strings.TrimSpace(command.SeatID)
	command.PoolID = strings.TrimSpace(command.PoolID)
	command.OwnerUserID = strings.TrimSpace(command.OwnerUserID)
	if command.AssignmentEpoch == 0 {
		command.AssignmentEpoch = 1
	}
	if command.PrincipalConcurrency == 0 {
		command.PrincipalConcurrency = 1
	}
	if err := validateProvisionCommand(command); err != nil {
		return nil, err
	}
	digest, err := provisionCommandDigest(command)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if existing, ok := c.operations[command.OperationID]; ok {
		if existing.Kind != OperationProvision || existing.requestDigest != digest {
			c.mu.Unlock()
			return nil, ErrOperationConflict
		}
		switch existing.Status {
		case OperationSucceeded:
			seat := c.seats[command.SeatID]
			if seat == nil {
				c.mu.Unlock()
				return nil, errors.New("provision operation succeeded without local seat")
			}
			result := &ProvisionSeatResult{Seat: cloneSeat(seat), Operation: cloneOperation(existing)}
			c.mu.Unlock()
			return result, nil
		case OperationRetryable:
			existing.Status = OperationRunning
			existing.Reason = ""
			existing.UpdatedAt = c.now().UTC()
		case OperationRunning:
			result := &ProvisionSeatResult{Operation: cloneOperation(existing)}
			c.mu.Unlock()
			return result, errors.New("seat provision is still running")
		default:
			result := &ProvisionSeatResult{Operation: cloneOperation(existing)}
			reason := existing.Reason
			if reason == "" {
				reason = "seat provision failed"
			}
			c.mu.Unlock()
			return result, errors.New(reason)
		}
	} else {
		if _, exists := c.seats[command.SeatID]; exists {
			c.mu.Unlock()
			return nil, errors.New("seat already exists")
		}
		if pending := c.provisioning[command.SeatID]; pending != "" {
			c.mu.Unlock()
			return nil, errors.New("another provision operation is pending for this seat")
		}
		if !command.SubscriptionExpiresAt.After(c.now()) {
			c.mu.Unlock()
			return nil, ErrInvalidProvisionRequest
		}
		now := c.now().UTC()
		op := c.newOperation(command.OperationID, OperationProvision, command.SeatID, command.OwnerUserID, "", now)
		op.requestDigest = digest
		c.provisioning[command.SeatID] = command.OperationID
	}
	op := c.operations[command.OperationID]
	c.mu.Unlock()

	gateway, ok := c.gateway.(ProvisionGateway)
	if !ok {
		failed := c.failProvision(command.SeatID, op, ErrProvisionGatewayUnavailable, false)
		return &ProvisionSeatResult{Operation: failed}, ErrProvisionGatewayUnavailable
	}
	upstream, callErr := gateway.ProvisionSeat(ctx, command)
	if callErr != nil {
		retryable := true
		var gatewayErr *GatewayError
		if errors.As(callErr, &gatewayErr) && !gatewayErr.Retryable && !gatewayErr.Ambiguous {
			retryable = false
		}
		failed := c.failProvision(command.SeatID, op, callErr, retryable)
		return &ProvisionSeatResult{Operation: failed}, callErr
	}
	if upstream.ExternalSeatID != command.SeatID || upstream.ExternalPoolID != command.PoolID ||
		!strings.EqualFold(upstream.State, "active") || upstream.AssignmentEpoch != command.AssignmentEpoch || upstream.Credential == "" {
		validationErr := errors.New("Sub2API provision response does not match the requested active seat")
		failed := c.failProvision(command.SeatID, op, validationErr, true)
		return &ProvisionSeatResult{Operation: failed}, validationErr
	}
	claimToken, err := c.claimToken()
	if err != nil {
		failed := c.failProvision(command.SeatID, op, err, true)
		return &ProvisionSeatResult{Operation: failed}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	seat, err := domain.NewSeat(command.SeatID, command.PoolID, command.OwnerUserID, c.now())
	if err != nil {
		op.Status = OperationRetryable
		op.Reason = err.Error()
		op.UpdatedAt = c.now().UTC()
		return &ProvisionSeatResult{Operation: cloneOperation(op)}, err
	}
	if epoch := c.poolEpochs[command.PoolID]; epoch > 0 {
		seat.MembershipEpoch = epoch
	} else {
		c.poolEpochs[command.PoolID] = seat.MembershipEpoch
	}
	c.seats[command.SeatID] = seat
	delete(c.provisioning, command.SeatID)
	op.Status = OperationSucceeded
	op.Reason = ""
	c.issueCredentialClaimLocked(op, claimToken, upstream.Credential)
	op.UpdatedAt = c.now().UTC()
	responseOperation := cloneOperation(op)
	// 明文 token 只存在于首次成功响应副本；Coordinator 内部仅保存不可逆摘要。
	responseOperation.CredentialClaimToken = claimToken
	return &ProvisionSeatResult{Seat: cloneSeat(seat), Operation: responseOperation}, nil
}

func (c *Coordinator) issueCredentialClaimLocked(op *Operation, claimToken, credential string) {
	now := c.now().UTC()
	expiresAt := now.Add(c.claimTTL)
	op.CredentialClaimToken = ""
	op.credentialClaimTokenHash = sha256.Sum256([]byte(claimToken))
	op.CredentialClaimStatus = credentialClaimReady
	op.CredentialClaimExpiresAt = &expiresAt
	op.credentialClaimOperationID = provisionClaimOperationID(op.ID)
	op.credential = credential
	if previous := c.claimTimers[op.ID]; previous != nil {
		previous.Stop()
	}
	c.claimTimers[op.ID] = time.AfterFunc(c.claimTTL, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		current := c.operations[op.ID]
		if current == nil || current.CredentialClaimExpiresAt == nil || !current.CredentialClaimExpiresAt.Equal(expiresAt) {
			return
		}
		c.expireCredentialClaimLocked(current)
	})
}

func (c *Coordinator) expireCredentialClaimLocked(op *Operation) {
	if op == nil || op.CredentialClaimStatus == credentialClaimClaimed || op.CredentialClaimStatus == credentialClaimExpired {
		return
	}
	op.credential = ""
	op.credentialClaimTokenHash = [32]byte{}
	op.CredentialClaimStatus = credentialClaimExpired
	op.UpdatedAt = c.now().UTC()
	if timer := c.claimTimers[op.ID]; timer != nil {
		timer.Stop()
	}
	delete(c.claimTimers, op.ID)
}

func provisionClaimOperationID(provisionOperationID string) string {
	digest := sha256.Sum256([]byte("provision-credential-claim\x00" + provisionOperationID))
	return "claim-" + hex.EncodeToString(digest[:])
}

func credentialFingerprint(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(digest[:])
}

func (c *Coordinator) failProvision(seatID string, op *Operation, failure error, retryable bool) *Operation {
	c.mu.Lock()
	defer c.mu.Unlock()
	op.Reason = failure.Error()
	op.UpdatedAt = c.now().UTC()
	if retryable {
		op.Status = OperationRetryable
		return cloneOperation(op)
	}
	op.Status = OperationFailed
	delete(c.provisioning, seatID)
	return cloneOperation(op)
}

func validateProvisionCommand(command ProvisionSeatCommand) error {
	if command.OperationID == "" || command.SeatID == "" || command.PoolID == "" || command.OwnerUserID == "" ||
		command.ExistingGroupID <= 0 || command.AssignmentEpoch != 1 || command.PrincipalConcurrency <= 0 ||
		command.PrincipalRPMLimit < 0 || command.SubscriptionExpiresAt.IsZero() {
		return ErrInvalidProvisionRequest
	}
	if len(command.OperationID) > 128 || len(command.SeatID) > 128 || len(command.PoolID) > 128 || len(command.OwnerUserID) > 128 {
		return ErrInvalidProvisionRequest
	}
	for _, limit := range []float64{command.APIKeyQuota, command.APIKeyRateLimit5h, command.APIKeyRateLimit1d, command.APIKeyRateLimit7d} {
		if math.IsNaN(limit) || math.IsInf(limit, 0) || limit < 0 {
			return ErrInvalidProvisionRequest
		}
	}
	return nil
}

func provisionCommandDigest(command ProvisionSeatCommand) (string, error) {
	payload := struct {
		Version               int       `json:"version"`
		OperationID           string    `json:"operation_id"`
		SeatID                string    `json:"seat_id"`
		PoolID                string    `json:"pool_id"`
		OwnerUserID           string    `json:"owner_user_id"`
		ExistingGroupID       int64     `json:"existing_group_id"`
		AssignmentEpoch       uint64    `json:"assignment_epoch"`
		PrincipalConcurrency  int       `json:"principal_concurrency"`
		PrincipalRPMLimit     int       `json:"principal_rpm_limit"`
		SubscriptionExpiresAt time.Time `json:"subscription_expires_at"`
		APIKeyQuota           float64   `json:"api_key_quota"`
		APIKeyRateLimit5h     float64   `json:"api_key_rate_limit_5h"`
		APIKeyRateLimit1d     float64   `json:"api_key_rate_limit_1d"`
		APIKeyRateLimit7d     float64   `json:"api_key_rate_limit_7d"`
	}{
		Version: 1, OperationID: command.OperationID, SeatID: command.SeatID, PoolID: command.PoolID,
		OwnerUserID: command.OwnerUserID, ExistingGroupID: command.ExistingGroupID,
		AssignmentEpoch: command.AssignmentEpoch, PrincipalConcurrency: command.PrincipalConcurrency,
		PrincipalRPMLimit: command.PrincipalRPMLimit, SubscriptionExpiresAt: command.SubscriptionExpiresAt.UTC(),
		APIKeyQuota: command.APIKeyQuota, APIKeyRateLimit5h: command.APIKeyRateLimit5h,
		APIKeyRateLimit1d: command.APIKeyRateLimit1d, APIKeyRateLimit7d: command.APIKeyRateLimit7d,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (c *Coordinator) CreateSeat(id, poolID, ownerUserID string) (*domain.Seat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.seats[id]; exists {
		return nil, errors.New("seat already exists")
	}
	seat, err := domain.NewSeat(id, poolID, ownerUserID, c.now())
	if err != nil {
		return nil, err
	}
	if epoch := c.poolEpochs[poolID]; epoch > 0 {
		seat.MembershipEpoch = epoch
	} else {
		c.poolEpochs[poolID] = seat.MembershipEpoch
	}
	c.seats[id] = seat
	return cloneSeat(seat), nil
}

func (c *Coordinator) Seat(_ context.Context, id string) (*domain.Seat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seat, ok := c.seats[id]
	if !ok {
		return nil, ErrSeatNotFound
	}
	return cloneSeat(seat), nil
}

func (c *Coordinator) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]PendingSettlement, error) {
	seatID = strings.TrimSpace(seatID)
	if !validSettlementIdentifier(seatID) {
		return nil, ErrInvalidSettlementRequest
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	gateway, ok := c.gateway.(PendingSettlementGateway)
	if !ok {
		return nil, ErrSettlementGatewayUnavailable
	}
	return gateway.ListPendingSettlements(ctx, seatID, limit)
}

func (c *Coordinator) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*PendingSettlement, error) {
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	if !validSettlementIdentifier(seatID) || !validSettlementIdentifier(settlementID) {
		return nil, ErrInvalidSettlementRequest
	}
	gateway, ok := c.gateway.(PendingSettlementGateway)
	if !ok {
		return nil, ErrSettlementGatewayUnavailable
	}
	return gateway.GetPendingSettlement(ctx, seatID, settlementID)
}

func (c *Coordinator) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, command ResolvePendingSettlementCommand) (*SettlementResolution, error) {
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	command.OperationID = strings.TrimSpace(command.OperationID)
	command.Reason = strings.TrimSpace(command.Reason)
	command.Evidence = strings.TrimSpace(command.Evidence)
	if !validSettlementIdentifier(seatID) || !validSettlementIdentifier(settlementID) ||
		!validSettlementIdentifier(command.OperationID) || command.Reason == "" || command.Evidence == "" ||
		len(command.Reason) > 1000 || len(command.Evidence) > 4000 {
		return nil, ErrInvalidSettlementRequest
	}
	gateway, ok := c.gateway.(PendingSettlementGateway)
	if !ok {
		return nil, ErrSettlementGatewayUnavailable
	}
	return gateway.ResolvePendingSettlement(ctx, seatID, settlementID, command)
}

func validSettlementIdentifier(value string) bool {
	return value != "" && len(value) <= 128
}

func (c *Coordinator) Operation(_ context.Context, id string) (*Operation, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	op, ok := c.operations[id]
	if !ok {
		return nil, false, nil
	}
	copy := *op
	// 查询接口只返回操作状态；领取令牌仅随原始幂等命令返回，避免按 ID 探测凭据。
	copy.CredentialClaimToken = ""
	copy.credential = ""
	return &copy, true, nil
}

func (c *Coordinator) Suspend(ctx context.Context, operationID, seatID string) (*Operation, error) {
	c.mu.Lock()
	seat, ok := c.seats[seatID]
	if !ok {
		c.mu.Unlock()
		return nil, ErrSeatNotFound
	}
	if existing, found, err := c.existingOperation(operationID, OperationSuspend, seatID, "", ""); found || err != nil {
		c.mu.Unlock()
		return existing, err
	}
	now := c.now()
	if err := seat.StartSuspend(operationID, now); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	op := c.newOperation(operationID, OperationSuspend, seatID, "", "", now)
	command := SuspendCommand{
		OperationID: operationID,
		SeatID:      seat.ID, PoolID: seat.PoolID, UserID: seat.Current.UserID,
		AssignmentEpoch: seat.AssignmentEpoch,
	}
	c.mu.Unlock()

	result, err := c.gateway.Suspend(ctx, command)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.handleGatewayFailure(op, err, func() { _ = seat.MarkSuspendRejected(operationID, c.now()) })
		return cloneOperation(op), err
	}
	if result.Draining {
		if err := seat.MarkDraining(operationID, c.now()); err != nil {
			op.Status = OperationReconcileRequired
			op.Reason = err.Error()
			op.UpdatedAt = c.now()
			return cloneOperation(op), err
		}
		op.Status = OperationReconcileRequired
		op.Reason = "upstream freeze barriers are still draining"
		op.UpdatedAt = c.now()
		return cloneOperation(op), nil
	}
	if result.Freeze == nil {
		err := errors.New("upstream omitted freeze snapshot")
		op.Status = OperationReconcileRequired
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	if err := seat.CompleteSuspend(*result.Freeze, c.now()); err != nil {
		op.Status = OperationReconcileRequired
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	op.Status = OperationSucceeded
	op.UpdatedAt = c.now()
	return cloneOperation(op), nil
}

func (c *Coordinator) AssignTemporary(ctx context.Context, operationID, seatID, targetUser string) (*Operation, error) {
	return c.assign(ctx, operationID, seatID, targetUser, "", OperationAssignTemp)
}

func (c *Coordinator) Restore(ctx context.Context, operationID, seatID string) (*Operation, error) {
	return c.assign(ctx, operationID, seatID, "", "", OperationRestore)
}

func (c *Coordinator) ReplacePermanently(ctx context.Context, operationID, seatID, targetUser, controlRotationEvidenceRef string) (*Operation, error) {
	return c.assign(ctx, operationID, seatID, targetUser, controlRotationEvidenceRef, OperationReplace)
}

func (c *Coordinator) assign(ctx context.Context, operationID, seatID, targetUser, controlRotationEvidenceRef string, kind OperationKind) (*Operation, error) {
	c.mu.Lock()
	seat, ok := c.seats[seatID]
	if !ok {
		c.mu.Unlock()
		return nil, ErrSeatNotFound
	}
	if kind == OperationRestore {
		targetUser = seat.OwnerUserID
	}
	if existing, found, err := c.existingOperation(operationID, kind, seatID, targetUser, controlRotationEvidenceRef); found || err != nil {
		c.mu.Unlock()
		return existing, err
	}
	if kind == OperationReplace {
		if c.evidence == nil {
			c.mu.Unlock()
			return nil, errors.New("control credential rotation evidence verifier is unavailable")
		}
		if err := c.evidence.ValidateControlRotationEvidence(controlRotationEvidenceRef, seat.PoolID, seat.MembershipEpoch, seat.MembershipEpoch+1); err != nil {
			c.mu.Unlock()
			return nil, fmt.Errorf("validate control credential rotation evidence: %w", err)
		}
	}
	// 所有成员变更先登记到 Pool：临时分配和恢复可共享，永久换员必须独占。
	// 同一幂等操作重复进入时复用原登记，避免重试与自身发生冲突。
	if err := c.beginPoolMemberOperation(seat.PoolID, operationID, seat.ID, kind); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	now := c.now()
	var err error
	switch kind {
	case OperationAssignTemp:
		err = seat.StartTemporaryAssignment(operationID, targetUser, now)
	case OperationRestore:
		err = seat.StartRestore(operationID, now)
	case OperationReplace:
		err = seat.StartPermanentReplacement(operationID, targetUser, controlRotationEvidenceRef, now)
	default:
		err = errors.New("unsupported assignment operation")
	}
	if err != nil {
		c.finishPoolMemberOperation(seat.PoolID, operationID)
		c.mu.Unlock()
		return nil, err
	}
	op := c.newOperation(operationID, kind, seatID, targetUser, controlRotationEvidenceRef, now)
	command := AssignmentCommand{
		OperationID: operationID,
		SeatID:      seat.ID, PoolID: seat.PoolID, TargetUser: targetUser,
		AssignmentEpoch: seat.AssignmentEpoch, MembershipEpoch: seat.MembershipEpoch,
		FreezeOperationID:          seat.Freeze.OperationID,
		Permanent:                  kind == OperationReplace,
		Mode:                       kind,
		ControlRotationEvidenceRef: controlRotationEvidenceRef,
	}
	c.mu.Unlock()

	result, callErr := c.gateway.Assign(ctx, command)
	c.mu.Lock()
	defer c.mu.Unlock()
	if callErr != nil {
		c.handleGatewayFailure(op, callErr, func() { _ = seat.MarkAssignmentRejected(operationID, c.now()) })
		if op.Status != OperationReconcileRequired {
			c.finishPoolMemberOperation(seat.PoolID, operationID)
		}
		return cloneOperation(op), callErr
	}
	if result.Credential == "" {
		err := errors.New("gateway omitted rotated access credential")
		op.Status = OperationReconcileRequired
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	claimToken, err := c.claimToken()
	if err != nil {
		op.Status = OperationReconcileRequired
		op.Reason = "credential claim token generation failed"
		op.UpdatedAt = c.now()
		return cloneOperation(op), fmt.Errorf("generate credential claim token: %w", err)
	}
	if kind == OperationReplace {
		if err := c.evidence.CommitControlRotationEvidence(controlRotationEvidenceRef, seat.PoolID, seat.MembershipEpoch, seat.MembershipEpoch+1); err != nil {
			op.Status = OperationReconcileRequired
			op.Reason = err.Error()
			op.UpdatedAt = c.now()
			return cloneOperation(op), err
		}
	}
	if err := seat.CompleteAssignment(operationID, result.AccessCredentialRotationComplete, controlRotationEvidenceRef, c.now()); err != nil {
		op.Status = OperationReconcileRequired
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	if kind == OperationReplace {
		c.advancePoolMembershipEpoch(seat.PoolID, seat.MembershipEpoch)
	}
	c.finishPoolMemberOperation(seat.PoolID, operationID)
	op.Status = OperationSucceeded
	c.issueCredentialClaimLocked(op, claimToken, result.Credential)
	op.UpdatedAt = c.now()
	responseOperation := cloneOperation(op)
	responseOperation.CredentialClaimToken = claimToken
	return responseOperation, nil
}

// Reconcile 查询上游幂等操作结果。仅结果未知的操作允许进入此流程。
func (c *Coordinator) Reconcile(ctx context.Context, operationID string) (*Operation, error) {
	c.mu.Lock()
	op, ok := c.operations[operationID]
	if !ok {
		c.mu.Unlock()
		return nil, errors.New("operation not found")
	}
	if op.Status != OperationReconcileRequired {
		copy := cloneOperation(op)
		c.mu.Unlock()
		return copy, nil
	}
	c.mu.Unlock()

	result, err := c.gateway.OperationStatus(ctx, operationID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	seat := c.seats[op.SeatID]
	if result.Draining {
		if seat.State == domain.SeatSuspendPending {
			_ = seat.MarkDraining(operationID, c.now())
		}
		op.Reason = "upstream freeze barriers are still draining"
		op.UpdatedAt = c.now()
		return cloneOperation(op), nil
	}
	if !result.Applied {
		op.Reason = "upstream result remains unknown"
		op.UpdatedAt = c.now()
		return cloneOperation(op), nil
	}
	if op.Kind == OperationSuspend {
		if result.Freeze == nil {
			return cloneOperation(op), errors.New("upstream omitted freeze snapshot")
		}
		err = seat.CompleteSuspend(*result.Freeze, c.now())
	} else {
		if result.Credential == "" {
			err = errors.New("gateway omitted rotated access credential")
		} else {
			if op.Kind == OperationReplace {
				err = c.evidence.CommitControlRotationEvidence(op.ControlRotationEvidenceRef, seat.PoolID, seat.MembershipEpoch, seat.MembershipEpoch+1)
			}
			if err == nil {
				err = seat.CompleteAssignment(operationID, result.AccessCredentialRotationComplete, op.ControlRotationEvidenceRef, c.now())
			}
		}
	}
	if err != nil {
		op.Reason = err.Error()
		op.UpdatedAt = c.now()
		return cloneOperation(op), err
	}
	if op.Kind == OperationReplace {
		c.advancePoolMembershipEpoch(seat.PoolID, seat.MembershipEpoch)
	}
	if op.Kind != OperationSuspend {
		c.finishPoolMemberOperation(seat.PoolID, operationID)
	}
	op.Status = OperationSucceeded
	op.Reason = ""
	op.UpdatedAt = c.now()
	responseOperation := cloneOperation(op)
	if op.Kind != OperationSuspend {
		claimToken, tokenErr := c.claimToken()
		if tokenErr != nil {
			op.Status = OperationReconcileRequired
			op.Reason = "credential claim token generation failed"
			return cloneOperation(op), fmt.Errorf("generate credential claim token: %w", tokenErr)
		}
		c.issueCredentialClaimLocked(op, claimToken, result.Credential)
		responseOperation = cloneOperation(op)
		responseOperation.CredentialClaimToken = claimToken
	}
	return responseOperation, nil
}

// AcknowledgeCredential 使用绑定目标成员的随机令牌完成一次性领取。
// Provision 凭据必须先由 Sub2API 持久确认；确认结果未知时失败关闭且绝不披露明文。
func (c *Coordinator) AcknowledgeCredential(ctx context.Context, operationID, targetUser, claimToken string) (*CredentialDelivery, error) {
	c.mu.Lock()
	op, ok := c.operations[operationID]
	if !ok {
		c.mu.Unlock()
		return nil, errors.New("operation not found")
	}
	if op.Status != OperationSucceeded || op.Kind == OperationSuspend {
		c.mu.Unlock()
		return nil, errors.New("operation has no deliverable credential")
	}
	if op.CredentialClaimExpiresAt == nil || !c.now().Before(*op.CredentialClaimExpiresAt) {
		c.expireCredentialClaimLocked(op)
		c.mu.Unlock()
		return nil, ErrCredentialClaimExpired
	}
	providedHash := sha256.Sum256([]byte(claimToken))
	if targetUser == "" || targetUser != op.TargetUser || claimToken == "" ||
		subtle.ConstantTimeCompare(providedHash[:], op.credentialClaimTokenHash[:]) != 1 {
		c.mu.Unlock()
		return nil, errors.New("credential claim is not authorized for the target member")
	}
	if op.credential == "" {
		c.mu.Unlock()
		return nil, errors.New("credential was already claimed")
	}
	if op.Kind == OperationProvision {
		return c.acknowledgeProvisionCredential(ctx, op)
	}
	defer c.mu.Unlock()
	delivery := &CredentialDelivery{OperationID: operationID, TargetUser: op.TargetUser, Credential: op.credential}
	c.completeCredentialClaimLocked(op)
	op.UpdatedAt = c.now()
	return delivery, nil
}

// acknowledgeProvisionCredential 进入时持有 Coordinator 锁，调用上游前必须释放。
func (c *Coordinator) acknowledgeProvisionCredential(ctx context.Context, op *Operation) (*CredentialDelivery, error) {
	if op.CredentialClaimStatus == credentialClaimRejected {
		c.mu.Unlock()
		return nil, ErrCredentialClaimRejected
	}
	if op.CredentialClaimStatus == credentialClaimAckPending {
		c.mu.Unlock()
		return nil, ErrCredentialClaimPending
	}
	op.CredentialClaimStatus = credentialClaimAckPending
	op.UpdatedAt = c.now().UTC()
	command := ProvisionCredentialAckCommand{
		SeatID: op.SeatID, ProvisionOperationID: op.ID,
		ClaimOperationID: op.credentialClaimOperationID, ClaimedBy: op.TargetUser,
		CredentialFingerprint: credentialFingerprint(op.credential),
	}
	c.mu.Unlock()

	gateway, ok := c.gateway.(ProvisionCredentialAcknowledger)
	if !ok {
		c.mu.Lock()
		op.CredentialClaimStatus = credentialClaimRejected
		op.credential = ""
		op.credentialClaimTokenHash = [32]byte{}
		op.UpdatedAt = c.now().UTC()
		c.mu.Unlock()
		return nil, ErrProvisionGatewayUnavailable
	}
	result, err := gateway.AcknowledgeProvisionCredential(ctx, command)
	if err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		var gatewayErr *GatewayError
		if !errors.As(err, &gatewayErr) || gatewayErr.Retryable || gatewayErr.Ambiguous {
			op.CredentialClaimStatus = credentialClaimReconcileRequired
		} else {
			// 明确拒绝同样失败关闭，避免上游已由其他流程领取后平台继续持有可交付秘密。
			op.CredentialClaimStatus = credentialClaimRejected
			op.credential = ""
			op.credentialClaimTokenHash = [32]byte{}
		}
		op.UpdatedAt = c.now().UTC()
		return nil, err
	}
	if result.ExternalSeatID != command.SeatID || result.ProvisionOperationID != command.ProvisionOperationID ||
		result.ClaimOperationID != command.ClaimOperationID || result.ClaimedBy != command.ClaimedBy ||
		result.CredentialFingerprint != command.CredentialFingerprint ||
		!result.CredentialClaimed || result.ClaimedAt.IsZero() {
		c.mu.Lock()
		op.CredentialClaimStatus = credentialClaimReconcileRequired
		op.UpdatedAt = c.now().UTC()
		c.mu.Unlock()
		return nil, &GatewayError{Reason: "Sub2API credential acknowledgement response is invalid", Retryable: true, Ambiguous: true}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if op.CredentialClaimExpiresAt == nil || !c.now().Before(*op.CredentialClaimExpiresAt) ||
		op.CredentialClaimStatus == credentialClaimExpired || op.credential == "" {
		c.expireCredentialClaimLocked(op)
		return nil, ErrCredentialClaimExpired
	}
	delivery := &CredentialDelivery{OperationID: op.ID, TargetUser: op.TargetUser, Credential: op.credential}
	c.completeCredentialClaimLocked(op)
	op.UpdatedAt = c.now().UTC()
	return delivery, nil
}

func (c *Coordinator) completeCredentialClaimLocked(op *Operation) {
	op.credential = ""
	op.CredentialClaimToken = ""
	op.credentialClaimTokenHash = [32]byte{}
	op.CredentialClaimStatus = credentialClaimClaimed
	if timer := c.claimTimers[op.ID]; timer != nil {
		timer.Stop()
		delete(c.claimTimers, op.ID)
	}
}

func (c *Coordinator) newOperation(id string, kind OperationKind, seatID, targetUser, controlRotationEvidenceRef string, now time.Time) *Operation {
	op := &Operation{ID: id, Kind: kind, SeatID: seatID, TargetUser: targetUser, ControlRotationEvidenceRef: controlRotationEvidenceRef, Status: OperationRunning, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	c.operations[id] = op
	return op
}

func (c *Coordinator) existingOperation(id string, kind OperationKind, seatID, targetUser, controlRotationEvidenceRef string) (*Operation, bool, error) {
	op, ok := c.operations[id]
	if !ok {
		return nil, false, nil
	}
	if op.Kind != kind || op.SeatID != seatID || op.TargetUser != targetUser || op.ControlRotationEvidenceRef != controlRotationEvidenceRef {
		return nil, false, ErrOperationConflict
	}
	// 明确未应用且可重试的命令允许同一幂等键重新投递；结果不明的命令只能走 Reconcile。
	if op.Status == OperationRetryable {
		return nil, false, nil
	}
	return cloneOperation(op), true, nil
}

func (c *Coordinator) beginPoolMemberOperation(poolID, operationID, seatID string, kind OperationKind) error {
	operations := c.poolMemberOps[poolID]
	if existing, ok := operations[operationID]; ok {
		if existing.SeatID != seatID || existing.Kind != kind {
			return ErrOperationConflict
		}
		return nil
	}
	if kind == OperationReplace {
		if len(operations) != 0 {
			return errors.New("another member operation is pending for this pool")
		}
		c.poolPending[poolID] = operationID
	} else if pending := c.poolPending[poolID]; pending != "" {
		return errors.New("a membership epoch transition is pending for this pool")
	}
	if operations == nil {
		operations = make(map[string]poolMemberOperation)
		c.poolMemberOps[poolID] = operations
	}
	operations[operationID] = poolMemberOperation{SeatID: seatID, Kind: kind}
	return nil
}

func (c *Coordinator) finishPoolMemberOperation(poolID, operationID string) {
	operations := c.poolMemberOps[poolID]
	delete(operations, operationID)
	if len(operations) == 0 {
		delete(c.poolMemberOps, poolID)
	}
	if c.poolPending[poolID] == operationID {
		delete(c.poolPending, poolID)
	}
}

func (c *Coordinator) advancePoolMembershipEpoch(poolID string, epoch uint64) {
	if epoch <= c.poolEpochs[poolID] {
		return
	}
	c.poolEpochs[poolID] = epoch
	for _, candidate := range c.seats {
		if candidate.PoolID == poolID {
			candidate.MembershipEpoch = epoch
		}
	}
}

func newClaimToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (c *Coordinator) handleGatewayFailure(op *Operation, err error, reject func()) {
	var gatewayErr *GatewayError
	op.Reason = err.Error()
	op.UpdatedAt = c.now()
	if !errors.As(err, &gatewayErr) {
		op.Status = OperationReconcileRequired
		return
	}
	if gatewayErr.Ambiguous {
		op.Status = OperationReconcileRequired
		return
	}
	reject()
	if gatewayErr.Retryable {
		op.Status = OperationRetryable
	} else {
		op.Status = OperationFailed
	}
}

func cloneOperation(op *Operation) *Operation {
	if op == nil {
		return nil
	}
	copy := *op
	return &copy
}

func cloneSeat(seat *domain.Seat) *domain.Seat {
	if seat == nil {
		return nil
	}
	copy := *seat
	if seat.Freeze != nil {
		freeze := *seat.Freeze
		freeze.Usage = cloneFloatMap(seat.Freeze.Usage)
		freeze.WindowStarts = cloneTimeMap(seat.Freeze.WindowStarts)
		copy.Freeze = &freeze
	}
	if seat.Pending != nil {
		pending := *seat.Pending
		copy.Pending = &pending
	}
	return &copy
}

func cloneFloatMap(source map[string]float64) map[string]float64 {
	result := make(map[string]float64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneTimeMap(source map[string]*time.Time) map[string]*time.Time {
	result := make(map[string]*time.Time, len(source))
	for key, value := range source {
		if value != nil {
			copy := *value
			result[key] = &copy
		}
	}
	return result
}

func (s OperationStatus) String() string { return string(s) }

func (o Operation) String() string {
	return fmt.Sprintf("%s:%s:%s", o.Kind, o.SeatID, o.Status)
}
