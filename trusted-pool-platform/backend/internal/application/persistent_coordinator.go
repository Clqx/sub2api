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
	"time"

	"trusted-pool-platform/backend/internal/domain"
)

var ErrPersistentWorkflowUnsupported = errors.New("workflow is not enabled in the persistent runtime")

// PersistentOperationError 只公开稳定分类，不携带上游响应体或数据库详情。
// error_code 持久化后，首次请求与进程重启后的幂等重放会得到同一 HTTP 语义。
type PersistentOperationError struct {
	Code string
}

func (e *PersistentOperationError) Error() string {
	if e == nil || strings.TrimSpace(e.Code) == "" {
		return "persistent operation failed"
	}
	return "persistent operation failed: " + e.Code
}

// CredentialEnvelopeCipher 只在应用层接触明文；Store 永远只收到 KMS 包装后的包络。
type CredentialEnvelopeCipher interface {
	Seal(context.Context, string, []byte) (CredentialEnvelope, error)
	Open(context.Context, CredentialEnvelope, []byte) (string, error)
}

type PersistentProvisionGateway interface {
	ProvisionGateway
	ProvisionCredentialAcknowledger
	Suspend(context.Context, SuspendCommand) (SuspendResult, error)
	ReconcileSuspend(context.Context, SuspendCommand) (GatewayOperationResult, error)
	Assign(context.Context, AssignmentCommand) (AssignmentResult, error)
	ReconcileAssignment(context.Context, AssignmentCommand) (AssignmentResult, error)
}

type PersistentCoordinatorOptions struct {
	IntegrationClientID string
	SettlementActorID   string
	SettlementRead      PendingSettlementReadGateway
	SettlementResolve   PendingSettlementResolveGateway
	WorkerID            string
	LeaseDuration       time.Duration
	ClaimTTL            time.Duration
	RecoveryBackoff     time.Duration
	Now                 func() time.Time
	ClaimToken          func() (string, error)
}

// PersistentCoordinator 的所有业务真相均来自 WorkflowStore，不使用进程内 map 恢复状态。
type PersistentCoordinator struct {
	store             WorkflowStore
	gateway           PersistentProvisionGateway
	cipher            CredentialEnvelopeCipher
	clientID          string
	workerID          string
	leaseDuration     time.Duration
	claimTTL          time.Duration
	recoveryBackoff   time.Duration
	now               func() time.Time
	claimToken        func() (string, error)
	settlementRead    PendingSettlementReadGateway
	settlementResolve PendingSettlementResolveGateway
	settlementActorID string
}

func NewPersistentCoordinator(store WorkflowStore, gateway PersistentProvisionGateway, cipher CredentialEnvelopeCipher, options PersistentCoordinatorOptions) (*PersistentCoordinator, error) {
	clientID, settlementActorID := strings.TrimSpace(options.IntegrationClientID), strings.TrimSpace(options.SettlementActorID)
	if store == nil || gateway == nil || cipher == nil || clientID == "" ||
		strings.TrimSpace(options.WorkerID) == "" {
		return nil, ErrWorkflowInvalidData
	}
	settlementConfigured := options.SettlementRead != nil || options.SettlementResolve != nil || settlementActorID != ""
	if settlementConfigured && (options.SettlementRead == nil || options.SettlementResolve == nil ||
		!validSettlementIdentifier(settlementActorID) || settlementActorID == clientID) {
		return nil, ErrWorkflowInvalidData
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 30 * time.Second
	}
	if options.ClaimTTL <= 0 {
		options.ClaimTTL = defaultCredentialClaimTTL
	}
	if options.RecoveryBackoff <= 0 {
		options.RecoveryBackoff = time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.ClaimToken == nil {
		options.ClaimToken = newPersistentClaimToken
	}
	return &PersistentCoordinator{
		store: store, gateway: gateway, cipher: cipher,
		clientID: clientID, workerID: strings.TrimSpace(options.WorkerID),
		leaseDuration: options.LeaseDuration, claimTTL: options.ClaimTTL, recoveryBackoff: options.RecoveryBackoff,
		now: options.Now, claimToken: options.ClaimToken,
		settlementRead: options.SettlementRead, settlementResolve: options.SettlementResolve,
		settlementActorID: settlementActorID,
	}, nil
}

func (c *PersistentCoordinator) ProvisionSeat(ctx context.Context, command ProvisionSeatCommand) (*ProvisionSeatResult, error) {
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
	snapshot, requestHash, err := persistentProvisionIntent(command)
	if err != nil {
		return nil, err
	}
	key := OperationKey{ClientID: c.clientID, OperationID: command.OperationID}
	stored, _, err := c.store.BeginOperation(ctx, BeginOperationInput{
		Key: key, Kind: OperationProvision, TargetType: "SEAT", TargetExternalID: command.SeatID,
		RequestHash: requestHash, RequestSnapshot: snapshot,
	})
	if err != nil {
		return nil, err
	}
	if stored.Status == OperationSucceeded {
		return c.loadProvisionResult(ctx, stored, false, "")
	}
	if stored.Status == OperationFailed {
		return &ProvisionSeatResult{Operation: storedOperationView(stored, nil)}, persistentOperationFailure(stored.ErrorCode)
	}
	lease, err := c.store.AcquireOperationLease(ctx, AcquireOperationLeaseInput{
		Key: key, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return &ProvisionSeatResult{Operation: storedOperationView(stored, nil)}, err
	}
	if err := c.store.ValidateProvisionPreflight(ctx, ProvisionPreflightInput{
		Key: key, PoolExternalID: command.PoolID, SeatExternalID: command.SeatID,
		OwnerExternalID: command.OwnerUserID, ExistingGroupID: command.ExistingGroupID,
		AssignmentEpoch: command.AssignmentEpoch,
	}); err != nil {
		committed, commitErr := c.store.CommitOperation(ctx, CommitOperationInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
			Status: OperationRetryable, ErrorCode: "CALLER_REPLAY_REQUIRED",
			ErrorDetail: "provision preflight must be satisfied before retry",
		})
		if commitErr != nil {
			return nil, commitErr
		}
		return &ProvisionSeatResult{Operation: storedOperationView(committed, nil)}, err
	}
	upstream, callErr := c.gateway.ProvisionSeat(ctx, command)
	if callErr != nil {
		status := OperationRetryable
		var gatewayErr *GatewayError
		if errors.As(callErr, &gatewayErr) {
			if gatewayErr.Ambiguous {
				status = OperationReconcileRequired
			} else if !gatewayErr.Retryable {
				status = OperationFailed
			}
		}
		code := persistentErrorCode(callErr)
		committed, commitErr := c.store.CommitOperation(ctx, CommitOperationInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken, Status: status,
			ErrorCode: code, ErrorDetail: code,
		})
		if commitErr != nil {
			return nil, commitErr
		}
		return &ProvisionSeatResult{Operation: storedOperationView(committed, nil)}, persistentOperationFailure(code)
	}
	if upstream.ExternalSeatID != command.SeatID || upstream.ExternalPoolID != command.PoolID ||
		!strings.EqualFold(upstream.State, "ACTIVE") || upstream.AssignmentEpoch != command.AssignmentEpoch ||
		upstream.PrincipalUserID <= 0 || upstream.SubscriptionID <= 0 || upstream.APIKeyID <= 0 ||
		upstream.ActiveAPIKeyVersion != 1 || upstream.LastOperationID != command.OperationID || upstream.Credential == "" {
		validationErr := errors.New("Sub2API provision response does not match the requested active seat")
		_, commitErr := c.store.CommitOperation(ctx, CommitOperationInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken, Status: OperationRetryable,
			ErrorCode: "UPSTREAM_RESPONSE_INVALID", ErrorDetail: validationErr.Error(),
		})
		if commitErr != nil {
			return nil, commitErr
		}
		return nil, persistentOperationFailure("UPSTREAM_RESPONSE_INVALID")
	}
	claimToken, err := c.claimToken()
	if err != nil {
		return nil, fmt.Errorf("generate credential claim token: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(claimToken))
	fingerprint := sha256.Sum256([]byte(upstream.Credential))
	claimOperationID := provisionClaimOperationID(command.OperationID)
	aad := persistentClaimAAD(c.clientID, command.OperationID, claimOperationID, command.PoolID,
		command.SeatID, command.OwnerUserID, fingerprint[:])
	envelope, err := c.cipher.Seal(ctx, upstream.Credential, aad)
	if err != nil {
		return nil, fmt.Errorf("seal provision credential: %w", err)
	}
	aadHash := sha256.Sum256(aad)
	envelope.AADHash = aadHash
	// 明文 credential 绝不能进入 operation 快照、错误详情或日志。
	resultSnapshot, err := json.Marshal(struct {
		ExternalPoolID        string `json:"external_pool_id"`
		ExternalSeatID        string `json:"external_seat_id"`
		State                 string `json:"state"`
		AssignmentEpoch       uint64 `json:"assignment_epoch"`
		PrincipalUserID       int64  `json:"principal_user_id"`
		SubscriptionID        int64  `json:"subscription_id"`
		APIKeyID              int64  `json:"api_key_id"`
		ActiveAPIKeyVersion   uint64 `json:"active_api_key_version"`
		LastOperationID       string `json:"last_operation_id"`
		CredentialFingerprint string `json:"credential_fingerprint"`
	}{
		upstream.ExternalPoolID, upstream.ExternalSeatID, upstream.State, upstream.AssignmentEpoch,
		upstream.PrincipalUserID, upstream.SubscriptionID, upstream.APIKeyID, upstream.ActiveAPIKeyVersion,
		upstream.LastOperationID,
		hex.EncodeToString(fingerprint[:]),
	})
	if err != nil {
		return nil, err
	}
	claimInput := CreateCredentialClaimInput{
		Key: ClaimKey(key), SeatExternalID: command.SeatID, TargetMemberExternalID: command.OwnerUserID,
		ClaimOperationID: claimOperationID, TokenHash: tokenHash,
		CredentialFingerprint: fingerprint, Envelope: envelope, ClaimTTL: c.claimTTL,
	}
	committed, claim, seat, err := c.store.CommitProvisionWithCredentialClaim(ctx, CommitProvisionWithCredentialClaimInput{
		Operation: CommitOperationWithCredentialClaimInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
			ResultSnapshot: resultSnapshot, Claim: claimInput,
		},
		PoolExternalID: command.PoolID, OwnerExternalID: command.OwnerUserID,
		ExistingGroupID: command.ExistingGroupID, AssignmentEpoch: command.AssignmentEpoch,
		PrincipalUserID: upstream.PrincipalUserID, SubscriptionID: upstream.SubscriptionID, APIKeyID: upstream.APIKeyID,
	})
	if err != nil {
		return nil, err
	}
	view := storedOperationView(committed, claim)
	view.CredentialClaimToken = claimToken
	return &ProvisionSeatResult{Seat: persistedSeatDomain(seat), Operation: view}, nil
}

func (c *PersistentCoordinator) AcknowledgeCredential(ctx context.Context, operationID, targetUser, claimToken string) (*CredentialDelivery, error) {
	key := ClaimKey{ClientID: c.clientID, OperationID: strings.TrimSpace(operationID)}
	providedHash := sha256.Sum256([]byte(claimToken))
	preflight, err := c.store.LoadCredentialClaim(ctx, key)
	if err != nil {
		return nil, err
	}
	if !persistentClaimAuthorized(preflight, targetUser, claimToken, providedHash) {
		return nil, errors.New("credential claim is not authorized for the target member")
	}
	lease, err := c.store.AcquireCredentialClaimLease(ctx, AcquireCredentialClaimLeaseInput{
		Key: key, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if !persistentClaimAuthorized(lease.Claim, targetUser, claimToken, providedHash) {
		return nil, errors.New("credential claim is not authorized for the target member")
	}
	if lease.Claim.Expired {
		_, expireErr := c.store.ExpireCredentialClaim(ctx, ExpireCredentialClaimInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		if expireErr != nil {
			return nil, expireErr
		}
		return nil, ErrCredentialClaimExpired
	}
	isProvision := lease.Claim.OperationKind == OperationProvision
	isAssignment := lease.Claim.OperationKind == OperationAssignTemp || lease.Claim.OperationKind == OperationRestore
	if !isProvision && !isAssignment {
		return nil, ErrPersistentWorkflowUnsupported
	}
	if isAssignment && lease.Claim.Status != CredentialClaimReady {
		switch lease.Claim.Status {
		case CredentialClaimExpired:
			return nil, ErrCredentialClaimExpired
		case CredentialClaimRejected:
			return nil, ErrCredentialClaimRejected
		default:
			return nil, ErrWorkflowInvalidState
		}
	}
	if isProvision && (lease.Claim.Status == CredentialClaimReady || lease.Claim.Status == CredentialClaimReconcileRequired) {
		lease.Claim, err = c.store.BeginCredentialAck(ctx, BeginCredentialAckInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		if err != nil {
			return nil, err
		}
	}
	if isProvision && len(lease.Claim.AckResultSnapshot) == 0 {
		if err := c.commitProvisionAck(ctx, lease); err != nil {
			return nil, err
		}
		lease, err = c.store.AcquireCredentialClaimLease(ctx, AcquireCredentialClaimLeaseInput{
			Key: key, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
		})
		if err != nil {
			return nil, err
		}
	}
	// ack 与再次取得领取租约之间可能跨越 expires_at；必须再次采用数据库时钟投影判定。
	if lease.Claim.Expired {
		_, expireErr := c.store.ExpireCredentialClaim(ctx, ExpireCredentialClaimInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		if expireErr != nil {
			return nil, expireErr
		}
		return nil, ErrCredentialClaimExpired
	}
	seat, err := c.store.LoadPersistedSeat(ctx, lease.Claim.SeatExternalID)
	if err != nil {
		return nil, err
	}
	aad := persistentClaimAAD(c.clientID, key.OperationID, lease.Claim.ClaimOperationID, seat.PoolExternalID,
		lease.Claim.SeatExternalID, targetUser, lease.Claim.CredentialFingerprint)
	credential, err := c.cipher.Open(ctx, lease.Claim.Envelope, aad)
	if err != nil {
		return nil, fmt.Errorf("open credential envelope: %w", err)
	}
	claimed, err := c.store.ClaimCredential(ctx, ClaimCredentialInput{
		Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		TargetMemberExternalID: targetUser, TokenHash: providedHash,
	})
	if err != nil {
		return nil, err
	}
	return &CredentialDelivery{OperationID: claimed.Key.OperationID, TargetUser: targetUser, Credential: credential}, nil
}

func (c *PersistentCoordinator) commitProvisionAck(ctx context.Context, lease *CredentialClaimLease) error {
	command := ProvisionCredentialAckCommand{
		SeatID: lease.Claim.SeatExternalID, ProvisionOperationID: lease.Claim.Key.OperationID,
		ClaimOperationID: lease.Claim.ClaimOperationID, ClaimedBy: lease.Claim.TargetMemberExternalID,
		CredentialFingerprint: hex.EncodeToString(lease.Claim.CredentialFingerprint),
	}
	evidence, err := c.gateway.AcknowledgeProvisionCredential(ctx, command)
	if err != nil {
		status := CredentialClaimReconcileRequired
		var gatewayErr *GatewayError
		if errors.As(err, &gatewayErr) && !gatewayErr.Retryable && !gatewayErr.Ambiguous {
			status = CredentialClaimRejected
		}
		_, commitErr := c.store.CommitCredentialAckFailure(ctx, CommitCredentialAckFailureInput{
			Key: lease.Claim.Key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
			Status: status, ErrorCode: persistentErrorCode(err),
		})
		if commitErr != nil {
			return commitErr
		}
		return err
	}
	_, err = c.store.CommitCredentialAck(ctx, CommitCredentialAckInput{
		Key: lease.Claim.Key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken, Evidence: evidence,
	})
	return err
}

func (c *PersistentCoordinator) loadProvisionResult(ctx context.Context, operation *StoredOperation, includeToken bool, token string) (*ProvisionSeatResult, error) {
	seat, err := c.store.LoadPersistedSeat(ctx, operation.TargetExternalID)
	if err != nil {
		if errors.Is(err, ErrWorkflowNotFound) {
			return nil, ErrWorkflowCorruptState
		}
		return nil, err
	}
	claim, err := c.store.LoadCredentialClaim(ctx, ClaimKey(operation.Key))
	if err != nil {
		if errors.Is(err, ErrWorkflowNotFound) {
			return nil, ErrWorkflowCorruptState
		}
		return nil, err
	}
	view := storedOperationView(operation, claim)
	if includeToken {
		view.CredentialClaimToken = token
	}
	return &ProvisionSeatResult{Seat: persistedSeatDomain(seat), Operation: view}, nil
}

func (c *PersistentCoordinator) Seat(ctx context.Context, id string) (*domain.Seat, error) {
	seat, err := c.store.LoadPersistedSeat(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	return persistedSeatDomain(seat), nil
}

func (c *PersistentCoordinator) Operation(ctx context.Context, id string) (*Operation, bool, error) {
	op, err := c.store.LoadOperation(ctx, OperationKey{ClientID: c.clientID, OperationID: strings.TrimSpace(id)})
	if err != nil {
		if errors.Is(err, ErrWorkflowNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	claim, err := c.store.LoadCredentialClaim(ctx, ClaimKey(op.Key))
	if err != nil {
		if !errors.Is(err, ErrWorkflowNotFound) {
			return nil, false, err
		}
		if (op.Kind == OperationProvision || op.Kind == OperationAssignTemp || op.Kind == OperationRestore) &&
			op.Status == OperationSucceeded {
			return nil, false, ErrWorkflowCorruptState
		}
	}
	return storedOperationView(op, claim), true, nil
}

func (*PersistentCoordinator) StorageStatus() string { return "postgres" }

func (c *PersistentCoordinator) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]PendingSettlement, error) {
	seatID = strings.TrimSpace(seatID)
	if !validSettlementIdentifier(seatID) {
		return nil, ErrInvalidSettlementRequest
	}
	if c.settlementRead == nil {
		return nil, ErrPersistentWorkflowUnsupported
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	seat, err := c.store.LoadPersistedSeat(ctx, seatID)
	if err != nil {
		return nil, err
	}
	items, err := c.settlementRead.ListPendingSettlements(ctx, seatID, limit)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if err := validatePersistentPendingSettlement(items[i], seat); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (c *PersistentCoordinator) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*PendingSettlement, error) {
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	if !validSettlementIdentifier(seatID) || !validSettlementIdentifier(settlementID) {
		return nil, ErrInvalidSettlementRequest
	}
	if c.settlementRead == nil {
		return nil, ErrPersistentWorkflowUnsupported
	}
	seat, err := c.store.LoadPersistedSeat(ctx, seatID)
	if err != nil {
		return nil, err
	}
	item, err := c.settlementRead.GetPendingSettlement(ctx, seatID, settlementID)
	if err != nil {
		return nil, err
	}
	if item == nil || item.SettlementID != settlementID {
		return nil, ErrWorkflowCorruptState
	}
	if err := validatePersistentPendingSettlement(*item, seat); err != nil {
		return nil, err
	}
	return item, nil
}

func (c *PersistentCoordinator) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, command ResolvePendingSettlementCommand) (*SettlementResolution, error) {
	if c.settlementResolve == nil || !validSettlementIdentifier(c.settlementActorID) {
		return nil, ErrPersistentWorkflowUnsupported
	}
	seatID, settlementID = strings.TrimSpace(seatID), strings.TrimSpace(settlementID)
	command.OperationID = strings.TrimSpace(command.OperationID)
	command.ExpectedRequestID = strings.TrimSpace(command.ExpectedRequestID)
	command.Reason, command.Evidence = strings.TrimSpace(command.Reason), strings.TrimSpace(command.Evidence)
	if !validSettlementIdentifier(seatID) || !validSettlementIdentifier(settlementID) ||
		!validSettlementIdentifier(command.OperationID) || command.ExpectedAssignmentEpoch == 0 ||
		!validSettlementIdentifier(command.ExpectedRequestID) || command.Reason == "" || command.Evidence == "" ||
		len(command.Reason) > 1000 || len(command.Evidence) > 4000 {
		return nil, ErrInvalidSettlementRequest
	}
	snapshot, requestHash, err := persistentSettlementIntent(seatID, settlementID, c.settlementActorID, command)
	if err != nil {
		return nil, err
	}
	key := OperationKey{ClientID: c.clientID, OperationID: command.OperationID}
	// 终态幂等重放只依赖不可变 operation/case/result，不受 Seat 后续合法换员影响。
	existing, loadErr := c.store.LoadOperation(ctx, key)
	if loadErr == nil && existing != nil && (existing.Status == OperationSucceeded || existing.Status == OperationFailed) {
		if !sameSettlementReplayIntent(existing, seatID, settlementID, command) {
			return nil, ErrWorkflowHashDrift
		}
		if existing.Status == OperationFailed {
			return nil, persistentOperationFailure(existing.ErrorCode)
		}
		target, err := c.store.LoadSettlementResolutionTarget(ctx, key)
		if err != nil {
			if errors.Is(err, ErrWorkflowNotFound) {
				return nil, ErrWorkflowCorruptState
			}
			return nil, err
		}
		return settlementResolutionFromTarget(target)
	}
	if loadErr == nil && existing != nil {
		if !sameSettlementReplayIntent(existing, seatID, settlementID, command) {
			return nil, ErrWorkflowHashDrift
		}
		lease, err := c.store.AcquireOperationLease(ctx, AcquireOperationLeaseInput{
			Key: key, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
		})
		if err != nil {
			return nil, err
		}
		target, err := c.store.LoadSettlementResolutionTarget(ctx, key)
		if err != nil {
			return nil, err
		}
		if lease == nil || lease.Operation == nil || target == nil || target.Operation == nil ||
			target.Operation.FencingToken != lease.FencingToken || target.Operation.LeaseOwner != c.workerID {
			return nil, ErrWorkflowStaleFence
		}
		return c.resolveSettlementTarget(ctx, target)
	}
	if loadErr != nil && !errors.Is(loadErr, ErrWorkflowNotFound) {
		return nil, loadErr
	}

	// Begin 前仅查询平台数据库，绝不为“预检”调用 Sub2API；上游访问必须晚于 durable intent。
	seat, err := c.store.LoadPersistedSeat(ctx, seatID)
	if err != nil {
		return nil, err
	}
	if seat.AssignmentEpoch != command.ExpectedAssignmentEpoch {
		return nil, ErrWorkflowInvalidState
	}
	target, _, err := c.store.BeginSettlementResolution(ctx, BeginSettlementResolutionInput{
		Key: key, SeatExternalID: seatID, SettlementID: settlementID,
		ExpectedRequestID: command.ExpectedRequestID, ExpectedAssignmentEpoch: command.ExpectedAssignmentEpoch,
		ExpectedActorClientID: c.settlementActorID,
		RequestHash:           requestHash, RequestSnapshot: snapshot, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Case == nil {
		return nil, ErrWorkflowCorruptState
	}
	if target.Operation.Status == OperationSucceeded {
		return settlementResolutionFromTarget(target)
	}
	if target.Operation.Status == OperationFailed {
		return nil, persistentOperationFailure(target.Operation.ErrorCode)
	}
	if target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil {
		return nil, ErrWorkflowLeaseHeld
	}
	return c.resolveSettlementTarget(ctx, target)
}

type persistentSettlementRequest struct {
	Version                 int    `json:"version"`
	OperationID             string `json:"operation_id"`
	SeatID                  string `json:"seat_id"`
	SettlementID            string `json:"settlement_id"`
	ExpectedAssignmentEpoch uint64 `json:"expected_assignment_epoch"`
	ExpectedRequestID       string `json:"expected_request_id"`
	ExpectedActorClientID   string `json:"expected_actor_client_id"`
	Reason                  string `json:"reason"`
	Evidence                string `json:"evidence"`
}

func persistentSettlementIntent(seatID, settlementID, actorClientID string, command ResolvePendingSettlementCommand) ([]byte, [32]byte, error) {
	payload := persistentSettlementRequest{
		Version: 1, OperationID: command.OperationID, SeatID: seatID, SettlementID: settlementID,
		ExpectedAssignmentEpoch: command.ExpectedAssignmentEpoch, ExpectedRequestID: command.ExpectedRequestID,
		ExpectedActorClientID: actorClientID, Reason: command.Reason, Evidence: command.Evidence,
	}
	snapshot, err := json.Marshal(payload)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return snapshot, sha256.Sum256(snapshot), nil
}

func sameSettlementReplayIntent(operation *StoredOperation, seatID, settlementID string, command ResolvePendingSettlementCommand) bool {
	if operation == nil || operation.Kind != OperationResolveSettlement || operation.TargetType != "SEAT" ||
		operation.TargetExternalID != seatID {
		return false
	}
	var stored persistentSettlementRequest
	if json.Unmarshal(operation.RequestSnapshot, &stored) != nil {
		return false
	}
	return stored.Version == 1 && stored.OperationID == command.OperationID && stored.SeatID == seatID &&
		stored.SettlementID == settlementID && stored.ExpectedAssignmentEpoch == command.ExpectedAssignmentEpoch &&
		stored.ExpectedRequestID == command.ExpectedRequestID && stored.Reason == command.Reason && stored.Evidence == command.Evidence
}

func settlementCommandFromTarget(target *SettlementResolutionTarget, requireCurrentEpoch bool) (ResolvePendingSettlementCommand, error) {
	if target == nil || target.Operation == nil || target.Case == nil ||
		target.Operation.Kind != OperationResolveSettlement || target.Operation.TargetType != "SEAT" {
		return ResolvePendingSettlementCommand{}, ErrWorkflowCorruptState
	}
	var request persistentSettlementRequest
	if err := json.Unmarshal(target.Operation.RequestSnapshot, &request); err != nil {
		return ResolvePendingSettlementCommand{}, ErrWorkflowCorruptState
	}
	if request.Version != 1 || request.OperationID != target.Operation.Key.OperationID ||
		request.SeatID != target.Operation.TargetExternalID || request.SeatID != target.Seat.SeatExternalID ||
		request.SettlementID != target.Case.SettlementID || request.ExpectedAssignmentEpoch == 0 ||
		request.ExpectedAssignmentEpoch != target.Case.ExpectedAssignmentEpoch ||
		(requireCurrentEpoch && request.ExpectedAssignmentEpoch != target.Seat.AssignmentEpoch) ||
		request.ExpectedRequestID == "" || request.ExpectedRequestID != target.Case.ExpectedRequestID ||
		request.ExpectedActorClientID == "" || request.ExpectedActorClientID != target.Case.ExpectedActorClientID ||
		request.Reason != target.Case.Reason || request.Evidence != target.Case.Evidence {
		return ResolvePendingSettlementCommand{}, ErrWorkflowCorruptState
	}
	return ResolvePendingSettlementCommand{
		OperationID: request.OperationID, ExpectedAssignmentEpoch: request.ExpectedAssignmentEpoch,
		ExpectedRequestID: request.ExpectedRequestID, Reason: request.Reason, Evidence: request.Evidence,
	}, nil
}

func validatePersistentPendingSettlement(item PendingSettlement, seat *PersistedSeat) error {
	if seat == nil {
		return ErrWorkflowCorruptState
	}
	if item.SeatID <= 0 || item.ExternalSeatID != seat.SeatExternalID || item.AssignmentEpoch <= 0 ||
		uint64(item.AssignmentEpoch) != seat.AssignmentEpoch || !validSettlementIdentifier(item.SettlementID) ||
		!validSettlementIdentifier(item.RequestID) {
		return ErrWorkflowCorruptState
	}
	return nil
}

func (c *PersistentCoordinator) resolveSettlementTarget(ctx context.Context, target *SettlementResolutionTarget) (*SettlementResolution, error) {
	command, err := settlementCommandFromTarget(target, true)
	if err != nil {
		return nil, err
	}
	if target.Case.ExpectedActorClientID != c.settlementActorID {
		return nil, ErrWorkflowCorruptState
	}
	result, callErr := c.settlementResolve.ResolvePendingSettlement(ctx, target.Seat.SeatExternalID, target.Case.SettlementID, command)
	if callErr != nil {
		return c.commitSettlementFailure(ctx, target, callErr)
	}
	if result == nil || result.ExternalSeatID != target.Seat.SeatExternalID ||
		result.SettlementID != target.Case.SettlementID || result.OperationID != target.Operation.Key.OperationID ||
		result.ActorClientID != c.settlementActorID || result.AssignmentEpoch != command.ExpectedAssignmentEpoch ||
		result.RequestID != command.ExpectedRequestID || result.Reason != command.Reason ||
		result.Evidence != command.Evidence || result.SeatID <= 0 || result.ResolvedAt.IsZero() {
		return c.commitSettlementFailure(ctx, target, &GatewayError{
			Reason: "settlement resolution response does not match durable intent", Retryable: true, Ambiguous: true,
		})
	}
	operation, stored, err := c.store.CommitSettlementResolution(ctx, CommitSettlementResolutionInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken, Result: *result,
	})
	if err != nil {
		return nil, err
	}
	if operation == nil || operation.Status != OperationSucceeded || stored == nil {
		return nil, ErrWorkflowCorruptState
	}
	return result, nil
}

func (c *PersistentCoordinator) commitSettlementFailure(ctx context.Context, target *SettlementResolutionTarget, callErr error) (*SettlementResolution, error) {
	code := persistentErrorCode(callErr)
	var gatewayErr *GatewayError
	if errors.As(callErr, &gatewayErr) && !gatewayErr.Retryable && !gatewayErr.Ambiguous &&
		gatewayErr.StatusCode >= 400 && gatewayErr.StatusCode < 500 {
		// POST 之后的 4xx 也不能证明未生效；保留 pending 并交由人工/同幂等键恢复。
		code = "OPERATOR_REVIEW_REQUIRED"
	}
	var nextAttempt *time.Time
	if code != "OPERATOR_REVIEW_REQUIRED" {
		next := c.now().UTC().Add(c.recoveryBackoff)
		nextAttempt = &next
	}
	committed, err := c.store.CommitSettlementResolutionFailure(ctx, CommitSettlementResolutionFailureInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken,
		ErrorCode: code, NextAttemptAt: nextAttempt,
	})
	if err != nil {
		return nil, err
	}
	if committed == nil || committed.Operation == nil {
		return nil, ErrWorkflowCorruptState
	}
	return nil, persistentOperationFailure(code)
}

func settlementResolutionFromTarget(target *SettlementResolutionTarget) (*SettlementResolution, error) {
	command, err := settlementCommandFromTarget(target, false)
	if err != nil || target.Resolution == nil || target.Operation.Status != OperationSucceeded ||
		target.Case.Status != SettlementResolutionSucceeded {
		return nil, ErrWorkflowCorruptState
	}
	stored := target.Resolution
	if stored.ExternalSeatID != target.Seat.SeatExternalID || stored.SettlementID != target.Case.SettlementID ||
		stored.OperationID != target.Operation.Key.OperationID || stored.UpstreamSeatID <= 0 || stored.ResolvedAt.IsZero() ||
		stored.ActorClientID != target.Case.ExpectedActorClientID ||
		stored.RequestID != command.ExpectedRequestID || stored.AssignmentEpoch != command.ExpectedAssignmentEpoch ||
		stored.Reason != command.Reason || stored.Evidence != command.Evidence {
		return nil, ErrWorkflowCorruptState
	}
	return &SettlementResolution{
		SeatID: stored.UpstreamSeatID, ExternalSeatID: stored.ExternalSeatID, SettlementID: stored.SettlementID,
		OperationID: stored.OperationID, ActorClientID: stored.ActorClientID,
		AssignmentEpoch: stored.AssignmentEpoch, RequestID: stored.RequestID,
		Reason: stored.Reason, Evidence: stored.Evidence, ResolvedAt: stored.ResolvedAt,
	}, nil
}

func (c *PersistentCoordinator) Reconcile(ctx context.Context, operationID string) (*Operation, error) {
	key := OperationKey{ClientID: c.clientID, OperationID: strings.TrimSpace(operationID)}
	op, err := c.store.LoadOperation(ctx, key)
	if err != nil {
		return nil, err
	}
	if op.Kind != OperationSuspend && op.Kind != OperationAssignTemp && op.Kind != OperationRestore {
		return nil, ErrPersistentWorkflowUnsupported
	}
	if op.Status == OperationSucceeded {
		if op.Kind == OperationAssignTemp || op.Kind == OperationRestore {
			return c.loadAssignmentOperation(ctx, op, false, "")
		}
		return storedOperationView(op, nil), nil
	}
	lease, err := c.store.AcquireOperationLease(ctx, AcquireOperationLeaseInput{
		Key: key, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if op.Kind == OperationSuspend {
		return c.recoverSuspendLease(ctx, lease)
	}
	return c.recoverAssignmentLease(ctx, lease)
}

func (c *PersistentCoordinator) Suspend(ctx context.Context, operationID, seatID string) (*Operation, error) {
	operationID, seatID = strings.TrimSpace(operationID), strings.TrimSpace(seatID)
	if !validSettlementIdentifier(operationID) || !validSettlementIdentifier(seatID) {
		return nil, ErrWorkflowInvalidData
	}
	key := OperationKey{ClientID: c.clientID, OperationID: operationID}
	var snapshot []byte
	var requestHash [32]byte
	existing, err := c.store.LoadOperation(ctx, key)
	switch {
	case err == nil:
		if existing.Kind != OperationSuspend || existing.TargetType != "SEAT" || existing.TargetExternalID != seatID {
			return nil, ErrWorkflowHashDrift
		}
		if existing.Status == OperationSucceeded {
			return storedOperationView(existing, nil), nil
		}
		if existing.Status == OperationFailed {
			return storedOperationView(existing, nil), persistentOperationFailure(existing.ErrorCode)
		}
		if _, parseErr := suspendCommandFromOperation(existing); parseErr != nil {
			return nil, parseErr
		}
		snapshot, requestHash = existing.RequestSnapshot, existing.RequestHash
	case errors.Is(err, ErrWorkflowNotFound):
		seat, seatErr := c.store.LoadPersistedSeat(ctx, seatID)
		if seatErr != nil {
			if errors.Is(seatErr, ErrWorkflowNotFound) {
				return nil, ErrSeatNotFound
			}
			return nil, seatErr
		}
		snapshot, requestHash, err = persistentSuspendIntent(SuspendCommand{
			OperationID: operationID, SeatID: seatID, PoolID: seat.PoolExternalID,
			UserID: seat.CurrentMemberID, AssignmentEpoch: seat.AssignmentEpoch,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	target, _, err := c.store.BeginSuspend(ctx, BeginSuspendInput{
		Key: key, SeatExternalID: seatID, RequestHash: requestHash, RequestSnapshot: snapshot,
		ReasonCode: SuspendReasonManualPolicyBreach, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Case == nil {
		return nil, ErrWorkflowCorruptState
	}
	if target.Operation.Status == OperationSucceeded || target.Case.Status == SuspendCaseFrozen {
		return storedOperationView(target.Operation, nil), nil
	}
	if target.Operation.Status == OperationFailed {
		return storedOperationView(target.Operation, nil), persistentOperationFailure(target.Operation.ErrorCode)
	}
	if target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil || target.Operation.FencingToken <= 0 {
		return nil, ErrWorkflowLeaseHeld
	}
	command, err := suspendCommandFromTarget(target)
	if err != nil {
		return nil, err
	}
	if target.Case.Status == SuspendCaseDraining {
		result, callErr := c.gateway.ReconcileSuspend(ctx, command)
		return c.commitSuspendGatewayResult(ctx, target, result, callErr)
	}
	result, callErr := c.gateway.Suspend(ctx, command)
	return c.commitSuspendGatewayResult(ctx, target, GatewayOperationResult{
		Applied: result.Freeze != nil, Draining: result.Draining,
		CurrentConcurrency: result.CurrentConcurrency, PendingSettlements: result.PendingSettlements,
		Freeze: result.Freeze,
	}, callErr)
}

func (c *PersistentCoordinator) AssignTemporary(ctx context.Context, operationID, seatID, targetUser string) (*Operation, error) {
	return c.assign(ctx, operationID, seatID, targetUser, OperationAssignTemp)
}

func (c *PersistentCoordinator) Restore(ctx context.Context, operationID, seatID string) (*Operation, error) {
	return c.assign(ctx, operationID, seatID, "", OperationRestore)
}

func (c *PersistentCoordinator) ReplacePermanently(context.Context, string, string, string, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

type persistentAssignmentRequest struct {
	Version      int           `json:"version"`
	OperationID  string        `json:"operation_id"`
	Mode         OperationKind `json:"mode"`
	SeatID       string        `json:"seat_id"`
	TargetMember string        `json:"target_member_id"`
}

func (c *PersistentCoordinator) assign(ctx context.Context, operationID, seatID, targetUser string, kind OperationKind) (*Operation, error) {
	operationID, seatID, targetUser = strings.TrimSpace(operationID), strings.TrimSpace(seatID), strings.TrimSpace(targetUser)
	if !validSettlementIdentifier(operationID) || !validSettlementIdentifier(seatID) ||
		(kind != OperationAssignTemp && kind != OperationRestore) || (kind == OperationAssignTemp && !validSettlementIdentifier(targetUser)) {
		return nil, ErrWorkflowInvalidData
	}
	key := OperationKey{ClientID: c.clientID, OperationID: operationID}
	existing, err := c.store.LoadOperation(ctx, key)
	if err == nil {
		request, parseErr := assignmentRequestFromOperation(existing)
		if parseErr != nil {
			return nil, parseErr
		}
		if existing.Kind != kind || existing.TargetType != "SEAT" || existing.TargetExternalID != seatID ||
			(kind == OperationAssignTemp && request.TargetMember != targetUser) {
			return nil, ErrWorkflowHashDrift
		}
		targetUser = request.TargetMember
		if existing.Status == OperationSucceeded {
			return c.loadAssignmentOperation(ctx, existing, false, "")
		}
		if existing.Status == OperationFailed {
			return storedOperationView(existing, nil), persistentOperationFailure(existing.ErrorCode)
		}
	} else if errors.Is(err, ErrWorkflowNotFound) {
		if kind == OperationRestore {
			seat, loadErr := c.store.LoadPersistedSeat(ctx, seatID)
			if loadErr != nil {
				if errors.Is(loadErr, ErrWorkflowNotFound) {
					return nil, ErrSeatNotFound
				}
				return nil, loadErr
			}
			targetUser = seat.OwnerExternalID
		}
	} else {
		return nil, err
	}
	snapshot, requestHash, err := persistentAssignmentIntent(operationID, seatID, targetUser, kind)
	if err != nil {
		return nil, err
	}
	target, created, err := c.store.BeginAssignment(ctx, BeginAssignmentInput{
		Key: key, Kind: kind, SeatExternalID: seatID, TargetMemberExternalID: targetUser,
		RequestHash: requestHash, RequestSnapshot: snapshot, LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Case == nil {
		return nil, ErrWorkflowCorruptState
	}
	if target.Operation.Status == OperationSucceeded || target.Case.Status == AssignmentCaseSucceeded {
		if target.Operation.Status != OperationSucceeded || target.Case.Status != AssignmentCaseSucceeded {
			return nil, ErrWorkflowCorruptState
		}
		return c.loadAssignmentOperation(ctx, target.Operation, false, "")
	}
	if target.Operation.Status == OperationFailed || target.Case.Status == AssignmentCaseCancelled {
		if target.Operation.Status != OperationFailed || target.Case.Status != AssignmentCaseCancelled {
			return nil, ErrWorkflowCorruptState
		}
		return storedOperationView(target.Operation, nil), persistentOperationFailure(target.Operation.ErrorCode)
	}
	if target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil || target.Operation.FencingToken <= 0 {
		return nil, ErrWorkflowLeaseHeld
	}
	command, err := assignmentCommandFromTarget(target)
	if err != nil {
		return nil, err
	}
	var result AssignmentResult
	var callErr error
	if created {
		result, callErr = c.gateway.Assign(ctx, command)
	} else {
		result, callErr = c.gateway.ReconcileAssignment(ctx, command)
	}
	return c.commitAssignmentGatewayResult(ctx, target, result, callErr)
}

func persistentAssignmentIntent(operationID, seatID, targetMember string, kind OperationKind) ([]byte, [32]byte, error) {
	request := persistentAssignmentRequest{Version: 1, OperationID: operationID, Mode: kind, SeatID: seatID, TargetMember: targetMember}
	if !validSettlementIdentifier(request.OperationID) || !validSettlementIdentifier(request.SeatID) ||
		!validSettlementIdentifier(request.TargetMember) || (kind != OperationAssignTemp && kind != OperationRestore) {
		return nil, [32]byte{}, ErrWorkflowInvalidData
	}
	snapshot, err := json.Marshal(request)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return snapshot, sha256.Sum256(snapshot), nil
}

func assignmentRequestFromOperation(operation *StoredOperation) (persistentAssignmentRequest, error) {
	if operation == nil || (operation.Kind != OperationAssignTemp && operation.Kind != OperationRestore) || operation.TargetType != "SEAT" {
		return persistentAssignmentRequest{}, ErrWorkflowInvalidState
	}
	var request persistentAssignmentRequest
	if err := json.Unmarshal(operation.RequestSnapshot, &request); err != nil {
		return persistentAssignmentRequest{}, ErrWorkflowCorruptState
	}
	if request.Version != 1 || request.OperationID != operation.Key.OperationID || request.Mode != operation.Kind ||
		request.SeatID != operation.TargetExternalID || !validSettlementIdentifier(request.TargetMember) {
		return persistentAssignmentRequest{}, ErrWorkflowCorruptState
	}
	return request, nil
}

func assignmentCommandFromTarget(target *AssignmentTarget) (AssignmentCommand, error) {
	if target == nil || target.Operation == nil || target.Case == nil {
		return AssignmentCommand{}, ErrWorkflowCorruptState
	}
	request, err := assignmentRequestFromOperation(target.Operation)
	if err != nil {
		return AssignmentCommand{}, err
	}
	caseRecord, seat := target.Case, target.Seat
	if caseRecord.Kind != request.Mode || caseRecord.Status != AssignmentCasePending ||
		seat.SeatExternalID != request.SeatID || seat.TargetMemberID != request.TargetMember ||
		seat.Status != domain.SeatAssignmentPending || seat.AssignmentEpoch != caseRecord.ExpectedAssignmentEpoch ||
		seat.MembershipEpoch != caseRecord.MembershipEpoch || caseRecord.NextAssignmentEpoch != caseRecord.ExpectedAssignmentEpoch+1 ||
		caseRecord.PrincipalUserID != seat.PrincipalUserID || caseRecord.SubscriptionID != seat.SubscriptionID ||
		caseRecord.APIKeyID != seat.APIKeyID || caseRecord.ExpectedAPIKeyVersion != seat.ActiveAPIKeyVersion ||
		caseRecord.ExpectedAPIKeyVersion != caseRecord.ExpectedAssignmentEpoch ||
		caseRecord.NextAPIKeyVersion != caseRecord.NextAssignmentEpoch || strings.TrimSpace(caseRecord.FreezeOperationID) == "" {
		return AssignmentCommand{}, ErrWorkflowCorruptState
	}
	if request.Mode == OperationRestore && request.TargetMember != seat.OwnerExternalID {
		return AssignmentCommand{}, ErrWorkflowCorruptState
	}
	var freeze domain.FreezeSnapshot
	if err := json.Unmarshal(caseRecord.FreezeSnapshot, &freeze); err != nil || freeze.OperationID != caseRecord.FreezeOperationID ||
		freeze.AssignmentEpoch != caseRecord.ExpectedAssignmentEpoch || !validPersistentFreezeSnapshot(&freeze) {
		return AssignmentCommand{}, ErrWorkflowCorruptState
	}
	return AssignmentCommand{
		OperationID: request.OperationID, SeatID: request.SeatID, PoolID: seat.PoolExternalID,
		TargetUser: request.TargetMember, AssignmentEpoch: caseRecord.ExpectedAssignmentEpoch,
		MembershipEpoch: caseRecord.MembershipEpoch, FreezeOperationID: caseRecord.FreezeOperationID,
		PrincipalUserID: caseRecord.PrincipalUserID, SubscriptionID: caseRecord.SubscriptionID,
		APIKeyID: caseRecord.APIKeyID, ActiveAPIKeyVersion: caseRecord.ExpectedAPIKeyVersion,
		Mode: request.Mode,
	}, nil
}

func (c *PersistentCoordinator) commitAssignmentGatewayResult(ctx context.Context, target *AssignmentTarget, result AssignmentResult, callErr error) (*Operation, error) {
	if callErr != nil {
		return c.commitAssignmentFailure(ctx, target, assignmentErrorCode(callErr), false)
	}
	if target == nil || target.Operation == nil || target.Case == nil ||
		!result.AccessCredentialRotationComplete || result.Credential == "" ||
		result.ExternalPoolID != target.Seat.PoolExternalID || result.ExternalSeatID != target.Seat.SeatExternalID ||
		!strings.EqualFold(result.State, "ACTIVE") || result.AssignmentEpoch != target.Case.NextAssignmentEpoch ||
		result.PrincipalUserID != target.Case.PrincipalUserID || result.SubscriptionID != target.Case.SubscriptionID ||
		result.APIKeyID != target.Case.APIKeyID || result.ActiveAPIKeyVersion != target.Case.NextAPIKeyVersion ||
		result.LastOperationID != target.Operation.Key.OperationID {
		return c.commitAssignmentFailure(ctx, target, "UPSTREAM_RESPONSE_INVALID", false)
	}
	claimToken, err := c.claimToken()
	if err != nil {
		return c.commitAssignmentFailure(ctx, target, "CLAIM_TOKEN_GENERATION_FAILED", false)
	}
	tokenHash := sha256.Sum256([]byte(claimToken))
	fingerprint := sha256.Sum256([]byte(result.Credential))
	claimOperationID := assignmentClaimOperationID(target.Operation.Key.OperationID)
	aad := persistentClaimAAD(c.clientID, target.Operation.Key.OperationID, claimOperationID,
		target.Seat.PoolExternalID, target.Seat.SeatExternalID, target.Seat.TargetMemberID, fingerprint[:])
	envelope, err := c.cipher.Seal(ctx, result.Credential, aad)
	if err != nil {
		return c.commitAssignmentFailure(ctx, target, "CREDENTIAL_SEAL_FAILED", false)
	}
	envelope.AADHash = sha256.Sum256(aad)
	resultSnapshot, err := json.Marshal(struct {
		Version               int    `json:"version"`
		ExternalPoolID        string `json:"external_pool_id"`
		ExternalSeatID        string `json:"external_seat_id"`
		State                 string `json:"state"`
		AssignmentEpoch       uint64 `json:"assignment_epoch"`
		PrincipalUserID       int64  `json:"principal_user_id"`
		SubscriptionID        int64  `json:"subscription_id"`
		APIKeyID              int64  `json:"api_key_id"`
		ActiveAPIKeyVersion   uint64 `json:"active_api_key_version"`
		LastOperationID       string `json:"last_operation_id"`
		CredentialFingerprint string `json:"credential_fingerprint"`
	}{
		1, result.ExternalPoolID, result.ExternalSeatID, result.State, result.AssignmentEpoch,
		result.PrincipalUserID, result.SubscriptionID, result.APIKeyID, result.ActiveAPIKeyVersion,
		result.LastOperationID,
		hex.EncodeToString(fingerprint[:]),
	})
	if err != nil {
		return nil, err
	}
	committed, claim, _, err := c.store.CommitAssignmentWithCredentialClaim(ctx, CommitAssignmentWithCredentialClaimInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken,
		ExpectedAssignmentEpoch: target.Case.ExpectedAssignmentEpoch, ResultSnapshot: resultSnapshot,
		Claim: CreateCredentialClaimInput{
			Key: ClaimKey(target.Operation.Key), SeatExternalID: target.Seat.SeatExternalID,
			TargetMemberExternalID: target.Seat.TargetMemberID, ClaimOperationID: claimOperationID,
			TokenHash: tokenHash, CredentialFingerprint: fingerprint, Envelope: envelope, ClaimTTL: c.claimTTL,
		},
	})
	if err != nil {
		return nil, err
	}
	if committed == nil || claim == nil {
		return nil, ErrWorkflowCorruptState
	}
	view := storedOperationView(committed, claim)
	view.CredentialClaimToken = claimToken
	return view, nil
}

func (c *PersistentCoordinator) commitAssignmentFailure(ctx context.Context, target *AssignmentTarget, code string, confirmedUnchanged bool) (*Operation, error) {
	if target == nil || target.Operation == nil || target.Case == nil {
		return nil, ErrWorkflowCorruptState
	}
	snapshot, err := json.Marshal(struct {
		Version            int    `json:"version"`
		ErrorCode          string `json:"error_code"`
		ConfirmedUnchanged bool   `json:"confirmed_unchanged"`
	}{1, code, confirmedUnchanged})
	if err != nil {
		return nil, err
	}
	var nextAttempt *time.Time
	if !confirmedUnchanged {
		next := c.now().UTC().Add(c.recoveryBackoff)
		nextAttempt = &next
	}
	committed, err := c.store.CommitAssignmentFailure(ctx, CommitAssignmentFailureInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken,
		ResultSnapshot: snapshot, ErrorCode: code, ErrorDetail: code, NextAttemptAt: nextAttempt,
		ConfirmedUnchanged: confirmedUnchanged,
	})
	if err != nil {
		return nil, err
	}
	if committed == nil || committed.Operation == nil {
		return nil, ErrWorkflowCorruptState
	}
	return storedOperationView(committed.Operation, nil), persistentOperationFailure(code)
}

func assignmentErrorCode(err error) string {
	var gatewayErr *GatewayError
	if errors.As(err, &gatewayErr) && !gatewayErr.Retryable && !gatewayErr.Ambiguous &&
		gatewayErr.StatusCode > 0 && gatewayErr.StatusCode < 500 {
		// 普通 4xx 不能证明 rotate 未提交；保持 Seat 禁用并等待人工核对。
		return "OPERATOR_REVIEW_REQUIRED"
	}
	return persistentErrorCode(err)
}

func assignmentClaimOperationID(operationID string) string {
	digest := sha256.Sum256([]byte("assignment-credential-claim\x00" + operationID))
	return "claim-" + hex.EncodeToString(digest[:])
}

func (c *PersistentCoordinator) loadAssignmentOperation(ctx context.Context, operation *StoredOperation, includeToken bool, token string) (*Operation, error) {
	if operation == nil || operation.Status != OperationSucceeded ||
		(operation.Kind != OperationAssignTemp && operation.Kind != OperationRestore) {
		return nil, ErrWorkflowCorruptState
	}
	claim, err := c.store.LoadCredentialClaim(ctx, ClaimKey(operation.Key))
	if err != nil {
		if errors.Is(err, ErrWorkflowNotFound) {
			return nil, ErrWorkflowCorruptState
		}
		return nil, err
	}
	view := storedOperationView(operation, claim)
	if includeToken {
		view.CredentialClaimToken = token
	}
	return view, nil
}

type PersistentRecoveryWorker struct{ coordinator *PersistentCoordinator }

func NewPersistentRecoveryWorker(coordinator *PersistentCoordinator) (*PersistentRecoveryWorker, error) {
	if coordinator == nil {
		return nil, ErrWorkflowInvalidData
	}
	return &PersistentRecoveryWorker{coordinator: coordinator}, nil
}

func (w *PersistentRecoveryWorker) RecoverNextOperation(ctx context.Context) (bool, error) {
	c := w.coordinator
	lease, err := c.store.AcquireNextOperationLease(ctx, AcquireNextOperationLeaseInput{
		LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if errors.Is(err, ErrWorkflowNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if lease.Operation.Kind == OperationSuspend {
		_, err = c.recoverSuspendLease(ctx, lease)
		return true, err
	}
	if lease.Operation.Kind == OperationAssignTemp || lease.Operation.Kind == OperationRestore {
		_, err = c.recoverAssignmentLease(ctx, lease)
		return true, err
	}
	if lease.Operation.Kind == OperationResolveSettlement {
		// 专用 settlement scanner 才能重放高权限调用；generic scanner 误选时绝不提交终态。
		return true, ErrWorkflowInvalidState
	}
	status, code, detail := OperationFailed, "PERSISTENT_WORKFLOW_UNSUPPORTED", ErrPersistentWorkflowUnsupported.Error()
	var nextAttempt *time.Time
	if lease.Operation.Kind == OperationProvision {
		status, code, detail = OperationRetryable, "CALLER_REPLAY_REQUIRED", "provision recovery requires the original caller to receive a new claim token"
		next := c.now().UTC().Add(c.recoveryBackoff)
		nextAttempt = &next
	}
	_, err = c.store.CommitOperation(ctx, CommitOperationInput{
		Key: lease.Operation.Key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		Status: status, ErrorCode: code, ErrorDetail: detail, NextAttemptAt: nextAttempt,
	})
	return true, err
}

// RecoverNextSettlementResolution 使用 Store 新取得的 fence，并从持久 request_snapshot 重建同一请求。
// worker 不先查询 Sub2API，避免在 durable intent 之外形成不可恢复的 resolve 副作用。
func (w *PersistentRecoveryWorker) RecoverNextSettlementResolution(ctx context.Context) (bool, error) {
	c := w.coordinator
	if c.settlementResolve == nil || !validSettlementIdentifier(c.settlementActorID) {
		return false, nil
	}
	target, err := c.store.AcquireNextSettlementResolution(ctx, AcquireNextSettlementResolutionInput{
		LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if errors.Is(err, ErrWorkflowNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if target == nil || target.Operation == nil || target.Case == nil ||
		target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil {
		return true, ErrWorkflowStaleFence
	}
	_, err = c.resolveSettlementTarget(ctx, target)
	var persistedOutcome *PersistentOperationError
	if errors.As(err, &persistedOutcome) {
		// 结果不明/人工复核已经原子持久化，不应让恢复循环退出。
		return true, nil
	}
	return true, err
}

type persistentSuspendRequest struct {
	Version         int    `json:"version"`
	OperationID     string `json:"operation_id"`
	SeatID          string `json:"seat_id"`
	PoolID          string `json:"pool_id"`
	CurrentMemberID string `json:"current_member_id"`
	AssignmentEpoch uint64 `json:"assignment_epoch"`
	ReasonCode      string `json:"reason_code"`
	ReasonDetail    string `json:"reason_detail"`
}

func persistentSuspendIntent(command SuspendCommand) ([]byte, [32]byte, error) {
	payload := persistentSuspendRequest{
		Version: 1, OperationID: command.OperationID, SeatID: command.SeatID,
		PoolID: command.PoolID, CurrentMemberID: command.UserID, AssignmentEpoch: command.AssignmentEpoch,
		ReasonCode: SuspendReasonManualPolicyBreach, ReasonDetail: "operator requested suspension",
	}
	if !validSettlementIdentifier(payload.OperationID) || !validSettlementIdentifier(payload.SeatID) ||
		!validSettlementIdentifier(payload.PoolID) || !validSettlementIdentifier(payload.CurrentMemberID) ||
		payload.AssignmentEpoch == 0 {
		return nil, [32]byte{}, ErrWorkflowInvalidData
	}
	snapshot, err := json.Marshal(payload)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return snapshot, sha256.Sum256(snapshot), nil
}

func suspendCommandFromOperation(operation *StoredOperation) (SuspendCommand, error) {
	if operation == nil || operation.Kind != OperationSuspend || operation.TargetType != "SEAT" {
		return SuspendCommand{}, ErrWorkflowInvalidState
	}
	var request persistentSuspendRequest
	if err := json.Unmarshal(operation.RequestSnapshot, &request); err != nil {
		return SuspendCommand{}, ErrWorkflowCorruptState
	}
	if request.Version != 1 || request.OperationID != operation.Key.OperationID ||
		request.SeatID != operation.TargetExternalID || request.AssignmentEpoch == 0 ||
		request.ReasonCode != SuspendReasonManualPolicyBreach {
		return SuspendCommand{}, ErrWorkflowCorruptState
	}
	return SuspendCommand{
		OperationID: request.OperationID, SeatID: request.SeatID, PoolID: request.PoolID,
		UserID: request.CurrentMemberID, AssignmentEpoch: request.AssignmentEpoch,
	}, nil
}

func suspendCommandFromTarget(target *SuspendTarget) (SuspendCommand, error) {
	if target == nil || target.Operation == nil || target.Case == nil {
		return SuspendCommand{}, ErrWorkflowCorruptState
	}
	command, err := suspendCommandFromOperation(target.Operation)
	if err != nil {
		return SuspendCommand{}, err
	}
	if target.Seat.SeatExternalID != command.SeatID || target.Seat.PoolExternalID != command.PoolID ||
		target.Seat.CurrentMemberID != command.UserID || target.Seat.AssignmentEpoch != command.AssignmentEpoch ||
		target.Case.ExpectedAssignmentEpoch != command.AssignmentEpoch ||
		target.Case.ReasonCode != SuspendReasonManualPolicyBreach {
		return SuspendCommand{}, ErrWorkflowCorruptState
	}
	expectedSeatState := domain.SeatSuspendPending
	if target.Case.Status == SuspendCaseDraining {
		expectedSeatState = domain.SeatDraining
	} else if target.Case.Status == SuspendCaseFrozen {
		expectedSeatState = domain.SeatFrozen
	}
	if target.Seat.Status != expectedSeatState {
		return SuspendCommand{}, ErrWorkflowCorruptState
	}
	return command, nil
}

func (c *PersistentCoordinator) recoverSuspendLease(ctx context.Context, lease *OperationLease) (*Operation, error) {
	if lease == nil || lease.Operation == nil {
		return nil, ErrWorkflowCorruptState
	}
	target, err := c.store.LoadSuspendTarget(ctx, lease.Operation.Key)
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Operation.FencingToken != lease.FencingToken ||
		target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil {
		return nil, ErrWorkflowStaleFence
	}
	command, err := suspendCommandFromTarget(target)
	if err != nil {
		return nil, err
	}
	result, callErr := c.gateway.ReconcileSuspend(ctx, command)
	return c.commitSuspendGatewayResult(ctx, target, result, callErr)
}

func (c *PersistentCoordinator) recoverAssignmentLease(ctx context.Context, lease *OperationLease) (*Operation, error) {
	if lease == nil || lease.Operation == nil ||
		(lease.Operation.Kind != OperationAssignTemp && lease.Operation.Kind != OperationRestore) {
		return nil, ErrWorkflowCorruptState
	}
	target, err := c.store.LoadAssignmentTarget(ctx, lease.Operation.Key)
	if err != nil {
		return nil, err
	}
	if target == nil || target.Operation == nil || target.Operation.FencingToken != lease.FencingToken ||
		target.Operation.LeaseOwner != c.workerID || target.Operation.LeaseExpiresAt == nil {
		return nil, ErrWorkflowStaleFence
	}
	command, err := assignmentCommandFromTarget(target)
	if err != nil {
		return nil, err
	}
	result, callErr := c.gateway.ReconcileAssignment(ctx, command)
	return c.commitAssignmentGatewayResult(ctx, target, result, callErr)
}

func (c *PersistentCoordinator) commitSuspendGatewayResult(ctx context.Context, target *SuspendTarget, result GatewayOperationResult, callErr error) (*Operation, error) {
	if target == nil || target.Operation == nil || target.Case == nil {
		return nil, ErrWorkflowCorruptState
	}
	if callErr != nil {
		return c.commitSuspendUnknown(ctx, target, persistentSuspendErrorCode(callErr))
	}
	progress := SuspendCaseDraining
	var freeze *domain.FreezeSnapshot
	if result.Freeze != nil {
		if !result.Applied || result.Freeze.OperationID != target.Operation.Key.OperationID ||
			result.Freeze.AssignmentEpoch != target.Case.ExpectedAssignmentEpoch ||
			result.Freeze.InFlight != 0 || result.Freeze.PendingSettlements != 0 ||
			!validPersistentFreezeSnapshot(result.Freeze) {
			return c.commitSuspendUnknown(ctx, target, "UPSTREAM_RESPONSE_INVALID")
		}
		progress, freeze = SuspendCaseFrozen, result.Freeze
	} else if !result.Draining || result.CurrentConcurrency < 0 || result.PendingSettlements < 0 {
		return c.commitSuspendUnknown(ctx, target, "UPSTREAM_RESPONSE_INVALID")
	}
	resultSnapshot, err := json.Marshal(struct {
		Version            int                    `json:"version"`
		State              SuspendCaseStatus      `json:"state"`
		CurrentConcurrency int                    `json:"current_concurrency"`
		PendingSettlements int                    `json:"pending_settlements"`
		Freeze             *domain.FreezeSnapshot `json:"freeze_snapshot,omitempty"`
	}{1, progress, result.CurrentConcurrency, result.PendingSettlements, freeze})
	if err != nil {
		return nil, err
	}
	var nextAttempt *time.Time
	if progress == SuspendCaseDraining {
		next := c.now().UTC().Add(c.recoveryBackoff)
		nextAttempt = &next
	}
	currentConcurrency, pendingSettlements := result.CurrentConcurrency, result.PendingSettlements
	committed, err := c.store.CommitSuspendProgress(ctx, CommitSuspendProgressInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken,
		Progress: progress, ExpectedAssignmentEpoch: target.Case.ExpectedAssignmentEpoch,
		CurrentConcurrency: &currentConcurrency, PendingSettlements: &pendingSettlements,
		Freeze: freeze, ResultSnapshot: resultSnapshot, NextAttemptAt: nextAttempt,
	})
	if err != nil {
		return nil, err
	}
	return storedOperationView(committed.Operation, nil), nil
}

func (c *PersistentCoordinator) commitSuspendUnknown(ctx context.Context, target *SuspendTarget, code string) (*Operation, error) {
	progress := target.Case.Status
	if progress != SuspendCasePending && progress != SuspendCaseDraining {
		return nil, ErrWorkflowInvalidState
	}
	var currentConcurrency, pendingSettlements *int
	if progress == SuspendCaseDraining {
		if target.Case.CurrentConcurrency == nil || target.Case.PendingSettlements == nil {
			return nil, ErrWorkflowCorruptState
		}
		currentValue, pendingValue := *target.Case.CurrentConcurrency, *target.Case.PendingSettlements
		currentConcurrency, pendingSettlements = &currentValue, &pendingValue
	}
	resultSnapshot, err := json.Marshal(struct {
		Version   int               `json:"version"`
		State     SuspendCaseStatus `json:"state"`
		ErrorCode string            `json:"error_code"`
	}{1, progress, code})
	if err != nil {
		return nil, err
	}
	next := c.now().UTC().Add(c.recoveryBackoff)
	committed, err := c.store.CommitSuspendProgress(ctx, CommitSuspendProgressInput{
		Key: target.Operation.Key, LeaseOwner: c.workerID, FencingToken: target.Operation.FencingToken,
		Progress: progress, ExpectedAssignmentEpoch: target.Case.ExpectedAssignmentEpoch,
		CurrentConcurrency: currentConcurrency, PendingSettlements: pendingSettlements,
		ResultSnapshot: resultSnapshot, ErrorCode: code, ErrorDetail: code, NextAttemptAt: &next,
	})
	if err != nil {
		return nil, err
	}
	return storedOperationView(committed.Operation, nil), persistentOperationFailure(code)
}

func persistentSuspendErrorCode(err error) string {
	var gatewayErr *GatewayError
	if errors.As(err, &gatewayErr) && !gatewayErr.Retryable && !gatewayErr.Ambiguous && gatewayErr.StatusCode < 500 {
		return "OPERATOR_REVIEW_REQUIRED"
	}
	return persistentErrorCode(err)
}

func validPersistentFreezeSnapshot(snapshot *domain.FreezeSnapshot) bool {
	if snapshot == nil || snapshot.CapturedAt.IsZero() || len(snapshot.Usage) != 4 || len(snapshot.WindowStarts) != 4 {
		return false
	}
	for _, window := range []string{"hourly", "daily", "weekly", "monthly"} {
		usage, usageOK := snapshot.Usage[window]
		startedAt, windowOK := snapshot.WindowStarts[window]
		if !usageOK || !windowOK || usage < 0 || math.IsNaN(usage) || math.IsInf(usage, 0) ||
			(startedAt != nil && startedAt.IsZero()) {
			return false
		}
	}
	return true
}

func (w *PersistentRecoveryWorker) RecoverNextCredentialClaim(ctx context.Context) (bool, error) {
	c := w.coordinator
	lease, err := c.store.AcquireNextCredentialClaimLease(ctx, AcquireNextCredentialClaimLeaseInput{
		LeaseOwner: c.workerID, LeaseDuration: c.leaseDuration,
	})
	if errors.Is(err, ErrWorkflowNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if lease.Claim.Expired {
		_, err = c.store.ExpireCredentialClaim(ctx, ExpireCredentialClaimInput{
			Key: lease.Claim.Key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		return true, err
	}
	if lease.Claim.OperationKind != OperationProvision {
		return true, ErrPersistentWorkflowUnsupported
	}
	// Store 的恢复扫描不选择未过期 READY；若适配器违反契约则失败关闭，绝不绕过 BeginCredentialAck。
	if lease.Claim.Status == CredentialClaimReady {
		return true, ErrWorkflowInvalidState
	}
	if lease.Claim.Status == CredentialClaimReconcileRequired {
		lease.Claim, err = c.store.BeginCredentialAck(ctx, BeginCredentialAckInput{
			Key: lease.Claim.Key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		if err != nil {
			return true, err
		}
	}
	return true, c.commitProvisionAck(ctx, lease)
}

func persistentProvisionIntent(command ProvisionSeatCommand) ([]byte, [32]byte, error) {
	payload := struct {
		Version int `json:"version"`
		ProvisionSeatCommand
		OwnerUserID string `json:"owner_user_id"`
	}{Version: 1, ProvisionSeatCommand: command, OwnerUserID: command.OwnerUserID}
	snapshot, err := json.Marshal(payload)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return snapshot, sha256.Sum256(snapshot), nil
}

func persistentClaimAAD(clientID, operationID, claimOperationID, poolID, seatID, memberID string, fingerprint []byte) []byte {
	value, _ := json.Marshal(struct {
		Version               int    `json:"version"`
		ClientID              string `json:"client_id"`
		OperationID           string `json:"operation_id"`
		ClaimOperationID      string `json:"claim_operation_id"`
		PoolID                string `json:"pool_id"`
		SeatID                string `json:"seat_id"`
		MemberID              string `json:"member_id"`
		CredentialFingerprint string `json:"credential_fingerprint"`
	}{1, clientID, operationID, claimOperationID, poolID, seatID, memberID, hex.EncodeToString(fingerprint)})
	return value
}

func persistentClaimAuthorized(claim *StoredCredentialClaim, targetUser, claimToken string, providedHash [32]byte) bool {
	return claim != nil && targetUser != "" && targetUser == claim.TargetMemberExternalID && claimToken != "" &&
		len(claim.TokenHash) == len(providedHash) && subtle.ConstantTimeCompare(claim.TokenHash, providedHash[:]) == 1
}

func persistedSeatDomain(record *PersistedSeat) *domain.Seat {
	if record == nil {
		return nil
	}
	state := record.State
	if state == "" {
		state = domain.SeatActive
	}
	assignmentKind := record.CurrentAssignmentKind
	if assignmentKind == "" {
		assignmentKind = domain.AssignmentOwner
	}
	return &domain.Seat{
		ID: record.SeatExternalID, PoolID: record.PoolExternalID, State: state,
		OwnerUserID: record.OwnerExternalID, AssignmentEpoch: record.AssignmentEpoch,
		MembershipEpoch: record.MembershipEpoch, UpdatedAt: record.UpdatedAt,
		Current: domain.Assignment{
			UserID: record.CurrentMemberID, Kind: assignmentKind,
			AssignmentEpoch: record.AssignmentEpoch, AssignedAt: record.AssignmentStarted,
		},
	}
}

func storedOperationView(stored *StoredOperation, claim *StoredCredentialClaim) *Operation {
	if stored == nil {
		return nil
	}
	view := &Operation{
		ID: stored.Key.OperationID, Kind: stored.Kind, SeatID: stored.TargetExternalID,
		Status: stored.Status, Reason: stored.ErrorDetail, CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
		requestDigest: hex.EncodeToString(stored.RequestHash[:]),
	}
	if claim != nil {
		view.TargetUser = claim.TargetMemberExternalID
		view.CredentialClaimStatus = string(claim.Status)
		view.CredentialClaimExpiresAt = &claim.ExpiresAt
		view.credentialClaimOperationID = claim.ClaimOperationID
	}
	return view
}

func persistentErrorCode(err error) string {
	if errors.Is(err, ErrProvisionGatewayUnavailable) {
		return "PROVISION_GATEWAY_UNAVAILABLE"
	}
	var gatewayErr *GatewayError
	if errors.As(err, &gatewayErr) {
		if gatewayErr.StatusCode == 409 {
			return "UPSTREAM_CONFLICT"
		}
		if gatewayErr.Ambiguous {
			return "UPSTREAM_RESULT_AMBIGUOUS"
		}
		if gatewayErr.Retryable {
			return "UPSTREAM_RETRYABLE"
		}
		if gatewayErr.StatusCode >= 500 {
			return "UPSTREAM_GATEWAY_ERROR"
		}
		return "UPSTREAM_REJECTED"
	}
	return "UPSTREAM_UNAVAILABLE"
}

func persistentOperationFailure(code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		code = "OPERATION_FAILED"
	}
	return &PersistentOperationError{Code: code}
}

func newPersistentClaimToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
