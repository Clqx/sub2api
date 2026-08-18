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
}

type PersistentCoordinatorOptions struct {
	IntegrationClientID string
	WorkerID            string
	LeaseDuration       time.Duration
	ClaimTTL            time.Duration
	RecoveryBackoff     time.Duration
	Now                 func() time.Time
	ClaimToken          func() (string, error)
}

// PersistentCoordinator 的所有业务真相均来自 WorkflowStore，不使用进程内 map 恢复状态。
type PersistentCoordinator struct {
	store           WorkflowStore
	gateway         PersistentProvisionGateway
	cipher          CredentialEnvelopeCipher
	clientID        string
	workerID        string
	leaseDuration   time.Duration
	claimTTL        time.Duration
	recoveryBackoff time.Duration
	now             func() time.Time
	claimToken      func() (string, error)
}

func NewPersistentCoordinator(store WorkflowStore, gateway PersistentProvisionGateway, cipher CredentialEnvelopeCipher, options PersistentCoordinatorOptions) (*PersistentCoordinator, error) {
	if store == nil || gateway == nil || cipher == nil || strings.TrimSpace(options.IntegrationClientID) == "" ||
		strings.TrimSpace(options.WorkerID) == "" {
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
		clientID: strings.TrimSpace(options.IntegrationClientID), workerID: strings.TrimSpace(options.WorkerID),
		leaseDuration: options.LeaseDuration, claimTTL: options.ClaimTTL, recoveryBackoff: options.RecoveryBackoff,
		now: options.Now, claimToken: options.ClaimToken,
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
		!strings.EqualFold(upstream.State, "ACTIVE") || upstream.AssignmentEpoch != command.AssignmentEpoch || upstream.Credential == "" {
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
		CredentialFingerprint string `json:"credential_fingerprint"`
	}{upstream.ExternalPoolID, upstream.ExternalSeatID, upstream.State, upstream.AssignmentEpoch, hex.EncodeToString(fingerprint[:])})
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
	if lease.Claim.OperationKind != OperationProvision {
		return nil, ErrPersistentWorkflowUnsupported
	}
	if lease.Claim.Status == CredentialClaimReady || lease.Claim.Status == CredentialClaimReconcileRequired {
		lease.Claim, err = c.store.BeginCredentialAck(ctx, BeginCredentialAckInput{
			Key: key, LeaseOwner: c.workerID, FencingToken: lease.FencingToken,
		})
		if err != nil {
			return nil, err
		}
	}
	if len(lease.Claim.AckResultSnapshot) == 0 {
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
	aad := persistentClaimAAD(c.clientID, operationID, lease.Claim.ClaimOperationID, seat.PoolExternalID,
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
		if op.Kind == OperationProvision && op.Status == OperationSucceeded {
			return nil, false, ErrWorkflowCorruptState
		}
	}
	return storedOperationView(op, claim), true, nil
}

func (*PersistentCoordinator) StorageStatus() string { return "postgres" }

func (*PersistentCoordinator) ListPendingSettlements(context.Context, string, int) ([]PendingSettlement, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (*PersistentCoordinator) GetPendingSettlement(context.Context, string, string) (*PendingSettlement, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (*PersistentCoordinator) ResolvePendingSettlement(context.Context, string, string, ResolvePendingSettlementCommand) (*SettlementResolution, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (*PersistentCoordinator) Reconcile(context.Context, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (c *PersistentCoordinator) Suspend(context.Context, string, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (c *PersistentCoordinator) AssignTemporary(context.Context, string, string, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (c *PersistentCoordinator) Restore(context.Context, string, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
}

func (c *PersistentCoordinator) ReplacePermanently(context.Context, string, string, string, string) (*Operation, error) {
	return nil, ErrPersistentWorkflowUnsupported
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
	return &domain.Seat{
		ID: record.SeatExternalID, PoolID: record.PoolExternalID, State: domain.SeatActive,
		OwnerUserID: record.OwnerExternalID, AssignmentEpoch: record.AssignmentEpoch,
		MembershipEpoch: record.MembershipEpoch, UpdatedAt: record.UpdatedAt,
		Current: domain.Assignment{
			UserID: record.CurrentMemberID, Kind: domain.AssignmentOwner,
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
