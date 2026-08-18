package application

import (
	"context"
	"errors"
	"time"
)

var (
	ErrWorkflowNotFound       = errors.New("workflow aggregate not found")
	ErrWorkflowHashDrift      = errors.New("workflow request hash drift")
	ErrWorkflowLeaseHeld      = errors.New("workflow aggregate lease is held")
	ErrWorkflowStaleFence     = errors.New("workflow fencing token is stale")
	ErrWorkflowInvalidState   = errors.New("workflow aggregate state is invalid")
	ErrWorkflowTargetConflict = errors.New("workflow target is already owned by another operation")
	ErrWorkflowInvalidData    = errors.New("workflow persistence data is invalid")
	ErrWorkflowCorruptState   = errors.New("workflow persistent state is incomplete")
)

// WorkflowStore 以工作流聚合为事务边界。上层不得拆分为多个 repository 调用，
// 否则幂等记录、租约 fencing token 与敏感凭据状态可能跨事务失去一致性。
type WorkflowStore interface {
	BeginOperation(context.Context, BeginOperationInput) (*StoredOperation, bool, error)
	LoadOperation(context.Context, OperationKey) (*StoredOperation, error)
	AcquireOperationLease(context.Context, AcquireOperationLeaseInput) (*OperationLease, error)
	ValidateProvisionPreflight(context.Context, ProvisionPreflightInput) error
	AcquireNextOperationLease(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error)
	CommitOperation(context.Context, CommitOperationInput) (*StoredOperation, error)
	CommitOperationWithCredentialClaim(context.Context, CommitOperationWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, error)
	CommitProvisionWithCredentialClaim(context.Context, CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error)
	LoadPersistedSeat(context.Context, string) (*PersistedSeat, error)

	CreateCredentialClaim(context.Context, CreateCredentialClaimInput) (*StoredCredentialClaim, bool, error)
	LoadCredentialClaim(context.Context, ClaimKey) (*StoredCredentialClaim, error)
	AcquireCredentialClaimLease(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error)
	AcquireNextCredentialClaimLease(context.Context, AcquireNextCredentialClaimLeaseInput) (*CredentialClaimLease, error)
	BeginCredentialAck(context.Context, BeginCredentialAckInput) (*StoredCredentialClaim, error)
	CommitCredentialAck(context.Context, CommitCredentialAckInput) (*StoredCredentialClaim, error)
	CommitCredentialAckFailure(context.Context, CommitCredentialAckFailureInput) (*StoredCredentialClaim, error)
	// ClaimCredential 之前须在数据库事务外完成 KMS 解密；提交成功后才能向 HTTP 调用方披露已解密值。
	ClaimCredential(context.Context, ClaimCredentialInput) (*StoredCredentialClaim, error)
	ExpireCredentialClaim(context.Context, ExpireCredentialClaimInput) (*StoredCredentialClaim, error)
}

type OperationKey struct {
	ClientID    string
	OperationID string
}

type BeginOperationInput struct {
	Key              OperationKey
	Kind             OperationKind
	TargetType       string
	TargetExternalID string
	RequestHash      [32]byte
	RequestSnapshot  []byte
}

type StoredOperation struct {
	AggregateID      string
	Key              OperationKey
	Kind             OperationKind
	TargetType       string
	TargetExternalID string
	MigrationState   string
	RequestHash      [32]byte
	RequestSnapshot  []byte
	Status           OperationStatus
	AttemptCount     int
	ResultSnapshot   []byte
	ErrorCode        string
	ErrorDetail      string
	FencingToken     int64
	LeaseOwner       string
	LeaseExpiresAt   *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CompletedAt      *time.Time
	NextAttemptAt    *time.Time
}

type AcquireOperationLeaseInput struct {
	Key           OperationKey
	LeaseOwner    string
	LeaseDuration time.Duration
}

type OperationLease struct {
	Operation    *StoredOperation
	FencingToken int64
}

// ProvisionPreflightInput 在调用外部网关前，从数据库核对开通目标的可信绑定。
// 最终提交仍必须重复校验，避免 preflight 与提交之间的并发状态漂移。
type ProvisionPreflightInput struct {
	Key             OperationKey
	PoolExternalID  string
	SeatExternalID  string
	OwnerExternalID string
	ExistingGroupID int64
	AssignmentEpoch uint64
}

type AcquireNextOperationLeaseInput struct {
	LeaseOwner    string
	LeaseDuration time.Duration
}

type CommitOperationInput struct {
	Key            OperationKey
	LeaseOwner     string
	FencingToken   int64
	Status         OperationStatus
	ResultSnapshot []byte
	ErrorCode      string
	ErrorDetail    string
	NextAttemptAt  *time.Time
}

type CommitOperationWithCredentialClaimInput struct {
	Key            OperationKey
	LeaseOwner     string
	FencingToken   int64
	ResultSnapshot []byte
	Claim          CreateCredentialClaimInput
}

type CommitProvisionWithCredentialClaimInput struct {
	Operation       CommitOperationWithCredentialClaimInput
	PoolExternalID  string
	OwnerExternalID string
	ExistingGroupID int64
	AssignmentEpoch uint64
}

// PersistedSeat 是数据库 Seat 与当前 ACTIVE Assignment 的只读投影。
type PersistedSeat struct {
	SeatID            string
	SeatExternalID    string
	PoolExternalID    string
	OwnerExternalID   string
	CurrentMemberID   string
	AssignmentEpoch   uint64
	MembershipEpoch   uint64
	AssignmentStarted time.Time
	UpdatedAt         time.Time
}

type ClaimKey struct {
	ClientID    string
	OperationID string
}

type CreateCredentialClaimInput struct {
	Key                    ClaimKey
	SeatExternalID         string
	TargetMemberExternalID string
	ClaimOperationID       string
	TokenHash              [32]byte
	CredentialFingerprint  [32]byte
	Envelope               CredentialEnvelope
	ClaimTTL               time.Duration
}

// CredentialEnvelope 是 KMS 包装后的待交付秘密；Store 永远不接收明文凭据或原始 claim token。
type CredentialEnvelope struct {
	Algorithm  string
	KeyRef     string
	Ciphertext []byte
	Nonce      []byte
	AADHash    [32]byte
	WrappedDEK []byte
}

type CredentialClaimStatus string

const (
	CredentialClaimReady             CredentialClaimStatus = "READY"
	CredentialClaimAckPending        CredentialClaimStatus = "ACK_PENDING"
	CredentialClaimReconcileRequired CredentialClaimStatus = "ACK_RECONCILE_REQUIRED"
	CredentialClaimClaimed           CredentialClaimStatus = "CLAIMED"
	CredentialClaimExpired           CredentialClaimStatus = "EXPIRED"
	CredentialClaimRejected          CredentialClaimStatus = "REJECTED"
)

type StoredCredentialClaim struct {
	ID                     string
	IntegrationOperationID string
	Key                    ClaimKey
	OperationKind          OperationKind
	SeatID                 string
	SeatExternalID         string
	TargetMemberID         string
	TargetMemberExternalID string
	ClaimOperationID       string
	TokenHash              []byte
	CredentialFingerprint  []byte
	IntentHash             []byte
	Envelope               CredentialEnvelope
	Status                 CredentialClaimStatus
	AckResultSnapshot      []byte
	ErrorCode              string
	FencingToken           int64
	LeaseOwner             string
	LeaseExpiresAt         *time.Time
	ExpiresAt              time.Time
	Expired                bool
	ClaimedAt              *time.Time
	TerminalAt             *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type AcquireCredentialClaimLeaseInput struct {
	Key           ClaimKey
	LeaseOwner    string
	LeaseDuration time.Duration
}

type CredentialClaimLease struct {
	Claim        *StoredCredentialClaim
	FencingToken int64
}

type AcquireNextCredentialClaimLeaseInput struct {
	LeaseOwner    string
	LeaseDuration time.Duration
}

type CommitCredentialAckInput struct {
	Key          ClaimKey
	LeaseOwner   string
	FencingToken int64
	Evidence     ProvisionCredentialAckResult
}

type BeginCredentialAckInput struct {
	Key          ClaimKey
	LeaseOwner   string
	FencingToken int64
}

type CommitCredentialAckFailureInput struct {
	Key          ClaimKey
	LeaseOwner   string
	FencingToken int64
	Status       CredentialClaimStatus
	ErrorCode    string
}

// ClaimCredentialInput 只提交领取 CAS，不携带或返回包络。
// 正确顺序是 Acquire lease -> 事务外 KMS 解密 -> fenced claim commit -> HTTP 披露。
type ClaimCredentialInput struct {
	Key                    ClaimKey
	LeaseOwner             string
	FencingToken           int64
	TargetMemberExternalID string
	TokenHash              [32]byte
}

type ExpireCredentialClaimInput struct {
	Key          ClaimKey
	LeaseOwner   string
	FencingToken int64
}
