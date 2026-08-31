package recovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

var (
	ErrNotFound     = errors.New("recovery governance aggregate not found")
	ErrHashDrift    = errors.New("recovery governance request hash drift")
	ErrLeaseHeld    = errors.New("recovery governance lease is held")
	ErrStaleFence   = errors.New("recovery governance fencing token is stale")
	ErrInvalidState = errors.New("recovery governance state is invalid")
	ErrInvalidData  = errors.New("recovery governance data is invalid")
	ErrLegacy       = errors.New("legacy recovery artifact is unverified")
)

type OperationKey struct {
	ClientID    string
	OperationID string
}

type StoredOperation struct {
	AggregateID      string
	Key              OperationKey
	Kind             string
	Status           string
	FencingToken     int64
	LeaseOwner       string
	LeaseExpiresAt   *time.Time
	RequestHash      [sha256.Size]byte
	RequestSnapshot  []byte
	ResponseSnapshot []byte
	ErrorCode        string
}

type ResourceAccountRegistration struct {
	Key                  OperationKey
	ExternalID           string
	PoolExternalID       string
	Provider             string
	ProviderAccountRef   string
	InventoryVersion     uint64
	ProviderKeyRef       string
	AttestationDigest    [sha256.Size]byte
	AttestationSignature []byte
	RequestHash          [sha256.Size]byte
	RequestSnapshot      []byte
}

// ResourceAccountSeatMappingRegistration 将账号登记与 Seat 范围分离；一个账号可显式映射多个 Seat，
// 但相同 provider/account ref 在同一 Pool 只能对应一个权威账号记录。
type ResourceAccountSeatMappingRegistration struct {
	Key               OperationKey
	AccountExternalID string
	SeatExternalID    string
	InventoryVersion  uint64
	RequestHash       [sha256.Size]byte
	RequestSnapshot   []byte
}

type EpochMember struct {
	SeatExternalID              string
	MemberExternalID            string
	Role                        string
	ShareIndex                  uint16
	SigningAlgorithm            string
	SigningKeyID                string
	SigningPublicKey            []byte
	SigningKeyFingerprint       [sha256.Size]byte
	SigningProofAlgorithm       string
	SigningProof                []byte
	RecoveryKeyAlgorithm        string
	RecoveryKeyID               string
	RecoveryEncryptionPublicKey []byte
	RecoveryKeyFingerprint      [sha256.Size]byte
	RecoveryKeyProofAlgorithm   string
	RecoveryKeyProof            []byte
}

// EpochSeatReplacement 只列出发生永久变更的 Seat；未列出的 Seat 必须从 from Epoch 原样复制。
// Store 会从 seats.owner_member_id 和 ACTIVE from Epoch 快照计算完整集合，不能相信调用方拼出的历史。
type EpochSeatReplacement struct {
	SeatExternalID          string
	FromMemberExternalID    string
	ToMemberExternalID      string
	ExpectedAssignmentEpoch uint64
	FreezeOperationID       string
	FreezeSnapshotHash      [sha256.Size]byte
}

// EpochSeatFreeze 固定 Pool ceremony 中每个 Seat 的暂停双屏障；即使 owner 不变也必须先 FROZEN。
type EpochSeatFreeze struct {
	SeatExternalID          string
	ExpectedAssignmentEpoch uint64
	FreezeOperationID       string
	FreezeSnapshotHash      [sha256.Size]byte
}

type BeginEpochPlanInput struct {
	Key                           OperationKey
	CeremonyType                  CeremonyType
	PlanExternalID                string
	PoolExternalID                string
	FromEpoch                     uint64
	ToEpoch                       uint64
	GovernanceThreshold           uint16
	RecoveryThreshold             uint16
	PreviousManifestHash          [sha256.Size]byte
	BootstrapAttestationRef       string
	BootstrapAttestationDigest    [sha256.Size]byte
	BootstrapAttestationIssuer    string
	BootstrapAttestationKeyID     string
	BootstrapAttestationSignature []byte
	BootstrapAttestationVersion   uint64
	PortableProfile               *PortableEvidenceProfile
	Members                       []EpochMember
	SeatFreezes                   []EpochSeatFreeze
	Replacements                  []EpochSeatReplacement
	Accounts                      []ResourceAccountPlan
	RequestHash                   [sha256.Size]byte
	RequestSnapshot               []byte
	LeaseOwner                    string
	LeaseDuration                 time.Duration
}

type AcquireEpochPlanLeaseInput struct {
	Key                  OperationKey
	LeaseOwner           string
	ExpectedFencingToken int64
	LeaseDuration        time.Duration
}

type StoredEpochPlan struct {
	ID                         string
	ExternalID                 string
	CeremonyType               CeremonyType
	PoolID                     string
	PoolExternalID             string
	FromEpoch                  uint64
	ToEpoch                    uint64
	Status                     string
	GovernanceThreshold        uint16
	RecoveryThreshold          uint16
	ExpectedMemberCount        int
	ExpectedResourceCount      int
	CommittedShareCount        int
	VerifiedSignatureCount     int
	AcknowledgedShareCount     int
	StagedBatchCount           int
	RootArtifactID             string
	ManifestID                 string
	ManifestHash               [sha256.Size]byte
	PreviousManifestHash       [sha256.Size]byte
	CeremonyAttestationRef     string
	CeremonyAttestationDigest  [sha256.Size]byte
	CeremonyAttestationIssuer  string
	CeremonyAttestationKeyID   string
	CeremonyAttestationVersion uint64
	PortableProfile            *PortableEvidenceProfile
	Version                    int64
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

type EpochPlanTarget struct {
	Operation *StoredOperation
	Plan      *StoredEpochPlan
}

type StoredShareDelivery struct {
	ExternalID                   string
	MemberExternalID             string
	ShareIndex                   uint16
	EncryptionAlgorithm          string
	RecipientKeyID               string
	RecipientKeyFingerprint      [sha256.Size]byte
	CiphertextHash               [sha256.Size]byte
	ProviderShareCommitment      []byte
	ProviderProofDigest          [sha256.Size]byte
	ProviderProofSignature       []byte
	PortableProofAlgorithm       string
	PortableProofKeyID           string
	PortableProofProtocolVersion string
	PortableProofSignature       []byte
	RootCommitmentHash           [sha256.Size]byte
	VSSCommitmentHash            [sha256.Size]byte
	RecoveryPackageHash          [sha256.Size]byte
	RequestIntentHash            [sha256.Size]byte
	Acknowledged                 bool
}

type StoredRootArtifact struct {
	ExternalID                         string
	Provider                           string
	ProviderKeyRef                     string
	RootHandle                         string
	RootKeyVersion                     string
	EpochRecoveryAlgorithm             string
	EpochRecoveryKeyID                 string
	EpochRecoveryKeyFingerprint        [sha256.Size]byte
	WrapDomain                         string
	WrapAlgorithm                      string
	VSSAlgorithm                       string
	VSSCommitmentHash                  [sha256.Size]byte
	VSSProofHash                       [sha256.Size]byte
	PrivateKeyCommitmentHash           [sha256.Size]byte
	RootCommitmentHash                 [sha256.Size]byte
	RecoveryPackageHash                [sha256.Size]byte
	RequestIntentHash                  [sha256.Size]byte
	ProviderAttestationRef             string
	AttestationDigest                  [sha256.Size]byte
	AttestationSignature               []byte
	AttestationKeyID                   string
	PortableAttestationAlgorithm       string
	PortableAttestationIssuer          string
	PortableAttestationKeyID           string
	PortableAttestationProtocolVersion string
	PortableAttestationSignature       []byte
}

// EpochSecuritySnapshot 是后续真实验签的唯一可信输入；调用方不得重复提交公钥覆盖 Epoch 快照。
type EpochSecuritySnapshot struct {
	Plan                       *StoredEpochPlan
	Root                       *StoredRootArtifact
	Members                    []EpochMember
	Deliveries                 []StoredShareDelivery
	RootCommitmentHash         [sha256.Size]byte
	VSSCommitmentHash          [sha256.Size]byte
	ManifestCanonical          []byte
	ManifestHash               [sha256.Size]byte
	ManifestPlatformDomain     string
	ManifestPlatformAlgorithm  string
	ManifestPlatformKeyRef     string
	ManifestPlatformSignature  []byte
	ManifestPlatformVerifiedAt time.Time
}

type RootArtifactInput struct {
	Key                                OperationKey
	LeaseOwner                         string
	FencingToken                       int64
	ExternalID                         string
	Provider                           string
	ProviderKeyRef                     string
	RootHandle                         string
	RootKeyVersion                     string
	EpochRecoveryAlgorithm             string
	EpochRecoveryKeyID                 string
	EpochRecoveryKeyFingerprint        [sha256.Size]byte
	WrapDomain                         string
	WrapAlgorithm                      string
	VSSAlgorithm                       string
	VSSCommitment                      []byte
	VSSCommitmentHash                  [sha256.Size]byte
	VSSProof                           []byte
	VSSProofHash                       [sha256.Size]byte
	PrivateKeyCommitment               []byte
	PrivateKeyCommitmentHash           [sha256.Size]byte
	RootCommitmentHash                 [sha256.Size]byte
	RecoveryPackageHash                [sha256.Size]byte
	RequestIntentHash                  [sha256.Size]byte
	ProviderAttestationRef             string
	AttestationDigest                  [sha256.Size]byte
	AttestationSignature               []byte
	AttestationKeyID                   string
	PortableAttestationAlgorithm       string
	PortableAttestationIssuer          string
	PortableAttestationKeyID           string
	PortableAttestationProtocolVersion string
	PortableAttestationSignature       []byte
}

type StagedBatchBinding struct {
	EpochRole                 string
	ResourceAccountExternalID string
	BatchExternalID           string
	AccountRef                string
	BatchType                 string
	BatchVersion              uint64
	CiphertextHash            [sha256.Size]byte
	RecoveryWrapHash          [sha256.Size]byte
}

type ManifestDraftInput struct {
	Key                       OperationKey
	LeaseOwner                string
	FencingToken              int64
	ExternalID                string
	ProtocolVersion           string
	CanonicalPayload          []byte
	ManifestHash              [sha256.Size]byte
	BatchSetHash              [sha256.Size]byte
	RecoveryPackageHash       [sha256.Size]byte
	ProviderAttestationDigest [sha256.Size]byte
	PlatformKeyRef            string
	PlatformAlgorithm         string
	PlatformSignatureDomain   string
	PlatformSignature         []byte
	PlatformVerifiedAt        time.Time
	BatchBindings             []StagedBatchBinding
}

type ShareDeliveryInput struct {
	ExternalID                   string
	MemberExternalID             string
	ShareIndex                   uint16
	EncryptionAlgorithm          string
	RecipientKeyID               string
	RecipientKeyFingerprint      [sha256.Size]byte
	Ciphertext                   []byte
	CiphertextHash               [sha256.Size]byte
	ProviderShareCommitment      []byte
	ProviderProofDigest          [sha256.Size]byte
	ProviderProofSignature       []byte
	PortableProofAlgorithm       string
	PortableProofKeyID           string
	PortableProofProtocolVersion string
	PortableProofSignature       []byte
}

type ManifestMemberSignature struct {
	MemberExternalID string
	Algorithm        string
	KeyID            string
	MessageHash      [sha256.Size]byte
	Signature        []byte
	VerifiedAt       time.Time
}

type CommitManifestInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
	Signatures   []ManifestMemberSignature
}

// ShareAcknowledgementInput 是对已存在 Manifest hash 的真实验签证据。
// 它与加密 Share 分开发送和提交，因而不存在“先 ACK 后 Manifest”的时序捷径。
type ShareAcknowledgementInput struct {
	DeliveryExternalID string
	MemberExternalID   string
	ManifestHash       [sha256.Size]byte
	RootCommitmentHash [sha256.Size]byte
	VSSCommitmentHash  [sha256.Size]byte
	VerifiedCommitment bool
	Algorithm          string
	KeyID              string
	MessageHash        [sha256.Size]byte
	Signature          []byte
	VerifiedAt         time.Time
}

type CommitShareAcknowledgementsInput struct {
	Key              OperationKey
	LeaseOwner       string
	FencingToken     int64
	Acknowledgements []ShareAcknowledgementInput
}

// StagedCredentialBatch 是永久轮换专用的 to-Epoch 批次。
// 普通 Phase2-E Seal 没有 Plan/Root 绑定，不能向 PREPARING Epoch 写入。
type StagedCredentialBatch struct {
	ExternalID                       string
	ResourceAccountExternalID        string
	AccountRef                       string
	Type                             credentials.BatchType
	BatchVersion                     uint64
	ContentFingerprint               [sha256.Size]byte
	EncryptionAlgorithm              string
	Ciphertext                       []byte
	Nonce                            []byte
	AADHash                          [sha256.Size]byte
	KMSWrapAlgorithm                 string
	KMSKeyRef                        string
	KMSWrapperDomain                 string
	WrappedDEKKMS                    []byte
	RecoveryWrapAlgorithm            string
	RecoveryWrapDomain               string
	RecoveryKeyHandle                string
	RecoveryKeyVersion               string
	RecoveryKeyFingerprint           [sha256.Size]byte
	WrappedDEKRecovery               []byte
	RecoveryBindingHash              [sha256.Size]byte
	ProviderWrapAttestationDigest    [sha256.Size]byte
	ProviderWrapAttestationSignature []byte
}

type CommitStagedBatchesInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
	BatchSetHash [sha256.Size]byte
	Batches      []StagedCredentialBatch
}

type ControlEvidenceBatchRef struct {
	EpochRole       string
	BatchType       string
	BatchExternalID string
}

type IssueControlEvidenceInput struct {
	Key                                OperationKey
	LeaseOwner                         string
	FencingToken                       int64
	EvidenceExternalID                 string
	PlanExternalID                     string
	ResourceExternalID                 string
	ProviderAttestationRef             string
	ProviderAttestationDigest          [sha256.Size]byte
	ProviderAttestationIssuer          string
	ProviderAttestationKeyID           string
	ProviderAttestationVersion         uint64
	ProviderAttestationAlgorithm       string
	ProviderAttestationSignature       []byte
	ProviderAttestationProtocolVersion string
	BatchReferences                    []ControlEvidenceBatchRef
	RequestHash                        [sha256.Size]byte
	RequestSnapshot                    []byte
}

type MarkEpochPlanReadyInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
}

type SeatReplacementIntent struct {
	SeatExternalID         string
	TargetMemberExternalID string
}

type BeginPermanentReplacementInput struct {
	Key                  OperationKey
	CaseExternalID       string
	PlanExternalID       string
	Seats                []SeatReplacementIntent
	EvidenceExternalIDs  []string
	RequestHash          [sha256.Size]byte
	RequestSnapshot      []byte
	LeaseOwner           string
	LeaseDuration        time.Duration
	ExpectedFencingToken int64
}

type BeginBootstrapFinalizationInput struct {
	Key                  OperationKey
	CaseExternalID       string
	PlanExternalID       string
	EvidenceExternalIDs  []string
	RequestHash          [sha256.Size]byte
	RequestSnapshot      []byte
	LeaseOwner           string
	LeaseDuration        time.Duration
	ExpectedFencingToken int64
}

type BeginSeatRotationInput struct {
	FinalizationKey           OperationKey
	FinalizationLeaseOwner    string
	FinalizationFencingToken  int64
	SeatExternalID            string
	DerivedOperationID        string
	RequestHash               [sha256.Size]byte
	RequestSnapshot           []byte
	ChildLeaseOwner           string
	ExpectedChildFencingToken int64
	ChildLeaseDuration        time.Duration
}

type StoredSeatRotationProgress struct {
	ID                      string
	PlanExternalID          string
	PoolExternalID          string
	FromEpoch               uint64
	ToEpoch                 uint64
	SeatExternalID          string
	TargetMemberExternalID  string
	ExpectedAssignmentEpoch uint64
	ExpectedPrincipalUserID int64
	ExpectedSubscriptionID  int64
	ExpectedAPIKeyID        int64
	ExpectedAPIKeyVersion   uint64
	DerivedOperationID      string
	Status                  string
	PrincipalUserID         int64
	SubscriptionID          int64
	APIKeyID                int64
	APIKeyVersion           uint64
	CredentialFingerprint   [sha256.Size]byte
	PreparedReference       string
	ProviderResultDigest    [sha256.Size]byte
	AttemptCount            int
	ErrorCode               string
	UpdatedAt               time.Time
}

// SeatRotationTarget 同时返回 child operation 的租约/fence 与不可变 Seat 快照。
// 外部 provider 调用必须发生在 Store 事务之外，并用 Operation.Key/RequestHash 作为幂等键。
type SeatRotationTarget struct {
	Operation *StoredOperation
	Progress  *StoredSeatRotationProgress
}

type CommitSeatRotationProgressInput struct {
	FinalizationKey          OperationKey
	FinalizationLeaseOwner   string
	FinalizationFencingToken int64
	ChildLeaseOwner          string
	ChildFencingToken        int64
	PreparationKey           OperationKey
	PreparationLeaseOwner    string
	PreparationFencingToken  int64
	PreparationSetHash       [sha256.Size]byte
	SeatExternalID           string
	DerivedOperationID       string
	Status                   string
	PrincipalUserID          int64
	SubscriptionID           int64
	APIKeyID                 int64
	APIKeyVersion            uint64
	Claim                    *ReplacementCredentialClaim
	ErrorCode                string
	ErrorDetail              string
	NextAttemptAt            *time.Time
}

type ReplacementCredentialClaim struct {
	SeatExternalID         string
	TargetMemberExternalID string
	PreparedReference      string
	ProviderResultDigest   [sha256.Size]byte
	CredentialFingerprint  [sha256.Size]byte
	EnvelopeAlgorithm      string
	EnvelopeKeyRef         string
	EnvelopeCiphertext     []byte
	EnvelopeNonce          []byte
	EnvelopeAADHash        [sha256.Size]byte
	WrappedDEK             []byte
}

type BeginPoolPreparationInput struct {
	FinalizationKey          OperationKey
	FinalizationLeaseOwner   string
	FinalizationFencingToken int64
	DerivedOperationID       string
	RequestHash              [sha256.Size]byte
	RequestSnapshot          []byte
	LeaseOwner               string
	ExpectedFencingToken     int64
	LeaseDuration            time.Duration
}

type PoolPreparationTarget struct {
	Operation     *StoredOperation
	Plan          *StoredEpochPlan
	IntentSetHash [sha256.Size]byte
}

type CommitPoolPreparationFailureInput struct {
	FinalizationKey          OperationKey
	FinalizationLeaseOwner   string
	FinalizationFencingToken int64
	PreparationKey           OperationKey
	PreparationLeaseOwner    string
	PreparationFencingToken  int64
	Status                   string
	ErrorCode                string
	ErrorDetail              string
	NextAttemptAt            *time.Time
}

type ReplacementClaimActivation struct {
	SeatExternalID   string
	ClaimOperationID string
	TokenHash        [sha256.Size]byte
	ExpiresAt        time.Time
}

const MaxReplacementClaimTTL = 30 * time.Minute

type ReplacementClaimIntent struct {
	SeatExternalID   string
	ClaimOperationID string
}

type BeginPoolActivationInput struct {
	FinalizationKey           OperationKey
	FinalizationLeaseOwner    string
	FinalizationFencingToken  int64
	DerivedOperationID        string
	RequestHash               [sha256.Size]byte
	RequestSnapshot           []byte
	ChildLeaseOwner           string
	ExpectedChildFencingToken int64
	ChildLeaseDuration        time.Duration
}

type PoolActivationTarget struct {
	Operation       *StoredOperation
	Plan            *StoredEpochPlan
	PreparedSetHash [sha256.Size]byte
}

type PoolActivatedSeat struct {
	SeatExternalID         string
	TargetMemberExternalID string
	PreparedReference      string
	PrincipalUserID        int64
	SubscriptionID         int64
	APIKeyID               int64
	APIKeyVersion          uint64
	CredentialFingerprint  [sha256.Size]byte
	CurrentConcurrency     int64
	PendingSettlements     int64
}

type CommitPoolActivationInput struct {
	FinalizationKey                   OperationKey
	FinalizationLeaseOwner            string
	FinalizationFencingToken          int64
	ChildLeaseOwner                   string
	ChildFencingToken                 int64
	DerivedOperationID                string
	Status                            string
	PreparedSetHash                   [sha256.Size]byte
	ProviderAttestationRef            string
	ProviderAttestationDigest         [sha256.Size]byte
	ProviderAttestationIssuer         string
	ProviderAttestationKeyID          string
	ProviderAttestationVersion        uint64
	ProviderAttestationSignature      []byte
	OldCredentialSetInvalidated       bool
	CredentialFingerprintGateEnforced bool
	AuthorizationCacheInvalidated     bool
	AuthorizationCacheDurableOutbox   bool
	AuthCacheMinimumEvents            int
	Seats                             []PoolActivatedSeat
	ErrorCode                         string
	ErrorDetail                       string
	NextAttemptAt                     *time.Time
}

type CommitPermanentReplacementInput struct {
	Key            OperationKey
	LeaseOwner     string
	FencingToken   int64
	ClaimIntents   []ReplacementClaimIntent
	ResultSnapshot []byte
}

type BeginProviderReleaseInput struct {
	FinalizationKey           OperationKey
	FinalizationLeaseOwner    string
	FinalizationFencingToken  int64
	DerivedOperationID        string
	RequestHash               [sha256.Size]byte
	RequestSnapshot           []byte
	ChildLeaseOwner           string
	ExpectedChildFencingToken int64
	ChildLeaseDuration        time.Duration
}

type ProviderReleaseTarget struct {
	Operation       *StoredOperation
	Plan            *StoredEpochPlan
	PreparedSetHash [sha256.Size]byte
}

type CommitProviderReleaseInput struct {
	FinalizationKey                   OperationKey
	FinalizationLeaseOwner            string
	FinalizationFencingToken          int64
	DerivedOperationID                string
	ChildLeaseOwner                   string
	ChildFencingToken                 int64
	Status                            string
	ProviderAttestationRef            string
	ProviderAttestationDigest         [sha256.Size]byte
	ProviderAttestationIssuer         string
	ProviderAttestationKeyID          string
	ProviderAttestationVersion        uint64
	ProviderAttestationSignature      []byte
	AllCredentialsEnabled             bool
	AllSubscriptionsEnabled           bool
	OldCredentialSetInvalidated       bool
	CredentialFingerprintGateEnforced bool
	AuthorizationCacheInvalidated     bool
	AuthorizationCacheDurableOutbox   bool
	AuthCacheMinimumEvents            int
	ResultSnapshot                    []byte
	ErrorCode                         string
	ErrorDetail                       string
	NextAttemptAt                     *time.Time
}

type CommitReplacementClaimsInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
	Claims       []ReplacementClaimActivation
}

type AcquireNextPermanentReplacementLeaseInput struct {
	LeaseOwner    string
	LeaseDuration time.Duration
}

type RenewPermanentReplacementLeaseInput struct {
	Key                  OperationKey
	LeaseOwner           string
	ExpectedFencingToken int64
	LeaseDuration        time.Duration
}

type RenewRecoveryChildOperationLeaseInput struct {
	FinalizationKey           OperationKey
	FinalizationLeaseOwner    string
	FinalizationFencingToken  int64
	DerivedOperationID        string
	ChildLeaseOwner           string
	ExpectedChildFencingToken int64
	ChildLeaseDuration        time.Duration
}

type PermanentReplacementTarget struct {
	Operation       *StoredOperation
	Plan            *StoredEpochPlan
	CaseExternalID  string
	CaseStatus      string
	SeatTargets     []SeatRotationTarget
	Preparation     *StoredOperation
	Activation      *StoredOperation
	ProviderRelease *StoredOperation
}

// StoredReplacementCredentialClaim 只包含 KMS 包络，不包含凭据或原始 claim token 明文。
type StoredReplacementCredentialClaim struct {
	ID                     string
	Key                    OperationKey
	PlanExternalID         string
	PrepareRequestHash     [sha256.Size]byte
	SeatExternalID         string
	TargetMemberExternalID string
	CredentialFingerprint  [sha256.Size]byte
	EnvelopeAlgorithm      string
	EnvelopeKeyRef         string
	EnvelopeCiphertext     []byte
	EnvelopeNonce          []byte
	EnvelopeAADHash        [sha256.Size]byte
	WrappedDEK             []byte
	Status                 string
	FencingToken           int64
	LeaseOwner             string
	LeaseExpiresAt         *time.Time
	ExpiresAt              time.Time
}

type AcquireReplacementCredentialClaimInput struct {
	Key                    OperationKey
	PlanExternalID         string
	SeatExternalID         string
	TargetMemberExternalID string
	TokenHash              [sha256.Size]byte
	LeaseOwner             string
	LeaseDuration          time.Duration
}

type CommitReplacementCredentialClaimInput struct {
	Key                    OperationKey
	PlanExternalID         string
	SeatExternalID         string
	TargetMemberExternalID string
	TokenHash              [sha256.Size]byte
	LeaseOwner             string
	FencingToken           int64
}

type CommitBootstrapFinalizationInput = CommitPermanentReplacementInput

type CommitPermanentReplacementFailureInput struct {
	Key           OperationKey
	LeaseOwner    string
	FencingToken  int64
	ErrorCode     string
	ErrorDetail   string
	NextAttemptAt *time.Time
}

// Store 只持久化外部密码学服务已经生成并由本地可信公钥验证的结果；接口没有 Root/Share 明文参数。
type Store interface {
	CommitMemberArtifactReceipt(context.Context, CommitMemberArtifactReceiptInput) error
	RegisterResourceAccount(context.Context, ResourceAccountRegistration) error
	RegisterResourceAccountSeatMapping(context.Context, ResourceAccountSeatMappingRegistration) error
	BeginEpochPlan(context.Context, BeginEpochPlanInput) (*EpochPlanTarget, bool, error)
	AcquireEpochPlanLease(context.Context, AcquireEpochPlanLeaseInput) (*StoredOperation, error)
	CommitRootArtifact(context.Context, RootArtifactInput) (*StoredEpochPlan, error)
	CommitShareDeliveries(context.Context, OperationKey, string, int64, []ShareDeliveryInput) (*StoredEpochPlan, error)
	CommitManifestDraft(context.Context, ManifestDraftInput) (*StoredEpochPlan, error)
	CommitManifest(context.Context, CommitManifestInput) (*StoredEpochPlan, error)
	CommitShareAcknowledgements(context.Context, CommitShareAcknowledgementsInput) (*StoredEpochPlan, error)
	CommitStagedBatches(context.Context, CommitStagedBatchesInput) (*StoredEpochPlan, error)
	MarkEpochPlanReady(context.Context, MarkEpochPlanReadyInput) (*StoredEpochPlan, error)
	GetEpochPlan(context.Context, string) (*StoredEpochPlan, error)
	// GetEpochPlanProgress 仅返回计划和治理 operation 租约元数据，不返回 Root、Share 或凭据材料。
	GetEpochPlanProgress(context.Context, string) (*EpochPlanTarget, error)
	GetEpochSecuritySnapshot(context.Context, string) (*EpochSecuritySnapshot, error)
	IssueControlEvidence(context.Context, IssueControlEvidenceInput) error
	BeginSeatRotation(context.Context, BeginSeatRotationInput) (*SeatRotationTarget, bool, error)
	CommitSeatRotationProgress(context.Context, CommitSeatRotationProgressInput) (*StoredSeatRotationProgress, error)
	BeginPoolPreparation(context.Context, BeginPoolPreparationInput) (*PoolPreparationTarget, bool, error)
	CommitPoolPreparationFailure(context.Context, CommitPoolPreparationFailureInput) (*StoredOperation, error)
	BeginPoolActivation(context.Context, BeginPoolActivationInput) (*PoolActivationTarget, bool, error)
	CommitPoolActivation(context.Context, CommitPoolActivationInput) (*PermanentReplacementTarget, error)
	BeginProviderRelease(context.Context, BeginProviderReleaseInput) (*ProviderReleaseTarget, bool, error)
	CommitProviderRelease(context.Context, CommitProviderReleaseInput) (*StoredOperation, bool, error)
	BeginPermanentReplacement(context.Context, BeginPermanentReplacementInput) (*PermanentReplacementTarget, bool, error)
	BeginBootstrapFinalization(context.Context, BeginBootstrapFinalizationInput) (*PermanentReplacementTarget, bool, error)
	AcquireNextPermanentReplacementLease(context.Context, AcquireNextPermanentReplacementLeaseInput) (*PermanentReplacementTarget, error)
	RenewPermanentReplacementLease(context.Context, RenewPermanentReplacementLeaseInput) (*PermanentReplacementTarget, error)
	RenewRecoveryChildOperationLease(context.Context, RenewRecoveryChildOperationLeaseInput) (*StoredOperation, error)
	CommitPermanentReplacement(context.Context, CommitPermanentReplacementInput) (*StoredOperation, bool, error)
	CommitBootstrapFinalization(context.Context, CommitBootstrapFinalizationInput) (*StoredOperation, bool, error)
	CommitReplacementClaims(context.Context, CommitReplacementClaimsInput) (*StoredOperation, bool, error)
	CommitPermanentReplacementFailure(context.Context, CommitPermanentReplacementFailureInput) (*StoredOperation, error)
	AcquireReplacementCredentialClaim(context.Context, AcquireReplacementCredentialClaimInput) (*StoredReplacementCredentialClaim, error)
	CommitReplacementCredentialClaim(context.Context, CommitReplacementCredentialClaimInput) (*StoredReplacementCredentialClaim, error)
}
