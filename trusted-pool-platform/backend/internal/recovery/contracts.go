package recovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

var (
	ErrProviderUnavailable = errors.New("recovery security provider is unavailable")
	ErrBindingMismatch     = errors.New("recovery governance binding mismatch")
	ErrDuplicate           = errors.New("recovery governance collection contains duplicates")
	ErrCanonicalization    = errors.New("manifest canonicalization failed")
	ErrSignatureInvalid    = errors.New("recovery governance signature is invalid")
)

const (
	ProtocolVersionV1               = "trusted-pool/recovery-governance/v1"
	PermanentSeatRotationProtocolV1 = "trusted-pool/permanent-seat-rotation/v1"

	MemberManifestSignatureDomain = "trusted-pool/member-manifest-signature/v1"
	ShareAcknowledgementDomain    = "trusted-pool/recovery-share-ack/v1"
	SigningKeyPossessionDomain    = "trusted-pool/member-signing-key-possession/v1"
	RecoveryKeyPossessionDomain   = "trusted-pool/member-recovery-key-possession/v1"
)

type CeremonyType string

const (
	CeremonyBootstrap CeremonyType = "BOOTSTRAP"
	CeremonyRotate    CeremonyType = "ROTATE"
)

// RecoveryRootProvider 必须在外部信任边界内完成非对称 Recovery Root 生成、阈值分片和逐成员公钥加密。
// 相同 RequestID 和 IntentHash 必须返回逐字节等价的既有 package；不确定结果只能查询/重放，禁止生成第二个 Root。
// 接口刻意不定义 Root/Share 明文返回值，在线平台只能持有公钥句柄/指纹、证明和密文。
type RecoveryRootProvider interface {
	Ready(context.Context) error
	CreateEncryptedPackage(context.Context, RecoveryPackageRequest) (EncryptedRecoveryPackage, error)
	WrapCredentialDEK(context.Context, EpochDEKWrapRequest) (EpochDEKWrapResult, error)
}

// EpochCredentialBatchProvider 在外部密码学边界内完成 payload 加密、online KMS 包装和本 Epoch Root 包装。
// HTTP/Store 不接收 Root、Share 或 DEK 明文；调用必须以
// (OperationID, BatchID, RequestHash) 精确幂等，未知结果只能查询或重放同一结果。
type EpochCredentialBatchProvider interface {
	Ready(context.Context) error
	SealCredentialBatch(context.Context, EpochCredentialBatchRequest) (EpochCredentialBatchResult, error)
}

// PermanentSeatRotationProvider 必须按 (OperationID, RequestHash) 精确幂等。
// Prepare 只生成禁用的新 Key；Activate 不返回凭据。超时或结果未知时只能重放相同请求。
type PermanentSeatRotationProvider interface {
	Ready(context.Context) error
	PreparePoolRotation(context.Context, PermanentPoolRotationPrepareRequest) (PermanentPoolRotationPrepareResult, error)
	ActivatePreparedPoolRotation(context.Context, PermanentPoolRotationActivateRequest) (PermanentPoolRotationActivateResult, error)
	CommitActivatedPoolRotation(context.Context, PermanentPoolRotationCommitRequest) (PermanentPoolRotationCommitResult, error)
}

// PermanentSeatActivationVerifier 使用独立信任锚验证 Pool 原子激活响应。
// 安全门是数据库实时 fingerprint gate；异步授权缓存 outbox 只用于运维收敛，不能替代该证明。
type PermanentSeatActivationVerifier interface {
	Ready(context.Context) error
	VerifyPoolActivation(context.Context, PermanentPoolActivationVerifyRequest) error
	VerifyPoolCommit(context.Context, PermanentPoolCommitVerifyRequest) error
}

// RecoveryCredentialCipher 只在进程内短暂接触新 Seat 凭据；持久层仅接收 KMS 包装后的 Envelope。
// Open 为后续一次性 claim 领取使用，不能作为运维读取或状态查询旁路。
type RecoveryCredentialCipher interface {
	Ready(context.Context) error
	Seal(context.Context, []byte, []byte) (credentials.Envelope, error)
	Open(context.Context, credentials.Envelope, []byte) ([]byte, error)
}

// MemberCeremonyGateway 将每个成员自己的加密 Share 与已签平台 Manifest 定向发布。
// 相同 OperationID/DeliveryID/ManifestHash 必须精确幂等；接口每次只允许一个成员的密文，禁止运营端批量读取。
type MemberCeremonyGateway interface {
	Ready(context.Context) error
	PublishArtifacts(context.Context, MemberArtifactPublishRequest) (MemberArtifactPublishReceipt, error)
}

// ManifestCanonicalizer 必须由成熟 RFC 8785/JCS 实现提供；平台不自行实现规范化算法。
type ManifestCanonicalizer interface {
	Ready(context.Context) error
	Canonicalize(context.Context, []byte) ([]byte, error)
}

// PlatformSigner 代表外部 KMS/HSM 签名能力，在线进程不得取得签名私钥。
type PlatformSigner interface {
	Ready(context.Context) error
	SignManifest(context.Context, PlatformManifestSignRequest) (PlatformManifestSignature, error)
	VerifyManifestSignature(context.Context, PlatformManifestVerifyRequest) error
}

// ProviderAttestationVerifier 使用独立配置的供应商信任锚验证 Root/Share 证明和控制权证明。
// 仅判断结构字段或比较供应商自报散列不能替代这里的真实验签。
type ProviderAttestationVerifier interface {
	Ready(context.Context) error
	VerifyRecoveryPackage(context.Context, RecoveryPackageVerifyRequest) error
	VerifyEncryptedShare(context.Context, EncryptedShareVerifyRequest) error
	VerifyCredentialDEKWrap(context.Context, EpochDEKWrapVerifyRequest) error
	VerifyStagedCredentialBatch(context.Context, EpochCredentialBatchVerifyRequest) error
	VerifyMemberArtifactReceipt(context.Context, MemberArtifactReceiptVerifyRequest) error
	VerifyControlAttestation(context.Context, ProviderAttestationVerifyRequest) (VerifiedProviderAttestation, error)
}

// MemberSignatureVerifier 使用成员 Epoch 快照中的公钥执行真实验签；应用层不得用计数代替验签。
type MemberSignatureVerifier interface {
	Ready(context.Context) error
	VerifyMemberKeyProof(context.Context, MemberKeyProofVerifyRequest) error
	VerifyMemberSignature(context.Context, MemberSignatureVerifyRequest) error
}

type Providers struct {
	Root              RecoveryRootProvider
	Canonicalizer     ManifestCanonicalizer
	PlatformSigner    PlatformSigner
	Attestation       ProviderAttestationVerifier
	MemberSignatures  MemberSignatureVerifier
	CredentialBatches EpochCredentialBatchProvider
	MemberArtifacts   MemberCeremonyGateway
	SeatRotations     PermanentSeatRotationProvider
	SeatActivations   PermanentSeatActivationVerifier
	CredentialCipher  RecoveryCredentialCipher
}

func (p Providers) Ready(ctx context.Context) error {
	checks := []interface{ Ready(context.Context) error }{
		p.Root, p.Canonicalizer, p.PlatformSigner, p.Attestation, p.MemberSignatures, p.CredentialBatches,
		p.MemberArtifacts,
		p.SeatRotations, p.SeatActivations, p.CredentialCipher,
	}
	for _, provider := range checks {
		if isNilProvider(provider) {
			return ErrProviderUnavailable
		}
		if err := provider.Ready(ctx); err != nil {
			return ErrProviderUnavailable
		}
	}
	return nil
}

// PermanentSeatRotationPrepareRequest 将 provider 调用绑定到计划、相邻 Epoch、稳定 Sub2API 身份与派生子操作。
// RequestHash 由 PermanentSeatRotationPrepareRequestHash 计算，provider 必须原样参与幂等键。
type PermanentSeatRotationPrepareRequest struct {
	ProtocolVersion         string
	OperationID             string
	RequestHash             [sha256.Size]byte
	PlanID                  string
	CeremonyType            CeremonyType
	PoolID                  string
	FromEpoch               uint64
	ToEpoch                 uint64
	SeatID                  string
	TargetMemberID          string
	ExpectedAssignmentEpoch uint64
	PrincipalUserID         int64
	SubscriptionID          int64
	APIKeyID                int64
	FromAPIKeyVersion       uint64
	ToAPIKeyVersion         uint64
}

// PermanentSeatRotationPrepareResult 的 Credential 是唯一明文敏感字段，Manager 验证后必须立即包络并清零。
// Prepare 成功后新 Key 必须保持 disabled，Subscription suspended，Seat 不得离开冻结态。
type PermanentSeatRotationPrepareResult struct {
	ProtocolVersion            string
	OperationID                string
	RequestHash                [sha256.Size]byte
	PlanID                     string
	CeremonyType               CeremonyType
	PoolID                     string
	FromEpoch                  uint64
	ToEpoch                    uint64
	SeatID                     string
	TargetMemberID             string
	AssignmentEpoch            uint64
	PrincipalUserID            int64
	SubscriptionID             int64
	APIKeyID                   int64
	ActiveAPIKeyVersion        uint64
	State                      string
	CredentialEnabled          bool
	SubscriptionEnabled        bool
	CredentialRotationComplete bool
	Credential                 []byte
	PreparedRotationRef        string
	CompletedAt                time.Time
}

// PermanentPoolRotationPrepareRequest 在一次 provider 调用中绑定规范排序的全部 child intent。
// Seats 中每个 RequestHash 仍是独立持久 child operation 的精确幂等散列。
type PermanentPoolRotationPrepareRequest struct {
	ProtocolVersion string
	OperationID     string
	RequestHash     [sha256.Size]byte
	PlanID          string
	CeremonyType    CeremonyType
	PoolID          string
	FromEpoch       uint64
	ToEpoch         uint64
	ChildSetHash    [sha256.Size]byte
	Seats           []PermanentSeatRotationPrepareRequest
}

type PermanentPoolRotationPrepareResult struct {
	ProtocolVersion string
	OperationID     string
	RequestHash     [sha256.Size]byte
	PlanID          string
	CeremonyType    CeremonyType
	PoolID          string
	FromEpoch       uint64
	ToEpoch         uint64
	ChildSetHash    [sha256.Size]byte
	Seats           []PermanentSeatRotationPrepareResult
}

type PermanentSeatActivationBinding struct {
	SeatID                  string
	TargetMemberID          string
	ExpectedAssignmentEpoch uint64
	PrincipalUserID         int64
	SubscriptionID          int64
	APIKeyID                int64
	ActiveAPIKeyVersion     uint64
	ChildOperationID        string
	ChildRequestHash        [sha256.Size]byte
	CredentialFingerprint   [sha256.Size]byte
	PreparedRotationRef     string
}

type PermanentSeatActivationResult struct {
	PermanentSeatActivationBinding
	AssignmentEpoch    uint64
	State              string
	CurrentConcurrency uint64
	PendingSettlements uint64
}

// PermanentPoolRotationActivateRequest 以规范排序全集做一次上游原子激活，不携带凭据。
type PermanentPoolRotationActivateRequest struct {
	ProtocolVersion    string
	OperationID        string
	PrepareOperationID string
	RequestHash        [sha256.Size]byte
	PlanID             string
	CeremonyType       CeremonyType
	PoolID             string
	FromEpoch          uint64
	ToEpoch            uint64
	PreparedSetHash    [sha256.Size]byte
	Seats              []PermanentSeatActivationBinding
}

type PermanentPoolRotationActivateResult struct {
	ProtocolVersion                   string
	OperationID                       string
	PrepareOperationID                string
	RequestHash                       [sha256.Size]byte
	PlanID                            string
	CeremonyType                      CeremonyType
	PoolID                            string
	FromEpoch                         uint64
	ToEpoch                           uint64
	PreparedSetHash                   [sha256.Size]byte
	State                             string
	AllCredentialsEnabled             bool
	AllSubscriptionsEnabled           bool
	OldCredentialSetInvalidated       bool
	CredentialFingerprintGateEnforced bool
	AuthorizationCacheInvalidated     bool
	AuthCacheDurableOutbox            bool
	AuthCacheMinimumEvents            int
	Seats                             []PermanentSeatActivationResult
	AttestationAlgorithm              string
	AttestationIssuer                 string
	AttestationRef                    string
	AttestationKeyID                  string
	AttestationVersion                uint64
	AttestationDigest                 [sha256.Size]byte
	Attestation                       []byte
	ActivatedAt                       time.Time
}

type PermanentPoolActivationVerifyRequest struct {
	Request PermanentPoolRotationActivateRequest
	Result  PermanentPoolRotationActivateResult
}

// PermanentPoolRotationCommitRequest 只释放已由平台完成 structural final 的完整 held 集合。
type PermanentPoolRotationCommitRequest struct {
	ProtocolVersion       string
	OperationID           string
	PrepareOperationID    string
	ActivationOperationID string
	ActivationRequestHash [sha256.Size]byte
	RequestHash           [sha256.Size]byte
	PlanID                string
	CeremonyType          CeremonyType
	PoolID                string
	FromEpoch             uint64
	ToEpoch               uint64
	PreparedSetHash       [sha256.Size]byte
	Seats                 []PermanentSeatActivationBinding
}

type PermanentPoolRotationCommitResult struct {
	ProtocolVersion                   string
	OperationID                       string
	PrepareOperationID                string
	ActivationOperationID             string
	ActivationRequestHash             [sha256.Size]byte
	RequestHash                       [sha256.Size]byte
	PlanID                            string
	CeremonyType                      CeremonyType
	PoolID                            string
	FromEpoch                         uint64
	ToEpoch                           uint64
	PreparedSetHash                   [sha256.Size]byte
	State                             string
	AllCredentialsEnabled             bool
	AllSubscriptionsEnabled           bool
	OldCredentialSetInvalidated       bool
	CredentialFingerprintGateEnforced bool
	AuthorizationCacheInvalidated     bool
	AuthCacheDurableOutbox            bool
	AuthCacheMinimumEvents            int
	Seats                             []PermanentSeatActivationResult
	AttestationAlgorithm              string
	AttestationIssuer                 string
	AttestationRef                    string
	AttestationKeyID                  string
	AttestationVersion                uint64
	AttestationDigest                 [sha256.Size]byte
	Attestation                       []byte
	CommittedAt                       time.Time
}

type PermanentPoolCommitVerifyRequest struct {
	Request PermanentPoolRotationCommitRequest
	Result  PermanentPoolRotationCommitResult
}

type MemberArtifactPublishRequest struct {
	CeremonyType          CeremonyType
	OperationID           string
	PoolID                string
	Epoch                 uint64
	DeliveryID            string
	MemberID              string
	ShareIndex            uint16
	EncryptedShare        []byte
	CiphertextHash        [sha256.Size]byte
	ProviderCommitment    []byte
	ProviderProof         []byte
	VSSAlgorithm          string
	VSSCommitment         []byte
	VSSProof              []byte
	VSSProofHash          [sha256.Size]byte
	ManifestCanonical     []byte
	ManifestHash          [sha256.Size]byte
	PlatformAlgorithm     string
	PlatformKeyID         string
	PlatformSignature     []byte
	PlatformVerifiedAt    time.Time
	RootCommitmentHash    [sha256.Size]byte
	VSSCommitmentHash     [sha256.Size]byte
	RootProviderID        string
	RootAttestationRef    string
	RootAttestationKeyID  string
	RootAttestationDigest [sha256.Size]byte
	RootAttestation       []byte
	RecoveryPackageHash   [sha256.Size]byte
	RecoveryRequestIntent [sha256.Size]byte
}

type MemberArtifactPublishReceipt struct {
	CeremonyType                 CeremonyType
	OperationID                  string
	PoolID                       string
	Epoch                        uint64
	DeliveryID                   string
	MemberID                     string
	ManifestHash                 [sha256.Size]byte
	ReceiptID                    string
	ReceiptHash                  [sha256.Size]byte
	ProviderProof                []byte
	ProviderProofDigest          [sha256.Size]byte
	ProviderProofAlgorithm       string
	ProviderProofKeyID           string
	ProviderProofProtocolVersion string
	PublishedAt                  time.Time
}

type MemberArtifactReceiptVerifyRequest struct {
	Request MemberArtifactPublishRequest
	Receipt MemberArtifactPublishReceipt
}

// RecoveryMember 是外部 Root Provider 所需的成员公钥投影，不含任何成员私钥。
type RecoveryMember struct {
	MemberID                 string
	Role                     string
	ShareIndex               uint16
	SigningAlgorithm         string
	SigningKeyID             string
	SigningKeyFingerprint    [sha256.Size]byte
	SigningPublicKey         []byte
	EncryptionAlgorithm      string
	EncryptionKeyID          string
	EncryptionKeyFingerprint [sha256.Size]byte
	EncryptionPublicKey      []byte
}

type RecoveryPackageRequest struct {
	Version              uint16
	CeremonyType         CeremonyType
	RequestID            string
	OperationID          string
	PoolID               string
	FromEpoch            uint64
	ToEpoch              uint64
	FromEpochStatus      string
	FromGovernanceState  string
	RecoveryThreshold    uint16
	PreviousManifestHash [sha256.Size]byte
	ExpectedProviderID   string
	TrustProfile         string
	Members              []RecoveryMember
	IntentHash           [sha256.Size]byte
}

// EncryptedRecoveryShare 只承载已经按成员公钥加密的 Share 和供应商证明。
type EncryptedRecoveryShare struct {
	MemberID                     string
	ShareIndex                   uint16
	EncryptionAlgorithm          string
	EncryptionKeyID              string
	EncryptionKeyFingerprint     [sha256.Size]byte
	Ciphertext                   []byte
	CiphertextHash               [sha256.Size]byte
	ProviderCommitment           []byte
	ProviderProof                []byte
	PortableProofAlgorithm       string
	PortableProofKeyID           string
	PortableProofProtocolVersion string
	PortableProofSignature       []byte
}

// EncryptedRecoveryPackage 不允许出现 Root 私钥或 Share 明文字段。
type EncryptedRecoveryPackage struct {
	Version                            uint16
	CeremonyType                       CeremonyType
	RequestID                          string
	OperationID                        string
	PoolID                             string
	FromEpoch                          uint64
	Epoch                              uint64
	FromEpochStatus                    string
	FromGovernanceState                string
	PreviousManifestHash               [sha256.Size]byte
	ProviderID                         string
	RootPublicAlgorithm                string
	RootPublicHandle                   string
	RootPublicFingerprint              [sha256.Size]byte
	RootKeyVersion                     string
	RootWrapDomain                     string
	RootWrapAlgorithm                  string
	RootPrivateCommitment              []byte
	VSSAlgorithm                       string
	VSSCommitment                      []byte
	VSSProof                           []byte
	ProviderAttestation                []byte
	ProviderAttestationRef             string
	ProviderAttestationKeyID           string
	ProviderAttestationDigest          [sha256.Size]byte
	PortableAttestationAlgorithm       string
	PortableAttestationIssuer          string
	PortableAttestationKeyID           string
	PortableAttestationProtocolVersion string
	PortableAttestationSignature       []byte
	EncryptedShares                    []EncryptedRecoveryShare
	PackageHash                        [sha256.Size]byte
	RequestIntentHash                  [sha256.Size]byte
	CreatedAt                          time.Time
}

// EpochDEKWrapRequest 的 PlaintextDEK 是待包装的随机数据密钥，不是 Root/Share 明文。
// Provider 必须使用指定 Epoch 的 opaque Root handle 完成非对称包装。
type EpochDEKWrapRequest struct {
	CeremonyType          CeremonyType
	OperationID           string
	PoolID                string
	Epoch                 uint64
	BatchID               string
	RootPublicHandle      string
	RootKeyVersion        string
	RootPublicFingerprint [sha256.Size]byte
	AADHash               [sha256.Size]byte
	PlaintextDEK          []byte
}

type EpochDEKWrapResult struct {
	CeremonyType          CeremonyType
	OperationID           string
	PoolID                string
	Epoch                 uint64
	BatchID               string
	RootPublicHandle      string
	RootKeyVersion        string
	RootPublicFingerprint [sha256.Size]byte
	WrapDomain            string
	WrapAlgorithm         string
	AADHash               [sha256.Size]byte
	WrappedDEK            []byte
	ProviderProof         []byte
}

type EpochDEKWrapVerifyRequest struct {
	Request EpochDEKWrapRequest
	Result  EpochDEKWrapResult
}

type EpochCredentialBatchRequest struct {
	CeremonyType          CeremonyType
	OperationID           string
	RequestHash           [sha256.Size]byte
	PoolID                string
	Epoch                 uint64
	BatchID               string
	ResourceAccountID     string
	AccountRef            string
	BatchType             credentials.BatchType
	BatchVersion          uint64
	RootPublicHandle      string
	RootKeyVersion        string
	RootPublicFingerprint [sha256.Size]byte
	RootWrapDomain        string
	RootWrapAlgorithm     string
	Payload               []byte
}

type EpochCredentialBatchResult struct {
	CeremonyType  CeremonyType
	OperationID   string
	RequestHash   [sha256.Size]byte
	PoolID        string
	Epoch         uint64
	Batch         StagedCredentialBatch
	ProviderProof []byte
}

type EpochCredentialBatchVerifyRequest struct {
	Request EpochCredentialBatchRequest
	Result  EpochCredentialBatchResult
}

type RecoveryPackageVerifyRequest struct {
	Request RecoveryPackageRequest
	Package EncryptedRecoveryPackage
}

type EncryptedShareVerifyRequest struct {
	CeremonyType          CeremonyType
	OperationID           string
	PoolID                string
	Epoch                 uint64
	ProviderID            string
	RootPublicHandle      string
	RootPublicFingerprint [sha256.Size]byte
	PackageHash           [sha256.Size]byte
	Member                RecoveryMember
	Share                 EncryptedRecoveryShare
	VSSCommitment         []byte
}

type SeatPlan struct {
	SeatID                  string `json:"seat_id"`
	MemberID                string `json:"member_id"`
	PrincipalUserID         int64  `json:"principal_user_id"`
	SubscriptionID          int64  `json:"subscription_id"`
	APIKeyID                int64  `json:"api_key_id"`
	ExpectedAssignmentEpoch uint64 `json:"expected_assignment_epoch"`
	FreezeOperationID       string `json:"freeze_operation_id"`
	FreezeSnapshotHash      string `json:"freeze_snapshot_hash"`
}

type ControlBatchPlan struct {
	BatchType          string `json:"batch_type"`
	FromBatchID        string `json:"from_batch_id"`
	FromBatchVersion   uint64 `json:"from_batch_version"`
	FromCiphertextHash string `json:"from_ciphertext_hash"`
	ToBatchID          string `json:"to_batch_id"`
	ToBatchVersion     uint64 `json:"to_batch_version"`
	ToCiphertextHash   string `json:"to_ciphertext_hash"`
	ToRecoveryWrapHash string `json:"to_recovery_wrap_hash"`
}

type ResourceAccountPlan struct {
	AccountID                          string             `json:"account_id"`
	SeatIDs                            []string           `json:"seat_ids"`
	AccountRef                         string             `json:"account_ref"`
	ProviderBinding                    string             `json:"provider_binding"`
	ControlEvidenceID                  string             `json:"control_evidence_id"`
	ProviderAttestationDigest          string             `json:"provider_attestation_digest"`
	ProviderAttestationIssuer          string             `json:"provider_attestation_issuer"`
	ProviderAttestationKeyID           string             `json:"provider_attestation_key_id"`
	ProviderAttestationVersion         uint64             `json:"provider_attestation_version"`
	ProviderAttestationAlgorithm       string             `json:"provider_attestation_algorithm"`
	ProviderAttestationSignature       []byte             `json:"provider_attestation_signature"`
	ProviderAttestationProtocolVersion string             `json:"provider_attestation_protocol_version"`
	Batches                            []ControlBatchPlan `json:"batches"`
}

type OwnerReplacementPlan struct {
	SeatID                  string `json:"seat_id"`
	FromMemberID            string `json:"from_member_id"`
	ToMemberID              string `json:"to_member_id"`
	ExpectedAssignmentEpoch uint64 `json:"expected_assignment_epoch"`
	FreezeOperationID       string `json:"freeze_operation_id"`
	FreezeSnapshotHash      string `json:"freeze_snapshot_hash"`
}

type ProviderAttestationIntent struct {
	Version              uint16
	CeremonyType         CeremonyType
	OperationID          string
	PoolID               string
	FromEpoch            uint64
	ToEpoch              uint64
	FromEpochStatus      string
	FromGovernanceState  string
	PreviousManifestHash [sha256.Size]byte
	Replacements         []OwnerReplacementPlan
	Seats                []SeatPlan
	Accounts             []ResourceAccountPlan
}

type ProviderAttestationVerifyRequest struct {
	Intent   ProviderAttestationIntent
	Envelope []byte
}

type VerifiedProviderAttestation struct {
	Version              uint16
	CeremonyType         CeremonyType
	Purpose              string
	OperationID          string
	PoolID               string
	FromEpoch            uint64
	ToEpoch              uint64
	FromEpochStatus      string
	FromGovernanceState  string
	PreviousManifestHash [sha256.Size]byte
	Replacements         []OwnerReplacementPlan
	Seats                []SeatPlan
	Accounts             []ResourceAccountPlan
	Issuer               string
	VerificationKeyID    string
	Reference            string
	CanonicalDigest      [sha256.Size]byte
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

type ManifestMember struct {
	MemberID                    string `json:"member_id"`
	Role                        string `json:"role"`
	ShareIndex                  uint16 `json:"share_index"`
	SigningAlgorithm            string `json:"signing_algorithm"`
	SigningKeyID                string `json:"signing_key_id"`
	SigningKeyFingerprint       string `json:"signing_key_fingerprint"`
	SigningPublicKey            []byte `json:"signing_public_key"`
	RecoveryEncryptionAlgorithm string `json:"recovery_encryption_algorithm"`
	RecoveryEncryptionKeyID     string `json:"recovery_encryption_key_id"`
	RecoveryEncryptionKeyHash   string `json:"recovery_encryption_key_fingerprint"`
	RecoveryEncryptionPublicKey []byte `json:"recovery_encryption_public_key"`
}

type ManifestRootBinding struct {
	PublicAlgorithm       string `json:"public_algorithm"`
	PublicHandle          string `json:"public_handle"`
	PublicFingerprint     string `json:"public_fingerprint"`
	WrapDomain            string `json:"wrap_domain"`
	WrapAlgorithm         string `json:"wrap_algorithm"`
	ProviderID            string `json:"provider_id"`
	KeyVersion            string `json:"key_version"`
	PrivateCommitmentHash string `json:"private_commitment_hash"`
	VSSAlgorithm          string `json:"vss_algorithm"`
	VSSCommitmentHash     string `json:"vss_commitment_hash"`
	VSSProofHash          string `json:"vss_proof_hash"`
	PackageHash           string `json:"package_hash"`
}

type ManifestEncryptedShare struct {
	MemberID           string `json:"member_id"`
	ShareIndex         uint16 `json:"share_index"`
	CiphertextHash     string `json:"ciphertext_hash"`
	ProviderProofHash  string `json:"provider_proof_hash"`
	ProviderCommitment string `json:"provider_commitment_hash"`
}

type ManifestPayload struct {
	ProtocolVersion              string                   `json:"protocol_version"`
	CeremonyType                 CeremonyType             `json:"ceremony_type"`
	OperationID                  string                   `json:"operation_id"`
	PoolID                       string                   `json:"pool_id"`
	FromEpoch                    uint64                   `json:"from_epoch"`
	FromEpochStatus              string                   `json:"from_epoch_status"`
	FromGovernanceState          string                   `json:"from_governance_state"`
	Epoch                        uint64                   `json:"epoch"`
	CreatedAt                    string                   `json:"created_at"`
	GovernanceThreshold          uint16                   `json:"governance_threshold"`
	RecoveryThreshold            uint16                   `json:"recovery_threshold"`
	RequiredShareAcknowledges    uint16                   `json:"required_share_acknowledges"`
	PreviousManifestHash         string                   `json:"previous_manifest_hash"`
	ProviderAttestationSetHash   string                   `json:"provider_attestation_set_hash"`
	CeremonyAttestationDigest    string                   `json:"ceremony_attestation_digest"`
	CeremonyAttestationPurpose   string                   `json:"ceremony_attestation_purpose"`
	CeremonyAttestationIssuer    string                   `json:"ceremony_attestation_issuer"`
	CeremonyAttestationKeyID     string                   `json:"ceremony_attestation_key_id"`
	CeremonyAttestationReference string                   `json:"ceremony_attestation_reference"`
	CeremonyAttestationVersion   uint64                   `json:"ceremony_attestation_version"`
	Members                      []ManifestMember         `json:"members"`
	Seats                        []SeatPlan               `json:"seats"`
	Replacements                 []OwnerReplacementPlan   `json:"replacements"`
	Accounts                     []ResourceAccountPlan    `json:"accounts"`
	EncryptedShares              []ManifestEncryptedShare `json:"encrypted_shares"`
	RecoveryRoot                 ManifestRootBinding      `json:"recovery_root"`
}

type CanonicalManifest struct {
	Payload ManifestPayload
	Bytes   []byte
	Hash    [sha256.Size]byte
}

type PlatformManifestSignRequest struct {
	SignatureDomain string
	CeremonyType    CeremonyType
	OperationID     string
	PoolID          string
	Epoch           uint64
	ManifestHash    [sha256.Size]byte
	Canonical       []byte
}

type PlatformManifestSignature struct {
	SignatureDomain string
	CeremonyType    CeremonyType
	OperationID     string
	PoolID          string
	Epoch           uint64
	ManifestHash    [sha256.Size]byte
	Algorithm       string
	KeyID           string
	Signature       []byte
	SignedAt        time.Time
}

type PlatformManifestVerifyRequest struct {
	Request   PlatformManifestSignRequest
	Signature PlatformManifestSignature
}

type MemberManifestApproval struct {
	Version      uint16
	CeremonyType CeremonyType
	OperationID  string
	PoolID       string
	Epoch        uint64
	MemberID     string
	ManifestHash [sha256.Size]byte
}

type ShareAcknowledgement struct {
	Version            uint16
	CeremonyType       CeremonyType
	OperationID        string
	DeliveryID         string
	PoolID             string
	Epoch              uint64
	MemberID           string
	ShareIndex         uint16
	CiphertextHash     [sha256.Size]byte
	ManifestHash       [sha256.Size]byte
	RootCommitmentHash [sha256.Size]byte
	VSSCommitmentHash  [sha256.Size]byte
	VerifiedCommitment bool
}

type MemberSignatureVerifyRequest struct {
	MemberID  string
	Algorithm string
	KeyID     string
	PublicKey []byte
	Message   []byte
	Signature []byte
}

type MemberKeyProofIntent struct {
	Version        uint16
	CeremonyType   CeremonyType
	OperationID    string
	PoolID         string
	Epoch          uint64
	MemberID       string
	Purpose        string
	Algorithm      string
	KeyID          string
	KeyFingerprint [sha256.Size]byte
}

type MemberKeyProofVerifyRequest struct {
	MemberID  string
	Purpose   string
	Algorithm string
	KeyID     string
	PublicKey []byte
	Message   []byte
	Proof     []byte
}

func isNilProvider(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
