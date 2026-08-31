package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const (
	PortableBundleFormatV1      = "trusted-pool/offline-evidence-bundle/v1"
	ProviderProofStatementV1    = "trusted-pool/provider-proof-statement/v1"
	PlatformManifestSignatureV2 = "trusted-pool/platform-manifest-signature/v2"
	PortableSignatureAlgorithm  = "Ed25519"

	VerificationCapabilityLegacyExportLimited = "LEGACY_EXPORT_LIMITED"
	VerificationCapabilityRevealCapable       = "REVEAL_CAPABLE"

	VerificationExportPending           = "PENDING"
	VerificationExportAvailable         = "AVAILABLE"
	VerificationExportReconcileRequired = "RECONCILE_REQUIRED"
	VerificationExportFailed            = "FAILED"

	RevealPendingApproval       = "PENDING_APPROVAL"
	RevealAuthorized            = "AUTHORIZED"
	RevealAuthorizationExported = "AUTHORIZATION_EXPORTED"
	RevealCompleted             = "COMPLETED"
	RevealCancelled             = "CANCELLED"
	RevealExpired               = "EXPIRED"
	RevealAborted               = "ABORTED"
	RevealOperatorReview        = "OPERATOR_REVIEW_REQUIRED"
)

type PortableEvidenceProfile struct {
	FormatVersion                string `json:"format_version"`
	RootTrustProfileID           string `json:"root_trust_profile_id"`
	CryptoSuiteID                string `json:"crypto_suite_id"`
	ProviderProofProfile         string `json:"provider_proof_profile"`
	CeremonyAttestationAlgorithm string `json:"ceremony_attestation_algorithm"`
	PlatformSignatureDomain      string `json:"platform_signature_domain"`
}

const MaxRevealAuthorizationTTL = 24 * time.Hour

var ErrRevealExecutionUnavailable = errors.New("online recovery Reveal execution is unavailable")

const (
	EvidenceRequestSnapshotVersion      = 1
	VerificationExportSignatureDomainV1 = "trusted-pool/verification-export-signature/v1"
)

// MemberArtifactReceipt 只保存成员侧分发的非秘密回执；不保存 Share 明文或成员私钥材料。
type MemberArtifactReceipt struct {
	PlanExternalID               string
	DeliveryExternalID           string
	ManifestExternalID           string
	MemberExternalID             string
	ArtifactDigest               [sha256.Size]byte
	ReceiptID                    string
	ReceiptDigest                [sha256.Size]byte
	ProviderProof                []byte
	ProviderProofDigest          [sha256.Size]byte
	ProviderProofAlgorithm       string
	ProviderProofKeyID           string
	ProviderProofProtocolVersion string
	PublishedAt                  time.Time
}

type CommitMemberArtifactReceiptInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
	Receipt      MemberArtifactReceipt
}

type BeginVerificationExportInput struct {
	Key              OperationKey
	ExportExternalID string
	PlanExternalID   string
	FormatVersion    string
	RequestHash      [sha256.Size]byte
	RequestSnapshot  []byte
	LeaseOwner       string
	LeaseDuration    time.Duration
}

type StoredVerificationExport struct {
	OperationKey         OperationKey
	ID                   string
	ExternalID           string
	PlanExternalID       string
	ManifestExternalID   string
	PoolExternalID       string
	MembershipEpoch      uint64
	FormatVersion        string
	Capability           string
	Status               string
	InventoryDigest      [sha256.Size]byte
	BundleDigest         [sha256.Size]byte
	SignerDomain         string
	SignerAlgorithm      string
	SignerKeyID          string
	Signature            []byte
	GeneratedAt          *time.Time
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
	MissingEvidenceCodes []string
}

type VerificationExportTarget struct {
	Operation *StoredOperation
	Export    *StoredVerificationExport
}

type LoadPublicEvidenceSnapshotInput struct {
	Key          OperationKey
	LeaseOwner   string
	FencingToken int64
	ExportID     string
}

type RenewVerificationExportLeaseInput struct {
	Key                  OperationKey
	LeaseOwner           string
	ExpectedFencingToken int64
	LeaseDuration        time.Duration
	ExportExternalID     string
}

type PublicPlatformSignature struct {
	Domain    string
	Algorithm string
	KeyID     string
	Signature []byte
}

type PublicMemberApproval struct {
	MemberID  string
	Algorithm string
	KeyID     string
	Signature []byte
}

type PublicShareAcknowledgement struct {
	DeliveryID         string
	MemberID           string
	ShareIndex         uint16
	CiphertextHash     [sha256.Size]byte
	RootCommitment     [sha256.Size]byte
	VSSCommitment      [sha256.Size]byte
	VerifiedCommitment bool
	Algorithm          string
	KeyID              string
	Signature          []byte
}

type PublicProviderProofStatement struct {
	ProtocolVersion string
	Kind            string
	ProviderID      string
	OperationID     string
	PoolID          string
	Epoch           uint64
	MemberID        string
	AccountRef      string
	ShareIndex      uint16
	SubjectHash     [sha256.Size]byte
}

type PublicProviderProof struct {
	Statement PublicProviderProofStatement
	Algorithm string
	KeyID     string
	Signature []byte
}

// PublicEvidenceSnapshot 是单 JSON bundle 的数据库投影，刻意不包含 Share ciphertext、批次密文、
// wrapped DEK、Root/Share 明文或任何 credential。
type PublicEvidenceSnapshot struct {
	Export                *StoredVerificationExport
	ProtocolVersion       string
	CanonicalManifest     []byte
	ManifestHash          [sha256.Size]byte
	PlatformSignature     PublicPlatformSignature
	MemberApprovals       []PublicMemberApproval
	ShareAcknowledgements []PublicShareAcknowledgement
	ProviderProofs        []PublicProviderProof
	MissingEvidenceCodes  []string
}

type CommitVerificationExportInput struct {
	Key              OperationKey
	LeaseOwner       string
	FencingToken     int64
	ExportExternalID string
	InventoryDigest  [sha256.Size]byte
	BundleDigest     [sha256.Size]byte
	SignerDomain     string
	SignerAlgorithm  string
	SignerKeyID      string
	Signature        []byte
	GeneratedAt      time.Time
}

type RevealApprovalIntent struct {
	MemberExternalID    string
	ExpectedMessageHash [sha256.Size]byte
}

type BeginRevealAuthorizationInput struct {
	Key              OperationKey
	RevealExternalID string
	PlanExternalID   string
	ExportExternalID string
	Purpose          string
	ScopeHash        [sha256.Size]byte
	ChallengeHash    [sha256.Size]byte
	ExpiresAt        time.Time
	ApprovalIntents  []RevealApprovalIntent
	RequestHash      [sha256.Size]byte
	RequestSnapshot  []byte
	LeaseOwner       string
	LeaseDuration    time.Duration
}

type RevealApproval struct {
	MemberExternalID string
	Algorithm        string
	KeyID            string
	MessageHash      [sha256.Size]byte
	Signature        []byte
	VerifiedAt       time.Time
}

type CommitRevealApprovalsInput struct {
	Key              OperationKey
	LeaseOwner       string
	FencingToken     int64
	RevealExternalID string
	Approvals        []RevealApproval
}

type ExportRevealAuthorizationInput struct {
	Key                 OperationKey
	LeaseOwner          string
	FencingToken        int64
	RevealExternalID    string
	AuthorizationDigest [sha256.Size]byte
	SignerDomain        string
	SignerAlgorithm     string
	SignerKeyID         string
	Signature           []byte
	ExportedAt          time.Time
}

type CommitRevealExecutorReceiptInput struct {
	Key                   OperationKey
	LeaseOwner            string
	FencingToken          int64
	RevealExternalID      string
	Disposition           string
	ReceiptDigest         [sha256.Size]byte
	TranscriptDigest      [sha256.Size]byte
	SinkAttestationDigest [sha256.Size]byte
	ExecutorProfile       string
	ExecutorAlgorithm     string
	ExecutorKeyID         string
	ExecutorSignature     []byte
	CompletedAt           time.Time
}

type StoredRevealAuthorization struct {
	ID                           string
	ExternalID                   string
	PlanExternalID               string
	ExportExternalID             string
	ManifestExternalID           string
	PoolExternalID               string
	MembershipEpoch              uint64
	Purpose                      string
	ScopeHash                    [sha256.Size]byte
	ChallengeHash                [sha256.Size]byte
	GovernanceThreshold          uint16
	RecoveryThreshold            uint16
	ApprovalCount                int
	Status                       string
	AuthorizationDigest          [sha256.Size]byte
	AuthorizationSignerDomain    string
	AuthorizationSignerAlgorithm string
	AuthorizationSignerKeyID     string
	AuthorizationSignature       []byte
	ExpiresAt                    time.Time
	AuthorizedAt                 *time.Time
	AuthorizationExportedAt      *time.Time
	CompletedAt                  *time.Time
	Version                      int64
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
}

type RevealAuthorizationTarget struct {
	Operation *StoredOperation
	Reveal    *StoredRevealAuthorization
}

// EvidenceStore 的类型表面没有任何 Root/Share/DEK/credential 明文参数。
type EvidenceStore interface {
	CommitMemberArtifactReceipt(context.Context, CommitMemberArtifactReceiptInput) error
	BeginVerificationExport(context.Context, BeginVerificationExportInput) (*VerificationExportTarget, bool, error)
	LoadPublicEvidenceSnapshot(context.Context, LoadPublicEvidenceSnapshotInput) (*PublicEvidenceSnapshot, error)
	RenewVerificationExportLease(context.Context, RenewVerificationExportLeaseInput) (*StoredOperation, error)
	CommitVerificationExport(context.Context, CommitVerificationExportInput) (*StoredVerificationExport, bool, error)
	GetVerificationExport(context.Context, string) (*StoredVerificationExport, error)
	BeginRevealAuthorization(context.Context, BeginRevealAuthorizationInput) (*RevealAuthorizationTarget, bool, error)
	CommitRevealApprovals(context.Context, CommitRevealApprovalsInput) (*StoredRevealAuthorization, error)
	ExportRevealAuthorization(context.Context, ExportRevealAuthorizationInput) (*StoredRevealAuthorization, error)
	CommitRevealExecutorReceipt(context.Context, CommitRevealExecutorReceiptInput) (*StoredRevealAuthorization, error)
	GetRevealAuthorization(context.Context, string) (*StoredRevealAuthorization, error)
}

type revealApprovalIntentSnapshot struct {
	MemberID    string `json:"member_id"`
	MessageHash string `json:"message_hash"`
}

// BuildVerificationExportRequestSnapshot returns the only accepted immutable export intent encoding.
func BuildVerificationExportRequestSnapshot(input BeginVerificationExportInput) ([]byte, [sha256.Size]byte, error) {
	value := map[string]any{
		"version": EvidenceRequestSnapshotVersion, "operation_id": input.Key.OperationID,
		"export_id": input.ExportExternalID, "plan_id": input.PlanExternalID,
		"format_version": input.FormatVersion,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return encoded, sha256.Sum256(encoded), nil
}

// BuildRevealAuthorizationRequestSnapshot sorts member intents and normalizes time to PostgreSQL precision.
func BuildRevealAuthorizationRequestSnapshot(input BeginRevealAuthorizationInput) ([]byte, [sha256.Size]byte, error) {
	intents := make([]revealApprovalIntentSnapshot, len(input.ApprovalIntents))
	for index, intent := range input.ApprovalIntents {
		intents[index] = revealApprovalIntentSnapshot{
			MemberID: intent.MemberExternalID, MessageHash: hex.EncodeToString(intent.ExpectedMessageHash[:]),
		}
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].MemberID < intents[j].MemberID })
	value := map[string]any{
		"version": EvidenceRequestSnapshotVersion, "operation_id": input.Key.OperationID,
		"reveal_id": input.RevealExternalID, "export_id": input.ExportExternalID,
		"plan_id": input.PlanExternalID, "purpose": input.Purpose,
		"scope_hash":       hex.EncodeToString(input.ScopeHash[:]),
		"challenge_hash":   hex.EncodeToString(input.ChallengeHash[:]),
		"expires_at":       input.ExpiresAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		"approval_intents": intents,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return encoded, sha256.Sum256(encoded), nil
}
