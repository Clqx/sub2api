// Package offline verifies public recovery-governance evidence without network,
// database, Share decryption, secret reconstruction, or credential decryption.
package offline

import "trusted-pool-platform/backend/internal/recovery"

const (
	BundleProtocolVersion      = recovery.PortableBundleFormatV1
	TrustPolicyProtocolVersion = "trusted-pool/offline-trust-policy/v1"
	ProviderStatementVersion   = recovery.ProviderProofStatementV1
	PlatformSignatureDomainV2  = recovery.PlatformManifestSignatureV2
	ProviderSignatureDomainV1  = "trusted-pool/provider-proof-signature/v1"
	RevealIntentVersion        = "trusted-pool/reveal-intent/v1"
	RevealApprovalsVersion     = "trusted-pool/reveal-approvals/v1"
	RevealApprovalDomainV1     = "trusted-pool/reveal-approval-signature/v1"
	VerificationExportDomainV1 = "trusted-pool/verification-export-signature/v1"
	ReportProtocolVersion      = "trusted-pool/offline-verification-report/v1"
	RevealReportVersion        = "trusted-pool/reveal-authorization-report/v1"

	SignatureAlgorithmEd25519 = recovery.PortableSignatureAlgorithm
)

type Verdict string

const (
	VerdictVerified   Verdict = "VERIFIED"
	VerdictIncomplete Verdict = "INCOMPLETE"
	VerdictRejected   Verdict = "REJECTED"
)

type ReasonCode string

const (
	ReasonOK                          ReasonCode = "OK"
	ReasonInputTooLarge               ReasonCode = "INPUT_TOO_LARGE"
	ReasonInvalidUTF8                 ReasonCode = "INVALID_UTF8"
	ReasonInvalidJSON                 ReasonCode = "INVALID_JSON"
	ReasonNonCanonicalJSON            ReasonCode = "NON_CANONICAL_JSON"
	ReasonSchemaInvalid               ReasonCode = "SCHEMA_INVALID"
	ReasonProtocolUnsupported         ReasonCode = "PROTOCOL_UNSUPPORTED"
	ReasonAlgorithmUnsupported        ReasonCode = "ALGORITHM_UNSUPPORTED"
	ReasonLegacySignatureUnsupported  ReasonCode = "LEGACY_UNSUPPORTED"
	ReasonTrustPolicyInvalid          ReasonCode = "TRUST_POLICY_INVALID"
	ReasonCheckpointMismatch          ReasonCode = "CHECKPOINT_MISMATCH"
	ReasonManifestChainInvalid        ReasonCode = "MANIFEST_CHAIN_INVALID"
	ReasonManifestHashMismatch        ReasonCode = "MANIFEST_HASH_MISMATCH"
	ReasonManifestInvalid             ReasonCode = "MANIFEST_INVALID"
	ReasonThresholdInvalid            ReasonCode = "THRESHOLD_INVALID"
	ReasonSetMismatch                 ReasonCode = "SET_MISMATCH"
	ReasonUntrustedKey                ReasonCode = "UNTRUSTED_KEY"
	ReasonSignatureInvalid            ReasonCode = "SIGNATURE_INVALID"
	ReasonMemberApprovalsIncomplete   ReasonCode = "MEMBER_APPROVALS_INCOMPLETE"
	ReasonShareAcknowledgesIncomplete ReasonCode = "SHARE_ACKNOWLEDGEMENTS_INCOMPLETE"
	ReasonProviderEvidenceIncomplete  ReasonCode = "PROVIDER_EVIDENCE_INCOMPLETE"
	ReasonProviderEvidenceInvalid     ReasonCode = "PROVIDER_EVIDENCE_INVALID"
	ReasonRevealIntentInvalid         ReasonCode = "REVEAL_INTENT_INVALID"
	ReasonRevealApprovalsIncomplete   ReasonCode = "REVEAL_APPROVALS_INCOMPLETE"
	ReasonRevealPolicyUnapproved      ReasonCode = "REVEAL_POLICY_UNAPPROVED"
	ReasonRevealAuthorizedNoExecutor  ReasonCode = "REVEAL_AUTHORIZED_NOT_EXECUTABLE"
	ReasonCLIUsageInvalid             ReasonCode = "CLI_USAGE_INVALID"
	ReasonIOFailure                   ReasonCode = "IO_FAILURE"
)

type Limits struct {
	MaxBundleBytes    int64
	MaxPolicyBytes    int64
	MaxIntentBytes    int64
	MaxApprovalsBytes int64
	MaxManifestBytes  int
	MaxManifests      int
	MaxMembers        int
	MaxEvidenceBytes  int
}

func DefaultLimits() Limits {
	return Limits{
		MaxBundleBytes: 32 << 20, MaxPolicyBytes: 1 << 20, MaxIntentBytes: 1 << 20,
		MaxApprovalsBytes: 1 << 20, MaxManifestBytes: 4 << 20, MaxManifests: 1024,
		MaxMembers: 4096, MaxEvidenceBytes: 1 << 20,
	}
}

type Bundle struct {
	ProtocolVersion string             `json:"protocol_version"`
	BundleID        string             `json:"bundle_id"`
	ExportedAt      string             `json:"exported_at"`
	Manifests       []ManifestEvidence `json:"manifests"`
}

type ManifestEvidence struct {
	CanonicalManifest     []byte                         `json:"canonical_manifest"`
	ManifestHash          string                         `json:"manifest_hash"`
	PlatformSignature     SignatureEvidence              `json:"platform_signature"`
	MemberApprovals       []MemberApprovalEvidence       `json:"member_approvals"`
	ShareAcknowledgements []ShareAcknowledgementEvidence `json:"share_acknowledgements"`
	ProviderProofs        []ProviderProofEvidence        `json:"provider_proofs"`
}

type SignatureEvidence struct {
	Domain    string `json:"domain"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

type MemberApprovalEvidence struct {
	MemberID  string `json:"member_id"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

type ShareAcknowledgementEvidence struct {
	DeliveryID         string `json:"delivery_id"`
	MemberID           string `json:"member_id"`
	ShareIndex         uint16 `json:"share_index"`
	CiphertextHash     string `json:"ciphertext_hash"`
	RootCommitmentHash string `json:"root_commitment_hash"`
	VSSCommitmentHash  string `json:"vss_commitment_hash"`
	VerifiedCommitment bool   `json:"verified_commitment"`
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	Signature          []byte `json:"signature"`
}

type ProviderProofKind string

const (
	ProviderProofCeremony ProviderProofKind = "CEREMONY_ATTESTATION"
	ProviderProofAccount  ProviderProofKind = "ACCOUNT_ATTESTATION"
	ProviderProofPackage  ProviderProofKind = "RECOVERY_PACKAGE"
	ProviderProofShare    ProviderProofKind = "SHARE_PROOF"
)

type ProviderStatement struct {
	ProtocolVersion string            `json:"protocol_version"`
	Kind            ProviderProofKind `json:"kind"`
	ProviderID      string            `json:"provider_id"`
	OperationID     string            `json:"operation_id"`
	PoolID          string            `json:"pool_id"`
	Epoch           uint64            `json:"epoch"`
	MemberID        string            `json:"member_id,omitempty"`
	AccountRef      string            `json:"account_ref,omitempty"`
	ShareIndex      uint16            `json:"share_index,omitempty"`
	SubjectHash     string            `json:"subject_hash"`
}

type ProviderProofEvidence struct {
	Statement ProviderStatement `json:"statement"`
	Algorithm string            `json:"algorithm"`
	KeyID     string            `json:"key_id"`
	Signature []byte            `json:"signature"`
}

type VerificationExportStatement struct {
	ProtocolVersion string `json:"protocol_version"`
	ExportID        string `json:"export_id"`
	FormatVersion   string `json:"format_version"`
	InventoryDigest string `json:"inventory_digest"`
	BundleDigest    string `json:"bundle_digest"`
	GeneratedAt     string `json:"generated_at"`
}

type TrustPolicy struct {
	ProtocolVersion   string                      `json:"protocol_version"`
	PolicyID          string                      `json:"policy_id"`
	Checkpoint        ManifestCheckpoint          `json:"checkpoint"`
	PlatformKeys      []TrustedEd25519Key         `json:"platform_keys"`
	ProviderKeys      []TrustedProviderEd25519Key `json:"provider_keys"`
	RevealPolicyState RevealPolicyState           `json:"reveal_policy_state"`
}

type ManifestCheckpoint struct {
	PoolID       string `json:"pool_id"`
	Epoch        uint64 `json:"epoch"`
	ManifestHash string `json:"manifest_hash"`
}

type TrustedEd25519Key struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"`
}

type TrustedProviderEd25519Key struct {
	ProviderID        string              `json:"provider_id"`
	KeyID             string              `json:"key_id"`
	AllowedProofKinds []ProviderProofKind `json:"allowed_proof_kinds"`
	PublicKey         []byte              `json:"public_key"`
}

type RevealPolicyState string

const (
	RevealPolicyUnapproved RevealPolicyState = "UNAPPROVED"
	RevealPolicyApproved   RevealPolicyState = "APPROVED"
)

type Report struct {
	ProtocolVersion string     `json:"protocol_version"`
	Verdict         Verdict    `json:"verdict"`
	ReasonCode      ReasonCode `json:"reason_code"`
	BundleHash      string     `json:"bundle_hash,omitempty"`
	PoolID          string     `json:"pool_id,omitempty"`
	FirstEpoch      uint64     `json:"first_epoch,omitempty"`
	LastEpoch       uint64     `json:"last_epoch,omitempty"`
	ManifestCount   int        `json:"manifest_count"`
}

type RevealIntent struct {
	ProtocolVersion     string        `json:"protocol_version"`
	RevealID            string        `json:"reveal_id"`
	Nonce               string        `json:"nonce"`
	BundleHash          string        `json:"bundle_hash"`
	ManifestHash        string        `json:"manifest_hash"`
	PolicyHash          string        `json:"policy_hash"`
	PoolID              string        `json:"pool_id"`
	Epoch               uint64        `json:"epoch"`
	Purpose             string        `json:"purpose"`
	CaseReference       string        `json:"case_reference"`
	OutputPolicy        string        `json:"output_policy"`
	EvidenceReferences  []string      `json:"evidence_references"`
	CreatedAt           string        `json:"created_at"`
	NotBefore           string        `json:"not_before"`
	ExpiresAt           string        `json:"expires_at"`
	GovernanceThreshold uint16        `json:"governance_threshold"`
	Batches             []RevealBatch `json:"batches"`
}

type RevealBatch struct {
	BatchID          string `json:"batch_id"`
	AccountRef       string `json:"account_ref"`
	BatchType        string `json:"batch_type"`
	BatchVersion     uint64 `json:"batch_version"`
	CiphertextHash   string `json:"ciphertext_hash"`
	RecoveryWrapHash string `json:"recovery_wrap_hash"`
}

type RevealApproval struct {
	MemberID  string `json:"member_id"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

type RevealApprovalsDocument struct {
	ProtocolVersion string           `json:"protocol_version"`
	Approvals       []RevealApproval `json:"approvals"`
}

type RevealVerdict string

const (
	RevealVerdictRejected                RevealVerdict = "REJECTED"
	RevealVerdictPolicyUnapproved        RevealVerdict = "POLICY_UNAPPROVED"
	RevealVerdictAuthorizedNotExecutable RevealVerdict = "AUTHORIZED_NOT_EXECUTABLE"
)

type RevealReport struct {
	ProtocolVersion string        `json:"protocol_version"`
	Verdict         RevealVerdict `json:"verdict"`
	ReasonCode      ReasonCode    `json:"reason_code"`
	EvaluationTime  string        `json:"evaluation_time"`
	RevealID        string        `json:"reveal_id,omitempty"`
	PoolID          string        `json:"pool_id,omitempty"`
	Epoch           uint64        `json:"epoch,omitempty"`
	ApprovalCount   int           `json:"approval_count"`
}

type VerifiedBundle struct {
	BundleHash   string
	PolicyHash   string
	PoolID       string
	LastEpoch    uint64
	LastHash     string
	LastManifest []byte
}
