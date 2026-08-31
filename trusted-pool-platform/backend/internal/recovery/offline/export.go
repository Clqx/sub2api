package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

// BuiltPublicEvidenceBundle contains the portable bytes and the two digests used
// by the persistent export ledger. InventoryDigest excludes export identity and
// time, while BundleDigest covers the exact bytes delivered to the verifier.
type BuiltPublicEvidenceBundle struct {
	CanonicalBytes  []byte
	InventoryDigest [sha256.Size]byte
	BundleDigest    [sha256.Size]byte
}

// BuildPublicEvidenceBundle maps the Store's deliberately public projection to
// one canonical portable Bundle. Signing and online publication remain separate
// fail-closed responsibilities.
func BuildPublicEvidenceBundle(snapshot recovery.PublicEvidenceSnapshot,
	exportedAt time.Time) (*BuiltPublicEvidenceBundle, error) {
	if snapshot.Export == nil || !validID(snapshot.Export.ExternalID) || exportedAt.IsZero() ||
		snapshot.ProtocolVersion != BundleProtocolVersion || len(snapshot.CanonicalManifest) == 0 {
		return nil, fail(ReasonSchemaInvalid)
	}
	manifestHash := encodeHash(snapshot.ManifestHash)
	if !validHash(manifestHash) {
		return nil, fail(ReasonManifestHashMismatch)
	}

	evidence := ManifestEvidence{
		CanonicalManifest: append([]byte(nil), snapshot.CanonicalManifest...),
		ManifestHash:      manifestHash,
		PlatformSignature: SignatureEvidence{
			Domain: snapshot.PlatformSignature.Domain, Algorithm: snapshot.PlatformSignature.Algorithm,
			KeyID:     snapshot.PlatformSignature.KeyID,
			Signature: append([]byte(nil), snapshot.PlatformSignature.Signature...),
		},
		MemberApprovals:       make([]MemberApprovalEvidence, len(snapshot.MemberApprovals)),
		ShareAcknowledgements: make([]ShareAcknowledgementEvidence, len(snapshot.ShareAcknowledgements)),
		ProviderProofs:        make([]ProviderProofEvidence, len(snapshot.ProviderProofs)),
	}
	for index, approval := range snapshot.MemberApprovals {
		evidence.MemberApprovals[index] = MemberApprovalEvidence{MemberID: approval.MemberID,
			Algorithm: approval.Algorithm, KeyID: approval.KeyID,
			Signature: append([]byte(nil), approval.Signature...)}
	}
	for index, acknowledgement := range snapshot.ShareAcknowledgements {
		evidence.ShareAcknowledgements[index] = ShareAcknowledgementEvidence{
			DeliveryID: acknowledgement.DeliveryID, MemberID: acknowledgement.MemberID,
			ShareIndex: acknowledgement.ShareIndex, CiphertextHash: encodeHash(acknowledgement.CiphertextHash),
			RootCommitmentHash: encodeHash(acknowledgement.RootCommitment),
			VSSCommitmentHash:  encodeHash(acknowledgement.VSSCommitment),
			VerifiedCommitment: acknowledgement.VerifiedCommitment, Algorithm: acknowledgement.Algorithm,
			KeyID: acknowledgement.KeyID, Signature: append([]byte(nil), acknowledgement.Signature...),
		}
	}
	for index, proof := range snapshot.ProviderProofs {
		evidence.ProviderProofs[index] = ProviderProofEvidence{Statement: ProviderStatement{
			ProtocolVersion: proof.Statement.ProtocolVersion, Kind: ProviderProofKind(proof.Statement.Kind),
			ProviderID: proof.Statement.ProviderID, OperationID: proof.Statement.OperationID,
			PoolID: proof.Statement.PoolID, Epoch: proof.Statement.Epoch, MemberID: proof.Statement.MemberID,
			AccountRef: proof.Statement.AccountRef, ShareIndex: proof.Statement.ShareIndex,
			SubjectHash: hex.EncodeToString(proof.Statement.SubjectHash[:]),
		}, Algorithm: proof.Algorithm, KeyID: proof.KeyID, Signature: append([]byte(nil), proof.Signature...)}
	}
	sort.Slice(evidence.MemberApprovals, func(i, j int) bool {
		return evidence.MemberApprovals[i].MemberID < evidence.MemberApprovals[j].MemberID
	})
	sort.Slice(evidence.ShareAcknowledgements, func(i, j int) bool {
		left, right := evidence.ShareAcknowledgements[i], evidence.ShareAcknowledgements[j]
		if left.ShareIndex != right.ShareIndex {
			return left.ShareIndex < right.ShareIndex
		}
		if left.MemberID != right.MemberID {
			return left.MemberID < right.MemberID
		}
		return left.DeliveryID < right.DeliveryID
	})
	sort.Slice(evidence.ProviderProofs, func(i, j int) bool {
		left, right := evidence.ProviderProofs[i], evidence.ProviderProofs[j]
		if left.Statement.Kind != right.Statement.Kind {
			return left.Statement.Kind < right.Statement.Kind
		}
		if left.Statement.AccountRef != right.Statement.AccountRef {
			return left.Statement.AccountRef < right.Statement.AccountRef
		}
		if left.Statement.MemberID != right.Statement.MemberID {
			return left.Statement.MemberID < right.Statement.MemberID
		}
		if left.Statement.ProviderID != right.Statement.ProviderID {
			return left.Statement.ProviderID < right.Statement.ProviderID
		}
		return left.KeyID < right.KeyID
	})

	inventoryBytes, err := marshalCanonical(struct {
		ProtocolVersion string             `json:"protocol_version"`
		Manifests       []ManifestEvidence `json:"manifests"`
	}{ProtocolVersion: BundleProtocolVersion, Manifests: []ManifestEvidence{evidence}})
	if err != nil {
		return nil, err
	}
	bundleBytes, err := MarshalCanonicalBundle(Bundle{ProtocolVersion: BundleProtocolVersion,
		BundleID:   snapshot.Export.ExternalID,
		ExportedAt: exportedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		Manifests:  []ManifestEvidence{evidence}})
	if err != nil {
		return nil, err
	}
	return &BuiltPublicEvidenceBundle{CanonicalBytes: bundleBytes,
		InventoryDigest: sha256.Sum256(inventoryBytes), BundleDigest: sha256.Sum256(bundleBytes)}, nil
}
