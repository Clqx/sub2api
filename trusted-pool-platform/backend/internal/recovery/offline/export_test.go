package offline

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

func TestBuildPublicEvidenceBundleIsCanonicalStableAndPublic(t *testing.T) {
	hash := func(value byte) [sha256.Size]byte {
		var result [sha256.Size]byte
		result[0] = value
		return result
	}
	snapshot := recovery.PublicEvidenceSnapshot{
		Export:            &recovery.StoredVerificationExport{ExternalID: "export-1"},
		ProtocolVersion:   BundleProtocolVersion,
		CanonicalManifest: []byte(`{"protocol_version":"trusted-pool/recovery-governance/v1"}`),
		ManifestHash:      hash(1),
		PlatformSignature: recovery.PublicPlatformSignature{Domain: PlatformSignatureDomainV2,
			Algorithm: SignatureAlgorithmEd25519, KeyID: "platform-key", Signature: []byte{1}},
		MemberApprovals: []recovery.PublicMemberApproval{
			{MemberID: "member-b", Algorithm: SignatureAlgorithmEd25519, KeyID: "b", Signature: []byte{2}},
			{MemberID: "member-a", Algorithm: SignatureAlgorithmEd25519, KeyID: "a", Signature: []byte{3}},
		},
		ShareAcknowledgements: []recovery.PublicShareAcknowledgement{
			{DeliveryID: "delivery-b", MemberID: "member-b", ShareIndex: 2, CiphertextHash: hash(2),
				RootCommitment: hash(3), VSSCommitment: hash(4), VerifiedCommitment: true,
				Algorithm: SignatureAlgorithmEd25519, KeyID: "b", Signature: []byte{4}},
			{DeliveryID: "delivery-a", MemberID: "member-a", ShareIndex: 1, CiphertextHash: hash(5),
				RootCommitment: hash(3), VSSCommitment: hash(4), VerifiedCommitment: true,
				Algorithm: SignatureAlgorithmEd25519, KeyID: "a", Signature: []byte{5}},
		},
		ProviderProofs: []recovery.PublicProviderProof{
			{Statement: recovery.PublicProviderProofStatement{ProtocolVersion: ProviderStatementVersion,
				Kind: string(ProviderProofShare), ProviderID: "provider", OperationID: "operation",
				PoolID: "pool", Epoch: 2, MemberID: "member-b", ShareIndex: 2, SubjectHash: hash(6)},
				Algorithm: SignatureAlgorithmEd25519, KeyID: "provider-key", Signature: []byte{6}},
			{Statement: recovery.PublicProviderProofStatement{ProtocolVersion: ProviderStatementVersion,
				Kind: string(ProviderProofCeremony), ProviderID: "provider", OperationID: "operation",
				PoolID: "pool", Epoch: 2, SubjectHash: hash(7)}, Algorithm: SignatureAlgorithmEd25519,
				KeyID: "provider-key", Signature: []byte{7}},
		},
	}
	exportedAt := time.Date(2026, 8, 21, 1, 2, 3, 123456789, time.FixedZone("offset", 8*60*60))
	first, err := BuildPublicEvidenceBundle(snapshot, exportedAt)
	if err != nil {
		t.Fatalf("build public bundle: %v", err)
	}
	snapshot.MemberApprovals[0], snapshot.MemberApprovals[1] = snapshot.MemberApprovals[1], snapshot.MemberApprovals[0]
	snapshot.ProviderProofs[0], snapshot.ProviderProofs[1] = snapshot.ProviderProofs[1], snapshot.ProviderProofs[0]
	second, err := BuildPublicEvidenceBundle(snapshot, exportedAt)
	if err != nil {
		t.Fatalf("rebuild public bundle: %v", err)
	}
	if string(first.CanonicalBytes) != string(second.CanonicalBytes) ||
		first.InventoryDigest != second.InventoryDigest || first.BundleDigest != second.BundleDigest {
		t.Fatal("public bundle changed when source collection order changed")
	}
	parsed, err := ParseBundle(first.CanonicalBytes, DefaultLimits())
	if err != nil {
		t.Fatalf("parse generated bundle: %v", err)
	}
	if parsed.ExportedAt != "2026-08-20T17:02:03.123456Z" || parsed.Manifests[0].MemberApprovals[0].MemberID != "member-a" ||
		parsed.Manifests[0].ProviderProofs[0].Statement.Kind != ProviderProofCeremony {
		t.Fatalf("generated bundle is not normalized: %+v", parsed)
	}
	if got := sha256.Sum256(first.CanonicalBytes); got != first.BundleDigest {
		t.Fatal("bundle digest does not cover exact canonical bytes")
	}
}

func TestBuildVerificationExportSignatureMessageIsDomainSeparatedAndStable(t *testing.T) {
	statement := VerificationExportStatement{ProtocolVersion: BundleProtocolVersion, ExportID: "export-1",
		FormatVersion: BundleProtocolVersion, InventoryDigest: strings.Repeat("01", sha256.Size),
		BundleDigest: strings.Repeat("02", sha256.Size), GeneratedAt: "2026-08-20T17:02:03.123456Z"}
	first, err := BuildVerificationExportSignatureMessage(statement)
	if err != nil {
		t.Fatalf("build export signature message: %v", err)
	}
	second, err := BuildVerificationExportSignatureMessage(statement)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("export signature message is not stable: %v", err)
	}
	prefix := append([]byte(VerificationExportDomainV1), 0)
	if !bytes.HasPrefix(first, prefix) {
		t.Fatalf("message is not domain separated: %q", first)
	}
	statement.BundleDigest = strings.Repeat("03", sha256.Size)
	changed, err := BuildVerificationExportSignatureMessage(statement)
	if err != nil || bytes.Equal(first, changed) {
		t.Fatal("bundle digest drift did not change signature transcript")
	}
	statement.GeneratedAt = "2026-08-20 17:02:03Z"
	if _, err := BuildVerificationExportSignatureMessage(statement); err == nil {
		t.Fatal("non-canonical generated_at was accepted")
	}
}

func TestBuildPublicEvidenceBundleRejectsIncompleteIdentity(t *testing.T) {
	_, err := BuildPublicEvidenceBundle(recovery.PublicEvidenceSnapshot{}, time.Now())
	if reasonOf(err, ReasonSchemaInvalid) != ReasonSchemaInvalid {
		t.Fatalf("error = %v", err)
	}
}
