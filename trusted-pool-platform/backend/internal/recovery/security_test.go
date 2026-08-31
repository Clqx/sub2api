package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type canonicalizerStub struct {
	readyErr error
	calls    int
	fn       func(int, []byte) ([]byte, error)
}

func (s *canonicalizerStub) Ready(context.Context) error { return s.readyErr }
func (s *canonicalizerStub) Canonicalize(_ context.Context, value []byte) ([]byte, error) {
	s.calls++
	if s.fn != nil {
		return s.fn(s.calls, value)
	}
	return append([]byte(nil), value...), nil
}

type attestationVerifierStub struct {
	readyErr    error
	packageErr  error
	shareErrAt  int
	packageCall int
	shareCalls  int
}

type permanentSeatActivationVerifierStub struct{ err error }

func (*permanentSeatActivationVerifierStub) Ready(context.Context) error { return nil }
func (s *permanentSeatActivationVerifierStub) VerifyPoolActivation(context.Context, PermanentPoolActivationVerifyRequest) error {
	return s.err
}
func (s *permanentSeatActivationVerifierStub) VerifyPoolCommit(context.Context, PermanentPoolCommitVerifyRequest) error {
	return s.err
}

type platformSignerStub struct {
	verifyErr error
}

func (s *platformSignerStub) Ready(context.Context) error { return nil }
func (s *platformSignerStub) SignManifest(context.Context, PlatformManifestSignRequest) (PlatformManifestSignature, error) {
	return PlatformManifestSignature{}, errors.New("not used")
}
func (s *platformSignerStub) VerifyManifestSignature(context.Context, PlatformManifestVerifyRequest) error {
	return s.verifyErr
}

func (s *attestationVerifierStub) Ready(context.Context) error { return s.readyErr }
func (s *attestationVerifierStub) VerifyRecoveryPackage(context.Context, RecoveryPackageVerifyRequest) error {
	s.packageCall++
	return s.packageErr
}
func (s *attestationVerifierStub) VerifyEncryptedShare(context.Context, EncryptedShareVerifyRequest) error {
	s.shareCalls++
	if s.shareErrAt == s.shareCalls {
		return errors.New("bad share proof")
	}
	return nil
}
func (s *attestationVerifierStub) VerifyCredentialDEKWrap(context.Context, EpochDEKWrapVerifyRequest) error {
	return nil
}
func (s *attestationVerifierStub) VerifyStagedCredentialBatch(context.Context, EpochCredentialBatchVerifyRequest) error {
	return nil
}
func (s *attestationVerifierStub) VerifyMemberArtifactReceipt(context.Context, MemberArtifactReceiptVerifyRequest) error {
	return nil
}
func (s *attestationVerifierStub) VerifyControlAttestation(context.Context, ProviderAttestationVerifyRequest) (VerifiedProviderAttestation, error) {
	return VerifiedProviderAttestation{}, nil
}

func TestRecoveryContractsDoNotExposeRootOrSharePlaintext(t *testing.T) {
	banned := map[string]struct{}{
		"Root": {}, "RootPrivateKey": {}, "RootPlaintext": {}, "Share": {}, "SharePlaintext": {},
	}
	for _, value := range []any{EncryptedRecoveryPackage{}, EncryptedRecoveryShare{}, RecoveryPackageVerifyRequest{}} {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			field := typeOf.Field(i)
			if _, found := banned[field.Name]; found {
				t.Fatalf("%s exposes prohibited field %s", typeOf.Name(), field.Name)
			}
		}
	}
	packageType := reflect.TypeOf(EncryptedRecoveryPackage{})
	if _, found := packageType.FieldByName("RootPublicKey"); found {
		t.Fatal("online service must receive only root public handle/fingerprint, not root key material")
	}
}

func TestProvidersReadyFailsClosedForMissingAndTypedNilProviders(t *testing.T) {
	var typedNil *canonicalizerStub
	providers := Providers{Canonicalizer: typedNil}
	if err := providers.Ready(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Ready() error = %v, want provider unavailable", err)
	}
}

func TestRecoveryIntentAndProviderPackageBindEveryMember(t *testing.T) {
	request := validRecoveryRequest(t)
	pkg := validRecoveryPackage(request)
	if err := ValidateEncryptedRecoveryPackage(request, pkg); err != nil {
		t.Fatalf("ValidateEncryptedRecoveryPackage() = %v", err)
	}

	reordered := request
	reordered.Members = append([]RecoveryMember(nil), request.Members...)
	reordered.Members[0], reordered.Members[1] = reordered.Members[1], reordered.Members[0]
	if _, err := RecoveryIntentHash(reordered); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("reordered members error = %v, want duplicate/non-canonical set", err)
	}

	tampered := pkg
	tampered.EncryptedShares = append([]EncryptedRecoveryShare(nil), pkg.EncryptedShares...)
	tampered.EncryptedShares[0].Ciphertext = []byte("different")
	if err := ValidateEncryptedRecoveryPackage(request, tampered); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}

	wrongRecipient := pkg
	wrongRecipient.EncryptedShares = append([]EncryptedRecoveryShare(nil), pkg.EncryptedShares...)
	wrongRecipient.EncryptedShares[0], wrongRecipient.EncryptedShares[1] = wrongRecipient.EncryptedShares[1], wrongRecipient.EncryptedShares[0]
	if err := ValidateEncryptedRecoveryPackage(request, wrongRecipient); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("reordered shares error = %v", err)
	}

	missingPortableRootProof := pkg
	missingPortableRootProof.PortableAttestationSignature = nil
	if err := ValidateEncryptedRecoveryPackage(request, missingPortableRootProof); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("missing portable Root proof error = %v", err)
	}
	missingPortableShareProof := pkg
	missingPortableShareProof.EncryptedShares = append([]EncryptedRecoveryShare(nil), pkg.EncryptedShares...)
	missingPortableShareProof.EncryptedShares[0].PortableProofSignature = nil
	if err := ValidateEncryptedRecoveryPackage(request, missingPortableShareProof); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("missing portable Share proof error = %v", err)
	}

	sameKey := request
	sameKey.Members = append([]RecoveryMember(nil), request.Members...)
	sameKey.Members[0].EncryptionKeyID = sameKey.Members[0].SigningKeyID
	sameKey.Members[0].EncryptionKeyFingerprint = sameKey.Members[0].SigningKeyFingerprint
	sameKey.Members[0].EncryptionPublicKey = append([]byte(nil), sameKey.Members[0].SigningPublicKey...)
	if _, err := RecoveryIntentHash(sameKey); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("same signing/recovery key error = %v", err)
	}
}

func TestVerifyRecoveryPackageVerifiesPackageAndEveryShare(t *testing.T) {
	request := validRecoveryRequest(t)
	pkg := validRecoveryPackage(request)
	verifier := &attestationVerifierStub{}
	if err := VerifyRecoveryPackage(context.Background(), verifier, request, pkg); err != nil {
		t.Fatalf("VerifyRecoveryPackage() = %v", err)
	}
	if verifier.packageCall != 1 || verifier.shareCalls != len(request.Members) {
		t.Fatalf("verification calls = package %d shares %d", verifier.packageCall, verifier.shareCalls)
	}

	verifier = &attestationVerifierStub{shareErrAt: 2}
	if err := VerifyRecoveryPackage(context.Background(), verifier, request, pkg); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("invalid provider share proof error = %v", err)
	}
}

func TestBuildCanonicalManifestRejectsSemanticSubstitutionAndNonIdempotence(t *testing.T) {
	payload := validManifestPayload()
	canonicalizer := &canonicalizerStub{}
	manifest, err := BuildCanonicalManifest(context.Background(), canonicalizer, payload)
	if err != nil {
		t.Fatalf("BuildCanonicalManifest() = %v", err)
	}
	if manifest.Hash != sha256.Sum256(manifest.Bytes) || canonicalizer.calls != 2 {
		t.Fatal("manifest hash or idempotence check is missing")
	}

	substitution := &canonicalizerStub{fn: func(_ int, _ []byte) ([]byte, error) { return []byte(`{}`), nil }}
	if _, err := BuildCanonicalManifest(context.Background(), substitution, payload); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("semantic substitution error = %v", err)
	}

	nonIdempotent := &canonicalizerStub{fn: func(call int, value []byte) ([]byte, error) {
		if call == 1 {
			return append([]byte(nil), value...), nil
		}
		return append([]byte(" "), value...), nil
	}}
	if _, err := BuildCanonicalManifest(context.Background(), nonIdempotent, payload); !errors.Is(err, ErrCanonicalization) {
		t.Fatalf("non-idempotent canonicalizer error = %v", err)
	}
}

func TestManifestRequiresCanonicalFullBindingsAndPreviousHashChain(t *testing.T) {
	payload := validManifestPayload()
	if err := ValidateManifestPayload(payload); err != nil {
		t.Fatalf("ValidateManifestPayload() = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ManifestPayload)
	}{
		{"member order", func(p *ManifestPayload) { p.Members[0], p.Members[1] = p.Members[1], p.Members[0] }},
		{"seat member", func(p *ManifestPayload) { p.Seats[0].MemberID = "unknown" }},
		{"account seat", func(p *ManifestPayload) { p.Accounts[0].SeatIDs[0] = "unknown" }},
		{"uncovered seat", func(p *ManifestPayload) { p.Accounts[1].SeatIDs = []string{"seat-a"} }},
		{"missing control batch", func(p *ManifestPayload) { p.Accounts[0].Batches = p.Accounts[0].Batches[:3] }},
		{"control batch order", func(p *ManifestPayload) {
			p.Accounts[0].Batches[0], p.Accounts[0].Batches[1] = p.Accounts[0].Batches[1], p.Accounts[0].Batches[0]
		}},
		{"account attestation aggregate", func(p *ManifestPayload) { p.Accounts[0].ProviderAttestationDigest = hashHex("tampered") }},
		{"unchanged batch", func(p *ManifestPayload) { p.Accounts[0].Batches[0].ToBatchID = p.Accounts[0].Batches[0].FromBatchID }},
		{"share member", func(p *ManifestPayload) { p.EncryptedShares[0].MemberID = "member-z" }},
		{"root wrap domain", func(p *ManifestPayload) { p.RecoveryRoot.WrapDomain = "" }},
		{"rotation without replacement", func(p *ManifestPayload) { p.Replacements = nil }},
		{"rotation missing pool freeze", func(p *ManifestPayload) { p.Seats[1].FreezeOperationID = ""; p.Seats[1].FreezeSnapshotHash = "" }},
		{"previous chain", func(p *ManifestPayload) { p.PreviousManifestHash = strings.Repeat("0", 64) }},
		{"partial ack threshold", func(p *ManifestPayload) { p.RequiredShareAcknowledges = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneManifestPayload(payload)
			test.mutate(&candidate)
			if err := ValidateManifestPayload(candidate); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestMemberManifestAndShareAckUseDifferentSignatureDomains(t *testing.T) {
	hash := sha256.Sum256([]byte("manifest"))
	manifestMessage, err := BuildMemberManifestSignatureMessage(MemberManifestApproval{
		Version: 1, CeremonyType: CeremonyRotate, OperationID: "op-1", PoolID: "pool-1", Epoch: 2, MemberID: "member-a", ManifestHash: hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	ackMessage, err := BuildShareAcknowledgementMessage(ShareAcknowledgement{
		Version: 1, CeremonyType: CeremonyRotate, OperationID: "op-1", DeliveryID: "delivery-a", PoolID: "pool-1", Epoch: 2,
		MemberID: "member-a", ShareIndex: 1, CiphertextHash: sha256.Sum256([]byte("cipher")), ManifestHash: hash,
		RootCommitmentHash: sha256.Sum256([]byte("root")), VSSCommitmentHash: sha256.Sum256([]byte("vss")),
		VerifiedCommitment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(manifestMessage, ackMessage) || !bytes.HasPrefix(manifestMessage, []byte(MemberManifestSignatureDomain+"\x00")) ||
		!bytes.HasPrefix(ackMessage, []byte(ShareAcknowledgementDomain+"\x00")) {
		t.Fatal("signature message domains are not separated")
	}
	bootstrapManifestMessage, err := BuildMemberManifestSignatureMessage(MemberManifestApproval{
		Version: 1, CeremonyType: CeremonyBootstrap, OperationID: "op-1", PoolID: "pool-1", Epoch: 2,
		MemberID: "member-a", ManifestHash: hash,
	})
	if err != nil || bytes.Equal(manifestMessage, bootstrapManifestMessage) {
		t.Fatal("member manifest signature can be replayed across ceremony types")
	}
	bootstrapAck := ShareAcknowledgement{Version: 1, CeremonyType: CeremonyBootstrap, OperationID: "op-1",
		DeliveryID: "delivery-a", PoolID: "pool-1", Epoch: 2, MemberID: "member-a", ShareIndex: 1,
		CiphertextHash: sha256.Sum256([]byte("cipher")), ManifestHash: hash,
		RootCommitmentHash: sha256.Sum256([]byte("root")), VSSCommitmentHash: sha256.Sum256([]byte("vss")),
		VerifiedCommitment: true}
	bootstrapAckMessage, err := BuildShareAcknowledgementMessage(bootstrapAck)
	if err != nil || bytes.Equal(ackMessage, bootstrapAckMessage) {
		t.Fatal("share acknowledgement can be replayed across ceremony types")
	}

	invalidAck := ShareAcknowledgement{Version: 1, CeremonyType: CeremonyRotate, OperationID: "op-1", DeliveryID: "delivery-a", PoolID: "pool-1",
		Epoch: 2, MemberID: "member-a", ShareIndex: 1, CiphertextHash: sha256.Sum256([]byte("cipher")),
		ManifestHash: hash, RootCommitmentHash: sha256.Sum256([]byte("root")), VSSCommitmentHash: sha256.Sum256([]byte("vss"))}
	if _, err := BuildShareAcknowledgementMessage(invalidAck); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("unverified commitment error = %v", err)
	}
}

func TestBootstrapGenesisIsReachableOnlyFromFrozenLegacyActiveEpoch(t *testing.T) {
	payload := validManifestPayload()
	payload.CeremonyType = CeremonyBootstrap
	payload.CeremonyAttestationPurpose = bootstrapAttestationPurpose
	payload.FromGovernanceState = governanceStateLegacy
	payload.PreviousManifestHash = ""
	payload.Replacements = nil
	if err := ValidateManifestPayload(payload); err != nil {
		t.Fatalf("bootstrap manifest should be reachable: %v", err)
	}
	intent := ProviderAttestationIntent{Version: 1, CeremonyType: CeremonyBootstrap,
		OperationID: payload.OperationID, PoolID: payload.PoolID, FromEpoch: payload.FromEpoch, ToEpoch: payload.Epoch,
		FromEpochStatus: payload.FromEpochStatus, FromGovernanceState: payload.FromGovernanceState,
		Replacements: payload.Replacements, Seats: payload.Seats, Accounts: payload.Accounts}
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	verified := VerifiedProviderAttestation{Version: 1, CeremonyType: CeremonyBootstrap,
		Purpose: bootstrapAttestationPurpose, OperationID: intent.OperationID, PoolID: intent.PoolID,
		FromEpoch: intent.FromEpoch, ToEpoch: intent.ToEpoch, FromEpochStatus: intent.FromEpochStatus,
		FromGovernanceState: intent.FromGovernanceState, Replacements: intent.Replacements,
		Seats: intent.Seats, Accounts: intent.Accounts, Issuer: "bootstrap-authority",
		VerificationKeyID: "bootstrap-key", Reference: "bootstrap-attestation-1",
		CanonicalDigest: sha256.Sum256([]byte("bootstrap-attestation")), IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := ValidateProviderAttestation(intent, verified, now); err != nil {
		t.Fatalf("bootstrap attestation should establish the first current chain: %v", err)
	}
	wrongPurpose := verified
	wrongPurpose.Purpose = rotationAttestationPurpose
	if err := ValidateProviderAttestation(intent, wrongPurpose, now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("bootstrap attestation purpose error = %v", err)
	}

	zeroHash := payload
	zeroHash.PreviousManifestHash = strings.Repeat("0", sha256.Size*2)
	if err := ValidateManifestPayload(zeroHash); err != nil {
		t.Fatalf("bootstrap zero previous hash should be accepted: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ManifestPayload)
	}{
		{"current source", func(p *ManifestPayload) { p.FromGovernanceState = governanceStateCurrent }},
		{"nonzero previous", func(p *ManifestPayload) { p.PreviousManifestHash = hashHex("not-genesis") }},
		{"owner replacement", func(p *ManifestPayload) { p.Replacements = validManifestPayload().Replacements }},
		{"not active", func(p *ManifestPayload) { p.FromEpochStatus = "RETIRED" }},
		{"missing pool freeze", func(p *ManifestPayload) { p.Seats[1].FreezeOperationID = ""; p.Seats[1].FreezeSnapshotHash = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneManifestPayload(payload)
			test.mutate(&candidate)
			if err := ValidateManifestPayload(candidate); err == nil {
				t.Fatal("invalid bootstrap ceremony was accepted")
			}
		})
	}
}

func TestRecoveryPackageIntentBindsCeremonyTypeAndGenesisSource(t *testing.T) {
	rotate := validRecoveryRequest(t)
	bootstrap := rotate
	bootstrap.CeremonyType = CeremonyBootstrap
	bootstrap.FromGovernanceState = governanceStateLegacy
	bootstrap.PreviousManifestHash = [sha256.Size]byte{}
	bootstrap.IntentHash = [sha256.Size]byte{}
	bootstrapHash, err := RecoveryIntentHash(bootstrap)
	if err != nil {
		t.Fatalf("bootstrap intent: %v", err)
	}
	bootstrap.IntentHash = bootstrapHash
	if rotate.IntentHash == bootstrap.IntentHash {
		t.Fatal("root package intent hash does not bind ceremony type")
	}
	pkg := validRecoveryPackage(bootstrap)
	if err := ValidateEncryptedRecoveryPackage(bootstrap, pkg); err != nil {
		t.Fatalf("bootstrap package: %v", err)
	}
	pkg.CeremonyType = CeremonyRotate
	if err := ValidateEncryptedRecoveryPackage(bootstrap, pkg); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-ceremony package error = %v", err)
	}
}

func TestProviderAttestationMustMatchFullIntentAndBeCurrent(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	payload := validManifestPayload()
	previous, _ := decodeOptionalHash(payload.PreviousManifestHash)
	intent := ProviderAttestationIntent{Version: 1, CeremonyType: payload.CeremonyType,
		OperationID: payload.OperationID, PoolID: payload.PoolID, FromEpoch: payload.FromEpoch, ToEpoch: payload.Epoch,
		FromEpochStatus: payload.FromEpochStatus, FromGovernanceState: payload.FromGovernanceState,
		PreviousManifestHash: previous, Replacements: payload.Replacements, Seats: payload.Seats, Accounts: payload.Accounts}
	verified := VerifiedProviderAttestation{Version: 1, CeremonyType: intent.CeremonyType, Purpose: rotationAttestationPurpose,
		OperationID: intent.OperationID, PoolID: intent.PoolID, FromEpoch: intent.FromEpoch, ToEpoch: intent.ToEpoch,
		FromEpochStatus: intent.FromEpochStatus, FromGovernanceState: intent.FromGovernanceState,
		PreviousManifestHash: intent.PreviousManifestHash, Replacements: intent.Replacements,
		Seats: intent.Seats, Accounts: intent.Accounts,
		Issuer: "provider", VerificationKeyID: "provider-key", Reference: "attestation-1",
		CanonicalDigest: sha256.Sum256([]byte("attestation")), IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := ValidateProviderAttestation(intent, verified, now); err != nil {
		t.Fatalf("ValidateProviderAttestation() = %v", err)
	}
	wrongCeremony := verified
	wrongCeremony.CeremonyType = CeremonyBootstrap
	wrongCeremony.Purpose = bootstrapAttestationPurpose
	if err := ValidateProviderAttestation(intent, wrongCeremony, now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-ceremony attestation error = %v", err)
	}
	tampered := verified
	tampered.Accounts = append([]ResourceAccountPlan(nil), verified.Accounts...)
	tampered.Accounts[0].SeatIDs = []string{"seat-b"}
	if err := ValidateProviderAttestation(intent, tampered, now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("tampered attestation error = %v", err)
	}
	expired := verified
	expired.ExpiresAt = now
	if err := ValidateProviderAttestation(intent, expired, now); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("expired attestation error = %v", err)
	}
}

func TestPlatformSignatureMustBindExactCanonicalManifest(t *testing.T) {
	canonical := []byte(`{"a":1}`)
	hash := sha256.Sum256(canonical)
	request := PlatformManifestSignRequest{SignatureDomain: PlatformManifestSignatureV2,
		CeremonyType: CeremonyRotate, OperationID: "op-1", PoolID: "pool-1", Epoch: 2, ManifestHash: hash, Canonical: canonical}
	result := PlatformManifestSignature{SignatureDomain: PlatformManifestSignatureV2,
		CeremonyType: CeremonyRotate, OperationID: "op-1", PoolID: "pool-1", Epoch: 2, ManifestHash: hash,
		Algorithm: "Ed25519", KeyID: "platform-key", Signature: []byte("signature"), SignedAt: time.Now().UTC()}
	if err := validatePlatformManifestSignature(request, result); err != nil {
		t.Fatalf("validatePlatformManifestSignature() = %v", err)
	}
	if err := VerifyPlatformManifestSignature(context.Background(), &platformSignerStub{}, request, result); err != nil {
		t.Fatalf("VerifyPlatformManifestSignature() = %v", err)
	}
	if err := VerifyPlatformManifestSignature(context.Background(), &platformSignerStub{verifyErr: errors.New("forged")}, request, result); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("forged platform signature error = %v", err)
	}
	crossCeremony := result
	crossCeremony.CeremonyType = CeremonyBootstrap
	if err := validatePlatformManifestSignature(request, crossCeremony); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-ceremony platform signature error = %v", err)
	}
	wrongDomain := result
	wrongDomain.SignatureDomain = "trusted-pool/platform-manifest-signature/v1"
	if err := validatePlatformManifestSignature(request, wrongDomain); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong platform signature domain error = %v", err)
	}
	message, err := BuildPlatformManifestSignatureMessageV2(canonical)
	if err != nil || !bytes.Equal(message, append([]byte(PlatformManifestSignatureV2+"\x00"), canonical...)) {
		t.Fatalf("portable platform message = %x, %v", message, err)
	}
	result.ManifestHash = sha256.Sum256([]byte("other"))
	if err := validatePlatformManifestSignature(request, result); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong manifest hash error = %v", err)
	}
}

func validRecoveryRequest(t *testing.T) RecoveryPackageRequest {
	t.Helper()
	members := []RecoveryMember{
		validRecoveryMember("member-a", 1),
		validRecoveryMember("member-b", 2),
	}
	request := RecoveryPackageRequest{Version: 1, CeremonyType: CeremonyRotate,
		RequestID: "request-1", OperationID: "op-1", PoolID: "pool-1", FromEpoch: 1, ToEpoch: 2,
		FromEpochStatus: epochStatusActive, FromGovernanceState: governanceStateCurrent,
		PreviousManifestHash: sha256.Sum256([]byte("previous")), ExpectedProviderID: "root-provider",
		TrustProfile: "root-trust-profile", RecoveryThreshold: 2, Members: members}
	hash, err := RecoveryIntentHash(request)
	if err != nil {
		t.Fatal(err)
	}
	request.IntentHash = hash
	return request
}

func validRecoveryMember(id string, index uint16) RecoveryMember {
	signingKey := []byte("signing-key-" + id)
	encryptionKey := []byte("encryption-key-" + id)
	return RecoveryMember{MemberID: id, Role: "MEMBER", ShareIndex: index,
		SigningAlgorithm: "Ed25519", SigningKeyID: "signing-" + id,
		SigningKeyFingerprint: sha256.Sum256(signingKey), SigningPublicKey: signingKey,
		EncryptionAlgorithm: "HPKE-X25519", EncryptionKeyID: "recovery-" + id,
		EncryptionKeyFingerprint: sha256.Sum256(encryptionKey), EncryptionPublicKey: encryptionKey}
}

func validRecoveryPackage(request RecoveryPackageRequest) EncryptedRecoveryPackage {
	shares := make([]EncryptedRecoveryShare, 0, len(request.Members))
	for _, member := range request.Members {
		ciphertext := []byte("encrypted-share-" + member.MemberID)
		shares = append(shares, EncryptedRecoveryShare{MemberID: member.MemberID, ShareIndex: member.ShareIndex,
			EncryptionAlgorithm: member.EncryptionAlgorithm, EncryptionKeyID: member.EncryptionKeyID,
			EncryptionKeyFingerprint: member.EncryptionKeyFingerprint, Ciphertext: ciphertext,
			CiphertextHash: sha256.Sum256(ciphertext), ProviderCommitment: []byte("commitment-" + member.MemberID),
			ProviderProof: []byte("proof-" + member.MemberID), PortableProofAlgorithm: "Ed25519",
			PortableProofKeyID: "portable-share-key", PortableProofProtocolVersion: "phase2h-v1",
			PortableProofSignature: []byte("portable-share-signature-" + member.MemberID)})
	}
	return EncryptedRecoveryPackage{Version: request.Version, CeremonyType: request.CeremonyType,
		RequestID: request.RequestID, OperationID: request.OperationID, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, Epoch: request.ToEpoch, FromEpochStatus: request.FromEpochStatus,
		FromGovernanceState: request.FromGovernanceState, PreviousManifestHash: request.PreviousManifestHash,
		ProviderID: "root-provider", RootPublicAlgorithm: "RSA-OAEP-256",
		RootPublicHandle: "provider://root/2", RootPublicFingerprint: sha256.Sum256([]byte("root-public")),
		RootKeyVersion: "version/alpha", RootWrapDomain: "recovery-epoch-2", RootWrapAlgorithm: "RSA-OAEP-256",
		RootPrivateCommitment: []byte("private-commitment"), VSSAlgorithm: "FELDMAN-VSS",
		VSSCommitment: []byte("vss-commitment"), VSSProof: []byte("vss-proof"), ProviderAttestation: []byte("attestation"),
		ProviderAttestationRef: "root-attestation-2", ProviderAttestationKeyID: "root-provider-key",
		ProviderAttestationDigest:    sha256.Sum256([]byte("attestation")),
		PortableAttestationAlgorithm: "Ed25519", PortableAttestationIssuer: "root-provider",
		PortableAttestationKeyID: "portable-root-key", PortableAttestationProtocolVersion: "phase2h-v1",
		PortableAttestationSignature: []byte("portable-root-signature"),
		EncryptedShares:              shares, PackageHash: sha256.Sum256([]byte("package")), RequestIntentHash: request.IntentHash,
		CreatedAt: time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)}
}

func validManifestPayload() ManifestPayload {
	members := []ManifestMember{}
	shares := []ManifestEncryptedShare{}
	for i, id := range []string{"member-a", "member-b"} {
		member := validRecoveryMember(id, uint16(i+1))
		members = append(members, ManifestMember{MemberID: id, Role: member.Role, ShareIndex: member.ShareIndex,
			SigningAlgorithm: member.SigningAlgorithm, SigningKeyID: member.SigningKeyID,
			SigningKeyFingerprint: hex.EncodeToString(member.SigningKeyFingerprint[:]), SigningPublicKey: member.SigningPublicKey,
			RecoveryEncryptionAlgorithm: member.EncryptionAlgorithm, RecoveryEncryptionKeyID: member.EncryptionKeyID,
			RecoveryEncryptionKeyHash:   hex.EncodeToString(member.EncryptionKeyFingerprint[:]),
			RecoveryEncryptionPublicKey: member.EncryptionPublicKey})
		shares = append(shares, ManifestEncryptedShare{MemberID: id, ShareIndex: uint16(i + 1),
			CiphertextHash: hashHex("cipher-" + id), ProviderProofHash: hashHex("proof-" + id),
			ProviderCommitment: hashHex("commitment-" + id)})
	}
	seats := []SeatPlan{
		{SeatID: "seat-a", MemberID: "member-a", PrincipalUserID: 1, SubscriptionID: 11, APIKeyID: 21,
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-a", FreezeSnapshotHash: hashHex("freeze-a")},
		{SeatID: "seat-b", MemberID: "member-b", PrincipalUserID: 2, SubscriptionID: 12, APIKeyID: 22,
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-b", FreezeSnapshotHash: hashHex("freeze-b")},
	}
	accounts := []ResourceAccountPlan{
		{AccountID: "account-a", SeatIDs: []string{"seat-a"}, AccountRef: "provider-ref-a", ProviderBinding: "provider/account-a",
			ControlEvidenceID: "evidence-a", ProviderAttestationDigest: hashHex("account-attestation-a"),
			ProviderAttestationIssuer: "provider", ProviderAttestationKeyID: "provider-key", ProviderAttestationVersion: 1,
			ProviderAttestationAlgorithm: "Ed25519", ProviderAttestationSignature: []byte("account-signature-a"),
			ProviderAttestationProtocolVersion: "trusted-pool/provider-statement/v1",
			Batches:                            validControlBatches("a")},
		{AccountID: "account-b", SeatIDs: []string{"seat-b"}, AccountRef: "provider-ref-b", ProviderBinding: "provider/account-b",
			ControlEvidenceID: "evidence-b", ProviderAttestationDigest: hashHex("account-attestation-b"),
			ProviderAttestationIssuer: "provider", ProviderAttestationKeyID: "provider-key", ProviderAttestationVersion: 1,
			ProviderAttestationAlgorithm: "Ed25519", ProviderAttestationSignature: []byte("account-signature-b"),
			ProviderAttestationProtocolVersion: "trusted-pool/provider-statement/v1",
			Batches:                            validControlBatches("b")},
	}
	attestationSetHash, _ := ProviderAttestationSetHash(accounts)
	return ManifestPayload{ProtocolVersion: ProtocolVersionV1, CeremonyType: CeremonyRotate,
		OperationID: "op-1", PoolID: "pool-1", FromEpoch: 1, FromEpochStatus: epochStatusActive,
		FromGovernanceState: governanceStateCurrent,
		Epoch:               2, CreatedAt: "2026-08-19T01:00:00Z", GovernanceThreshold: 2, RecoveryThreshold: 2,
		RequiredShareAcknowledges: 2, PreviousManifestHash: hashHex("previous"),
		ProviderAttestationSetHash: hex.EncodeToString(attestationSetHash[:]),
		CeremonyAttestationDigest:  hashHex("ceremony-attestation"), CeremonyAttestationPurpose: rotationAttestationPurpose,
		CeremonyAttestationIssuer: "provider",
		CeremonyAttestationKeyID:  "provider-key", CeremonyAttestationReference: "ceremony-attestation-1",
		CeremonyAttestationVersion: 1,
		Members:                    members, Seats: seats,
		Replacements: []OwnerReplacementPlan{{SeatID: "seat-a", FromMemberID: "member-old-a", ToMemberID: "member-a",
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-a", FreezeSnapshotHash: hashHex("freeze-a")}},
		Accounts: accounts, EncryptedShares: shares,
		RecoveryRoot: ManifestRootBinding{PublicAlgorithm: "RSA-OAEP-256", PublicHandle: "provider://root/2",
			PublicFingerprint: hashHex("root-public"), WrapDomain: "recovery-epoch-2", WrapAlgorithm: "RSA-OAEP-256",
			ProviderID: "root-provider", KeyVersion: "version/alpha",
			PrivateCommitmentHash: hashHex("private"), VSSAlgorithm: "FELDMAN-VSS", VSSCommitmentHash: hashHex("vss"),
			VSSProofHash: hashHex("vss-proof"), PackageHash: hashHex("package")}}
}

func TestProviderAttestationSetHashBindsDetachedAccountProof(t *testing.T) {
	accounts := validManifestPayload().Accounts
	original, err := ProviderAttestationSetHash(accounts)
	if err != nil {
		t.Fatalf("hash typed account proofs: %v", err)
	}
	accounts[0].ProviderAttestationSignature = []byte("different-valid-signature")
	changed, err := ProviderAttestationSetHash(accounts)
	if err != nil || changed == original {
		t.Fatalf("detached account proof drift was not bound: hash=%x err=%v", changed, err)
	}
	accounts[0].ProviderAttestationSignature = nil
	if _, err := ProviderAttestationSetHash(accounts); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("missing detached account proof = %v", err)
	}
}

func validControlBatches(suffix string) []ControlBatchPlan {
	result := make([]ControlBatchPlan, 0, 4)
	for _, batchType := range []string{"LOGIN", "MFA", "RECOVERY", "OWNERSHIP"} {
		result = append(result, ControlBatchPlan{BatchType: batchType,
			FromBatchID: "batch-old-" + strings.ToLower(batchType) + "-" + suffix, FromBatchVersion: 1,
			FromCiphertextHash: hashHex("old-" + batchType + "-" + suffix),
			ToBatchID:          "batch-new-" + strings.ToLower(batchType) + "-" + suffix, ToBatchVersion: 2,
			ToCiphertextHash:   hashHex("new-" + batchType + "-" + suffix),
			ToRecoveryWrapHash: hashHex("wrap-" + batchType + "-" + suffix)})
	}
	return result
}

func TestPermanentSeatRotationPrepareRequestHashBindsEveryStableIdentity(t *testing.T) {
	request := validPermanentSeatRotationPrepareRequest()
	request.RequestHash = PermanentSeatRotationPrepareRequestHash(request)
	if request.RequestHash == ([sha256.Size]byte{}) {
		t.Fatal("rotation request hash is empty")
	}
	mutations := []func(*PermanentSeatRotationPrepareRequest){
		func(value *PermanentSeatRotationPrepareRequest) { value.OperationID = "seat-op-other" },
		func(value *PermanentSeatRotationPrepareRequest) { value.PlanID = "plan-other" },
		func(value *PermanentSeatRotationPrepareRequest) { value.PoolID = "pool-other" },
		func(value *PermanentSeatRotationPrepareRequest) { value.FromEpoch++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.ToEpoch++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.SeatID = "seat-other" },
		func(value *PermanentSeatRotationPrepareRequest) { value.TargetMemberID = "member-other" },
		func(value *PermanentSeatRotationPrepareRequest) { value.ExpectedAssignmentEpoch++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.PrincipalUserID++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.SubscriptionID++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.APIKeyID++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.FromAPIKeyVersion++ },
		func(value *PermanentSeatRotationPrepareRequest) { value.ToAPIKeyVersion++ },
	}
	for index, mutate := range mutations {
		changed := request
		mutate(&changed)
		if PermanentSeatRotationPrepareRequestHash(changed) == request.RequestHash {
			t.Fatalf("mutation %d did not change the exact idempotency hash", index)
		}
	}
}

func TestPermanentSeatRotationPrepareResultRejectsWrongBindingAndBadPayload(t *testing.T) {
	request := validPermanentSeatRotationPrepareRequest()
	request.RequestHash = PermanentSeatRotationPrepareRequestHash(request)
	result := PermanentSeatRotationPrepareResult{
		ProtocolVersion: request.ProtocolVersion, OperationID: request.OperationID, RequestHash: request.RequestHash,
		PlanID: request.PlanID, CeremonyType: request.CeremonyType, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch, SeatID: request.SeatID,
		TargetMemberID: request.TargetMemberID, AssignmentEpoch: request.ExpectedAssignmentEpoch + 1,
		PrincipalUserID: request.PrincipalUserID, SubscriptionID: request.SubscriptionID,
		APIKeyID: request.APIKeyID, ActiveAPIKeyVersion: request.ToAPIKeyVersion,
		State: "ROTATION_PREPARED", CredentialRotationComplete: true, Credential: []byte("sensitive-credential"),
		PreparedRotationRef: "prepared-rotation-1",
		CompletedAt:         time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC),
	}
	if err := ValidatePermanentSeatRotationPrepareResult(request, result); err != nil {
		t.Fatalf("valid rotation result = %v", err)
	}
	wrongPool := result
	wrongPool.PoolID = "pool-other"
	if err := ValidatePermanentSeatRotationPrepareResult(request, wrongPool); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong Pool result = %v", err)
	}
	wrongPrincipal := result
	wrongPrincipal.PrincipalUserID++
	if err := ValidatePermanentSeatRotationPrepareResult(request, wrongPrincipal); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong stable principal result = %v", err)
	}
	badPackage := result
	badPackage.Credential = nil
	if err := ValidatePermanentSeatRotationPrepareResult(request, badPackage); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("empty credential result = %v", err)
	}
}

func TestPermanentSeatCredentialAADBindsClaimToRequestAndFingerprint(t *testing.T) {
	request := validPermanentSeatRotationPrepareRequest()
	request.RequestHash = PermanentSeatRotationPrepareRequestHash(request)
	fingerprint := sha256.Sum256([]byte("credential-a"))
	aad := PermanentSeatCredentialAAD(request, fingerprint)
	changed := request
	changed.SeatID = "seat-other"
	changed.RequestHash = PermanentSeatRotationPrepareRequestHash(changed)
	if bytes.Equal(aad, PermanentSeatCredentialAAD(changed, fingerprint)) {
		t.Fatal("claim AAD did not bind Seat rotation request")
	}
	if bytes.Equal(aad, PermanentSeatCredentialAAD(request, sha256.Sum256([]byte("credential-b")))) {
		t.Fatal("claim AAD did not bind credential fingerprint")
	}
}

func TestPermanentPoolRotationActivationBindsCompletePreparedSet(t *testing.T) {
	prepared := validPermanentSeatRotationPrepareRequest()
	prepared.RequestHash = PermanentSeatRotationPrepareRequestHash(prepared)
	fingerprint := sha256.Sum256([]byte("prepared-credential"))
	seats := []PermanentSeatActivationBinding{{SeatID: prepared.SeatID, TargetMemberID: prepared.TargetMemberID,
		ExpectedAssignmentEpoch: prepared.ExpectedAssignmentEpoch,
		PrincipalUserID:         prepared.PrincipalUserID, SubscriptionID: prepared.SubscriptionID, APIKeyID: prepared.APIKeyID,
		ActiveAPIKeyVersion: prepared.ToAPIKeyVersion, ChildOperationID: prepared.OperationID,
		ChildRequestHash: prepared.RequestHash, CredentialFingerprint: fingerprint,
		PreparedRotationRef: "prepared-rotation-1"}}
	setHash, err := PermanentPreparedSeatSetHash(seats)
	if err != nil {
		t.Fatal(err)
	}
	request := PermanentPoolRotationActivateRequest{
		ProtocolVersion: PermanentSeatRotationProtocolV1, OperationID: "activate-pool-op-1",
		PrepareOperationID: "prepare-pool-op-1", PlanID: prepared.PlanID,
		CeremonyType: prepared.CeremonyType, PoolID: prepared.PoolID, FromEpoch: prepared.FromEpoch,
		ToEpoch: prepared.ToEpoch, PreparedSetHash: setHash, Seats: seats,
	}
	request.RequestHash = PermanentPoolRotationActivateRequestHash(request)
	proof := []byte("signed-activation-proof")
	result := PermanentPoolRotationActivateResult{
		ProtocolVersion: request.ProtocolVersion, OperationID: request.OperationID, RequestHash: request.RequestHash,
		PlanID: request.PlanID, CeremonyType: request.CeremonyType, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch, PreparedSetHash: request.PreparedSetHash,
		PrepareOperationID: request.PrepareOperationID, State: "ACTIVATED_PENDING_COMMIT",
		OldCredentialSetInvalidated: true, CredentialFingerprintGateEnforced: true,
		AuthCacheDurableOutbox: true, AuthCacheMinimumEvents: 2,
		Seats: []PermanentSeatActivationResult{{PermanentSeatActivationBinding: seats[0],
			AssignmentEpoch: seats[0].ExpectedAssignmentEpoch + 1, State: "ROTATION_ACTIVATED_PENDING_COMMIT"}},
		AttestationAlgorithm: "Ed25519", AttestationIssuer: "sub2api-permanent-rotation",
		AttestationRef: "activation-proof-1", AttestationKeyID: "provider-key-1", AttestationVersion: 1,
		AttestationDigest: sha256.Sum256(proof), Attestation: proof,
		ActivatedAt: time.Date(2026, 8, 20, 3, 5, 0, 0, time.UTC),
	}
	verifier := &permanentSeatActivationVerifierStub{}
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); err != nil {
		t.Fatalf("valid activation = %v", err)
	}
	tampered := result
	tampered.PreparedSetHash = sha256.Sum256([]byte("different-set"))
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, tampered); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong prepared rotation activation = %v", err)
	}
	enabledTooEarly := result
	enabledTooEarly.AllCredentialsEnabled = true
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, enabledTooEarly); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("activation released credentials before structural final = %v", err)
	}
	result.AuthorizationCacheInvalidated = false
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); err != nil {
		t.Fatalf("async auth cache convergence was incorrectly made a security gate: %v", err)
	}
	result.CredentialFingerprintGateEnforced = false
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("missing fingerprint gate = %v", err)
	}
	result.CredentialFingerprintGateEnforced = true
	result.AuthCacheDurableOutbox = false
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("missing durable outbox = %v", err)
	}
	result.AuthCacheDurableOutbox = true
	result.AuthCacheMinimumEvents = 1
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("incomplete outbox evidence = %v", err)
	}
	result.AuthCacheMinimumEvents = 2
	verifier.err = errors.New("invalid signature")
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier, request, result); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("invalid activation proof = %v", err)
	}
}

func TestPermanentPoolRotationCommitRequiresReleasedSignedCompleteSet(t *testing.T) {
	seatRequest := validPermanentSeatRotationPrepareRequest()
	seatRequest.RequestHash = PermanentSeatRotationPrepareRequestHash(seatRequest)
	binding := PermanentSeatActivationBinding{SeatID: seatRequest.SeatID, TargetMemberID: seatRequest.TargetMemberID,
		ExpectedAssignmentEpoch: seatRequest.ExpectedAssignmentEpoch, PrincipalUserID: seatRequest.PrincipalUserID,
		SubscriptionID: seatRequest.SubscriptionID, APIKeyID: seatRequest.APIKeyID,
		ActiveAPIKeyVersion: seatRequest.ToAPIKeyVersion, ChildOperationID: seatRequest.OperationID,
		ChildRequestHash: seatRequest.RequestHash, CredentialFingerprint: sha256.Sum256([]byte("credential")),
		PreparedRotationRef: "prepared-seat-1"}
	setHash, _ := PermanentPreparedSeatSetHash([]PermanentSeatActivationBinding{binding})
	activationRequest := PermanentPoolRotationActivateRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: "activate-pool-op", PrepareOperationID: "prepare-pool-op", PlanID: seatRequest.PlanID,
		CeremonyType: seatRequest.CeremonyType, PoolID: seatRequest.PoolID,
		FromEpoch: seatRequest.FromEpoch, ToEpoch: seatRequest.ToEpoch, PreparedSetHash: setHash,
		Seats: []PermanentSeatActivationBinding{binding}}
	activationRequest.RequestHash = PermanentPoolRotationActivateRequestHash(activationRequest)
	activationProof := []byte("activation-proof")
	activationResult := PermanentPoolRotationActivateResult{ProtocolVersion: activationRequest.ProtocolVersion,
		OperationID: activationRequest.OperationID, PrepareOperationID: activationRequest.PrepareOperationID,
		RequestHash: activationRequest.RequestHash, PlanID: activationRequest.PlanID,
		CeremonyType: activationRequest.CeremonyType, PoolID: activationRequest.PoolID,
		FromEpoch: activationRequest.FromEpoch, ToEpoch: activationRequest.ToEpoch,
		PreparedSetHash: activationRequest.PreparedSetHash, State: "ACTIVATED_PENDING_COMMIT",
		OldCredentialSetInvalidated: true, CredentialFingerprintGateEnforced: true,
		AuthCacheDurableOutbox: true, AuthCacheMinimumEvents: 1,
		Seats: []PermanentSeatActivationResult{{PermanentSeatActivationBinding: binding,
			AssignmentEpoch: binding.ExpectedAssignmentEpoch + 1, State: "ROTATION_ACTIVATED_PENDING_COMMIT"}},
		AttestationAlgorithm: "Ed25519", AttestationIssuer: "sub2api", AttestationRef: "activation-proof-1",
		AttestationKeyID: "key-1", AttestationVersion: 1, AttestationDigest: sha256.Sum256(activationProof),
		Attestation: activationProof, ActivatedAt: time.Date(2026, 8, 20, 3, 55, 0, 0, time.UTC)}
	verifier := &permanentSeatActivationVerifierStub{}
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier,
		activationRequest, activationResult); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("activation accepted fewer than 2N durable outbox events: %v", err)
	}
	activationResult.AuthCacheMinimumEvents = 2
	if err := VerifyPermanentPoolRotationActivateResult(context.Background(), verifier,
		activationRequest, activationResult); err != nil {
		t.Fatalf("activation rejected exactly 2N durable outbox events: %v", err)
	}
	request := PermanentPoolRotationCommitRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: "commit-pool-op", PrepareOperationID: "prepare-pool-op",
		ActivationOperationID: activationRequest.OperationID, ActivationRequestHash: activationRequest.RequestHash,
		PlanID: seatRequest.PlanID, CeremonyType: seatRequest.CeremonyType, PoolID: seatRequest.PoolID,
		FromEpoch: seatRequest.FromEpoch, ToEpoch: seatRequest.ToEpoch, PreparedSetHash: setHash,
		Seats: []PermanentSeatActivationBinding{binding}}
	request.RequestHash = PermanentPoolRotationCommitRequestHash(request)
	proof := []byte("commit-proof")
	result := PermanentPoolRotationCommitResult{ProtocolVersion: request.ProtocolVersion,
		OperationID: request.OperationID, PrepareOperationID: request.PrepareOperationID,
		ActivationOperationID: request.ActivationOperationID, ActivationRequestHash: request.ActivationRequestHash,
		RequestHash: request.RequestHash, PlanID: request.PlanID, CeremonyType: request.CeremonyType,
		PoolID: request.PoolID, FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch,
		PreparedSetHash: request.PreparedSetHash, State: "COMMITTED", AllCredentialsEnabled: true,
		AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true,
		CredentialFingerprintGateEnforced: true, AuthCacheDurableOutbox: true, AuthCacheMinimumEvents: 1,
		Seats: []PermanentSeatActivationResult{{PermanentSeatActivationBinding: binding,
			AssignmentEpoch: binding.ExpectedAssignmentEpoch + 1, State: "ACTIVE"}},
		AttestationAlgorithm: "Ed25519", AttestationIssuer: "sub2api", AttestationRef: "proof-1",
		AttestationKeyID: "key-1", AttestationVersion: 1, AttestationDigest: sha256.Sum256(proof),
		Attestation: proof, CommittedAt: time.Date(2026, 8, 20, 4, 0, 0, 0, time.UTC)}
	if err := VerifyPermanentPoolRotationCommitResult(context.Background(), verifier, request, result); err != nil {
		t.Fatalf("commit rejected exactly N durable outbox events: %v", err)
	}
	insufficientOutbox := result
	insufficientOutbox.AuthCacheMinimumEvents = 0
	if err := VerifyPermanentPoolRotationCommitResult(context.Background(), verifier, request, insufficientOutbox); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("commit accepted fewer than N durable outbox events: %v", err)
	}
	notReleased := result
	notReleased.AllCredentialsEnabled = false
	if err := VerifyPermanentPoolRotationCommitResult(context.Background(), verifier, request, notReleased); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("unreleased commit = %v", err)
	}
	tampered := result
	tampered.ActivationRequestHash = sha256.Sum256([]byte("other-activation"))
	if err := VerifyPermanentPoolRotationCommitResult(context.Background(), verifier, request, tampered); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("commit activation drift = %v", err)
	}
}

func validPermanentSeatRotationPrepareRequest() PermanentSeatRotationPrepareRequest {
	return PermanentSeatRotationPrepareRequest{
		ProtocolVersion: PermanentSeatRotationProtocolV1, OperationID: "seat-op-1", PlanID: "plan-1",
		CeremonyType: CeremonyRotate, PoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		SeatID: "seat-1", TargetMemberID: "member-new", ExpectedAssignmentEpoch: 3,
		PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303,
		FromAPIKeyVersion: 3, ToAPIKeyVersion: 4,
	}
}

func TestPermanentRotationHashFixedVectors(t *testing.T) {
	first := validPermanentSeatRotationPrepareRequest()
	first.SeatID, first.OperationID = "seat-a", "child-op-a"
	first.RequestHash = PermanentSeatRotationPrepareRequestHash(first)
	second := first
	second.SeatID, second.OperationID, second.TargetMemberID = "seat-b", "child-op-b", "member-b"
	second.PrincipalUserID, second.SubscriptionID, second.APIKeyID = 102, 203, 304
	second.RequestHash = PermanentSeatRotationPrepareRequestHash(second)
	children := []PermanentSeatRotationPrepareRequest{first, second}
	childSet, err := PermanentRotationChildSetHash(children)
	if err != nil {
		t.Fatal(err)
	}
	prepare := PermanentPoolRotationPrepareRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: "prepare-pool-op", PlanID: first.PlanID, CeremonyType: first.CeremonyType,
		PoolID: first.PoolID, FromEpoch: first.FromEpoch, ToEpoch: first.ToEpoch,
		ChildSetHash: childSet, Seats: children}
	prepare.RequestHash = PermanentPoolRotationPrepareRequestHash(prepare)
	preparedSeats := []PermanentSeatActivationBinding{
		{SeatID: "seat-a", TargetMemberID: "member-new", ExpectedAssignmentEpoch: first.ExpectedAssignmentEpoch,
			PrincipalUserID: 101, SubscriptionID: 202,
			APIKeyID: 303, ActiveAPIKeyVersion: 4, CredentialFingerprint: sha256.Sum256([]byte("credential-a")),
			PreparedRotationRef: "prepared-a", ChildOperationID: first.OperationID, ChildRequestHash: first.RequestHash},
		{SeatID: "seat-b", TargetMemberID: "member-b", ExpectedAssignmentEpoch: second.ExpectedAssignmentEpoch,
			PrincipalUserID: 102, SubscriptionID: 203,
			APIKeyID: 304, ActiveAPIKeyVersion: 4, CredentialFingerprint: sha256.Sum256([]byte("credential-b")),
			PreparedRotationRef: "prepared-b", ChildOperationID: second.OperationID, ChildRequestHash: second.RequestHash},
	}
	preparedSet, err := PermanentPreparedSeatSetHash(preparedSeats)
	if err != nil {
		t.Fatal(err)
	}
	activate := PermanentPoolRotationActivateRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: "activate-pool-op", PrepareOperationID: prepare.OperationID,
		PlanID: first.PlanID, CeremonyType: first.CeremonyType,
		PoolID: first.PoolID, FromEpoch: first.FromEpoch, ToEpoch: first.ToEpoch,
		PreparedSetHash: preparedSet, Seats: preparedSeats}
	activate.RequestHash = PermanentPoolRotationActivateRequestHash(activate)
	commit := PermanentPoolRotationCommitRequest{ProtocolVersion: PermanentSeatRotationProtocolV1,
		OperationID: "commit-pool-op", PrepareOperationID: prepare.OperationID,
		ActivationOperationID: activate.OperationID, ActivationRequestHash: activate.RequestHash,
		PlanID: first.PlanID, CeremonyType: first.CeremonyType, PoolID: first.PoolID,
		FromEpoch: first.FromEpoch, ToEpoch: first.ToEpoch, PreparedSetHash: preparedSet, Seats: preparedSeats}
	commit.RequestHash = PermanentPoolRotationCommitRequestHash(commit)
	want := map[string]string{
		"child_a":      "40687cdc14f04f77276b2ea9dbd7f971c1fe4dbc1207583bd0f286deec582012",
		"child_b":      "b3cd30fc1625a77ce4a69546f12ceb0c181f2e2b7728660974652e5341188feb",
		"child_set":    "94c426879876dcf4b861be633f203e023eb90670144f8dcd36c5a12ab1e752c9",
		"prepare":      "63dc318b24b47335dd8089b3202940cb4c1467b9b4284f6996bd429b822d38e3",
		"prepared_set": "5db639866d27d07d3187627cb4a62f84bcf8c9f86518aeec2aa1ad4a230ceaf7",
		"activate":     "be38cb7aba7eecb97c2bed2faf8fd66cebb9398588981b2a87ff14bb2d877ccc",
		"commit":       "8af081439638d45ec867ef9a92771cd5d68184e310b17659be18bc51ea19e5e4",
	}
	got := map[string][sha256.Size]byte{"child_a": first.RequestHash, "child_b": second.RequestHash,
		"child_set": childSet, "prepare": prepare.RequestHash, "prepared_set": preparedSet,
		"activate": activate.RequestHash, "commit": commit.RequestHash}
	for name, digest := range got {
		if hex.EncodeToString(digest[:]) != want[name] {
			t.Fatalf("%s vector = %s", name, hex.EncodeToString(digest[:]))
		}
	}
}

func cloneManifestPayload(payload ManifestPayload) ManifestPayload {
	clone := payload
	clone.Members = append([]ManifestMember(nil), payload.Members...)
	clone.Seats = append([]SeatPlan(nil), payload.Seats...)
	clone.Replacements = append([]OwnerReplacementPlan(nil), payload.Replacements...)
	clone.Accounts = append([]ResourceAccountPlan(nil), payload.Accounts...)
	for i := range clone.Accounts {
		clone.Accounts[i].SeatIDs = append([]string(nil), payload.Accounts[i].SeatIDs...)
		clone.Accounts[i].Batches = append([]ControlBatchPlan(nil), payload.Accounts[i].Batches...)
	}
	clone.EncryptedShares = append([]ManifestEncryptedShare(nil), payload.EncryptedShares...)
	return clone
}

func hashHex(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
