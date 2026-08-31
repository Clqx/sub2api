package offline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"

	"trusted-pool-platform/backend/internal/recovery"
)

type fixture struct {
	bundleJSON, policyJSON []byte
	bundle                 Bundle
	policy                 TrustPolicy
	memberPrivate          map[string]ed25519.PrivateKey
}

func TestVerifyGoldenBundle(t *testing.T) {
	value := newFixture(t, RevealPolicyUnapproved)
	report := Verify(value.bundleJSON, value.policyJSON, DefaultLimits())
	if report.Verdict != VerdictVerified || report.ReasonCode != ReasonOK || report.ManifestCount != 1 ||
		report.PoolID != "pool-1" || report.FirstEpoch != 2 || report.LastEpoch != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	first, err := MarshalCanonicalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalCanonicalReport(report)
	if err != nil || string(first) != string(second) {
		t.Fatalf("report is not deterministic: %q / %q", first, second)
	}
}

func TestVerifyIncompleteEvidenceNeverBecomesVerified(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Bundle)
		want ReasonCode
	}{
		{name: "missing provider proof", edit: func(value *Bundle) { value.Manifests[0].ProviderProofs = nil }, want: ReasonProviderEvidenceIncomplete},
		{name: "legacy platform signature", edit: func(value *Bundle) {
			value.Manifests[0].PlatformSignature.Domain = "trusted-pool/legacy-adapter"
		}, want: ReasonLegacySignatureUnsupported},
		{name: "missing governance approval", edit: func(value *Bundle) {
			value.Manifests[0].MemberApprovals = value.Manifests[0].MemberApprovals[:1]
		}, want: ReasonMemberApprovalsIncomplete},
		{name: "missing acknowledgement", edit: func(value *Bundle) {
			value.Manifests[0].ShareAcknowledgements = value.Manifests[0].ShareAcknowledgements[:1]
		}, want: ReasonShareAcknowledgesIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t, RevealPolicyUnapproved)
			test.edit(&value.bundle)
			encoded := mustCanonical(t, value.bundle)
			report := Verify(encoded, value.policyJSON, DefaultLimits())
			if report.Verdict != VerdictIncomplete || report.ReasonCode != test.want {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestIncompleteSetsDoNotMaskInvalidProvidedEvidence(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Bundle)
	}{
		{name: "member approval", edit: func(bundle *Bundle) {
			items := append([]MemberApprovalEvidence(nil), bundle.Manifests[0].MemberApprovals[:1]...)
			items[0].Signature = append([]byte(nil), items[0].Signature...)
			items[0].Signature[0] ^= 1
			bundle.Manifests[0].MemberApprovals = items
		}},
		{name: "share acknowledgement", edit: func(bundle *Bundle) {
			items := append([]ShareAcknowledgementEvidence(nil), bundle.Manifests[0].ShareAcknowledgements[:1]...)
			items[0].Signature = append([]byte(nil), items[0].Signature...)
			items[0].Signature[0] ^= 1
			bundle.Manifests[0].ShareAcknowledgements = items
		}},
		{name: "provider proof", edit: func(bundle *Bundle) {
			items := append([]ProviderProofEvidence(nil), bundle.Manifests[0].ProviderProofs[:1]...)
			items[0].Signature = append([]byte(nil), items[0].Signature...)
			items[0].Signature[0] ^= 1
			bundle.Manifests[0].ProviderProofs = items
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t, RevealPolicyUnapproved)
			test.edit(&value.bundle)
			report := Verify(mustCanonical(t, value.bundle), value.policyJSON, DefaultLimits())
			if report.Verdict != VerdictRejected || report.ReasonCode != ReasonSignatureInvalid {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestProviderIdentityAndRoleSubstitutionRejected(t *testing.T) {
	tests := []struct {
		name         string
		kind         ProviderProofKind
		providerID   string
		keyID        string
		allowedKinds []ProviderProofKind
	}{
		{name: "account cross provider", kind: ProviderProofAccount, providerID: "root-provider",
			keyID: "provider-key", allowedKinds: []ProviderProofKind{ProviderProofAccount}},
		{name: "package key only authorized for shares", kind: ProviderProofPackage, providerID: "root-provider",
			keyID: "root-share-only-key", allowedKinds: []ProviderProofKind{ProviderProofShare}},
		{name: "share key only authorized for packages", kind: ProviderProofShare, providerID: "root-provider",
			keyID: "root-package-only-key", allowedKinds: []ProviderProofKind{ProviderProofPackage}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t, RevealPolicyUnapproved)
			mutated := value.bundle
			mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
			proofs := append([]ProviderProofEvidence(nil), value.bundle.Manifests[0].ProviderProofs...)
			proofIndex := -1
			for index := range proofs {
				if proofs[index].Statement.Kind == test.kind {
					proofIndex = index
					break
				}
			}
			if proofIndex < 0 {
				t.Fatalf("fixture has no %s proof", test.kind)
			}
			seed := sha256.Sum256([]byte("substitution-" + test.name))
			private := ed25519.NewKeyFromSeed(seed[:])
			proofs[proofIndex].Statement.ProviderID = test.providerID
			proofs[proofIndex].KeyID = test.keyID
			message, err := BuildProviderProofMessage(proofs[proofIndex].Statement)
			if err != nil {
				t.Fatal(err)
			}
			proofs[proofIndex].Signature = ed25519.Sign(private, message)
			mutated.Manifests[0].ProviderProofs = proofs
			policy := value.policy
			policy.ProviderKeys = append(append([]TrustedProviderEd25519Key(nil), value.policy.ProviderKeys...),
				TrustedProviderEd25519Key{ProviderID: test.providerID, KeyID: test.keyID,
					AllowedProofKinds: test.allowedKinds, PublicKey: private.Public().(ed25519.PublicKey)})
			report := Verify(mustCanonical(t, mutated), mustCanonical(t, policy), DefaultLimits())
			if report.Verdict != VerdictRejected || report.ReasonCode != ReasonProviderEvidenceInvalid {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestProviderTrustPolicyRequiresSortedUniqueCapabilities(t *testing.T) {
	tests := []struct {
		name  string
		kinds []ProviderProofKind
	}{
		{name: "unsorted", kinds: []ProviderProofKind{ProviderProofCeremony, ProviderProofAccount}},
		{name: "duplicate", kinds: []ProviderProofKind{ProviderProofAccount, ProviderProofAccount}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t, RevealPolicyUnapproved)
			policy := value.policy
			policy.ProviderKeys = append([]TrustedProviderEd25519Key(nil), value.policy.ProviderKeys...)
			policy.ProviderKeys[0].AllowedProofKinds = test.kinds
			report := Verify(value.bundleJSON, mustCanonical(t, policy), DefaultLimits())
			if report.Verdict != VerdictRejected || report.ReasonCode != ReasonTrustPolicyInvalid {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestVerifyRejectsStrictJSONAndCryptographicMutations(t *testing.T) {
	value := newFixture(t, RevealPolicyUnapproved)
	var unknownObject map[string]any
	if err := json.Unmarshal(value.bundleJSON, &unknownObject); err != nil {
		t.Fatal(err)
	}
	unknownObject["unknown_critical"] = true
	unknown := mustCanonical(t, unknownObject)
	duplicate := append([]byte(`{"protocol_version":"other",`), value.bundleJSON[1:]...)
	nonCanonical := append([]byte("\n"), value.bundleJSON...)
	trailing := append(append([]byte(nil), value.bundleJSON...), []byte(`{}`)...)
	invalidUTF8 := append(append([]byte(nil), value.bundleJSON...), 0xff)

	tests := []struct {
		name string
		data []byte
		want ReasonCode
	}{
		{name: "unknown field", data: unknown, want: ReasonSchemaInvalid},
		{name: "duplicate key", data: duplicate, want: ReasonInvalidJSON},
		{name: "non canonical", data: nonCanonical, want: ReasonNonCanonicalJSON},
		{name: "trailing value", data: trailing, want: ReasonInvalidJSON},
		{name: "invalid utf8", data: invalidUTF8, want: ReasonInvalidUTF8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := Verify(test.data, value.policyJSON, DefaultLimits())
			if report.Verdict != VerdictRejected || report.ReasonCode != test.want {
				t.Fatalf("report = %#v", report)
			}
		})
	}

	t.Run("signature bit flip", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		mutated.Manifests[0].PlatformSignature.Signature = append([]byte(nil), value.bundle.Manifests[0].PlatformSignature.Signature...)
		mutated.Manifests[0].PlatformSignature.Signature[0] ^= 1
		report := Verify(mustCanonical(t, mutated), value.policyJSON, DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonSignatureInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("checkpoint drift", func(t *testing.T) {
		policy := value.policy
		policy.Checkpoint.ManifestHash = hashHex("other-checkpoint")
		report := Verify(value.bundleJSON, mustCanonical(t, policy), DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonCheckpointMismatch {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("provider signature bit flip", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		mutated.Manifests[0].ProviderProofs = append([]ProviderProofEvidence(nil), value.bundle.Manifests[0].ProviderProofs...)
		mutated.Manifests[0].ProviderProofs[0].Signature = append([]byte(nil), value.bundle.Manifests[0].ProviderProofs[0].Signature...)
		mutated.Manifests[0].ProviderProofs[0].Signature[0] ^= 1
		report := Verify(mustCanonical(t, mutated), value.policyJSON, DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonSignatureInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("dynamic threshold is invalid", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		var payload recovery.ManifestPayload
		if err := json.Unmarshal(mutated.Manifests[0].CanonicalManifest, &payload); err != nil {
			t.Fatal(err)
		}
		payload.RecoveryThreshold = 3
		mutated.Manifests[0].CanonicalManifest = mustCanonical(t, payload)
		manifestHash := sha256.Sum256(mutated.Manifests[0].CanonicalManifest)
		mutated.Manifests[0].ManifestHash = encodeHash(manifestHash)
		report := Verify(mustCanonical(t, mutated), value.policyJSON, DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonThresholdInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("duplicate acknowledgement", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		mutated.Manifests[0].ShareAcknowledgements = append([]ShareAcknowledgementEvidence(nil),
			value.bundle.Manifests[0].ShareAcknowledgements...)
		mutated.Manifests[0].ShareAcknowledgements[1] = mutated.Manifests[0].ShareAcknowledgements[0]
		report := Verify(mustCanonical(t, mutated), value.policyJSON, DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonSetMismatch {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("unsupported provider proof cannot produce green", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		mutated.Manifests[0].ProviderProofs = append([]ProviderProofEvidence(nil), value.bundle.Manifests[0].ProviderProofs...)
		mutated.Manifests[0].ProviderProofs[0].Algorithm = "OPAQUE"
		report := Verify(mustCanonical(t, mutated), value.policyJSON, DefaultLimits())
		if report.Verdict != VerdictIncomplete || report.ReasonCode != ReasonProviderEvidenceIncomplete {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("provider key substitution", func(t *testing.T) {
		mutated := value.bundle
		mutated.Manifests = append([]ManifestEvidence(nil), value.bundle.Manifests...)
		mutated.Manifests[0].ProviderProofs = append([]ProviderProofEvidence(nil), value.bundle.Manifests[0].ProviderProofs...)
		secondSeed := sha256.Sum256([]byte("provider-key-2"))
		secondPrivate := ed25519.NewKeyFromSeed(secondSeed[:])
		mutated.Manifests[0].ProviderProofs[0].KeyID = "provider-key-2"
		message, err := BuildProviderProofMessage(mutated.Manifests[0].ProviderProofs[0].Statement)
		if err != nil {
			t.Fatal(err)
		}
		mutated.Manifests[0].ProviderProofs[0].Signature = ed25519.Sign(secondPrivate, message)
		policy := value.policy
		policy.ProviderKeys = append(policy.ProviderKeys, TrustedProviderEd25519Key{ProviderID: "provider",
			KeyID: "provider-key-2", AllowedProofKinds: []ProviderProofKind{ProviderProofCeremony},
			PublicKey: secondPrivate.Public().(ed25519.PublicKey)})
		report := Verify(mustCanonical(t, mutated), mustCanonical(t, policy), DefaultLimits())
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonProviderEvidenceInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("bundle size limit", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxBundleBytes = int64(len(value.bundleJSON) - 1)
		report := Verify(value.bundleJSON, value.policyJSON, limits)
		if report.Verdict != VerdictRejected || report.ReasonCode != ReasonInputTooLarge {
			t.Fatalf("report = %#v", report)
		}
	})
}

func TestEvaluateRevealAuthorizationTerminalStates(t *testing.T) {
	tests := []struct {
		name        string
		policyState RevealPolicyState
		wantVerdict RevealVerdict
		wantReason  ReasonCode
	}{
		{name: "ADR unapproved", policyState: RevealPolicyUnapproved,
			wantVerdict: RevealVerdictPolicyUnapproved, wantReason: ReasonRevealPolicyUnapproved},
		{name: "approved but H1 has no executor", policyState: RevealPolicyApproved,
			wantVerdict: RevealVerdictAuthorizedNotExecutable, wantReason: ReasonRevealAuthorizedNoExecutor},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := newFixture(t, test.policyState)
			intentJSON, approvalsJSON := newRevealDocuments(t, value)
			report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, intentJSON, approvalsJSON,
				time.Date(2026, 8, 21, 8, 10, 0, 0, time.UTC), DefaultLimits())
			if report.Verdict != test.wantVerdict || report.ReasonCode != test.wantReason || report.ApprovalCount != 2 ||
				report.EvaluationTime != "2026-08-21T08:10:00Z" {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestEvaluateRevealAuthorizationRejectsBadTranscript(t *testing.T) {
	value := newFixture(t, RevealPolicyApproved)
	intentJSON, approvalsJSON := newRevealDocuments(t, value)
	verificationTime := time.Date(2026, 8, 21, 8, 10, 0, 0, time.UTC)

	t.Run("insufficient approvals", func(t *testing.T) {
		var approvals RevealApprovalsDocument
		if err := json.Unmarshal(approvalsJSON, &approvals); err != nil {
			t.Fatal(err)
		}
		approvals.Approvals = approvals.Approvals[:1]
		report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, intentJSON,
			mustCanonical(t, approvals), verificationTime, DefaultLimits())
		if report.Verdict != RevealVerdictRejected || report.ReasonCode != ReasonRevealApprovalsIncomplete {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("signature tamper", func(t *testing.T) {
		var approvals RevealApprovalsDocument
		if err := json.Unmarshal(approvalsJSON, &approvals); err != nil {
			t.Fatal(err)
		}
		approvals.Approvals[0].Signature[0] ^= 1
		report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, intentJSON,
			mustCanonical(t, approvals), verificationTime, DefaultLimits())
		if report.Verdict != RevealVerdictRejected || report.ReasonCode != ReasonSignatureInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("expired", func(t *testing.T) {
		report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, intentJSON, approvalsJSON,
			time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC), DefaultLimits())
		if report.Verdict != RevealVerdictRejected || report.ReasonCode != ReasonRevealIntentInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("output policy drift invalidates approvals", func(t *testing.T) {
		var intent RevealIntent
		if err := json.Unmarshal(intentJSON, &intent); err != nil {
			t.Fatal(err)
		}
		intent.OutputPolicy = "review-room-redacted-v2"
		report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, mustCanonical(t, intent), approvalsJSON,
			verificationTime, DefaultLimits())
		if report.Verdict != RevealVerdictRejected || report.ReasonCode != ReasonSignatureInvalid {
			t.Fatalf("report = %#v", report)
		}
	})

	t.Run("missing output policy is invalid", func(t *testing.T) {
		var intent RevealIntent
		if err := json.Unmarshal(intentJSON, &intent); err != nil {
			t.Fatal(err)
		}
		intent.OutputPolicy = ""
		report := EvaluateRevealAuthorization(value.bundleJSON, value.policyJSON, mustCanonical(t, intent), approvalsJSON,
			verificationTime, DefaultLimits())
		if report.Verdict != RevealVerdictRejected || report.ReasonCode != ReasonRevealIntentInvalid {
			t.Fatalf("report = %#v", report)
		}
	})
}

func TestRFC8785CanonicalizationKAT(t *testing.T) {
	input, err := os.ReadFile("testdata/rfc8785-input.json")
	if err != nil {
		t.Fatal(err)
	}
	wantHex, err := os.ReadFile("testdata/rfc8785-expected.hex")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := jcs.Transform(input)
	if err != nil || string(got) != string(want) {
		t.Fatalf("JCS KAT = %q, %v", got, err)
	}
}

func TestEd25519AndPlatformDomainKAT(t *testing.T) {
	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	seed := decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPublic := decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	wantSignature := decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	private := ed25519.NewKeyFromSeed(seed)
	if got := private.Public().(ed25519.PublicKey); string(got) != string(wantPublic) {
		t.Fatalf("RFC 8032 public key = %x", got)
	}
	if got := ed25519.Sign(private, nil); string(got) != string(wantSignature) {
		t.Fatalf("RFC 8032 signature = %x", got)
	}

	message, err := BuildPlatformManifestSignatureMessage([]byte(`{"example":"manifest"}`))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	if got := hex.EncodeToString(digest[:]); got != "1a121e13d3c0df36e0c1a685c1ef691883fd8643b612824da3d074aceb6c2c6d" {
		t.Fatalf("platform domain message hash = %s", got)
	}
}

func FuzzParseBundle(f *testing.F) {
	value := newFixture(f, RevealPolicyUnapproved)
	f.Add(value.bundleJSON)
	f.Add([]byte(`{"protocol_version":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := DefaultLimits()
		limits.MaxBundleBytes = 1 << 20
		_, _ = ParseBundle(data, limits)
	})
}

func FuzzParseRevealIntent(f *testing.F) {
	value := newFixture(f, RevealPolicyUnapproved)
	intent, _ := newRevealDocuments(f, value)
	f.Add(intent)
	f.Add([]byte(`{"protocol_version":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := DefaultLimits()
		limits.MaxIntentBytes = 1 << 20
		_, _ = ParseRevealIntent(data, limits)
	})
}

func newRevealDocuments(t testing.TB, value fixture) ([]byte, []byte) {
	t.Helper()
	var manifest recovery.ManifestPayload
	if err := json.Unmarshal(value.bundle.Manifests[0].CanonicalManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	selected := manifest.Accounts[0].Batches[0]
	intent := RevealIntent{ProtocolVersion: RevealIntentVersion, RevealID: "reveal-1", Nonce: hashHex("nonce"),
		BundleHash: hashText(value.bundleJSON), ManifestHash: value.bundle.Manifests[0].ManifestHash,
		PolicyHash: hashText(value.policyJSON), PoolID: manifest.PoolID, Epoch: manifest.Epoch,
		Purpose: "INCIDENT_RESPONSE", CaseReference: "case-1", OutputPolicy: "review-room-redacted-v1",
		EvidenceReferences: []string{"evidence-1"},
		CreatedAt:          "2026-08-21T08:02:00Z", NotBefore: "2026-08-21T08:05:00Z",
		ExpiresAt: "2026-08-21T09:00:00Z", GovernanceThreshold: manifest.GovernanceThreshold,
		Batches: []RevealBatch{{BatchID: selected.ToBatchID, AccountRef: manifest.Accounts[0].AccountRef,
			BatchType: selected.BatchType, BatchVersion: selected.ToBatchVersion,
			CiphertextHash: selected.ToCiphertextHash, RecoveryWrapHash: selected.ToRecoveryWrapHash}}}
	message, err := BuildRevealApprovalMessage(intent)
	if err != nil {
		t.Fatal(err)
	}
	approvals := RevealApprovalsDocument{ProtocolVersion: RevealApprovalsVersion}
	for _, member := range manifest.Members {
		approvals.Approvals = append(approvals.Approvals, RevealApproval{MemberID: member.MemberID,
			Algorithm: SignatureAlgorithmEd25519, KeyID: member.SigningKeyID,
			Signature: ed25519.Sign(value.memberPrivate[member.MemberID], message)})
	}
	return mustCanonical(t, intent), mustCanonical(t, approvals)
}

func newFixture(t testing.TB, revealState RevealPolicyState) fixture {
	t.Helper()
	memberPrivate := make(map[string]ed25519.PrivateKey)
	members := make([]recovery.ManifestMember, 0, 2)
	shares := make([]recovery.ManifestEncryptedShare, 0, 2)
	for index, memberID := range []string{"member-a", "member-b"} {
		seed := sha256.Sum256([]byte("signing-" + memberID))
		private := ed25519.NewKeyFromSeed(seed[:])
		public := append([]byte(nil), private.Public().(ed25519.PublicKey)...)
		recoveryPublicHash := sha256.Sum256([]byte("recovery-public-" + memberID))
		recoveryPublic := append([]byte(nil), recoveryPublicHash[:]...)
		members = append(members, recovery.ManifestMember{MemberID: memberID, Role: "OWNER", ShareIndex: uint16(index + 1),
			SigningAlgorithm: SignatureAlgorithmEd25519, SigningKeyID: "signing-key-" + memberID,
			SigningKeyFingerprint: hashBytes(public), SigningPublicKey: public,
			RecoveryEncryptionAlgorithm: "HPKE-X25519", RecoveryEncryptionKeyID: "recovery-key-" + memberID,
			RecoveryEncryptionKeyHash: hashBytes(recoveryPublic), RecoveryEncryptionPublicKey: recoveryPublic})
		shares = append(shares, recovery.ManifestEncryptedShare{MemberID: memberID, ShareIndex: uint16(index + 1),
			CiphertextHash: hashHex("cipher-" + memberID), ProviderProofHash: hashHex("proof-" + memberID),
			ProviderCommitment: hashHex("commitment-" + memberID)})
		memberPrivate[memberID] = private
	}
	seats := []recovery.SeatPlan{
		{SeatID: "seat-a", MemberID: "member-a", PrincipalUserID: 1, SubscriptionID: 11, APIKeyID: 21,
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-a", FreezeSnapshotHash: hashHex("freeze-a")},
		{SeatID: "seat-b", MemberID: "member-b", PrincipalUserID: 2, SubscriptionID: 12, APIKeyID: 22,
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-b", FreezeSnapshotHash: hashHex("freeze-b")},
	}
	accounts := []recovery.ResourceAccountPlan{
		validAccount("account-a", "seat-a", "a"), validAccount("account-b", "seat-b", "b"),
	}
	setHash, err := recovery.ProviderAttestationSetHash(accounts)
	if err != nil {
		t.Fatal(err)
	}
	payload := recovery.ManifestPayload{ProtocolVersion: recovery.ProtocolVersionV1, CeremonyType: recovery.CeremonyRotate,
		OperationID: "op-1", PoolID: "pool-1", FromEpoch: 1, FromEpochStatus: "ACTIVE",
		FromGovernanceState: "CURRENT", Epoch: 2, CreatedAt: "2026-08-21T08:00:00Z",
		GovernanceThreshold: 2, RecoveryThreshold: 2, RequiredShareAcknowledges: 2,
		PreviousManifestHash: hashHex("checkpoint"), ProviderAttestationSetHash: encodeHash(setHash),
		CeremonyAttestationDigest: hashHex("ceremony-attestation"), CeremonyAttestationPurpose: "ROTATION_CONTROL",
		CeremonyAttestationIssuer: "provider", CeremonyAttestationKeyID: "provider-key",
		CeremonyAttestationReference: "ceremony-ref", CeremonyAttestationVersion: 1,
		Members: members, Seats: seats,
		Replacements: []recovery.OwnerReplacementPlan{{SeatID: "seat-a", FromMemberID: "old-member-a", ToMemberID: "member-a",
			ExpectedAssignmentEpoch: 2, FreezeOperationID: "freeze-a", FreezeSnapshotHash: hashHex("freeze-a")}},
		Accounts: accounts, EncryptedShares: shares,
		RecoveryRoot: recovery.ManifestRootBinding{PublicAlgorithm: "HPKE-X25519", PublicHandle: "root-handle",
			PublicFingerprint: hashHex("root-public"), WrapDomain: "recovery-wrap", WrapAlgorithm: "HPKE-X25519-AES256GCM",
			ProviderID: "root-provider", KeyVersion: "root-version", PrivateCommitmentHash: hashHex("private-commitment"),
			VSSAlgorithm: "FELDMAN-VSS", VSSCommitmentHash: hashHex("vss"), VSSProofHash: hashHex("vss-proof"),
			PackageHash: hashHex("package")}}
	canonicalManifest := mustCanonical(t, payload)
	manifestHash := sha256.Sum256(canonicalManifest)

	platformSeed := sha256.Sum256([]byte("platform-key"))
	platformPrivate := ed25519.NewKeyFromSeed(platformSeed[:])
	providerSeed := sha256.Sum256([]byte("provider-key"))
	providerPrivate := ed25519.NewKeyFromSeed(providerSeed[:])
	rootProviderSeed := sha256.Sum256([]byte("root-provider-key"))
	rootProviderPrivate := ed25519.NewKeyFromSeed(rootProviderSeed[:])
	platformMessage, _ := BuildPlatformManifestSignatureMessage(canonicalManifest)
	evidence := ManifestEvidence{CanonicalManifest: canonicalManifest, ManifestHash: encodeHash(manifestHash),
		PlatformSignature: SignatureEvidence{Domain: PlatformSignatureDomainV2, Algorithm: SignatureAlgorithmEd25519,
			KeyID: "platform-key", Signature: ed25519.Sign(platformPrivate, platformMessage)}}
	rootCommitmentHash := hashHex("root-commitment")
	for _, member := range members {
		approvalMessage, _ := recovery.BuildMemberManifestSignatureMessage(recovery.MemberManifestApproval{Version: 1,
			CeremonyType: payload.CeremonyType, OperationID: payload.OperationID, PoolID: payload.PoolID,
			Epoch: payload.Epoch, MemberID: member.MemberID, ManifestHash: manifestHash})
		evidence.MemberApprovals = append(evidence.MemberApprovals, MemberApprovalEvidence{MemberID: member.MemberID,
			Algorithm: SignatureAlgorithmEd25519, KeyID: member.SigningKeyID,
			Signature: ed25519.Sign(memberPrivate[member.MemberID], approvalMessage)})
		share := shares[int(member.ShareIndex)-1]
		ack := recovery.ShareAcknowledgement{Version: 1, CeremonyType: payload.CeremonyType, OperationID: payload.OperationID,
			DeliveryID: "delivery-" + member.MemberID, PoolID: payload.PoolID, Epoch: payload.Epoch,
			MemberID: member.MemberID, ShareIndex: member.ShareIndex, ManifestHash: manifestHash, VerifiedCommitment: true}
		mustDecodeHash(t, share.CiphertextHash, &ack.CiphertextHash)
		mustDecodeHash(t, rootCommitmentHash, &ack.RootCommitmentHash)
		mustDecodeHash(t, payload.RecoveryRoot.VSSCommitmentHash, &ack.VSSCommitmentHash)
		ackMessage, _ := recovery.BuildShareAcknowledgementMessage(ack)
		evidence.ShareAcknowledgements = append(evidence.ShareAcknowledgements, ShareAcknowledgementEvidence{
			DeliveryID: ack.DeliveryID, MemberID: member.MemberID, ShareIndex: member.ShareIndex,
			CiphertextHash: share.CiphertextHash, RootCommitmentHash: rootCommitmentHash,
			VSSCommitmentHash: payload.RecoveryRoot.VSSCommitmentHash, VerifiedCommitment: true,
			Algorithm: SignatureAlgorithmEd25519, KeyID: member.SigningKeyID,
			Signature: ed25519.Sign(memberPrivate[member.MemberID], ackMessage)})
	}
	statements := []ProviderStatement{
		{ProtocolVersion: ProviderStatementVersion, Kind: ProviderProofCeremony, ProviderID: "provider",
			OperationID: payload.OperationID,
			PoolID:      payload.PoolID, Epoch: payload.Epoch, SubjectHash: payload.CeremonyAttestationDigest},
		{ProtocolVersion: ProviderStatementVersion, Kind: ProviderProofPackage, ProviderID: "root-provider",
			OperationID: payload.OperationID,
			PoolID:      payload.PoolID, Epoch: payload.Epoch, SubjectHash: payload.RecoveryRoot.PackageHash},
	}
	for _, account := range accounts {
		statements = append(statements, ProviderStatement{ProtocolVersion: ProviderStatementVersion, Kind: ProviderProofAccount,
			ProviderID: "provider", OperationID: payload.OperationID, PoolID: payload.PoolID, Epoch: payload.Epoch,
			AccountRef: account.AccountRef, SubjectHash: account.ProviderAttestationDigest})
	}
	for _, share := range shares {
		statements = append(statements, ProviderStatement{ProtocolVersion: ProviderStatementVersion, Kind: ProviderProofShare,
			ProviderID: "root-provider", OperationID: payload.OperationID, PoolID: payload.PoolID,
			Epoch: payload.Epoch, MemberID: share.MemberID,
			ShareIndex: share.ShareIndex, SubjectHash: share.ProviderProofHash})
	}
	for _, statement := range statements {
		message, _ := BuildProviderProofMessage(statement)
		keyID := "provider-key"
		private := providerPrivate
		if statement.ProviderID == "root-provider" {
			keyID = "root-provider-key"
			private = rootProviderPrivate
		}
		evidence.ProviderProofs = append(evidence.ProviderProofs, ProviderProofEvidence{Statement: statement,
			Algorithm: SignatureAlgorithmEd25519, KeyID: keyID, Signature: ed25519.Sign(private, message)})
	}
	bundle := Bundle{ProtocolVersion: BundleProtocolVersion, BundleID: "bundle-1", ExportedAt: "2026-08-21T08:01:00Z",
		Manifests: []ManifestEvidence{evidence}}
	policy := TrustPolicy{ProtocolVersion: TrustPolicyProtocolVersion, PolicyID: "policy-1",
		Checkpoint:   ManifestCheckpoint{PoolID: payload.PoolID, Epoch: payload.FromEpoch, ManifestHash: payload.PreviousManifestHash},
		PlatformKeys: []TrustedEd25519Key{{KeyID: "platform-key", PublicKey: platformPrivate.Public().(ed25519.PublicKey)}},
		ProviderKeys: []TrustedProviderEd25519Key{
			{ProviderID: "provider", KeyID: "provider-key",
				AllowedProofKinds: []ProviderProofKind{ProviderProofAccount, ProviderProofCeremony},
				PublicKey:         providerPrivate.Public().(ed25519.PublicKey)},
			{ProviderID: "root-provider", KeyID: "root-provider-key",
				AllowedProofKinds: []ProviderProofKind{ProviderProofPackage, ProviderProofShare},
				PublicKey:         rootProviderPrivate.Public().(ed25519.PublicKey)},
		},
		RevealPolicyState: revealState}
	return fixture{bundleJSON: mustCanonical(t, bundle), policyJSON: mustCanonical(t, policy), bundle: bundle,
		policy: policy, memberPrivate: memberPrivate}
}

func validAccount(accountID, seatID, suffix string) recovery.ResourceAccountPlan {
	batches := make([]recovery.ControlBatchPlan, 0, 4)
	for _, batchType := range []string{"LOGIN", "MFA", "RECOVERY", "OWNERSHIP"} {
		lower := strings.ToLower(batchType)
		batches = append(batches, recovery.ControlBatchPlan{BatchType: batchType,
			FromBatchID: "old-" + lower + "-" + suffix, FromBatchVersion: 1,
			FromCiphertextHash: hashHex("old-" + batchType + "-" + suffix),
			ToBatchID:          "new-" + lower + "-" + suffix, ToBatchVersion: 2,
			ToCiphertextHash:   hashHex("new-" + batchType + "-" + suffix),
			ToRecoveryWrapHash: hashHex("wrap-" + batchType + "-" + suffix)})
	}
	return recovery.ResourceAccountPlan{AccountID: accountID, SeatIDs: []string{seatID}, AccountRef: "ref-" + suffix,
		ProviderBinding: "provider-" + suffix, ControlEvidenceID: "evidence-" + suffix,
		ProviderAttestationDigest: hashHex("account-attestation-" + suffix), ProviderAttestationIssuer: "provider",
		ProviderAttestationKeyID: "provider-key", ProviderAttestationVersion: 1,
		ProviderAttestationAlgorithm:       SignatureAlgorithmEd25519,
		ProviderAttestationSignature:       []byte("account-signature-" + suffix),
		ProviderAttestationProtocolVersion: ProviderStatementVersion, Batches: batches}
}

func mustCanonical(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func hashHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func mustDecodeHash(t testing.TB, value string, target *[sha256.Size]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	copy(target[:], decoded)
}
