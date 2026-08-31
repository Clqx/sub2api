package offline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

type manifestView struct {
	evidence ManifestEvidence
	payload  recovery.ManifestPayload
	hash     [sha256.Size]byte
}

type providerProofExpectation struct {
	subjectHash string
	providerID  string
	keyID       string
}

type trustedProviderKey struct {
	publicKey    ed25519.PublicKey
	allowedKinds map[ProviderProofKind]struct{}
}

type providerKeyReference struct {
	providerID string
	keyID      string
}

func Verify(bundleJSON, policyJSON []byte, limits Limits) Report {
	report, _ := VerifyDetailed(bundleJSON, policyJSON, limits)
	return report
}

func VerifyDetailed(bundleJSON, policyJSON []byte, limits Limits) (Report, *VerifiedBundle) {
	report := Report{ProtocolVersion: ReportProtocolVersion, Verdict: VerdictRejected, ReasonCode: ReasonSchemaInvalid}
	bundle, err := ParseBundle(bundleJSON, limits)
	if err != nil {
		report.ReasonCode = reasonOf(err, ReasonSchemaInvalid)
		return report, nil
	}
	policy, err := ParseTrustPolicy(policyJSON, limits)
	if err != nil {
		report.ReasonCode = reasonOf(err, ReasonTrustPolicyInvalid)
		return report, nil
	}
	report.BundleHash = hashText(bundleJSON)
	policyHash := hashText(policyJSON)
	limits = normalizedLimits(limits)
	if err := validateBundleShape(*bundle, limits); err != nil {
		report.ReasonCode = reasonOf(err, ReasonSchemaInvalid)
		return report, nil
	}
	platformKeys, providerKeys, err := validateTrustPolicy(*policy)
	if err != nil {
		report.ReasonCode = reasonOf(err, ReasonTrustPolicyInvalid)
		return report, nil
	}

	views := make([]manifestView, len(bundle.Manifests))
	firstIncomplete := ReasonCode("")
	for index := range bundle.Manifests {
		view, incomplete, verifyErr := verifyManifestEvidence(bundle.Manifests[index], platformKeys, providerKeys, limits)
		if verifyErr != nil {
			report.ReasonCode = reasonOf(verifyErr, ReasonManifestInvalid)
			return report, nil
		}
		if firstIncomplete == "" && incomplete != "" {
			firstIncomplete = incomplete
		}
		views[index] = view
	}
	if err := verifyManifestChain(views, policy.Checkpoint); err != nil {
		report.ReasonCode = reasonOf(err, ReasonManifestChainInvalid)
		return report, nil
	}
	first, last := views[0], views[len(views)-1]
	report.PoolID, report.FirstEpoch, report.LastEpoch = first.payload.PoolID, first.payload.Epoch, last.payload.Epoch
	report.ManifestCount = len(views)
	verified := &VerifiedBundle{BundleHash: report.BundleHash, PolicyHash: policyHash, PoolID: last.payload.PoolID,
		LastEpoch: last.payload.Epoch, LastHash: encodeHash(last.hash),
		LastManifest: append([]byte(nil), last.evidence.CanonicalManifest...)}
	if firstIncomplete != "" {
		report.Verdict, report.ReasonCode = VerdictIncomplete, firstIncomplete
		return report, verified
	}
	report.Verdict, report.ReasonCode = VerdictVerified, ReasonOK
	return report, verified
}

func validateBundleShape(bundle Bundle, limits Limits) error {
	if bundle.ProtocolVersion != BundleProtocolVersion {
		return fail(ReasonProtocolUnsupported)
	}
	if !validID(bundle.BundleID) || len(bundle.Manifests) == 0 || len(bundle.Manifests) > limits.MaxManifests {
		return fail(ReasonSchemaInvalid)
	}
	if _, err := parseCanonicalTime(bundle.ExportedAt); err != nil {
		return fail(ReasonSchemaInvalid)
	}
	return nil
}

func validateTrustPolicy(policy TrustPolicy) (map[string]ed25519.PublicKey,
	map[providerKeyReference]trustedProviderKey, error) {
	if policy.ProtocolVersion != TrustPolicyProtocolVersion || !validID(policy.PolicyID) ||
		!validID(policy.Checkpoint.PoolID) || policy.Checkpoint.Epoch == 0 || !validHash(policy.Checkpoint.ManifestHash) ||
		(policy.RevealPolicyState != RevealPolicyApproved && policy.RevealPolicyState != RevealPolicyUnapproved) {
		return nil, nil, fail(ReasonTrustPolicyInvalid)
	}
	platform, err := trustedKeyMap(policy.PlatformKeys)
	if err != nil || len(platform) == 0 {
		return nil, nil, fail(ReasonTrustPolicyInvalid)
	}
	provider, err := trustedProviderKeyMap(policy.ProviderKeys)
	if err != nil {
		return nil, nil, fail(ReasonTrustPolicyInvalid)
	}
	return platform, provider, nil
}

func trustedKeyMap(keys []TrustedEd25519Key) (map[string]ed25519.PublicKey, error) {
	result := make(map[string]ed25519.PublicKey, len(keys))
	for _, key := range keys {
		if !validID(key.KeyID) || len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, fail(ReasonTrustPolicyInvalid)
		}
		if _, duplicate := result[key.KeyID]; duplicate {
			return nil, fail(ReasonTrustPolicyInvalid)
		}
		result[key.KeyID] = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	return result, nil
}

func trustedProviderKeyMap(keys []TrustedProviderEd25519Key) (map[providerKeyReference]trustedProviderKey, error) {
	result := make(map[providerKeyReference]trustedProviderKey, len(keys))
	for _, key := range keys {
		if !validID(key.ProviderID) || !validID(key.KeyID) || len(key.PublicKey) != ed25519.PublicKeySize ||
			len(key.AllowedProofKinds) == 0 {
			return nil, fail(ReasonTrustPolicyInvalid)
		}
		allowed := make(map[ProviderProofKind]struct{}, len(key.AllowedProofKinds))
		for index, kind := range key.AllowedProofKinds {
			if !validProviderProofKind(kind) || (index > 0 && key.AllowedProofKinds[index-1] >= kind) {
				return nil, fail(ReasonTrustPolicyInvalid)
			}
			allowed[kind] = struct{}{}
		}
		identity := providerKeyIdentity(key.ProviderID, key.KeyID)
		if _, duplicate := result[identity]; duplicate {
			return nil, fail(ReasonTrustPolicyInvalid)
		}
		result[identity] = trustedProviderKey{publicKey: append(ed25519.PublicKey(nil), key.PublicKey...),
			allowedKinds: allowed}
	}
	return result, nil
}

func verifyManifestEvidence(evidence ManifestEvidence, platformKeys map[string]ed25519.PublicKey,
	providerKeys map[providerKeyReference]trustedProviderKey,
	limits Limits) (manifestView, ReasonCode, error) {
	var view manifestView
	if len(evidence.CanonicalManifest) == 0 || len(evidence.CanonicalManifest) > limits.MaxManifestBytes ||
		len(evidence.PlatformSignature.Signature) > limits.MaxEvidenceBytes {
		return view, "", fail(ReasonInputTooLarge)
	}
	var payload recovery.ManifestPayload
	if err := decodeStrictCanonical(evidence.CanonicalManifest, int64(limits.MaxManifestBytes), &payload); err != nil {
		return view, "", fail(ReasonManifestInvalid)
	}
	if payload.RecoveryThreshold > payload.GovernanceThreshold ||
		payload.GovernanceThreshold > uint16(len(payload.Members)) || len(payload.Members) > limits.MaxMembers {
		return view, "", fail(ReasonThresholdInvalid)
	}
	if err := recovery.ValidateManifestPayload(payload); err != nil {
		return view, "", fail(ReasonManifestInvalid)
	}
	hash := sha256.Sum256(evidence.CanonicalManifest)
	if !validHash(evidence.ManifestHash) || evidence.ManifestHash != encodeHash(hash) {
		return view, "", fail(ReasonManifestHashMismatch)
	}
	view = manifestView{evidence: evidence, payload: payload, hash: hash}

	incomplete := ReasonCode("")
	if code, err := verifyPlatformSignature(evidence, platformKeys); err != nil {
		return view, "", err
	} else if code != "" {
		incomplete = code
	}
	if code, err := verifyMemberApprovals(view, limits.MaxEvidenceBytes); err != nil {
		return view, "", err
	} else if incomplete == "" && code != "" {
		incomplete = code
	}
	if code, err := verifyShareAcknowledgements(view, limits.MaxEvidenceBytes); err != nil {
		return view, "", err
	} else if incomplete == "" && code != "" {
		incomplete = code
	}
	if code, err := verifyProviderProofs(view, providerKeys, limits.MaxEvidenceBytes); err != nil {
		return view, "", err
	} else if incomplete == "" && code != "" {
		incomplete = code
	}
	return view, incomplete, nil
}

func verifyPlatformSignature(evidence ManifestEvidence, keys map[string]ed25519.PublicKey) (ReasonCode, error) {
	signature := evidence.PlatformSignature
	if signature.Domain != PlatformSignatureDomainV2 {
		return ReasonLegacySignatureUnsupported, nil
	}
	if signature.Algorithm != SignatureAlgorithmEd25519 {
		return ReasonAlgorithmUnsupported, nil
	}
	key, exists := keys[signature.KeyID]
	if !exists {
		return "", fail(ReasonUntrustedKey)
	}
	message, err := BuildPlatformManifestSignatureMessage(evidence.CanonicalManifest)
	if err != nil || len(signature.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature.Signature) {
		return "", fail(ReasonSignatureInvalid)
	}
	return "", nil
}

func verifyMemberApprovals(view manifestView, maxEvidenceBytes int) (ReasonCode, error) {
	for _, evidence := range view.evidence.MemberApprovals {
		if len(evidence.Signature) > maxEvidenceBytes {
			return "", fail(ReasonInputTooLarge)
		}
	}
	members := manifestMemberMap(view.payload.Members)
	seen := make(map[string]struct{}, len(view.evidence.MemberApprovals))
	incomplete := ReasonCode("")
	for _, evidence := range view.evidence.MemberApprovals {
		member, exists := members[evidence.MemberID]
		if !exists || evidence.Algorithm != member.SigningAlgorithm || evidence.KeyID != member.SigningKeyID {
			return "", fail(ReasonSetMismatch)
		}
		if _, duplicate := seen[evidence.MemberID]; duplicate {
			return "", fail(ReasonSetMismatch)
		}
		seen[evidence.MemberID] = struct{}{}
		if evidence.Algorithm != SignatureAlgorithmEd25519 {
			incomplete = ReasonAlgorithmUnsupported
			continue
		}
		approval := recovery.MemberManifestApproval{Version: 1, CeremonyType: view.payload.CeremonyType,
			OperationID: view.payload.OperationID, PoolID: view.payload.PoolID, Epoch: view.payload.Epoch,
			MemberID: member.MemberID, ManifestHash: view.hash}
		message, err := recovery.BuildMemberManifestSignatureMessage(approval)
		if err != nil || len(member.SigningPublicKey) != ed25519.PublicKeySize ||
			len(evidence.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(member.SigningPublicKey), message, evidence.Signature) {
			return "", fail(ReasonSignatureInvalid)
		}
	}
	if len(seen) < int(view.payload.GovernanceThreshold) {
		return ReasonMemberApprovalsIncomplete, nil
	}
	return incomplete, nil
}

func verifyShareAcknowledgements(view manifestView, maxEvidenceBytes int) (ReasonCode, error) {
	for _, evidence := range view.evidence.ShareAcknowledgements {
		if len(evidence.Signature) > maxEvidenceBytes {
			return "", fail(ReasonInputTooLarge)
		}
	}
	if len(view.evidence.ShareAcknowledgements) > len(view.payload.Members) {
		return "", fail(ReasonSetMismatch)
	}
	members := manifestMemberMap(view.payload.Members)
	shares := manifestShareMap(view.payload.EncryptedShares)
	seen := make(map[string]struct{}, len(view.evidence.ShareAcknowledgements))
	rootHash := ""
	incomplete := ReasonCode("")
	for _, evidence := range view.evidence.ShareAcknowledgements {
		member, exists := members[evidence.MemberID]
		share, shareExists := shares[evidence.MemberID]
		if !exists || !shareExists || evidence.ShareIndex != member.ShareIndex || share.ShareIndex != member.ShareIndex ||
			evidence.CiphertextHash != share.CiphertextHash ||
			evidence.VSSCommitmentHash != view.payload.RecoveryRoot.VSSCommitmentHash ||
			!evidence.VerifiedCommitment || evidence.Algorithm != member.SigningAlgorithm || evidence.KeyID != member.SigningKeyID ||
			!validID(evidence.DeliveryID) || !validHash(evidence.RootCommitmentHash) {
			return "", fail(ReasonSetMismatch)
		}
		if rootHash == "" {
			rootHash = evidence.RootCommitmentHash
		} else if rootHash != evidence.RootCommitmentHash {
			return "", fail(ReasonSetMismatch)
		}
		if _, duplicate := seen[evidence.MemberID]; duplicate {
			return "", fail(ReasonSetMismatch)
		}
		seen[evidence.MemberID] = struct{}{}
		if evidence.Algorithm != SignatureAlgorithmEd25519 {
			incomplete = ReasonAlgorithmUnsupported
			continue
		}
		ack := recovery.ShareAcknowledgement{Version: 1, CeremonyType: view.payload.CeremonyType,
			OperationID: view.payload.OperationID, DeliveryID: evidence.DeliveryID, PoolID: view.payload.PoolID,
			Epoch: view.payload.Epoch, MemberID: evidence.MemberID, ShareIndex: evidence.ShareIndex,
			VerifiedCommitment: true, ManifestHash: view.hash}
		if !decodeHashInto(evidence.CiphertextHash, &ack.CiphertextHash) ||
			!decodeHashInto(evidence.RootCommitmentHash, &ack.RootCommitmentHash) ||
			!decodeHashInto(evidence.VSSCommitmentHash, &ack.VSSCommitmentHash) {
			return "", fail(ReasonSetMismatch)
		}
		message, err := recovery.BuildShareAcknowledgementMessage(ack)
		if err != nil || len(member.SigningPublicKey) != ed25519.PublicKeySize ||
			len(evidence.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(member.SigningPublicKey), message, evidence.Signature) {
			return "", fail(ReasonSignatureInvalid)
		}
	}
	if len(seen) < len(view.payload.Members) {
		return ReasonShareAcknowledgesIncomplete, nil
	}
	return incomplete, nil
}

func verifyProviderProofs(view manifestView, keys map[providerKeyReference]trustedProviderKey,
	maxEvidenceBytes int) (ReasonCode, error) {
	for _, evidence := range view.evidence.ProviderProofs {
		if len(evidence.Signature) > maxEvidenceBytes {
			return "", fail(ReasonInputTooLarge)
		}
	}
	wantCount := len(view.payload.EncryptedShares) + len(view.payload.Accounts) + 2
	if len(view.evidence.ProviderProofs) > wantCount {
		return "", fail(ReasonProviderEvidenceInvalid)
	}
	wants := make(map[string]providerProofExpectation, wantCount)
	wants[string(ProviderProofCeremony)+"/"] = providerProofExpectation{
		subjectHash: view.payload.CeremonyAttestationDigest, providerID: view.payload.CeremonyAttestationIssuer,
		keyID: view.payload.CeremonyAttestationKeyID}
	wants[string(ProviderProofPackage)+"/"] = providerProofExpectation{
		subjectHash: view.payload.RecoveryRoot.PackageHash, providerID: view.payload.RecoveryRoot.ProviderID}
	for _, account := range view.payload.Accounts {
		wants[string(ProviderProofAccount)+"/"+account.AccountRef] = providerProofExpectation{
			subjectHash: account.ProviderAttestationDigest, providerID: account.ProviderAttestationIssuer,
			keyID: account.ProviderAttestationKeyID}
	}
	for _, share := range view.payload.EncryptedShares {
		wants[string(ProviderProofShare)+"/"+share.MemberID] = providerProofExpectation{
			subjectHash: share.ProviderProofHash, providerID: view.payload.RecoveryRoot.ProviderID}
	}
	seen := make(map[string]struct{}, wantCount)
	incomplete := ReasonCode("")
	for _, proof := range view.evidence.ProviderProofs {
		statement := proof.Statement
		identity := statement.MemberID
		if statement.Kind == ProviderProofAccount {
			identity = statement.AccountRef
		}
		keyName := string(statement.Kind) + "/" + identity
		want, exists := wants[keyName]
		if !exists || statement.ProtocolVersion != ProviderStatementVersion ||
			statement.OperationID != view.payload.OperationID || statement.PoolID != view.payload.PoolID ||
			statement.Epoch != view.payload.Epoch || statement.SubjectHash != want.subjectHash ||
			statement.ProviderID != want.providerID ||
			!validID(proof.Algorithm) || !validID(proof.KeyID) || (want.keyID != "" && proof.KeyID != want.keyID) {
			return "", fail(ReasonProviderEvidenceInvalid)
		}
		if statement.Kind == ProviderProofShare {
			share := manifestShareMap(view.payload.EncryptedShares)[statement.MemberID]
			if share.ShareIndex != statement.ShareIndex || statement.ShareIndex == 0 || statement.AccountRef != "" {
				return "", fail(ReasonProviderEvidenceInvalid)
			}
		} else if statement.Kind == ProviderProofAccount {
			if !validID(statement.AccountRef) || statement.MemberID != "" || statement.ShareIndex != 0 {
				return "", fail(ReasonProviderEvidenceInvalid)
			}
		} else if statement.MemberID != "" || statement.AccountRef != "" || statement.ShareIndex != 0 {
			return "", fail(ReasonProviderEvidenceInvalid)
		}
		if _, duplicate := seen[keyName]; duplicate {
			return "", fail(ReasonProviderEvidenceInvalid)
		}
		seen[keyName] = struct{}{}
		if proof.Algorithm != SignatureAlgorithmEd25519 {
			incomplete = ReasonProviderEvidenceIncomplete
			continue
		}
		key, trusted := keys[providerKeyIdentity(statement.ProviderID, proof.KeyID)]
		if !trusted {
			return "", fail(ReasonUntrustedKey)
		}
		if _, allowed := key.allowedKinds[statement.Kind]; !allowed {
			return "", fail(ReasonProviderEvidenceInvalid)
		}
		message, err := BuildProviderProofMessage(statement)
		if err != nil || len(proof.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(key.publicKey, message, proof.Signature) {
			return "", fail(ReasonSignatureInvalid)
		}
	}
	if len(seen) < wantCount {
		return ReasonProviderEvidenceIncomplete, nil
	}
	return incomplete, nil
}

func verifyManifestChain(views []manifestView, checkpoint ManifestCheckpoint) error {
	if len(views) == 0 {
		return fail(ReasonManifestChainInvalid)
	}
	first := views[0]
	if first.payload.PoolID != checkpoint.PoolID {
		return fail(ReasonCheckpointMismatch)
	}
	anchoredAtManifest := first.payload.Epoch == checkpoint.Epoch && encodeHash(first.hash) == checkpoint.ManifestHash
	anchoredAtPrevious := first.payload.FromEpoch == checkpoint.Epoch &&
		first.payload.PreviousManifestHash == checkpoint.ManifestHash
	if !anchoredAtManifest && !anchoredAtPrevious {
		return fail(ReasonCheckpointMismatch)
	}
	for index := 1; index < len(views); index++ {
		previous, current := views[index-1], views[index]
		if current.payload.PoolID != previous.payload.PoolID || current.payload.FromEpoch != previous.payload.Epoch ||
			current.payload.Epoch != previous.payload.Epoch+1 ||
			current.payload.PreviousManifestHash != encodeHash(previous.hash) {
			return fail(ReasonManifestChainInvalid)
		}
	}
	return nil
}

func validateProviderStatementShape(statement ProviderStatement) error {
	if statement.ProtocolVersion != ProviderStatementVersion || !validID(statement.ProviderID) ||
		!validID(statement.OperationID) ||
		!validID(statement.PoolID) || statement.Epoch == 0 || !validHash(statement.SubjectHash) {
		return fail(ReasonProviderEvidenceInvalid)
	}
	switch statement.Kind {
	case ProviderProofCeremony, ProviderProofPackage:
		if statement.MemberID != "" || statement.AccountRef != "" || statement.ShareIndex != 0 {
			return fail(ReasonProviderEvidenceInvalid)
		}
	case ProviderProofAccount:
		if !validID(statement.AccountRef) || statement.MemberID != "" || statement.ShareIndex != 0 {
			return fail(ReasonProviderEvidenceInvalid)
		}
	case ProviderProofShare:
		if !validID(statement.MemberID) || statement.AccountRef != "" || statement.ShareIndex == 0 {
			return fail(ReasonProviderEvidenceInvalid)
		}
	default:
		return fail(ReasonProtocolUnsupported)
	}
	return nil
}

func validProviderProofKind(kind ProviderProofKind) bool {
	switch kind {
	case ProviderProofCeremony, ProviderProofAccount, ProviderProofPackage, ProviderProofShare:
		return true
	default:
		return false
	}
}

func providerKeyIdentity(providerID, keyID string) providerKeyReference {
	return providerKeyReference{providerID: providerID, keyID: keyID}
}

func manifestMemberMap(values []recovery.ManifestMember) map[string]recovery.ManifestMember {
	result := make(map[string]recovery.ManifestMember, len(values))
	for _, value := range values {
		result[value.MemberID] = value
	}
	return result
}

func manifestShareMap(values []recovery.ManifestEncryptedShare) map[string]recovery.ManifestEncryptedShare {
	result := make(map[string]recovery.ManifestEncryptedShare, len(values))
	for _, value := range values {
		result[value.MemberID] = value
	}
	return result
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fail(ReasonSchemaInvalid)
	}
	return parsed, nil
}

func decodeHashInto(value string, target *[sha256.Size]byte) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	copy(target[:], decoded)
	return true
}

func encodeHash(value [sha256.Size]byte) string { return hex.EncodeToString(value[:]) }

func sortedUniqueStrings(values []string) bool {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	for index := range copyValues {
		if !validID(copyValues[index]) || (index > 0 && copyValues[index] == copyValues[index-1]) {
			return false
		}
	}
	return bytes.Equal([]byte(joinStrings(values)), []byte(joinStrings(copyValues)))
}

func joinStrings(values []string) string {
	var result bytes.Buffer
	for _, value := range values {
		result.WriteString(value)
		result.WriteByte(0)
	}
	return result.String()
}
