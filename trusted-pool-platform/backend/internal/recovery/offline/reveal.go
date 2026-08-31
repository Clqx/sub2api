package offline

import (
	"crypto/ed25519"
	"sort"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

func EvaluateRevealAuthorization(bundleJSON, policyJSON, intentJSON, approvalsJSON []byte,
	verificationTime time.Time, limits Limits) RevealReport {
	limits = normalizedLimits(limits)
	report := RevealReport{ProtocolVersion: RevealReportVersion, Verdict: RevealVerdictRejected,
		ReasonCode: ReasonRevealIntentInvalid}
	if !verificationTime.IsZero() && verificationTime.Location() == time.UTC {
		report.EvaluationTime = verificationTime.Format(time.RFC3339Nano)
	}
	bundleReport, verified := VerifyDetailed(bundleJSON, policyJSON, limits)
	if bundleReport.Verdict != VerdictVerified || verified == nil {
		report.ReasonCode = bundleReport.ReasonCode
		return report
	}
	policy, err := ParseTrustPolicy(policyJSON, limits)
	if err != nil {
		report.ReasonCode = ReasonTrustPolicyInvalid
		return report
	}
	intent, err := ParseRevealIntent(intentJSON, limits)
	if err != nil || validateRevealIntentShape(*intent) != nil {
		report.ReasonCode = reasonOf(err, ReasonRevealIntentInvalid)
		return report
	}
	approvals, err := ParseRevealApprovals(approvalsJSON, limits)
	if err != nil {
		report.ReasonCode = reasonOf(err, ReasonRevealIntentInvalid)
		return report
	}
	if approvals.ProtocolVersion != RevealApprovalsVersion {
		report.ReasonCode = ReasonProtocolUnsupported
		return report
	}
	report.RevealID, report.PoolID, report.Epoch = intent.RevealID, intent.PoolID, intent.Epoch
	if intent.BundleHash != verified.BundleHash || intent.PolicyHash != verified.PolicyHash ||
		intent.ManifestHash != verified.LastHash || intent.PoolID != verified.PoolID || intent.Epoch != verified.LastEpoch {
		report.ReasonCode = ReasonSetMismatch
		return report
	}
	if verificationTime.IsZero() || verificationTime.Location() != time.UTC {
		report.ReasonCode = ReasonRevealIntentInvalid
		return report
	}
	notBefore, _ := parseCanonicalTime(intent.NotBefore)
	expiresAt, _ := parseCanonicalTime(intent.ExpiresAt)
	if verificationTime.Before(notBefore) || !verificationTime.Before(expiresAt) {
		report.ReasonCode = ReasonRevealIntentInvalid
		return report
	}
	var manifest recovery.ManifestPayload
	if err := decodeStrictCanonical(verified.LastManifest, int64(normalizedLimits(limits).MaxManifestBytes), &manifest); err != nil {
		report.ReasonCode = ReasonManifestInvalid
		return report
	}
	if intent.GovernanceThreshold != manifest.GovernanceThreshold ||
		!revealBatchesMatchManifest(intent.Batches, manifest.Accounts) {
		report.ReasonCode = ReasonSetMismatch
		return report
	}
	message, err := BuildRevealApprovalMessage(*intent)
	if err != nil {
		report.ReasonCode = ReasonRevealIntentInvalid
		return report
	}
	members := manifestMemberMap(manifest.Members)
	seen := make(map[string]struct{}, len(approvals.Approvals))
	for _, approval := range approvals.Approvals {
		if len(approval.Signature) > limits.MaxEvidenceBytes {
			report.ReasonCode = ReasonInputTooLarge
			return report
		}
		member, exists := members[approval.MemberID]
		if !exists || approval.Algorithm != member.SigningAlgorithm || approval.KeyID != member.SigningKeyID ||
			approval.Algorithm != SignatureAlgorithmEd25519 {
			report.ReasonCode = ReasonSetMismatch
			return report
		}
		if _, duplicate := seen[approval.MemberID]; duplicate {
			report.ReasonCode = ReasonSetMismatch
			return report
		}
		seen[approval.MemberID] = struct{}{}
		if len(member.SigningPublicKey) != ed25519.PublicKeySize || len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(member.SigningPublicKey), message, approval.Signature) {
			report.ReasonCode = ReasonSignatureInvalid
			return report
		}
	}
	report.ApprovalCount = len(seen)
	if len(seen) < int(manifest.GovernanceThreshold) {
		report.ReasonCode = ReasonRevealApprovalsIncomplete
		return report
	}
	if policy.RevealPolicyState != RevealPolicyApproved {
		report.Verdict, report.ReasonCode = RevealVerdictPolicyUnapproved, ReasonRevealPolicyUnapproved
		return report
	}
	// H1 刻意没有 decrypt/reconstruct/unwrap port；授权成立也只能形成审计结论。
	report.Verdict, report.ReasonCode = RevealVerdictAuthorizedNotExecutable, ReasonRevealAuthorizedNoExecutor
	return report
}

func validateRevealIntentShape(intent RevealIntent) error {
	if intent.ProtocolVersion != RevealIntentVersion || !validID(intent.RevealID) || !validHash(intent.Nonce) ||
		!validHash(intent.BundleHash) || !validHash(intent.ManifestHash) || !validHash(intent.PolicyHash) ||
		!validID(intent.PoolID) || intent.Epoch == 0 || !validID(intent.Purpose) ||
		!validID(intent.CaseReference) || !validProfileID(intent.OutputPolicy) ||
		intent.GovernanceThreshold == 0 || len(intent.Batches) == 0 ||
		len(intent.EvidenceReferences) == 0 || !sortedUniqueStrings(intent.EvidenceReferences) {
		return fail(ReasonRevealIntentInvalid)
	}
	createdAt, err1 := parseCanonicalTime(intent.CreatedAt)
	notBefore, err2 := parseCanonicalTime(intent.NotBefore)
	expiresAt, err3 := parseCanonicalTime(intent.ExpiresAt)
	if err1 != nil || err2 != nil || err3 != nil || notBefore.Before(createdAt) || !expiresAt.After(notBefore) {
		return fail(ReasonRevealIntentInvalid)
	}
	keys := make([]string, len(intent.Batches))
	for index, batch := range intent.Batches {
		if !validID(batch.BatchID) || !validID(batch.AccountRef) || !validID(batch.BatchType) ||
			batch.BatchVersion == 0 || !validHash(batch.CiphertextHash) || !validHash(batch.RecoveryWrapHash) {
			return fail(ReasonRevealIntentInvalid)
		}
		keys[index] = revealBatchKey(batch)
	}
	if !sort.StringsAreSorted(keys) {
		return fail(ReasonRevealIntentInvalid)
	}
	for index := 1; index < len(keys); index++ {
		if keys[index] == keys[index-1] {
			return fail(ReasonRevealIntentInvalid)
		}
	}
	return nil
}

func revealBatchesMatchManifest(selected []RevealBatch, accounts []recovery.ResourceAccountPlan) bool {
	authoritative := make(map[string]RevealBatch)
	for _, account := range accounts {
		for _, batch := range account.Batches {
			candidate := RevealBatch{BatchID: batch.ToBatchID, AccountRef: account.AccountRef,
				BatchType: batch.BatchType, BatchVersion: batch.ToBatchVersion,
				CiphertextHash: batch.ToCiphertextHash, RecoveryWrapHash: batch.ToRecoveryWrapHash}
			authoritative[revealBatchKey(candidate)] = candidate
		}
	}
	for _, batch := range selected {
		want, exists := authoritative[revealBatchKey(batch)]
		if !exists || want != batch {
			return false
		}
	}
	return true
}

func revealBatchKey(batch RevealBatch) string {
	return batch.AccountRef + "\x00" + batch.BatchType + "\x00" + batch.BatchID
}
