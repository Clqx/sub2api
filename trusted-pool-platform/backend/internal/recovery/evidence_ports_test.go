package recovery

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestVerificationExportRequestSnapshotBindsIntent(t *testing.T) {
	input := BeginVerificationExportInput{Key: OperationKey{OperationID: "operation-1"},
		ExportExternalID: "export-1", PlanExternalID: "plan-1", FormatVersion: "phase2h-v1"}
	snapshot, hash, err := BuildVerificationExportRequestSnapshot(input)
	if err != nil {
		t.Fatalf("build export snapshot: %v", err)
	}
	for _, fragment := range []string{"operation-1", "export-1", "plan-1", "phase2h-v1"} {
		if !bytes.Contains(snapshot, []byte(fragment)) {
			t.Fatalf("snapshot does not bind %q: %s", fragment, snapshot)
		}
	}
	input.PlanExternalID = "plan-2"
	changed, changedHash, err := BuildVerificationExportRequestSnapshot(input)
	if err != nil || bytes.Equal(snapshot, changed) || hash == changedHash {
		t.Fatalf("plan drift did not change snapshot/hash: err=%v", err)
	}
}

func TestRevealAuthorizationRequestSnapshotIsSortedAndUsesDatabasePrecision(t *testing.T) {
	input := BeginRevealAuthorizationInput{
		Key: OperationKey{OperationID: "operation-1"}, RevealExternalID: "reveal-1",
		ExportExternalID: "export-1", PlanExternalID: "plan-1", Purpose: "incident-recovery",
		ScopeHash: [32]byte{1}, ChallengeHash: [32]byte{2},
		ExpiresAt: time.Date(2026, 8, 21, 9, 10, 11, 123456789, time.FixedZone("offset", 8*60*60)),
		ApprovalIntents: []RevealApprovalIntent{
			{MemberExternalID: "member-b", ExpectedMessageHash: [32]byte{4}},
			{MemberExternalID: "member-a", ExpectedMessageHash: [32]byte{3}},
		},
	}
	first, firstHash, err := BuildRevealAuthorizationRequestSnapshot(input)
	if err != nil {
		t.Fatalf("build Reveal snapshot: %v", err)
	}
	if strings.Index(string(first), "member-a") >= strings.Index(string(first), "member-b") {
		t.Fatalf("approval intents are not sorted: %s", first)
	}
	if !bytes.Contains(first, []byte(`"expires_at":"2026-08-21T01:10:11.123456Z"`)) {
		t.Fatalf("expiry is not normalized to PostgreSQL precision: %s", first)
	}
	input.ApprovalIntents[0], input.ApprovalIntents[1] = input.ApprovalIntents[1], input.ApprovalIntents[0]
	second, secondHash, err := BuildRevealAuthorizationRequestSnapshot(input)
	if err != nil || !bytes.Equal(first, second) || firstHash != secondHash {
		t.Fatalf("intent order changed canonical snapshot: err=%v", err)
	}
	input.ChallengeHash[0]++
	changed, changedHash, err := BuildRevealAuthorizationRequestSnapshot(input)
	if err != nil || bytes.Equal(first, changed) || firstHash == changedHash {
		t.Fatalf("challenge drift did not change snapshot/hash: err=%v", err)
	}
}
