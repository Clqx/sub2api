package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

const (
	managerProcessHelperMode    = "PHASE2H_MANAGER_PROCESS_HELPER"
	managerProcessHelperDSN     = "PHASE2H_MANAGER_PROCESS_DSN"
	managerProcessHelperSchema  = "PHASE2H_MANAGER_PROCESS_SCHEMA"
	managerProcessHelperRecord  = "PHASE2H_MANAGER_PROCESS_RECORD"
	managerProcessHelperReceipt = "PHASE2H_MANAGER_PROCESS_RECEIPT"
	managerProcessHelperNonce   = "PHASE2H_MANAGER_PROCESS_NONCE"
	managerProviderCrashCode    = 79
)

type managerProcessFixture struct {
	finalizationKey recovery.OperationKey
	planID          string
	planExternalID  string
	caseExternalID  string
	seatExternalID  string
	targetMemberID  string
	oldOwner        string
	initialFence    int64
	preparedSetHash [sha256.Size]byte
}

type managerProviderRecord struct {
	DurableExecutions int                                         `json:"durable_executions"`
	Request           recovery.PermanentPoolRotationCommitRequest `json:"request"`
	Result            recovery.PermanentPoolRotationCommitResult  `json:"result"`
}

type managerReplayReceipt struct {
	Worked          bool `json:"worked"`
	ClaimTokenCalls int  `json:"claim_token_calls"`
}

type managerDurableCommitProvider struct {
	recordPath      string
	crashAfterWrite bool
	requireExisting bool
}

func (*managerDurableCommitProvider) Ready(context.Context) error { return nil }

func (*managerDurableCommitProvider) PreparePoolRotation(context.Context,
	recovery.PermanentPoolRotationPrepareRequest) (recovery.PermanentPoolRotationPrepareResult, error) {
	return recovery.PermanentPoolRotationPrepareResult{}, recovery.ErrProviderUnavailable
}

func (*managerDurableCommitProvider) ActivatePreparedPoolRotation(context.Context,
	recovery.PermanentPoolRotationActivateRequest) (recovery.PermanentPoolRotationActivateResult, error) {
	return recovery.PermanentPoolRotationActivateResult{}, recovery.ErrProviderUnavailable
}

func (p *managerDurableCommitProvider) CommitActivatedPoolRotation(_ context.Context,
	request recovery.PermanentPoolRotationCommitRequest) (recovery.PermanentPoolRotationCommitResult, error) {
	record, err := readManagerProviderRecord(p.recordPath)
	if err == nil {
		if !reflect.DeepEqual(record.Request, request) || record.DurableExecutions != 1 {
			return recovery.PermanentPoolRotationCommitResult{}, recovery.ErrBindingMismatch
		}
		return cloneManagerCommitResult(record.Result), nil
	}
	if !errors.Is(err, os.ErrNotExist) || p.requireExisting {
		return recovery.PermanentPoolRotationCommitResult{}, recovery.ErrProviderUnavailable
	}
	result := managerCommitResult(request)
	record = managerProviderRecord{DurableExecutions: 1, Request: request, Result: result}
	encoded, err := json.Marshal(record)
	if err != nil {
		return recovery.PermanentPoolRotationCommitResult{}, err
	}
	if err := os.WriteFile(p.recordPath, encoded, 0o600); err != nil {
		return recovery.PermanentPoolRotationCommitResult{}, err
	}
	if p.crashAfterWrite {
		os.Exit(managerProviderCrashCode)
	}
	return cloneManagerCommitResult(result), nil
}

// This test verifier isolates crash/replay persistence; cryptographic signature
// verification is covered by recovery security tests.
type managerProcessActivationVerifier struct{}

func (*managerProcessActivationVerifier) Ready(context.Context) error { return nil }
func (*managerProcessActivationVerifier) VerifyPoolActivation(context.Context,
	recovery.PermanentPoolActivationVerifyRequest) error {
	return nil
}
func (*managerProcessActivationVerifier) VerifyPoolCommit(context.Context,
	recovery.PermanentPoolCommitVerifyRequest) error {
	return nil
}

func readManagerProviderRecord(path string) (managerProviderRecord, error) {
	var result managerProviderRecord
	encoded, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		return managerProviderRecord{}, err
	}
	return result, nil
}

func managerCommitResult(request recovery.PermanentPoolRotationCommitRequest) recovery.PermanentPoolRotationCommitResult {
	seats := make([]recovery.PermanentSeatActivationResult, len(request.Seats))
	for index, binding := range request.Seats {
		seats[index] = recovery.PermanentSeatActivationResult{PermanentSeatActivationBinding: binding,
			AssignmentEpoch: binding.ExpectedAssignmentEpoch + 1, State: "ACTIVE"}
	}
	attestation := []byte("durable-manager-process-provider-attestation")
	return recovery.PermanentPoolRotationCommitResult{
		ProtocolVersion: request.ProtocolVersion, OperationID: request.OperationID,
		PrepareOperationID:    request.PrepareOperationID,
		ActivationOperationID: request.ActivationOperationID,
		ActivationRequestHash: request.ActivationRequestHash, RequestHash: request.RequestHash,
		PlanID: request.PlanID, CeremonyType: request.CeremonyType, PoolID: request.PoolID,
		FromEpoch: request.FromEpoch, ToEpoch: request.ToEpoch, PreparedSetHash: request.PreparedSetHash,
		State: "COMMITTED", AllCredentialsEnabled: true, AllSubscriptionsEnabled: true,
		OldCredentialSetInvalidated: true, CredentialFingerprintGateEnforced: true,
		AuthorizationCacheInvalidated: false, AuthCacheDurableOutbox: true,
		AuthCacheMinimumEvents: len(seats), Seats: seats, AttestationAlgorithm: "Ed25519",
		AttestationIssuer: "manager-process-provider", AttestationRef: "manager-process-proof",
		AttestationKeyID: "manager-process-key", AttestationVersion: 1,
		AttestationDigest: sha256.Sum256(attestation), Attestation: attestation,
		CommittedAt: time.Date(2026, 8, 30, 3, 0, 0, 0, time.UTC),
	}
}

func cloneManagerCommitResult(value recovery.PermanentPoolRotationCommitResult) recovery.PermanentPoolRotationCommitResult {
	value.Seats = append([]recovery.PermanentSeatActivationResult(nil), value.Seats...)
	value.Attestation = append([]byte(nil), value.Attestation...)
	return value
}

func managerProcessOperationIntent(operationID string) ([]byte, [sha256.Size]byte) {
	snapshot, _ := json.Marshal(map[string]string{"fixture": operationID})
	return snapshot, sha256.Sum256(snapshot)
}

func managerProcessCanonicalIntent(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSONObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func managerProcessRotationIntent(t *testing.T, value any, hashField string,
	setHash [sha256.Size]byte) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	encodedHash, err := json.Marshal(fmt.Sprintf("%x", setHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	object[hashField] = encodedHash
	return managerProcessCanonicalIntent(t, object)
}

func TestRecoveryManagerProviderCommitReplaySurvivesProcessExit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_manager_process_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create Manager process schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer db.Close()
	if err := Migrate(ctx, db, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for Manager process test: %v", err)
	}
	fixture := insertManagerProviderPendingFixture(t, ctx, db)
	assertManagerProcessOperationHashes(t, ctx, db, fixture.finalizationKey.ClientID, nil)

	recordPath := filepath.Join(t.TempDir(), "provider-commit.json")
	receiptPath := filepath.Join(filepath.Dir(recordPath), "replay-receipt.json")
	crashOutput, crashErr := runRecoveryManagerProcessHelper(ctx, dsn, schema, recordPath, receiptPath, "crash")
	var exitErr *exec.ExitError
	if !errors.As(crashErr, &exitErr) || exitErr.ExitCode() != managerProviderCrashCode {
		t.Fatalf("Manager helper did not exit after durable provider effect: err=%v output=%s", crashErr, crashOutput)
	}
	record, err := readManagerProviderRecord(recordPath)
	if err != nil || record.DurableExecutions != 1 || record.Request.PlanID != fixture.planExternalID ||
		record.Request.PreparedSetHash != fixture.preparedSetHash {
		t.Fatalf("durable provider record = %+v, %v", record, err)
	}

	childOwner := "manager-before-exit"
	var parentStatus, parentOwner, caseStatus, childStatus, childOwnerStored, attemptStatus string
	var parentFence, childFence int64
	var claimTokens int
	if err := db.QueryRowContext(ctx, `SELECT parent.status, COALESCE(parent.lease_owner,''),
parent.fencing_token, replacement.status, child.status, COALESCE(child.lease_owner,''),
child.fencing_token, attempt.status,
(SELECT count(*) FROM credential_claims WHERE claim_token_hash IS NOT NULL)
FROM permanent_replacement_cases replacement
JOIN integration_operations parent ON parent.id=replacement.integration_operation_id
JOIN recovery_pool_provider_commit_attempts attempt ON attempt.plan_id=replacement.plan_id
JOIN integration_operations child ON child.id=attempt.integration_operation_id
WHERE parent.integration_client_id=$1 AND parent.operation_id=$2`, fixture.finalizationKey.ClientID,
		fixture.finalizationKey.OperationID).Scan(&parentStatus, &parentOwner, &parentFence, &caseStatus,
		&childStatus, &childOwnerStored, &childFence, &attemptStatus, &claimTokens); err != nil {
		t.Fatal(err)
	}
	if parentStatus != "RUNNING" || parentOwner != childOwner || parentFence != fixture.initialFence+1 ||
		caseStatus != "PROVIDER_COMMIT_PENDING" || childStatus != "RUNNING" ||
		childOwnerStored != childOwner || childFence != 1 || attemptStatus != "PENDING" || claimTokens != 0 {
		t.Fatalf("unexpected crash boundary: parent=%s/%s/%d case=%s child=%s/%s/%d attempt=%s tokens=%d",
			parentStatus, parentOwner, parentFence, caseStatus, childStatus, childOwnerStored,
			childFence, attemptStatus, claimTokens)
	}

	if _, err := db.ExecContext(ctx, `UPDATE integration_operations SET
lease_expires_at=CURRENT_TIMESTAMP - interval '1 second', version=version+1,
updated_at=CURRENT_TIMESTAMP
WHERE integration_client_id=$1 AND operation_id IN ($2,$3)`, fixture.finalizationKey.ClientID,
		fixture.finalizationKey.OperationID, record.Request.OperationID); err != nil {
		t.Fatalf("expire exited Manager leases: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	resultSnapshot, err := json.Marshal(record.Result)
	if err != nil {
		t.Fatal(err)
	}
	staleInput := recovery.CommitProviderReleaseInput{
		FinalizationKey: fixture.finalizationKey, FinalizationLeaseOwner: childOwner,
		FinalizationFencingToken: parentFence, DerivedOperationID: record.Request.OperationID,
		ChildLeaseOwner: childOwner, ChildFencingToken: childFence, Status: "RELEASED",
		ProviderAttestationRef:            record.Result.AttestationRef,
		ProviderAttestationDigest:         record.Result.AttestationDigest,
		ProviderAttestationIssuer:         record.Result.AttestationIssuer,
		ProviderAttestationKeyID:          record.Result.AttestationKeyID,
		ProviderAttestationVersion:        record.Result.AttestationVersion,
		ProviderAttestationSignature:      append([]byte(nil), record.Result.Attestation...),
		AllCredentialsEnabled:             record.Result.AllCredentialsEnabled,
		AllSubscriptionsEnabled:           record.Result.AllSubscriptionsEnabled,
		OldCredentialSetInvalidated:       record.Result.OldCredentialSetInvalidated,
		CredentialFingerprintGateEnforced: record.Result.CredentialFingerprintGateEnforced,
		AuthorizationCacheInvalidated:     record.Result.AuthorizationCacheInvalidated,
		AuthorizationCacheDurableOutbox:   record.Result.AuthCacheDurableOutbox,
		AuthCacheMinimumEvents:            record.Result.AuthCacheMinimumEvents, ResultSnapshot: resultSnapshot,
	}
	_, committed, expiredLeaseErr := store.CommitProviderRelease(ctx, staleInput)
	if !errors.Is(expiredLeaseErr, recovery.ErrNotFound) || committed {
		t.Fatalf("expired exited leases committed provider release: committed=%t err=%v", committed, expiredLeaseErr)
	}
	current, err := store.AcquireNextPermanentReplacementLease(ctx,
		recovery.AcquireNextPermanentReplacementLeaseInput{LeaseOwner: "manager-child-fence-check",
			LeaseDuration: 30 * time.Second})
	if err != nil || current == nil || current.Operation == nil || current.ProviderRelease == nil ||
		current.Operation.FencingToken != parentFence+1 ||
		current.ProviderRelease.FencingToken != childFence {
		t.Fatalf("acquire current parent for child-fence check: target=%+v err=%v", current, err)
	}
	staleInput.FinalizationLeaseOwner = current.Operation.LeaseOwner
	staleInput.FinalizationFencingToken = parentFence
	_, committed, parentFenceErr := store.CommitProviderRelease(ctx, staleInput)
	if !errors.Is(parentFenceErr, recovery.ErrNotFound) || committed {
		t.Fatalf("stale parent fence committed with a live current lease: committed=%t err=%v",
			committed, parentFenceErr)
	}
	staleInput.FinalizationFencingToken = current.Operation.FencingToken
	staleInput.FinalizationLeaseOwner = childOwner
	_, committed, parentOwnerErr := store.CommitProviderRelease(ctx, staleInput)
	if !errors.Is(parentOwnerErr, recovery.ErrNotFound) || committed {
		t.Fatalf("stale parent owner committed with a live current fence: committed=%t err=%v",
			committed, parentOwnerErr)
	}
	staleInput.FinalizationLeaseOwner = current.Operation.LeaseOwner
	currentChild, created, err := store.BeginProviderRelease(ctx, recovery.BeginProviderReleaseInput{
		FinalizationKey: fixture.finalizationKey, FinalizationLeaseOwner: current.Operation.LeaseOwner,
		FinalizationFencingToken: current.Operation.FencingToken, DerivedOperationID: record.Request.OperationID,
		RequestHash: record.Request.RequestHash, RequestSnapshot: current.ProviderRelease.RequestSnapshot,
		ChildLeaseOwner: "manager-current-child", ExpectedChildFencingToken: childFence,
		ChildLeaseDuration: 30 * time.Second,
	})
	if err != nil || created || currentChild == nil || currentChild.Operation == nil ||
		currentChild.Operation.FencingToken != childFence+1 ||
		currentChild.Operation.LeaseOwner != "manager-current-child" {
		t.Fatalf("acquire current child for fence check: target=%+v created=%t err=%v",
			currentChild, created, err)
	}
	staleInput.ChildLeaseOwner = currentChild.Operation.LeaseOwner
	staleInput.ChildFencingToken = childFence
	_, committed, childStaleErr := store.CommitProviderRelease(ctx, staleInput)
	if !errors.Is(childStaleErr, recovery.ErrNotFound) || committed {
		t.Fatalf("stale child fence committed with live current leases: committed=%t err=%v",
			committed, childStaleErr)
	}
	staleInput.ChildFencingToken = currentChild.Operation.FencingToken
	staleInput.ChildLeaseOwner = childOwner
	_, committed, childOwnerErr := store.CommitProviderRelease(ctx, staleInput)
	if !errors.Is(childOwnerErr, recovery.ErrNotFound) || committed {
		t.Fatalf("stale child owner committed with live current fences: committed=%t err=%v",
			committed, childOwnerErr)
	}
	var unchangedCase, unchangedAttempt string
	var unchangedParentFence, unchangedChildFence int64
	var releaseProofs int
	if err := db.QueryRowContext(ctx, `SELECT replacement.status, attempt.status,
parent.fencing_token, child.fencing_token,
(SELECT count(*) FROM recovery_pool_provider_commit_attempts WHERE status='RELEASED')
FROM permanent_replacement_cases replacement
JOIN integration_operations parent ON parent.id=replacement.integration_operation_id
JOIN recovery_pool_provider_commit_attempts attempt ON attempt.plan_id=replacement.plan_id
JOIN integration_operations child ON child.id=attempt.integration_operation_id
WHERE parent.integration_client_id=$1 AND parent.operation_id=$2`,
		fixture.finalizationKey.ClientID, fixture.finalizationKey.OperationID).Scan(&unchangedCase,
		&unchangedAttempt, &unchangedParentFence, &unchangedChildFence, &releaseProofs); err != nil {
		t.Fatal(err)
	}
	if unchangedCase != "PROVIDER_COMMIT_PENDING" || unchangedAttempt != "PENDING" ||
		unchangedParentFence != current.Operation.FencingToken ||
		unchangedChildFence != currentChild.Operation.FencingToken ||
		releaseProofs != 0 {
		t.Fatalf("stale fence changed aggregate: case=%s attempt=%s fences=%d/%d proofs=%d",
			unchangedCase, unchangedAttempt, unchangedParentFence, unchangedChildFence, releaseProofs)
	}
	if _, err := db.ExecContext(ctx, `UPDATE integration_operations SET
lease_expires_at=CURRENT_TIMESTAMP - interval '1 second', version=version+1,
updated_at=CURRENT_TIMESTAMP
WHERE integration_client_id=$1 AND operation_id=$2 AND fencing_token=$3 AND lease_owner=$4`,
		fixture.finalizationKey.ClientID, fixture.finalizationKey.OperationID,
		current.Operation.FencingToken, current.Operation.LeaseOwner); err != nil {
		t.Fatalf("expire child-fence-check parent lease: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE integration_operations SET
lease_expires_at=CURRENT_TIMESTAMP - interval '1 second', version=version+1,
updated_at=CURRENT_TIMESTAMP
WHERE integration_client_id=$1 AND operation_id=$2 AND fencing_token=$3 AND lease_owner=$4`,
		fixture.finalizationKey.ClientID, record.Request.OperationID,
		currentChild.Operation.FencingToken, currentChild.Operation.LeaseOwner); err != nil {
		t.Fatalf("expire child-fence-check child lease: %v", err)
	}

	replayOutput, replayErr := runRecoveryManagerProcessHelper(ctx, dsn, schema, recordPath, receiptPath, "replay")
	if replayErr != nil {
		t.Fatalf("restarted Manager did not converge: err=%v output=%s", replayErr, replayOutput)
	}
	var receipt managerReplayReceipt
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read replay receipt: %v", err)
	}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil || !receipt.Worked || receipt.ClaimTokenCalls != 0 {
		t.Fatalf("restarted worker receipt = %+v, decode=%v", receipt, err)
	}

	var finalCase, finalParentStatus, finalParentOwner, finalChildStatus, finalChildOwner, finalAttempt string
	var finalParentFence, finalChildFence int64
	var pendingClaims, releasedProofs int
	var finalChildLeaseCleared bool
	if err := db.QueryRowContext(ctx, `SELECT replacement.status, parent.status,
COALESCE(parent.lease_owner,''), parent.fencing_token, child.status,
COALESCE(child.lease_owner,''), child.lease_expires_at IS NULL, child.fencing_token, attempt.status,
(SELECT count(*) FROM credential_claims WHERE status='ISSUANCE_PENDING' AND claim_token_hash IS NULL),
(SELECT count(*) FROM recovery_pool_provider_commit_attempts WHERE status='RELEASED')
FROM permanent_replacement_cases replacement
JOIN integration_operations parent ON parent.id=replacement.integration_operation_id
JOIN recovery_pool_provider_commit_attempts attempt ON attempt.plan_id=replacement.plan_id
JOIN integration_operations child ON child.id=attempt.integration_operation_id
WHERE parent.integration_client_id=$1 AND parent.operation_id=$2`, fixture.finalizationKey.ClientID,
		fixture.finalizationKey.OperationID).Scan(&finalCase, &finalParentStatus, &finalParentOwner,
		&finalParentFence, &finalChildStatus, &finalChildOwner, &finalChildLeaseCleared,
		&finalChildFence, &finalAttempt, &pendingClaims, &releasedProofs); err != nil {
		t.Fatal(err)
	}
	if finalCase != "READY_TO_ISSUE" || finalParentStatus != "RUNNING" ||
		finalParentOwner != "manager-after-restart" || finalParentFence != fixture.initialFence+3 ||
		finalChildStatus != "SUCCEEDED" || finalChildOwner != "" || !finalChildLeaseCleared ||
		finalChildFence != childFence+2 || finalAttempt != "RELEASED" ||
		pendingClaims != 1 || releasedProofs != 1 {
		t.Fatalf("unexpected restart aggregate: case=%s parent=%s/%s/%d child=%s/%s/cleared=%t/%d attempt=%s claims=%d proofs=%d",
			finalCase, finalParentStatus, finalParentOwner, finalParentFence, finalChildStatus,
			finalChildOwner, finalChildLeaseCleared, finalChildFence, finalAttempt, pendingClaims, releasedProofs)
	}
	recordAfterReplay, err := readManagerProviderRecord(recordPath)
	if err != nil || recordAfterReplay.DurableExecutions != 1 || !reflect.DeepEqual(record, recordAfterReplay) {
		t.Fatalf("provider replay created a second durable result: before=%+v after=%+v err=%v",
			record, recordAfterReplay, err)
	}
	assertManagerProviderReleaseProof(t, ctx, db, fixture.planID, record)
	tampered := record.Request
	tampered.PlanID += "-drift"
	if _, err := (&managerDurableCommitProvider{recordPath: recordPath, requireExisting: true}).
		CommitActivatedPoolRotation(ctx, tampered); !errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("durable provider accepted request drift: %v", err)
	}
	assertManagerProcessOperationHashes(t, ctx, db, fixture.finalizationKey.ClientID, &record.Request)
}

func TestRecoveryManagerProviderCommitProcessHelper(t *testing.T) {
	mode := strings.TrimSpace(os.Getenv(managerProcessHelperMode))
	if mode != "crash" && mode != "replay" {
		t.Skip("subprocess helper")
	}
	dsn := strings.TrimSpace(os.Getenv(managerProcessHelperDSN))
	schema := strings.TrimSpace(os.Getenv(managerProcessHelperSchema))
	recordPath := strings.TrimSpace(os.Getenv(managerProcessHelperRecord))
	receiptPath := strings.TrimSpace(os.Getenv(managerProcessHelperReceipt))
	nonce := strings.TrimSpace(os.Getenv(managerProcessHelperNonce))
	if dsn == "" || schema == "" || recordPath == "" || receiptPath == "" ||
		nonce != schema+":"+strconv.Itoa(os.Getppid()) {
		t.Fatal("Manager subprocess helper configuration is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	tokenCalls := 0
	owner := "manager-before-exit"
	provider := &managerDurableCommitProvider{recordPath: recordPath, crashAfterWrite: true}
	if mode == "replay" {
		owner = "manager-after-restart"
		provider.crashAfterWrite = false
		provider.requireExisting = true
	}
	manager, err := recovery.NewManager(store, recovery.Providers{SeatRotations: provider,
		SeatActivations: &managerProcessActivationVerifier{}}, recovery.ManagerConfig{
		ClientID: "manager-process-client", LeaseOwner: owner, LeaseDuration: 30 * time.Second,
		ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1",
		ClaimToken: func() (string, error) {
			tokenCalls++
			return "must-not-be-issued-by-worker", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := manager.RecoverNextFinalization(ctx)
	if err != nil || !worked {
		t.Fatalf("RecoverNextFinalization() = %v, %v", worked, err)
	}
	if mode == "crash" {
		t.Fatal("crash provider returned without terminating the helper")
	}
	receipt, err := json.Marshal(managerReplayReceipt{Worked: worked, ClaimTokenCalls: tokenCalls})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		t.Fatalf("write replay receipt: %v", err)
	}
}

func runRecoveryManagerProcessHelper(ctx context.Context, dsn, schema, recordPath, receiptPath,
	mode string) ([]byte, error) {
	command := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestRecoveryManagerProviderCommitProcessHelper$", "-test.v")
	command.Env = append(os.Environ(), managerProcessHelperMode+"="+mode,
		managerProcessHelperDSN+"="+dsn, managerProcessHelperSchema+"="+schema,
		managerProcessHelperRecord+"="+recordPath, managerProcessHelperReceipt+"="+receiptPath,
		managerProcessHelperNonce+"="+schema+":"+strconv.Itoa(os.Getpid()))
	return command.CombinedOutput()
}

func assertManagerProcessOperationHashes(t *testing.T, ctx context.Context, db *sql.DB, clientID string,
	expectedProviderRequest *recovery.PermanentPoolRotationCommitRequest) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT operation_id, operation_type, request_hash, request_snapshot::text
FROM integration_operations WHERE integration_client_id=$1 ORDER BY operation_id`, clientID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	seatRequests := make(map[string]recovery.PermanentSeatRotationPrepareRequest)
	var preparationRequest *recovery.PermanentPoolRotationPrepareRequest
	var activationRequest *recovery.PermanentPoolRotationActivateRequest
	for rows.Next() {
		var operationID, operationType string
		var storedHash, snapshot []byte
		if err := rows.Scan(&operationID, &operationType, &storedHash, &snapshot); err != nil {
			t.Fatal(err)
		}
		canonical, err := canonicalJSONObject(snapshot)
		if err != nil {
			t.Fatalf("%s request snapshot is not canonicalizable: %v", operationID, err)
		}
		if operationType == "COMMIT_PERMANENT_REPLACEMENT_PROVIDER" {
			var request recovery.PermanentPoolRotationCommitRequest
			if err := json.Unmarshal(canonical, &request); err != nil {
				t.Fatalf("decode %s provider request snapshot: %v", operationID, err)
			}
			want := recovery.PermanentPoolRotationCommitRequestHash(request)
			if expectedProviderRequest == nil || !reflect.DeepEqual(request, *expectedProviderRequest) ||
				request.RequestHash != want || !reflect.DeepEqual(storedHash, want[:]) ||
				!rotationSnapshotBindsRequest(canonical, "prepared_set_hash", request.PreparedSetHash, request) {
				t.Fatalf("%s provider request snapshot does not bind its domain hash", operationID)
			}
		} else if operationType == "PREPARE_PERMANENT_REPLACEMENT" {
			var request recovery.PermanentSeatRotationPrepareRequest
			if err := json.Unmarshal(canonical, &request); err != nil {
				t.Fatalf("decode %s Seat prepare snapshot: %v", operationID, err)
			}
			want := recovery.PermanentSeatRotationPrepareRequestHash(request)
			if request.OperationID != operationID || request.RequestHash != want ||
				!reflect.DeepEqual(storedHash, want[:]) ||
				!seatPrepareSnapshotBindsRequest(canonical, request.RequestHash, request) {
				t.Fatalf("%s Seat prepare snapshot does not bind its domain hash", operationID)
			}
			seatRequests[operationID] = request
		} else if operationType == "PREPARE_PERMANENT_REPLACEMENT_SET" {
			var request recovery.PermanentPoolRotationPrepareRequest
			if err := json.Unmarshal(canonical, &request); err != nil {
				t.Fatalf("decode %s Pool prepare snapshot: %v", operationID, err)
			}
			childSetHash, err := recovery.PermanentRotationChildSetHash(request.Seats)
			want := recovery.PermanentPoolRotationPrepareRequestHash(request)
			if err != nil || request.OperationID != operationID || request.ChildSetHash != childSetHash ||
				request.RequestHash != want || !reflect.DeepEqual(storedHash, want[:]) ||
				!rotationSnapshotBindsRequest(canonical, "child_set_hash", childSetHash, request) {
				t.Fatalf("%s Pool prepare snapshot does not bind its domain set/hash: %v", operationID, err)
			}
			stored := request
			preparationRequest = &stored
		} else if operationType == "ACTIVATE_PERMANENT_REPLACEMENT" {
			var request recovery.PermanentPoolRotationActivateRequest
			if err := json.Unmarshal(canonical, &request); err != nil {
				t.Fatalf("decode %s Pool activation snapshot: %v", operationID, err)
			}
			preparedSetHash, err := recovery.PermanentPreparedSeatSetHash(request.Seats)
			want := recovery.PermanentPoolRotationActivateRequestHash(request)
			if err != nil || request.OperationID != operationID || request.PreparedSetHash != preparedSetHash ||
				request.RequestHash != want || !reflect.DeepEqual(storedHash, want[:]) ||
				!rotationSnapshotBindsRequest(canonical, "prepared_set_hash", preparedSetHash, request) {
				t.Fatalf("%s Pool activation snapshot does not bind its domain set/hash: %v", operationID, err)
			}
			stored := request
			activationRequest = &stored
		} else {
			want := sha256.Sum256(canonical)
			if len(storedHash) != sha256.Size || !reflect.DeepEqual(storedHash, want[:]) {
				t.Fatalf("%s request hash does not bind its canonical snapshot: got=%x want=%x",
					operationID, storedHash, want)
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("Manager process fixture contains no integration operations")
	}
	if preparationRequest == nil || activationRequest == nil ||
		len(preparationRequest.Seats) != len(seatRequests) ||
		len(activationRequest.Seats) != len(seatRequests) ||
		activationRequest.PrepareOperationID != preparationRequest.OperationID ||
		activationRequest.ProtocolVersion != preparationRequest.ProtocolVersion ||
		activationRequest.PlanID != preparationRequest.PlanID ||
		activationRequest.CeremonyType != preparationRequest.CeremonyType ||
		activationRequest.PoolID != preparationRequest.PoolID ||
		activationRequest.FromEpoch != preparationRequest.FromEpoch ||
		activationRequest.ToEpoch != preparationRequest.ToEpoch {
		t.Fatal("Manager process fixture does not contain one complete typed prepare/activation chain")
	}
	if expectedProviderRequest != nil {
		provider := expectedProviderRequest
		if provider.ProtocolVersion != activationRequest.ProtocolVersion ||
			provider.PrepareOperationID != preparationRequest.OperationID ||
			provider.ActivationOperationID != activationRequest.OperationID ||
			provider.ActivationRequestHash != activationRequest.RequestHash ||
			provider.PlanID != activationRequest.PlanID ||
			provider.CeremonyType != activationRequest.CeremonyType ||
			provider.PoolID != activationRequest.PoolID ||
			provider.FromEpoch != activationRequest.FromEpoch ||
			provider.ToEpoch != activationRequest.ToEpoch ||
			provider.PreparedSetHash != activationRequest.PreparedSetHash ||
			!reflect.DeepEqual(provider.Seats, activationRequest.Seats) {
			t.Fatal("Provider commit request does not continue the exact durable activation chain")
		}
	}
	for _, child := range preparationRequest.Seats {
		stored, exists := seatRequests[child.OperationID]
		if !exists || !reflect.DeepEqual(stored, child) {
			t.Fatalf("Pool prepare child %s does not match its durable Seat operation", child.OperationID)
		}
	}
	for _, binding := range activationRequest.Seats {
		child, exists := seatRequests[binding.ChildOperationID]
		if !exists || binding.ChildRequestHash != child.RequestHash || binding.SeatID != child.SeatID ||
			binding.TargetMemberID != child.TargetMemberID ||
			binding.ExpectedAssignmentEpoch != child.ExpectedAssignmentEpoch ||
			binding.PrincipalUserID != child.PrincipalUserID ||
			binding.SubscriptionID != child.SubscriptionID || binding.APIKeyID != child.APIKeyID ||
			binding.ActiveAPIKeyVersion != child.ToAPIKeyVersion {
			t.Fatalf("Pool activation binding %s does not match its durable Seat prepare intent",
				binding.ChildOperationID)
		}
		var progressReference, proofReference string
		var progressFingerprint, proofFingerprint []byte
		var progressPrincipal, progressSubscription, progressAPIKey, progressAPIVersion int64
		var proofPrincipal, proofSubscription, proofAPIKey, proofAPIVersion int64
		if err := db.QueryRowContext(ctx, `SELECT progress.prepared_reference,
progress.credential_fingerprint, progress.principal_user_id, progress.subscription_id,
progress.api_key_id, progress.api_key_version, proof.prepared_reference,
proof.credential_fingerprint, proof.principal_user_id, proof.subscription_id,
proof.api_key_id, proof.api_key_version
FROM recovery_seat_rotation_progress progress
JOIN integration_operations child ON child.id=progress.derived_operation_id
JOIN recovery_pool_activation_attempts activation ON activation.plan_id=progress.plan_id
JOIN integration_operations activation_operation ON activation_operation.id=activation.integration_operation_id
JOIN recovery_pool_activation_seats proof ON proof.activation_attempt_id=activation.id
 AND proof.plan_id=progress.plan_id AND proof.seat_id=progress.seat_id
WHERE child.integration_client_id=$1 AND child.operation_id=$2
  AND activation_operation.operation_id=$3`, clientID, binding.ChildOperationID,
			activationRequest.OperationID).Scan(&progressReference, &progressFingerprint,
			&progressPrincipal, &progressSubscription, &progressAPIKey, &progressAPIVersion,
			&proofReference, &proofFingerprint, &proofPrincipal, &proofSubscription,
			&proofAPIKey, &proofAPIVersion); err != nil {
			t.Fatalf("load durable activation binding %s: %v", binding.ChildOperationID, err)
		}
		if progressReference != binding.PreparedRotationRef ||
			proofReference != binding.PreparedRotationRef ||
			!reflect.DeepEqual(progressFingerprint, binding.CredentialFingerprint[:]) ||
			!reflect.DeepEqual(proofFingerprint, binding.CredentialFingerprint[:]) ||
			progressPrincipal != binding.PrincipalUserID || proofPrincipal != binding.PrincipalUserID ||
			progressSubscription != binding.SubscriptionID || proofSubscription != binding.SubscriptionID ||
			progressAPIKey != binding.APIKeyID || proofAPIKey != binding.APIKeyID ||
			progressAPIVersion != int64(binding.ActiveAPIKeyVersion) ||
			proofAPIVersion != int64(binding.ActiveAPIKeyVersion) {
			t.Fatalf("activation binding %s does not match durable progress/proof", binding.ChildOperationID)
		}
	}
}

func assertManagerProviderReleaseProof(t *testing.T, ctx context.Context, db *sql.DB,
	planID string, record managerProviderRecord) {
	t.Helper()
	var preparedSetHash, childRequestHash, activationRequestHash []byte
	var childOperationID, prepareOperationID, activationOperationID string
	var attestationRef, attestationIssuer, attestationKeyID string
	var attestationDigest, attestationSignature, resultSnapshot, childResponseSnapshot []byte
	var attestationVersion int64
	var allCredentialsEnabled, allSubscriptionsEnabled, oldCredentialSetInvalidated bool
	var credentialFingerprintGateEnforced, authorizationCacheInvalidated bool
	var authorizationCacheDurableOutbox bool
	var authCacheMinimumEvents int
	err := db.QueryRowContext(ctx, `SELECT attempt.prepared_set_hash,
child.operation_id, child.request_hash, prep_op.operation_id,
activation_op.operation_id, activation_op.request_hash,
attempt.provider_attestation_ref, attempt.provider_attestation_digest,
attempt.provider_attestation_issuer, attempt.provider_attestation_key_id,
attempt.provider_attestation_version, attempt.provider_attestation_signature,
attempt.all_credentials_enabled, attempt.all_subscriptions_enabled,
attempt.old_credential_set_invalidated, attempt.credential_fingerprint_gate_enforced,
attempt.authorization_cache_invalidated, attempt.authorization_cache_durable_outbox,
attempt.auth_cache_minimum_events, attempt.result_snapshot, child.response_snapshot
FROM recovery_pool_provider_commit_attempts attempt
JOIN integration_operations child ON child.id=attempt.integration_operation_id
JOIN recovery_pool_preparation_attempts prep ON prep.plan_id=attempt.plan_id
JOIN integration_operations prep_op ON prep_op.id=prep.integration_operation_id
JOIN recovery_pool_activation_attempts activation ON activation.id=attempt.activation_attempt_id
JOIN integration_operations activation_op ON activation_op.id=activation.integration_operation_id
WHERE attempt.plan_id=$1`, planID).Scan(&preparedSetHash, &childOperationID, &childRequestHash,
		&prepareOperationID, &activationOperationID, &activationRequestHash, &attestationRef,
		&attestationDigest, &attestationIssuer, &attestationKeyID, &attestationVersion,
		&attestationSignature, &allCredentialsEnabled, &allSubscriptionsEnabled,
		&oldCredentialSetInvalidated, &credentialFingerprintGateEnforced,
		&authorizationCacheInvalidated, &authorizationCacheDurableOutbox,
		&authCacheMinimumEvents, &resultSnapshot, &childResponseSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	request := record.Request
	result := record.Result
	if !reflect.DeepEqual(preparedSetHash, request.PreparedSetHash[:]) ||
		childOperationID != request.OperationID ||
		!reflect.DeepEqual(childRequestHash, request.RequestHash[:]) ||
		prepareOperationID != request.PrepareOperationID ||
		activationOperationID != request.ActivationOperationID ||
		!reflect.DeepEqual(activationRequestHash, request.ActivationRequestHash[:]) ||
		attestationRef != result.AttestationRef ||
		!reflect.DeepEqual(attestationDigest, result.AttestationDigest[:]) ||
		attestationIssuer != result.AttestationIssuer || attestationKeyID != result.AttestationKeyID ||
		attestationVersion != int64(result.AttestationVersion) ||
		!reflect.DeepEqual(attestationSignature, result.Attestation) ||
		allCredentialsEnabled != result.AllCredentialsEnabled ||
		allSubscriptionsEnabled != result.AllSubscriptionsEnabled ||
		oldCredentialSetInvalidated != result.OldCredentialSetInvalidated ||
		credentialFingerprintGateEnforced != result.CredentialFingerprintGateEnforced ||
		authorizationCacheInvalidated != result.AuthorizationCacheInvalidated ||
		authorizationCacheDurableOutbox != result.AuthCacheDurableOutbox ||
		authCacheMinimumEvents != result.AuthCacheMinimumEvents {
		t.Fatalf("released provider proof does not match durable request/result")
	}
	var storedResult recovery.PermanentPoolRotationCommitResult
	if err := json.Unmarshal(resultSnapshot, &storedResult); err != nil {
		t.Fatalf("decode released provider result snapshot: %v", err)
	}
	if !reflect.DeepEqual(storedResult, result) {
		t.Fatalf("released provider result snapshot differs from durable result: got=%+v want=%+v",
			storedResult, result)
	}
	var storedChildResult recovery.PermanentPoolRotationCommitResult
	if err := json.Unmarshal(childResponseSnapshot, &storedChildResult); err != nil {
		t.Fatalf("decode provider child response snapshot: %v", err)
	}
	if !reflect.DeepEqual(storedChildResult, result) {
		t.Fatalf("provider child response snapshot differs from durable result: got=%+v want=%+v",
			storedChildResult, result)
	}
}

func insertManagerProviderPendingFixture(t *testing.T, ctx context.Context, db *sql.DB) managerProcessFixture {
	t.Helper()
	fixture := managerProcessFixture{
		finalizationKey: recovery.OperationKey{ClientID: "manager-process-client",
			OperationID: "manager-process-finalize"},
		planExternalID: "manager-process-plan", caseExternalID: "manager-process-case",
		seatExternalID: "manager-process-seat", targetMemberID: "manager-process-target",
		oldOwner: "manager-process-expired", initialFence: 7,
	}
	const poolExternalID = "manager-process-pool"
	const seatChildOperationID = "manager-process-seat-child"
	const preparationOperationID = "manager-process-prepare-set"
	const activationOperationID = "manager-process-activate"
	seatRequest := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     seatChildOperationID, PlanID: fixture.planExternalID,
		CeremonyType: recovery.CeremonyBootstrap, PoolID: poolExternalID,
		FromEpoch: 1, ToEpoch: 2, SeatID: fixture.seatExternalID,
		TargetMemberID: fixture.targetMemberID, ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 4101, SubscriptionID: 4201, APIKeyID: 4301,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	seatRequest.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(seatRequest)
	credentialFingerprint := sha256.Sum256([]byte("manager-process-credential"))
	providerDigest := sha256.Sum256([]byte("manager-process-prepare-result"))
	binding := recovery.PermanentSeatActivationBinding{
		SeatID: fixture.seatExternalID, TargetMemberID: fixture.targetMemberID,
		ExpectedAssignmentEpoch: 1, PrincipalUserID: 4101, SubscriptionID: 4201,
		APIKeyID: 4301, ActiveAPIKeyVersion: 2, ChildOperationID: seatChildOperationID,
		ChildRequestHash: seatRequest.RequestHash, CredentialFingerprint: credentialFingerprint,
		PreparedRotationRef: "manager-process-prepared",
	}
	var err error
	fixture.preparedSetHash, err = recovery.PermanentPreparedSeatSetHash(
		[]recovery.PermanentSeatActivationBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	childSetHash, err := recovery.PermanentRotationChildSetHash(
		[]recovery.PermanentSeatRotationPrepareRequest{seatRequest})
	if err != nil {
		t.Fatal(err)
	}
	preparationRequest := recovery.PermanentPoolRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     preparationOperationID, PlanID: fixture.planExternalID,
		CeremonyType: recovery.CeremonyBootstrap, PoolID: poolExternalID,
		FromEpoch: 1, ToEpoch: 2, ChildSetHash: childSetHash,
		Seats: []recovery.PermanentSeatRotationPrepareRequest{seatRequest},
	}
	preparationRequest.RequestHash = recovery.PermanentPoolRotationPrepareRequestHash(preparationRequest)
	activationRequest := recovery.PermanentPoolRotationActivateRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     activationOperationID, PrepareOperationID: preparationOperationID,
		PlanID: fixture.planExternalID, CeremonyType: recovery.CeremonyBootstrap,
		PoolID: poolExternalID, FromEpoch: 1, ToEpoch: 2,
		PreparedSetHash: fixture.preparedSetHash,
		Seats:           []recovery.PermanentSeatActivationBinding{binding},
	}
	activationRequest.RequestHash = recovery.PermanentPoolRotationActivateRequestHash(activationRequest)
	seatSnapshot := managerProcessCanonicalIntent(t, seatRequest)
	preparationSnapshot := managerProcessRotationIntent(t, preparationRequest,
		"child_set_hash", childSetHash)
	activationSnapshot := managerProcessRotationIntent(t, activationRequest,
		"prepared_set_hash", fixture.preparedSetHash)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tables := []string{
		"integration_operations", "members", "pools", "seats", "seat_assignments",
		"suspension_cases", "membership_epochs", "recovery_epoch_plans", "recovery_plan_seats",
		"pool_resource_accounts", "recovery_plan_resource_accounts", "manifests",
		"credential_batches", "recovery_plan_batch_bindings", "recovery_control_evidence",
		"credential_claims", "recovery_seat_rotation_progress", "permanent_replacement_cases",
		"recovery_pool_preparation_attempts", "recovery_pool_activation_attempts",
		"recovery_pool_activation_seats",
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
			t.Fatalf("disable %s fixture triggers: %v", table, err)
		}
	}

	var poolID, oldMemberID, targetMemberID, seatID, suspensionID, fromEpochID, toEpochID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, credential_epoch_floor
) VALUES ('manager-process-pool','Manager Process Pool','ACTIVE',2,2,2) RETURNING id`).Scan(&poolID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO members (
external_id, sub2api_user_id, display_name, status
) VALUES ('manager-process-old',4001,'Manager Process Old','ACTIVE') RETURNING id`).Scan(&oldMemberID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO members (
external_id, sub2api_user_id, display_name, status
) VALUES ($1,4002,'Manager Process Target','ACTIVE') RETURNING id`,
		fixture.targetMemberID).Scan(&targetMemberID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO seats (
external_id, pool_id, seat_no, status, assignment_epoch, owner_member_id,
sub2api_principal_id, sub2api_subscription_id, sub2api_api_key_id, active_api_key_version
) VALUES ($1,$2,1,'ACTIVE',2,$3,4101,4201,4301,2) RETURNING id`,
		fixture.seatExternalID, poolID, targetMemberID).Scan(&seatID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, starts_at
) VALUES ($1,$2,$3,'PERMANENT','ACTIVE',2,CURRENT_TIMESTAMP)`, seatID, poolID, targetMemberID); err != nil {
		t.Fatal(err)
	}
	freezeSnapshot, freezeHash := managerProcessOperationIntent("manager-process-freeze")
	var freezeIntegrationID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, attempt_count,
response_snapshot, completed_at
) VALUES ($1,'manager-process-freeze','SUSPEND','SEAT',$2,$3,'CURRENT',
$4,$5::jsonb,'SUCCEEDED',1,1,jsonb_build_object('status','succeeded'),CURRENT_TIMESTAMP) RETURNING id`,
		fixture.finalizationKey.ClientID, seatID, fixture.seatExternalID, freezeHash[:],
		freezeSnapshot).Scan(&freezeIntegrationID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO suspension_cases (
seat_id, operation_id, integration_operation_id, migration_state, status, reason_code,
expected_assignment_epoch, frozen_at, freeze_snapshot
) VALUES ($1,'manager-process-freeze',$2,'LEGACY_UNRECOVERABLE','FROZEN','RECOVERY',1,
CURRENT_TIMESTAMP,jsonb_build_object('status','frozen')) RETURNING id`,
		seatID, freezeIntegrationID).Scan(&suspensionID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold,
recovery_governance_state, activated_at, retired_at
) VALUES ($1,1,'RETIRED',1,1,'LEGACY_UNVERIFIED',CURRENT_TIMESTAMP - interval '2 hours',
CURRENT_TIMESTAMP - interval '1 hour') RETURNING id`, poolID).Scan(&fromEpochID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold,
recovery_governance_state, activated_at
) VALUES ($1,2,'ACTIVE',1,1,'LEGACY_UNVERIFIED',CURRENT_TIMESTAMP - interval '1 hour')
RETURNING id`, poolID).Scan(&toEpochID); err != nil {
		t.Fatal(err)
	}

	insertOperation := func(operationID, operationType, targetType, targetID, targetExternalID,
		status, leaseOwner string, fence int64, requestSnapshot []byte,
		requestHash [sha256.Size]byte) string {
		t.Helper()
		var aggregateID string
		var owner any
		var lease any
		if leaseOwner != "" {
			owner = leaseOwner
			lease = time.Now().UTC().Add(-time.Minute)
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count, response_snapshot, completed_at
) VALUES ($1,$2::varchar,$3,$4,$5,$6,'CURRENT',$7,$8::jsonb,
$9,$10,$11,$12,1,CASE WHEN $9='SUCCEEDED' THEN jsonb_build_object('status','succeeded') ELSE NULL END,
CASE WHEN $9='SUCCEEDED' THEN CURRENT_TIMESTAMP ELSE NULL END) RETURNING id`,
			fixture.finalizationKey.ClientID, operationID, operationType, targetType, targetID,
			targetExternalID, requestHash[:], requestSnapshot, status, fence, owner,
			lease).Scan(&aggregateID); err != nil {
			t.Fatalf("insert %s operation: %v", operationID, err)
		}
		return aggregateID
	}
	insertGenericOperation := func(operationID, operationType, targetType, targetID, targetExternalID,
		status, leaseOwner string, fence int64) string {
		snapshot, requestHash := managerProcessOperationIntent(operationID)
		return insertOperation(operationID, operationType, targetType, targetID, targetExternalID,
			status, leaseOwner, fence, snapshot, requestHash)
	}
	ceremonyID := insertGenericOperation("manager-process-ceremony", "BOOTSTRAP_RECOVERY_EPOCH",
		"POOL", poolID, poolExternalID, "SUCCEEDED", "", 1)
	finalizationID := insertGenericOperation(fixture.finalizationKey.OperationID, "FINALIZE_RECOVERY_BOOTSTRAP",
		"POOL", poolID, poolExternalID, "RUNNING", fixture.oldOwner, fixture.initialFence)
	seatChildID := insertOperation(binding.ChildOperationID, "PREPARE_PERMANENT_REPLACEMENT",
		"SEAT", seatID, fixture.seatExternalID, "SUCCEEDED", "", 1,
		seatSnapshot, seatRequest.RequestHash)
	preparationID := insertOperation(preparationOperationID, "PREPARE_PERMANENT_REPLACEMENT_SET",
		"POOL", poolID, poolExternalID, "SUCCEEDED", "", 1,
		preparationSnapshot, preparationRequest.RequestHash)
	activationID := insertOperation(activationOperationID, "ACTIVATE_PERMANENT_REPLACEMENT",
		"POOL", poolID, poolExternalID, "SUCCEEDED", "", 1,
		activationSnapshot, activationRequest.RequestHash)
	registrationID := insertGenericOperation("manager-process-account-registration", "REGISTER_RESOURCE_ACCOUNT",
		"POOL", poolID, poolExternalID, "SUCCEEDED", "", 1)
	evidenceOperationID := insertGenericOperation("manager-process-evidence", "VERIFY_RECOVERY_CONTROL",
		"POOL", poolID, poolExternalID, "SUCCEEDED", "", 1)

	if err := tx.QueryRowContext(ctx, `INSERT INTO recovery_epoch_plans (
external_id, integration_operation_id, ceremony_type, pool_id, from_epoch, to_epoch, status,
governance_threshold, recovery_threshold, required_share_ack_count,
expected_member_count, expected_seat_count, expected_resource_count, expected_control_batch_count,
provider_attestation_set_hash, previous_manifest_hash, from_epoch_status, from_governance_state,
bootstrap_attestation_ref, bootstrap_attestation_digest, bootstrap_attestation_issuer,
bootstrap_attestation_key_id, bootstrap_attestation_signature, bootstrap_attestation_version,
ready_at, finalized_at, version
) VALUES ($1,$2,'BOOTSTRAP',$3,1,2,'FINALIZED',1,1,1,1,1,1,4,
decode(repeat('31',32),'hex'),decode(repeat('00',32),'hex'),'ACTIVE','LEGACY_UNVERIFIED',
'manager-process-bootstrap',decode(repeat('32',32),'hex'),'manager-process-issuer',
'manager-process-key',decode('33','hex'),1,CURRENT_TIMESTAMP - interval '2 hours',
CURRENT_TIMESTAMP - interval '1 hour',2) RETURNING id`, fixture.planExternalID, ceremonyID,
		poolID).Scan(&fixture.planID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE membership_epochs SET recovery_plan_id=$1
WHERE id=$2`, fixture.planID, toEpochID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO manifests (
epoch_id, protocol_version, canonical_payload, manifest_hash, platform_signature, status,
published_at, external_id, recovery_plan_id, migration_state
) VALUES ($1,'fixture-v1','{}'::jsonb,decode(repeat('34',32),'hex'),decode('35','hex'),
'ACTIVE',CURRENT_TIMESTAMP,'manager-process-manifest',$2,'LEGACY_UNVERIFIED')`,
		toEpochID, fixture.planID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_seats (
plan_id, pool_id, from_epoch, to_epoch, seat_id, from_member_id, to_member_id,
expected_assignment_epoch, expected_active_api_key_version, is_replacement,
freeze_suspension_case_id, freeze_operation_id, freeze_snapshot_hash
) VALUES ($1,$2,1,2,$3,$4,$5,1,1,true,$6,'manager-process-freeze',
decode(repeat('36',32),'hex'))`, fixture.planID, poolID, seatID, oldMemberID, targetMemberID,
		suspensionID); err != nil {
		t.Fatal(err)
	}

	var accountID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO pool_resource_accounts (
external_id, pool_id, registration_operation_id, provider, provider_account_ref,
inventory_version, provider_key_ref, attestation_digest, attestation_signature, status
) VALUES ('manager-process-account',$1,$2,'sub2api','manager-process-account-ref',1,
'manager-process-provider-key',decode(repeat('37',32),'hex'),decode('38','hex'),'ACTIVE')
RETURNING id`, poolID, registrationID).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_resource_accounts (
plan_id, resource_account_id, pool_id, account_external_id, provider, provider_account_ref,
inventory_version, provider_key_ref, attestation_digest, provider_binding,
control_evidence_external_id, control_attestation_digest, control_attestation_issuer,
control_attestation_key_id, control_attestation_version
) VALUES ($1,$2,$3,'manager-process-account','sub2api','manager-process-account-ref',1,
'manager-process-provider-key',decode(repeat('37',32),'hex'),'manager-process-binding',
'manager-process-evidence',decode(repeat('39',32),'hex'),'manager-process-issuer',
'manager-process-control-key',1)`, fixture.planID, accountID, poolID); err != nil {
		t.Fatal(err)
	}
	batchTypes := []string{"LOGIN", "MFA", "RECOVERY", "OWNERSHIP"}
	for index, batchType := range batchTypes {
		for _, epochRole := range []string{"FROM", "TO"} {
			epoch := 1
			status := "RETIRED"
			if epochRole == "TO" {
				epoch = 2
				status = "ACTIVE"
			}
			externalID := fmt.Sprintf("manager-process-%s-%s", strings.ToLower(epochRole),
				strings.ToLower(batchType))
			var batchID string
			if err := tx.QueryRowContext(ctx, `INSERT INTO credential_batches (
external_id, migration_state, pool_id, membership_epoch, resource_account_ref,
batch_type, batch_version, status
) VALUES ($1,'LEGACY_UNRECOVERABLE',$2,$3,'manager-process-account-ref',$4,1,$5)
RETURNING id`, externalID, poolID, epoch, batchType, status).Scan(&batchID); err != nil {
				t.Fatalf("insert %s %s batch: %v", epochRole, batchType, err)
			}
			ciphertextHash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", epochRole, batchType, index)))
			var recoveryWrap any
			if epochRole == "TO" {
				wrap := sha256.Sum256([]byte("wrap-" + externalID))
				recoveryWrap = wrap[:]
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_batch_bindings (
plan_id, resource_account_id, epoch_role, batch_type, credential_batch_id,
ciphertext_hash, recovery_wrap_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7)`, fixture.planID, accountID, epochRole,
				batchType, batchID, ciphertextHash[:], recoveryWrap); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_control_evidence (
external_id, integration_operation_id, plan_id, resource_account_id,
provider_attestation_ref, provider_attestation_digest, provider_attestation_issuer,
provider_attestation_key_id, provider_attestation_version, ceremony_type,
attestation_purpose, status, verified_at, committed_at,
provider_attestation_algorithm, provider_attestation_signature,
provider_attestation_protocol_version
) VALUES ('manager-process-evidence',$1,$2,$3,'manager-process-control-proof',
decode(repeat('39',32),'hex'),'manager-process-issuer','manager-process-control-key',1,
'BOOTSTRAP','BOOTSTRAP_GENESIS','COMMITTED',CURRENT_TIMESTAMP - interval '2 hours',
CURRENT_TIMESTAMP - interval '1 hour','Ed25519',decode('3a','hex'),
'trusted-pool/provider-proof-statement/v1')`, evidenceOperationID, fixture.planID, accountID); err != nil {
		t.Fatal(err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO permanent_replacement_cases (
external_id, integration_operation_id, plan_id, status, version
) VALUES ($1,$2,$3,'PROVIDER_COMMIT_PENDING',4)`, fixture.caseExternalID,
		finalizationID, fixture.planID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_pool_preparation_attempts (
plan_id, integration_operation_id, intent_set_hash, status, version
) VALUES ($1,$2,$3,'PREPARED',2)`, fixture.planID, preparationID,
		childSetHash[:]); err != nil {
		t.Fatal(err)
	}
	var activationAttemptID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO recovery_pool_activation_attempts (
plan_id, integration_operation_id, prepared_set_hash, status,
provider_attestation_ref, provider_attestation_digest, provider_attestation_issuer,
provider_attestation_key_id, provider_attestation_version, provider_attestation_signature,
old_credential_set_invalidated, credential_fingerprint_gate_enforced,
authorization_cache_invalidated, authorization_cache_durable_outbox,
auth_cache_minimum_events, activated_at, version
) VALUES ($1,$2,$3,'ACTIVATED','manager-process-activation-proof',
decode(repeat('41',32),'hex'),'manager-process-provider','manager-process-activation-key',
1,decode('42','hex'),true,true,false,true,2,CURRENT_TIMESTAMP - interval '1 hour',2)
RETURNING id`, fixture.planID, activationID, fixture.preparedSetHash[:]).Scan(&activationAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_pool_activation_seats (
activation_attempt_id, plan_id, seat_id, target_member_id, prepared_reference,
principal_user_id, subscription_id, api_key_id, api_key_version, credential_fingerprint,
current_concurrency, pending_settlements
) VALUES ($1,$2,$3,$4,$5,4101,4201,4301,2,$6,0,0)`, activationAttemptID,
		fixture.planID, seatID, targetMemberID, binding.PreparedRotationRef,
		credentialFingerprint[:]); err != nil {
		t.Fatal(err)
	}
	var claimID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_intent_hash, claim_token_hash, credential_fingerprint, envelope_algorithm,
envelope_key_ref, envelope_ciphertext, envelope_nonce, envelope_aad_hash,
wrapped_dek_kms, expires_at
) VALUES ($1,$2,$3,'manager-process-claim','ISSUANCE_PENDING',
decode(repeat('43',32),'hex'),NULL,$4,'TEST','kms/manager-process',
decode('44','hex'),decode('0102030405060708090a0b0c','hex'),
decode(repeat('45',32),'hex'),decode('46','hex'),NULL) RETURNING id`, seatChildID,
		seatID, targetMemberID, credentialFingerprint[:]).Scan(&claimID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_seat_rotation_progress (
plan_id, seat_id, derived_operation_id, status, principal_user_id, subscription_id,
api_key_id, api_key_version, credential_fingerprint, credential_claim_id,
prepared_reference, provider_result_digest, attempt_count
) VALUES ($1,$2,$3,'COMMITTED',4101,4201,4301,2,$4,$5,$6,$7,1)`,
		fixture.planID, seatID, seatChildID, credentialFingerprint[:], claimID,
		binding.PreparedRotationRef, providerDigest[:]); err != nil {
		t.Fatal(err)
	}

	if _, err := tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		t.Fatalf("flush Manager process fixture constraints: %v", err)
	}
	for index := len(tables) - 1; index >= 0; index-- {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+tables[index]+` ENABLE TRIGGER USER`); err != nil {
			t.Fatalf("enable %s fixture triggers: %v", tables[index], err)
		}
	}
	if _, err := tx.ExecContext(ctx, `SELECT assert_phase2g_execution_aggregate($1)`,
		fixture.planID); err != nil {
		t.Fatalf("Manager process fixture is not a valid provider-pending aggregate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit Manager process fixture: %v", err)
	}
	_ = fromEpochID
	return fixture
}
