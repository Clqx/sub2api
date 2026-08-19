package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/domain"
)

func TestPersistentProvisionCommitsAggregateAndRestartReplayDoesNotCallGateway(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	calls := []string{}
	stored := persistentTestOperation(now, OperationRunning)
	claim := persistentTestClaim(now, CredentialClaimReady)
	seat := persistentTestSeat(now)
	store := &persistentStoreStub{}
	store.beginOperation = func(_ context.Context, input BeginOperationInput) (*StoredOperation, bool, error) {
		calls = append(calls, "begin")
		stored.RequestHash = input.RequestHash
		stored.RequestSnapshot = input.RequestSnapshot
		return stored, true, nil
	}
	store.acquireOperation = func(context.Context, AcquireOperationLeaseInput) (*OperationLease, error) {
		calls = append(calls, "lease")
		return &OperationLease{Operation: stored, FencingToken: 7}, nil
	}
	store.preflightProvision = func(context.Context, ProvisionPreflightInput) error {
		calls = append(calls, "preflight")
		return nil
	}
	store.commitProvision = func(_ context.Context, input CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
		calls = append(calls, "commit")
		if input.Operation.FencingToken != 7 || input.OwnerExternalID != "owner-1" || len(input.Operation.Claim.Envelope.Ciphertext) == 0 {
			t.Fatalf("invalid aggregate input: %+v", input)
		}
		if input.ExistingGroupID != 10 || input.PrincipalUserID != 101 || input.SubscriptionID != 201 || input.APIKeyID != 301 ||
			strings.Contains(string(input.Operation.ResultSnapshot), "sk-secret") {
			t.Fatalf("provision snapshot leaked secret or lost Group binding: %s", input.Operation.ResultSnapshot)
		}
		stored.Status = OperationSucceeded
		return stored, claim, seat, nil
	}
	gateway := &persistentGatewayStub{provision: func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error) {
		calls = append(calls, "gateway")
		return ProvisionGatewayResult{ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "ACTIVE", AssignmentEpoch: 1,
			PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301, ActiveAPIKeyVersion: 1,
			LastOperationID: "op-1", Credential: "sk-secret"}, nil
	}}
	cipher := &persistentCipherStub{seal: func(_ context.Context, plaintext string, _ []byte) (CredentialEnvelope, error) {
		calls = append(calls, "seal")
		if plaintext != "sk-secret" {
			t.Fatalf("unexpected plaintext %q", plaintext)
		}
		return CredentialEnvelope{Algorithm: "TEST", KeyRef: "kms/test", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), WrappedDEK: []byte("dek")}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	result, err := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	if err != nil {
		t.Fatalf("ProvisionSeat(): %v", err)
	}
	if result.Seat == nil || result.Operation.CredentialClaimToken != "claim-token" {
		t.Fatalf("unexpected provision result: %+v", result)
	}
	if want := []string{"begin", "lease", "preflight", "gateway", "seal", "commit"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}

	// 模拟进程重启：新 Coordinator 只从 Store 重建结果，不再次调用上游，也不重发原始 token。
	calls = nil
	store.beginOperation = func(context.Context, BeginOperationInput) (*StoredOperation, bool, error) {
		calls = append(calls, "begin")
		return stored, false, nil
	}
	store.loadSeat = func(context.Context, string) (*PersistedSeat, error) {
		calls = append(calls, "load-seat")
		return seat, nil
	}
	store.loadClaim = func(context.Context, ClaimKey) (*StoredCredentialClaim, error) {
		calls = append(calls, "load-claim")
		return claim, nil
	}
	restarted := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	replayed, err := restarted.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	if err != nil {
		t.Fatalf("restart replay: %v", err)
	}
	if replayed.Operation.CredentialClaimToken != "" {
		t.Fatal("restart replay must not mint or disclose another claim token")
	}
	if want := []string{"begin", "load-seat", "load-claim"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("restart calls=%v want=%v", calls, want)
	}
}

func TestPersistentProvisionPreflightFailsBeforeGatewayAndSeal(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	stored := persistentTestOperation(now, OperationRunning)
	gatewayCalls, sealCalls := 0, 0
	preflightCalls := 0
	store := &persistentStoreStub{
		beginOperation: func(context.Context, BeginOperationInput) (*StoredOperation, bool, error) {
			return stored, true, nil
		},
		acquireOperation: func(context.Context, AcquireOperationLeaseInput) (*OperationLease, error) {
			return &OperationLease{Operation: stored, FencingToken: 3}, nil
		},
		preflightProvision: func(_ context.Context, input ProvisionPreflightInput) error {
			preflightCalls++
			if input.PoolExternalID != "pool-1" || input.OwnerExternalID != "owner-1" || input.ExistingGroupID != 10 {
				t.Fatalf("unexpected preflight input: %+v", input)
			}
			if preflightCalls == 1 {
				return ErrWorkflowInvalidState
			}
			return nil
		},
		commitOperation: func(_ context.Context, input CommitOperationInput) (*StoredOperation, error) {
			if input.Status != OperationRetryable || input.ErrorCode != "CALLER_REPLAY_REQUIRED" {
				t.Fatalf("preflight failure did not release lease safely: %+v", input)
			}
			stored.Status, stored.ErrorCode = input.Status, input.ErrorCode
			return stored, nil
		},
		commitProvision: func(context.Context, CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
			stored.Status = OperationSucceeded
			return stored, persistentTestClaim(now, CredentialClaimReady), persistentTestSeat(now), nil
		},
	}
	gateway := &persistentGatewayStub{provision: func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error) {
		gatewayCalls++
		return ProvisionGatewayResult{ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "ACTIVE", AssignmentEpoch: 1,
			PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301, ActiveAPIKeyVersion: 1,
			LastOperationID: "op-1", Credential: "sk-secret"}, nil
	}}
	cipher := &persistentCipherStub{seal: func(context.Context, string, []byte) (CredentialEnvelope, error) {
		sealCalls++
		return CredentialEnvelope{Algorithm: "TEST", KeyRef: "kms/test", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), WrappedDEK: []byte("dek")}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	_, err := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	if !errors.Is(err, ErrWorkflowInvalidState) {
		t.Fatalf("expected preflight state error, got %v", err)
	}
	if gatewayCalls != 0 || sealCalls != 0 {
		t.Fatalf("preflight failure caused side effects: gateway=%d seal=%d", gatewayCalls, sealCalls)
	}
	result, err := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	if err != nil || result == nil || result.Operation.Status != OperationSucceeded {
		t.Fatalf("same request could not retry immediately after preflight repair: result=%+v err=%v", result, err)
	}
	if gatewayCalls != 1 || sealCalls != 1 {
		t.Fatalf("repaired retry side effects: gateway=%d seal=%d", gatewayCalls, sealCalls)
	}
}

func TestPersistentFailedProvisionReplayRestoresStableTypedError(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	stored := persistentTestOperation(now, OperationRunning)
	gatewayCalls := 0
	store := &persistentStoreStub{
		beginOperation: func(context.Context, BeginOperationInput) (*StoredOperation, bool, error) {
			return stored, stored.Status == OperationRunning, nil
		},
		acquireOperation: func(context.Context, AcquireOperationLeaseInput) (*OperationLease, error) {
			return &OperationLease{Operation: stored, FencingToken: 4}, nil
		},
		preflightProvision: func(context.Context, ProvisionPreflightInput) error { return nil },
		commitOperation: func(_ context.Context, input CommitOperationInput) (*StoredOperation, error) {
			stored.Status, stored.ErrorCode, stored.ErrorDetail = input.Status, input.ErrorCode, input.ErrorDetail
			return stored, nil
		},
	}
	gateway := &persistentGatewayStub{provision: func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error) {
		gatewayCalls++
		return ProvisionGatewayResult{}, &GatewayError{Reason: "secret upstream body", StatusCode: 409}
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, &persistentCipherStub{}, now)

	_, firstErr := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	_, replayErr := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now))
	var firstTyped, replayTyped *PersistentOperationError
	if !errors.As(firstErr, &firstTyped) || !errors.As(replayErr, &replayTyped) ||
		firstTyped.Code != "UPSTREAM_CONFLICT" || replayTyped.Code != firstTyped.Code {
		t.Fatalf("unstable persisted error: first=%v replay=%v", firstErr, replayErr)
	}
	if gatewayCalls != 1 || strings.Contains(firstErr.Error(), "secret upstream body") || strings.Contains(replayErr.Error(), "secret upstream body") {
		t.Fatalf("failed replay called gateway or leaked detail: calls=%d first=%v replay=%v", gatewayCalls, firstErr, replayErr)
	}
}

func TestPersistentSucceededProvisionReplayRequiresSeatAndClaim(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	stored := persistentTestOperation(now, OperationSucceeded)
	store := &persistentStoreStub{
		beginOperation: func(context.Context, BeginOperationInput) (*StoredOperation, bool, error) {
			return stored, false, nil
		},
		loadSeat: func(context.Context, string) (*PersistedSeat, error) {
			return nil, ErrWorkflowNotFound
		},
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) {
			t.Fatal("claim was loaded after required Seat was missing")
			return nil, nil
		},
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	if _, err := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now)); !errors.Is(err, ErrWorkflowCorruptState) {
		t.Fatalf("missing succeeded Seat was not treated as corrupt: %v", err)
	}
	store.loadSeat = func(context.Context, string) (*PersistedSeat, error) { return persistentTestSeat(now), nil }
	store.loadClaim = func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return nil, ErrWorkflowNotFound }
	if _, err := coordinator.ProvisionSeat(context.Background(), persistentProvisionCommand(now)); !errors.Is(err, ErrWorkflowCorruptState) {
		t.Fatalf("missing succeeded claim was not treated as corrupt: %v", err)
	}
}

func TestPersistentSuspendBeginsAtomicallyAndPersistsDraining(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	calls := []string{}
	store := &persistentStoreStub{
		loadOperation: func(context.Context, OperationKey) (*StoredOperation, error) {
			calls = append(calls, "load-operation")
			return nil, ErrWorkflowNotFound
		},
		loadSeat: func(context.Context, string) (*PersistedSeat, error) {
			calls = append(calls, "load-seat")
			return persistentTestSeat(now), nil
		},
	}
	var target *SuspendTarget
	store.beginSuspend = func(_ context.Context, input BeginSuspendInput) (*SuspendTarget, bool, error) {
		calls = append(calls, "begin-suspend")
		var snapshot persistentSuspendRequest
		if err := json.Unmarshal(input.RequestSnapshot, &snapshot); err != nil {
			t.Fatal(err)
		}
		if input.ReasonCode != SuspendReasonManualPolicyBreach || snapshot.Version != 1 ||
			snapshot.ReasonCode != SuspendReasonManualPolicyBreach || snapshot.AssignmentEpoch != 1 ||
			snapshot.OperationID != "suspend-1" || snapshot.SeatID != "seat-1" {
			t.Fatalf("unsafe suspend intent: input=%+v snapshot=%+v", input, snapshot)
		}
		op := persistentTestOperation(now, OperationRunning)
		op.Key.OperationID, op.Kind, op.TargetExternalID = "suspend-1", OperationSuspend, "seat-1"
		leaseUntil := now.Add(time.Minute)
		op.RequestHash, op.RequestSnapshot, op.FencingToken = input.RequestHash, input.RequestSnapshot, 11
		op.LeaseOwner, op.LeaseExpiresAt = "worker-1", &leaseUntil
		target = persistentSuspendTarget(op, now, SuspendCasePending)
		return target, true, nil
	}
	store.commitSuspend = func(_ context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
		calls = append(calls, "commit-draining")
		if input.FencingToken != 11 || input.Progress != SuspendCaseDraining ||
			input.CurrentConcurrency == nil || *input.CurrentConcurrency != 2 ||
			input.PendingSettlements == nil || *input.PendingSettlements != 1 || input.NextAttemptAt == nil {
			t.Fatalf("unexpected draining commit: %+v", input)
		}
		target.Operation.Status, target.Case.Status = OperationReconcileRequired, SuspendCaseDraining
		return target, nil
	}
	gateway := &persistentGatewayStub{suspend: func(_ context.Context, command SuspendCommand) (SuspendResult, error) {
		calls = append(calls, "gateway-suspend")
		if command.OperationID != "suspend-1" || command.SeatID != "seat-1" || command.AssignmentEpoch != 1 {
			t.Fatalf("unexpected suspend command: %+v", command)
		}
		return SuspendResult{Draining: true, CurrentConcurrency: 2, PendingSettlements: 1}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, &persistentCipherStub{}, now)
	op, err := coordinator.Suspend(context.Background(), "suspend-1", "seat-1")
	if err != nil || op.Status != OperationReconcileRequired {
		t.Fatalf("Suspend() op=%+v err=%v", op, err)
	}
	if want := []string{"load-operation", "load-seat", "begin-suspend", "gateway-suspend", "commit-draining"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentSuspendBeginConcurrentCompletionDoesNotCallGateway(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	store := &persistentStoreStub{
		loadOperation: func(context.Context, OperationKey) (*StoredOperation, error) { return nil, ErrWorkflowNotFound },
		loadSeat:      func(context.Context, string) (*PersistedSeat, error) { return persistentTestSeat(now), nil },
	}
	store.beginSuspend = func(_ context.Context, input BeginSuspendInput) (*SuspendTarget, bool, error) {
		op := persistentTestOperation(now, OperationSucceeded)
		op.Key.OperationID, op.Kind, op.TargetExternalID = "suspend-race", OperationSuspend, "seat-1"
		op.RequestHash, op.RequestSnapshot = input.RequestHash, input.RequestSnapshot
		return persistentSuspendTarget(op, now, SuspendCaseFrozen), false, nil
	}
	gateway := &persistentGatewayStub{
		suspend: func(context.Context, SuspendCommand) (SuspendResult, error) {
			t.Fatal("concurrently completed suspend called gateway")
			return SuspendResult{}, nil
		},
		reconcile: func(context.Context, SuspendCommand) (GatewayOperationResult, error) {
			t.Fatal("concurrently completed suspend reconciled gateway")
			return GatewayOperationResult{}, nil
		},
	}
	coordinator := newPersistentTestCoordinator(t, store, gateway, &persistentCipherStub{}, now)
	op, err := coordinator.Suspend(context.Background(), "suspend-race", "seat-1")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("Suspend() op=%+v err=%v", op, err)
	}
}

func TestPersistentSuspendRecoveryRebuildsCommandFromSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	snapshot, hash, err := persistentSuspendIntent(SuspendCommand{
		OperationID: "suspend-restart", SeatID: "seat-1", PoolID: "pool-1", UserID: "owner-1", AssignmentEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	op := persistentTestOperation(now, OperationReconcileRequired)
	op.Key.OperationID, op.Kind, op.TargetExternalID = "suspend-restart", OperationSuspend, "seat-1"
	op.RequestSnapshot, op.RequestHash, op.FencingToken = snapshot, hash, 12
	leaseUntil := now.Add(time.Minute)
	op.LeaseOwner, op.LeaseExpiresAt = "worker-1", &leaseUntil
	target := persistentSuspendTarget(op, now, SuspendCaseDraining)
	calls := []string{}
	store := &persistentStoreStub{
		acquireNextOperation: func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error) {
			calls = append(calls, "lease")
			return &OperationLease{Operation: op, FencingToken: 12}, nil
		},
		loadSuspend: func(_ context.Context, key OperationKey) (*SuspendTarget, error) {
			calls = append(calls, "load-target")
			if key.OperationID != "suspend-restart" {
				t.Fatalf("unexpected recovery key: %+v", key)
			}
			return target, nil
		},
	}
	freeze := persistentValidFreeze("suspend-restart", 1, now)
	gateway := &persistentGatewayStub{reconcile: func(_ context.Context, command SuspendCommand) (GatewayOperationResult, error) {
		calls = append(calls, "gateway-reconcile")
		if command.OperationID != "suspend-restart" || command.SeatID != "seat-1" || command.AssignmentEpoch != 1 {
			t.Fatalf("recovery did not use persisted snapshot: %+v", command)
		}
		return GatewayOperationResult{Applied: true, Freeze: freeze}, nil
	}}
	store.commitSuspend = func(_ context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
		calls = append(calls, "commit-frozen")
		if input.Progress != SuspendCaseFrozen || input.FencingToken != 12 || input.Freeze != freeze || input.NextAttemptAt != nil {
			t.Fatalf("unexpected frozen commit: %+v", input)
		}
		target.Operation.Status, target.Case.Status = OperationSucceeded, SuspendCaseFrozen
		return target, nil
	}
	coordinator := newPersistentTestCoordinator(t, store, gateway, &persistentCipherStub{}, now)
	worker, _ := NewPersistentRecoveryWorker(coordinator)
	worked, err := worker.RecoverNextOperation(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextOperation() worked=%v err=%v", worked, err)
	}
	if want := []string{"lease", "load-target", "gateway-reconcile", "commit-frozen"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentSuspendGatewayFailureCommitsPendingAggregate(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	snapshot, hash, err := persistentSuspendIntent(SuspendCommand{
		OperationID: "suspend-1", SeatID: "seat-1", PoolID: "pool-1", UserID: "owner-1", AssignmentEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	op := persistentTestOperation(now, OperationRunning)
	op.Key.OperationID, op.Kind, op.TargetExternalID = "suspend-1", OperationSuspend, "seat-1"
	op.RequestSnapshot, op.RequestHash, op.FencingToken = snapshot, hash, 14
	target := persistentSuspendTarget(op, now, SuspendCasePending)
	store := &persistentStoreStub{commitSuspend: func(_ context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
		if input.Progress != SuspendCasePending || input.ErrorCode != "OPERATOR_REVIEW_REQUIRED" ||
			input.CurrentConcurrency != nil || input.PendingSettlements != nil || input.NextAttemptAt == nil {
			t.Fatalf("gateway failure escaped aggregate commit: %+v", input)
		}
		target.Operation.Status = OperationReconcileRequired
		return target, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	result, err := coordinator.commitSuspendGatewayResult(context.Background(), target, GatewayOperationResult{}, &GatewayError{
		Reason: "upstream detail", StatusCode: 409,
	})
	var typed *PersistentOperationError
	if !errors.As(err, &typed) || typed.Code != "OPERATOR_REVIEW_REQUIRED" || result.Status != OperationReconcileRequired {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPersistentDrainingReconcileTimeoutKeepsLastObservedCounters(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	op := persistentTestOperation(now, OperationReconcileRequired)
	op.Key.OperationID, op.Kind, op.TargetExternalID, op.FencingToken = "suspend-1", OperationSuspend, "seat-1", 15
	target := persistentSuspendTarget(op, now, SuspendCaseDraining)
	currentConcurrency, pendingSettlements := 2, 1
	target.Case.CurrentConcurrency, target.Case.PendingSettlements = &currentConcurrency, &pendingSettlements
	store := &persistentStoreStub{commitSuspend: func(_ context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
		if input.Progress != SuspendCaseDraining || input.ErrorCode != "UPSTREAM_RESULT_AMBIGUOUS" ||
			input.CurrentConcurrency == nil || *input.CurrentConcurrency != 2 ||
			input.PendingSettlements == nil || *input.PendingSettlements != 1 || input.NextAttemptAt == nil {
			t.Fatalf("draining timeout regressed state or evidence: %+v", input)
		}
		if strings.Contains(string(input.ResultSnapshot), "timeout raw detail") {
			t.Fatalf("upstream detail leaked into result snapshot: %s", input.ResultSnapshot)
		}
		return target, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	_, err := coordinator.commitSuspendGatewayResult(context.Background(), target, GatewayOperationResult{}, &GatewayError{
		Reason: "timeout raw detail", Retryable: true, Ambiguous: true, StatusCode: 504,
	})
	var typed *PersistentOperationError
	if !errors.As(err, &typed) || typed.Code != "UPSTREAM_RESULT_AMBIGUOUS" {
		t.Fatalf("unexpected timeout error: %v", err)
	}
}

func TestPersistentSuspendRejectsInvalidFreezeEvidenceBeforeFrozenCommit(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*domain.FreezeSnapshot)
	}{
		{name: "old epoch", mutate: func(snapshot *domain.FreezeSnapshot) { snapshot.AssignmentEpoch = 2 }},
		{name: "negative usage", mutate: func(snapshot *domain.FreezeSnapshot) { snapshot.Usage["daily"] = -1 }},
		{name: "missing window", mutate: func(snapshot *domain.FreezeSnapshot) { delete(snapshot.WindowStarts, "weekly") }},
		{name: "missing captured at", mutate: func(snapshot *domain.FreezeSnapshot) { snapshot.CapturedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			op := persistentTestOperation(now, OperationReconcileRequired)
			op.Key.OperationID, op.Kind, op.TargetExternalID, op.FencingToken = "suspend-1", OperationSuspend, "seat-1", 16
			target := persistentSuspendTarget(op, now, SuspendCaseDraining)
			currentConcurrency, pendingSettlements := 2, 1
			target.Case.CurrentConcurrency, target.Case.PendingSettlements = &currentConcurrency, &pendingSettlements
			freeze := persistentValidFreeze("suspend-1", 1, now)
			test.mutate(freeze)
			store := &persistentStoreStub{commitSuspend: func(_ context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
				if input.Progress != SuspendCaseDraining || input.ErrorCode != "UPSTREAM_RESPONSE_INVALID" || input.Freeze != nil ||
					input.CurrentConcurrency == nil || *input.CurrentConcurrency != currentConcurrency ||
					input.PendingSettlements == nil || *input.PendingSettlements != pendingSettlements {
					t.Fatalf("invalid evidence reached frozen commit: %+v", input)
				}
				target.Operation.Status = OperationReconcileRequired
				return target, nil
			}}
			coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
			_, err := coordinator.commitSuspendGatewayResult(context.Background(), target, GatewayOperationResult{Applied: true, Freeze: freeze}, nil)
			var typed *PersistentOperationError
			if !errors.As(err, &typed) || typed.Code != "UPSTREAM_RESPONSE_INVALID" {
				t.Fatalf("invalid evidence error=%v", err)
			}
		})
	}
}

func TestPersistentTemporaryAssignmentCommitsEncryptedClaimAtomically(t *testing.T) {
	now := time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC)
	target := persistentAssignmentTarget(t, now, OperationAssignTemp, "assign-1", "member-2")
	calls := []string{}
	store := &persistentStoreStub{
		loadOperation: func(context.Context, OperationKey) (*StoredOperation, error) {
			calls = append(calls, "load-operation")
			return nil, ErrWorkflowNotFound
		},
		beginAssignment: func(_ context.Context, input BeginAssignmentInput) (*AssignmentTarget, bool, error) {
			calls = append(calls, "begin")
			if input.Kind != OperationAssignTemp || input.TargetMemberExternalID != "member-2" || len(input.RequestSnapshot) == 0 {
				t.Fatalf("unexpected begin assignment: %+v", input)
			}
			target.Operation.RequestHash, target.Operation.RequestSnapshot = input.RequestHash, input.RequestSnapshot
			return target, true, nil
		},
	}
	store.commitAssignment = func(_ context.Context, input CommitAssignmentWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
		calls = append(calls, "commit")
		if input.FencingToken != 21 || input.ExpectedAssignmentEpoch != 1 || input.Claim.TargetMemberExternalID != "member-2" ||
			len(input.Claim.Envelope.Ciphertext) == 0 || strings.Contains(string(input.ResultSnapshot), "rotated-secret") {
			t.Fatalf("unsafe assignment aggregate commit: %+v", input)
		}
		target.Operation.Status, target.Case.Status = OperationSucceeded, AssignmentCaseSucceeded
		claim := persistentTestClaim(now, CredentialClaimReady)
		claim.Key = ClaimKey(target.Operation.Key)
		claim.OperationKind, claim.TargetMemberExternalID = OperationAssignTemp, "member-2"
		claim.ClaimOperationID = assignmentClaimOperationID("assign-1")
		return target.Operation, claim, persistentTestSeat(now), nil
	}
	gateway := &persistentGatewayStub{assign: func(_ context.Context, command AssignmentCommand) (AssignmentResult, error) {
		calls = append(calls, "gateway")
		if command.OperationID != "assign-1" || command.SeatID != "seat-1" || command.TargetUser != "member-2" ||
			command.AssignmentEpoch != 1 || command.MembershipEpoch != 1 || command.FreezeOperationID != "suspend-1" ||
			command.PrincipalUserID != 101 || command.SubscriptionID != 201 || command.APIKeyID != 301 || command.ActiveAPIKeyVersion != 1 {
			t.Fatalf("assignment command was not rebuilt from Store: %+v", command)
		}
		return persistentAssignmentResult("assign-1", "rotated-secret"), nil
	}}
	cipher := &persistentCipherStub{seal: func(_ context.Context, plaintext string, _ []byte) (CredentialEnvelope, error) {
		calls = append(calls, "seal")
		if plaintext != "rotated-secret" {
			t.Fatalf("unexpected plaintext %q", plaintext)
		}
		return CredentialEnvelope{Algorithm: "TEST", KeyRef: "kms/test", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), WrappedDEK: []byte("dek")}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	op, err := coordinator.AssignTemporary(context.Background(), "assign-1", "seat-1", "member-2")
	if err != nil || op.Status != OperationSucceeded || op.CredentialClaimToken != "claim-token" {
		t.Fatalf("AssignTemporary() op=%+v err=%v", op, err)
	}
	if want := []string{"load-operation", "begin", "gateway", "seal", "commit"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentAssignmentRecoveryUsesExplicitStoreTarget(t *testing.T) {
	now := time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC)
	target := persistentAssignmentTarget(t, now, OperationRestore, "restore-1", "owner-1")
	target.Operation.Status = OperationReconcileRequired
	calls := []string{}
	store := &persistentStoreStub{
		acquireNextOperation: func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error) {
			calls = append(calls, "lease")
			return &OperationLease{Operation: target.Operation, FencingToken: 21}, nil
		},
		loadAssignment: func(context.Context, OperationKey) (*AssignmentTarget, error) {
			calls = append(calls, "load-target")
			return target, nil
		},
	}
	store.commitAssignment = func(context.Context, CommitAssignmentWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
		calls = append(calls, "commit")
		target.Operation.Status = OperationSucceeded
		claim := persistentTestClaim(now, CredentialClaimReady)
		claim.OperationKind, claim.TargetMemberExternalID = OperationRestore, "owner-1"
		return target.Operation, claim, persistentTestSeat(now), nil
	}
	gateway := &persistentGatewayStub{reconcileAssignment: func(_ context.Context, command AssignmentCommand) (AssignmentResult, error) {
		calls = append(calls, "reconcile")
		if command.OperationID != "restore-1" || command.Mode != OperationRestore || command.TargetUser != "owner-1" {
			t.Fatalf("restart recovery lost persisted command: %+v", command)
		}
		return persistentAssignmentResult("restore-1", "restored-secret"), nil
	}}
	cipher := &persistentCipherStub{seal: func(context.Context, string, []byte) (CredentialEnvelope, error) {
		return CredentialEnvelope{Algorithm: "TEST", KeyRef: "kms/test", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), WrappedDEK: []byte("dek")}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	worker, _ := NewPersistentRecoveryWorker(coordinator)
	worked, err := worker.RecoverNextOperation(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextOperation() worked=%v err=%v", worked, err)
	}
	if want := []string{"lease", "load-target", "reconcile", "commit"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentAssignmentFailureUsesAggregateOutcome(t *testing.T) {
	now := time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		gateway      *GatewayError
		expectedCode string
	}{
		{name: "ambiguous keeps pending", gateway: &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true, StatusCode: 504}, expectedCode: "UPSTREAM_RESULT_AMBIGUOUS"},
		{name: "ordinary rejection requires operator review", gateway: &GatewayError{Reason: "rejected", StatusCode: 400}, expectedCode: "OPERATOR_REVIEW_REQUIRED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := persistentAssignmentTarget(t, now, OperationAssignTemp, "assign-1", "member-2")
			store := &persistentStoreStub{
				loadOperation:   func(context.Context, OperationKey) (*StoredOperation, error) { return nil, ErrWorkflowNotFound },
				beginAssignment: func(context.Context, BeginAssignmentInput) (*AssignmentTarget, bool, error) { return target, true, nil },
				commitAssignmentFailure: func(_ context.Context, input CommitAssignmentFailureInput) (*AssignmentTarget, error) {
					if input.ConfirmedUnchanged || input.NextAttemptAt == nil || input.ErrorCode != test.expectedCode ||
						strings.Contains(string(input.ResultSnapshot), test.gateway.Reason) {
						t.Fatalf("incorrect assignment failure commit: %+v", input)
					}
					target.Operation.Status = OperationReconcileRequired
					return target, nil
				},
			}
			gateway := &persistentGatewayStub{assign: func(context.Context, AssignmentCommand) (AssignmentResult, error) {
				return AssignmentResult{}, test.gateway
			}}
			coordinator := newPersistentTestCoordinator(t, store, gateway, &persistentCipherStub{}, now)
			op, err := coordinator.AssignTemporary(context.Background(), "assign-1", "seat-1", "member-2")
			if err == nil || op == nil {
				t.Fatalf("assignment failure op=%+v err=%v", op, err)
			}
		})
	}
}

func TestPersistentAssignmentClaimSkipsProvisionAck(t *testing.T) {
	now := time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC)
	claim := persistentTestClaim(now, CredentialClaimReady)
	claim.OperationKind, claim.TargetMemberExternalID = OperationAssignTemp, "member-2"
	claim.TokenHash, claim.ClaimOperationID = hashBytes("claim-token"), assignmentClaimOperationID("assign-1")
	claim.Key.OperationID = "assign-1"
	claim.FencingToken, claim.LeaseOwner = 9, "worker-1"
	store := &persistentStoreStub{
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return claim, nil },
		acquireClaim: func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
			return &CredentialClaimLease{Claim: claim, FencingToken: 9}, nil
		},
		loadSeat: func(context.Context, string) (*PersistedSeat, error) { return persistentTestSeat(now), nil },
		claimCredential: func(_ context.Context, input ClaimCredentialInput) (*StoredCredentialClaim, error) {
			if input.FencingToken != 9 || input.TargetMemberExternalID != "member-2" {
				t.Fatalf("unexpected assignment claim CAS: %+v", input)
			}
			return claim, nil
		},
	}
	cipher := &persistentCipherStub{open: func(context.Context, CredentialEnvelope, []byte) (string, error) { return "rotated-secret", nil }}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, cipher, now)
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), "assign-1", "member-2", "claim-token")
	if err != nil || delivery.Credential != "rotated-secret" {
		t.Fatalf("assignment claim delivery=%+v err=%v", delivery, err)
	}
}

func TestPersistentCredentialClaimUsesAckThenDecryptThenCAS(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	calls := []string{}
	claim := persistentTestClaim(now, CredentialClaimReady)
	claim.TokenHash = hashBytes("claim-token")
	claim.FencingToken = 4
	claim.LeaseOwner = "worker-1"
	store := &persistentStoreStub{}
	store.loadClaim = func(context.Context, ClaimKey) (*StoredCredentialClaim, error) {
		calls = append(calls, "preflight")
		return claim, nil
	}
	acquireCount := 0
	store.acquireClaim = func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
		acquireCount++
		calls = append(calls, "lease")
		copy := *claim
		if acquireCount == 2 {
			copy.AckResultSnapshot = []byte(`{"credential_claimed":true}`)
			copy.Status = CredentialClaimAckPending
			copy.FencingToken = 5
		}
		return &CredentialClaimLease{Claim: &copy, FencingToken: copy.FencingToken}, nil
	}
	store.beginAck = func(context.Context, BeginCredentialAckInput) (*StoredCredentialClaim, error) {
		calls = append(calls, "begin-ack")
		copy := *claim
		copy.Status = CredentialClaimAckPending
		return &copy, nil
	}
	store.commitAck = func(context.Context, CommitCredentialAckInput) (*StoredCredentialClaim, error) {
		calls = append(calls, "commit-ack")
		return claim, nil
	}
	store.claimCredential = func(_ context.Context, input ClaimCredentialInput) (*StoredCredentialClaim, error) {
		calls = append(calls, "claim-cas")
		if input.FencingToken != 5 {
			t.Fatalf("claim used stale fence %d", input.FencingToken)
		}
		copy := *claim
		copy.Status = CredentialClaimClaimed
		return &copy, nil
	}
	store.loadSeat = func(context.Context, string) (*PersistedSeat, error) {
		calls = append(calls, "load-seat")
		return persistentTestSeat(now), nil
	}
	gateway := &persistentGatewayStub{ack: func(context.Context, ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error) {
		calls = append(calls, "gateway-ack")
		return persistentAckEvidence(now), nil
	}}
	cipher := &persistentCipherStub{open: func(context.Context, CredentialEnvelope, []byte) (string, error) {
		calls = append(calls, "decrypt")
		return "sk-secret", nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), "op-1", "owner-1", "claim-token")
	if err != nil {
		t.Fatalf("AcknowledgeCredential(): %v", err)
	}
	if delivery.Credential != "sk-secret" {
		t.Fatalf("unexpected delivery: %+v", delivery)
	}
	want := []string{"preflight", "lease", "begin-ack", "gateway-ack", "commit-ack", "lease", "load-seat", "decrypt", "claim-cas"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentCredentialClaimRejectsWrongTokenBeforeLease(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	claim := persistentTestClaim(now, CredentialClaimReady)
	claim.TokenHash = hashBytes("claim-token")
	store := &persistentStoreStub{
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return claim, nil },
		acquireClaim: func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
			t.Fatal("unauthorized request acquired a claim lease")
			return nil, nil
		},
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	_, err := coordinator.AcknowledgeCredential(context.Background(), "op-1", "owner-1", "wrong-token")
	if err == nil {
		t.Fatal("wrong token must be rejected")
	}
}

func TestPersistentCredentialClaimExpiresBeforeAckOrKMS(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	claim := persistentTestClaim(now, CredentialClaimReady)
	claim.TokenHash = hashBytes("claim-token")
	claim.Expired = true
	expired := false
	store := &persistentStoreStub{
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return claim, nil },
		acquireClaim: func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
			return &CredentialClaimLease{Claim: claim, FencingToken: 4}, nil
		},
		expireClaim: func(context.Context, ExpireCredentialClaimInput) (*StoredCredentialClaim, error) {
			expired = true
			return claim, nil
		},
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	_, err := coordinator.AcknowledgeCredential(context.Background(), "op-1", "owner-1", "claim-token")
	if !errors.Is(err, ErrCredentialClaimExpired) || !expired {
		t.Fatalf("expired claim must be fenced-expired before side effects: expired=%v err=%v", expired, err)
	}
}

func TestPersistentCredentialClaimExpiresAfterSuccessfulAckBeforeKMS(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	claim := persistentTestClaim(now, CredentialClaimReady)
	claim.TokenHash = hashBytes("claim-token")
	calls := []string{}
	acquireCount := 0
	store := &persistentStoreStub{
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return claim, nil },
		acquireClaim: func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
			acquireCount++
			copy := *claim
			copy.FencingToken = int64(3 + acquireCount)
			if acquireCount == 2 {
				copy.Status = CredentialClaimAckPending
				copy.AckResultSnapshot = []byte(`{"credential_claimed":true}`)
				copy.Expired = true
			}
			calls = append(calls, "lease")
			return &CredentialClaimLease{Claim: &copy, FencingToken: copy.FencingToken}, nil
		},
		beginAck: func(context.Context, BeginCredentialAckInput) (*StoredCredentialClaim, error) {
			calls = append(calls, "begin-ack")
			copy := *claim
			copy.Status = CredentialClaimAckPending
			return &copy, nil
		},
		commitAck: func(context.Context, CommitCredentialAckInput) (*StoredCredentialClaim, error) {
			calls = append(calls, "commit-ack")
			return claim, nil
		},
		expireClaim: func(_ context.Context, input ExpireCredentialClaimInput) (*StoredCredentialClaim, error) {
			calls = append(calls, "expire")
			if input.FencingToken != 5 {
				t.Fatalf("expiry used stale fence: %+v", input)
			}
			return claim, nil
		},
	}
	gateway := &persistentGatewayStub{ack: func(context.Context, ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error) {
		calls = append(calls, "gateway-ack")
		return persistentAckEvidence(now), nil
	}}
	cipher := &persistentCipherStub{open: func(context.Context, CredentialEnvelope, []byte) (string, error) {
		t.Fatal("expired post-ack claim reached KMS Open")
		return "", nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, gateway, cipher, now)
	_, err := coordinator.AcknowledgeCredential(context.Background(), "op-1", "owner-1", "claim-token")
	if !errors.Is(err, ErrCredentialClaimExpired) {
		t.Fatalf("expected expired claim, got %v", err)
	}
	want := []string{"lease", "begin-ack", "gateway-ack", "commit-ack", "lease", "expire"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentReadsPreserveContextAndDatabaseErrors(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("request"), "request-1")
	dbErr := errors.New("database unavailable")
	stored := persistentTestOperation(now, OperationSucceeded)
	store := &persistentStoreStub{
		loadSeat: func(got context.Context, _ string) (*PersistedSeat, error) {
			if got.Value(contextKey("request")) != "request-1" {
				t.Fatal("Seat discarded request context")
			}
			return nil, dbErr
		},
		loadOperation: func(got context.Context, _ OperationKey) (*StoredOperation, error) {
			if got.Value(contextKey("request")) != "request-1" {
				t.Fatal("Operation discarded request context")
			}
			return stored, nil
		},
		loadClaim: func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return nil, dbErr },
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	if _, err := coordinator.Seat(ctx, "seat-1"); !errors.Is(err, dbErr) {
		t.Fatalf("Seat masked database error: %v", err)
	}
	if _, ok, err := coordinator.Operation(ctx, "op-1"); ok || !errors.Is(err, dbErr) {
		t.Fatalf("Operation masked claim database error: ok=%v err=%v", ok, err)
	}
	store.loadClaim = func(context.Context, ClaimKey) (*StoredCredentialClaim, error) { return nil, ErrWorkflowNotFound }
	if _, ok, err := coordinator.Operation(ctx, "op-1"); ok || !errors.Is(err, ErrWorkflowCorruptState) {
		t.Fatalf("succeeded provision without claim was partially returned: ok=%v err=%v", ok, err)
	}
	stored.Status = OperationRunning
	if op, ok, err := coordinator.Operation(ctx, "op-1"); err != nil || !ok || op == nil {
		t.Fatalf("non-terminal claim NotFound should be ignored: op=%+v ok=%v err=%v", op, ok, err)
	}
	store.loadOperation = func(context.Context, OperationKey) (*StoredOperation, error) { return nil, dbErr }
	if _, ok, err := coordinator.Operation(ctx, "op-1"); ok || !errors.Is(err, dbErr) {
		t.Fatalf("Operation masked database error: ok=%v err=%v", ok, err)
	}
}

func TestPersistentSettlementReadBindsUpstreamItemsToLocalSeatEpoch(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	store := &persistentStoreStub{loadSeat: func(context.Context, string) (*PersistedSeat, error) {
		return persistentTestSeat(now), nil
	}}
	read := &settlementReadStub{list: func(context.Context, string, int) ([]PendingSettlement, error) {
		return []PendingSettlement{{SeatID: 7, ExternalSeatID: "seat-1", SettlementID: "settlement-1", RequestID: "request-1", AssignmentEpoch: 1}}, nil
	}}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	coordinator.settlementRead = read
	items, err := coordinator.ListPendingSettlements(context.Background(), "seat-1", 20)
	if err != nil || len(items) != 1 {
		t.Fatalf("ListPendingSettlements() items=%+v err=%v", items, err)
	}
	read.list = func(context.Context, string, int) ([]PendingSettlement, error) {
		return []PendingSettlement{{SeatID: 7, ExternalSeatID: "seat-1", SettlementID: "settlement-1", RequestID: "request-1", AssignmentEpoch: 2}}, nil
	}
	if _, err := coordinator.ListPendingSettlements(context.Background(), "seat-1", 20); !errors.Is(err, ErrWorkflowCorruptState) {
		t.Fatalf("stale epoch accepted: %v", err)
	}
}

func TestPersistentCoordinatorRejectsPartialOrReusedSettlementCapability(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	base := PersistentCoordinatorOptions{
		IntegrationClientID: "client-1", WorkerID: "worker-1", Now: func() time.Time { return now },
		SettlementRead: &settlementReadStub{}, SettlementResolve: &settlementResolveStub{}, SettlementActorID: "client-1",
	}
	if _, err := NewPersistentCoordinator(&persistentStoreStub{}, &persistentGatewayStub{}, &persistentCipherStub{}, base); !errors.Is(err, ErrWorkflowInvalidData) {
		t.Fatalf("control client reused as settlement actor: %v", err)
	}
	base.SettlementActorID = "settlement-resolve"
	base.SettlementRead = nil
	if _, err := NewPersistentCoordinator(&persistentStoreStub{}, &persistentGatewayStub{}, &persistentCipherStub{}, base); !errors.Is(err, ErrWorkflowInvalidData) {
		t.Fatalf("partial settlement capability accepted: %v", err)
	}
}

func TestPersistentSettlementResolvePersistsIntentBeforeNetwork(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	calls := []string{}
	target := persistentSettlementTarget(t, now, OperationRunning)
	store := &persistentStoreStub{
		loadOperation: func(context.Context, OperationKey) (*StoredOperation, error) {
			calls = append(calls, "load-operation")
			return nil, ErrWorkflowNotFound
		},
		loadSeat: func(context.Context, string) (*PersistedSeat, error) {
			calls = append(calls, "load-seat")
			seat := persistentTestSeat(now)
			seat.State = domain.SeatDraining
			return seat, nil
		},
		beginSettlement: func(_ context.Context, input BeginSettlementResolutionInput) (*SettlementResolutionTarget, bool, error) {
			calls = append(calls, "begin")
			if input.ExpectedRequestID != "request-1" || input.ExpectedAssignmentEpoch != 1 ||
				input.ExpectedActorClientID != "settlement-resolve" || len(input.RequestSnapshot) == 0 {
				t.Fatalf("incomplete settlement intent: %+v", input)
			}
			target.Operation.RequestHash, target.Operation.RequestSnapshot = input.RequestHash, input.RequestSnapshot
			return target, true, nil
		},
		commitSettlement: func(_ context.Context, input CommitSettlementResolutionInput) (*StoredOperation, *StoredSettlementResolution, error) {
			calls = append(calls, "commit")
			if input.FencingToken != 31 || input.Result.RequestID != "request-1" || input.Result.AssignmentEpoch != 1 {
				t.Fatalf("unbound settlement commit: %+v", input)
			}
			target.Operation.Status = OperationSucceeded
			return target.Operation, persistentStoredSettlement(now), nil
		},
	}
	resolve := &settlementResolveStub{resolve: func(_ context.Context, seatID, settlementID string, command ResolvePendingSettlementCommand) (*SettlementResolution, error) {
		calls = append(calls, "resolve")
		if seatID != "seat-1" || settlementID != "settlement-1" || command != persistentSettlementCommand() {
			t.Fatalf("wrong durable command: seat=%s settlement=%s command=%+v", seatID, settlementID, command)
		}
		return persistentSettlementResult(now), nil
	}}
	coordinator := newPersistentSettlementTestCoordinator(t, store, resolve, now)
	result, err := coordinator.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", persistentSettlementCommand())
	if err != nil || result == nil || result.ActorClientID != "settlement-resolve" {
		t.Fatalf("ResolvePendingSettlement() result=%+v err=%v", result, err)
	}
	if want := []string{"load-operation", "load-seat", "begin", "resolve", "commit"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestPersistentSettlementRecoveryReplaysStoredIntentAndKeepsUnknownPending(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	target := persistentSettlementTarget(t, now, OperationReconcileRequired)
	acquireCalls, resolveCalls := 0, 0
	store := &persistentStoreStub{
		acquireNextSettlement: func(context.Context, AcquireNextSettlementResolutionInput) (*SettlementResolutionTarget, error) {
			acquireCalls++
			if acquireCalls > 1 {
				return nil, ErrWorkflowNotFound
			}
			return target, nil
		},
		commitSettlementFailure: func(_ context.Context, input CommitSettlementResolutionFailureInput) (*SettlementResolutionTarget, error) {
			if input.NextAttemptAt == nil || input.ErrorCode == "" {
				t.Fatalf("ambiguous resolve was not retained for recovery: %+v", input)
			}
			return target, nil
		},
	}
	resolve := &settlementResolveStub{resolve: func(_ context.Context, _, _ string, command ResolvePendingSettlementCommand) (*SettlementResolution, error) {
		resolveCalls++
		if command != persistentSettlementCommand() {
			t.Fatalf("recovery did not use stored command: %+v", command)
		}
		return nil, &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}
	}}
	coordinator := newPersistentSettlementTestCoordinator(t, store, resolve, now)
	worker, _ := NewPersistentRecoveryWorker(coordinator)
	worked, err := worker.RecoverNextSettlementResolution(context.Background())
	if !worked || err != nil || resolveCalls != 1 {
		t.Fatalf("first recovery worked=%v calls=%d err=%v", worked, resolveCalls, err)
	}
	worked, err = worker.RecoverNextSettlementResolution(context.Background())
	if worked || err != nil || resolveCalls != 1 {
		t.Fatalf("empty recovery churned: worked=%v calls=%d err=%v", worked, resolveCalls, err)
	}
}

func TestPersistentSettlementTerminalReplayIgnoresCurrentSeatAndActorConfig(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	target := persistentSettlementTarget(t, now, OperationSucceeded)
	target.Seat.AssignmentEpoch = 9
	target.Seat.Status = domain.SeatActive
	target.Resolution = persistentStoredSettlement(now)
	store := &persistentStoreStub{
		loadOperation:  func(context.Context, OperationKey) (*StoredOperation, error) { return target.Operation, nil },
		loadSettlement: func(context.Context, OperationKey) (*SettlementResolutionTarget, error) { return target, nil },
		loadSeat: func(context.Context, string) (*PersistedSeat, error) {
			t.Fatal("terminal replay depended on current Seat")
			return nil, nil
		},
	}
	coordinator := newPersistentSettlementTestCoordinator(t, store, &settlementResolveStub{}, now)
	coordinator.settlementActorID = "rotated-resolve-client"
	result, err := coordinator.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", persistentSettlementCommand())
	if err != nil || result == nil || result.AssignmentEpoch != 1 || result.RequestID != "request-1" {
		t.Fatalf("terminal replay result=%+v err=%v", result, err)
	}
}

func TestPersistentSettlementExplicit4xxRemainsPending(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	target := persistentSettlementTarget(t, now, OperationRunning)
	store := &persistentStoreStub{commitSettlementFailure: func(_ context.Context, input CommitSettlementResolutionFailureInput) (*SettlementResolutionTarget, error) {
		if input.ErrorCode != "OPERATOR_REVIEW_REQUIRED" {
			t.Fatalf("POST 4xx incorrectly marked unchanged: %+v", input)
		}
		return target, nil
	}}
	coordinator := newPersistentSettlementTestCoordinator(t, store, &settlementResolveStub{resolve: func(context.Context, string, string, ResolvePendingSettlementCommand) (*SettlementResolution, error) {
		return nil, &GatewayError{Reason: "not found", StatusCode: 404}
	}}, now)
	_, err := coordinator.resolveSettlementTarget(context.Background(), target)
	var typed *PersistentOperationError
	if !errors.As(err, &typed) || typed.Code != "OPERATOR_REVIEW_REQUIRED" {
		t.Fatalf("unexpected explicit error: %v", err)
	}
}

func TestPersistentRecoveryWorkersUseStoreAndUnsupportedMutationsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	store := &persistentStoreStub{}
	op := persistentTestOperation(now, OperationRunning)
	acquireCount := 0
	store.acquireNextOperation = func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error) {
		acquireCount++
		if acquireCount > 1 {
			return nil, ErrWorkflowNotFound
		}
		return &OperationLease{Operation: op, FencingToken: 9}, nil
	}
	store.commitOperation = func(_ context.Context, input CommitOperationInput) (*StoredOperation, error) {
		if input.Status != OperationRetryable || input.ErrorCode != "CALLER_REPLAY_REQUIRED" {
			t.Fatalf("unexpected recovery commit: %+v", input)
		}
		return op, nil
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	worker, _ := NewPersistentRecoveryWorker(coordinator)
	worked, err := worker.RecoverNextOperation(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextOperation() worked=%v err=%v", worked, err)
	}
	worked, err = worker.RecoverNextOperation(context.Background())
	if err != nil || worked {
		t.Fatalf("caller-replay marker must not churn: worked=%v err=%v", worked, err)
	}
	if _, err := coordinator.ReplacePermanently(context.Background(), "op-5", "seat-1", "member-2", "evidence-1"); !errors.Is(err, ErrPersistentWorkflowUnsupported) {
		t.Fatalf("ReplacePermanently must fail closed, got %v", err)
	}
	if _, err := coordinator.ListPendingSettlements(context.Background(), "seat-1", 10); !errors.Is(err, ErrPersistentWorkflowUnsupported) {
		t.Fatalf("settlement read must fail closed without independent client, got %v", err)
	}
	if _, err := coordinator.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", ResolvePendingSettlementCommand{}); !errors.Is(err, ErrPersistentWorkflowUnsupported) {
		t.Fatalf("settlement resolve must fail closed without independent client, got %v", err)
	}
}

func TestGenericRecoveryNeverCommitsSettlementOperation(t *testing.T) {
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	op := persistentTestOperation(now, OperationReconcileRequired)
	op.Kind = OperationResolveSettlement
	store := &persistentStoreStub{
		acquireNextOperation: func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error) {
			return &OperationLease{Operation: op, FencingToken: 44}, nil
		},
		commitOperation: func(context.Context, CommitOperationInput) (*StoredOperation, error) {
			t.Fatal("generic recovery committed a settlement operation")
			return nil, nil
		},
	}
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	worker, _ := NewPersistentRecoveryWorker(coordinator)
	worked, err := worker.RecoverNextOperation(context.Background())
	if !worked || !errors.Is(err, ErrWorkflowInvalidState) {
		t.Fatalf("generic settlement guard worked=%v err=%v", worked, err)
	}
}

func newPersistentTestCoordinator(t *testing.T, store WorkflowStore, gateway PersistentProvisionGateway, cipher CredentialEnvelopeCipher, now time.Time) *PersistentCoordinator {
	t.Helper()
	coordinator, err := NewPersistentCoordinator(store, gateway, cipher, PersistentCoordinatorOptions{
		IntegrationClientID: "client-1", WorkerID: "worker-1", LeaseDuration: time.Minute,
		ClaimTTL: 10 * time.Minute, Now: func() time.Time { return now }, ClaimToken: func() (string, error) { return "claim-token", nil },
	})
	if err != nil {
		t.Fatalf("NewPersistentCoordinator(): %v", err)
	}
	return coordinator
}

func newPersistentSettlementTestCoordinator(t *testing.T, store WorkflowStore, resolve PendingSettlementResolveGateway, now time.Time) *PersistentCoordinator {
	t.Helper()
	coordinator := newPersistentTestCoordinator(t, store, &persistentGatewayStub{}, &persistentCipherStub{}, now)
	coordinator.settlementResolve = resolve
	coordinator.settlementActorID = "settlement-resolve"
	return coordinator
}

func persistentSettlementCommand() ResolvePendingSettlementCommand {
	return ResolvePendingSettlementCommand{
		OperationID: "resolve-1", ExpectedAssignmentEpoch: 1, ExpectedRequestID: "request-1",
		Reason: "usage verified", Evidence: "ticket-123",
	}
}

func persistentSettlementTarget(t *testing.T, now time.Time, status OperationStatus) *SettlementResolutionTarget {
	t.Helper()
	snapshot, hash, err := persistentSettlementIntent("seat-1", "settlement-1", "settlement-resolve", persistentSettlementCommand())
	if err != nil {
		t.Fatal(err)
	}
	op := persistentTestOperation(now, status)
	op.Key.OperationID, op.Kind, op.TargetExternalID = "resolve-1", OperationResolveSettlement, "seat-1"
	op.RequestSnapshot, op.RequestHash, op.FencingToken = snapshot, hash, 31
	leaseUntil := now.Add(time.Minute)
	op.LeaseOwner, op.LeaseExpiresAt = "worker-1", &leaseUntil
	caseStatus := SettlementResolutionPending
	if status == OperationSucceeded {
		caseStatus = SettlementResolutionSucceeded
	}
	return &SettlementResolutionTarget{
		Operation: op,
		Case: &StoredSettlementResolutionCase{
			SettlementID: "settlement-1", ExpectedRequestID: "request-1", ExpectedAssignmentEpoch: 1,
			ExpectedActorClientID: "settlement-resolve", Reason: "usage verified", Evidence: "ticket-123",
			Status: caseStatus, CreatedAt: now, UpdatedAt: now,
		},
		Seat: SettlementResolutionSeat{
			SeatID: "seat-db-id", SeatExternalID: "seat-1", PoolExternalID: "pool-1",
			AssignmentEpoch: 1, Status: domain.SeatDraining,
		},
	}
}

func persistentSettlementResult(now time.Time) *SettlementResolution {
	return &SettlementResolution{
		SeatID: 7, ExternalSeatID: "seat-1", SettlementID: "settlement-1", OperationID: "resolve-1",
		ActorClientID: "settlement-resolve", AssignmentEpoch: 1, RequestID: "request-1",
		Reason: "usage verified", Evidence: "ticket-123", ResolvedAt: now,
	}
}

func persistentStoredSettlement(now time.Time) *StoredSettlementResolution {
	result := persistentSettlementResult(now)
	return &StoredSettlementResolution{
		UpstreamSeatID: result.SeatID, ExternalSeatID: result.ExternalSeatID, SettlementID: result.SettlementID,
		OperationID: result.OperationID, ActorClientID: result.ActorClientID,
		AssignmentEpoch: result.AssignmentEpoch, RequestID: result.RequestID,
		Reason: result.Reason, Evidence: result.Evidence, ResolvedAt: result.ResolvedAt, CreatedAt: now,
	}
}

type settlementResolveStub struct {
	resolve func(context.Context, string, string, ResolvePendingSettlementCommand) (*SettlementResolution, error)
}

type settlementReadStub struct {
	list func(context.Context, string, int) ([]PendingSettlement, error)
	get  func(context.Context, string, string) (*PendingSettlement, error)
}

func (s *settlementReadStub) ListPendingSettlements(ctx context.Context, seatID string, limit int) ([]PendingSettlement, error) {
	return s.list(ctx, seatID, limit)
}

func (s *settlementReadStub) GetPendingSettlement(ctx context.Context, seatID, settlementID string) (*PendingSettlement, error) {
	return s.get(ctx, seatID, settlementID)
}

func (s *settlementResolveStub) ResolvePendingSettlement(ctx context.Context, seatID, settlementID string, command ResolvePendingSettlementCommand) (*SettlementResolution, error) {
	if s.resolve == nil {
		return nil, errors.New("unexpected settlement resolve")
	}
	return s.resolve(ctx, seatID, settlementID, command)
}

func persistentProvisionCommand(now time.Time) ProvisionSeatCommand {
	return ProvisionSeatCommand{
		OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 10, AssignmentEpoch: 1, PrincipalConcurrency: 1,
		SubscriptionExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

func persistentTestOperation(now time.Time, status OperationStatus) *StoredOperation {
	return &StoredOperation{
		AggregateID: "operation-db-id", Key: OperationKey{ClientID: "client-1", OperationID: "op-1"},
		Kind: OperationProvision, TargetType: "SEAT", TargetExternalID: "seat-1", MigrationState: "CURRENT",
		Status: status, CreatedAt: now, UpdatedAt: now,
	}
}

func persistentTestClaim(now time.Time, status CredentialClaimStatus) *StoredCredentialClaim {
	fingerprint := sha256.Sum256([]byte("sk-secret"))
	return &StoredCredentialClaim{
		Key: ClaimKey{ClientID: "client-1", OperationID: "op-1"}, OperationKind: OperationProvision,
		SeatExternalID: "seat-1", TargetMemberExternalID: "owner-1", ClaimOperationID: provisionClaimOperationID("op-1"),
		CredentialFingerprint: fingerprint[:], Status: status, ExpiresAt: now.Add(10 * time.Minute),
		Envelope: CredentialEnvelope{Algorithm: "TEST", KeyRef: "kms/test", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), WrappedDEK: []byte("dek")},
	}
}

func persistentTestSeat(now time.Time) *PersistedSeat {
	return &PersistedSeat{
		SeatID: "seat-db-id", SeatExternalID: "seat-1", PoolExternalID: "pool-1",
		State:           domain.SeatActive,
		OwnerExternalID: "owner-1", CurrentMemberID: "owner-1", AssignmentEpoch: 1,
		MembershipEpoch: 1, PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301,
		ActiveAPIKeyVersion: 1, AssignmentStarted: now, UpdatedAt: now,
	}
}

func TestPersistedSeatDomainPreservesSuspensionState(t *testing.T) {
	record := persistentTestSeat(time.Now().UTC())
	record.State = domain.SeatDraining
	seat := persistedSeatDomain(record)
	if seat == nil || seat.State != domain.SeatDraining {
		t.Fatalf("persisted Seat state was not preserved: %+v", seat)
	}
}

func TestPersistedSeatDomainPreservesTemporaryAssignment(t *testing.T) {
	record := persistentTestSeat(time.Now().UTC())
	record.CurrentMemberID = "temporary-member"
	record.CurrentAssignmentKind = domain.AssignmentTemporary
	seat := persistedSeatDomain(record)
	if seat == nil || seat.Current.UserID != "temporary-member" || seat.Current.Kind != domain.AssignmentTemporary {
		t.Fatalf("persisted temporary Assignment was not preserved: %+v", seat)
	}
}

func persistentSuspendTarget(op *StoredOperation, now time.Time, status SuspendCaseStatus) *SuspendTarget {
	seatStatus := domain.SeatSuspendPending
	if status == SuspendCaseDraining {
		seatStatus = domain.SeatDraining
	} else if status == SuspendCaseFrozen {
		seatStatus = domain.SeatFrozen
	}
	return &SuspendTarget{
		Operation: op,
		Case: &StoredSuspensionCase{
			OperationID: op.Key.OperationID, Status: status, ReasonCode: SuspendReasonManualPolicyBreach,
			ExpectedAssignmentEpoch: 1, CreatedAt: now, UpdatedAt: now,
		},
		Seat: SuspendSeatTarget{
			SeatID: "seat-db-id", SeatExternalID: "seat-1", PoolExternalID: "pool-1",
			OwnerExternalID: "owner-1", CurrentMemberID: "owner-1", Status: seatStatus,
			AssignmentEpoch: 1, MembershipEpoch: 1,
		},
	}
}

func persistentAssignmentTarget(t *testing.T, now time.Time, kind OperationKind, operationID, targetMember string) *AssignmentTarget {
	t.Helper()
	snapshot, hash, err := persistentAssignmentIntent(operationID, "seat-1", targetMember, kind)
	if err != nil {
		t.Fatal(err)
	}
	freeze, err := json.Marshal(persistentValidFreeze("suspend-1", 1, now))
	if err != nil {
		t.Fatal(err)
	}
	op := persistentTestOperation(now, OperationRunning)
	op.Key.OperationID, op.Kind, op.TargetExternalID = operationID, kind, "seat-1"
	op.RequestSnapshot, op.RequestHash, op.FencingToken = snapshot, hash, 21
	leaseUntil := now.Add(time.Minute)
	op.LeaseOwner, op.LeaseExpiresAt = "worker-1", &leaseUntil
	currentMember := "owner-1"
	if kind == OperationRestore {
		currentMember = "member-2"
	}
	return &AssignmentTarget{
		Operation: op,
		Case: &StoredAssignmentCase{
			Kind: kind, Status: AssignmentCasePending, ExpectedAssignmentEpoch: 1, NextAssignmentEpoch: 2,
			MembershipEpoch: 1, PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301,
			ExpectedAPIKeyVersion: 1, NextAPIKeyVersion: 2, FreezeOperationID: "suspend-1",
			FreezeSnapshot: freeze, CreatedAt: now, UpdatedAt: now,
		},
		Seat: AssignmentSeatTarget{
			SeatID: "seat-db-id", SeatExternalID: "seat-1", PoolExternalID: "pool-1",
			OwnerExternalID: "owner-1", CurrentMemberID: currentMember, TargetMemberID: targetMember,
			Status: domain.SeatAssignmentPending, AssignmentEpoch: 1, MembershipEpoch: 1,
			PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301, ActiveAPIKeyVersion: 1,
		},
	}
}

func persistentAssignmentResult(operationID, credential string) AssignmentResult {
	return AssignmentResult{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "ACTIVE", AssignmentEpoch: 2,
		PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301, ActiveAPIKeyVersion: 2,
		LastOperationID:                  operationID,
		AccessCredentialRotationComplete: true, Credential: credential,
	}
}

func persistentValidFreeze(operationID string, epoch uint64, capturedAt time.Time) *domain.FreezeSnapshot {
	return &domain.FreezeSnapshot{
		OperationID: operationID, AssignmentEpoch: epoch, CapturedAt: capturedAt,
		Usage:        map[string]float64{"hourly": 0, "daily": 3.5, "weekly": 3.5, "monthly": 3.5},
		WindowStarts: map[string]*time.Time{"hourly": nil, "daily": nil, "weekly": nil, "monthly": nil},
	}
}

func persistentAckEvidence(now time.Time) ProvisionCredentialAckResult {
	return ProvisionCredentialAckResult{
		ExternalSeatID: "seat-1", ProvisionOperationID: "op-1", ClaimOperationID: provisionClaimOperationID("op-1"),
		ClaimedBy: "owner-1", CredentialFingerprint: credentialFingerprint("sk-secret"), CredentialClaimed: true, ClaimedAt: now,
	}
}

func hashBytes(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

type persistentGatewayStub struct {
	provision           func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error)
	ack                 func(context.Context, ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error)
	suspend             func(context.Context, SuspendCommand) (SuspendResult, error)
	reconcile           func(context.Context, SuspendCommand) (GatewayOperationResult, error)
	assign              func(context.Context, AssignmentCommand) (AssignmentResult, error)
	reconcileAssignment func(context.Context, AssignmentCommand) (AssignmentResult, error)
}

func (g *persistentGatewayStub) ProvisionSeat(ctx context.Context, command ProvisionSeatCommand) (ProvisionGatewayResult, error) {
	if g.provision == nil {
		return ProvisionGatewayResult{}, errors.New("unexpected provision")
	}
	return g.provision(ctx, command)
}

func (g *persistentGatewayStub) AcknowledgeProvisionCredential(ctx context.Context, command ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error) {
	if g.ack == nil {
		return ProvisionCredentialAckResult{}, errors.New("unexpected ack")
	}
	return g.ack(ctx, command)
}

func (g *persistentGatewayStub) Suspend(ctx context.Context, command SuspendCommand) (SuspendResult, error) {
	if g.suspend == nil {
		return SuspendResult{}, errors.New("unexpected suspend")
	}
	return g.suspend(ctx, command)
}

func (g *persistentGatewayStub) ReconcileSuspend(ctx context.Context, command SuspendCommand) (GatewayOperationResult, error) {
	if g.reconcile == nil {
		return GatewayOperationResult{}, errors.New("unexpected suspend reconcile")
	}
	return g.reconcile(ctx, command)
}

func (g *persistentGatewayStub) Assign(ctx context.Context, command AssignmentCommand) (AssignmentResult, error) {
	if g.assign == nil {
		return AssignmentResult{}, errors.New("unexpected assignment")
	}
	return g.assign(ctx, command)
}

func (g *persistentGatewayStub) ReconcileAssignment(ctx context.Context, command AssignmentCommand) (AssignmentResult, error) {
	if g.reconcileAssignment == nil {
		return AssignmentResult{}, errors.New("unexpected assignment reconcile")
	}
	return g.reconcileAssignment(ctx, command)
}

type persistentCipherStub struct {
	seal func(context.Context, string, []byte) (CredentialEnvelope, error)
	open func(context.Context, CredentialEnvelope, []byte) (string, error)
}

func (c *persistentCipherStub) Seal(ctx context.Context, plaintext string, aad []byte) (CredentialEnvelope, error) {
	if c.seal == nil {
		return CredentialEnvelope{}, errors.New("unexpected seal")
	}
	return c.seal(ctx, plaintext, aad)
}

func (c *persistentCipherStub) Open(ctx context.Context, envelope CredentialEnvelope, aad []byte) (string, error) {
	if c.open == nil {
		return "", errors.New("unexpected open")
	}
	return c.open(ctx, envelope, aad)
}

type persistentStoreStub struct {
	beginOperation          func(context.Context, BeginOperationInput) (*StoredOperation, bool, error)
	loadOperation           func(context.Context, OperationKey) (*StoredOperation, error)
	acquireOperation        func(context.Context, AcquireOperationLeaseInput) (*OperationLease, error)
	preflightProvision      func(context.Context, ProvisionPreflightInput) error
	acquireNextOperation    func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error)
	commitOperation         func(context.Context, CommitOperationInput) (*StoredOperation, error)
	commitProvision         func(context.Context, CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error)
	loadSeat                func(context.Context, string) (*PersistedSeat, error)
	beginSuspend            func(context.Context, BeginSuspendInput) (*SuspendTarget, bool, error)
	loadSuspend             func(context.Context, OperationKey) (*SuspendTarget, error)
	commitSuspend           func(context.Context, CommitSuspendProgressInput) (*SuspendTarget, error)
	beginAssignment         func(context.Context, BeginAssignmentInput) (*AssignmentTarget, bool, error)
	loadAssignment          func(context.Context, OperationKey) (*AssignmentTarget, error)
	commitAssignment        func(context.Context, CommitAssignmentWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error)
	commitAssignmentFailure func(context.Context, CommitAssignmentFailureInput) (*AssignmentTarget, error)
	beginSettlement         func(context.Context, BeginSettlementResolutionInput) (*SettlementResolutionTarget, bool, error)
	loadSettlement          func(context.Context, OperationKey) (*SettlementResolutionTarget, error)
	acquireNextSettlement   func(context.Context, AcquireNextSettlementResolutionInput) (*SettlementResolutionTarget, error)
	commitSettlement        func(context.Context, CommitSettlementResolutionInput) (*StoredOperation, *StoredSettlementResolution, error)
	commitSettlementFailure func(context.Context, CommitSettlementResolutionFailureInput) (*SettlementResolutionTarget, error)
	loadClaim               func(context.Context, ClaimKey) (*StoredCredentialClaim, error)
	acquireClaim            func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error)
	beginAck                func(context.Context, BeginCredentialAckInput) (*StoredCredentialClaim, error)
	commitAck               func(context.Context, CommitCredentialAckInput) (*StoredCredentialClaim, error)
	claimCredential         func(context.Context, ClaimCredentialInput) (*StoredCredentialClaim, error)
	expireClaim             func(context.Context, ExpireCredentialClaimInput) (*StoredCredentialClaim, error)
}

func (s *persistentStoreStub) BeginOperation(ctx context.Context, input BeginOperationInput) (*StoredOperation, bool, error) {
	return s.beginOperation(ctx, input)
}
func (s *persistentStoreStub) LoadOperation(ctx context.Context, key OperationKey) (*StoredOperation, error) {
	return s.loadOperation(ctx, key)
}
func (s *persistentStoreStub) AcquireOperationLease(ctx context.Context, input AcquireOperationLeaseInput) (*OperationLease, error) {
	return s.acquireOperation(ctx, input)
}
func (s *persistentStoreStub) ValidateProvisionPreflight(ctx context.Context, input ProvisionPreflightInput) error {
	return s.preflightProvision(ctx, input)
}
func (s *persistentStoreStub) AcquireNextOperationLease(ctx context.Context, input AcquireNextOperationLeaseInput) (*OperationLease, error) {
	return s.acquireNextOperation(ctx, input)
}
func (s *persistentStoreStub) CommitOperation(ctx context.Context, input CommitOperationInput) (*StoredOperation, error) {
	return s.commitOperation(ctx, input)
}
func (*persistentStoreStub) CommitOperationWithCredentialClaim(context.Context, CommitOperationWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, error) {
	panic("unexpected CommitOperationWithCredentialClaim")
}
func (s *persistentStoreStub) CommitProvisionWithCredentialClaim(ctx context.Context, input CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
	return s.commitProvision(ctx, input)
}
func (s *persistentStoreStub) LoadPersistedSeat(ctx context.Context, id string) (*PersistedSeat, error) {
	return s.loadSeat(ctx, id)
}
func (s *persistentStoreStub) BeginSuspend(ctx context.Context, input BeginSuspendInput) (*SuspendTarget, bool, error) {
	return s.beginSuspend(ctx, input)
}
func (s *persistentStoreStub) LoadSuspendTarget(ctx context.Context, key OperationKey) (*SuspendTarget, error) {
	return s.loadSuspend(ctx, key)
}
func (s *persistentStoreStub) CommitSuspendProgress(ctx context.Context, input CommitSuspendProgressInput) (*SuspendTarget, error) {
	return s.commitSuspend(ctx, input)
}
func (s *persistentStoreStub) BeginAssignment(ctx context.Context, input BeginAssignmentInput) (*AssignmentTarget, bool, error) {
	return s.beginAssignment(ctx, input)
}
func (s *persistentStoreStub) LoadAssignmentTarget(ctx context.Context, key OperationKey) (*AssignmentTarget, error) {
	return s.loadAssignment(ctx, key)
}
func (s *persistentStoreStub) CommitAssignmentWithCredentialClaim(ctx context.Context, input CommitAssignmentWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error) {
	return s.commitAssignment(ctx, input)
}
func (s *persistentStoreStub) CommitAssignmentFailure(ctx context.Context, input CommitAssignmentFailureInput) (*AssignmentTarget, error) {
	return s.commitAssignmentFailure(ctx, input)
}
func (s *persistentStoreStub) BeginSettlementResolution(ctx context.Context, input BeginSettlementResolutionInput) (*SettlementResolutionTarget, bool, error) {
	return s.beginSettlement(ctx, input)
}
func (s *persistentStoreStub) LoadSettlementResolutionTarget(ctx context.Context, key OperationKey) (*SettlementResolutionTarget, error) {
	return s.loadSettlement(ctx, key)
}
func (s *persistentStoreStub) AcquireNextSettlementResolution(ctx context.Context, input AcquireNextSettlementResolutionInput) (*SettlementResolutionTarget, error) {
	return s.acquireNextSettlement(ctx, input)
}
func (s *persistentStoreStub) CommitSettlementResolution(ctx context.Context, input CommitSettlementResolutionInput) (*StoredOperation, *StoredSettlementResolution, error) {
	return s.commitSettlement(ctx, input)
}
func (s *persistentStoreStub) CommitSettlementResolutionFailure(ctx context.Context, input CommitSettlementResolutionFailureInput) (*SettlementResolutionTarget, error) {
	return s.commitSettlementFailure(ctx, input)
}
func (*persistentStoreStub) CreateCredentialClaim(context.Context, CreateCredentialClaimInput) (*StoredCredentialClaim, bool, error) {
	panic("unexpected CreateCredentialClaim")
}
func (s *persistentStoreStub) LoadCredentialClaim(ctx context.Context, key ClaimKey) (*StoredCredentialClaim, error) {
	return s.loadClaim(ctx, key)
}
func (s *persistentStoreStub) AcquireCredentialClaimLease(ctx context.Context, input AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
	return s.acquireClaim(ctx, input)
}
func (*persistentStoreStub) AcquireNextCredentialClaimLease(context.Context, AcquireNextCredentialClaimLeaseInput) (*CredentialClaimLease, error) {
	panic("unexpected AcquireNextCredentialClaimLease")
}
func (s *persistentStoreStub) BeginCredentialAck(ctx context.Context, input BeginCredentialAckInput) (*StoredCredentialClaim, error) {
	return s.beginAck(ctx, input)
}
func (s *persistentStoreStub) CommitCredentialAck(ctx context.Context, input CommitCredentialAckInput) (*StoredCredentialClaim, error) {
	return s.commitAck(ctx, input)
}
func (*persistentStoreStub) CommitCredentialAckFailure(context.Context, CommitCredentialAckFailureInput) (*StoredCredentialClaim, error) {
	panic("unexpected CommitCredentialAckFailure")
}
func (s *persistentStoreStub) ClaimCredential(ctx context.Context, input ClaimCredentialInput) (*StoredCredentialClaim, error) {
	return s.claimCredential(ctx, input)
}
func (s *persistentStoreStub) ExpireCredentialClaim(ctx context.Context, input ExpireCredentialClaimInput) (*StoredCredentialClaim, error) {
	return s.expireClaim(ctx, input)
}
