package application

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
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
		if input.ExistingGroupID != 10 || strings.Contains(string(input.Operation.ResultSnapshot), "sk-secret") {
			t.Fatalf("provision snapshot leaked secret or lost Group binding: %s", input.Operation.ResultSnapshot)
		}
		stored.Status = OperationSucceeded
		return stored, claim, seat, nil
	}
	gateway := &persistentGatewayStub{provision: func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error) {
		calls = append(calls, "gateway")
		return ProvisionGatewayResult{ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "ACTIVE", AssignmentEpoch: 1, Credential: "sk-secret"}, nil
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
		return ProvisionGatewayResult{ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "ACTIVE", AssignmentEpoch: 1, Credential: "sk-secret"}, nil
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
	if _, err := coordinator.Suspend(context.Background(), "op-2", "seat-1"); !errors.Is(err, ErrPersistentWorkflowUnsupported) {
		t.Fatalf("Suspend must fail closed, got %v", err)
	}
	if _, err := coordinator.AssignTemporary(context.Background(), "op-3", "seat-1", "member-2"); !errors.Is(err, ErrPersistentWorkflowUnsupported) {
		t.Fatalf("AssignTemporary must fail closed, got %v", err)
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
		OwnerExternalID: "owner-1", CurrentMemberID: "owner-1", AssignmentEpoch: 1,
		MembershipEpoch: 1, AssignmentStarted: now, UpdatedAt: now,
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
	provision func(context.Context, ProvisionSeatCommand) (ProvisionGatewayResult, error)
	ack       func(context.Context, ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error)
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
	beginOperation       func(context.Context, BeginOperationInput) (*StoredOperation, bool, error)
	loadOperation        func(context.Context, OperationKey) (*StoredOperation, error)
	acquireOperation     func(context.Context, AcquireOperationLeaseInput) (*OperationLease, error)
	preflightProvision   func(context.Context, ProvisionPreflightInput) error
	acquireNextOperation func(context.Context, AcquireNextOperationLeaseInput) (*OperationLease, error)
	commitOperation      func(context.Context, CommitOperationInput) (*StoredOperation, error)
	commitProvision      func(context.Context, CommitProvisionWithCredentialClaimInput) (*StoredOperation, *StoredCredentialClaim, *PersistedSeat, error)
	loadSeat             func(context.Context, string) (*PersistedSeat, error)
	loadClaim            func(context.Context, ClaimKey) (*StoredCredentialClaim, error)
	acquireClaim         func(context.Context, AcquireCredentialClaimLeaseInput) (*CredentialClaimLease, error)
	beginAck             func(context.Context, BeginCredentialAckInput) (*StoredCredentialClaim, error)
	commitAck            func(context.Context, CommitCredentialAckInput) (*StoredCredentialClaim, error)
	claimCredential      func(context.Context, ClaimCredentialInput) (*StoredCredentialClaim, error)
	expireClaim          func(context.Context, ExpireCredentialClaimInput) (*StoredCredentialClaim, error)
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
