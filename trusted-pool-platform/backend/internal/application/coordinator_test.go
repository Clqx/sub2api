package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/domain"
)

type fakeGateway struct {
	suspendResult   SuspendResult
	suspendErr      error
	assignResult    AssignmentResult
	assignErr       error
	statusResult    GatewayOperationResult
	statusErr       error
	provisionResult ProvisionGatewayResult
	provisionErr    error
	ackResult       ProvisionCredentialAckResult
	ackErr          error
	suspendCalls    int
	assignCalls     int
	provisionCalls  int
	ackCalls        int
	ackCommands     []ProvisionCredentialAckCommand
	ackEntered      chan struct{}
	ackRelease      chan struct{}
}

type blockingAssignGateway struct {
	*fakeGateway
	entered chan AssignmentCommand
	release chan struct{}
}

func (f *blockingAssignGateway) Assign(ctx context.Context, command AssignmentCommand) (AssignmentResult, error) {
	f.assignCalls++
	f.entered <- command
	select {
	case <-f.release:
		return f.assignResult, f.assignErr
	case <-ctx.Done():
		return AssignmentResult{}, ctx.Err()
	}
}

func (f *fakeGateway) Suspend(_ context.Context, command SuspendCommand) (SuspendResult, error) {
	f.suspendCalls++
	result := f.suspendResult
	if result.Freeze == nil && !result.Draining {
		result.Freeze = &domain.FreezeSnapshot{
			OperationID: command.OperationID, AssignmentEpoch: command.AssignmentEpoch,
			Usage: map[string]float64{"daily": 2.5}, WindowStarts: map[string]*time.Time{"daily": testTime(time.Now().Add(-time.Hour))}, CapturedAt: time.Now(),
		}
	}
	return result, f.suspendErr
}

func (f *fakeGateway) ProvisionSeat(_ context.Context, _ ProvisionSeatCommand) (ProvisionGatewayResult, error) {
	f.provisionCalls++
	return f.provisionResult, f.provisionErr
}

func (f *fakeGateway) AcknowledgeProvisionCredential(_ context.Context, command ProvisionCredentialAckCommand) (ProvisionCredentialAckResult, error) {
	f.ackCalls++
	f.ackCommands = append(f.ackCommands, command)
	if f.ackEntered != nil {
		f.ackEntered <- struct{}{}
		<-f.ackRelease
	}
	if f.ackErr != nil {
		return ProvisionCredentialAckResult{}, f.ackErr
	}
	result := f.ackResult
	if result.ExternalSeatID == "" {
		result = ProvisionCredentialAckResult{
			ExternalSeatID: command.SeatID, ProvisionOperationID: command.ProvisionOperationID,
			ClaimOperationID: command.ClaimOperationID, ClaimedBy: command.ClaimedBy,
			CredentialFingerprint: command.CredentialFingerprint,
			CredentialClaimed:     true, ClaimedAt: time.Now().UTC(),
		}
	}
	return result, nil
}

func TestCoordinatorProvisionSeatIsUpstreamFirstAndIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{provisionResult: ProvisionGatewayResult{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "active", AssignmentEpoch: 1, Credential: "initial-key",
	}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	command := ProvisionSeatCommand{
		OperationID: "provision-1", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, SubscriptionExpiresAt: now.Add(30 * 24 * time.Hour), APIKeyQuota: 100,
	}
	first, err := coordinator.ProvisionSeat(context.Background(), command)
	if err != nil || first.Seat == nil || first.Seat.State != domain.SeatActive || first.Operation.Status != OperationSucceeded {
		t.Fatalf("provision failed: result=%+v err=%v", first, err)
	}
	if first.Operation.CredentialClaimToken == "" || gateway.provisionCalls != 1 {
		t.Fatalf("provision did not issue one claim token: operation=%+v calls=%d", first.Operation, gateway.provisionCalls)
	}
	replayed, err := coordinator.ProvisionSeat(context.Background(), command)
	if err != nil || replayed.Operation.CredentialClaimToken != "" || gateway.provisionCalls != 1 {
		t.Fatalf("successful replay called upstream or returned stored token: result=%+v calls=%d err=%v", replayed, gateway.provisionCalls, err)
	}
	status, _, _ := coordinator.Operation(context.Background(), command.OperationID)
	if status.CredentialClaimToken != "" {
		t.Fatal("operation query exposed provision claim token")
	}
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), command.OperationID, command.OwnerUserID, first.Operation.CredentialClaimToken)
	if err != nil || delivery.Credential != "initial-key" || gateway.ackCalls != 1 {
		t.Fatalf("provision credential claim failed: delivery=%+v err=%v", delivery, err)
	}
	drifted := command
	drifted.ExistingGroupID = 8
	if _, err := coordinator.ProvisionSeat(context.Background(), drifted); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation content drift was accepted: %v", err)
	}
	drifted = command
	drifted.OwnerUserID = "owner-2"
	if _, err := coordinator.ProvisionSeat(context.Background(), drifted); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("owner drift was accepted: %v", err)
	}
}

func TestCoordinatorProvisionRetryableFailureDoesNotCreateLocalSeat(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{provisionErr: &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	command := ProvisionSeatCommand{
		OperationID: "provision-unknown", SeatID: "seat-unknown", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, SubscriptionExpiresAt: now.Add(30 * 24 * time.Hour),
	}
	failed, err := coordinator.ProvisionSeat(context.Background(), command)
	if err == nil || failed.Operation.Status != OperationRetryable {
		t.Fatalf("ambiguous provision was not retryable: result=%+v err=%v", failed, err)
	}
	if _, err := coordinator.Seat(context.Background(), command.SeatID); !errors.Is(err, ErrSeatNotFound) {
		t.Fatalf("local seat was created before explicit upstream success: %v", err)
	}
	gateway.provisionErr = nil
	gateway.provisionResult = ProvisionGatewayResult{
		ExternalPoolID: command.PoolID, ExternalSeatID: command.SeatID, State: "active", AssignmentEpoch: 1, Credential: "recovered-key",
	}
	recovered, err := coordinator.ProvisionSeat(context.Background(), command)
	if err != nil || recovered.Seat == nil || recovered.Operation.Status != OperationSucceeded || gateway.provisionCalls != 2 {
		t.Fatalf("same-operation replay did not recover: result=%+v calls=%d err=%v", recovered, gateway.provisionCalls, err)
	}
}

func TestCoordinatorProvisionClaimFailsClosedAndReplaysUpstreamAck(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{
		provisionResult: ProvisionGatewayResult{
			ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "active", AssignmentEpoch: 1, Credential: "initial-key",
		},
		ackErr: &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true},
	}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	result, err := coordinator.ProvisionSeat(context.Background(), ProvisionSeatCommand{
		OperationID: "provision-1", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, SubscriptionExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	token := result.Operation.CredentialClaimToken
	if token == "" {
		t.Fatal("initial provision response omitted claim token")
	}
	stored := coordinator.operations["provision-1"]
	if stored.CredentialClaimToken != "" || stored.credentialClaimTokenHash == ([32]byte{}) {
		t.Fatal("coordinator retained raw claim token or omitted its hash")
	}
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), "provision-1", "owner-1", token)
	if err == nil || delivery != nil || stored.CredentialClaimStatus != credentialClaimReconcileRequired || stored.credential == "" {
		t.Fatalf("ambiguous ack disclosed or discarded credential: delivery=%+v operation=%+v err=%v", delivery, stored, err)
	}
	gateway.ackErr = nil
	delivery, err = coordinator.AcknowledgeCredential(context.Background(), "provision-1", "owner-1", token)
	if err != nil || delivery == nil || delivery.Credential != "initial-key" || gateway.ackCalls != 2 {
		t.Fatalf("ack replay did not deliver exactly once: delivery=%+v calls=%d err=%v", delivery, gateway.ackCalls, err)
	}
	if len(gateway.ackCommands) != 2 || gateway.ackCommands[0].ClaimOperationID != gateway.ackCommands[1].ClaimOperationID ||
		gateway.ackCommands[0].CredentialFingerprint != credentialFingerprint("initial-key") {
		t.Fatalf("ack idempotency or credential binding drifted: %+v", gateway.ackCommands)
	}
}

func TestCoordinatorCredentialClaimTTLActivelyClearsSecret(t *testing.T) {
	gateway := &fakeGateway{provisionResult: ProvisionGatewayResult{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "active", AssignmentEpoch: 1, Credential: "expiring-key",
	}}
	coordinator := NewCoordinator(gateway, time.Now)
	if err := coordinator.ConfigureCredentialClaimTTL(20 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ProvisionSeat(context.Background(), ProvisionSeatCommand{
		OperationID: "provision-expiring", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, SubscriptionExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		coordinator.mu.Lock()
		stored := coordinator.operations["provision-expiring"]
		expired := stored.CredentialClaimStatus == credentialClaimExpired && stored.credential == "" && stored.credentialClaimTokenHash == ([32]byte{})
		coordinator.mu.Unlock()
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claim expiry timer did not clear credential")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := coordinator.AcknowledgeCredential(context.Background(), "provision-expiring", "owner-1", result.Operation.CredentialClaimToken); !errors.Is(err, ErrCredentialClaimExpired) {
		t.Fatalf("expired token was not rejected: %v", err)
	}
}

func TestCoordinatorProvisionAckCrossingTTLDoesNotDiscloseCredential(t *testing.T) {
	gateway := &fakeGateway{
		provisionResult: ProvisionGatewayResult{
			ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: "active", AssignmentEpoch: 1, Credential: "must-expire",
		},
		ackEntered: make(chan struct{}, 1), ackRelease: make(chan struct{}),
	}
	coordinator := NewCoordinator(gateway, time.Now)
	if err := coordinator.ConfigureCredentialClaimTTL(20 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ProvisionSeat(context.Background(), ProvisionSeatCommand{
		OperationID: "provision-slow-ack", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, SubscriptionExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		delivery *CredentialDelivery
		err      error
	}
	done := make(chan claimResult, 1)
	go func() {
		delivery, claimErr := coordinator.AcknowledgeCredential(
			context.Background(), "provision-slow-ack", "owner-1", result.Operation.CredentialClaimToken,
		)
		done <- claimResult{delivery: delivery, err: claimErr}
	}()
	<-gateway.ackEntered
	time.Sleep(30 * time.Millisecond)
	close(gateway.ackRelease)
	claimed := <-done
	if claimed.delivery != nil || !errors.Is(claimed.err, ErrCredentialClaimExpired) {
		t.Fatalf("ack crossing TTL disclosed credential: delivery=%+v err=%v", claimed.delivery, claimed.err)
	}
	coordinator.mu.Lock()
	stored := coordinator.operations["provision-slow-ack"]
	cleared := stored.credential == "" && stored.credentialClaimTokenHash == ([32]byte{}) && stored.CredentialClaimStatus == credentialClaimExpired
	coordinator.mu.Unlock()
	if !cleared {
		t.Fatal("ack crossing TTL retained credential material")
	}
}

func TestCoordinatorSupportsDrainingBeforeFrozen(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{suspendResult: SuspendResult{Draining: true}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	op, err := coordinator.Suspend(context.Background(), "op-freeze", "seat-1")
	if err != nil || op.Status != OperationReconcileRequired {
		t.Fatalf("expected draining reconciliation: operation=%+v err=%v", op, err)
	}
	seat, _ := coordinator.Seat(context.Background(), "seat-1")
	if seat.State != domain.SeatDraining {
		t.Fatalf("expected DRAINING, got %s", seat.State)
	}
	gateway.statusResult = GatewayOperationResult{
		Applied: true,
		Freeze: &domain.FreezeSnapshot{OperationID: "op-freeze", AssignmentEpoch: 1,
			Usage: map[string]float64{"daily": 2.5}, WindowStarts: map[string]*time.Time{"daily": testTime(now.Add(-time.Hour))}, CapturedAt: now},
	}
	op, err = coordinator.Reconcile(context.Background(), "op-freeze")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("freeze reconciliation failed: operation=%+v err=%v", op, err)
	}
	seat, _ = coordinator.Seat(context.Background(), "seat-1")
	if seat.State != domain.SeatFrozen {
		t.Fatalf("expected FROZEN, got %s", seat.State)
	}
}

func (f *fakeGateway) Assign(_ context.Context, _ AssignmentCommand) (AssignmentResult, error) {
	f.assignCalls++
	return f.assignResult, f.assignErr
}

func (f *fakeGateway) OperationStatus(_ context.Context, _ string) (GatewayOperationResult, error) {
	return f.statusResult, f.statusErr
}

func TestCoordinatorIdempotentSuspendAndTemporaryAssignment(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	if _, err := coordinator.CreateSeat("seat-1", "pool-1", "owner-1"); err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Suspend(context.Background(), "op-freeze", "seat-1")
	if err != nil || first.Status != OperationSucceeded {
		t.Fatalf("freeze failed: operation=%+v err=%v", first, err)
	}
	second, err := coordinator.Suspend(context.Background(), "op-freeze", "seat-1")
	if err != nil || second.Status != OperationSucceeded || gateway.suspendCalls != 1 {
		t.Fatalf("idempotent replay called gateway again: operation=%+v calls=%d err=%v", second, gateway.suspendCalls, err)
	}

	assigned, err := coordinator.AssignTemporary(context.Background(), "op-temp", "seat-1", "temp-1")
	if err != nil || assigned.Status != OperationSucceeded {
		t.Fatalf("temporary assignment failed: operation=%+v err=%v", assigned, err)
	}
	if assigned.CredentialClaimToken == "" {
		t.Fatalf("credential claim token was not issued: %+v", assigned)
	}
	replayed, err := coordinator.AssignTemporary(context.Background(), "op-temp", "seat-1", "temp-1")
	if err != nil || replayed.CredentialClaimToken != "" || gateway.assignCalls != 1 {
		t.Fatalf("idempotent replay returned a stored claim token: operation=%+v calls=%d err=%v", replayed, gateway.assignCalls, err)
	}
	status, _, _ := coordinator.Operation(context.Background(), "op-temp")
	if status.CredentialClaimToken != "" {
		t.Fatal("operation status exposed credential claim token")
	}
	if _, err := coordinator.AcknowledgeCredential(context.Background(), "op-temp", "other-user", assigned.CredentialClaimToken); err == nil {
		t.Fatal("credential was delivered to a different target member")
	}
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), "op-temp", "temp-1", assigned.CredentialClaimToken)
	if err != nil || delivery.Credential != "rotated-key" {
		t.Fatalf("credential claim failed: delivery=%+v err=%v", delivery, err)
	}
	if _, err := coordinator.AcknowledgeCredential(context.Background(), "op-temp", "temp-1", assigned.CredentialClaimToken); err == nil {
		t.Fatal("credential was delivered more than once")
	}
	seat, _ := coordinator.Seat(context.Background(), "seat-1")
	if seat.Current.UserID != "temp-1" || seat.State != domain.SeatActive {
		t.Fatalf("unexpected seat: %+v", seat)
	}
	if _, err := coordinator.Restore(context.Background(), "op-restore", "seat-1"); !errors.Is(err, domain.ErrFreezeRequired) {
		t.Fatalf("restore bypassed freeze: %v", err)
	}
}

func TestCoordinatorAllAssignmentClaimsUseHashTTLAndOneTimeDelivery(t *testing.T) {
	tests := []struct {
		name       string
		targetUser string
		run        func(*Coordinator) (*Operation, error)
	}{
		{name: "temporary", targetUser: "temp-1", run: func(c *Coordinator) (*Operation, error) {
			return c.AssignTemporary(context.Background(), "assign-1", "seat-1", "temp-1")
		}},
		{name: "restore", targetUser: "owner-1", run: func(c *Coordinator) (*Operation, error) {
			return c.Restore(context.Background(), "restore-1", "seat-1")
		}},
		{name: "replace", targetUser: "owner-2", run: func(c *Coordinator) (*Operation, error) {
			return c.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-2", "evidence-1")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gateway := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
			coordinator := NewCoordinator(gateway, time.Now, controlEvidenceVerifierStub{validReference: "evidence-1"})
			_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
			_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
			if test.name == "restore" {
				if _, err := coordinator.AssignTemporary(context.Background(), "setup-temp", "seat-1", "temp-1"); err != nil {
					t.Fatal(err)
				}
				if _, err := coordinator.Suspend(context.Background(), "freeze-restore", "seat-1"); err != nil {
					t.Fatal(err)
				}
			}
			op, err := test.run(coordinator)
			if err != nil || op.CredentialClaimToken == "" || op.CredentialClaimExpiresAt == nil {
				t.Fatalf("assignment claim was not issued: operation=%+v err=%v", op, err)
			}
			stored := coordinator.operations[op.ID]
			if stored.CredentialClaimToken != "" || stored.credentialClaimTokenHash == ([32]byte{}) || stored.CredentialClaimStatus != credentialClaimReady {
				t.Fatalf("assignment retained raw token or omitted hash/TTL: %+v", stored)
			}
			delivery, err := coordinator.AcknowledgeCredential(context.Background(), op.ID, test.targetUser, op.CredentialClaimToken)
			if err != nil || delivery.Credential != "rotated-key" || gateway.ackCalls != 0 {
				t.Fatalf("assignment credential delivery failed: delivery=%+v err=%v", delivery, err)
			}
			if _, err := coordinator.AcknowledgeCredential(context.Background(), op.ID, test.targetUser, op.CredentialClaimToken); err == nil {
				t.Fatal("assignment credential was delivered twice")
			}
		})
	}
}

func TestCoordinatorKeepsAmbiguousSuspendPendingUntilReconciled(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{
		suspendErr: &GatewayError{Reason: "timeout after sending request", Retryable: true, Ambiguous: true},
	}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	op, err := coordinator.Suspend(context.Background(), "op-freeze", "seat-1")
	if err == nil || op.Status != OperationReconcileRequired {
		t.Fatalf("expected reconciliation, operation=%+v err=%v", op, err)
	}
	seat, _ := coordinator.Seat(context.Background(), "seat-1")
	if seat.State != domain.SeatSuspendPending {
		t.Fatalf("ambiguous call reactivated seat: %s", seat.State)
	}

	gateway.suspendErr = nil
	gateway.statusResult = GatewayOperationResult{
		Applied: true,
		Freeze: &domain.FreezeSnapshot{
			OperationID:     "op-freeze",
			AssignmentEpoch: 1,
			Usage:           map[string]float64{"daily": 2.5},
			WindowStarts:    map[string]*time.Time{"daily": testTime(now.Add(-time.Hour))},
			CapturedAt:      now,
		},
	}
	op, err = coordinator.Reconcile(context.Background(), "op-freeze")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("reconciliation failed: operation=%+v err=%v", op, err)
	}
	seat, _ = coordinator.Seat(context.Background(), "seat-1")
	if seat.State != domain.SeatFrozen {
		t.Fatalf("reconciliation did not freeze seat: %s", seat.State)
	}
}

func TestCoordinatorExplicitRejectionReturnsSeatToSafePriorState(t *testing.T) {
	now := time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC)
	gateway := &fakeGateway{
		suspendErr: &GatewayError{Reason: "request validation failed"},
	}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	op, err := coordinator.Suspend(context.Background(), "op-freeze", "seat-1")
	if err == nil || op.Status != OperationFailed {
		t.Fatalf("expected explicit failure: operation=%+v err=%v", op, err)
	}
	seat, _ := coordinator.Seat(context.Background(), "seat-1")
	if seat.State != domain.SeatActive {
		t.Fatalf("explicit non-applied rejection should restore ACTIVE, got %s", seat.State)
	}
}

func TestCoordinatorAmbiguousAssignmentIssuesClaimTokenOnlyAfterReconcile(t *testing.T) {
	now := time.Now().UTC()
	gateway := &fakeGateway{assignErr: &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now })
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	op, err := coordinator.AssignTemporary(context.Background(), "assign-1", "seat-1", "temp-1")
	if err == nil || op.Status != OperationReconcileRequired || op.CredentialClaimToken != "" {
		t.Fatalf("ambiguous assignment exposed a premature claim token: operation=%+v err=%v", op, err)
	}
	gateway.statusResult = GatewayOperationResult{
		Applied: true, AccessCredentialRotationComplete: true, Credential: "reconciled-key",
	}
	op, err = coordinator.Reconcile(context.Background(), "assign-1")
	if err != nil || op.Status != OperationSucceeded || op.CredentialClaimToken == "" {
		t.Fatalf("reconciled assignment omitted claim token: operation=%+v err=%v", op, err)
	}
	claimToken := op.CredentialClaimToken
	delivery, err := coordinator.AcknowledgeCredential(context.Background(), "assign-1", "temp-1", claimToken)
	if err != nil || delivery.Credential != "reconciled-key" {
		t.Fatalf("reconciled credential was not deliverable: delivery=%+v err=%v", delivery, err)
	}
}

func TestCoordinatorRetriesExplicitlyRetryableAssignmentWithSameOperationID(t *testing.T) {
	gateway := &fakeGateway{assignErr: &GatewayError{Reason: "busy", Retryable: true}}
	coordinator := NewCoordinator(gateway, time.Now)
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	op, err := coordinator.AssignTemporary(context.Background(), "assign-1", "seat-1", "temp-1")
	if err == nil || op.Status != OperationRetryable {
		t.Fatalf("expected retryable assignment: operation=%+v err=%v", op, err)
	}
	gateway.assignErr = nil
	gateway.assignResult = AssignmentResult{AccessCredentialRotationComplete: true, Credential: "retried-key"}
	op, err = coordinator.AssignTemporary(context.Background(), "assign-1", "seat-1", "temp-1")
	if err != nil || op.Status != OperationSucceeded || gateway.assignCalls != 2 {
		t.Fatalf("retry did not execute safely: operation=%+v calls=%d err=%v", op, gateway.assignCalls, err)
	}
}

func TestCoordinatorRejectsOperationIDReuseWithDifferentCommand(t *testing.T) {
	gateway := &fakeGateway{}
	coordinator := NewCoordinator(gateway, time.Now)
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.Suspend(context.Background(), "same-id", "seat-1")
	if _, err := coordinator.AssignTemporary(context.Background(), "same-id", "seat-1", "temp-1"); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestCoordinatorRequiresProviderControlRotationEvidenceBeforePermanentRotate(t *testing.T) {
	now := time.Now().UTC()
	gateway := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
	coordinator := NewCoordinator(gateway, func() time.Time { return now }, controlEvidenceVerifierStub{validReference: "provider-attestation-1"})
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.CreateSeat("seat-2", "pool-1", "owner-3")
	if _, err := coordinator.Suspend(context.Background(), "freeze-1", "seat-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-2", ""); err == nil {
		t.Fatal("permanent replacement accepted without provider control rotation evidence")
	}
	if gateway.assignCalls != 0 {
		t.Fatal("gateway rotate was called before provider control rotation evidence was supplied")
	}
	operation, err := coordinator.ReplacePermanently(context.Background(), "replace-2", "seat-1", "owner-2", "provider-attestation-1")
	if err != nil || operation.Status != OperationSucceeded || gateway.assignCalls != 1 {
		t.Fatalf("permanent replacement failed: operation=%+v calls=%d err=%v", operation, gateway.assignCalls, err)
	}
	otherSeat, err := coordinator.Seat(context.Background(), "seat-2")
	if err != nil || otherSeat.MembershipEpoch != 2 {
		t.Fatalf("pool membership epoch did not advance atomically across seats: seat=%+v err=%v", otherSeat, err)
	}
}

func TestCoordinatorReconcilesPermanentReplacementAtPoolEpoch(t *testing.T) {
	gateway := &fakeGateway{assignErr: &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}}
	coordinator := NewCoordinator(gateway, time.Now, controlEvidenceVerifierStub{validReference: "evidence-1"})
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.CreateSeat("seat-2", "pool-1", "owner-2")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-2", "seat-2")
	op, err := coordinator.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-3", "evidence-1")
	if err == nil || op.Status != OperationReconcileRequired {
		t.Fatalf("expected ambiguous replacement: operation=%+v err=%v", op, err)
	}
	if _, err := coordinator.AssignTemporary(context.Background(), "temp-2", "seat-2", "temp-user"); err == nil {
		t.Fatal("sibling seat changed members while the pool epoch transition was pending")
	}
	gateway.statusResult = GatewayOperationResult{Applied: true, AccessCredentialRotationComplete: true, Credential: "reconciled-key"}
	op, err = coordinator.Reconcile(context.Background(), "replace-1")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("permanent reconciliation failed: operation=%+v err=%v", op, err)
	}
	otherSeat, _ := coordinator.Seat(context.Background(), "seat-2")
	if otherSeat.MembershipEpoch != 2 || coordinator.poolPending["pool-1"] != "" {
		t.Fatalf("permanent reconciliation did not finalize pool epoch: seat=%+v pending=%q", otherSeat, coordinator.poolPending["pool-1"])
	}
}

func TestCoordinatorTemporaryAssignmentBlocksPermanentReplacementUntilFinished(t *testing.T) {
	base := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
	gateway := &blockingAssignGateway{
		fakeGateway: base,
		entered:     make(chan AssignmentCommand, 2),
		release:     make(chan struct{}),
	}
	defer func() {
		select {
		case <-gateway.release:
		default:
			close(gateway.release)
		}
	}()
	coordinator := NewCoordinator(gateway, time.Now, controlEvidenceVerifierStub{validReference: "evidence-1"})
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.CreateSeat("seat-2", "pool-1", "owner-2")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-2", "seat-2")

	type assignmentOutcome struct {
		op  *Operation
		err error
	}
	done := make(chan assignmentOutcome, 1)
	go func() {
		op, err := coordinator.AssignTemporary(context.Background(), "temp-2", "seat-2", "temp-user")
		done <- assignmentOutcome{op: op, err: err}
	}()
	select {
	case <-gateway.entered:
	case <-time.After(time.Second):
		t.Fatal("temporary assignment did not reach gateway")
	}
	if _, err := coordinator.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-3", "evidence-1"); err == nil {
		t.Fatal("permanent replacement entered while a sibling temporary assignment was in flight")
	}
	close(gateway.release)
	outcome := <-done
	if outcome.err != nil || outcome.op.Status != OperationSucceeded {
		t.Fatalf("temporary assignment failed: operation=%+v err=%v", outcome.op, outcome.err)
	}
	// 临时分配明确完成并释放共享登记后，永久换员才能进入同一个 Pool。
	op, err := coordinator.ReplacePermanently(context.Background(), "replace-2", "seat-1", "owner-3", "evidence-1")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("permanent replacement remained blocked after temporary assignment: operation=%+v err=%v", op, err)
	}
}

func TestCoordinatorRestoreReconciliationBlocksPermanentReplacementUntilFinished(t *testing.T) {
	gateway := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
	coordinator := NewCoordinator(gateway, time.Now, controlEvidenceVerifierStub{validReference: "evidence-1"})
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.CreateSeat("seat-2", "pool-1", "owner-2")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-2", "seat-2")
	if _, err := coordinator.AssignTemporary(context.Background(), "temp-2", "seat-2", "temp-user"); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Suspend(context.Background(), "freeze-3", "seat-2"); err != nil {
		t.Fatal(err)
	}

	gateway.assignErr = &GatewayError{Reason: "timeout", Retryable: true, Ambiguous: true}
	op, err := coordinator.Restore(context.Background(), "restore-2", "seat-2")
	if err == nil || op.Status != OperationReconcileRequired {
		t.Fatalf("expected ambiguous restore: operation=%+v err=%v", op, err)
	}
	if _, err := coordinator.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-3", "evidence-1"); err == nil {
		t.Fatal("permanent replacement entered while a sibling restore awaited reconciliation")
	}

	gateway.statusResult = GatewayOperationResult{Applied: true, AccessCredentialRotationComplete: true, Credential: "restored-key"}
	op, err = coordinator.Reconcile(context.Background(), "restore-2")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("restore reconciliation failed: operation=%+v err=%v", op, err)
	}
	gateway.assignErr = nil
	op, err = coordinator.ReplacePermanently(context.Background(), "replace-2", "seat-1", "owner-3", "evidence-1")
	if err != nil || op.Status != OperationSucceeded {
		t.Fatalf("permanent replacement remained blocked after restore reconciliation: operation=%+v err=%v", op, err)
	}
}

func TestCoordinatorClaimTokenFailureKeepsReplacementInReconcile(t *testing.T) {
	gateway := &fakeGateway{assignResult: AssignmentResult{AccessCredentialRotationComplete: true, Credential: "rotated-key"}}
	coordinator := NewCoordinator(gateway, time.Now, controlEvidenceVerifierStub{validReference: "evidence-1"})
	_, _ = coordinator.CreateSeat("seat-1", "pool-1", "owner-1")
	_, _ = coordinator.Suspend(context.Background(), "freeze-1", "seat-1")
	coordinator.claimToken = func() (string, error) { return "", errors.New("rng failed") }
	if _, err := coordinator.ReplacePermanently(context.Background(), "replace-1", "seat-1", "owner-2", "evidence-1"); err == nil {
		t.Fatal("expected claim token generation failure")
	}
	if coordinator.poolPending["pool-1"] == "" {
		t.Fatal("claim token failure released a replacement whose upstream result requires reconciliation")
	}
}

type controlEvidenceVerifierStub struct {
	validReference string
}

func (s controlEvidenceVerifierStub) ValidateControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error {
	if reference != s.validReference || poolID != "pool-1" || fromEpoch != 1 || toEpoch != 2 {
		return errors.New("invalid control rotation evidence")
	}
	return nil
}

func (s controlEvidenceVerifierStub) CommitControlRotationEvidence(reference, poolID string, fromEpoch, toEpoch uint64) error {
	return s.ValidateControlRotationEvidence(reference, poolID, fromEpoch, toEpoch)
}

func testTime(value time.Time) *time.Time { return &value }
