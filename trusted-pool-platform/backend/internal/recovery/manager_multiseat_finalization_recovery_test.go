package recovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type exactReplayPrepareProvider struct {
	delegate          *finalizationRotationProvider
	calls             int
	durableExecutions int
	request           *PermanentPoolRotationPrepareRequest
	result            PermanentPoolRotationPrepareResult
}

func (p *exactReplayPrepareProvider) Ready(ctx context.Context) error {
	return p.delegate.Ready(ctx)
}

func (p *exactReplayPrepareProvider) PreparePoolRotation(ctx context.Context,
	request PermanentPoolRotationPrepareRequest) (PermanentPoolRotationPrepareResult, error) {
	p.calls++
	if p.request == nil {
		result, err := p.delegate.PreparePoolRotation(ctx, request)
		if err != nil {
			return PermanentPoolRotationPrepareResult{}, err
		}
		storedRequest := request
		storedRequest.Seats = append([]PermanentSeatRotationPrepareRequest(nil), request.Seats...)
		p.request = &storedRequest
		p.result = clonePoolPrepareResult(result)
		p.durableExecutions++
		return clonePoolPrepareResult(p.result), nil
	}
	if !reflect.DeepEqual(*p.request, request) {
		return PermanentPoolRotationPrepareResult{}, ErrBindingMismatch
	}
	return clonePoolPrepareResult(p.result), nil
}

func (p *exactReplayPrepareProvider) ActivatePreparedPoolRotation(ctx context.Context,
	request PermanentPoolRotationActivateRequest) (PermanentPoolRotationActivateResult, error) {
	result, err := p.delegate.ActivatePreparedPoolRotation(ctx, request)
	result.AuthCacheMinimumEvents = 2 * len(request.Seats)
	return result, err
}

func (p *exactReplayPrepareProvider) CommitActivatedPoolRotation(ctx context.Context,
	request PermanentPoolRotationCommitRequest) (PermanentPoolRotationCommitResult, error) {
	result, err := p.delegate.CommitActivatedPoolRotation(ctx, request)
	result.AuthCacheMinimumEvents = len(request.Seats)
	return result, err
}

func clonePoolPrepareResult(result PermanentPoolRotationPrepareResult) PermanentPoolRotationPrepareResult {
	clone := result
	clone.Seats = append([]PermanentSeatRotationPrepareResult(nil), result.Seats...)
	for index := range clone.Seats {
		clone.Seats[index].Credential = append([]byte(nil), result.Seats[index].Credential...)
	}
	return clone
}

type multiSeatPartialPrepareStore struct {
	*finalizationResponseLossStore
	parentBegun           bool
	prepareLossEnabled    bool
	prepareLost           bool
	activationLossEnabled bool
	activationLost        bool

	parentTakeovers          int
	seatTakeovers            map[string]int
	poolPreparationTakeovers int
	seatBeginCalls           map[string]int
	seatCommitCalls          map[string]int
	activationCommitCalls    int
	lastActivationInput      CommitPoolActivationInput
}

func newMultiSeatPartialPrepareStore(now time.Time) *multiSeatPartialPrepareStore {
	base := newFinalizationStoreStub(now)
	base.target.Operation.LeaseOwner = "worker-partial-a"
	base.target.Plan.ExpectedMemberCount = 2
	base.target.SeatTargets[0].Progress.TargetMemberExternalID = "member-new-1"
	base.target.SeatTargets = append(base.target.SeatTargets, SeatRotationTarget{
		Progress: &StoredSeatRotationProgress{PlanExternalID: "plan-1", PoolExternalID: "pool-1",
			FromEpoch: 7, ToEpoch: 8, SeatExternalID: "seat-2", TargetMemberExternalID: "member-new-2",
			ExpectedAssignmentEpoch: 5, ExpectedPrincipalUserID: 111, ExpectedSubscriptionID: 212,
			ExpectedAPIKeyID: 313, ExpectedAPIKeyVersion: 5},
	})
	return &multiSeatPartialPrepareStore{
		finalizationResponseLossStore: &finalizationResponseLossStore{finalizationStoreStub: base},
		prepareLossEnabled:            true,
		seatTakeovers:                 make(map[string]int),
		seatBeginCalls:                make(map[string]int),
		seatCommitCalls:               make(map[string]int),
	}
}

func newMultiSeatActivationResponseLossStore(now time.Time) *multiSeatPartialPrepareStore {
	store := newMultiSeatPartialPrepareStore(now)
	store.prepareLossEnabled = false
	store.activationLossEnabled = true
	return store
}

func (s *multiSeatPartialPrepareStore) parentMatches(owner string, fence int64) bool {
	operation := s.target.Operation
	return operation != nil && operation.Status == "RUNNING" && operation.LeaseOwner == owner &&
		operation.FencingToken == fence && s.parentFence == fence && operation.LeaseExpiresAt != nil &&
		s.now.Before(*operation.LeaseExpiresAt)
}

func (s *multiSeatPartialPrepareStore) AcquireNextPermanentReplacementLease(_ context.Context,
	input AcquireNextPermanentReplacementLeaseInput) (*PermanentReplacementTarget, error) {
	operation := s.target.Operation
	if s.workerLeased || operation == nil || operation.Status != "RUNNING" ||
		operation.LeaseExpiresAt == nil || s.now.Before(*operation.LeaseExpiresAt) {
		return nil, ErrNotFound
	}
	operation.FencingToken++
	operation.LeaseOwner = input.LeaseOwner
	expires := s.now.Add(input.LeaseDuration)
	operation.LeaseExpiresAt = &expires
	s.parentFence = operation.FencingToken
	s.parentTakeovers++
	s.workerLeased = true
	return s.target, nil
}

func (s *multiSeatPartialPrepareStore) BeginPermanentReplacement(_ context.Context,
	input BeginPermanentReplacementInput) (*PermanentReplacementTarget, bool, error) {
	if input.Key != s.target.Operation.Key || input.PlanExternalID != s.target.Plan.ExternalID ||
		len(input.Seats) != len(s.target.SeatTargets) {
		return nil, false, ErrBindingMismatch
	}
	for index := range input.Seats {
		progress := s.target.SeatTargets[index].Progress
		if input.Seats[index].SeatExternalID != progress.SeatExternalID ||
			input.Seats[index].TargetMemberExternalID != progress.TargetMemberExternalID {
			return nil, false, ErrBindingMismatch
		}
	}
	operation := s.target.Operation
	if !s.parentBegun {
		if input.ExpectedFencingToken != 0 {
			return nil, false, ErrStaleFence
		}
		s.parentBegun = true
		operation.RequestHash = input.RequestHash
		operation.LeaseOwner = input.LeaseOwner
		expires := s.now.Add(input.LeaseDuration)
		operation.LeaseExpiresAt = &expires
		return s.target, true, nil
	}
	if operation.RequestHash != input.RequestHash {
		return nil, false, ErrHashDrift
	}
	if s.issued {
		operation.Status = "SUCCEEDED"
		return s.target, false, nil
	}
	if input.ExpectedFencingToken != operation.FencingToken {
		return nil, false, ErrLeaseHeld
	}
	active := operation.LeaseExpiresAt != nil && s.now.Before(*operation.LeaseExpiresAt)
	if active && operation.LeaseOwner != input.LeaseOwner {
		return nil, false, ErrLeaseHeld
	}
	if !active {
		operation.FencingToken++
		s.parentFence = operation.FencingToken
		s.parentTakeovers++
	}
	operation.LeaseOwner = input.LeaseOwner
	expires := s.now.Add(input.LeaseDuration)
	operation.LeaseExpiresAt = &expires
	return s.target, false, nil
}

func (s *multiSeatPartialPrepareStore) beginChild(slot **StoredOperation, key OperationKey,
	requestHash [32]byte, owner string, expectedFence int64,
	duration time.Duration) (*StoredOperation, bool, bool, error) {
	if *slot == nil {
		if expectedFence != 0 {
			return nil, false, false, ErrStaleFence
		}
		expires := s.now.Add(duration)
		*slot = &StoredOperation{Key: key, Status: "RUNNING", RequestHash: requestHash,
			FencingToken: 1, LeaseOwner: owner, LeaseExpiresAt: &expires}
		s.childFences[key.OperationID] = 1
		return *slot, true, false, nil
	}
	operation := *slot
	if operation.Key != key || operation.RequestHash != requestHash {
		return nil, false, false, ErrHashDrift
	}
	if expectedFence != operation.FencingToken || operation.Status != "RUNNING" {
		return nil, false, false, ErrLeaseHeld
	}
	active := operation.LeaseExpiresAt != nil && s.now.Before(*operation.LeaseExpiresAt)
	if active && operation.LeaseOwner != owner {
		return nil, false, false, ErrLeaseHeld
	}
	takenOver := !active
	if takenOver {
		operation.FencingToken++
	}
	operation.LeaseOwner = owner
	expires := s.now.Add(duration)
	operation.LeaseExpiresAt = &expires
	s.childFences[key.OperationID] = operation.FencingToken
	return operation, false, takenOver, nil
}

func (s *multiSeatPartialPrepareStore) BeginSeatRotation(_ context.Context,
	input BeginSeatRotationInput) (*SeatRotationTarget, bool, error) {
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) {
		return nil, false, ErrStaleFence
	}
	for index := range s.target.SeatTargets {
		seat := &s.target.SeatTargets[index]
		if seat.Progress.SeatExternalID != input.SeatExternalID {
			continue
		}
		s.seatBeginCalls[input.SeatExternalID]++
		key := OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
		operation, created, takenOver, err := s.beginChild(&seat.Operation, key, input.RequestHash,
			input.ChildLeaseOwner, input.ExpectedChildFencingToken, input.ChildLeaseDuration)
		if err != nil {
			return nil, false, err
		}
		if takenOver {
			s.seatTakeovers[input.SeatExternalID]++
		}
		seat.Operation = operation
		seat.Progress.DerivedOperationID = input.DerivedOperationID
		seat.Progress.Status = "PREPARE_PENDING"
		return seat, created, nil
	}
	return nil, false, ErrBindingMismatch
}

func (s *multiSeatPartialPrepareStore) BeginPoolPreparation(_ context.Context,
	input BeginPoolPreparationInput) (*PoolPreparationTarget, bool, error) {
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) {
		return nil, false, ErrStaleFence
	}
	s.beginOrder = append(s.beginOrder, "pool-prepare")
	key := OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	operation, created, takenOver, err := s.beginChild(&s.target.Preparation, key, input.RequestHash,
		input.LeaseOwner, input.ExpectedFencingToken, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if takenOver {
		s.poolPreparationTakeovers++
	}
	requests := make([]PermanentSeatRotationPrepareRequest, len(s.target.SeatTargets))
	for index := range s.target.SeatTargets {
		requests[index] = mustSeatPrepareRequestForTest(s.target.Plan, s.target.SeatTargets[index].Progress)
	}
	setHash, err := PermanentRotationChildSetHash(requests)
	if err != nil {
		return nil, false, err
	}
	return &PoolPreparationTarget{Operation: operation, Plan: s.target.Plan, IntentSetHash: setHash}, created, nil
}

func (s *multiSeatPartialPrepareStore) CommitSeatRotationProgress(_ context.Context,
	input CommitSeatRotationProgressInput) (*StoredSeatRotationProgress, error) {
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) {
		return nil, ErrStaleFence
	}
	if s.target.Preparation == nil || input.PreparationKey != s.target.Preparation.Key ||
		input.PreparationLeaseOwner != s.target.Preparation.LeaseOwner ||
		input.PreparationFencingToken != s.target.Preparation.FencingToken || input.Claim == nil ||
		input.Status != "PREPARED" {
		return nil, ErrStaleFence
	}
	for index := range s.target.SeatTargets {
		seat := &s.target.SeatTargets[index]
		if seat.Progress.SeatExternalID != input.SeatExternalID {
			continue
		}
		if seat.Operation == nil || input.DerivedOperationID != seat.Operation.Key.OperationID ||
			input.ChildLeaseOwner != seat.Operation.LeaseOwner ||
			input.ChildFencingToken != seat.Operation.FencingToken {
			return nil, ErrStaleFence
		}
		progress := seat.Progress
		progress.Status = "PREPARED"
		progress.PrincipalUserID, progress.SubscriptionID = input.PrincipalUserID, input.SubscriptionID
		progress.APIKeyID, progress.APIKeyVersion = input.APIKeyID, input.APIKeyVersion
		progress.CredentialFingerprint = input.Claim.CredentialFingerprint
		progress.PreparedReference = input.Claim.PreparedReference
		progress.ProviderResultDigest = input.Claim.ProviderResultDigest
		seat.Operation.Status = "SUCCEEDED"
		seat.Operation.LeaseOwner = ""
		seat.Operation.LeaseExpiresAt = nil
		s.seatCommitCalls[input.SeatExternalID]++
		allPrepared := true
		for targetIndex := range s.target.SeatTargets {
			allPrepared = allPrepared && s.target.SeatTargets[targetIndex].Progress.Status == "PREPARED"
		}
		if allPrepared {
			s.target.Preparation.Status = "SUCCEEDED"
			s.target.Preparation.LeaseOwner = ""
			s.target.Preparation.LeaseExpiresAt = nil
		}
		if s.prepareLossEnabled && input.SeatExternalID == "seat-1" && !s.prepareLost {
			s.prepareLost = true
			return nil, errFinalizationCommitResponseLost
		}
		return progress, nil
	}
	return nil, ErrBindingMismatch
}

func (s *multiSeatPartialPrepareStore) BeginPoolActivation(_ context.Context,
	input BeginPoolActivationInput) (*PoolActivationTarget, bool, error) {
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) {
		return nil, false, ErrStaleFence
	}
	s.beginOrder = append(s.beginOrder, "pool-activate")
	key := OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	operation, created, _, err := s.beginChild(&s.target.Activation, key, input.RequestHash,
		input.ChildLeaseOwner, input.ExpectedChildFencingToken, input.ChildLeaseDuration)
	if err != nil {
		return nil, false, err
	}
	bindings, err := activationBindings(s.target.SeatTargets)
	if err != nil {
		return nil, false, err
	}
	setHash, err := PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		return nil, false, err
	}
	return &PoolActivationTarget{Operation: operation, Plan: s.target.Plan, PreparedSetHash: setHash}, created, nil
}

func (s *multiSeatPartialPrepareStore) CommitPoolActivation(_ context.Context,
	input CommitPoolActivationInput) (*PermanentReplacementTarget, error) {
	s.lastActivationInput = input
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) ||
		s.target.Activation == nil || input.ChildLeaseOwner != s.target.Activation.LeaseOwner ||
		input.ChildFencingToken != s.target.Activation.FencingToken ||
		s.target.Activation.Status != "RUNNING" {
		return nil, ErrStaleFence
	}
	if input.DerivedOperationID != s.target.Activation.Key.OperationID {
		return nil, ErrBindingMismatch
	}
	for index := range s.target.SeatTargets {
		progress := s.target.SeatTargets[index].Progress
		if progress == nil || progress.Status != "PREPARED" {
			return nil, ErrInvalidData
		}
	}
	bindings, err := activationBindings(s.target.SeatTargets)
	if err != nil {
		return nil, err
	}
	preparedSetHash, err := PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		return nil, err
	}
	if input.PreparedSetHash != preparedSetHash || len(input.Seats) != len(s.target.SeatTargets) {
		return nil, ErrBindingMismatch
	}
	if input.Status != "ACTIVATED" || input.ProviderAttestationRef == "" ||
		input.ProviderAttestationDigest == ([32]byte{}) || input.ProviderAttestationIssuer == "" ||
		input.ProviderAttestationKeyID == "" || input.ProviderAttestationVersion == 0 ||
		len(input.ProviderAttestationSignature) == 0 || !input.OldCredentialSetInvalidated ||
		!input.CredentialFingerprintGateEnforced || input.AuthorizationCacheInvalidated ||
		!input.AuthorizationCacheDurableOutbox ||
		input.AuthCacheMinimumEvents < 2*len(s.target.SeatTargets) {
		return nil, ErrInvalidData
	}
	for index, activated := range input.Seats {
		binding := bindings[index]
		if activated.SeatExternalID != binding.SeatID ||
			activated.TargetMemberExternalID != binding.TargetMemberID ||
			activated.PreparedReference != binding.PreparedRotationRef ||
			activated.PrincipalUserID != binding.PrincipalUserID ||
			activated.SubscriptionID != binding.SubscriptionID ||
			activated.APIKeyID != binding.APIKeyID ||
			activated.APIKeyVersion != binding.ActiveAPIKeyVersion ||
			activated.CredentialFingerprint != binding.CredentialFingerprint {
			return nil, ErrBindingMismatch
		}
		if activated.CurrentConcurrency != 0 || activated.PendingSettlements != 0 {
			return nil, ErrInvalidData
		}
	}
	s.activationCommitCalls++
	s.target.Activation.Status = "SUCCEEDED"
	s.target.Activation.LeaseOwner = ""
	s.target.Activation.LeaseExpiresAt = nil
	for index := range s.target.SeatTargets {
		s.target.SeatTargets[index].Progress.Status = "ACTIVATED"
	}
	s.target.CaseStatus = "READY_TO_COMMIT"
	if s.activationLossEnabled && !s.activationLost {
		s.activationLost = true
		return nil, errFinalizationCommitResponseLost
	}
	return s.target, nil
}

func (s *multiSeatPartialPrepareStore) CommitPermanentReplacement(_ context.Context,
	input CommitPermanentReplacementInput) (*StoredOperation, bool, error) {
	s.structuralCommitCalls++
	if input.Key != s.target.Operation.Key || !s.parentMatches(input.LeaseOwner, input.FencingToken) {
		return nil, false, ErrStaleFence
	}
	if s.structural {
		return s.target.Operation, false, nil
	}
	s.claimIntents = append([]ReplacementClaimIntent(nil), input.ClaimIntents...)
	s.structural = true
	s.target.Plan.Status = planStatusFinalized
	s.target.CaseStatus = "PROVIDER_COMMIT_PENDING"
	for index := range s.target.SeatTargets {
		s.target.SeatTargets[index].Progress.Status = "COMMITTED"
	}
	return s.target.Operation, true, nil
}

func (s *multiSeatPartialPrepareStore) BeginProviderRelease(_ context.Context,
	input BeginProviderReleaseInput) (*ProviderReleaseTarget, bool, error) {
	if !s.parentMatches(input.FinalizationLeaseOwner, input.FinalizationFencingToken) {
		return nil, false, ErrStaleFence
	}
	s.beginOrder = append(s.beginOrder, "provider-release")
	key := OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	operation, created, _, err := s.beginChild(&s.target.ProviderRelease, key, input.RequestHash,
		input.ChildLeaseOwner, input.ExpectedChildFencingToken, input.ChildLeaseDuration)
	if err != nil {
		return nil, false, err
	}
	bindings, err := releaseBindings(s.target.SeatTargets)
	if err != nil {
		return nil, false, err
	}
	setHash, err := PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		return nil, false, err
	}
	return &ProviderReleaseTarget{Operation: operation, Plan: s.target.Plan, PreparedSetHash: setHash}, created, nil
}

func newOwnedFinalizationRecoveryManager(t *testing.T, store Store, rotations PermanentSeatRotationProvider,
	now time.Time, owner string, cipher *managerRecoveryCipher, tokenCalls *int) *Manager {
	t.Helper()
	manager, err := NewManager(store, Providers{SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: cipher},
		ManagerConfig{ClientID: "recovery-client", LeaseOwner: owner, LeaseDuration: time.Minute,
			ExpectedRootProviderID: "root-provider", RootTrustProfile: "prod-root-v1",
			Now: func() time.Time { return now }, ClaimToken: func() (string, error) {
				(*tokenCalls)++
				return "one-time-claim-token", nil
			}})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func multiSeatFinalizationRecoveryRequest() FinalizeRequest {
	return FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{
			{SeatExternalID: "seat-1", TargetMemberExternalID: "member-new-1"},
			{SeatExternalID: "seat-2", TargetMemberExternalID: "member-new-2"},
		}, EvidenceExternalIDs: []string{"evidence-1"}}
}

func TestFinalizationMultiSeatPartialPrepareResponseLossTakenOverByDifferentOwner(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 0, 0, 0, time.UTC)
	store := newMultiSeatPartialPrepareStore(now)
	delegate := &finalizationRotationProvider{now: now}
	rotations := &exactReplayPrepareProvider{delegate: delegate}
	sealCalls := 0
	cipher := &managerRecoveryCipher{onSeal: func() { sealCalls++ }}
	tokenCalls := 0
	request := multiSeatFinalizationRecoveryRequest()

	first := newOwnedFinalizationRecoveryManager(t, store, rotations, now,
		"worker-partial-a", cipher, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		var validationErr error
		if rotations.request != nil {
			validationErr = ValidatePermanentPoolRotationPrepareResult(*rotations.request, rotations.result)
		}
		t.Fatalf("Finalize() at partial prepare response loss = %+v, %v (provider=%d/%d delegate=%d seals=%d reconciled=%v validation=%v statuses=%s/%s)",
			progress, err, rotations.calls, rotations.durableExecutions, delegate.prepareCalls, sealCalls,
			store.reconciled, validationErr, store.target.SeatTargets[0].Progress.Status,
			store.target.SeatTargets[1].Progress.Status)
	}
	if store.target.SeatTargets[0].Progress.Status != "PREPARED" ||
		store.target.SeatTargets[1].Progress.Status != "PREPARE_PENDING" ||
		store.target.Preparation == nil || store.target.Preparation.Status != "RUNNING" ||
		rotations.calls != 1 || rotations.durableExecutions != 1 || delegate.prepareCalls != 1 ||
		sealCalls != 1 || store.seatCommitCalls["seat-1"] != 1 ||
		store.seatCommitCalls["seat-2"] != 0 || tokenCalls != 0 {
		t.Fatalf("partial prepare boundary mismatch: statuses=%s/%s preparation=%+v provider=%d/%d/%d seals=%d commits=%v tokens=%d",
			store.target.SeatTargets[0].Progress.Status, store.target.SeatTargets[1].Progress.Status,
			store.target.Preparation, rotations.calls, rotations.durableExecutions,
			delegate.prepareCalls, sealCalls, store.seatCommitCalls, tokenCalls)
	}

	restartedAt := now.Add(2 * time.Minute)
	store.now = restartedAt
	worker := newOwnedFinalizationRecoveryManager(t, store, rotations, restartedAt,
		"worker-partial-b", cipher, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextFinalization() = %v, %v (parent=%+v preparation=%+v activation=%+v activationInput=%+v activationCommits=%d seats=%+v provider=%d/%d/%d seals=%d commits=%v)",
			worked, err, store.target.Operation, store.target.Preparation, store.target.Activation,
			store.lastActivationInput, store.activationCommitCalls, store.target.SeatTargets, rotations.calls,
			rotations.durableExecutions, delegate.activateCalls, sealCalls, store.seatCommitCalls)
	}
	if store.target.CaseStatus != "READY_TO_COMMIT" ||
		store.target.Operation.LeaseOwner != "worker-partial-b" ||
		store.target.Operation.FencingToken != 2 || store.parentTakeovers != 1 ||
		store.target.SeatTargets[0].Operation.FencingToken != 1 ||
		store.target.SeatTargets[1].Operation.FencingToken != 2 ||
		store.seatTakeovers["seat-1"] != 0 || store.seatTakeovers["seat-2"] != 1 ||
		store.target.Preparation.FencingToken != 2 || store.poolPreparationTakeovers != 1 {
		t.Fatalf("different-owner takeover mismatch: case=%s parent=%+v parentTakeovers=%d seatFences=%d/%d seatTakeovers=%v preparation=%+v preparationTakeovers=%d",
			store.target.CaseStatus, store.target.Operation, store.parentTakeovers,
			store.target.SeatTargets[0].Operation.FencingToken,
			store.target.SeatTargets[1].Operation.FencingToken, store.seatTakeovers,
			store.target.Preparation, store.poolPreparationTakeovers)
	}
	if rotations.calls != 2 || rotations.durableExecutions != 1 || delegate.prepareCalls != 1 ||
		delegate.activateCalls != 1 || delegate.commitCalls != 0 || sealCalls != 2 ||
		store.seatCommitCalls["seat-1"] != 1 || store.seatCommitCalls["seat-2"] != 1 ||
		store.activationCommitCalls != 1 || store.structural || tokenCalls != 0 {
		t.Fatalf("worker repeated completed work or crossed issuance boundary: provider=%d/%d delegate=%d/%d/%d seals=%d commits=%v activationCommits=%d structural=%v tokens=%d",
			rotations.calls, rotations.durableExecutions, delegate.prepareCalls, delegate.activateCalls,
			delegate.commitCalls, sealCalls, store.seatCommitCalls, store.activationCommitCalls,
			store.structural, tokenCalls)
	}
	if _, err := store.RenewPermanentReplacementLease(context.Background(),
		RenewPermanentReplacementLeaseInput{Key: store.target.Operation.Key,
			LeaseOwner: "worker-partial-a", ExpectedFencingToken: 1,
			LeaseDuration: time.Minute}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old owner/fence renewed after takeover: %v", err)
	}

	request.ExpectedFencingToken = 2
	synchronous := newOwnedFinalizationRecoveryManager(t, store, rotations, restartedAt,
		"worker-partial-b", cipher, &tokenCalls)
	progress, err := synchronous.Finalize(context.Background(), request)
	if err != nil || progress == nil || progress.Status != planStatusFinalized ||
		len(progress.Claims) != 2 {
		t.Fatalf("Finalize() after worker takeover = %+v, %v", progress, err)
	}
	if rotations.calls != 2 || rotations.durableExecutions != 1 || delegate.prepareCalls != 1 ||
		delegate.activateCalls != 1 || delegate.commitCalls != 1 || sealCalls != 2 ||
		store.seatCommitCalls["seat-1"] != 1 || store.seatCommitCalls["seat-2"] != 1 ||
		store.structuralCommitCalls != 1 || store.releaseProofCalls != 1 ||
		store.claimCommitCalls != 1 || tokenCalls != 2 {
		t.Fatalf("synchronous completion repeated a durable boundary: provider=%d/%d delegate=%d/%d/%d seals=%d commits=%v structural=%d release=%d claims=%d tokens=%d",
			rotations.calls, rotations.durableExecutions, delegate.prepareCalls, delegate.activateCalls,
			delegate.commitCalls, sealCalls, store.seatCommitCalls, store.structuralCommitCalls,
			store.releaseProofCalls, store.claimCommitCalls, tokenCalls)
	}

	replay, err := synchronous.Finalize(context.Background(), request)
	if err != nil || replay == nil || replay.Status != planStatusFinalized ||
		len(replay.Claims) != 0 || tokenCalls != 2 || rotations.calls != 2 ||
		sealCalls != 2 || store.claimCommitCalls != 1 {
		t.Fatalf("terminal replay regenerated raw claims or repeated prepare: %+v, %v tokens=%d provider=%d seals=%d claimCommits=%d",
			replay, err, tokenCalls, rotations.calls, sealCalls, store.claimCommitCalls)
	}
}

// This deterministic unit gate models a successful in-memory store commit followed by response loss.
// Process restart with PostgreSQL state reload is covered by the separate integration gate.
func TestFinalizationMultiSeatActivationResponseLossOnlyParentLeaseIsTakenOver(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	store := newMultiSeatActivationResponseLossStore(now)
	delegate := &finalizationRotationProvider{now: now}
	rotations := &exactReplayPrepareProvider{delegate: delegate}
	sealCalls := 0
	cipher := &managerRecoveryCipher{onSeal: func() { sealCalls++ }}
	tokenCalls := 0
	request := multiSeatFinalizationRecoveryRequest()

	first := newOwnedFinalizationRecoveryManager(t, store, rotations, now,
		"worker-activation-a", cipher, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at activation response loss = %+v, %v", progress, err)
	}
	if store.target.CaseStatus != "READY_TO_COMMIT" ||
		store.target.Preparation == nil || store.target.Preparation.Status != "SUCCEEDED" ||
		store.target.Preparation.LeaseOwner != "" || store.target.Preparation.LeaseExpiresAt != nil ||
		store.target.Activation == nil || store.target.Activation.Status != "SUCCEEDED" ||
		store.target.Activation.LeaseOwner != "" || store.target.Activation.LeaseExpiresAt != nil ||
		len(store.lastActivationInput.Seats) != 2 ||
		store.lastActivationInput.Seats[0].SeatExternalID == store.lastActivationInput.Seats[1].SeatExternalID ||
		store.target.SeatTargets[0].Progress.Status != "ACTIVATED" ||
		store.target.SeatTargets[1].Progress.Status != "ACTIVATED" ||
		store.target.SeatTargets[0].Operation.Status != "SUCCEEDED" ||
		store.target.SeatTargets[1].Operation.Status != "SUCCEEDED" ||
		store.target.SeatTargets[0].Operation.LeaseOwner != "" ||
		store.target.SeatTargets[1].Operation.LeaseOwner != "" ||
		store.target.SeatTargets[0].Operation.LeaseExpiresAt != nil ||
		store.target.SeatTargets[1].Operation.LeaseExpiresAt != nil ||
		store.seatCommitCalls["seat-1"] != 1 || store.seatCommitCalls["seat-2"] != 1 ||
		store.activationCommitCalls != 1 || rotations.calls != 1 ||
		rotations.durableExecutions != 1 || delegate.prepareCalls != 1 ||
		delegate.activateCalls != 1 || delegate.commitCalls != 0 || sealCalls != 2 ||
		store.structural || store.structuralCommitCalls != 0 || store.target.ProviderRelease != nil ||
		store.releaseProofCalls != 0 || store.claimCommitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("in-memory Pool activation commit was not atomic: case=%s preparation=%+v activation=%+v seats=%+v activationSeats=%d seatCommits=%v activationCommits=%d provider=%d/%d delegate=%d/%d/%d seals=%d structural=%v/%d release=%+v/%d claims=%d tokens=%d",
			store.target.CaseStatus, store.target.Preparation, store.target.Activation,
			store.target.SeatTargets, len(store.lastActivationInput.Seats), store.seatCommitCalls,
			store.activationCommitCalls, rotations.calls, rotations.durableExecutions,
			delegate.prepareCalls, delegate.activateCalls,
			delegate.commitCalls, sealCalls, store.structural, store.structuralCommitCalls,
			store.target.ProviderRelease, store.releaseProofCalls, store.claimCommitCalls, tokenCalls)
	}

	takeoverAt := now.Add(2 * time.Minute)
	store.now = takeoverAt
	worker := newOwnedFinalizationRecoveryManager(t, store, rotations, takeoverAt,
		"worker-activation-b", cipher, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if err != nil || !worked {
		t.Fatalf("RecoverNextFinalization() = %v, %v", worked, err)
	}
	if store.target.CaseStatus != "READY_TO_COMMIT" ||
		store.target.Operation.LeaseOwner != "worker-activation-b" ||
		store.target.Operation.FencingToken != 2 || store.parentTakeovers != 1 ||
		store.target.Activation.Status != "SUCCEEDED" ||
		store.target.Activation.FencingToken != 1 || store.target.Activation.LeaseOwner != "" ||
		store.target.Activation.LeaseExpiresAt != nil ||
		store.target.SeatTargets[0].Progress.Status != "ACTIVATED" ||
		store.target.SeatTargets[1].Progress.Status != "ACTIVATED" ||
		store.target.SeatTargets[0].Operation.FencingToken != 1 ||
		store.target.SeatTargets[1].Operation.FencingToken != 1 ||
		store.target.Preparation.FencingToken != 1 ||
		store.seatTakeovers["seat-1"] != 0 || store.seatTakeovers["seat-2"] != 0 ||
		store.poolPreparationTakeovers != 0 ||
		store.seatCommitCalls["seat-1"] != 1 || store.seatCommitCalls["seat-2"] != 1 ||
		rotations.calls != 1 || rotations.durableExecutions != 1 ||
		delegate.prepareCalls != 1 || delegate.activateCalls != 1 || delegate.commitCalls != 0 ||
		store.activationCommitCalls != 1 || store.structural || store.structuralCommitCalls != 0 ||
		store.target.ProviderRelease != nil || store.releaseProofCalls != 0 ||
		store.claimCommitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("worker crossed the committed activation boundary or took over a child lease: case=%s parent=%+v parentTakeovers=%d activation=%+v seats=%+v seatTakeovers=%v preparationTakeovers=%d seatCommits=%v provider=%d/%d delegate=%d/%d/%d activationCommits=%d structural=%v/%d release=%+v/%d claims=%d tokens=%d",
			store.target.CaseStatus, store.target.Operation, store.parentTakeovers,
			store.target.Activation, store.target.SeatTargets, store.seatTakeovers,
			store.poolPreparationTakeovers, store.seatCommitCalls, rotations.calls, rotations.durableExecutions,
			delegate.prepareCalls, delegate.activateCalls, delegate.commitCalls,
			store.activationCommitCalls, store.structural, store.structuralCommitCalls,
			store.target.ProviderRelease, store.releaseProofCalls, store.claimCommitCalls, tokenCalls)
	}
	if _, err := store.RenewPermanentReplacementLease(context.Background(),
		RenewPermanentReplacementLeaseInput{Key: store.target.Operation.Key,
			LeaseOwner: "worker-activation-a", ExpectedFencingToken: 1,
			LeaseDuration: time.Minute}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old owner/fence renewed after activation takeover: %v", err)
	}

	request.ExpectedFencingToken = 2
	synchronous := newOwnedFinalizationRecoveryManager(t, store, rotations, takeoverAt,
		"worker-activation-b", cipher, &tokenCalls)
	progress, err := synchronous.Finalize(context.Background(), request)
	if err != nil || progress == nil || progress.Status != planStatusFinalized ||
		len(progress.Claims) != 2 || progress.Claims[0].SeatID == progress.Claims[1].SeatID {
		t.Fatalf("Finalize() after activation takeover = %+v, %v", progress, err)
	}
	if store.target.Operation.Status != "SUCCEEDED" || store.target.CaseStatus != "FINALIZED" ||
		rotations.calls != 1 || rotations.durableExecutions != 1 ||
		delegate.prepareCalls != 1 || delegate.activateCalls != 1 || delegate.commitCalls != 1 ||
		store.activationCommitCalls != 1 || store.structuralCommitCalls != 1 ||
		store.releaseProofCalls != 1 || store.claimCommitCalls != 1 ||
		len(store.claimIntents) != 2 || len(store.commitClaims) != 2 || tokenCalls != 2 {
		t.Fatalf("synchronous takeover did not complete exactly once per Pool/Seat: parent=%s case=%s provider=%d/%d delegate=%d/%d/%d activation=%d structural=%d release=%d claimCommits=%d intents=%d claims=%d tokens=%d",
			store.target.Operation.Status, store.target.CaseStatus, rotations.calls,
			rotations.durableExecutions, delegate.prepareCalls, delegate.activateCalls,
			delegate.commitCalls, store.activationCommitCalls, store.structuralCommitCalls,
			store.releaseProofCalls, store.claimCommitCalls, len(store.claimIntents),
			len(store.commitClaims), tokenCalls)
	}

	replay, err := synchronous.Finalize(context.Background(), request)
	if err != nil || replay == nil || replay.Status != planStatusFinalized ||
		len(replay.Claims) != 0 || rotations.calls != 1 || rotations.durableExecutions != 1 ||
		delegate.prepareCalls != 1 || delegate.activateCalls != 1 || delegate.commitCalls != 1 ||
		store.activationCommitCalls != 1 || store.structuralCommitCalls != 1 ||
		store.releaseProofCalls != 1 || store.claimCommitCalls != 1 || tokenCalls != 2 {
		t.Fatalf("terminal replay regenerated a claim or repeated a committed boundary: %+v, %v provider=%d/%d delegate=%d/%d/%d activation=%d structural=%d release=%d claims=%d tokens=%d",
			replay, err, rotations.calls, rotations.durableExecutions, delegate.prepareCalls,
			delegate.activateCalls, delegate.commitCalls, store.activationCommitCalls,
			store.structuralCommitCalls, store.releaseProofCalls, store.claimCommitCalls, tokenCalls)
	}
}
