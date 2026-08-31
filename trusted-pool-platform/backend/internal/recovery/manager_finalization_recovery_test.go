package recovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"
)

var (
	errFinalizationCommitResponseLost   = errors.New("durable finalization commit response lost")
	errFinalizationProviderResponseLost = errors.New("durable provider commit response lost")
)

type finalizationDurableBoundary uint8

const (
	finalizationBoundaryNone finalizationDurableBoundary = iota
	finalizationBoundaryPrepare
	finalizationBoundaryActivation
	finalizationBoundaryStructural
	finalizationBoundaryReleaseProof
	finalizationBoundaryClaims
)

type finalizationResponseLossStore struct {
	*finalizationStoreStub
	boundary finalizationDurableBoundary
	tripped  bool

	structuralCommitCalls int
	releaseProofCalls     int
	claimCommitCalls      int
	releaseReconcileCalls int
}

func (s *finalizationResponseLossStore) loseResponseAt(boundary finalizationDurableBoundary) bool {
	if s.boundary != boundary || s.tripped {
		return false
	}
	s.tripped = true
	return true
}

func (s *finalizationResponseLossStore) CommitSeatRotationProgress(ctx context.Context,
	input CommitSeatRotationProgressInput) (*StoredSeatRotationProgress, error) {
	progress, err := s.finalizationStoreStub.CommitSeatRotationProgress(ctx, input)
	if err == nil && s.loseResponseAt(finalizationBoundaryPrepare) {
		return nil, errFinalizationCommitResponseLost
	}
	return progress, err
}

func (s *finalizationResponseLossStore) CommitPoolActivation(ctx context.Context,
	input CommitPoolActivationInput) (*PermanentReplacementTarget, error) {
	target, err := s.finalizationStoreStub.CommitPoolActivation(ctx, input)
	if err == nil && s.loseResponseAt(finalizationBoundaryActivation) {
		return nil, errFinalizationCommitResponseLost
	}
	return target, err
}

func (s *finalizationResponseLossStore) CommitPermanentReplacement(ctx context.Context,
	input CommitPermanentReplacementInput) (*StoredOperation, bool, error) {
	s.structuralCommitCalls++
	operation, committed, err := s.finalizationStoreStub.CommitPermanentReplacement(ctx, input)
	if err == nil && s.loseResponseAt(finalizationBoundaryStructural) {
		return nil, false, errFinalizationCommitResponseLost
	}
	return operation, committed, err
}

func (s *finalizationResponseLossStore) CommitProviderRelease(ctx context.Context,
	input CommitProviderReleaseInput) (*StoredOperation, bool, error) {
	if input.Status == "RECONCILE_REQUIRED" {
		s.releaseReconcileCalls++
		if s.target.ProviderRelease == nil || input.DerivedOperationID != s.target.ProviderRelease.Key.OperationID {
			return nil, false, ErrBindingMismatch
		}
		s.target.ProviderRelease.Status = "RECONCILE_REQUIRED"
		return s.target.Operation, true, nil
	}
	s.releaseProofCalls++
	operation, committed, err := s.finalizationStoreStub.CommitProviderRelease(ctx, input)
	if err == nil && s.loseResponseAt(finalizationBoundaryReleaseProof) {
		return nil, false, errFinalizationCommitResponseLost
	}
	return operation, committed, err
}

func (s *finalizationResponseLossStore) CommitReplacementClaims(ctx context.Context,
	input CommitReplacementClaimsInput) (*StoredOperation, bool, error) {
	s.claimCommitCalls++
	operation, committed, err := s.finalizationStoreStub.CommitReplacementClaims(ctx, input)
	if err == nil && s.loseResponseAt(finalizationBoundaryClaims) {
		return nil, false, errFinalizationCommitResponseLost
	}
	return operation, committed, err
}

type exactReplayCommitProvider struct {
	delegate          *finalizationRotationProvider
	calls             int
	durableExecutions int
	request           *PermanentPoolRotationCommitRequest
	result            PermanentPoolRotationCommitResult
}

func (p *exactReplayCommitProvider) Ready(ctx context.Context) error {
	return p.delegate.Ready(ctx)
}

func (p *exactReplayCommitProvider) PreparePoolRotation(ctx context.Context,
	request PermanentPoolRotationPrepareRequest) (PermanentPoolRotationPrepareResult, error) {
	return p.delegate.PreparePoolRotation(ctx, request)
}

func (p *exactReplayCommitProvider) ActivatePreparedPoolRotation(ctx context.Context,
	request PermanentPoolRotationActivateRequest) (PermanentPoolRotationActivateResult, error) {
	return p.delegate.ActivatePreparedPoolRotation(ctx, request)
}

func (p *exactReplayCommitProvider) CommitActivatedPoolRotation(ctx context.Context,
	request PermanentPoolRotationCommitRequest) (PermanentPoolRotationCommitResult, error) {
	p.calls++
	if p.request == nil {
		stored := request
		stored.Seats = append([]PermanentSeatActivationBinding(nil), request.Seats...)
		result, err := p.delegate.CommitActivatedPoolRotation(ctx, request)
		if err != nil {
			return PermanentPoolRotationCommitResult{}, err
		}
		p.request = &stored
		p.result = result
		p.result.Seats = append([]PermanentSeatActivationResult(nil), result.Seats...)
		p.result.Attestation = append([]byte(nil), result.Attestation...)
		p.durableExecutions++
		return PermanentPoolRotationCommitResult{}, errFinalizationProviderResponseLost
	}
	if !reflect.DeepEqual(*p.request, request) {
		return PermanentPoolRotationCommitResult{}, ErrBindingMismatch
	}
	result := p.result
	result.Seats = append([]PermanentSeatActivationResult(nil), p.result.Seats...)
	result.Attestation = append([]byte(nil), p.result.Attestation...)
	return result, nil
}

func newFinalizationRecoveryManager(t *testing.T, store Store, rotations PermanentSeatRotationProvider,
	now time.Time, tokenCalls *int) *Manager {
	t.Helper()
	manager, err := NewManager(store, Providers{SeatRotations: rotations,
		SeatActivations: &managerSeatActivationVerifier{}, CredentialCipher: &managerRecoveryCipher{}},
		ManagerConfig{ClientID: "recovery-client", LeaseOwner: "worker-unique-1",
			LeaseDuration: time.Minute, ExpectedRootProviderID: "root-provider",
			RootTrustProfile: "prod-root-v1", Now: func() time.Time { return now },
			ClaimToken: func() (string, error) {
				(*tokenCalls)++
				return "one-time-claim-token", nil
			}})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func finalizationRecoveryRequest() FinalizeRequest {
	return FinalizeRequest{OperationID: "finalize-op-1", PlanExternalID: "plan-1",
		CaseExternalID: "case-1", Replacements: []SeatReplacementIntent{{SeatExternalID: "seat-1",
			TargetMemberExternalID: "member-new"}}, EvidenceExternalIDs: []string{"evidence-1"}}
}

func requireFirstFinalizationClaim(t *testing.T, progress *FinalizationProgress, err error) {
	t.Helper()
	if err != nil || progress == nil || progress.Status != planStatusFinalized || len(progress.Claims) != 1 ||
		progress.Claims[0].ClaimToken != "one-time-claim-token" {
		t.Fatalf("finalization after restart = %+v, %v", progress, err)
	}
}

func TestFinalizationPrepareCommitResponseLossRestartsWithoutPreparingAgain(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryPrepare}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at lost prepare commit response = %+v, %v", progress, err)
	}
	if store.target.SeatTargets[0].Progress.Status != "PREPARED" ||
		store.target.Preparation == nil || store.target.Preparation.Status != "SUCCEEDED" ||
		rotations.prepareCalls != 1 || rotations.activateCalls != 0 || store.structural || tokenCalls != 0 {
		t.Fatalf("durable prepare boundary was not held: target=%+v prepare=%d activate=%d structural=%v tokens=%d",
			store.target, rotations.prepareCalls, rotations.activateCalls, store.structural, tokenCalls)
	}

	restarted := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := restarted.Finalize(context.Background(), request)
	requireFirstFinalizationClaim(t, progress, err)
	if rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 1 ||
		store.structuralCommitCalls != 1 || store.releaseProofCalls != 1 || store.claimCommitCalls != 1 ||
		tokenCalls != 1 {
		t.Fatalf("restart repeated a completed boundary: prepare=%d activate=%d providerCommit=%d structural=%d releaseProof=%d claims=%d tokens=%d",
			rotations.prepareCalls, rotations.activateCalls, rotations.commitCalls, store.structuralCommitCalls,
			store.releaseProofCalls, store.claimCommitCalls, tokenCalls)
	}
}

func TestFinalizationActivationCommitResponseLossWorkerHoldsStructuralBoundary(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 10, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryActivation}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at lost activation commit response = %+v, %v", progress, err)
	}
	if store.target.CaseStatus != "READY_TO_COMMIT" || store.target.Plan.Status != planStatusReady ||
		store.target.SeatTargets[0].Progress.Status != "ACTIVATED" || store.structural ||
		rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("activate-held boundary was not durable: case=%s plan=%s seat=%s structural=%v calls=%d/%d/%d tokens=%d",
			store.target.CaseStatus, store.target.Plan.Status, store.target.SeatTargets[0].Progress.Status,
			store.structural, rotations.prepareCalls, rotations.activateCalls, rotations.commitCalls, tokenCalls)
	}

	worker := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if err != nil || !worked || store.target.CaseStatus != "READY_TO_COMMIT" || store.structural ||
		rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("worker crossed or replayed activate-held boundary: worked=%v err=%v case=%s structural=%v calls=%d/%d/%d tokens=%d",
			worked, err, store.target.CaseStatus, store.structural, rotations.prepareCalls,
			rotations.activateCalls, rotations.commitCalls, tokenCalls)
	}

	restarted := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := restarted.Finalize(context.Background(), request)
	requireFirstFinalizationClaim(t, progress, err)
	if rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 1 ||
		store.structuralCommitCalls != 1 || tokenCalls != 1 {
		t.Fatalf("sync restart repeated activation: calls=%d/%d/%d structural=%d tokens=%d",
			rotations.prepareCalls, rotations.activateCalls, rotations.commitCalls,
			store.structuralCommitCalls, tokenCalls)
	}
}

func TestFinalizationActivationRestartRejectsTamperedPersistedBinding(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 15, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryActivation}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if _, err := first.Finalize(context.Background(), request); !errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at activation boundary = %v", err)
	}
	store.target.Activation.RequestHash = sha256.Sum256([]byte("tampered-activation-request"))

	worker := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if !worked || !errors.Is(err, ErrBindingMismatch) || store.structural ||
		rotations.prepareCalls != 1 || rotations.activateCalls != 1 || rotations.commitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("tampered activation crossed recovery boundary: worked=%v err=%v structural=%v calls=%d/%d/%d tokens=%d",
			worked, err, store.structural, rotations.prepareCalls, rotations.activateCalls,
			rotations.commitCalls, tokenCalls)
	}
}

func TestFinalizationStructuralCommitResponseLossResumesAtProviderCommit(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 20, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryStructural}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at lost structural commit response = %+v, %v", progress, err)
	}
	if store.target.Plan.Status != planStatusFinalized || store.target.CaseStatus != "PROVIDER_COMMIT_PENDING" ||
		!store.structural || store.structuralCommitCalls != 1 || rotations.commitCalls != 0 || tokenCalls != 0 {
		t.Fatalf("structural boundary was not durable: plan=%s case=%s structural=%v commits=%d provider=%d tokens=%d",
			store.target.Plan.Status, store.target.CaseStatus, store.structural, store.structuralCommitCalls,
			rotations.commitCalls, tokenCalls)
	}

	restarted := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := restarted.Finalize(context.Background(), request)
	requireFirstFinalizationClaim(t, progress, err)
	if store.structuralCommitCalls != 1 || rotations.prepareCalls != 1 || rotations.activateCalls != 1 ||
		rotations.commitCalls != 1 || tokenCalls != 1 {
		t.Fatalf("restart repeated structural work: structural=%d calls=%d/%d/%d tokens=%d",
			store.structuralCommitCalls, rotations.prepareCalls, rotations.activateCalls,
			rotations.commitCalls, tokenCalls)
	}
}

func TestFinalizationProviderCommitResponseLossWorkerReplaysExactlyWithoutToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 30, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now)}
	delegate := &finalizationRotationProvider{now: now}
	rotations := &exactReplayCommitProvider{delegate: delegate}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Finalize() at lost provider commit response = %+v, %v", progress, err)
	}
	if store.target.ProviderRelease == nil || store.target.ProviderRelease.Status != "RECONCILE_REQUIRED" ||
		store.releaseReconcileCalls != 1 || rotations.calls != 1 || rotations.durableExecutions != 1 ||
		delegate.commitCalls != 1 || tokenCalls != 0 {
		t.Fatalf("unknown provider result was not held for exact replay: release=%+v reconcile=%d calls=%d durable=%d delegate=%d tokens=%d",
			store.target.ProviderRelease, store.releaseReconcileCalls, rotations.calls,
			rotations.durableExecutions, delegate.commitCalls, tokenCalls)
	}

	worker := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if err != nil || !worked || store.target.CaseStatus != "READY_TO_ISSUE" ||
		store.target.Operation.Status != "RUNNING" || rotations.calls != 2 ||
		rotations.durableExecutions != 1 || delegate.commitCalls != 1 || tokenCalls != 0 {
		t.Fatalf("worker exact replay = worked=%v err=%v case=%s parent=%s calls=%d durable=%d delegate=%d tokens=%d",
			worked, err, store.target.CaseStatus, store.target.Operation.Status, rotations.calls,
			rotations.durableExecutions, delegate.commitCalls, tokenCalls)
	}

	synchronous := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := synchronous.Finalize(context.Background(), request)
	requireFirstFinalizationClaim(t, progress, err)
	if rotations.calls != 2 || rotations.durableExecutions != 1 || delegate.commitCalls != 1 || tokenCalls != 1 {
		t.Fatalf("issuance repeated provider commit: calls=%d durable=%d delegate=%d tokens=%d",
			rotations.calls, rotations.durableExecutions, delegate.commitCalls, tokenCalls)
	}
}

func TestFinalizationReleaseProofCommitResponseLossDoesNotRepeatProviderCommit(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 40, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryReleaseProof}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at lost release-proof response = %+v, %v", progress, err)
	}
	if store.target.CaseStatus != "READY_TO_ISSUE" || store.target.ProviderRelease.Status != "SUCCEEDED" ||
		rotations.commitCalls != 1 || store.releaseProofCalls != 1 || tokenCalls != 0 {
		t.Fatalf("release proof was not durable: case=%s release=%s provider=%d proof=%d tokens=%d",
			store.target.CaseStatus, store.target.ProviderRelease.Status, rotations.commitCalls,
			store.releaseProofCalls, tokenCalls)
	}

	worker := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	worked, err := worker.RecoverNextFinalization(context.Background())
	if err != nil || !worked || rotations.commitCalls != 1 || store.releaseProofCalls != 1 || tokenCalls != 0 {
		t.Fatalf("worker repeated release or issued token: worked=%v err=%v provider=%d proof=%d tokens=%d",
			worked, err, rotations.commitCalls, store.releaseProofCalls, tokenCalls)
	}

	restarted := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := restarted.Finalize(context.Background(), request)
	requireFirstFinalizationClaim(t, progress, err)
}

func TestFinalizationClaimCommitResponseLossNeverDisclosesOrRegeneratesRawToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 50, 0, 0, time.UTC)
	store := &finalizationResponseLossStore{finalizationStoreStub: newFinalizationStoreStub(now),
		boundary: finalizationBoundaryClaims}
	rotations := &finalizationRotationProvider{now: now}
	tokenCalls := 0
	request := finalizationRecoveryRequest()

	first := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	if progress, err := first.Finalize(context.Background(), request); progress != nil ||
		!errors.Is(err, errFinalizationCommitResponseLost) {
		t.Fatalf("Finalize() at lost claim commit response disclosed data: %+v, %v", progress, err)
	}
	if !store.issued || store.target.Operation.Status != "SUCCEEDED" ||
		store.claimCommitCalls != 1 || tokenCalls != 1 {
		t.Fatalf("claim commit was not durable: issued=%v parent=%s commits=%d tokens=%d",
			store.issued, store.target.Operation.Status, store.claimCommitCalls, tokenCalls)
	}

	restarted := newFinalizationRecoveryManager(t, store, rotations, now, &tokenCalls)
	progress, err := restarted.Finalize(context.Background(), request)
	if err != nil || progress == nil || progress.Status != planStatusFinalized || len(progress.Claims) != 0 {
		t.Fatalf("terminal replay leaked raw token: %+v, %v", progress, err)
	}
	if store.claimCommitCalls != 1 || tokenCalls != 1 || rotations.prepareCalls != 1 ||
		rotations.activateCalls != 1 || rotations.commitCalls != 1 {
		t.Fatalf("terminal replay repeated work: claims=%d tokens=%d calls=%d/%d/%d",
			store.claimCommitCalls, tokenCalls, rotations.prepareCalls, rotations.activateCalls,
			rotations.commitCalls)
	}
}
