//go:build unit

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type trustedPoolRepoStub struct {
	seat                  *TrustedPoolSeat
	getSeatCalls          int
	risk                  *TrustedPoolUsageRisk
	frozen                bool
	rotateCalls           int
	lastCredential        string
	byAPIKeySeats         []*TrustedPoolSeat
	byAPIKeyCalls         int
	credentialMatches     *bool
	credentialMatchErr    error
	usageSnapshot         *TrustedPoolUsageSnapshot
	events                *[]string
	pending               int
	pendingStatus         string
	pendingBilling        string
	pendingError          string
	markCalls             int
	createErr             error
	completeErr           error
	countErr              error
	provisionInputs       []ProvisionTrustedPoolSeatInput
	ackInputs             []AckTrustedPoolProvisionCredentialInput
	permanentPrepareCalls int
	permanentCommitReplay *TrustedPoolPermanentRotationCommitResult
	permanentCommitFound  bool
	permanentCommitErr    error
	permanentReplayCalls  int
}

func trustedPoolTestContext() context.Context {
	return WithTrustedPoolIntegrationPrincipal(context.Background(), TrustedPoolIntegrationPrincipal{
		ClientID: "platform-1", ExternalPoolID: "pool-1",
	})
}

func (r *trustedPoolRepoStub) ProvisionSeat(_ context.Context, input ProvisionTrustedPoolSeatInput) (*TrustedPoolProvisionResult, error) {
	r.provisionInputs = append(r.provisionInputs, input)
	seat := &TrustedPoolSeat{
		ExternalPoolID: input.ExternalPoolID, ExternalSeatID: input.ExternalSeatID,
		GroupID: input.ExistingGroupID, AssignmentEpoch: input.AssignmentEpoch,
	}
	return &TrustedPoolProvisionResult{Seat: seat, Credential: input.Credential, CredentialFingerprint: input.CredentialFingerprint}, nil
}

func (r *trustedPoolRepoStub) AckProvisionCredential(_ context.Context, externalSeatID string, input AckTrustedPoolProvisionCredentialInput) (*TrustedPoolProvisionCredentialClaim, error) {
	r.ackInputs = append(r.ackInputs, input)
	return &TrustedPoolProvisionCredentialClaim{
		ExternalSeatID: externalSeatID, ProvisionOperationID: input.ProvisionOperationID,
		ClaimOperationID: input.ClaimOperationID, ClaimedBy: input.ClaimedBy, CredentialFingerprint: input.CredentialFingerprint,
		CredentialClaimed: true, ClaimedAt: time.Now(),
	}, nil
}

func TestTrustedPoolProvisionCanonicalizesStableRequestHash(t *testing.T) {
	repo := &trustedPoolRepoStub{}
	svc := NewTrustedPoolIntegrationService(repo, nil, nil, nil)
	expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	input := ProvisionTrustedPoolSeatInput{
		ExternalPoolID: " pool-1 ", ExternalSeatID: " seat-1 ", ExistingGroupID: 9,
		OperationID: " provision-1 ", ActorClientID: " platform-1 ", PrincipalConcurrency: 2,
		SubscriptionExpiresAt: expiresAt, APIKeyQuota: 10,
	}
	first, err := svc.ProvisionSeat(trustedPoolTestContext(), input)
	require.NoError(t, err)
	require.NotEmpty(t, first.Credential)
	_, err = svc.ProvisionSeat(trustedPoolTestContext(), input)
	require.NoError(t, err)
	require.Len(t, repo.provisionInputs, 2)
	require.Equal(t, repo.provisionInputs[0].RequestHash, repo.provisionInputs[1].RequestHash)
	require.Equal(t, "pool-1", repo.provisionInputs[0].ExternalPoolID)
	require.Equal(t, int64(1), repo.provisionInputs[0].AssignmentEpoch)
	require.Contains(t, repo.provisionInputs[0].PrincipalEmail, "@principal.invalid")
	require.Len(t, first.CredentialFingerprint, 64)
}

func TestTrustedPoolProvisionRejectsInvalidLimitsBeforeRepository(t *testing.T) {
	repo := &trustedPoolRepoStub{}
	svc := NewTrustedPoolIntegrationService(repo, nil, nil, nil)
	_, err := svc.ProvisionSeat(trustedPoolTestContext(), ProvisionTrustedPoolSeatInput{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", ExistingGroupID: 9,
		OperationID: "provision-1", ActorClientID: "platform-1", PrincipalConcurrency: 1,
		SubscriptionExpiresAt: time.Now().Add(time.Hour), APIKeyQuota: -1,
	})
	require.Error(t, err)
	require.Empty(t, repo.provisionInputs)
}

func TestTrustedPoolCredentialAckValidatesAndNormalizesInput(t *testing.T) {
	repo := &trustedPoolRepoStub{}
	svc := NewTrustedPoolIntegrationService(repo, nil, nil, nil)
	claim, err := svc.AckProvisionCredential(trustedPoolTestContext(), " seat-1 ", AckTrustedPoolProvisionCredentialInput{
		ProvisionOperationID: " provision-1 ", ClaimOperationID: " claim-1 ",
		ClaimedBy: " vault-record-1 ", CredentialFingerprint: strings.Repeat("a", 64), ActorClientID: " platform-1 ",
	})
	require.NoError(t, err)
	require.True(t, claim.CredentialClaimed)
	require.Len(t, repo.ackInputs, 1)
	require.Equal(t, "claim-1", repo.ackInputs[0].ClaimOperationID)
	require.Equal(t, "vault-record-1", repo.ackInputs[0].ClaimedBy)
}

func (r *trustedPoolRepoStub) RegisterSeat(_ context.Context, input RegisterTrustedPoolSeatInput) (*TrustedPoolSeat, error) {
	if r.seat == nil {
		r.seat = &TrustedPoolSeat{ExternalSeatID: input.ExternalSeatID, AssignmentEpoch: input.AssignmentEpoch}
	}
	return r.seat, nil
}
func (r *trustedPoolRepoStub) GetSeat(context.Context, string, string) (*TrustedPoolSeat, error) {
	r.getSeatCalls++
	cp := *r.seat
	return &cp, nil
}
func (r *trustedPoolRepoStub) GetSeatByAPIKeyID(context.Context, int64) (*TrustedPoolSeat, error) {
	if r.events != nil {
		*r.events = append(*r.events, "read-gate")
	}
	if len(r.byAPIKeySeats) == 0 {
		return nil, ErrTrustedPoolSeatNotFound
	}
	index := r.byAPIKeyCalls
	if index >= len(r.byAPIKeySeats) {
		index = len(r.byAPIKeySeats) - 1
	}
	r.byAPIKeyCalls++
	if r.byAPIKeySeats[index] == nil {
		return nil, ErrTrustedPoolSeatNotFound
	}
	cp := *r.byAPIKeySeats[index]
	return &cp, nil
}
func (r *trustedPoolRepoStub) TrustedPoolCredentialMatches(context.Context, int64, string) (bool, error) {
	if r.credentialMatchErr != nil {
		return false, r.credentialMatchErr
	}
	if r.credentialMatches != nil {
		return *r.credentialMatches, nil
	}
	return true, nil
}
func (r *trustedPoolRepoStub) GetUsageSnapshot(context.Context, int64) (*TrustedPoolUsageSnapshot, error) {
	if r.usageSnapshot == nil {
		return &TrustedPoolUsageSnapshot{Usage: map[string]float64{}, WindowStarts: map[string]*string{}, CapturedAt: time.Now()}, nil
	}
	return r.usageSnapshot, nil
}
func (r *trustedPoolRepoStub) CreatePendingSettlement(context.Context, int64, string, string, int64) error {
	if r.events != nil {
		*r.events = append(*r.events, "create-pending")
	}
	if r.createErr != nil {
		return r.createErr
	}
	r.pending++
	return nil
}
func (r *trustedPoolRepoStub) CompletePendingSettlement(context.Context, int64, string) error {
	if r.events != nil {
		*r.events = append(*r.events, "complete-pending")
	}
	if r.completeErr != nil {
		return r.completeErr
	}
	if r.pending > 0 {
		r.pending--
	}
	return nil
}
func (r *trustedPoolRepoStub) MarkPendingSettlement(_ context.Context, _ int64, _ string, status, billingID, lastError string) error {
	r.markCalls++
	r.pendingStatus = status
	r.pendingBilling = billingID
	r.pendingError = lastError
	return nil
}
func (r *trustedPoolRepoStub) CountPendingSettlements(context.Context, int64) (int, error) {
	return r.pending, r.countErr
}
func (r *trustedPoolRepoStub) ListPendingSettlements(context.Context, string, string, int) ([]TrustedPoolPendingSettlement, error) {
	return nil, nil
}
func (r *trustedPoolRepoStub) GetPendingSettlement(context.Context, string, string, string) (*TrustedPoolPendingSettlement, error) {
	return nil, ErrTrustedPoolSettlementNotFound
}
func (r *trustedPoolRepoStub) ResolvePendingSettlement(_ context.Context, seatID, settlementID string, input ResolveTrustedPoolSettlementInput) (*TrustedPoolSettlementResolution, error) {
	return &TrustedPoolSettlementResolution{ExternalSeatID: seatID, SettlementID: settlementID, OperationID: input.OperationID,
		AssignmentEpoch: input.ExpectedAssignmentEpoch, RequestID: input.ExpectedRequestID}, nil
}
func (r *trustedPoolRepoStub) SuspendSeat(context.Context, string, string, string) (*TrustedPoolSeat, error) {
	r.seat.State = TrustedPoolSeatStateDraining
	return r.seat, nil
}
func (r *trustedPoolRepoStub) FreezeSeat(context.Context, string, string, string) (*TrustedPoolSeat, error) {
	r.frozen = true
	r.seat.State = TrustedPoolSeatStateFrozen
	return r.seat, nil
}
func (r *trustedPoolRepoStub) RotateSeatCredential(_ context.Context, _, _ string, operationID, credential string, targetEpoch int64) (*TrustedPoolRotationResult, error) {
	r.rotateCalls++
	if credential != "" {
		r.lastCredential = credential
		r.seat.AssignmentEpoch = targetEpoch
		r.seat.LastOperationID = operationID
		r.seat.State = TrustedPoolSeatStateActive
	}
	return &TrustedPoolRotationResult{Seat: r.seat, Credential: r.lastCredential}, nil
}
func (r *trustedPoolRepoStub) PreparePermanentRotation(_ context.Context, input PrepareTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationPrepareResult, error) {
	r.permanentPrepareCalls++
	result := &TrustedPoolPermanentRotationPrepareResult{
		ProtocolVersion: input.ProtocolVersion, OperationID: input.OperationID, RequestHash: input.RequestHash,
		ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID, CeremonyType: input.CeremonyType,
		FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch, ChildSetHash: input.ChildSetHash,
		PreparedSetHash: input.PreparedSetHash, Status: "prepared", CredentialsDisclosed: true,
		PreparedAt: time.Now().UTC(), Seats: make([]TrustedPoolPermanentRotationPreparedSeat, len(input.Seats)),
	}
	for index := range input.Seats {
		result.Seats[index] = TrustedPoolPermanentRotationPreparedSeat{
			TrustedPoolPermanentRotationSeatBinding: input.Seats[index], Credential: input.Credentials[index],
			CredentialFingerprint: trustedPoolCredentialFingerprintForTest(input.Credentials[index]),
			ActiveAPIKeyVersion:   input.Seats[index].ToAPIKeyVersion, PreparedRotationRef: input.PreparedRotationRefs[index],
			State: "ROTATION_PREPARED", CredentialRotationComplete: true, CompletedAt: result.PreparedAt,
		}
	}
	return result, nil
}
func (r *trustedPoolRepoStub) ActivatePermanentRotation(context.Context, ActivateTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationActivationResult, error) {
	return nil, errors.New("unexpected activation")
}
func (r *trustedPoolRepoStub) TryReplayPermanentRotationCommit(context.Context, CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, bool, error) {
	r.permanentReplayCalls++
	return r.permanentCommitReplay, r.permanentCommitFound, r.permanentCommitErr
}
func (r *trustedPoolRepoStub) CommitPermanentRotation(context.Context, CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, error) {
	return nil, errors.New("unexpected commit")
}

type trustedPoolPermanentFlowRepoStub struct {
	*trustedPoolRepoStub
	activationInput ActivateTrustedPoolPermanentRotationInput
	commitInput     CommitTrustedPoolPermanentRotationInput
	commitCalls     int
}

func (r *trustedPoolPermanentFlowRepoStub) ActivatePermanentRotation(_ context.Context, input ActivateTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationActivationResult, error) {
	r.activationInput = input
	return &TrustedPoolPermanentRotationActivationResult{
		ProtocolVersion: input.ProtocolVersion, OperationID: input.OperationID, RequestHash: input.RequestHash,
		PrepareOperationID: input.PrepareOperationID, ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID,
		CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch,
		PreparedSetHash: input.PreparedSetHash, Status: "activated_pending_commit",
		OldCredentialSetInvalidated: true, CredentialFingerprintGateEnforced: true, ObservedAt: time.Now().UTC(),
	}, nil
}

func (r *trustedPoolPermanentFlowRepoStub) CommitPermanentRotation(_ context.Context, input CommitTrustedPoolPermanentRotationInput) (*TrustedPoolPermanentRotationCommitResult, error) {
	r.commitCalls++
	r.commitInput = input
	return &TrustedPoolPermanentRotationCommitResult{
		ProtocolVersion: input.ProtocolVersion, OperationID: input.OperationID, RequestHash: input.RequestHash,
		PrepareOperationID: input.PrepareOperationID, ActivationOperationID: input.ActivationOperationID,
		ActivationRequestHash: input.ActivationRequestHash, ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID,
		CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch,
		PreparedSetHash: input.PreparedSetHash, Status: "committed", AllCredentialsEnabled: true,
		AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true,
		CredentialFingerprintGateEnforced: true, ObservedAt: time.Now().UTC(),
	}, nil
}

func trustedPoolCredentialFingerprintForTest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
func (r *trustedPoolRepoStub) GetUsageRisk(context.Context, string, string, time.Time) (*TrustedPoolUsageRisk, error) {
	return r.risk, nil
}

func TestTrustedPoolFreezeRequiresStrictZeroConcurrency(t *testing.T) {
	previousHeartbeat := trustedPoolLeaseHeartbeatInterval
	trustedPoolLeaseHeartbeatInterval = time.Millisecond
	defer func() { trustedPoolLeaseHeartbeatInterval = previousHeartbeat }()
	repo := &trustedPoolRepoStub{seat: &TrustedPoolSeat{ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateDraining}}
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrency: map[int64]int{9: 1}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	_, err := svc.Freeze(trustedPoolTestContext(), "seat-1", "op-freeze")
	require.ErrorIs(t, err, ErrTrustedPoolNotDrained)
	require.False(t, repo.frozen)

	cache.apiKeyConcurrency[9] = 0
	seat, err := svc.Freeze(trustedPoolTestContext(), "seat-1", "op-freeze")
	require.NoError(t, err)
	require.Equal(t, TrustedPoolSeatStateFrozen, seat.State)
}

func TestTrustedPoolDrainFailsClosedWhenConcurrencyUnknown(t *testing.T) {
	repo := &trustedPoolRepoStub{seat: &TrustedPoolSeat{ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateDraining}}
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrencyErr: errors.New("redis down")}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	_, err := svc.DrainStatus(trustedPoolTestContext(), "seat-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot verify trusted pool drain state")
}

func TestTrustedPoolDrainFailsClosedWhenPendingCountUnknown(t *testing.T) {
	repo := &trustedPoolRepoStub{
		seat:     &TrustedPoolSeat{ID: 1, ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateDraining},
		countErr: errors.New("db down"),
	}
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrency: map[int64]int{9: 0}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	_, err := svc.DrainStatus(trustedPoolTestContext(), "seat-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot verify trusted pool settlements")
}

func TestTrustedPoolFreezeFailsClosedWhenSecondDrainCheckFails(t *testing.T) {
	previousHeartbeat := trustedPoolLeaseHeartbeatInterval
	trustedPoolLeaseHeartbeatInterval = time.Millisecond
	defer func() { trustedPoolLeaseHeartbeatInterval = previousHeartbeat }()

	repo := &trustedPoolRepoStub{seat: &TrustedPoolSeat{ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateDraining}}
	calls := 0
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrencyFn: func([]int64) (map[int64]int, error) {
		calls++
		if calls == 1 {
			return map[int64]int{9: 0}, nil
		}
		return nil, errors.New("redis interrupted")
	}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	_, err := svc.Freeze(trustedPoolTestContext(), "seat-1", "op-freeze")
	require.Error(t, err)
	require.False(t, repo.frozen)
}

func TestTrustedPoolFreezeBlockedByPendingSettlement(t *testing.T) {
	repo := &trustedPoolRepoStub{
		seat:    &TrustedPoolSeat{ID: 1, ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateDraining},
		pending: 1,
	}
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrency: map[int64]int{9: 0}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	seat, err := svc.DrainStatus(trustedPoolTestContext(), "seat-1")
	require.NoError(t, err)
	require.Equal(t, 1, seat.PendingSettlements)
	_, err = svc.Freeze(trustedPoolTestContext(), "seat-1", "op-freeze")
	require.ErrorIs(t, err, ErrTrustedPoolNotDrained)
	require.False(t, repo.frozen)
}

func TestTrustedPoolRotateIsIdempotentByOperationAndEpoch(t *testing.T) {
	repo := &trustedPoolRepoStub{seat: &TrustedPoolSeat{ExternalSeatID: "seat-1", APIKeyID: 9, State: TrustedPoolSeatStateFrozen, AssignmentEpoch: 3}}
	cache := &stubConcurrencyCacheForTest{apiKeyConcurrency: map[int64]int{9: 0}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	first, err := svc.Rotate(trustedPoolTestContext(), "seat-1", "op-4", 4)
	require.NoError(t, err)
	require.NotEmpty(t, first.Credential)
	second, err := svc.Rotate(trustedPoolTestContext(), "seat-1", "op-4", 4)
	require.NoError(t, err)
	require.Equal(t, first.Credential, second.Credential)
	require.Equal(t, 2, repo.rotateCalls) // 第二次只读取当前 credential，不产生新值。
	require.True(t, second.AccessCredentialRotated)
}

func TestTrustedPoolGatewayAdmissionTracksBeforeReadingLatestGate(t *testing.T) {
	events := []string{}
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}, events: &events}
	cache := &stubConcurrencyCacheForTest{
		apiKeyTrackHook:   func() { events = append(events, "track") },
		apiKeyReleaseHook: func() { events = append(events, "release") },
	}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())
	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.NoError(t, err)
	require.True(t, guarded)
	require.Equal(t, []string{"read-gate", "track", "read-gate", "create-pending"}, events)
	MarkTrustedPoolSettlementSucceeded(ctx)
	release()
	require.Equal(t, 0, repo.pending)
	require.Equal(t, "release", events[len(events)-1])
}

func TestTrustedPoolGatewayAdmissionRetainsFailedSettlement(t *testing.T) {
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive, AssignmentEpoch: 2}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)
	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.NoError(t, err)
	require.True(t, guarded)
	require.Equal(t, 1, repo.pending)
	MarkTrustedPoolSettlementFailure(ctx, errors.New("billing failed"))
	release()
	require.Equal(t, 1, repo.pending, "计费失败后必须保留 pending barrier")
	require.Equal(t, "failed", repo.pendingStatus)
}

func TestTrustedPoolGatewayAdmissionRetainsUnresolvedSettlement(t *testing.T) {
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive, AssignmentEpoch: 2}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)
	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.NoError(t, err)
	require.True(t, guarded)
	release()
	require.Equal(t, 1, repo.pending, "未调度 RecordUsage 的早退必须保留 pending barrier")
	require.Equal(t, "pending", repo.pendingStatus)
}

func TestTrustedPoolGatewayAdmissionRetainsPendingWhenCompletionFails(t *testing.T) {
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive, AssignmentEpoch: 2}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}, completeErr: errors.New("db down")}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)
	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.NoError(t, err)
	require.True(t, guarded)
	SetTrustedPoolSettlementBillingID(ctx, "billing-1")
	MarkTrustedPoolSettlementSucceeded(ctx)
	release()
	require.Equal(t, 1, repo.pending, "完成删除失败时必须保留 pending barrier")
	require.Equal(t, 1, repo.markCalls)
	require.Equal(t, "failed", repo.pendingStatus)
	require.Equal(t, "billing-1", repo.pendingBilling)
	require.Equal(t, "pending settlement completion failed", repo.pendingError)
}

func TestTrustedPoolGatewayAdmissionFailsClosedWhenPendingCreateFails(t *testing.T) {
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive, AssignmentEpoch: 2}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}, createErr: errors.New("db down")}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)
	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.Error(t, err)
	require.True(t, guarded)
	require.Nil(t, release)
	require.Len(t, cache.releasedAPIKeyIDs, 1, "pending 创建失败后必须释放已登记的严格租约")
}

func TestOpenAIRecordUsageErrorMarksTrustedPoolSettlementFailed(t *testing.T) {
	ctx, tracker := WithTrustedPoolSettlementTracker(context.Background())
	svc := &OpenAIGatewayService{}

	err := svc.RecordUsage(ctx, nil)
	require.Error(t, err)
	require.True(t, tracker.Failed(), "RecordUsage 返回错误必须标记 settlement 失败")
}

func TestTrustedPoolGatewayAdmissionBlocksGateChangedAfterTrack(t *testing.T) {
	events := []string{}
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive}
	draining := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateDraining}
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, draining}, events: &events}
	cache := &stubConcurrencyCacheForTest{
		apiKeyTrackHook:   func() { events = append(events, "track") },
		apiKeyReleaseHook: func() { events = append(events, "release") },
	}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())
	_, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, strings.Repeat("a", 64))
	require.ErrorIs(t, err, ErrTrustedPoolSeatSuspended)
	require.True(t, guarded)
	require.Equal(t, []string{"read-gate", "track", "read-gate", "release"}, events)
}

func TestTrustedPoolGatewayAdmissionRejectsStaleCachedCredentialAfterActivation(t *testing.T) {
	active := &TrustedPoolSeat{ID: 1, APIKeyID: 9, State: TrustedPoolSeatStateActive, AssignmentEpoch: 4}
	matches := false
	repo := &trustedPoolRepoStub{byAPIKeySeats: []*TrustedPoolSeat{active, active}, credentialMatches: &matches}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)
	ctx, _ := WithTrustedPoolSettlementTracker(context.Background())

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9, hex.EncodeToString(sha256.New().Sum(nil)))
	require.ErrorIs(t, err, ErrTrustedPoolSeatSuspended)
	require.True(t, guarded)
	require.Nil(t, release)
	require.Len(t, cache.releasedAPIKeyIDs, 1, "旧 credential 正缓存必须在 DB 指纹 gate 处释放租约并拒绝")
	require.Zero(t, repo.pending)
}

func TestTrustedPoolGatewayAdmissionPassesNonSeatWithoutLease(t *testing.T) {
	repo := &trustedPoolRepoStub{}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	release, guarded, err := svc.AcquireGatewayAdmission(context.Background(), 9, strings.Repeat("a", 64))
	require.NoError(t, err)
	require.False(t, guarded)
	require.Nil(t, release)
	require.Empty(t, cache.trackedAPIKeyIDs)
}

type trustedPoolAuthRepoStub struct {
	client *TrustedPoolIntegrationClient
	nonces map[string]bool
}

type trustedPoolAuthTestEncryptor struct{}

func (trustedPoolAuthTestEncryptor) Encrypt(value string) (string, error) {
	return "encrypted:" + value, nil
}
func (trustedPoolAuthTestEncryptor) Decrypt(value string) (string, error) {
	plain, ok := strings.CutPrefix(value, "encrypted:")
	if !ok {
		return "", errors.New("invalid ciphertext")
	}
	return plain, nil
}

func (r *trustedPoolAuthRepoStub) GetIntegrationClient(context.Context, string) (*TrustedPoolIntegrationClient, error) {
	return r.client, nil
}
func (r *trustedPoolAuthRepoStub) ClaimIntegrationNonce(_ context.Context, _, nonce string, _ time.Time) (bool, error) {
	if r.nonces[nonce] {
		return false, nil
	}
	r.nonces[nonce] = true
	return true, nil
}

func TestTrustedPoolAuthBearerScopeAndHMACReplay(t *testing.T) {
	bearerSecret := "bearer-secret-value"
	hmacSecret := "hmac-secret-value"
	hash := sha256.Sum256([]byte(bearerSecret))
	repo := &trustedPoolAuthRepoStub{client: &TrustedPoolIntegrationClient{
		ClientID: "platform", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(hash[:]),
		HMACSecretEncrypted: "encrypted:" + hmacSecret, Scopes: []string{"seat:write"},
	}, nonces: map[string]bool{}}
	svc := NewTrustedPoolAuthService(repo, trustedPoolAuthTestEncryptor{})
	fixedNow := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return fixedNow }

	principal, err := svc.AuthenticateBearer(context.Background(), "platform", bearerSecret, "seat:write")
	require.NoError(t, err)
	require.Equal(t, "pool-1", principal.ExternalPoolID)
	_, err = svc.AuthenticateBearer(context.Background(), "platform", bearerSecret, "seat:read")
	require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	_, err = svc.AuthenticateBearer(context.Background(), "platform", "invalid-secret", "seat:read")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)
	_, err = svc.AuthenticateBearer(context.Background(), "platform", hmacSecret, "seat:write")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)

	timestamp := fixedNow.Format(time.RFC3339)
	canonical := "POST\n/path\n" + timestamp + "\nnonce-1\nbodyhash"
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	_, _ = mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-1", signature, canonical, "seat:write")
	require.NoError(t, err)
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-1", signature, canonical, "seat:write")
	require.ErrorIs(t, err, ErrTrustedPoolReplay)

	// The Bearer secret belongs to a separate credential domain and cannot sign.
	bearerMAC := hmac.New(sha256.New, []byte(bearerSecret))
	_, _ = bearerMAC.Write([]byte(canonical))
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-2",
		hex.EncodeToString(bearerMAC.Sum(nil)), canonical, "seat:write")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)

	// A DB reader sees secret_hash, but that verifier is not sufficient to
	// forge a request because HMAC uses independently encrypted raw material.
	verifierMAC := hmac.New(sha256.New, hash[:])
	_, _ = verifierMAC.Write([]byte(canonical))
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-3",
		hex.EncodeToString(verifierMAC.Sum(nil)), canonical, "seat:write")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)

	missingScopeCanonical := "GET\n/path\n" + timestamp + "\nnonce-4\nbodyhash"
	missingScopeMAC := hmac.New(sha256.New, []byte(hmacSecret))
	_, _ = missingScopeMAC.Write([]byte(missingScopeCanonical))
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-4",
		hex.EncodeToString(missingScopeMAC.Sum(nil)), missingScopeCanonical, "seat:read")
	require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	_, err = svc.AuthenticateHMAC(context.Background(), "platform", timestamp, "nonce-5",
		strings.Repeat("0", sha256.Size*2), missingScopeCanonical, "seat:read")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)
}

func TestTrustedPoolSettlementResolveRequiresDedicatedScope(t *testing.T) {
	secret := "settlement-secret"
	digest := sha256.Sum256([]byte(secret))
	repo := &trustedPoolAuthRepoStub{
		client: &TrustedPoolIntegrationClient{ClientID: "platform", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(digest[:]), Scopes: []string{"seat:write"}},
		nonces: map[string]bool{},
	}
	auth := NewTrustedPoolAuthService(repo, nil)

	_, err := auth.AuthenticateBearer(context.Background(), "platform", secret, "settlement:resolve")
	require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	repo.client.Scopes = []string{"*"}
	_, err = auth.AuthenticateBearer(context.Background(), "platform", secret, "settlement:resolve")
	require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	repo.client.Scopes = []string{"seat:read", "settlement:resolve"}
	_, err = auth.AuthenticateBearer(context.Background(), "platform", secret, "settlement:resolve")
	require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	repo.client.Scopes = []string{"settlement:resolve"}
	_, err = auth.AuthenticateBearer(context.Background(), "platform", secret, "settlement:resolve")
	require.NoError(t, err)
}

func TestTrustedPoolPermanentRotationRequiresExactSingletonScope(t *testing.T) {
	secret := "permanent-rotation-secret"
	digest := sha256.Sum256([]byte(secret))
	repo := &trustedPoolAuthRepoStub{client: &TrustedPoolIntegrationClient{
		ClientID: "recovery", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(digest[:]),
	}, nonces: map[string]bool{}}
	auth := NewTrustedPoolAuthService(repo, nil)
	for _, scopes := range [][]string{{"seat:write"}, {"*"}, {"seat:read", "seat:permanent-rotate"}} {
		repo.client.Scopes = scopes
		_, err := auth.AuthenticateBearer(context.Background(), "recovery", secret, "seat:permanent-rotate")
		require.ErrorIs(t, err, ErrTrustedPoolForbidden)
	}
	repo.client.Scopes = []string{"seat:permanent-rotate"}
	_, err := auth.AuthenticateBearer(context.Background(), "recovery", secret, "seat:permanent-rotate")
	require.NoError(t, err)
}

func TestTrustedPoolAuthRejectsRepositoryIdentityMismatch(t *testing.T) {
	secret := "bearer-secret"
	digest := sha256.Sum256([]byte(secret))
	repo := &trustedPoolAuthRepoStub{
		client: &TrustedPoolIntegrationClient{
			ClientID: "different-client", ExternalPoolID: "pool-1",
			SecretHash: hex.EncodeToString(digest[:]), Scopes: []string{"seat:read"},
		},
		nonces: map[string]bool{},
	}
	auth := NewTrustedPoolAuthService(repo, nil)

	_, err := auth.AuthenticateBearer(context.Background(), "requested-client", secret, "seat:read")
	require.ErrorIs(t, err, ErrTrustedPoolUnauthorized)
}

func TestTrustedPoolPermanentRotationHashFixedVectors(t *testing.T) {
	prepare := PrepareTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1,
		OperationID:     "prepare-pool-op", PlanID: "plan-1", CeremonyType: "ROTATE", ExternalPoolID: "pool-1",
		FromEpoch: 7, ToEpoch: 8,
		Seats: []TrustedPoolPermanentRotationSeatBinding{
			{ExternalSeatID: "seat-a", TargetMemberID: "member-new", ExpectedAssignmentEpoch: 3,
				PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303, FromAPIKeyVersion: 3, ToAPIKeyVersion: 4, ChildOperationID: "child-op-a"},
			{ExternalSeatID: "seat-b", TargetMemberID: "member-b", ExpectedAssignmentEpoch: 3,
				PrincipalUserID: 102, SubscriptionID: 203, APIKeyID: 304, FromAPIKeyVersion: 3, ToAPIKeyVersion: 4, ChildOperationID: "child-op-b"},
		},
	}
	prepare.Seats[0].ChildRequestHash = trustedPoolPermanentChildRequestHash(prepare, prepare.Seats[0])
	prepare.Seats[1].ChildRequestHash = trustedPoolPermanentChildRequestHash(prepare, prepare.Seats[1])
	require.Equal(t, "40687cdc14f04f77276b2ea9dbd7f971c1fe4dbc1207583bd0f286deec582012", prepare.Seats[0].ChildRequestHash)
	require.Equal(t, "b3cd30fc1625a77ce4a69546f12ceb0c181f2e2b7728660974652e5341188feb", prepare.Seats[1].ChildRequestHash)
	childSet, err := trustedPoolPermanentChildSetHash(prepare)
	require.NoError(t, err)
	require.Equal(t, "94c426879876dcf4b861be633f203e023eb90670144f8dcd36c5a12ab1e752c9", childSet)
	prepare.ChildSetHash = childSet
	require.Equal(t, "63dc318b24b47335dd8089b3202940cb4c1467b9b4284f6996bd429b822d38e3", trustedPoolPermanentPrepareRequestHash(prepare))

	fingerprintA := sha256.Sum256([]byte("credential-a"))
	fingerprintB := sha256.Sum256([]byte("credential-b"))
	activationSeats := []ActivateTrustedPoolPermanentRotationSeat{
		{ExternalSeatID: "seat-a", TargetMemberID: "member-new", ExpectedAssignmentEpoch: 3, PrincipalUserID: 101, SubscriptionID: 202,
			APIKeyID: 303, ActiveAPIKeyVersion: 4, CredentialFingerprint: hex.EncodeToString(fingerprintA[:]), PreparedRotationRef: "prepared-a",
			ChildOperationID: "child-op-a", ChildRequestHash: prepare.Seats[0].ChildRequestHash},
		{ExternalSeatID: "seat-b", TargetMemberID: "member-b", ExpectedAssignmentEpoch: 3, PrincipalUserID: 102, SubscriptionID: 203,
			APIKeyID: 304, ActiveAPIKeyVersion: 4, CredentialFingerprint: hex.EncodeToString(fingerprintB[:]), PreparedRotationRef: "prepared-b",
			ChildOperationID: "child-op-b", ChildRequestHash: prepare.Seats[1].ChildRequestHash},
	}
	preparedSet, err := trustedPoolPermanentPreparedSetHash(activationSeats)
	require.NoError(t, err)
	require.Equal(t, "5db639866d27d07d3187627cb4a62f84bcf8c9f86518aeec2aa1ad4a230ceaf7", preparedSet)
	activate := ActivateTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "activate-pool-op",
		PrepareOperationID: "prepare-pool-op",
		PlanID:             "plan-1", CeremonyType: "ROTATE", ExternalPoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSet, Seats: activationSeats,
	}
	activate.RequestHash = trustedPoolPermanentActivateRequestHash(activate)
	require.Equal(t, "be38cb7aba7eecb97c2bed2faf8fd66cebb9398588981b2a87ff14bb2d877ccc", activate.RequestHash)
	commit := CommitTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "commit-pool-op",
		PrepareOperationID: "prepare-pool-op", ActivationOperationID: "activate-pool-op", ActivationRequestHash: activate.RequestHash,
		PlanID: "plan-1", CeremonyType: "ROTATE", ExternalPoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSet, Seats: activationSeats,
	}
	require.Equal(t, "8af081439638d45ec867ef9a92771cd5d68184e310b17659be18bc51ea19e5e4", trustedPoolPermanentCommitRequestHash(commit))
	mutated := append([]ActivateTrustedPoolPermanentRotationSeat(nil), activationSeats...)
	mutated[0].ExpectedAssignmentEpoch++
	mutated[0].ActiveAPIKeyVersion++
	changed, err := trustedPoolPermanentPreparedSetHash(mutated)
	require.NoError(t, err)
	require.NotEqual(t, preparedSet, changed)
	mutated = append([]ActivateTrustedPoolPermanentRotationSeat(nil), activationSeats...)
	mutated[0].ChildOperationID = "different-child"
	changed, err = trustedPoolPermanentPreparedSetHash(mutated)
	require.NoError(t, err)
	require.NotEqual(t, preparedSet, changed)
	mutated = append([]ActivateTrustedPoolPermanentRotationSeat(nil), activationSeats...)
	mutated[0].ChildRequestHash = strings.Repeat("f", 64)
	changed, err = trustedPoolPermanentPreparedSetHash(mutated)
	require.NoError(t, err)
	require.NotEqual(t, preparedSet, changed)
	activate.PrepareOperationID = "different-prepare"
	require.NotEqual(t, "be38cb7aba7eecb97c2bed2faf8fd66cebb9398588981b2a87ff14bb2d877ccc", trustedPoolPermanentActivateRequestHash(activate))
	baselineCommit := trustedPoolPermanentCommitRequestHash(commit)
	commit.ActivationOperationID = "different-activation"
	require.NotEqual(t, baselineCommit, trustedPoolPermanentCommitRequestHash(commit))
}

func TestTrustedPoolPermanentRotationAttestationUsesIndependentEd25519Key(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	svc := &TrustedPoolIntegrationService{}
	require.Error(t, svc.ConfigurePermanentRotationAttestation("", privateKey))
	require.NoError(t, svc.ConfigurePermanentRotationAttestation("rotation-signing-key-1", privateKey))
	result := &TrustedPoolPermanentRotationActivationResult{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "activate-op",
		RequestHash: strings.Repeat("a", 64), PrepareOperationID: "prepare-op", ExternalPoolID: "pool-1",
		PlanID: "plan-1", CeremonyType: "ROTATE", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: strings.Repeat("b", 64), Status: "activated_pending_commit",
		OldCredentialSetInvalidated:       true,
		CredentialFingerprintGateEnforced: true, ObservedAt: time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC),
	}
	attestation, err := svc.signPermanentActivationResult(result)
	require.NoError(t, err)
	require.Equal(t, "rotation-signing-key-1", attestation.KeyID)
	digest, err := hex.DecodeString(attestation.Digest)
	require.NoError(t, err)
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(publicKey, digest, signature))

	disabled := &TrustedPoolIntegrationService{}
	_, err = disabled.signPermanentActivationResult(result)
	require.Error(t, err)
}

func TestTrustedPoolPermanentPrepareAttestationBindsDisclosureAndEnablementState(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	svc := &TrustedPoolIntegrationService{}
	require.NoError(t, svc.ConfigurePermanentRotationAttestation("rotation-signing-key-1", privateKey))
	result := &TrustedPoolPermanentRotationPrepareResult{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "prepare-op",
		RequestHash: strings.Repeat("a", 64), ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "ROTATE",
		FromEpoch: 7, ToEpoch: 8, ChildSetHash: strings.Repeat("b", 64), PreparedSetHash: strings.Repeat("c", 64),
		Status: "prepared", CredentialsDisclosed: true,
		Seats: []TrustedPoolPermanentRotationPreparedSeat{{
			TrustedPoolPermanentRotationSeatBinding: TrustedPoolPermanentRotationSeatBinding{
				ExternalSeatID: "seat-1", TargetMemberID: "member-2", ExpectedAssignmentEpoch: 3,
				PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303,
				ChildOperationID: "child-op", ChildRequestHash: strings.Repeat("d", 64),
			},
			CredentialFingerprint: strings.Repeat("e", 64), ActiveAPIKeyVersion: 4,
			PreparedRotationRef: "prepared-ref", State: "ROTATION_PREPARED",
			CredentialEnabled: false, SubscriptionEnabled: false, CredentialRotationComplete: true,
		}},
	}
	baseline, err := svc.signPermanentPrepareResult(result)
	require.NoError(t, err)

	result.CredentialsDisclosed = false
	mutated, err := svc.signPermanentPrepareResult(result)
	require.NoError(t, err)
	require.NotEqual(t, baseline.Digest, mutated.Digest)
	result.CredentialsDisclosed = true
	result.Seats[0].CredentialEnabled = true
	mutated, err = svc.signPermanentPrepareResult(result)
	require.NoError(t, err)
	require.NotEqual(t, baseline.Digest, mutated.Digest)
	result.Seats[0].CredentialEnabled = false
	result.Seats[0].SubscriptionEnabled = true
	mutated, err = svc.signPermanentPrepareResult(result)
	require.NoError(t, err)
	require.NotEqual(t, baseline.Digest, mutated.Digest)
	result.Seats[0].SubscriptionEnabled = false
	result.Seats[0].CredentialRotationComplete = false
	mutated, err = svc.signPermanentPrepareResult(result)
	require.NoError(t, err)
	require.NotEqual(t, baseline.Digest, mutated.Digest)
}

func TestTrustedPoolPermanentRotationFailsClosedWithoutSigningKey(t *testing.T) {
	svc := &TrustedPoolIntegrationService{}
	_, err := svc.PreparePermanentRotation(trustedPoolTestContext(), PrepareTrustedPoolPermanentRotationInput{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation signer is unavailable")
	_, err = svc.ActivatePermanentRotation(trustedPoolTestContext(), ActivateTrustedPoolPermanentRotationInput{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation signer is unavailable")
	_, err = svc.CommitPermanentRotation(trustedPoolTestContext(), CommitTrustedPoolPermanentRotationInput{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation signer is unavailable")
}

func TestTrustedPoolPermanentActivationHoldsUntilSignedCommit(t *testing.T) {
	base := &trustedPoolRepoStub{seat: &TrustedPoolSeat{
		ID: 1, ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: TrustedPoolSeatStateRotationPrepared,
		AssignmentEpoch: 3, PrincipalUserID: 101, GroupID: 11, SubscriptionID: 202, APIKeyID: 303,
	}}
	repo := &trustedPoolPermanentFlowRepoStub{trustedPoolRepoStub: base}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(&stubConcurrencyCacheForTest{}), nil, nil)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, svc.ConfigurePermanentRotationAttestation("test-signing-key", privateKey))
	fingerprint := strings.Repeat("a", 64)
	childHash := strings.Repeat("b", 64)
	seats := []ActivateTrustedPoolPermanentRotationSeat{{
		ExternalSeatID: "seat-1", TargetMemberID: "member-2", ExpectedAssignmentEpoch: 3,
		PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303, ActiveAPIKeyVersion: 4,
		ChildOperationID: "child-op", ChildRequestHash: childHash, CredentialFingerprint: fingerprint,
		PreparedRotationRef: "prepared-ref",
	}}
	preparedSetHash, err := trustedPoolPermanentPreparedSetHash(seats)
	require.NoError(t, err)
	activate := ActivateTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "activate-op", PrepareOperationID: "prepare-op",
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "ROTATE", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSetHash, Seats: seats,
	}
	activate.RequestHash = trustedPoolPermanentActivateRequestHash(activate)
	activated, err := svc.ActivatePermanentRotation(trustedPoolTestContext(), activate)
	require.NoError(t, err)
	require.Equal(t, "activated_pending_commit", activated.Status)
	require.False(t, activated.AllCredentialsEnabled)
	require.False(t, activated.AllSubscriptionsEnabled)
	require.True(t, repo.activationInput.ConcurrencyVerified)
	require.NotNil(t, activated.Attestation)

	base.seat.State = TrustedPoolSeatStateRotationPendingCommit
	base.seat.AssignmentEpoch = 4
	commit := CommitTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "commit-op", PrepareOperationID: "prepare-op",
		ActivationOperationID: "activate-op", ActivationRequestHash: activate.RequestHash,
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "ROTATE", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSetHash, Seats: seats,
	}
	commit.RequestHash = trustedPoolPermanentCommitRequestHash(commit)
	committed, err := svc.CommitPermanentRotation(trustedPoolTestContext(), commit)
	require.NoError(t, err)
	require.Equal(t, "committed", committed.Status)
	require.True(t, committed.AllCredentialsEnabled)
	require.True(t, committed.AllSubscriptionsEnabled)
	require.True(t, repo.commitInput.ConcurrencyVerified)
	require.NotNil(t, committed.Attestation)
	replayCallsBefore := base.permanentReplayCalls
	getSeatCallsBefore := base.getSeatCalls
	commitCallsBefore := repo.commitCalls
	initialObservedAt := committed.ObservedAt
	initialDigest := committed.Attestation.Digest
	initialSignature := committed.Attestation.Signature

	// durable commit 成功但响应丢失后，即使 Seat 已进入 retiring，也必须先重放原始回执。
	base.permanentCommitReplay = committed
	base.permanentCommitFound = true
	base.seat.State = TrustedPoolSeatStateFrozen
	replayed, err := svc.CommitPermanentRotation(trustedPoolTestContext(), commit)
	require.NoError(t, err)
	require.Equal(t, committed.OperationID, replayed.OperationID)
	require.Equal(t, committed.RequestHash, replayed.RequestHash)
	require.Equal(t, initialObservedAt, replayed.ObservedAt)
	require.Equal(t, initialDigest, replayed.Attestation.Digest)
	require.Equal(t, initialSignature, replayed.Attestation.Signature)
	require.Equal(t, replayCallsBefore+1, base.permanentReplayCalls)
	require.Equal(t, getSeatCallsBefore, base.getSeatCalls)
	require.Equal(t, commitCallsBefore, repo.commitCalls)
}

func TestTrustedPoolPermanentCommitReplayErrorPrecedesLiveGate(t *testing.T) {
	base := &trustedPoolRepoStub{
		seat:               &TrustedPoolSeat{ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: TrustedPoolSeatStateRotationPendingCommit},
		permanentCommitErr: ErrTrustedPoolPermanentCommitReceiptUnavailable,
	}
	repo := &trustedPoolPermanentFlowRepoStub{trustedPoolRepoStub: base}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(&stubConcurrencyCacheForTest{}), nil, nil)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, svc.ConfigurePermanentRotationAttestation("test-signing-key", privateKey))
	seats := []ActivateTrustedPoolPermanentRotationSeat{{
		ExternalSeatID: "seat-1", TargetMemberID: "member-2", ExpectedAssignmentEpoch: 3,
		PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303, ActiveAPIKeyVersion: 4,
		ChildOperationID: "child-op", ChildRequestHash: strings.Repeat("b", 64),
		CredentialFingerprint: strings.Repeat("a", 64), PreparedRotationRef: "prepared-ref",
	}}
	preparedSetHash, err := trustedPoolPermanentPreparedSetHash(seats)
	require.NoError(t, err)
	input := CommitTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "commit-op", PrepareOperationID: "prepare-op",
		ActivationOperationID: "activate-op", ActivationRequestHash: strings.Repeat("c", 64),
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "ROTATE", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSetHash, Seats: seats,
	}
	input.RequestHash = trustedPoolPermanentCommitRequestHash(input)

	_, err = svc.CommitPermanentRotation(trustedPoolTestContext(), input)
	require.ErrorIs(t, err, ErrTrustedPoolPermanentCommitReceiptUnavailable)
	require.Equal(t, 1, base.permanentReplayCalls)
	require.Zero(t, base.getSeatCalls)
	require.Zero(t, repo.commitCalls)
}

func TestTrustedPoolPermanentPrepareExactReplayAcceptsRotationPreparedSeat(t *testing.T) {
	repo := &trustedPoolRepoStub{seat: &TrustedPoolSeat{
		ID: 1, ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", State: TrustedPoolSeatStateRotationPrepared,
		AssignmentEpoch: 3, PrincipalUserID: 101, GroupID: 11, SubscriptionID: 202, APIKeyID: 303,
	}}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(&stubConcurrencyCacheForTest{}), nil, nil)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, svc.ConfigurePermanentRotationAttestation("test-signing-key", privateKey))
	input := PrepareTrustedPoolPermanentRotationInput{
		ProtocolVersion: TrustedPoolPermanentRotationProtocolV1, OperationID: "prepare-op", PlanID: "plan-1",
		CeremonyType: "ROTATE", ExternalPoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		Seats: []TrustedPoolPermanentRotationSeatBinding{{
			ExternalSeatID: "seat-1", TargetMemberID: "member-2", ExpectedAssignmentEpoch: 3,
			PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303,
			FromAPIKeyVersion: 3, ToAPIKeyVersion: 4, ChildOperationID: "child-op",
		}},
	}
	input.Seats[0].ChildRequestHash = trustedPoolPermanentChildRequestHash(input, input.Seats[0])
	input.ChildSetHash, err = trustedPoolPermanentChildSetHash(input)
	require.NoError(t, err)
	input.RequestHash = trustedPoolPermanentPrepareRequestHash(input)
	result, err := svc.PreparePermanentRotation(trustedPoolTestContext(), input)
	require.NoError(t, err)
	require.Equal(t, 1, repo.permanentPrepareCalls)
	require.True(t, result.CredentialsDisclosed)
	require.NotEmpty(t, result.Seats[0].Credential)
	require.NotNil(t, result.Attestation)
}
