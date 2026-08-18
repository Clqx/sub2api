//go:build unit

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type trustedPoolRepoStub struct {
	seat            *TrustedPoolSeat
	risk            *TrustedPoolUsageRisk
	frozen          bool
	rotateCalls     int
	lastCredential  string
	byAPIKeySeats   []*TrustedPoolSeat
	byAPIKeyCalls   int
	usageSnapshot   *TrustedPoolUsageSnapshot
	events          *[]string
	pending         int
	pendingStatus   string
	pendingBilling  string
	pendingError    string
	markCalls       int
	createErr       error
	completeErr     error
	countErr        error
	provisionInputs []ProvisionTrustedPoolSeatInput
	ackInputs       []AckTrustedPoolProvisionCredentialInput
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
	return &TrustedPoolSettlementResolution{ExternalSeatID: seatID, SettlementID: settlementID, OperationID: input.OperationID}, nil
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
	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
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

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
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

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
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

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
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

	release, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
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
	_, guarded, err := svc.AcquireGatewayAdmission(ctx, 9)
	require.ErrorIs(t, err, ErrTrustedPoolSeatSuspended)
	require.True(t, guarded)
	require.Equal(t, []string{"read-gate", "track", "read-gate", "release"}, events)
}

func TestTrustedPoolGatewayAdmissionPassesNonSeatWithoutLease(t *testing.T) {
	repo := &trustedPoolRepoStub{}
	cache := &stubConcurrencyCacheForTest{}
	svc := NewTrustedPoolIntegrationService(repo, NewConcurrencyService(cache), nil, nil)

	release, guarded, err := svc.AcquireGatewayAdmission(context.Background(), 9)
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
	repo.client.Scopes = append(repo.client.Scopes, "settlement:resolve")
	_, err = auth.AuthenticateBearer(context.Background(), "platform", secret, "settlement:resolve")
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
