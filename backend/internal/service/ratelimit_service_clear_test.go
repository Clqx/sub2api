//go:build unit

package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type rateLimitClearRepoStub struct {
	mockAccountRepoForGemini
	getByIDAccount            *Account
	getByIDErr                error
	getByIDCalls              int
	clearErrorCalls           int
	clearRateLimitCalls       int
	clearAntigravityCalls     int
	clearModelRateLimitCalls  int
	clearTempUnschedCalls     int
	clearErrorErr             error
	clearRateLimitErr         error
	clearAntigravityErr       error
	clearModelRateLimitErr    error
	clearTempUnschedulableErr error
	conditionalConflict       bool
	conditionalTempErr        error
}

func (r *rateLimitClearRepoStub) conditionalMatches(precondition AccountStatePrecondition) bool {
	return !r.conditionalConflict && accountMatchesStatePrecondition(r.getByIDAccount, precondition) == nil
}

func (r *rateLimitClearRepoStub) ClearErrorIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if !r.conditionalMatches(precondition) {
		return false, nil
	}
	return true, r.ClearError(ctx, id)
}

func (r *rateLimitClearRepoStub) ClearAccountRateLimitIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if !r.conditionalMatches(precondition) {
		return false, nil
	}
	r.clearRateLimitCalls++
	if r.clearRateLimitErr != nil {
		return false, r.clearRateLimitErr
	}
	r.getByIDAccount.RateLimitedAt = nil
	r.getByIDAccount.RateLimitResetAt = nil
	r.getByIDAccount.OverloadUntil = nil
	return true, nil
}

func (r *rateLimitClearRepoStub) RecoverAccountStateIf(ctx context.Context, id int64, clearError, clearRateLimit bool, precondition AccountStatePrecondition) (bool, error) {
	if !r.conditionalMatches(precondition) {
		return false, nil
	}
	if clearError {
		r.clearErrorCalls++
		r.getByIDAccount.Status = StatusActive
		r.getByIDAccount.ErrorMessage = ""
	}
	if clearRateLimit {
		r.clearRateLimitCalls++
		r.getByIDAccount.RateLimitedAt = nil
		r.getByIDAccount.RateLimitResetAt = nil
		r.getByIDAccount.OverloadUntil = nil
	}
	return true, nil
}

func (r *rateLimitClearRepoStub) SetSchedulableIf(ctx context.Context, id int64, schedulable bool, precondition AccountStatePrecondition) (bool, error) {
	if !r.conditionalMatches(precondition) {
		return false, nil
	}
	r.getByIDAccount.Schedulable = schedulable
	return true, nil
}

func (r *rateLimitClearRepoStub) ClearTempUnschedulableIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if r.conditionalTempErr != nil {
		return false, r.conditionalTempErr
	}
	if !r.conditionalMatches(precondition) {
		return false, nil
	}
	r.clearTempUnschedCalls++
	r.getByIDAccount.TempUnschedulableUntil = nil
	r.getByIDAccount.TempUnschedulableReason = ""
	return true, nil
}

func (r *rateLimitClearRepoStub) GetByID(ctx context.Context, id int64) (*Account, error) {
	r.getByIDCalls++
	if r.getByIDErr != nil {
		return nil, r.getByIDErr
	}
	return r.getByIDAccount, nil
}

func (r *rateLimitClearRepoStub) ClearError(ctx context.Context, id int64) error {
	r.clearErrorCalls++
	return r.clearErrorErr
}

func (r *rateLimitClearRepoStub) ClearRateLimit(ctx context.Context, id int64) error {
	r.clearRateLimitCalls++
	return r.clearRateLimitErr
}

func (r *rateLimitClearRepoStub) ClearAntigravityQuotaScopes(ctx context.Context, id int64) error {
	r.clearAntigravityCalls++
	return r.clearAntigravityErr
}

func (r *rateLimitClearRepoStub) ClearModelRateLimits(ctx context.Context, id int64) error {
	r.clearModelRateLimitCalls++
	return r.clearModelRateLimitErr
}

func (r *rateLimitClearRepoStub) ClearTempUnschedulable(ctx context.Context, id int64) error {
	r.clearTempUnschedCalls++
	return r.clearTempUnschedulableErr
}

type tempUnschedCacheRecorder struct {
	deletedIDs              []int64
	deleteErr               error
	state                   *TempUnschedState
	conditionalDeleteErr    error
	replacementBeforeDelete *TempUnschedState
	conditionalDeleteCalls  int
	setCalls                int
}

type recoverTokenInvalidatorStub struct {
	accounts []*Account
	err      error
}

type nonConditionalRateRepoStub struct {
	mockAccountRepoForGemini
	account             *Account
	clearRateLimitCalls int
}

func (r *nonConditionalRateRepoStub) GetByID(context.Context, int64) (*Account, error) {
	return r.account, nil
}

func (r *nonConditionalRateRepoStub) ClearRateLimit(context.Context, int64) error {
	r.clearRateLimitCalls++
	return nil
}

func (c *tempUnschedCacheRecorder) SetTempUnsched(ctx context.Context, accountID int64, state *TempUnschedState) error {
	c.setCalls++
	copy := *state
	c.state = &copy
	return nil
}

type interleavingTempRepo struct {
	*rateLimitClearRepoStub
	mu            sync.Mutex
	getCalls      int
	firstCaptured chan struct{}
	releaseFirst  chan struct{}
}

func (r *interleavingTempRepo) GetByID(ctx context.Context, id int64) (*Account, error) {
	r.mu.Lock()
	r.getCalls++
	call := r.getCalls
	if call == 1 {
		snapshot := *r.getByIDAccount
		r.mu.Unlock()
		close(r.firstCaptured)
		<-r.releaseFirst
		return &snapshot, nil
	}
	r.mu.Unlock()
	return r.rateLimitClearRepoStub.GetByID(ctx, id)
}

func (c *tempUnschedCacheRecorder) GetTempUnsched(ctx context.Context, accountID int64) (*TempUnschedState, error) {
	if c.state == nil {
		return nil, nil
	}
	copy := *c.state
	return &copy, nil
}

func (c *tempUnschedCacheRecorder) DeleteTempUnsched(ctx context.Context, accountID int64) error {
	c.deletedIDs = append(c.deletedIDs, accountID)
	c.state = nil
	return c.deleteErr
}

func (c *tempUnschedCacheRecorder) DeleteTempUnschedIfObserved(_ context.Context, accountID int64, observedGeneration string) (bool, error) {
	c.conditionalDeleteCalls++
	if c.replacementBeforeDelete != nil {
		copy := *c.replacementBeforeDelete
		c.state = &copy
		c.replacementBeforeDelete = nil
	}
	if c.conditionalDeleteErr != nil {
		return false, c.conditionalDeleteErr
	}
	if c.state == nil {
		return true, nil
	}
	if observedGeneration == "" || c.state.Generation != observedGeneration {
		return false, nil
	}
	c.deletedIDs = append(c.deletedIDs, accountID)
	c.state = nil
	return true, nil
}

type generationRuntimeBlocker struct {
	generation       uint64
	blocked          bool
	rearmBeforeClear bool
	clearedIDs       []int64
}

func (b *generationRuntimeBlocker) BlockAccountScheduling(_ *Account, _ time.Time, _ string) {
	b.generation++
	b.blocked = true
}

func (b *generationRuntimeBlocker) ClearAccountSchedulingBlock(accountID int64) {
	b.generation++
	b.blocked = false
	b.clearedIDs = append(b.clearedIDs, accountID)
}

func (b *generationRuntimeBlocker) AccountSchedulingBlockGeneration(int64) (uint64, bool) {
	return b.generation, b.blocked
}

func (b *generationRuntimeBlocker) ClearAccountSchedulingBlockIfGeneration(accountID int64, generation uint64) bool {
	if b.rearmBeforeClear {
		b.generation++
		b.blocked = true
		b.rearmBeforeClear = false
	}
	if !b.blocked || b.generation != generation {
		return false
	}
	b.generation++
	b.blocked = false
	b.clearedIDs = append(b.clearedIDs, accountID)
	return true
}

func (s *recoverTokenInvalidatorStub) InvalidateToken(ctx context.Context, account *Account) error {
	s.accounts = append(s.accounts, account)
	return s.err
}

func TestRateLimitService_ClearRateLimit_AlsoClearsTempUnschedulable(t *testing.T) {
	repo := &rateLimitClearRepoStub{}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 42)
	require.NoError(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Equal(t, []int64{42}, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_ClearTempUnschedulableFailed(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		clearTempUnschedulableErr: errors.New("clear temp unsched failed"),
	}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 7)
	require.Error(t, err)

	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_ClearRateLimitFailed(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		clearRateLimitErr: errors.New("clear rate limit failed"),
	}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 11)
	require.Error(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 0, repo.clearAntigravityCalls)
	require.Equal(t, 0, repo.clearModelRateLimitCalls)
	require.Equal(t, 0, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_ClearAntigravityFailed(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		clearAntigravityErr: errors.New("clear antigravity failed"),
	}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 12)
	require.Error(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 0, repo.clearModelRateLimitCalls)
	require.Equal(t, 0, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_ClearModelRateLimitsFailed(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		clearModelRateLimitErr: errors.New("clear model rate limits failed"),
	}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 13)
	require.Error(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 0, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_CacheDeleteFailedShouldNotFail(t *testing.T) {
	repo := &rateLimitClearRepoStub{}
	cache := &tempUnschedCacheRecorder{
		deleteErr: errors.New("cache delete failed"),
	}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearRateLimit(context.Background(), 14)
	require.NoError(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Equal(t, []int64{14}, cache.deletedIDs)
}

func TestRateLimitService_ClearRateLimit_WithoutTempUnschedCache(t *testing.T) {
	repo := &rateLimitClearRepoStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	err := svc.ClearRateLimit(context.Background(), 15)
	require.NoError(t, err)

	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
}

func TestRateLimitService_ClearAccountRateLimitConditionally_PreservesUnrelatedState(t *testing.T) {
	now := time.Now().UTC()
	resetAt := now.Add(5 * time.Minute)
	overloadUntil := now.Add(2 * time.Minute)
	tempUntil := now.Add(10 * time.Minute)
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{
		ID:                      51,
		UpdatedAt:               now,
		Status:                  StatusError,
		Schedulable:             false,
		RateLimitedAt:           &now,
		RateLimitResetAt:        &resetAt,
		OverloadUntil:           &overloadUntil,
		TempUnschedulableUntil:  &tempUntil,
		TempUnschedulableReason: "new isolation",
		Extra: map[string]any{
			"model_rate_limits":        map[string]any{"gpt-5": map[string]any{"reset_at": resetAt}},
			"antigravity_quota_scopes": map[string]any{"gemini": true},
		},
	}}
	cache := &tempUnschedCacheRecorder{}
	blocker := &runtimeBlockRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	err := svc.ClearAccountRateLimitConditionally(context.Background(), 51, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.NoError(t, err)
	require.Nil(t, repo.getByIDAccount.RateLimitedAt)
	require.Nil(t, repo.getByIDAccount.RateLimitResetAt)
	require.Nil(t, repo.getByIDAccount.OverloadUntil)
	require.NotNil(t, repo.getByIDAccount.TempUnschedulableUntil)
	require.Equal(t, StatusError, repo.getByIDAccount.Status)
	require.False(t, repo.getByIDAccount.Schedulable)
	require.Contains(t, repo.getByIDAccount.Extra, "model_rate_limits")
	require.Contains(t, repo.getByIDAccount.Extra, "antigravity_quota_scopes")
	require.Zero(t, repo.clearAntigravityCalls)
	require.Zero(t, repo.clearModelRateLimitCalls)
	require.Zero(t, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
	require.Empty(t, blocker.clearedIDs)
}

func TestRateLimitService_RecoverAccountStateConditionally_PreservesManualAndScopedState(t *testing.T) {
	now := time.Now().UTC()
	resetAt := now.Add(5 * time.Minute)
	tempUntil := now.Add(10 * time.Minute)
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{
		ID:                      52,
		Type:                    AccountTypeOAuth,
		UpdatedAt:               now,
		Status:                  StatusError,
		ErrorMessage:            "old error",
		Schedulable:             false,
		RateLimitResetAt:        &resetAt,
		TempUnschedulableUntil:  &tempUntil,
		TempUnschedulableReason: "new isolation",
		Extra: map[string]any{
			"model_rate_limits": map[string]any{"gpt-5": map[string]any{"reset_at": resetAt}},
		},
	}}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	result, err := svc.RecoverAccountStateConditionally(context.Background(), 52, AccountStatePrecondition{ExpectedUpdatedAt: &now}, false)
	require.NoError(t, err)
	require.True(t, result.ClearedError)
	require.True(t, result.ClearedRateLimit)
	require.Equal(t, StatusActive, repo.getByIDAccount.Status)
	require.Nil(t, repo.getByIDAccount.RateLimitResetAt)
	require.False(t, repo.getByIDAccount.Schedulable)
	require.NotNil(t, repo.getByIDAccount.TempUnschedulableUntil)
	require.Contains(t, repo.getByIDAccount.Extra, "model_rate_limits")
	require.Zero(t, repo.clearModelRateLimitCalls)
	require.Zero(t, repo.clearTempUnschedCalls)
}

func TestRateLimitService_ConditionalRecovery_StaleSnapshotConflicts(t *testing.T) {
	now := time.Now().UTC()
	repo := &rateLimitClearRepoStub{
		getByIDAccount:      &Account{ID: 53, UpdatedAt: now, Status: StatusError},
		conditionalConflict: true,
	}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	_, err := svc.RecoverAccountStateConditionally(context.Background(), 53, AccountStatePrecondition{ExpectedUpdatedAt: &now}, false)
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.Zero(t, repo.clearErrorCalls)
	require.Zero(t, repo.clearRateLimitCalls)
}

func TestRateLimitService_ConditionalRateClear_UnsupportedRepositoryFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	resetAt := now.Add(5 * time.Minute)
	repo := &nonConditionalRateRepoStub{account: &Account{ID: 59, UpdatedAt: now, RateLimitResetAt: &resetAt}}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	err := svc.ClearAccountRateLimitConditionally(context.Background(), 59, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, ErrAccountConditionalUpdateUnavailable)
	require.Zero(t, repo.clearRateLimitCalls)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_ProtectsNewGeneration(t *testing.T) {
	now := time.Now().UTC()
	observedUntil := now.Add(5 * time.Minute)
	newUntil := now.Add(15 * time.Minute)
	repo := &rateLimitClearRepoStub{
		getByIDAccount: &Account{ID: 54, UpdatedAt: now, TempUnschedulableUntil: &newUntil},
	}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 54, AccountStatePrecondition{
		ExpectedTempUnschedulableUntil: &observedUntil,
	})
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.NotNil(t, repo.getByIDAccount.TempUnschedulableUntil)
	require.Equal(t, newUntil, *repo.getByIDAccount.TempUnschedulableUntil)
	require.Zero(t, repo.clearTempUnschedCalls)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_DBConflictDoesNotClearCache(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	repo := &rateLimitClearRepoStub{
		getByIDAccount:      &Account{ID: 55, UpdatedAt: now, TempUnschedulableUntil: &until},
		conditionalConflict: true,
	}
	cache := &tempUnschedCacheRecorder{state: &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"}}
	blocker := &generationRuntimeBlocker{generation: 3, blocked: true}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 55, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.Zero(t, cache.conditionalDeleteCalls)
	require.Equal(t, "old", cache.state.Generation)
	require.True(t, blocker.blocked)
	require.Empty(t, blocker.clearedIDs)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_DBErrorDoesNotClearCacheOrRuntime(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	dbErr := errors.New("database unavailable")
	repo := &rateLimitClearRepoStub{
		getByIDAccount:     &Account{ID: 551, UpdatedAt: now, TempUnschedulableUntil: &until},
		conditionalTempErr: dbErr,
	}
	cache := &tempUnschedCacheRecorder{state: &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"}}
	blocker := &generationRuntimeBlocker{generation: 4, blocked: true}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 551, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, dbErr)
	require.Zero(t, cache.conditionalDeleteCalls)
	require.Equal(t, "old", cache.state.Generation)
	require.True(t, blocker.blocked)
	require.Empty(t, blocker.clearedIDs)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_CacheFailureKeepsBlockAndReturnsError(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	cacheErr := errors.New("redis unavailable")
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{ID: 56, UpdatedAt: now, TempUnschedulableUntil: &until}}
	cache := &tempUnschedCacheRecorder{
		state:                &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"},
		conditionalDeleteErr: cacheErr,
	}
	blocker := &generationRuntimeBlocker{generation: 9, blocked: true}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 56, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, cacheErr)
	require.Equal(t, 1, repo.clearTempUnschedCalls, "DB CAS completes before the fail-safe cache clear")
	require.Equal(t, "old", cache.state.Generation, "cache failure must leave the runtime block in place")
	require.True(t, blocker.blocked)
	require.Empty(t, blocker.clearedIDs)

	cache.conditionalDeleteErr = nil
	err = svc.ClearTempUnschedulableConditionally(context.Background(), 56, AccountStatePrecondition{
		ExpectedUpdatedAt:              &now,
		ExpectedTempUnschedulableUntil: &until,
	})
	require.NoError(t, err, "an idempotent retry may finish cache cleanup after the DB CAS committed")
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Nil(t, cache.state)
	require.False(t, blocker.blocked)
	require.Equal(t, []int64{56}, blocker.clearedIDs)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_RetryDoesNotClearRearmedRuntimeGeneration(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	cacheErr := errors.New("redis unavailable")
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{ID: 562, UpdatedAt: now, TempUnschedulableUntil: &until}}
	cache := &tempUnschedCacheRecorder{
		state:                &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"},
		conditionalDeleteErr: cacheErr,
	}
	blocker := &generationRuntimeBlocker{generation: 10, blocked: true}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 562, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, cacheErr)
	blocker.BlockAccountScheduling(repo.getByIDAccount, time.Now().Add(10*time.Minute), "new fault")
	cache.conditionalDeleteErr = nil
	err = svc.ClearTempUnschedulableConditionally(context.Background(), 562, AccountStatePrecondition{
		ExpectedUpdatedAt:              &now,
		ExpectedTempUnschedulableUntil: &until,
	})
	require.NoError(t, err)
	require.Nil(t, cache.state)
	require.True(t, blocker.blocked, "retry must only clear the runtime generation captured by the first attempt")
	require.Empty(t, blocker.clearedIDs)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_RetryAfterCacheDisappearsClearsOnlyOldRuntime(t *testing.T) {
	tests := []struct {
		name             string
		rearmRuntime     bool
		wantBlocked      bool
		wantClearedCount int
	}{
		{name: "old runtime is cleared", wantBlocked: false, wantClearedCount: 1},
		{name: "new runtime is preserved", rearmRuntime: true, wantBlocked: true, wantClearedCount: 0},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			until := now.Add(5 * time.Minute)
			accountID := int64(570 + index)
			cacheErr := errors.New("redis unavailable")
			repo := &rateLimitClearRepoStub{getByIDAccount: &Account{
				ID: accountID, UpdatedAt: now, TempUnschedulableUntil: &until,
			}}
			cache := &tempUnschedCacheRecorder{
				state:                &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"},
				conditionalDeleteErr: cacheErr,
			}
			blocker := &generationRuntimeBlocker{generation: 20, blocked: true}
			svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
			svc.SetAccountRuntimeBlocker(blocker)

			err := svc.ClearTempUnschedulableConditionally(context.Background(), accountID, AccountStatePrecondition{ExpectedUpdatedAt: &now})
			require.ErrorIs(t, err, cacheErr)
			if test.rearmRuntime {
				blocker.BlockAccountScheduling(repo.getByIDAccount, time.Now().Add(10*time.Minute), "new fault")
			}
			cache.conditionalDeleteErr = nil
			cache.state = nil
			err = svc.ClearTempUnschedulableConditionally(context.Background(), accountID, AccountStatePrecondition{
				ExpectedUpdatedAt:              &now,
				ExpectedTempUnschedulableUntil: &until,
			})
			require.NoError(t, err)
			require.Equal(t, test.wantBlocked, blocker.blocked)
			require.Len(t, blocker.clearedIDs, test.wantClearedCount)
		})
	}
}

func TestRateLimitService_GetTempUnschedStatus_DoesNotResurrectCacheAfterConcurrentClear(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	base := &rateLimitClearRepoStub{getByIDAccount: &Account{
		ID: 60, UpdatedAt: now, TempUnschedulableUntil: &until, TempUnschedulableReason: "old isolation",
	}}
	repo := &interleavingTempRepo{
		rateLimitClearRepoStub: base,
		firstCaptured:          make(chan struct{}),
		releaseFirst:           make(chan struct{}),
	}
	cache := &tempUnschedCacheRecorder{state: &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"}}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	getDone := make(chan struct {
		state *TempUnschedState
		err   error
	}, 1)
	go func() {
		state, err := svc.GetTempUnschedStatus(context.Background(), 60)
		getDone <- struct {
			state *TempUnschedState
			err   error
		}{state: state, err: err}
	}()
	<-repo.firstCaptured
	clearErr := svc.ClearTempUnschedulableConditionally(context.Background(), 60, AccountStatePrecondition{
		ExpectedUpdatedAt:              &now,
		ExpectedTempUnschedulableUntil: &until,
	})
	close(repo.releaseFirst)
	getResult := <-getDone

	require.NoError(t, clearErr)
	require.NoError(t, getResult.err)
	require.NotNil(t, getResult.state, "the in-flight read intentionally observed the old snapshot")
	require.Nil(t, cache.state, "the old read must not repopulate a cleared cache generation")
	require.Zero(t, cache.setCalls)
}

func TestRateLimitService_GetTempUnschedStatus_IsReadOnlyForAbsentAndExpiredDBState(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	cache := &tempUnschedCacheRecorder{state: &TempUnschedState{UntilUnix: now.Add(time.Minute).Unix(), Generation: "concurrent"}}
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{ID: 61, UpdatedAt: now}}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	state, err := svc.GetTempUnschedStatus(context.Background(), 61)
	require.NoError(t, err)
	require.Nil(t, state)
	require.Equal(t, "concurrent", cache.state.Generation)
	require.Empty(t, cache.deletedIDs)
	require.Zero(t, cache.setCalls)

	repo.getByIDAccount.TempUnschedulableUntil = &expired
	state, err = svc.GetTempUnschedStatus(context.Background(), 61)
	require.NoError(t, err)
	require.Nil(t, state)
	require.Equal(t, "concurrent", cache.state.Generation)
	require.Empty(t, cache.deletedIDs)
	require.Zero(t, cache.setCalls)
}

func TestRateLimitService_ClearTempUnschedulableConditionally_DoesNotDeleteRearmedCacheGeneration(t *testing.T) {
	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	newUntil := now.Add(10 * time.Minute)
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{ID: 57, UpdatedAt: now, TempUnschedulableUntil: &until}}
	cache := &tempUnschedCacheRecorder{
		state:                   &TempUnschedState{UntilUnix: until.Unix(), Generation: "old"},
		replacementBeforeDelete: &TempUnschedState{UntilUnix: newUntil.Unix(), Generation: "new"},
	}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	err := svc.ClearTempUnschedulableConditionally(context.Background(), 57, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Equal(t, "new", cache.state.Generation)
}

func TestRateLimitService_ConditionalRateClear_DoesNotClearNewRuntimeGenerationOr403Counter(t *testing.T) {
	now := time.Now().UTC()
	resetAt := now.Add(5 * time.Minute)
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{
		ID: 58, UpdatedAt: now, Status: StatusActive, RateLimitResetAt: &resetAt,
	}}
	blocker := &generationRuntimeBlocker{generation: 7, blocked: true, rearmBeforeClear: true}
	counter := &openAI403CounterResetStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	svc.SetAccountRuntimeBlocker(blocker)
	svc.SetOpenAI403CounterCache(counter)

	err := svc.ClearAccountRateLimitConditionally(context.Background(), 58, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.NoError(t, err)
	require.True(t, blocker.blocked)
	require.Empty(t, blocker.clearedIDs)
	require.Empty(t, counter.resetCalls)
}

func TestRateLimitService_RecoverAccountAfterSuccessfulTest_ClearsErrorAndRateLimitRelatedState(t *testing.T) {
	now := time.Now()
	repo := &rateLimitClearRepoStub{
		getByIDAccount: &Account{
			ID:                     42,
			Status:                 StatusError,
			RateLimitedAt:          &now,
			TempUnschedulableUntil: &now,
			Extra: map[string]any{
				"model_rate_limits": map[string]any{
					"claude-sonnet-4-5": map[string]any{
						"rate_limit_reset_at": now.Format(time.RFC3339),
					},
				},
				"antigravity_quota_scopes": map[string]any{"gemini": true},
			},
		},
	}
	cache := &tempUnschedCacheRecorder{}
	blocker := &runtimeBlockRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	svc.SetAccountRuntimeBlocker(blocker)

	result, err := svc.RecoverAccountAfterSuccessfulTest(context.Background(), 42)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.ClearedError)
	require.True(t, result.ClearedRateLimit)

	require.Equal(t, 1, repo.getByIDCalls)
	require.Equal(t, 1, repo.clearErrorCalls)
	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Equal(t, []int64{42}, cache.deletedIDs)
	require.Equal(t, []int64{42}, blocker.clearedIDs)
}

func TestRateLimitService_RecoverAccountAfterSuccessfulTest_NoRecoverableStateIsNoop(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		getByIDAccount: &Account{
			ID:          7,
			Status:      StatusActive,
			Schedulable: true,
			Extra:       map[string]any{},
		},
	}
	cache := &tempUnschedCacheRecorder{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)

	result, err := svc.RecoverAccountAfterSuccessfulTest(context.Background(), 7)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.ClearedError)
	require.False(t, result.ClearedRateLimit)

	require.Equal(t, 1, repo.getByIDCalls)
	require.Equal(t, 0, repo.clearErrorCalls)
	require.Equal(t, 0, repo.clearRateLimitCalls)
	require.Equal(t, 0, repo.clearAntigravityCalls)
	require.Equal(t, 0, repo.clearModelRateLimitCalls)
	require.Equal(t, 0, repo.clearTempUnschedCalls)
	require.Empty(t, cache.deletedIDs)
}

func TestRateLimitService_RecoverAccountAfterSuccessfulTest_ClearErrorFailed(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		getByIDAccount: &Account{
			ID:     9,
			Status: StatusError,
		},
		clearErrorErr: errors.New("clear error failed"),
	}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)

	result, err := svc.RecoverAccountAfterSuccessfulTest(context.Background(), 9)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, 1, repo.getByIDCalls)
	require.Equal(t, 1, repo.clearErrorCalls)
	require.Equal(t, 0, repo.clearRateLimitCalls)
}

func TestRateLimitService_RecoverAccountState_InvalidatesOAuthTokenOnErrorRecovery(t *testing.T) {
	repo := &rateLimitClearRepoStub{
		getByIDAccount: &Account{
			ID:     21,
			Type:   AccountTypeOAuth,
			Status: StatusError,
		},
	}
	invalidator := &recoverTokenInvalidatorStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	svc.SetTokenCacheInvalidator(invalidator)

	result, err := svc.RecoverAccountState(context.Background(), 21, AccountRecoveryOptions{
		InvalidateToken: true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.ClearedError)
	require.False(t, result.ClearedRateLimit)
	require.Equal(t, 1, repo.clearErrorCalls)
	require.Len(t, invalidator.accounts, 1)
	require.Equal(t, int64(21), invalidator.accounts[0].ID)
}

func TestRateLimitService_ConditionalRecovery_DoesNotInvalidateOAuthTokenOrReset403Counter(t *testing.T) {
	now := time.Now().UTC()
	repo := &rateLimitClearRepoStub{getByIDAccount: &Account{
		ID: 22, Type: AccountTypeOAuth, Status: StatusError, UpdatedAt: now,
	}}
	invalidator := &recoverTokenInvalidatorStub{}
	counter := &openAI403CounterResetStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	svc.SetTokenCacheInvalidator(invalidator)
	svc.SetOpenAI403CounterCache(counter)

	result, err := svc.RecoverAccountStateConditionally(context.Background(), 22, AccountStatePrecondition{ExpectedUpdatedAt: &now}, true)
	require.NoError(t, err)
	require.True(t, result.ClearedError)
	require.Empty(t, invalidator.accounts)
	require.Empty(t, counter.resetCalls)
}
