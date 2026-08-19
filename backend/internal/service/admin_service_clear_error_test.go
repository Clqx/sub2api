//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type accountRepoStubForClearAccountError struct {
	mockAccountRepoForGemini
	account                  *Account
	clearErrorCalls          int
	clearRateLimitCalls      int
	clearAntigravityCalls    int
	clearModelRateLimitCalls int
	clearTempUnschedCalls    int
	getByIDCalls             int
}

type conditionalAccountRepoStub struct {
	*accountRepoStubForClearAccountError
	forceConflict bool
}

func (r *conditionalAccountRepoStub) matches(precondition AccountStatePrecondition) bool {
	return !r.forceConflict && accountMatchesStatePrecondition(r.account, precondition) == nil
}

func (r *conditionalAccountRepoStub) ClearErrorIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if !r.matches(precondition) {
		return false, nil
	}
	r.clearErrorCalls++
	r.account.Status = StatusActive
	r.account.ErrorMessage = ""
	return true, nil
}

func (r *conditionalAccountRepoStub) ClearAccountRateLimitIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if !r.matches(precondition) {
		return false, nil
	}
	r.clearRateLimitCalls++
	r.account.RateLimitedAt = nil
	r.account.RateLimitResetAt = nil
	r.account.OverloadUntil = nil
	return true, nil
}

func (r *conditionalAccountRepoStub) RecoverAccountStateIf(ctx context.Context, id int64, clearError, clearRateLimit bool, precondition AccountStatePrecondition) (bool, error) {
	if !r.matches(precondition) {
		return false, nil
	}
	if clearError {
		r.clearErrorCalls++
		r.account.Status = StatusActive
		r.account.ErrorMessage = ""
	}
	if clearRateLimit {
		r.clearRateLimitCalls++
		r.account.RateLimitedAt = nil
		r.account.RateLimitResetAt = nil
		r.account.OverloadUntil = nil
	}
	return true, nil
}

func (r *conditionalAccountRepoStub) SetSchedulableIf(ctx context.Context, id int64, schedulable bool, precondition AccountStatePrecondition) (bool, error) {
	if !r.matches(precondition) {
		return false, nil
	}
	r.account.Schedulable = schedulable
	return true, nil
}

func (r *conditionalAccountRepoStub) ClearTempUnschedulableIf(ctx context.Context, id int64, precondition AccountStatePrecondition) (bool, error) {
	if !r.matches(precondition) {
		return false, nil
	}
	r.clearTempUnschedCalls++
	r.account.TempUnschedulableUntil = nil
	r.account.TempUnschedulableReason = ""
	return true, nil
}

func (r *accountRepoStubForClearAccountError) GetByID(ctx context.Context, id int64) (*Account, error) {
	r.getByIDCalls++
	return r.account, nil
}

func (r *accountRepoStubForClearAccountError) ClearError(ctx context.Context, id int64) error {
	r.clearErrorCalls++
	r.account.Status = StatusActive
	r.account.ErrorMessage = ""
	return nil
}

func (r *accountRepoStubForClearAccountError) ClearRateLimit(ctx context.Context, id int64) error {
	r.clearRateLimitCalls++
	r.account.RateLimitedAt = nil
	r.account.RateLimitResetAt = nil
	return nil
}

func (r *accountRepoStubForClearAccountError) ClearAntigravityQuotaScopes(ctx context.Context, id int64) error {
	r.clearAntigravityCalls++
	return nil
}

func (r *accountRepoStubForClearAccountError) ClearModelRateLimits(ctx context.Context, id int64) error {
	r.clearModelRateLimitCalls++
	return nil
}

func (r *accountRepoStubForClearAccountError) ClearTempUnschedulable(ctx context.Context, id int64) error {
	r.clearTempUnschedCalls++
	r.account.TempUnschedulableUntil = nil
	r.account.TempUnschedulableReason = ""
	return nil
}

func TestAdminService_ClearAccountError_AlsoClearsRecoverableRuntimeState(t *testing.T) {
	until := time.Now().Add(10 * time.Minute)
	resetAt := time.Now().Add(5 * time.Minute)
	repo := &accountRepoStubForClearAccountError{
		account: &Account{
			ID:                      31,
			Platform:                PlatformOpenAI,
			Type:                    AccountTypeOAuth,
			Status:                  StatusError,
			ErrorMessage:            "refresh failed",
			RateLimitResetAt:        &resetAt,
			TempUnschedulableUntil:  &until,
			TempUnschedulableReason: "missing refresh token",
		},
	}
	blocker := &runtimeBlockRecorder{}
	svc := &adminServiceImpl{accountRepo: repo, runtimeBlocker: blocker}

	updated, err := svc.ClearAccountError(context.Background(), 31)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Equal(t, 1, repo.clearErrorCalls)
	require.Equal(t, 1, repo.clearRateLimitCalls)
	require.Equal(t, 1, repo.clearAntigravityCalls)
	require.Equal(t, 1, repo.clearModelRateLimitCalls)
	require.Equal(t, 1, repo.clearTempUnschedCalls)
	require.Nil(t, updated.RateLimitResetAt)
	require.Nil(t, updated.TempUnschedulableUntil)
	require.Empty(t, updated.TempUnschedulableReason)
	require.Equal(t, []int64{31}, blocker.clearedIDs)
}

func TestAdminService_ClearAccountError_WithPreconditionOnlyClearsError(t *testing.T) {
	now := time.Now().UTC()
	resetAt := now.Add(5 * time.Minute)
	tempUntil := now.Add(10 * time.Minute)
	base := &accountRepoStubForClearAccountError{account: &Account{
		ID:                      41,
		Status:                  StatusError,
		ErrorMessage:            "refresh failed",
		UpdatedAt:               now,
		Schedulable:             false,
		RateLimitResetAt:        &resetAt,
		TempUnschedulableUntil:  &tempUntil,
		TempUnschedulableReason: "new isolation",
		Extra: map[string]any{
			"model_rate_limits": map[string]any{"gpt-5": map[string]any{"reset_at": resetAt}},
		},
	}}
	repo := &conditionalAccountRepoStub{accountRepoStubForClearAccountError: base}
	blocker := &runtimeBlockRecorder{}
	svc := &adminServiceImpl{accountRepo: repo, runtimeBlocker: blocker}

	updated, err := svc.ClearAccountError(context.Background(), 41, AccountStatePrecondition{
		ExpectedUpdatedAt: &now,
	})
	require.NoError(t, err)
	require.Equal(t, StatusActive, updated.Status)
	require.Empty(t, updated.ErrorMessage)
	require.NotNil(t, updated.RateLimitResetAt)
	require.NotNil(t, updated.TempUnschedulableUntil)
	require.Contains(t, updated.Extra, "model_rate_limits")
	require.Equal(t, 1, base.clearErrorCalls)
	require.Zero(t, base.clearRateLimitCalls)
	require.Zero(t, base.clearModelRateLimitCalls)
	require.Zero(t, base.clearTempUnschedCalls)
	require.Empty(t, blocker.clearedIDs)
	require.Equal(t, 1, base.getByIDCalls, "conditional success must not depend on a post-write read")
}

func TestAdminService_ClearAccountError_StalePreconditionConflicts(t *testing.T) {
	now := time.Now().UTC()
	base := &accountRepoStubForClearAccountError{account: &Account{ID: 42, Status: StatusError, UpdatedAt: now}}
	repo := &conditionalAccountRepoStub{accountRepoStubForClearAccountError: base, forceConflict: true}
	svc := &adminServiceImpl{accountRepo: repo}

	_, err := svc.ClearAccountError(context.Background(), 42, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.Zero(t, base.clearErrorCalls)
}

func TestAdminService_ClearAccountError_ConditionalUnsupportedRepositoryFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	repo := &accountRepoStubForClearAccountError{account: &Account{
		ID: 44, Status: StatusError, ErrorMessage: "still active", UpdatedAt: now,
	}}
	svc := &adminServiceImpl{accountRepo: repo}

	_, err := svc.ClearAccountError(context.Background(), 44, AccountStatePrecondition{ExpectedUpdatedAt: &now})
	require.ErrorIs(t, err, ErrAccountConditionalUpdateUnavailable)
	require.Zero(t, repo.clearErrorCalls)
	require.Equal(t, StatusError, repo.account.Status)
}

func TestAdminService_SetAccountSchedulable_StalePreconditionDoesNotReenable(t *testing.T) {
	now := time.Now().UTC()
	base := &accountRepoStubForClearAccountError{account: &Account{
		ID:          43,
		Status:      StatusActive,
		UpdatedAt:   now,
		Schedulable: false,
	}}
	repo := &conditionalAccountRepoStub{accountRepoStubForClearAccountError: base, forceConflict: true}
	svc := &adminServiceImpl{accountRepo: repo}

	_, err := svc.SetAccountSchedulable(context.Background(), 43, true, AccountStatePrecondition{
		ExpectedUpdatedAt: &now,
	})
	require.ErrorIs(t, err, ErrAccountStateChanged)
	require.False(t, base.account.Schedulable)
}

func TestAdminService_SetAccountSchedulable_ConditionalSuccessDoesNotReadAfterWrite(t *testing.T) {
	now := time.Now().UTC()
	base := &accountRepoStubForClearAccountError{account: &Account{
		ID: 45, Status: StatusActive, UpdatedAt: now, Schedulable: false,
	}}
	repo := &conditionalAccountRepoStub{accountRepoStubForClearAccountError: base}
	svc := &adminServiceImpl{accountRepo: repo}

	updated, err := svc.SetAccountSchedulable(context.Background(), 45, true, AccountStatePrecondition{
		ExpectedUpdatedAt: &now,
	})
	require.NoError(t, err)
	require.True(t, updated.Schedulable)
	require.Equal(t, 1, base.getByIDCalls, "conditional success must not depend on a post-write read")
}
