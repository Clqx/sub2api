//go:build unit

package admin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type conditionalRecoveryRepoStub struct {
	service.AccountRepository
	lastPrecondition service.AccountStatePrecondition
	account          *service.Account
	clearTempResult  bool
	clearTempCalls   int
	clearRateResult  bool
}

func (r *conditionalRecoveryRepoStub) GetByID(context.Context, int64) (*service.Account, error) {
	return r.account, nil
}

func (r *conditionalRecoveryRepoStub) ClearErrorIf(context.Context, int64, service.AccountStatePrecondition) (bool, error) {
	return false, nil
}

func (r *conditionalRecoveryRepoStub) ClearAccountRateLimitIf(context.Context, int64, service.AccountStatePrecondition) (bool, error) {
	if r.clearRateResult {
		r.account.RateLimitedAt = nil
		r.account.RateLimitResetAt = nil
		r.account.OverloadUntil = nil
		return true, nil
	}
	return false, nil
}

func (r *conditionalRecoveryRepoStub) RecoverAccountStateIf(context.Context, int64, bool, bool, service.AccountStatePrecondition) (bool, error) {
	return false, nil
}

func (r *conditionalRecoveryRepoStub) SetSchedulableIf(context.Context, int64, bool, service.AccountStatePrecondition) (bool, error) {
	return false, nil
}

func (r *conditionalRecoveryRepoStub) ClearTempUnschedulableIf(_ context.Context, _ int64, precondition service.AccountStatePrecondition) (bool, error) {
	r.lastPrecondition = precondition
	r.clearTempCalls++
	if r.clearTempResult {
		r.account.TempUnschedulableUntil = nil
		r.account.TempUnschedulableReason = ""
		return true, nil
	}
	return false, nil
}

type conditionalTempCacheStub struct {
	state      *service.TempUnschedState
	deleteFail bool
}

func (c *conditionalTempCacheStub) SetTempUnsched(context.Context, int64, *service.TempUnschedState) error {
	return nil
}

func (c *conditionalTempCacheStub) GetTempUnsched(context.Context, int64) (*service.TempUnschedState, error) {
	return c.state, nil
}

func (c *conditionalTempCacheStub) DeleteTempUnsched(context.Context, int64) error {
	c.state = nil
	return nil
}

func (c *conditionalTempCacheStub) DeleteTempUnschedIfObserved(_ context.Context, _ int64, generation string) (bool, error) {
	if c.deleteFail {
		return false, errors.New("redis unavailable")
	}
	if c.state == nil {
		return true, nil
	}
	if c.state.Generation != generation {
		return false, nil
	}
	c.state = nil
	return true, nil
}

func TestClearError_BindsRecoveryPreconditionAndReturnsConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	adminSvc := newStubAdminService()
	adminSvc.clearAccountErrorErr = service.ErrAccountStateChanged
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.POST("/accounts/:id/clear-error", handler.ClearError)

	requestBody := []byte(`{"expected_updated_at":"2026-08-10T03:04:05.123456Z","expected_status":"error","expected_schedulable":false}`)
	req := httptest.NewRequest(http.MethodPost, "/accounts/17/clear-error", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusConflict, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"reason":"ACCOUNT_STATE_CHANGED"`)
	require.Len(t, adminSvc.clearAccountErrorPreconditions, 1)
	precondition := adminSvc.clearAccountErrorPreconditions[0]
	require.NotNil(t, precondition.ExpectedUpdatedAt)
	require.Equal(t, time.Date(2026, 8, 10, 3, 4, 5, 123456000, time.UTC), *precondition.ExpectedUpdatedAt)
	require.NotNil(t, precondition.ExpectedStatus)
	require.Equal(t, service.StatusError, *precondition.ExpectedStatus)
	require.NotNil(t, precondition.ExpectedSchedulable)
	require.False(t, *precondition.ExpectedSchedulable)
}

func TestClearError_EmptyBodyKeepsLegacyRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	adminSvc := newStubAdminService()
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.POST("/accounts/:id/clear-error", handler.ClearError)

	req := httptest.NewRequest(http.MethodPost, "/accounts/17/clear-error", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, adminSvc.clearAccountErrorPreconditions, 1)
	require.True(t, adminSvc.clearAccountErrorPreconditions[0].Empty())
}

type recoveryTokenInvalidatorRecorder struct {
	calls int
}

func (r *recoveryTokenInvalidatorRecorder) InvalidateToken(context.Context, *service.Account) error {
	r.calls++
	return nil
}

func TestClearError_ConditionalRequestDoesNotInvalidateOAuthToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	adminSvc := newStubAdminService()
	adminSvc.clearAccountErrorResult = &service.Account{ID: 17, Type: service.AccountTypeOAuth, Status: service.StatusActive}
	invalidator := &recoveryTokenInvalidatorRecorder{}
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, invalidator)
	router := gin.New()
	router.POST("/accounts/:id/clear-error", handler.ClearError)

	req := httptest.NewRequest(http.MethodPost, "/accounts/17/clear-error", bytes.NewBufferString(`{"expected_status":"error"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Zero(t, invalidator.calls)
}

func TestClearError_OptionalIdempotencyKeyReplaysWithoutRepeatingMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousCoordinator := service.DefaultIdempotencyCoordinator()
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(
		newMemoryIdempotencyRepoStub(),
		service.DefaultIdempotencyConfig(),
	))
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(previousCoordinator) })

	adminSvc := newStubAdminService()
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.POST("/accounts/:id/clear-error", handler.ClearError)

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/accounts/17/clear-error", bytes.NewBufferString(`{"expected_status":"error"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "monitor-recovery-17")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	first := call()
	second := call()
	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, http.StatusOK, second.Code)
	require.Equal(t, 1, adminSvc.clearAccountErrorCalls)
	require.Equal(t, "true", second.Header().Get("X-Idempotency-Replayed"))
}

func TestClearTempUnschedulable_StaleGenerationReturnsConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	updatedAt := time.Date(2026, 8, 10, 3, 4, 5, 0, time.UTC)
	until := time.Date(2026, 8, 10, 3, 14, 5, 0, time.UTC)
	repo := &conditionalRecoveryRepoStub{account: &service.Account{
		ID: 17, Status: service.StatusActive, UpdatedAt: updatedAt, TempUnschedulableUntil: &until,
	}}
	rateLimitService := service.NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	handler := NewAccountHandler(newStubAdminService(), nil, nil, nil, nil, nil, rateLimitService, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.DELETE("/accounts/:id/temp-unschedulable", handler.ClearTempUnschedulable)

	requestBody := []byte(`{"expected_updated_at":"2026-08-10T03:04:05Z","expected_temp_unschedulable_until":"2026-08-10T03:14:05Z"}`)
	req := httptest.NewRequest(http.MethodDelete, "/accounts/17/temp-unschedulable", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusConflict, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"reason":"ACCOUNT_STATE_CHANGED"`)
	require.NotNil(t, repo.lastPrecondition.ExpectedTempUnschedulableUntil)
	require.Equal(t, time.Date(2026, 8, 10, 3, 14, 5, 0, time.UTC), *repo.lastPrecondition.ExpectedTempUnschedulableUntil)
}

func TestClearTempUnschedulable_IdempotentRetryFinishesCacheCleanupAndReplays(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousCoordinator := service.DefaultIdempotencyCoordinator()
	cfg := service.DefaultIdempotencyConfig()
	cfg.FailedRetryBackoff = 0
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(newMemoryIdempotencyRepoStub(), cfg))
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(previousCoordinator) })

	updatedAt := time.Date(2026, 8, 10, 3, 4, 5, 0, time.UTC)
	until := time.Date(2026, 8, 10, 3, 14, 5, 0, time.UTC)
	repo := &conditionalRecoveryRepoStub{
		account: &service.Account{
			ID: 18, Status: service.StatusActive, UpdatedAt: updatedAt, TempUnschedulableUntil: &until,
		},
		clearTempResult: true,
	}
	cache := &conditionalTempCacheStub{
		state:      &service.TempUnschedState{UntilUnix: until.Unix(), Generation: "observed-generation"},
		deleteFail: true,
	}
	rateLimitService := service.NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
	handler := NewAccountHandler(newStubAdminService(), nil, nil, nil, nil, nil, rateLimitService, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.DELETE("/accounts/:id/temp-unschedulable", handler.ClearTempUnschedulable)

	call := func() *httptest.ResponseRecorder {
		body := bytes.NewBufferString(`{"expected_updated_at":"2026-08-10T03:04:05Z","expected_temp_unschedulable_until":"2026-08-10T03:14:05Z"}`)
		req := httptest.NewRequest(http.MethodDelete, "/accounts/18/temp-unschedulable", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "monitor-temp-recovery-18")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	first := call()
	require.Equal(t, http.StatusInternalServerError, first.Code)
	require.NotNil(t, cache.state, "failed Redis cleanup remains fail-safe")
	cache.deleteFail = false
	second := call()
	third := call()
	require.Equal(t, http.StatusOK, second.Code)
	require.Equal(t, http.StatusOK, third.Code)
	require.Equal(t, 1, repo.clearTempCalls, "retry only finishes cleanup; it does not repeat the DB mutation")
	require.Nil(t, cache.state)
	require.Equal(t, "true", third.Header().Get("X-Idempotency-Replayed"))
}

func TestClearRateLimit_ConditionalSuccessDoesNotDependOnPostWriteAccountRead(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 8, 10, 3, 4, 5, 0, time.UTC)
	resetAt := now.Add(10 * time.Minute)
	repo := &conditionalRecoveryRepoStub{
		account:         &service.Account{ID: 19, Status: service.StatusActive, UpdatedAt: now, RateLimitResetAt: &resetAt},
		clearRateResult: true,
	}
	rateLimitService := service.NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	adminSvc := newStubAdminService()
	adminSvc.getAccountErr = errors.New("post-write read unavailable")
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, rateLimitService, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.POST("/accounts/:id/clear-rate-limit", handler.ClearRateLimit)

	body := bytes.NewBufferString(`{"expected_updated_at":"2026-08-10T03:04:05Z"}`)
	req := httptest.NewRequest(http.MethodPost, "/accounts/19/clear-rate-limit", body)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Zero(t, adminSvc.getAccountCalls)
	require.Contains(t, recorder.Body.String(), `"cleared_rate_limit":true`)
}
