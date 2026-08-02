package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

type loginCaptchaRepoStub struct {
	record        *LoginCaptchaIPRecord
	failures      int
	successes     int
	unblocks      int
	lastThreshold int
	lastWindow    time.Duration
	lastBlock     time.Duration
}

type loginSecurityVerifierStub struct {
	result *TurnstileVerifyResponse
	err    error
	calls  int
}

func (s *loginSecurityVerifierStub) VerifyToken(context.Context, string, string, string) (*TurnstileVerifyResponse, error) {
	s.calls++
	return s.result, s.err
}

type loginSecuritySettingRepoStub struct {
	values map[string]string
}

func (s *loginSecuritySettingRepoStub) Get(context.Context, string) (*Setting, error) {
	return nil, ErrSettingNotFound
}
func (s *loginSecuritySettingRepoStub) GetValue(_ context.Context, key string) (string, error) {
	value, ok := s.values[key]
	if !ok {
		return "", ErrSettingNotFound
	}
	return value, nil
}
func (s *loginSecuritySettingRepoStub) Set(context.Context, string, string) error { return nil }
func (s *loginSecuritySettingRepoStub) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := s.values[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}
func (s *loginSecuritySettingRepoStub) SetMultiple(context.Context, map[string]string) error {
	return nil
}
func (s *loginSecuritySettingRepoStub) GetAll(context.Context) (map[string]string, error) {
	return s.values, nil
}
func (s *loginSecuritySettingRepoStub) Delete(context.Context, string) error { return nil }

func (r *loginCaptchaRepoStub) GetBlocked(context.Context, string, time.Time) (*LoginCaptchaIPRecord, error) {
	if r.record != nil && r.record.BlockedUntil != nil {
		return r.record, nil
	}
	return nil, nil
}

func (r *loginCaptchaRepoStub) RecordFailure(_ context.Context, ip, _ string, now time.Time, threshold int, window, block time.Duration) (*LoginCaptchaIPRecord, error) {
	r.failures++
	r.lastThreshold, r.lastWindow, r.lastBlock = threshold, window, block
	record := &LoginCaptchaIPRecord{ID: 1, ClientIP: ip, FailureCount: r.failures, TotalFailures: int64(r.failures)}
	if r.failures >= threshold {
		blockedUntil := now.Add(block)
		record.BlockedUntil = &blockedUntil
		record.Status = "blocked"
	}
	r.record = record
	return record, nil
}

func (r *loginCaptchaRepoStub) RecordSuccess(context.Context, string, time.Time) error {
	r.successes++
	return nil
}

func (r *loginCaptchaRepoStub) List(context.Context, *LoginCaptchaIPFilter, time.Time, time.Duration) (*LoginCaptchaIPList, error) {
	return &LoginCaptchaIPList{}, nil
}

func (r *loginCaptchaRepoStub) Unblock(_ context.Context, _ int64, actorUserID int64, note string, now time.Time) (*LoginCaptchaIPRecord, error) {
	r.unblocks++
	r.record = &LoginCaptchaIPRecord{ID: 1, ClientIP: "203.0.113.10", Status: "cleared", ResolvedAt: &now, ResolvedByUserID: &actorUserID, ResolutionNote: note}
	return r.record, nil
}

func enabledTurnstileSettings(t *testing.T) *SettingService {
	t.Helper()
	return NewSettingService(&loginSecuritySettingRepoStub{values: map[string]string{
		SettingKeyTurnstileEnabled:   "true",
		SettingKeyTurnstileSecretKey: "secret",
	}}, &config.Config{})
}

func TestTurnstileLoginSecurityBlocksAtConfiguredThreshold(t *testing.T) {
	repo := &loginCaptchaRepoStub{}
	verifier := &loginSecurityVerifierStub{result: &TurnstileVerifyResponse{Success: false, ErrorCodes: []string{"invalid-input-response"}}}
	cfg := &config.Config{Turnstile: config.TurnstileConfig{
		FailureThreshold: 3, FailureWindowMinutes: 7, BlockMinutes: 30,
	}}
	service := NewTurnstileService(enabledTurnstileSettings(t), verifier, repo, cfg)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	for range 2 {
		err := service.VerifyLoginToken(context.Background(), "bad-token", "203.0.113.10", "scanner")
		require.ErrorIs(t, err, ErrTurnstileVerificationFailed)
	}
	err := service.VerifyLoginToken(context.Background(), "bad-token", "203.0.113.10", "scanner")
	require.Equal(t, "LOGIN_CAPTCHA_IP_BLOCKED", infraerrors.Reason(err))
	require.Equal(t, 3, repo.failures)
	require.Equal(t, 3, repo.lastThreshold)
	require.Equal(t, 7*time.Minute, repo.lastWindow)
	require.Equal(t, 30*time.Minute, repo.lastBlock)
	require.Equal(t, 3, verifier.calls)

	// A blocked request is rejected before contacting the challenge provider.
	err = service.VerifyLoginToken(context.Background(), "another-token", "203.0.113.10", "scanner")
	require.Equal(t, "LOGIN_CAPTCHA_IP_BLOCKED", infraerrors.Reason(err))
	require.Equal(t, "true", infraerrors.FromError(err).Metadata["repeated"])
	require.Equal(t, 3, verifier.calls)
}

func TestTurnstileLoginSecurityDoesNotCountProviderErrors(t *testing.T) {
	repo := &loginCaptchaRepoStub{}
	verifier := &loginSecurityVerifierStub{err: errors.New("provider unavailable")}
	service := NewTurnstileService(enabledTurnstileSettings(t), verifier, repo, &config.Config{})

	err := service.VerifyLoginToken(context.Background(), "token", "203.0.113.20", "browser")
	require.Error(t, err)
	require.Zero(t, repo.failures)
}

func TestTurnstileLoginSecurityRecordsSuccessAndAdminUnblock(t *testing.T) {
	repo := &loginCaptchaRepoStub{}
	verifier := &loginSecurityVerifierStub{result: &TurnstileVerifyResponse{Success: true}}
	service := NewTurnstileService(enabledTurnstileSettings(t), verifier, repo, &config.Config{})
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	require.NoError(t, service.VerifyLoginToken(context.Background(), "valid", "203.0.113.30", "browser"))
	require.Equal(t, 1, repo.successes)

	record, err := service.UnblockLoginCaptchaIP(context.Background(), 1, 99, "verified office IP")
	require.NoError(t, err)
	require.Equal(t, "cleared", record.Status)
	require.Equal(t, int64(99), *record.ResolvedByUserID)
	require.Equal(t, "verified office IP", record.ResolutionNote)
}
