//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type principalGateUserRepo struct {
	UserRepository
	user        *User
	updateCalls int
}

func (r *principalGateUserRepo) GetByEmail(context.Context, string) (*User, error) {
	if r.user == nil {
		return nil, ErrUserNotFound
	}
	return r.user, nil
}

func (r *principalGateUserRepo) GetByID(context.Context, int64) (*User, error) {
	if r.user == nil {
		return nil, ErrUserNotFound
	}
	return r.user, nil
}

func (r *principalGateUserRepo) Update(context.Context, *User, UserUpdateFields) error {
	r.updateCalls++
	return nil
}

type principalGateRefreshCache struct {
	RefreshTokenCache
	data          *RefreshTokenData
	deletedFamily string
}

func (c *principalGateRefreshCache) GetRefreshToken(context.Context, string) (*RefreshTokenData, error) {
	return c.data, nil
}

func (c *principalGateRefreshCache) DeleteTokenFamily(_ context.Context, familyID string) error {
	c.deletedFamily = familyID
	return nil
}

func TestTrustedPoolSeatInteractiveAuthGate(t *testing.T) {
	seat := &User{
		ID:            7,
		Email:         "seat@example.com",
		PasswordHash:  "$2a$10$7EqJtq98hPqEX7fNZaFWoO5cQ2BBE.CbCe6wP4h.CvjOCPLmR1J1e",
		Status:        StatusActive,
		PrincipalType: PrincipalTypeTrustedPoolSeat,
	}
	repo := &principalGateUserRepo{user: seat}
	cache := &principalGateRefreshCache{data: &RefreshTokenData{
		UserID:    seat.ID,
		FamilyID:  "seat-family",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	cfg := &config.Config{}
	cfg.JWT.Secret = "principal-gate-test-secret-32bytes"
	svc := NewAuthService(nil, repo, nil, cache, cfg, nil, nil, nil, nil, nil, nil, nil, nil)

	_, _, err := svc.Login(context.Background(), seat.Email, "password")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	_, err = svc.GenerateToken(context.Background(), seat)
	require.ErrorIs(t, err, ErrInteractiveAuthForbidden)
	_, err = svc.GenerateTokenPair(context.Background(), seat, "")
	require.ErrorIs(t, err, ErrInteractiveAuthForbidden)

	_, err = svc.RefreshTokenPair(context.Background(), "rt_existing")
	require.True(t, errors.Is(err, ErrInteractiveAuthForbidden))
	require.Equal(t, "seat-family", cache.deletedFamily)

	_, _, proceed := svc.preparePasswordReset(context.Background(), seat.Email, "https://example.com")
	require.False(t, proceed)

	userSvc := NewUserService(repo, nil, nil, nil)
	err = userSvc.ChangePassword(context.Background(), seat.ID, ChangePasswordRequest{CurrentPassword: "password", NewPassword: "new-password"})
	require.ErrorIs(t, err, ErrInteractiveAuthForbidden)
	require.Zero(t, repo.updateCalls)
}
