package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var (
	ErrTrustedPoolUnauthorized = infraerrors.Unauthorized("TRUSTED_POOL_UNAUTHORIZED", "invalid trusted pool integration credential")
	ErrTrustedPoolForbidden    = infraerrors.Forbidden("TRUSTED_POOL_FORBIDDEN", "trusted pool integration scope is insufficient")
	ErrTrustedPoolReplay       = infraerrors.Unauthorized("TRUSTED_POOL_REPLAY", "trusted pool integration request was replayed")
)

type TrustedPoolIntegrationClient struct {
	ClientID            string
	ExternalPoolID      string
	SecretHash          string
	HMACSecretEncrypted string
	Scopes              []string
	ExpiresAt           *time.Time
}

// TrustedPoolIntegrationPrincipal is the authorization identity established by
// TrustedPoolAuth. Callers must use this value instead of re-reading identity
// headers, which remain attacker-controlled request data.
type TrustedPoolIntegrationPrincipal struct {
	ClientID       string
	ExternalPoolID string
}

type trustedPoolIntegrationPrincipalContextKey struct{}

func WithTrustedPoolIntegrationPrincipal(ctx context.Context, principal TrustedPoolIntegrationPrincipal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, trustedPoolIntegrationPrincipalContextKey{}, principal)
}

func TrustedPoolIntegrationPrincipalFromContext(ctx context.Context) (TrustedPoolIntegrationPrincipal, bool) {
	if ctx == nil {
		return TrustedPoolIntegrationPrincipal{}, false
	}
	principal, ok := ctx.Value(trustedPoolIntegrationPrincipalContextKey{}).(TrustedPoolIntegrationPrincipal)
	if !ok || strings.TrimSpace(principal.ClientID) == "" || strings.TrimSpace(principal.ExternalPoolID) == "" {
		return TrustedPoolIntegrationPrincipal{}, false
	}
	return principal, true
}

type TrustedPoolAuthRepository interface {
	GetIntegrationClient(ctx context.Context, clientID string) (*TrustedPoolIntegrationClient, error)
	ClaimIntegrationNonce(ctx context.Context, clientID, nonce string, expiresAt time.Time) (bool, error)
}

type TrustedPoolAuthService struct {
	repo      TrustedPoolAuthRepository
	encryptor SecretEncryptor
	now       func() time.Time
}

func NewTrustedPoolAuthService(repo TrustedPoolAuthRepository, encryptor SecretEncryptor) *TrustedPoolAuthService {
	return &TrustedPoolAuthService{repo: repo, encryptor: encryptor, now: time.Now}
}

func (s *TrustedPoolAuthService) AuthenticateBearer(ctx context.Context, clientID, secret, scope string) (*TrustedPoolIntegrationPrincipal, error) {
	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(secret))
	actual := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(client.SecretHash)) != 1 {
		return nil, ErrTrustedPoolUnauthorized
	}
	if !trustedPoolClientHasScope(client, scope) {
		return nil, ErrTrustedPoolForbidden
	}
	return integrationPrincipal(client), nil
}

func (s *TrustedPoolAuthService) AuthenticateHMAC(ctx context.Context, clientID, timestamp, nonce, signature, canonical, scope string) (*TrustedPoolIntegrationPrincipal, error) {
	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	parsedAt, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || strings.TrimSpace(nonce) == "" || len(nonce) > 128 {
		return nil, ErrTrustedPoolUnauthorized
	}
	now := s.now()
	if parsedAt.Before(now.Add(-5*time.Minute)) || parsedAt.After(now.Add(5*time.Minute)) {
		return nil, ErrTrustedPoolUnauthorized
	}
	// HMAC requires recoverable signing material. The Bearer verifier is
	// intentionally never reused as a signing key: a read-only DB leak must not
	// be enough to forge signed requests.
	if s.encryptor == nil || strings.TrimSpace(client.HMACSecretEncrypted) == "" {
		return nil, ErrTrustedPoolUnauthorized
	}
	key, err := s.encryptor.Decrypt(client.HMACSecretEncrypted)
	if err != nil || key == "" {
		return nil, ErrTrustedPoolUnauthorized
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(canonical))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(expected)) != 1 {
		return nil, ErrTrustedPoolUnauthorized
	}
	claimed, err := s.repo.ClaimIntegrationNonce(ctx, clientID, nonce, now.Add(10*time.Minute))
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("TRUSTED_POOL_AUTH_UNAVAILABLE", "trusted pool authentication store unavailable").WithCause(err)
	}
	if !claimed {
		return nil, ErrTrustedPoolReplay
	}
	if !trustedPoolClientHasScope(client, scope) {
		return nil, ErrTrustedPoolForbidden
	}
	return integrationPrincipal(client), nil
}

func (s *TrustedPoolAuthService) loadClient(ctx context.Context, clientID string) (*TrustedPoolIntegrationClient, error) {
	clientID = strings.TrimSpace(clientID)
	if s == nil || s.repo == nil || clientID == "" {
		return nil, ErrTrustedPoolUnauthorized
	}
	client, err := s.repo.GetIntegrationClient(ctx, clientID)
	if err != nil || client == nil {
		return nil, ErrTrustedPoolUnauthorized
	}
	client.ClientID = strings.TrimSpace(client.ClientID)
	client.ExternalPoolID = strings.TrimSpace(client.ExternalPoolID)
	if client.ClientID == "" || client.ClientID != clientID || client.ExternalPoolID == "" {
		return nil, ErrTrustedPoolUnauthorized
	}
	if client.ExpiresAt != nil && !client.ExpiresAt.After(s.now()) {
		return nil, ErrTrustedPoolUnauthorized
	}
	return client, nil
}

func trustedPoolClientHasScope(client *TrustedPoolIntegrationClient, scope string) bool {
	if client == nil {
		return false
	}
	for _, candidate := range client.Scopes {
		if candidate == scope || candidate == "*" {
			return true
		}
	}
	return false
}

func integrationPrincipal(client *TrustedPoolIntegrationClient) *TrustedPoolIntegrationPrincipal {
	return &TrustedPoolIntegrationPrincipal{ClientID: client.ClientID, ExternalPoolID: client.ExternalPoolID}
}

func IsTrustedPoolUnauthorized(err error) bool {
	return errors.Is(err, ErrTrustedPoolUnauthorized) || errors.Is(err, ErrTrustedPoolReplay)
}
