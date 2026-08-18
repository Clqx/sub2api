//go:build unit

package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type trustedPoolAuthRepoForMiddleware struct {
	client *service.TrustedPoolIntegrationClient
	nonces map[string]bool
}

type trustedPoolTestEncryptor struct{}

func (trustedPoolTestEncryptor) Encrypt(value string) (string, error) {
	return "encrypted:" + value, nil
}
func (trustedPoolTestEncryptor) Decrypt(value string) (string, error) {
	plain, ok := strings.CutPrefix(value, "encrypted:")
	if !ok {
		return "", fmt.Errorf("invalid ciphertext")
	}
	return plain, nil
}

func (r trustedPoolAuthRepoForMiddleware) GetIntegrationClient(context.Context, string) (*service.TrustedPoolIntegrationClient, error) {
	return r.client, nil
}

func (r trustedPoolAuthRepoForMiddleware) ClaimIntegrationNonce(_ context.Context, _, nonce string, _ time.Time) (bool, error) {
	if r.nonces != nil {
		if r.nonces[nonce] {
			return false, nil
		}
		r.nonces[nonce] = true
	}
	return true, nil
}

func TestTrustedPoolAuthRejectsMissingService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", TrustedPoolAuth(nil, "seat:read"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/protected", nil))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestTrustedPoolAuthEnforcesBearerScope(t *testing.T) {
	secret := "integration-secret"
	hash := sha256.Sum256([]byte(secret))
	auth := service.NewTrustedPoolAuthService(trustedPoolAuthRepoForMiddleware{client: &service.TrustedPoolIntegrationClient{
		ClientID: "platform", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(hash[:]), Scopes: []string{"seat:read"},
	}}, nil)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/read", TrustedPoolAuth(auth, "seat:read"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.POST("/write", TrustedPoolAuth(auth, "seat:write"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	request := httptest.NewRequest(http.MethodGet, "/read", nil)
	request.Header.Set("X-Integration-Client-ID", "platform")
	request.Header.Set("Authorization", "Bearer "+secret)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusNoContent, recorder.Code)

	request = httptest.NewRequest(http.MethodPost, "/write", nil)
	request.Header.Set("X-Integration-Client-ID", "platform")
	request.Header.Set("Authorization", "Bearer "+secret)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestTrustedPoolAuthHMACCanonicalBodyAndReplay(t *testing.T) {
	bearerSecret := "integration-bearer-secret"
	hmacSecret := "integration-hmac-secret"
	secretHash := sha256.Sum256([]byte(bearerSecret))
	auth := service.NewTrustedPoolAuthService(trustedPoolAuthRepoForMiddleware{
		client: &service.TrustedPoolIntegrationClient{
			ClientID: "platform", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(secretHash[:]),
			HMACSecretEncrypted: "encrypted:" + hmacSecret, Scopes: []string{"seat:write"},
		},
		nonces: map[string]bool{},
	}, trustedPoolTestEncryptor{})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", TrustedPoolAuth(auth, "seat:write"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	body := `{"seat":"seat-1"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := "nonce-1"
	bodyHash := sha256.Sum256([]byte(body))
	canonical := fmt.Sprintf("POST\n/protected?mode=freeze\n%s\n%s\n%s", timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	_, _ = mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/protected?mode=freeze", strings.NewReader(body))
		req.Header.Set("X-Integration-Client-ID", "platform")
		req.Header.Set("X-Integration-Timestamp", timestamp)
		req.Header.Set("X-Integration-Nonce", nonce)
		req.Header.Set("X-Integration-Signature", signature)
		return req
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request())
	require.Equal(t, http.StatusNoContent, recorder.Code)

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request())
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestTrustedPoolAuthHMACRejectsOversizedBody(t *testing.T) {
	secretHash := sha256.Sum256([]byte("integration-secret"))
	auth := service.NewTrustedPoolAuthService(trustedPoolAuthRepoForMiddleware{client: &service.TrustedPoolIntegrationClient{
		ClientID: "platform", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(secretHash[:]), Scopes: []string{"seat:write"},
	}}, nil)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", TrustedPoolAuth(auth, "seat:write"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	request := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(strings.Repeat("x", trustedPoolMaxSignedBody+1)))
	request.Header.Set("X-Integration-Client-ID", "platform")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}
