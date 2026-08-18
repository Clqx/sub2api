package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const trustedPoolMaxSignedBody = 1 << 20

// TrustedPoolAuth 为可信池集成接口提供独立 scope 认证，不复用全权限 Admin API Key。
// Bearer: Authorization + X-Integration-Client-ID；HMAC: X-Integration-* 四个头。
func TrustedPoolAuth(auth *service.TrustedPoolAuthService, requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if auth == nil {
			response.ErrorFrom(c, service.ErrTrustedPoolUnauthorized)
			c.Abort()
			return
		}
		clientID := strings.TrimSpace(c.GetHeader("X-Integration-Client-ID"))
		authorization := strings.TrimSpace(c.GetHeader("Authorization"))
		var principal *service.TrustedPoolIntegrationPrincipal
		var err error
		if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			principal, err = auth.AuthenticateBearer(c.Request.Context(), clientID, strings.TrimSpace(authorization[7:]), requiredScope)
		} else {
			principal, err = authenticateTrustedPoolHMAC(c, auth, clientID, requiredScope)
		}
		if err != nil || principal == nil {
			if err == nil {
				err = service.ErrTrustedPoolUnauthorized
			}
			response.ErrorFrom(c, err)
			c.Abort()
			return
		}
		c.Request = c.Request.WithContext(service.WithTrustedPoolIntegrationPrincipal(c.Request.Context(), *principal))
		c.Next()
	}
}

func authenticateTrustedPoolHMAC(c *gin.Context, auth *service.TrustedPoolAuthService, clientID, scope string) (*service.TrustedPoolIntegrationPrincipal, error) {
	if c.Request.Body == nil {
		c.Request.Body = http.NoBody
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, trustedPoolMaxSignedBody+1))
	if err != nil || len(body) > trustedPoolMaxSignedBody {
		return nil, service.ErrTrustedPoolUnauthorized
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	bodyHash := sha256.Sum256(body)
	timestamp := strings.TrimSpace(c.GetHeader("X-Integration-Timestamp"))
	nonce := strings.TrimSpace(c.GetHeader("X-Integration-Nonce"))
	signature := strings.TrimSpace(c.GetHeader("X-Integration-Signature"))
	canonical := strings.Join([]string{c.Request.Method, c.Request.URL.RequestURI(), timestamp, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	return auth.AuthenticateHMAC(c.Request.Context(), clientID, timestamp, nonce, signature, canonical, scope)
}
