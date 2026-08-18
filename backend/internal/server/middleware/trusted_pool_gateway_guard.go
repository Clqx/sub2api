package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const trustedPoolAPIKeySlotHeldKey = "trusted_pool_api_key_slot_held"

type trustedPoolRequestContextKey struct{}

type TrustedPoolGatewayAdmission interface {
	AcquireGatewayAdmission(ctx context.Context, apiKeyID int64) (release func(), guarded bool, err error)
}

// TrustedPoolGatewayGuard 在业务处理前登记严格请求租约，再读取最新 Seat gate。
// 登记顺序不能反转，否则冻结可能在“并发为 0”和请求真正进入之间穿透。
func TrustedPoolGatewayGuard(integration TrustedPoolGatewayAdmission) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey, ok := GetAPIKeyFromContext(c)
		if !ok || apiKey == nil || integration == nil {
			c.Next()
			return
		}
		requestCtx, _ := service.WithTrustedPoolSettlementTracker(c.Request.Context())
		release, guarded, err := integration.AcquireGatewayAdmission(requestCtx, apiKey.ID)
		if err != nil {
			if errors.Is(err, service.ErrTrustedPoolSeatSuspended) {
				AbortWithError(c, http.StatusForbidden, "TRUSTED_POOL_SEAT_SUSPENDED", "Trusted pool seat is suspended")
				return
			}
			AbortWithError(c, http.StatusServiceUnavailable, "TRUSTED_POOL_GATE_UNAVAILABLE", "Trusted pool gateway admission is unavailable")
			return
		}
		if !guarded {
			c.Next()
			return
		}
		c.Set(trustedPoolAPIKeySlotHeldKey, true)
		c.Request = c.Request.WithContext(WithTrustedPoolRequestContext(requestCtx))
		defer release()
		// MVP 不允许可信 Seat 提交会在 HTTP 返回后继续执行的任务，否则冻结快照无法覆盖后台用量。
		if isTrustedPoolAsyncSubmission(c.Request.Method, c.Request.URL.Path) {
			// 请求在 Guard 内被拒绝，确定未进入上游和计费路径，可安全完成本次 barrier。
			service.MarkTrustedPoolSettlementSucceeded(c.Request.Context())
			AbortWithError(c, http.StatusForbidden, "TRUSTED_POOL_ASYNC_NOT_ALLOWED", "Trusted pool seats cannot submit asynchronous jobs")
			return
		}
		c.Next()
		if isTrustedPoolNoBillingRoute(c.Request.Method, c.Request.URL.Path) {
			// 仅对显式维护的控制面端点标记无计费完成；未知/新增路由默认 unresolved、fail-close。
			service.MarkTrustedPoolSettlementSucceeded(c.Request.Context())
		}
	}
}

func isTrustedPoolNoBillingRoute(method, path string) bool {
	path = strings.TrimRight(path, "/")
	switch method {
	case http.MethodPost:
		return strings.HasSuffix(path, "/messages/count_tokens") ||
			(strings.Contains(path, "/images/batches/") && strings.HasSuffix(path, "/cancel"))
	case http.MethodDelete:
		return strings.Contains(path, "/images/batches/") || strings.Contains(path, "/custom-voices/")
	case http.MethodPatch:
		return strings.Contains(path, "/custom-voices/")
	case http.MethodGet:
		// /responses、/realtime、/live 与 Codex sideband 可能是长连接或继续产生用量，刻意不在此列。
		return path == "/v1/usage" || path == "/antigravity/v1/usage" ||
			strings.HasSuffix(path, "/sub2api/billing") ||
			strings.HasSuffix(path, "/models") || strings.Contains(path, "/models/") ||
			strings.Contains(path, "/images/tasks/") || strings.Contains(path, "/images/batches") ||
			strings.Contains(path, "/videos/") ||
			strings.HasSuffix(path, "/custom-voices") || strings.Contains(path, "/custom-voices/")
	default:
		return false
	}
}

// WithTrustedPoolRequestContext 标记可信 Seat 请求，供计费层在释放并发租约前同步完成结算。
func WithTrustedPoolRequestContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustedPoolRequestContextKey{}, true)
}

// IsTrustedPoolRequestContext 判断当前请求是否由可信 Seat 网关守卫接管。
func IsTrustedPoolRequestContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(trustedPoolRequestContextKey{}).(bool)
	return value
}

func isTrustedPoolAsyncSubmission(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	path = strings.TrimRight(path, "/")
	return strings.HasSuffix(path, "/images/generations/async") ||
		strings.HasSuffix(path, "/images/edits/async") ||
		strings.HasSuffix(path, "/images/batches") ||
		path == "/v1/videos" || path == "/videos" ||
		strings.Contains(path, "/videos/generations") ||
		strings.Contains(path, "/videos/edits") ||
		strings.Contains(path, "/videos/extensions")
}

// IsTrustedPoolAPIKeySlotHeld 供 Gateway 并发辅助层避免对同一请求重复登记 API Key 租约。
func IsTrustedPoolAPIKeySlotHeld(c *gin.Context) bool {
	if c == nil {
		return false
	}
	held, _ := c.Get(trustedPoolAPIKeySlotHeldKey)
	value, _ := held.(bool)
	return value
}
