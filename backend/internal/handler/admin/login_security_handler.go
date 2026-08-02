package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type LoginSecurityHandler struct {
	turnstileService *service.TurnstileService
}

func NewLoginSecurityHandler(turnstileService *service.TurnstileService) *LoginSecurityHandler {
	return &LoginSecurityHandler{turnstileService: turnstileService}
}

// ListLoginCaptchaIPs lists aggregated login challenge failures by client IP.
// GET /api/v1/admin/login-security/ip-records
func (h *LoginSecurityHandler) ListLoginCaptchaIPs(c *gin.Context) {
	if h == nil || h.turnstileService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Login verification security service not available")
		return
	}
	page, pageSize := response.ParsePagination(c)
	if pageSize > 200 {
		pageSize = 200
	}
	status := strings.TrimSpace(c.Query("status"))
	switch status {
	case "", "blocked", "monitoring", "cleared":
	default:
		response.BadRequest(c, "Invalid status")
		return
	}
	result, err := h.turnstileService.ListLoginCaptchaIPs(c.Request.Context(), &service.LoginCaptchaIPFilter{
		Page: page, PageSize: pageSize, Query: strings.TrimSpace(c.Query("q")), Status: status,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Paginated(c, result.Records, int64(result.Total), result.Page, result.PageSize)
}

type unblockLoginCaptchaIPRequest struct {
	Note string `json:"note"`
}

// UnblockLoginCaptchaIP clears an automatic block while preserving its history.
// POST /api/v1/admin/login-security/ip-records/:id/unblock
func (h *LoginSecurityHandler) UnblockLoginCaptchaIP(c *gin.Context) {
	if h == nil || h.turnstileService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Login verification security service not available")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid login verification IP record id")
		return
	}
	var request unblockLoginCaptchaIPRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&request); err != nil {
			response.BadRequest(c, "Invalid request")
			return
		}
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Forbidden(c, "Administrator identity is required")
		return
	}
	middleware.SetAuditAction(c, "admin.login_security.ip.unblock")
	record, err := h.turnstileService.UnblockLoginCaptchaIP(c.Request.Context(), id, subject.UserID, request.Note)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, record)
}
