package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *AccountHandler) SetMonitorCostRouting(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid account ID")
		return
	}
	var req struct {
		Priority *int                              `json:"priority" binding:"required"`
		Control  service.MonitorCostRoutingControl `json:"control"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid cost routing control")
		return
	}
	account, err := h.adminService.SetMonitorCostRouting(c.Request.Context(), id, *req.Priority, req.Control)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	control, managed := account.MonitorCostRouting()
	response.Success(c, gin.H{"priority": account.Priority, "control": control, "enforced": managed, "suppressed": account.IsMonitorCostSuppressed()})
}
