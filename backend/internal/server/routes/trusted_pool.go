package routes

import (
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func RegisterTrustedPoolRoutes(v1 *gin.RouterGroup, h *handler.TrustedPoolHandler, auth *service.TrustedPoolAuthService) {
	root := v1.Group("/integrations/trusted-pools")
	read := root.Group("")
	read.Use(middleware.TrustedPoolAuth(auth, "seat:read"))
	{
		read.GET("/seats/:seat_id/drain-status", h.DrainStatus)
		read.GET("/seats/:seat_id/usage-risk", h.UsageRisk)
		read.GET("/seats/:seat_id/settlements", h.ListPendingSettlements)
		read.GET("/seats/:seat_id/settlements/:settlement_id", h.GetPendingSettlement)
	}
	write := root.Group("")
	write.Use(middleware.TrustedPoolAuth(auth, "seat:write"))
	{
		write.POST("/seats/register", h.Register)
		write.POST("/seats/:seat_id/suspend", h.Suspend)
		write.POST("/seats/:seat_id/freeze", h.Freeze)
		write.POST("/seats/:seat_id/rotate", h.Rotate)
	}
	provision := root.Group("")
	provision.Use(middleware.TrustedPoolAuth(auth, "seat:provision"))
	{
		provision.POST("/seats/provision", h.Provision)
	}
	credentialAck := root.Group("")
	credentialAck.Use(middleware.TrustedPoolAuth(auth, "credential:ack"))
	{
		credentialAck.POST("/seats/:seat_id/provision-credential/ack", h.AckProvisionCredential)
	}
	resolve := root.Group("")
	resolve.Use(middleware.TrustedPoolAuth(auth, "settlement:resolve"))
	{
		resolve.POST("/seats/:seat_id/settlements/:settlement_id/resolve", h.ResolvePendingSettlement)
	}
	permanentRotate := root.Group("")
	permanentRotate.Use(middleware.TrustedPoolAuth(auth, "seat:permanent-rotate"))
	{
		permanentRotate.POST("/permanent-rotations/prepare", h.PreparePermanentRotation)
		permanentRotate.POST("/permanent-rotations/activate", h.ActivatePermanentRotation)
		permanentRotate.POST("/permanent-rotations/commit", h.CommitPermanentRotation)
	}
}
