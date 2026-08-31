package handler

import (
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type TrustedPoolHandler struct {
	service *service.TrustedPoolIntegrationService
}

func NewTrustedPoolHandler(service *service.TrustedPoolIntegrationService) *TrustedPoolHandler {
	return &TrustedPoolHandler{service: service}
}

func (h *TrustedPoolHandler) Provision(c *gin.Context) {
	var input service.ProvisionTrustedPoolSeatInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool seat provision request")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	bodyOperationID := strings.TrimSpace(input.OperationID)
	if headerOperationID != "" && bodyOperationID != "" && headerOperationID != bodyOperationID {
		response.BadRequest(c, "idempotency key conflicts with operation_id")
		return
	}
	input.OperationID = operationID(c, input.OperationID)
	result, err := h.service.ProvisionSeat(c.Request.Context(), input)
	if response.ErrorFrom(c, err) {
		return
	}
	// credential 是敏感值，仅在受限集成响应中返回，禁止写入日志或 trace。
	response.Created(c, result)
}

func (h *TrustedPoolHandler) AckProvisionCredential(c *gin.Context) {
	var input service.AckTrustedPoolProvisionCredentialInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool credential acknowledgement")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	bodyOperationID := strings.TrimSpace(input.ClaimOperationID)
	if headerOperationID != "" && bodyOperationID != "" && headerOperationID != bodyOperationID {
		response.BadRequest(c, "idempotency key conflicts with claim_operation_id")
		return
	}
	if headerOperationID != "" {
		input.ClaimOperationID = headerOperationID
	}
	claim, err := h.service.AckProvisionCredential(c.Request.Context(), c.Param("seat_id"), input)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, claim)
}

func (h *TrustedPoolHandler) Register(c *gin.Context) {
	var input service.RegisterTrustedPoolSeatInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool seat binding")
		return
	}
	input.OperationID = operationID(c, input.OperationID)
	seat, err := h.service.RegisterSeat(c.Request.Context(), input)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Created(c, seat)
}

type trustedPoolOperationRequest struct {
	OperationID string `json:"operation_id"`
}
type trustedPoolRotateRequest struct {
	OperationID string `json:"operation_id"`
	TargetEpoch int64  `json:"target_epoch"`
}
type trustedPoolResolveSettlementRequest struct {
	OperationID             string `json:"operation_id"`
	ExpectedAssignmentEpoch int64  `json:"expected_assignment_epoch"`
	ExpectedRequestID       string `json:"expected_request_id"`
	Reason                  string `json:"reason"`
	Evidence                string `json:"evidence"`
}

func (h *TrustedPoolHandler) Suspend(c *gin.Context) {
	var input trustedPoolOperationRequest
	if err := c.ShouldBindJSON(&input); err != nil && c.Request.ContentLength != 0 {
		response.BadRequest(c, "invalid trusted pool suspend request")
		return
	}
	seat, err := h.service.Suspend(c.Request.Context(), c.Param("seat_id"), operationID(c, input.OperationID))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Accepted(c, seat)
}

func (h *TrustedPoolHandler) DrainStatus(c *gin.Context) {
	seat, err := h.service.DrainStatus(c.Request.Context(), c.Param("seat_id"))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, seat)
}

func (h *TrustedPoolHandler) Freeze(c *gin.Context) {
	var input trustedPoolOperationRequest
	if err := c.ShouldBindJSON(&input); err != nil && c.Request.ContentLength != 0 {
		response.BadRequest(c, "invalid trusted pool freeze request")
		return
	}
	seat, err := h.service.Freeze(c.Request.Context(), c.Param("seat_id"), operationID(c, input.OperationID))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, seat)
}

func (h *TrustedPoolHandler) Rotate(c *gin.Context) {
	var input trustedPoolRotateRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool rotate request")
		return
	}
	result, err := h.service.Rotate(c.Request.Context(), c.Param("seat_id"), operationID(c, input.OperationID), input.TargetEpoch)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}

func (h *TrustedPoolHandler) PreparePermanentRotation(c *gin.Context) {
	var input service.PrepareTrustedPoolPermanentRotationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool permanent rotation prepare request")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if headerOperationID == "" || strings.TrimSpace(input.OperationID) == "" || headerOperationID != strings.TrimSpace(input.OperationID) {
		response.BadRequest(c, "idempotency key must match operation_id")
		return
	}
	result, err := h.service.PreparePermanentRotation(c.Request.Context(), input)
	if response.ErrorFrom(c, err) {
		return
	}
	// credential 仅在 PREPARED 状态的精确幂等重放中返回；当前无 TTL，禁止记录响应体与 trace。
	response.Created(c, result)
}

func (h *TrustedPoolHandler) ActivatePermanentRotation(c *gin.Context) {
	var input service.ActivateTrustedPoolPermanentRotationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool permanent rotation activation request")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if headerOperationID == "" || strings.TrimSpace(input.OperationID) == "" || headerOperationID != strings.TrimSpace(input.OperationID) {
		response.BadRequest(c, "idempotency key must match operation_id")
		return
	}
	result, err := h.service.ActivatePermanentRotation(c.Request.Context(), input)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}

func (h *TrustedPoolHandler) CommitPermanentRotation(c *gin.Context) {
	var input service.CommitTrustedPoolPermanentRotationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "invalid trusted pool permanent rotation commit request")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if headerOperationID == "" || strings.TrimSpace(input.OperationID) == "" || headerOperationID != strings.TrimSpace(input.OperationID) {
		response.BadRequest(c, "idempotency key must match operation_id")
		return
	}
	result, err := h.service.CommitPermanentRotation(c.Request.Context(), input)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}

func (h *TrustedPoolHandler) UsageRisk(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	risk, err := h.service.UsageRisk(c.Request.Context(), c.Param("seat_id"), hours)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, risk)
}

func (h *TrustedPoolHandler) ListPendingSettlements(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	items, err := h.service.ListPendingSettlements(c.Request.Context(), c.Param("seat_id"), limit)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, items)
}

func (h *TrustedPoolHandler) GetPendingSettlement(c *gin.Context) {
	item, err := h.service.GetPendingSettlement(c.Request.Context(), c.Param("seat_id"), c.Param("settlement_id"))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, item)
}

func (h *TrustedPoolHandler) ResolvePendingSettlement(c *gin.Context) {
	var request trustedPoolResolveSettlementRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "invalid trusted pool settlement resolution")
		return
	}
	headerOperationID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	bodyOperationID := strings.TrimSpace(request.OperationID)
	if headerOperationID == "" || bodyOperationID == "" || headerOperationID != bodyOperationID {
		response.BadRequest(c, "idempotency key must match operation_id")
		return
	}
	result, err := h.service.ResolvePendingSettlement(c.Request.Context(), c.Param("seat_id"), c.Param("settlement_id"), service.ResolveTrustedPoolSettlementInput{
		OperationID:             bodyOperationID,
		ExpectedAssignmentEpoch: request.ExpectedAssignmentEpoch,
		ExpectedRequestID:       request.ExpectedRequestID,
		Reason:                  request.Reason,
		Evidence:                request.Evidence,
	})
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}

func operationID(c *gin.Context, bodyValue string) string {
	if value := strings.TrimSpace(c.GetHeader("Idempotency-Key")); value != "" {
		return value
	}
	return strings.TrimSpace(bodyValue)
}
