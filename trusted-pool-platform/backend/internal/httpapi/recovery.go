package httpapi

import (
	"net/http"

	"trusted-pool-platform/backend/internal/recovery"
)

func (s *Server) prepareRecoveryPlan(writer http.ResponseWriter, request *http.Request) {
	if !s.requireRecoveryService(writer, request) {
		return
	}
	var body recovery.PlanRequest
	if !decodeJSON(writer, request, &body) || !requireMatchingIdempotencyKey(writer, request, body.OperationID) {
		return
	}
	progress, err := s.recoveryGovernance.Prepare(request.Context(), body)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, recoveryProgressMetadata(progress))
}

func (s *Server) getRecoveryPlan(writer http.ResponseWriter, request *http.Request) {
	if s.recoveryGovernance == nil {
		writeDomainError(writer, recovery.ErrProviderUnavailable)
		return
	}
	progress, err := s.recoveryGovernance.Get(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, recoveryProgressMetadata(progress))
}

func (s *Server) commitRecoveryManifestSignatures(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Plan       recovery.PlanRequest                `json:"plan"`
		Signatures []recovery.SubmittedMemberSignature `json:"signatures"`
	}
	s.handleRecoveryStage(writer, request, &body, func() (*recovery.PlanProgress, error) {
		return s.recoveryGovernance.CommitMemberSignatures(request.Context(), body.Plan, body.Signatures)
	}, &body.Plan)
}

func (s *Server) commitRecoveryShareAcknowledgements(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Plan             recovery.PlanRequest                     `json:"plan"`
		Acknowledgements []recovery.SubmittedShareAcknowledgement `json:"acknowledgements"`
	}
	s.handleRecoveryStage(writer, request, &body, func() (*recovery.PlanProgress, error) {
		return s.recoveryGovernance.CommitShareAcknowledgements(request.Context(), body.Plan, body.Acknowledgements)
	}, &body.Plan)
}

func (s *Server) stageRecoveryCredentialBatches(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Plan    recovery.PlanRequest          `json:"plan"`
		Batches []recovery.StagedBatchPayload `json:"batches"`
	}
	s.handleRecoveryStage(writer, request, &body, func() (*recovery.PlanProgress, error) {
		return s.recoveryGovernance.StageCredentialBatches(request.Context(), body.Plan, body.Batches)
	}, &body.Plan)
}

func (s *Server) markRecoveryPlanReady(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Plan recovery.PlanRequest `json:"plan"`
	}
	s.handleRecoveryStage(writer, request, &body, func() (*recovery.PlanProgress, error) {
		return s.recoveryGovernance.VerifyEvidenceAndMarkReady(request.Context(), body.Plan)
	}, &body.Plan)
}

func (s *Server) handleRecoveryStage(writer http.ResponseWriter, request *http.Request, body any,
	call func() (*recovery.PlanProgress, error), plan *recovery.PlanRequest) {
	if !s.requireRecoveryService(writer, request) || !decodeJSON(writer, request, body) {
		return
	}
	if plan.PlanExternalID != request.PathValue("id") {
		writeError(writer, http.StatusBadRequest, "RECOVERY_PLAN_ID_MISMATCH", "路径计划 ID 与请求体不一致")
		return
	}
	if !requireMatchingIdempotencyKey(writer, request, plan.OperationID) {
		return
	}
	progress, err := call()
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, recoveryProgressMetadata(progress))
}

func (s *Server) requireRecoveryService(writer http.ResponseWriter, request *http.Request) bool {
	if s.recoveryGovernance == nil {
		writeDomainError(writer, recovery.ErrProviderUnavailable)
		return false
	}
	if err := s.recoveryGovernance.Ready(request.Context()); err != nil {
		writeDomainError(writer, recovery.ErrProviderUnavailable)
		return false
	}
	return true
}

func (s *Server) finalizeRecoveryPlan(writer http.ResponseWriter, request *http.Request) {
	if !s.requireRecoveryService(writer, request) {
		return
	}
	var body recovery.FinalizeRequest
	if !decodeJSON(writer, request, &body) {
		return
	}
	if body.PlanExternalID != request.PathValue("id") {
		writeError(writer, http.StatusBadRequest, "RECOVERY_PLAN_ID_MISMATCH", "路径计划 ID 与请求体不一致")
		return
	}
	if !requireMatchingIdempotencyKey(writer, request, body.OperationID) {
		return
	}
	progress, err := s.recoveryGovernance.Finalize(request.Context(), body)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	status := http.StatusAccepted
	if progress != nil && progress.Status == "FINALIZED" {
		status = http.StatusOK
	}
	writeJSON(writer, status, progress)
}

func (s *Server) claimRecoveryCredential(writer http.ResponseWriter, request *http.Request) {
	if !s.requireRecoveryService(writer, request) {
		return
	}
	var body struct {
		SeatID         string `json:"seat_id"`
		TargetMemberID string `json:"target_member_id"`
		ClaimToken     string `json:"claim_token"`
	}
	if !decodeJSON(writer, request, &body) {
		return
	}
	operationID := request.PathValue("operation_id")
	if !requireMatchingIdempotencyKey(writer, request, operationID) {
		return
	}
	delivery, err := s.recoveryGovernance.ClaimReplacementCredential(request.Context(),
		recovery.ReplacementCredentialClaimRequest{PlanExternalID: request.PathValue("id"),
			OperationID: operationID, SeatID: body.SeatID,
			TargetMemberID: body.TargetMemberID, ClaimToken: body.ClaimToken})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, delivery)
}

func recoveryProgressMetadata(progress *recovery.PlanProgress) map[string]any {
	if progress == nil {
		return map[string]any{}
	}
	result := recoveryPlanMetadata(progress.Plan)
	result["fencing_token"] = progress.FencingToken
	result["lease_expires_at"] = progress.LeaseExpiresAt
	return result
}

func recoveryPlanMetadata(plan *recovery.StoredEpochPlan) map[string]any {
	if plan == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id": plan.ExternalID, "ceremony_type": plan.CeremonyType, "pool_id": plan.PoolExternalID,
		"from_epoch": plan.FromEpoch, "to_epoch": plan.ToEpoch, "status": plan.Status,
		"expected_members": plan.ExpectedMemberCount, "expected_accounts": plan.ExpectedResourceCount,
		"committed_shares": plan.CommittedShareCount, "verified_signatures": plan.VerifiedSignatureCount,
		"acknowledged_shares": plan.AcknowledgedShareCount, "staged_batches": plan.StagedBatchCount,
		"record_version": plan.Version, "created_at": plan.CreatedAt, "updated_at": plan.UpdatedAt,
	}
}
