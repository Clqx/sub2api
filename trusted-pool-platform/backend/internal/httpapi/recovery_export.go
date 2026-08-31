package httpapi

import (
	"encoding/hex"
	"net/http"

	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/exporter"
)

const recoveryEvidenceMediaType = "application/vnd.trusted-pool.recovery-evidence+json"

func (s *Server) createRecoveryVerificationExport(writer http.ResponseWriter, request *http.Request) {
	if !s.requireRecoveryExportService(writer, request) {
		return
	}
	var body struct {
		OperationID string `json:"operation_id"`
		ExportID    string `json:"export_id"`
	}
	if !decodeJSON(writer, request, &body) || !requireMatchingIdempotencyKey(writer, request, body.OperationID) {
		return
	}
	result, err := s.recoveryExports.Export(request.Context(), exporter.Command{
		OperationID: body.OperationID, ExportID: body.ExportID, PlanID: request.PathValue("id"),
	})
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	status := http.StatusOK
	if result.FirstDelivery {
		status = http.StatusCreated
	}
	writeRecoveryEvidenceBundle(writer, status, result)
}

func (s *Server) downloadRecoveryVerificationExport(writer http.ResponseWriter, request *http.Request) {
	if !s.requireRecoveryExportService(writer, request) {
		return
	}
	result, err := s.recoveryExports.Download(request.Context(), request.PathValue("id"), request.PathValue("export_id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeRecoveryEvidenceBundle(writer, http.StatusOK, result)
}

func (s *Server) requireRecoveryExportService(writer http.ResponseWriter, request *http.Request) bool {
	if s.recoveryExports == nil {
		writeDomainError(writer, recovery.ErrProviderUnavailable)
		return false
	}
	if err := s.recoveryExports.Ready(request.Context()); err != nil {
		writeDomainError(writer, recovery.ErrProviderUnavailable)
		return false
	}
	return true
}

func writeRecoveryEvidenceBundle(writer http.ResponseWriter, status int, result *exporter.Result) {
	if result == nil || result.Export == nil || len(result.Bundle) == 0 {
		writeDomainError(writer, recovery.ErrInvalidState)
		return
	}
	writer.Header().Set("Content-Type", recoveryEvidenceMediaType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Recovery-Export-ID", result.Export.ExternalID)
	writer.Header().Set("X-Recovery-Export-Capability", result.Export.Capability)
	writer.Header().Set("ETag", `"`+hex.EncodeToString(result.Export.BundleDigest[:])+`"`)
	writer.WriteHeader(status)
	_, _ = writer.Write(result.Bundle)
}
