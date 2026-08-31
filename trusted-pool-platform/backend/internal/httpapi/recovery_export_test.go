package httpapi

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trusted-pool-platform/backend/internal/recovery"
	"trusted-pool-platform/backend/internal/recovery/exporter"
)

type verificationExportServiceStub struct {
	readyErr      error
	exportCommand exporter.Command
	downloadPlan  string
	downloadID    string
	result        *exporter.Result
}

func (stub *verificationExportServiceStub) Ready(context.Context) error { return stub.readyErr }

func (stub *verificationExportServiceStub) Export(_ context.Context, command exporter.Command) (*exporter.Result, error) {
	stub.exportCommand = command
	return stub.result, nil
}

func (stub *verificationExportServiceStub) Download(_ context.Context, planID, exportID string) (*exporter.Result, error) {
	stub.downloadPlan = planID
	stub.downloadID = exportID
	return stub.result, nil
}

func newTestRecoveryExportServer(t *testing.T, service VerificationExportService) *Server {
	t.Helper()
	server := newTestRecoveryServer(t, nil)
	server.recoveryExports = service
	server.recoveryAPIKeyHash = sha256.Sum256([]byte(testRecoveryAPIKey))
	return server
}

func testVerificationExportResult() *exporter.Result {
	bundle := []byte(`{"bundle_id":"export-1","protocol_version":"trusted-pool/offline-evidence-bundle/v1"}`)
	digest := sha256.Sum256(bundle)
	return &exporter.Result{Export: &recovery.StoredVerificationExport{
		ExternalID: "export-1", PlanExternalID: "plan-1", Capability: recovery.VerificationCapabilityRevealCapable,
		Status: recovery.VerificationExportAvailable, BundleDigest: digest,
	}, Bundle: bundle, FirstDelivery: true}
}

func TestRecoveryVerificationExportUsesRecoveryKeyAndExactIdempotencyKey(t *testing.T) {
	service := &verificationExportServiceStub{result: testVerificationExportResult()}
	server := newTestRecoveryExportServer(t, service)
	body := map[string]any{"operation_id": "export-operation-1", "export_id": "export-1"}
	path := "/api/v1/recovery-plans/plan-1/verification-exports"

	ordinary := requestJSONWithKey(t, server.Handler(), http.MethodPost, path, body, "export-operation-1", testAPIKey)
	if ordinary.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary key status = %d", ordinary.Code)
	}
	missing := requestJSONWithKey(t, server.Handler(), http.MethodPost, path, body, "", testRecoveryAPIKey)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key status = %d body=%s", missing.Code, missing.Body.String())
	}
	drift := requestJSONWithKey(t, server.Handler(), http.MethodPost, path, body, "different-operation", testRecoveryAPIKey)
	if drift.Code != http.StatusBadRequest {
		t.Fatalf("drift idempotency key status = %d body=%s", drift.Code, drift.Body.String())
	}

	created := requestJSONWithKey(t, server.Handler(), http.MethodPost, path, body, "export-operation-1", testRecoveryAPIKey)
	assertRecoveryEvidenceResponse(t, created, http.StatusCreated, service.result)
	if service.exportCommand != (exporter.Command{OperationID: "export-operation-1", ExportID: "export-1", PlanID: "plan-1"}) {
		t.Fatalf("export command = %+v", service.exportCommand)
	}
}

func TestRecoveryVerificationExportDownloadReturnsExactCanonicalBundle(t *testing.T) {
	service := &verificationExportServiceStub{result: testVerificationExportResult()}
	service.result.FirstDelivery = false
	server := newTestRecoveryExportServer(t, service)
	path := "/api/v1/recovery-plans/plan-1/verification-exports/export-1"

	ordinary := requestJSONWithKey(t, server.Handler(), http.MethodGet, path, nil, "", testAPIKey)
	if ordinary.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary key status = %d", ordinary.Code)
	}
	downloaded := requestJSONWithKey(t, server.Handler(), http.MethodGet, path, nil, "", testRecoveryAPIKey)
	assertRecoveryEvidenceResponse(t, downloaded, http.StatusOK, service.result)
	if service.downloadPlan != "plan-1" || service.downloadID != "export-1" {
		t.Fatalf("download binding = %s/%s", service.downloadPlan, service.downloadID)
	}
}

func assertRecoveryEvidenceResponse(t *testing.T, response *httptest.ResponseRecorder, status int, result *exporter.Result) {
	t.Helper()
	httpResponse := response.Result()
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != status {
		t.Fatalf("status = %d", httpResponse.StatusCode)
	}
	if got := httpResponse.Header.Get("Content-Type"); got != recoveryEvidenceMediaType {
		t.Fatalf("content type = %q", got)
	}
	if got := httpResponse.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	if got := httpResponse.Header.Get("X-Recovery-Export-ID"); got != "export-1" {
		t.Fatalf("export id header = %q", got)
	}
	if got := httpResponse.Header.Get("ETag"); !strings.Contains(got, "\"") || len(got) != 66 {
		t.Fatalf("etag = %q", got)
	}
	if got := response.Body.String(); got != string(result.Bundle) {
		t.Fatalf("body = %q", got)
	}
}
