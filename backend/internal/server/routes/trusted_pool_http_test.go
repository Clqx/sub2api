//go:build unit

package routes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type trustedPoolHTTPRepoStub struct {
	seat           *service.TrustedPoolSeat
	listLimit      int
	resolveCalls   int
	provisionCalls int
	provisionInput service.ProvisionTrustedPoolSeatInput
	ackCalls       int
	ackInput       service.AckTrustedPoolProvisionCredentialInput
	requestedPools []string
}

func (r *trustedPoolHTTPRepoStub) ProvisionSeat(_ context.Context, input service.ProvisionTrustedPoolSeatInput) (*service.TrustedPoolProvisionResult, error) {
	r.provisionCalls++
	r.provisionInput = input
	return &service.TrustedPoolProvisionResult{
		Seat:                  &service.TrustedPoolSeat{ExternalPoolID: input.ExternalPoolID, ExternalSeatID: input.ExternalSeatID, GroupID: input.ExistingGroupID},
		Credential:            "sk-tp-response-secret",
		CredentialFingerprint: input.CredentialFingerprint,
	}, nil
}
func (r *trustedPoolHTTPRepoStub) AckProvisionCredential(_ context.Context, seatID string, input service.AckTrustedPoolProvisionCredentialInput) (*service.TrustedPoolProvisionCredentialClaim, error) {
	r.ackCalls++
	r.ackInput = input
	return &service.TrustedPoolProvisionCredentialClaim{
		ExternalSeatID: seatID, ProvisionOperationID: input.ProvisionOperationID,
		ClaimOperationID: input.ClaimOperationID, ClaimedBy: input.ClaimedBy, CredentialFingerprint: input.CredentialFingerprint,
		CredentialClaimed: true, ClaimedAt: time.Now(),
	}, nil
}

func (r *trustedPoolHTTPRepoStub) RegisterSeat(context.Context, service.RegisterTrustedPoolSeatInput) (*service.TrustedPoolSeat, error) {
	return r.seat, nil
}
func (r *trustedPoolHTTPRepoStub) GetSeat(_ context.Context, externalPoolID, _ string) (*service.TrustedPoolSeat, error) {
	r.requestedPools = append(r.requestedPools, externalPoolID)
	if r.seat == nil || (r.seat.ExternalPoolID != "" && r.seat.ExternalPoolID != externalPoolID) {
		return nil, service.ErrTrustedPoolSeatNotFound
	}
	return r.seat, nil
}
func (r *trustedPoolHTTPRepoStub) GetSeatByAPIKeyID(context.Context, int64) (*service.TrustedPoolSeat, error) {
	return nil, service.ErrTrustedPoolSeatNotFound
}
func (r *trustedPoolHTTPRepoStub) GetUsageSnapshot(context.Context, int64) (*service.TrustedPoolUsageSnapshot, error) {
	return nil, nil
}
func (r *trustedPoolHTTPRepoStub) CreatePendingSettlement(context.Context, int64, string, string, int64) error {
	return nil
}
func (r *trustedPoolHTTPRepoStub) CompletePendingSettlement(context.Context, int64, string) error {
	return nil
}
func (r *trustedPoolHTTPRepoStub) MarkPendingSettlement(context.Context, int64, string, string, string, string) error {
	return nil
}
func (r *trustedPoolHTTPRepoStub) CountPendingSettlements(context.Context, int64) (int, error) {
	return 0, nil
}
func (r *trustedPoolHTTPRepoStub) ListPendingSettlements(_ context.Context, _, _ string, limit int) ([]service.TrustedPoolPendingSettlement, error) {
	r.listLimit = limit
	return []service.TrustedPoolPendingSettlement{}, nil
}
func (r *trustedPoolHTTPRepoStub) GetPendingSettlement(context.Context, string, string, string) (*service.TrustedPoolPendingSettlement, error) {
	return nil, service.ErrTrustedPoolSettlementNotFound
}
func (r *trustedPoolHTTPRepoStub) ResolvePendingSettlement(_ context.Context, seatID, settlementID string, input service.ResolveTrustedPoolSettlementInput) (*service.TrustedPoolSettlementResolution, error) {
	r.resolveCalls++
	return &service.TrustedPoolSettlementResolution{
		ExternalSeatID: seatID, SettlementID: settlementID, OperationID: input.OperationID,
		AssignmentEpoch: input.ExpectedAssignmentEpoch, RequestID: input.ExpectedRequestID,
		ActorClientID: input.ActorClientID, Reason: input.Reason, Evidence: input.Evidence, ResolvedAt: time.Now(),
	}, nil
}
func (r *trustedPoolHTTPRepoStub) SuspendSeat(context.Context, string, string, string) (*service.TrustedPoolSeat, error) {
	return r.seat, nil
}
func (r *trustedPoolHTTPRepoStub) FreezeSeat(context.Context, string, string, string) (*service.TrustedPoolSeat, error) {
	return r.seat, nil
}
func (r *trustedPoolHTTPRepoStub) RotateSeatCredential(context.Context, string, string, string, string, int64) (*service.TrustedPoolRotationResult, error) {
	return nil, nil
}
func (r *trustedPoolHTTPRepoStub) GetUsageRisk(context.Context, string, string, time.Time) (*service.TrustedPoolUsageRisk, error) {
	return nil, nil
}

type trustedPoolHTTPAuthRepoStub struct {
	client *service.TrustedPoolIntegrationClient
}

func (r *trustedPoolHTTPAuthRepoStub) GetIntegrationClient(context.Context, string) (*service.TrustedPoolIntegrationClient, error) {
	return r.client, nil
}
func (r *trustedPoolHTTPAuthRepoStub) ClaimIntegrationNonce(context.Context, string, string, time.Time) (bool, error) {
	return true, nil
}

func newTrustedPoolHTTPRouter(repo *trustedPoolHTTPRepoStub, scopes []string) (*gin.Engine, string) {
	gin.SetMode(gin.TestMode)
	secret := "integration-secret"
	digest := sha256.Sum256([]byte(secret))
	auth := service.NewTrustedPoolAuthService(&trustedPoolHTTPAuthRepoStub{client: &service.TrustedPoolIntegrationClient{
		ClientID: "platform-1", ExternalPoolID: "pool-1", SecretHash: hex.EncodeToString(digest[:]), Scopes: scopes,
	}}, nil)
	integration := service.NewTrustedPoolIntegrationService(repo, nil, nil, nil)
	router := gin.New()
	RegisterTrustedPoolRoutes(router.Group("/v1"), handler.NewTrustedPoolHandler(integration), auth)
	return router, secret
}

func trustedPoolHTTPRequest(method, path, body, secret string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("X-Integration-Client-ID", "platform-1")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestTrustedPoolSettlementListUnknownSeatReturns404(t *testing.T) {
	repo := &trustedPoolHTTPRepoStub{}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:read"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, trustedPoolHTTPRequest(http.MethodGet, "/v1/integrations/trusted-pools/seats/missing/settlements", "", secret))
	require.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestTrustedPoolReadCannotAccessSeatFromAnotherPool(t *testing.T) {
	repo := &trustedPoolHTTPRepoStub{seat: &service.TrustedPoolSeat{
		ID: 2, ExternalPoolID: "pool-2", ExternalSeatID: "other-seat",
	}}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:read"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, trustedPoolHTTPRequest(http.MethodGet,
		"/v1/integrations/trusted-pools/seats/other-seat/settlements", "", secret))
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Equal(t, []string{"pool-1"}, repo.requestedPools)
}

func TestTrustedPoolProvisionRejectsAuthenticatedClientPoolMismatch(t *testing.T) {
	repo := &trustedPoolHTTPRepoStub{}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:provision"})
	recorder := httptest.NewRecorder()
	body := `{"external_pool_id":"pool-2","external_seat_id":"seat-2","existing_group_id":9,"operation_id":"provision-2","principal_concurrency":1,"subscription_expires_at":"2027-01-01T00:00:00Z"}`

	router.ServeHTTP(recorder, trustedPoolHTTPRequest(http.MethodPost,
		"/v1/integrations/trusted-pools/seats/provision", body, secret))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Zero(t, repo.provisionCalls)
}

func TestTrustedPoolSettlementListClampsLimitTo200(t *testing.T) {
	repo := &trustedPoolHTTPRepoStub{seat: &service.TrustedPoolSeat{ID: 1, ExternalSeatID: "seat-1"}}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:read"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, trustedPoolHTTPRequest(http.MethodGet, "/v1/integrations/trusted-pools/seats/seat-1/settlements?limit=999", "", secret))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, 200, repo.listLimit)
}

func TestTrustedPoolSettlementResolveRequiresDedicatedScope(t *testing.T) {
	const path = "/v1/integrations/trusted-pools/seats/seat-1/settlements/pending-1/resolve"
	const body = `{"operation_id":"resolve-1","expected_assignment_epoch":3,"expected_request_id":"request-1","reason":"ledger checked","evidence":"ticket-1"}`
	repo := &trustedPoolHTTPRepoStub{seat: &service.TrustedPoolSeat{ID: 1, ExternalSeatID: "seat-1"}}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:write"})
	denied := httptest.NewRecorder()
	request := trustedPoolHTTPRequest(http.MethodPost, path, body, secret)
	request.Header.Set("Idempotency-Key", "resolve-1")
	router.ServeHTTP(denied, request)
	require.Equal(t, http.StatusForbidden, denied.Code)
	require.Zero(t, repo.resolveCalls)

	// 高权限人工核账必须显式授权；历史通配 scope 不得绕过独立凭据边界。
	router, secret = newTrustedPoolHTTPRouter(repo, []string{"*"})
	wildcardDenied := httptest.NewRecorder()
	request = trustedPoolHTTPRequest(http.MethodPost, path, body, secret)
	request.Header.Set("Idempotency-Key", "resolve-1")
	router.ServeHTTP(wildcardDenied, request)
	require.Equal(t, http.StatusForbidden, wildcardDenied.Code)
	require.Zero(t, repo.resolveCalls)

	router, secret = newTrustedPoolHTTPRouter(repo, []string{"settlement:resolve"})
	allowed := httptest.NewRecorder()
	request = trustedPoolHTTPRequest(http.MethodPost, path, body, secret)
	request.Header.Set("Idempotency-Key", "resolve-1")
	router.ServeHTTP(allowed, request)
	require.Equal(t, http.StatusOK, allowed.Code)
	require.Equal(t, 1, repo.resolveCalls)

	missingHeader := httptest.NewRecorder()
	router.ServeHTTP(missingHeader, trustedPoolHTTPRequest(http.MethodPost, path, body, secret))
	require.Equal(t, http.StatusBadRequest, missingHeader.Code)
	require.Equal(t, 1, repo.resolveCalls)

	mismatched := trustedPoolHTTPRequest(http.MethodPost, path, body, secret)
	mismatched.Header.Set("Idempotency-Key", "different-operation")
	mismatchedResponse := httptest.NewRecorder()
	router.ServeHTTP(mismatchedResponse, mismatched)
	require.Equal(t, http.StatusBadRequest, mismatchedResponse.Code)
	require.Equal(t, 1, repo.resolveCalls)
}

func TestTrustedPoolProvisionRequiresDedicatedScope(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"operation_id":"provision-1","external_pool_id":"pool-1","external_seat_id":"seat-1","existing_group_id":20,"principal_concurrency":2,"subscription_expires_at":"` + expiresAt + `"}`
	path := "/v1/integrations/trusted-pools/seats/provision"
	repo := &trustedPoolHTTPRepoStub{}

	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:write"})
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, trustedPoolHTTPRequest(http.MethodPost, path, body, secret))
	require.Equal(t, http.StatusForbidden, denied.Code)
	require.Zero(t, repo.provisionCalls)

	router, secret = newTrustedPoolHTTPRouter(repo, []string{"seat:provision"})
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, trustedPoolHTTPRequest(http.MethodPost, path, body, secret))
	require.Equal(t, http.StatusCreated, allowed.Code)
	require.Equal(t, 1, repo.provisionCalls)
	require.Equal(t, "platform-1", repo.provisionInput.ActorClientID)
	require.Contains(t, allowed.Body.String(), "sk-tp-response-secret")
	require.NotContains(t, allowed.Body.String(), "principal.invalid")
}

func TestTrustedPoolProvisionRejectsMismatchedIdempotencyKey(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"operation_id":"body-operation","external_pool_id":"pool-1","external_seat_id":"seat-1","existing_group_id":20,"principal_concurrency":2,"subscription_expires_at":"` + expiresAt + `"}`
	repo := &trustedPoolHTTPRepoStub{}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:provision"})
	request := trustedPoolHTTPRequest(http.MethodPost, "/v1/integrations/trusted-pools/seats/provision", body, secret)
	request.Header.Set("Idempotency-Key", "header-operation")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Zero(t, repo.provisionCalls)
}

func TestTrustedPoolCredentialAckRequiresDedicatedScope(t *testing.T) {
	const path = "/v1/integrations/trusted-pools/seats/seat-1/provision-credential/ack"
	const body = `{"provision_operation_id":"provision-1","claim_operation_id":"claim-1","claimed_by":"vault-record-1","credential_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	repo := &trustedPoolHTTPRepoStub{}

	router, secret := newTrustedPoolHTTPRouter(repo, []string{"seat:provision"})
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, trustedPoolHTTPRequest(http.MethodPost, path, body, secret))
	require.Equal(t, http.StatusForbidden, denied.Code)
	require.Zero(t, repo.ackCalls)

	router, secret = newTrustedPoolHTTPRouter(repo, []string{"credential:ack"})
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, trustedPoolHTTPRequest(http.MethodPost, path, body, secret))
	require.Equal(t, http.StatusOK, allowed.Code)
	require.Equal(t, 1, repo.ackCalls)
	require.Equal(t, "platform-1", repo.ackInput.ActorClientID)
	require.Contains(t, allowed.Body.String(), `"credential_claimed":true`)
	require.NotContains(t, allowed.Body.String(), "credential\"")
}

func TestTrustedPoolCredentialAckRejectsMismatchedIdempotencyKey(t *testing.T) {
	const path = "/v1/integrations/trusted-pools/seats/seat-1/provision-credential/ack"
	const body = `{"provision_operation_id":"provision-1","claim_operation_id":"body-claim","claimed_by":"vault-record-1","credential_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	repo := &trustedPoolHTTPRepoStub{}
	router, secret := newTrustedPoolHTTPRouter(repo, []string{"credential:ack"})
	request := trustedPoolHTTPRequest(http.MethodPost, path, body, secret)
	request.Header.Set("Idempotency-Key", "header-claim")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Zero(t, repo.ackCalls)
}
