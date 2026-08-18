//go:build unit

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type trustedPoolGatewayAdmissionStub struct {
	guarded      bool
	err          error
	releaseCalls int
	settled      bool
}

func (s *trustedPoolGatewayAdmissionStub) AcquireGatewayAdmission(ctx context.Context, _ int64) (func(), bool, error) {
	if s.err != nil {
		return nil, s.guarded, s.err
	}
	if !s.guarded {
		return nil, false, nil
	}
	return func() {
		s.releaseCalls++
		s.settled = service.IsTrustedPoolSettlementSucceeded(ctx)
	}, true, nil
}

func trustedPoolGatewayGuardRouter(stub TrustedPoolGatewayAdmission, method, path string, reached *bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(ContextKeyAPIKey), &service.APIKey{ID: 9})
		c.Next()
	})
	router.Use(TrustedPoolGatewayGuard(stub))
	router.Handle(method, path, func(c *gin.Context) {
		*reached = true
		c.Status(http.StatusNoContent)
	})
	return router
}

func TestTrustedPoolGatewayGuardHoldsLeaseThroughHandler(t *testing.T) {
	stub := &trustedPoolGatewayAdmissionStub{guarded: true}
	reached := false
	router := trustedPoolGatewayGuardRouter(stub, http.MethodGet, "/v1/models", &reached)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.True(t, reached)
	require.Equal(t, 1, stub.releaseCalls)
}

func TestTrustedPoolGatewayGuardBlocksSuspendedSeat(t *testing.T) {
	stub := &trustedPoolGatewayAdmissionStub{guarded: true, err: service.ErrTrustedPoolSeatSuspended}
	reached := false
	router := trustedPoolGatewayGuardRouter(stub, http.MethodGet, "/v1/models", &reached)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.False(t, reached)
}

func TestTrustedPoolGatewayGuardPassesNonSeat(t *testing.T) {
	stub := &trustedPoolGatewayAdmissionStub{guarded: false}
	reached := false
	router := trustedPoolGatewayGuardRouter(stub, http.MethodGet, "/v1/models", &reached)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.True(t, reached)
}

func TestTrustedPoolGatewayGuardRejectsAsyncSubmission(t *testing.T) {
	stub := &trustedPoolGatewayAdmissionStub{guarded: true}
	reached := false
	router := trustedPoolGatewayGuardRouter(stub, http.MethodPost, "/v1/images/generations/async", &reached)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/images/generations/async", nil))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.False(t, reached)
	require.Equal(t, 1, stub.releaseCalls)
	require.True(t, stub.settled, "Guard 自身拒绝异步提交时确定没有计费，可安全完成 barrier")
}

func TestTrustedPoolGatewayGuardNoBillingRoutesResolveSettlement(t *testing.T) {
	for _, path := range []string{"/v1/models", "/v1/usage", "/v1/images/tasks/task-1", "/v1/videos/request-1/content"} {
		t.Run(path, func(t *testing.T) {
			stub := &trustedPoolGatewayAdmissionStub{guarded: true}
			reached := false
			router := trustedPoolGatewayGuardRouter(stub, http.MethodGet, path, &reached)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			require.True(t, reached)
			require.True(t, stub.settled, "显式非计费路由不得遗留 pending")
		})
	}
}

func TestTrustedPoolGatewayGuardUnknownEarlyExitRemainsUnresolved(t *testing.T) {
	stub := &trustedPoolGatewayAdmissionStub{guarded: true}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(ContextKeyAPIKey), &service.APIKey{ID: 9})
		c.Next()
	})
	router.Use(TrustedPoolGatewayGuard(stub))
	router.GET("/v1/unknown-billable", func(*gin.Context) { panic("early panic") })

	require.Panics(t, func() {
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/unknown-billable", nil))
	})
	require.Equal(t, 1, stub.releaseCalls)
	require.False(t, stub.settled, "未知路由早退或 panic 必须保持 unresolved")
}

func TestTrustedPoolGatewayGuardDoesNotBypassPotentiallyBillableGET(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/v1/realtime", "/v1/live/call-1"} {
		t.Run(path, func(t *testing.T) {
			stub := &trustedPoolGatewayAdmissionStub{guarded: true}
			reached := false
			router := trustedPoolGatewayGuardRouter(stub, http.MethodGet, path, &reached)
			router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
			require.False(t, stub.settled)
		})
	}
}
