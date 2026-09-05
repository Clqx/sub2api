package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMonitorCostRoutingHandlerRequiresPriorityAndConfirmsEnforcement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAccountHandler(&stubAdminService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router.PUT("/accounts/:id/monitor-cost-routing", handler.SetMonitorCostRouting)
	for _, tc := range []struct {
		name   string
		id     string
		body   string
		status int
	}{
		{"missing priority", "1", `{"control":{"version":1}}`, http.StatusBadRequest},
		{"invalid account", "0", `{"priority":0}`, http.StatusBadRequest},
		{"explicit zero priority", "1", `{"priority":0,"control":{"version":1,"unhealthy_priority":100000,"fallback":false,"suppressed":true}}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/accounts/"+tc.id+"/monitor-cost-routing", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equal(t, tc.status, response.Code)
			if tc.status == http.StatusOK {
				var payload struct {
					Data struct {
						Priority   int  `json:"priority"`
						Enforced   bool `json:"enforced"`
						Suppressed bool `json:"suppressed"`
					} `json:"data"`
				}
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
				require.Zero(t, payload.Data.Priority)
				require.True(t, payload.Data.Enforced)
				require.True(t, payload.Data.Suppressed)
			}
		})
	}
}
