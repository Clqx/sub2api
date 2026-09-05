package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func monitorTestAccount(id int64, priority int, fallback, suppressed bool) Account {
	return Account{ID: id, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, Concurrency: 1, GroupIDs: []int64{10}, Priority: priority,
		Extra: map[string]any{MonitorCostRoutingExtraKey: map[string]any{"version": 1, "unhealthy_priority": 100000, "fallback": fallback, "suppressed": suppressed}},
	}
}

func TestMonitorCostSuppressionDoesNotOverrideManualDisable(t *testing.T) {
	a := monitorTestAccount(1, 100000, false, true)
	require.False(t, a.IsSchedulable())
	a.Priority = 1 // An unrelated/manual priority edit cannot clear the gate.
	require.False(t, a.IsSchedulable())
	a.Extra[MonitorCostRoutingExtraKey].(map[string]any)["suppressed"] = false
	require.True(t, a.IsSchedulable())
	a.Schedulable = false
	require.False(t, a.IsSchedulable())
	a = monitorTestAccount(2, 500, true, false)
	require.True(t, a.IsSchedulable())
	a.Status = StatusDisabled
	require.False(t, a.IsSchedulable())
}

func TestMonitorCostStickySwitchAndSuddenRecovery(t *testing.T) {
	for _, advanced := range []string{"true", "false"} {
		t.Run("advanced="+advanced, func(t *testing.T) { monitorCostStickyScenario(t, advanced) })
	}
}

func monitorCostStickyScenario(t *testing.T, advanced string) {
	resetOpenAIAdvancedSchedulerSettingCacheForTest()
	defer resetOpenAIAdvancedSchedulerSettingCacheForTest()
	accounts := []Account{monitorTestAccount(1, 300, false, false), monitorTestAccount(2, 500, false, false), monitorTestAccount(3, 1, true, false)}
	cache := &schedulerTestGatewayCache{sessionBindings: map[string]int64{"openai:monitor-session": 1}}
	svc := &OpenAIGatewayService{
		accountRepo: schedulerTestOpenAIAccountRepo{accounts: accounts}, cache: cache, cfg: &config.Config{},
		rateLimitService: newOpenAIAdvancedSchedulerRateLimitService(advanced), concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
	}
	group := int64(10)
	selectAccount := func(want int64) {
		t.Helper()
		selection, _, err := svc.SelectAccountWithScheduler(context.Background(), &group, "", "monitor-session", "gpt-5.1", nil, OpenAIUpstreamTransportAny, false)
		require.NoError(t, err)
		require.Equal(t, want, selection.Account.ID)
		if selection.ReleaseFunc != nil {
			selection.ReleaseFunc()
		}
	}
	selectAccount(1)
	accounts[0].Extra[MonitorCostRoutingExtraKey].(map[string]any)["suppressed"] = true
	selectAccount(2) // A rising above the ceiling cannot retain its sticky session.
	accounts[1].Extra[MonitorCostRoutingExtraKey].(map[string]any)["suppressed"] = true
	selectAccount(3) // Protected fallback remains usable even at a high upstream rate.
	accounts[0].Priority = 100
	accounts[0].Extra[MonitorCostRoutingExtraKey].(map[string]any)["suppressed"] = false
	selectAccount(1) // Sudden price drop switches the same session off fallback.
	selectAccount(1) // Equal-cost steady state retains the session.
}

func TestMonitorCostWebSocketNextTurnChecksLatestGate(t *testing.T) {
	stale := monitorTestAccount(1, 300, false, false)
	latest := monitorTestAccount(1, 100000, false, true)
	svc := &OpenAIGatewayService{accountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{latest}}}
	require.ErrorContains(t, svc.CheckMonitorCostContinuation(context.Background(), &stale), "resend full conversation")
}

func TestMonitorCostPreviousResponseRequiresExplicitReplay(t *testing.T) {
	for _, advanced := range []string{"true", "false"} {
		t.Run("advanced="+advanced, func(t *testing.T) {
			resetOpenAIAdvancedSchedulerSettingCacheForTest()
			defer resetOpenAIAdvancedSchedulerSettingCacheForTest()
			ctx := context.Background()
			group := int64(10)
			account := monitorTestAccount(1, 100000, false, true)
			account.Extra["openai_apikey_responses_websockets_v2_enabled"] = true
			cfg := &config.Config{}
			cfg.Gateway.OpenAIWS.Enabled = true
			cfg.Gateway.OpenAIWS.APIKeyEnabled = true
			cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
			cfg.Gateway.OpenAIWS.StickyResponseIDTTLSeconds = 3600
			svc := &OpenAIGatewayService{
				accountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{account, monitorTestAccount(2, 500, true, false)}},
				cache:       &schedulerTestGatewayCache{}, cfg: cfg,
				rateLimitService:   newOpenAIAdvancedSchedulerRateLimitService(advanced),
				concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
			}
			require.NoError(t, svc.getOpenAIWSStateStore().BindResponseAccount(ctx, group, "resp_monitor_cost", 1, time.Hour))
			selection, _, err := svc.SelectAccountWithScheduler(ctx, &group, "resp_monitor_cost", "", "gpt-5.1", nil, OpenAIUpstreamTransportAny, false)
			require.ErrorIs(t, err, ErrMonitorCostReplayRequired)
			require.Nil(t, selection, "must not send an account-bound response ID to fallback")
		})
	}
}
