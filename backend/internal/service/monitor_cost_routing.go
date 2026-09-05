package service

import (
	"context"
	"errors"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// This namespaced gate never changes the operator's Schedulable switch.
const MonitorCostRoutingExtraKey = "monitor_cost_routing"

var ErrMonitorCostReplayRequired = errors.New("account suppressed by monitor cost policy; resend full conversation history without previous_response_id")

type MonitorCostRoutingControl struct {
	Version           int  `json:"version"`
	UnhealthyPriority int  `json:"unhealthy_priority"`
	Fallback          bool `json:"fallback"`
	Suppressed        bool `json:"suppressed"`
}

func (a *Account) MonitorCostRouting() (MonitorCostRoutingControl, bool) {
	if a == nil || !a.IsOpenAI() || a.Type != AccountTypeAPIKey {
		return MonitorCostRoutingControl{}, false
	}
	raw, ok := a.Extra[MonitorCostRoutingExtraKey].(map[string]any)
	if !ok || ParseExtraInt(raw["version"]) != 1 {
		return MonitorCostRoutingControl{}, false
	}
	control := MonitorCostRoutingControl{Version: 1, UnhealthyPriority: ParseExtraInt(raw["unhealthy_priority"])}
	control.Fallback, _ = raw["fallback"].(bool)
	control.Suppressed, _ = raw["suppressed"].(bool)
	return control, control.UnhealthyPriority >= 2
}

func (a *Account) IsMonitorCostSuppressed() bool {
	control, managed := a.MonitorCostRouting()
	return managed && control.Suppressed
}

// A protected fallback is last-resort, not a permanently preferred cheap route.
func monitorCostBetter(left, right *Account) bool {
	l, lm := left.MonitorCostRouting()
	r, rm := right.MonitorCostRouting()
	if !lm || !rm {
		return false
	}
	if l.Fallback != r.Fallback {
		return !l.Fallback
	}
	return left.Priority < right.Priority
}

func monitorCostPreferredPool(accounts []*Account) []*Account {
	var best *Account
	for _, a := range accounts {
		if _, managed := a.MonitorCostRouting(); managed && (best == nil || monitorCostBetter(a, best)) {
			best = a
		}
	}
	if best == nil {
		return accounts
	}
	out := make([]*Account, 0, len(accounts))
	for _, a := range accounts {
		if !monitorCostBetter(best, a) {
			out = append(out, a)
		}
	}
	return out
}

func (s *adminServiceImpl) SetMonitorCostRouting(ctx context.Context, id int64, priority int, control MonitorCostRoutingControl) (*Account, error) {
	if priority < 0 || priority > 2_000_000_000 || control.Version != 1 || control.UnhealthyPriority < 2 || control.UnhealthyPriority > 2_000_000_000 {
		return nil, infraerrors.BadRequest("INVALID_MONITOR_COST_ROUTING", "invalid monitor cost routing control")
	}
	account, err := s.accountRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !account.IsOpenAI() || account.Type != AccountTypeAPIKey {
		return nil, infraerrors.BadRequest("INVALID_MONITOR_COST_ACCOUNT", "monitor cost routing requires an OpenAI API-key account")
	}
	// A single column/JSONB patch plus scheduler outbox transaction; no snapshot
	// overwrite of credentials, quota state, or manual scheduling controls.
	rows, err := s.accountRepo.BulkUpdate(ctx, []int64{id}, AccountBulkUpdate{
		Priority: &priority,
		Extra: map[string]any{MonitorCostRoutingExtraKey: map[string]any{
			"version": 1, "unhealthy_priority": control.UnhealthyPriority, "fallback": control.Fallback, "suppressed": control.Suppressed,
		}},
	})
	if err != nil {
		return nil, err
	}
	if rows != 1 {
		return nil, ErrAccountNotFound
	}
	return s.accountRepo.GetByID(ctx, id)
}

func (s *defaultOpenAIAccountScheduler) hasCheaperMonitorAccount(ctx context.Context, req OpenAIAccountScheduleRequest, current *Account) bool {
	if _, managed := current.MonitorCostRouting(); !managed {
		return false
	}
	accounts, err := s.service.listSchedulableAccounts(ctx, req.GroupID, req.Platform)
	if err != nil {
		return false
	}
	for i := range accounts {
		a := &accounts[i]
		if _, excluded := req.ExcludedIDs[a.ID]; excluded {
			continue
		}
		if !a.IsSchedulable() || !monitorCostBetter(a, current) || !s.isAccountRequestCompatible(ctx, a, req) || !s.isAccountTransportCompatible(a, req.RequiredTransport) {
			continue
		}
		a = s.service.recheckSelectedOpenAIAccountFromDB(ctx, a, req.GroupID, req.Platform, req.RequestedModel, req.RequireCompact, req.RequiredCapability)
		if a != nil && a.IsSchedulable() && monitorCostBetter(a, current) && s.service.openAIAccountMatchesSchedulingGroup(a, req.GroupID) {
			return true
		}
	}
	return false
}

// A WebSocket connection is account-bound. Stop at the next turn, never cut
// an in-flight response or silently replay an incomplete conversation.
func (s *OpenAIGatewayService) CheckMonitorCostContinuation(ctx context.Context, account *Account) error {
	if account == nil || !account.IsOpenAI() || account.Type != AccountTypeAPIKey || s.accountRepo == nil {
		return nil
	}
	latest, err := s.accountRepo.GetByID(ctx, account.ID)
	if err != nil {
		return err
	}
	if latest == nil || latest.IsMonitorCostSuppressed() {
		return ErrMonitorCostReplayRequired
	}
	return nil
}
