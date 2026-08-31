# V1 Capability Matrix

The UI and Hub API expose observed capabilities, not assumptions based on a selected mode. `API_ONLY` and `FULL` are the required V1 onboarding paths.

Last reviewed: 2026-08-30. Rows in this table describe implemented capability surfaces in the current candidate worktree. Production readiness is tracked separately in [STATUS.md](STATUS.md) and [DELIVERY_PLAN.md](DELIVERY_PLAN.md).

| Capability | V1 role | API_ONLY | FULL | Notes |
|---|---|---|---|---|
| Instance health/version | Diagnostic | Probe | Probe | Public health may remain available when authenticated calls fail. |
| Account inventory | Required | API must support | API or supported DB schema | Missing support leaves the target `not_ready`. |
| Effective schedulability | Required | API must support | API or supported DB schema | This is not an active upstream login test. |
| Per-account usage analytics | Optional, read-only | Read on demand | Read on demand | Native request, token, cost, latency, daily trend, model, and inbound/upstream endpoint statistics for 1-90 days. |
| Passive quota snapshots | Optional | Probe | Probe API and DB | Missing quota reduces coverage but does not block availability monitoring. |
| Active quota probe | Optional, opt-in | Provider/account probe | Provider/account probe | May call upstream and change target-side snapshots/state. |
| Upstream billing-rate probe | Optional, target-managed | Discover and operate | Discover and operate | Reads normalized snapshots; manual probes may call the account's upstream deployment. |
| Channel monitor inventory | Optional, target-managed | Discover and operate | Discover and operate | Aggregates status, latency, availability, and history without exposing channel API keys. |
| Streaming TTFT policy | Optional, read-only | Evaluate native Ops sample | Evaluate native Ops sample | Uses exact streaming sample count, configured percentile/window, minimum samples, warning/critical thresholds, and recovery hysteresis; it is not an end-user SLO guarantee. |
| Group membership/capacity | Optional | Probe | Probe API and DB | Missing capability is `unsupported`, never zero. |
| Native operations telemetry | Optional, read-only | Probe and aggregate | Probe and aggregate | Dashboard trends, QPS/TPS, latency, concurrency, account availability, requests/errors, OpenAI tokens, alerts, logs, pipeline health, group usage, and capacity. |
| Native Ops alert ingestion | Optional, read-only | Mirror and resolve | Mirror and resolve | Polls firing target alerts; incomplete snapshots never resolve known incidents. |
| Event subscriptions | Optional | ntfy/Telegram/Webhook | ntfy/Telegram/Webhook | Target, event-type, and severity filters share the durable at-least-once outbox; Webhooks support Bearer and HMAC-SHA256. |
| Account fault automation | Optional, manual approval | Recommend, then approve | Recommend, then approve | Fixed Admin API allowlist, separate audited approval for each action, five-minute minimum cooldown, idempotency, audit, and post-action verification; unattended execution cannot be enabled. |
| Cost-aware fault routing | Optional, explicit opt-in | Recommend or execute | Recommend or execute | OpenAI API-key accounts only; fixed 30-second control cycle, 25-second execution budget, availability and bound-channel-quality demotion, deterministic priority bands, decisions, audit, and repeated change notifications. |
| Actual account-switch events | Optional, read-only | Observe bounded recent usage | Observe bounded recent usage | First observation establishes a baseline; later same-session changes emit deduplicated events without persisting prompts, bodies, or credentials. |
| Model-detection safety pause | Optional, controlled | Pause mutation and suppress frozen state | Pause mutation and suppress frozen state | Pauses before upstream mutation; frozen detection snapshots do not appear as current dashboard truth. |
| API/DB consistency check | Full-mode required | N/A | Must pass | Mismatch blocks full-mode merge. |
| Target DB fallback | Optional | N/A | Schema/permission probe | Read-only and limited to allowlisted queries. |

Capability values independently report `support_state` (`unknown` until conclusively probed), `runtime_state`, and `freshness`, plus scope, enablement, source, side effects, attempt/success/error timestamps, and reason. The frontend renders each dimension explicitly rather than inferring a healthy state. Provider/account-scoped support is never promoted to unsupported peers.

DB-only access is a possible post-V1 compatibility mode, not a release requirement. It must not be silently promoted to `FULL`.
