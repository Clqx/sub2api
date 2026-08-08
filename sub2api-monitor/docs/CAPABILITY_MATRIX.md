# V1 Capability Matrix

The UI and Hub API expose observed capabilities, not assumptions based on a selected mode. `API_ONLY` and `FULL` are the required V1 onboarding paths.

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
| Group membership/capacity | Optional | Probe | Probe API and DB | Missing capability is `unsupported`, never zero. |
| Native operations telemetry | Optional, read-only | Probe and aggregate | Probe and aggregate | Dashboard trends, QPS/TPS, latency, concurrency, account availability, requests/errors, OpenAI tokens, alerts, logs, pipeline health, group usage, and capacity. |
| API/DB consistency check | Full-mode required | N/A | Must pass | Mismatch blocks full-mode merge. |
| Target DB fallback | Optional | N/A | Schema/permission probe | Read-only and limited to allowlisted queries. |

Capability values independently report `support_state` (`unknown` until conclusively probed), `runtime_state`, and `freshness`, plus scope, enablement, source, side effects, attempt/success/error timestamps, and reason. The frontend renders each dimension explicitly rather than inferring a healthy state. Provider/account-scoped support is never promoted to unsupported peers.

DB-only access is a possible post-V1 compatibility mode, not a release requirement. It must not be silently promoted to `FULL`.
