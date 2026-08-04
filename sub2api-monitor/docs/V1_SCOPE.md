# V1 Scope

## Product Goal

Monitor accounts across multiple Sub2API deployments, identify unavailable or low-quota accounts early, and send deduplicated firing and recovery notifications through ntfy.

## Target Identity

Each deployment is a `target`. Accounts are globally identified by `(target_id, upstream_account_id)`. A target has a stable UUID, display name, labels, connection mode, policy assignment, collection schedule, and discovered capability set.

## V1 Functional Requirements

| ID | Requirement | Acceptance summary |
|---|---|---|
| TGT-01 | Manage multiple targets | Add, edit, disable, probe, and collect targets independently. |
| TGT-02 | Isolate failures | One slow or invalid target cannot delay another target's collection. |
| TGT-03 | Support graded access | `api_only` exposes only API-derived capabilities; `full` adds read-only DB capabilities without overstating missing data. |
| CAP-01 | Discover capabilities | Store support, runtime, and freshness dimensions independently with timestamps and reasons. |
| CAP-02 | Declare side effects | Every capability states whether collection is passive, calls an upstream provider, or may change target-side state. |
| ACC-01 | Account inventory | List accounts across targets with server-side filtering and stable global identity. |
| ACC-02 | Availability | Explain effective availability using status, schedulable, expiry, rate limit, overload, and temporary quarantine when present. |
| QTA-01 | Normalize quota | Represent percentage windows, balances, credits, reset times, source, and observed time without losing provider meaning. |
| QTA-02 | Detect stale data | Never treat missing or expired quota samples as healthy zero usage. |
| ALT-01 | Evaluate policies | Support warning, critical, exhausted, unavailable, group-capacity, stale-data, and recovery events. |
| ALT-02 | Control noise | Apply sustain duration, hysteresis, cooldown, reminder, deduplication, acknowledgement, and silence. |
| NTF-01 | Publish to ntfy | Route by target/policy, redact content, retry failures durably, and retain delivery history. |
| OPS-01 | Self-observability | Expose health, readiness, worker heartbeat, collection runs, and outbox state. |
| SEC-01 | Protect credentials | Secrets are write-only in APIs, encrypted at rest, redacted from logs, and never exposed to the browser. |
| DEP-01 | Docker deployment | Start API, worker, web, and monitoring PostgreSQL from an empty volume using Docker Compose. |

## V1 UI

- Overview: instance reachability, monitoring coverage, available accounts, low quota, firing incidents, failed collections.
- Targets: onboarding wizard, connection tests, capabilities, collection status, settings.
- Accounts: cross-target table and account detail drawer with availability reasons and quota windows.
- Alerts: firing, acknowledged, silenced, resolved, and notification delivery state.
- Policies: global defaults with per-target overrides.
- Notifications: ntfy destinations, routing, test publish, and delivery history.
- System: worker status, collection runs, audit records, and configuration diagnostics.

## V1 Defaults

- Availability scan: 15 seconds for DB-capable targets, configurable per target.
- API account refresh: 60 seconds, subject to target rate limits.
- Passive quota refresh: 5-10 minutes with jitter where supported.
- Active quota refresh: explicit per-target opt-in only; `force=true` remains disabled for scheduled collection.
- Quota warning: remaining at or below 20%.
- Quota critical: remaining at or below 5%.
- Recovery hysteresis: warning recovers above 30%; critical recovers above 10%.
- Stale threshold: provider-specific, default 20 minutes for actively refreshed quota.
- Monitoring readiness: account monitoring is enabled only when `accounts.inventory` and `accounts.availability` are supported and currently usable; incomplete targets may be saved as `not_ready` but are excluded from healthy-target counts.

## Explicit Non-Goals

- Modifying monitored Sub2API source code.
- Direct SQL/DDL/DML writes through monitored Sub2API database connections. Separately authorized active API probes may cause documented incidental target-side writes under the Probe Safety contract.
- Monitor-initiated management actions such as account disablement, credential rotation, or traffic rerouting. An explicitly authorized active usage API may have documented target-side incidental writes; that does not grant general management authority.
- Treating API-only access as equivalent to full access.
- Arbitrary compatibility with forks that replace the core account/API contracts.
- General infrastructure monitoring unrelated to account health and quota.
- Multi-channel notification beyond ntfy in V1.
- AI/LLM analysis or autonomous management in V1.

## Future Agent Boundary

V1 reserves two separate extension boundaries. A future edge Collector Agent may collect and buffer observations for targets that the Hub cannot reach. A future Analysis Agent may read normalized observations and propose actions through `AnalysisRun`, `Finding`, `Recommendation`, and `ApprovalAction` contracts. Neither can bypass the policy engine or publish notifications directly; management actions require explicit approval, authorization, idempotency, and audit.

V1 creates no Agent menu, route, empty page, credential, or runtime table. It preserves only stable target/account identities and observation/incident contracts needed by later phases.
