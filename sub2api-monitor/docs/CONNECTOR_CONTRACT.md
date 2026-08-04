# Connector Contract

## Connection Modes

### API Only

Requires a Sub2API base URL and one supported administrator credential (`x-api-key`, JWT access token, or access/refresh token pair). It may provide:

- public health
- authenticated version
- account and group inventory exposed by the installed API version
- status and scheduling fields returned by account endpoints
- provider quota returned by `/api/v1/admin/accounts/{id}/usage`
- active quota refresh where the endpoint/provider supports it

Fields or endpoints absent from the target API are `unsupported`, not zero.

### Full

Requires both the API credentials above and a PostgreSQL read-only connection. It provides API-only capabilities and may add:

- account status and durable scheduling fields
- account/group membership and capacity
- persisted passive quota snapshots
- local usage aggregates when the required schema is supported

- API failure fallback to durable DB observations
- comparison of API and DB observations
- richer freshness and data-quality reporting

Full mode is not permission escalation. Each capability remains bounded by the supplied API and DB permissions. The monitor must never write the target database. API and DB identities must be cross-checked before observations are merged.

### Optional DB-Only Compatibility

A passive DB-only connector may be added after V1 for environments where no API credential can be supplied. It is not part of the V1 onboarding or release gate and cannot initiate provider quota refresh.

## Capability Model

```json
{
  "key": "quota.active_refresh",
  "scope": {"type": "provider", "id": "anthropic"},
  "support_state": "supported",
  "runtime_state": "healthy",
  "freshness": "fresh",
  "enabled": false,
  "source": "api",
  "side_effect": "upstream_call_and_possible_target_write",
  "reason": null,
  "last_attempt_at": "2026-08-03T10:00:00Z",
  "last_success_at": "2026-08-03T10:00:00Z",
  "last_error_at": null
}
```

Support states:

- `unknown`: not probed or no conclusive support result exists
- `supported`
- `unsupported`
- `permission_denied`

Runtime states:

- `healthy`
- `unavailable`
- `misconfigured`
- `disabled`

Freshness states:

- `fresh`
- `stale`
- `missing`

Support never changes merely because the latest call failed, and a supported capability may have `runtime_state=unavailable` with `freshness=stale`. A first probe timeout, 5xx, or unavailable authentication service leaves support `unknown`; only an explicit contract/schema absence such as a conclusive 404 or missing inspected DB field becomes `unsupported`. `enabled` is configuration, not proof of support. Capability scope is `target`, `provider`, or `account`; target-level summaries must not promote support from one provider/account to all others.

Allowed side-effect classes:

- `none`: local read from the target API or read-only database
- `upstream_call`: invokes an external provider but does not intentionally write target state
- `upstream_call_and_possible_target_write`: target implementation may refresh tokens, write quota snapshots, or clear recoverable errors

Minimum capability keys:

- `instance.health`
- `instance.version`
- `accounts.inventory`
- `accounts.availability`
- `groups.inventory`
- `groups.capacity`
- `quota.passive`
- `quota.active_refresh`
- `quota.balance`
- `quota.credits`

## Aggregate Target State

Target responses keep these aggregates separate:

- `connection_state`: per-connector reachability/authentication for API and DB
- `monitoring_readiness`: `ready`, `degraded`, or `not_ready`
- `coverage_level`: the supported account/quota/group capability set

Account monitoring requires supported and usable `accounts.inventory` and `accounts.availability`. A target that only passes public health may be saved for correction but stays `not_ready`, cannot start account monitoring, and is excluded from healthy-target counts. A full target with one failed connector is `degraded`. API/DB fingerprint mismatch is `not_ready` and no merged observation may be stored.

## Full-Mode Binding

`FULL` is enabled only after API and DB evidence identifies the same target:

- Prefer a stable deployment identifier exposed by both connectors when a supported target version provides one.
- Otherwise compare a time-bounded signature of allowlisted stable account IDs plus version/schema evidence from API and DB. Raw IDs are not stored in the fingerprint record.
- An empty target or evidence without a common stable identifier is inconclusive and remains API-only/`not_ready` for full merge; an operator label is not identity proof.
- Evidence stores method, hashes, confidence, checked time, and expiry. Connector URL/database/credential changes force immediate revalidation; unchanged targets are revalidated at least every 24 hours.
- A prior verified binding permits isolated DB fallback for at most one hour during API outage. The target is `degraded`; after the trust window expires, DB diagnostics continue but current account/quota state is not advanced.
- Mismatch stops current-state updates and full-mode evaluation. Each connector's diagnostic result remains isolated for repair and audit.

These rules detect ordinary misconfiguration, not deliberate cloned targets. Strong identity requires a future common deployment identifier in Sub2API.

## Full-Mode Field Precedence

| Normalized field | Preferred source | Freshness limit | Conflict action |
|---|---|---|---|
| Account identity/provider | API, verified by DB | Until next inventory run | Quarantine unmatched rows; never merge by display name. |
| Enabled/status/scheduling fields | Newest supported DB observation | Two availability intervals | Fresh disagreement marks data quality degraded and suppresses a destructive interpretation. |
| Expiry/rate-limit/quarantine times | Newest observation by field | Provider/field policy | Preserve both evidence values; evaluate the more conservative availability until reconciled. |
| Passive quota snapshot | Newest valid API or DB snapshot | Provider stale threshold | Equal-time mismatch marks sample degraded; do not average. |
| Active quota result | Explicit active API observation | Active schedule plus grace | Never overwrite it with an older passive snapshot. |
| Quota reset time | Same observation as selected quota value | Same as selected sample | Do not combine quota value and reset time from different samples. |
| Group membership/capacity | Newest complete supported source | Inventory interval plus grace | Incomplete/conflicting set is degraded and excluded from capacity totals. |

Every selection retains source observation IDs. Fixture contract tests cover precedence, expiry, conflicts, and source recovery.

## Normalized Quota Window

```json
{
  "kind": "five_hour",
  "label": "5 hour quota",
  "utilization_percent": 82.4,
  "remaining_percent": 17.6,
  "remaining_value": null,
  "unit": "percent",
  "reset_at": "2026-08-03T14:00:00Z",
  "observed_at": "2026-08-03T09:58:00Z",
  "source": "sub2api_api",
  "freshness": "fresh"
}
```

Unknown numeric values remain `null`. Provider-specific window identifiers and explicitly allowlisted non-secret metadata may be retained alongside the normalized fields; raw provider payloads are not persisted.

## Compatibility Rules

- Probe behavior and fields, not version strings alone.
- API adapters ignore unknown response fields.
- DB adapters inspect `information_schema` before selecting optional columns.
- Adapter queries use explicit column and JSON-key allowlists.
- A target with partial permissions becomes degraded while other capabilities continue.
- Official/common Sub2API schemas are supported by fixtures. A fork that changes core contracts requires a connector adapter.

## Authentication

V1 API strategies:

- static `x-api-key` administrator key where supported
- static bearer access token
- rotating access/refresh token pair

The monitor does not store an administrator password. CAPTCHA/TOTP login bootstrap is performed outside the monitor, then the resulting token pair is supplied as a secret.

Sub2API API keys are currently treated as full administrator credentials, not read-only scopes. The monitor requests no more credentials than the selected mode requires, encrypts them at rest, and projects account responses through an allowlist before persistence. Raw account `extra` data is neither stored nor logged.

## Probe Safety

- Connection tests are read-only.
- Connection tests use only public health, authenticated version, paginated account inventory, and fixed DB identity/schema queries; they never call account usage/active endpoints.
- Active quota calls require explicit per-target opt-in and are rate-limited per target and account.
- Capability support and operator enablement are separate fields; schedules run only when both are true.
- `force=true` is disabled for scheduled collection.
- Active calls that may refresh tokens or update passive snapshots are marked as non-passive capabilities in the UI.
- Enabling a non-passive capability requires a side-effect summary and a separate confirmation after target onboarding.
- Every active attempt records target/account, actor or scheduler, before/after observation metadata, outcome, and correlation ID without secrets.
- A global and per-target emergency switch stops new active probes without disabling passive monitoring.
- Connection tests and capability discovery never invoke an active probe.
- If a target version cannot bound or describe the endpoint's side effects, active probing is `unsupported` for that target.

The monitor's own list APIs use cursor pagination. Upstream Sub2API adapters use the target's native page/page-size contract with bounded page count and response size, then normalize results internally.
