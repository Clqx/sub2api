# Architecture

## Runtime Roles

One repository and one application image provide separate process roles:

- `api`: FastAPI REST API, authentication, target/policy management, query endpoints, and static frontend fallback if packaged together.
- `worker`: collection scheduling, target connectors, normalization, policy evaluation, incident transitions, and notification outbox delivery.
- `collector-agent`: reserved edge-collector role for a later release; not enabled in V1.
- `web`: React static assets served by a small unprivileged web server or packaged into the API image after evaluation.

The API and worker share only the monitor-owned PostgreSQL. Background collection never runs inside an API web worker.

## Module Boundaries

```text
backend/app/
  api/              HTTP routes and schemas
  auth/             monitor UI authentication and authorization
  targets/          target lifecycle and capability inventory
  connectors/       Sub2API API and PostgreSQL adapters
  observations/     normalized account/quota models
  collection/       schedules, leases, runs, backoff
  policies/         rule evaluation and incident transitions
  notifications/    ntfy publisher and transactional outbox
  audit/            security and configuration audit events
  agent_contract/   future collector/analysis agent DTOs only

frontend/src/
  app/              routing and application shell
  features/targets/
  features/accounts/
  features/incidents/
  features/policies/
  features/notifications/
  features/system/
  api/              generated OpenAPI client
```

## Collection Flow

1. Scheduler claims a due target using a PostgreSQL lease/advisory lock.
2. Connector probes or reuses the target capability set.
3. API and/or DB adapters collect only supported observations.
4. Normalizer emits source-tagged account and quota observations.
5. A transaction stores observations, evaluates state transitions, creates incidents, and appends notification outbox rows.
6. Notification dispatcher publishes to ntfy and records retry/delivery state.

## Source Precedence

Full mode does not silently overwrite one source with another:

- API is preferred for actively refreshed quota when it is newer and valid.
- DB is preferred for durable scheduling fields and passive quota snapshots.
- Every normalized value records `source`, `observed_at`, and `freshness`.
- Conflicting fresh values generate a data-quality observation and follow a documented per-field precedence rule.
- The precedence table and binding trust window are defined in `CONNECTOR_CONTRACT.md`; every selected value links back to its source observation.
- API and DB connector health remain independent. A full target with one failed connector is `degraded`, not wholly healthy or offline.

## Monitor-Owned Data

Initial tables are expected to include:

- `users`, `sessions`
- `targets`, `target_secrets`, `target_capabilities`
- `collection_runs`, `collector_leases`
- `accounts`, `account_observations`, `quota_samples`
- `policies`, `policy_bindings`, `silences`
- `incidents`, `incident_transitions`
- `notification_channels`, `notification_outbox`, `notification_deliveries`
- `audit_events`
- future: `analysis_runs`, `analysis_findings`, `recommendations`, `approval_actions`

## Reliability

- PostgreSQL-backed leases prevent duplicate collection across workers.
- Incident uniqueness and a transactional outbox prevent duplicate state transitions.
- ntfy delivery is at-least-once; ambiguous HTTP outcomes may duplicate a notification but cannot lose the durable event.
- Per-target timeout, concurrency limit, jitter, exponential backoff, and circuit state isolate failures.
- Collection payloads are bounded and lists use cursor pagination.
- Monitor-facing lists use cursor pagination; upstream adapters honor each target's bounded native pagination.

## Security

- Target URLs are validated against an explicit network policy to reduce SSRF risk.
- Database connectors execute fixed, parameterized, read-only queries and validate transaction read-only mode.
- API/DB credentials are encrypted using an application master key supplied outside the database.
- API and DB fingerprints are cross-checked before full mode is enabled to prevent merging different Sub2API instances.
- A fingerprint mismatch blocks merge and persistence of combined observations until the operator corrects the target configuration.
- Target API keys are treated as administrator credentials; connectors immediately project responses through field allowlists and never persist raw `extra` payloads.
- Secret fields are accepted write-only and returned only as `configured: true`.
- Logs use structured allowlisted fields and centralized redaction.
- The browser communicates only with the monitor API and never receives target credentials.
- Future Analysis Agent code consumes normalized observations only. A future Collector Agent receives a narrowly scoped collection configuration and has no policy or notification authority.

## Docker Topology

V1 Compose services:

- `web`
- `api`
- `worker`
- `monitor-postgres`

Redis is intentionally excluded from V1. PostgreSQL provides leases, durable schedules, and outbox semantics until measured scale requires another component.
