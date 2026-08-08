# Sub2API Monitor

Independent monitoring center for multiple Sub2API deployments. It observes account availability and quota, evaluates alert policies, and delivers notifications through ntfy without changing monitored Sub2API source code.

## Project Status

Phase 1 and the current Phase 2 slices are complete. The runnable system supports multiple API-only or API+read-only-DB targets, account availability, passive and explicitly opted-in active quota observations, upstream billing-rate discovery, channel uptime monitoring, alert incidents, durable ntfy delivery, and an operations UI. The current source of truth is [docs/STATUS.md](docs/STATUS.md).

## Stack

- Backend: Python 3.13, FastAPI, Pydantic, SQLAlchemy 2, Alembic, httpx, asyncpg
- Frontend: React, TypeScript, Vite, TanStack Query, TanStack Table, React Router
- State: dedicated PostgreSQL owned by this project
- Delivery: Docker images and Docker Compose
- Notifications: ntfy JSON publish API with durable retry outbox

## Quick Start

```bash
cp .env.example .env
# Replace every placeholder secret in .env.
docker compose up -d --build --wait
```

Open `http://127.0.0.1:8080` and sign in with `MONITOR_ADMIN_USERNAME` and `MONITOR_ADMIN_PASSWORD`. Only the web port is published. The monitor database, API, and worker remain on the private Compose network.

For QA fixtures and the end-to-end smoke path:

```bash
docker compose --profile qa up -d --build --wait
MONITOR_SMOKE_PASSWORD="$MONITOR_ADMIN_PASSWORD" python3 qa/smoke.py
```

To monitor the sibling `sub2api-loc` Compose deployment over a dedicated API network, run these commands from the parent Sub2API project directory:

```bash
docker network inspect sub2api-monitor-target-net >/dev/null 2>&1 || \
  docker network create sub2api-monitor-target-net
docker network inspect sub2api-monitor-target-db-net >/dev/null 2>&1 || \
  docker network create sub2api-monitor-target-db-net
docker compose -f docker-compose.yml \
  -f sub2api-monitor/compose.sub2api-local.target.yaml up -d sub2api-loc
cd sub2api-monitor
docker compose -f compose.yaml -f compose.sub2api-local.yaml up -d --build --wait
```

Create an API-only target with base URL `http://sub2api-loc:8080` and an approved Sub2API Admin API Key. Set `MONITOR_ALLOW_PRIVATE_TARGETS=true` for this trusted private-network deployment. The API network contains only `sub2api-loc`, the monitor API, and the monitor worker. The separate DB network contains only target PostgreSQL, the monitor API, and the monitor worker. Redis, redeem, web, and the monitor database join neither target network. The QA profile is not required for a real target.

Runtime credentials may be supplied directly or through `MONITOR_MASTER_KEY_FILE`, `MONITOR_ADMIN_PASSWORD_FILE`, and `MONITOR_DATABASE_URL_FILE`. PostgreSQL also accepts `MONITOR_DB_PASSWORD_FILE`.

## Connection Modes

- `api_only`: exposes only capabilities discoverable through the supplied Sub2API API permissions.
- `full`: uses both API and read-only database access, combines observations, and records source/freshness for every value.

These are the two required V1 paths. A DB-only connector may be retained as a later compatibility/degraded mode, but is not a V1 onboarding contract.

Capabilities are probed per target. Support, current runtime state, and data freshness are reported independently; unknown values are never converted to zero.

### FULL read-only database setup

Create a separate PostgreSQL login on every monitored Sub2API database. Replace the password and database name before running this as a database administrator:

```sql
CREATE ROLE sub2api_monitor_ro LOGIN PASSWORD '<strong-random-password>'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE sub2api_monitor_ro SET default_transaction_read_only = on;
ALTER ROLE sub2api_monitor_ro SET statement_timeout = '5s';
ALTER ROLE sub2api_monitor_ro SET lock_timeout = '1s';
GRANT CONNECT ON DATABASE sub2api TO sub2api_monitor_ro;
GRANT USAGE ON SCHEMA public TO sub2api_monitor_ro;
GRANT SELECT (
  id, name, platform, type, status, schedulable, expires_at,
  auto_pause_on_expired, rate_limit_reset_at, overload_until,
  temp_unschedulable_until, updated_at, deleted_at, extra
) ON TABLE public.accounts TO sub2api_monitor_ro;
```

Use `postgresql://sub2api_monitor_ro:<password>@<host>:5432/<database>?sslmode=require` in the FULL target form. For a public TLS endpoint, select the downloaded `.crt`/`.pem` file or paste the complete PEM contents into **TLS server certificate (PEM)**; DER-formatted `.crt` files are converted to PEM in the browser. A path on the monitored server is not accessible to the monitor. The connection URL and certificate are encrypted together. Adjust the column grant only when a compatible Sub2API schema omits a listed column. Do not grant `credentials`. The connector rejects roles without access to `id`, roles with `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`, and transactions that are not read-only. It queries only fixed allowlisted account columns and quota keys.

FULL scheduled collection remains passive until active quota refresh is explicitly authorized. OpenAI Codex 5-hour/7-day snapshots, configured local limits, and supported provider snapshots include source, observation time, reset time, and freshness. Snapshots older than `MONITOR_TARGET_QUOTA_STALE_SECONDS` (default one hour), or past their reset time, remain visible as expired but do not fire or recover low-quota incidents.

### Opt-in active quota refresh

Set `MONITOR_ACTIVE_QUOTA_REFRESH_ENABLED=true` to permit active quota work globally, restart the API and worker, then enable **Active quota refresh** in the target capability panel and confirm its side effects. Both switches are required. The scheduler calls the existing Sub2API admin usage API with `source=active`; it never sends `force=true`. Defaults limit target attempts to every five minutes, each account to every fifteen minutes, and each run to twenty accounts. Attempts and outcomes are retained in the monitor database without raw provider payloads or secrets.

Active usage may make Sub2API contact the upstream provider, refresh a token, update its quota cache, or clear a recoverable account error. Disabling either switch stops new active calls without disabling passive account monitoring. Unsupported account types, including an OpenAI API key without configured local limits, remain quota-unknown rather than zero.

### Upstream billing-rate discovery

The **Upstream rates** page aggregates each account's configured cost multiplier and the target's `upstream_billing_probe` snapshot. It preserves the declared effective/resolved multiplier, peak multiplier, attempt time, freshness deadline, next probe time, failure reason, and whether automatic probing or rate synchronization is enabled. Operators can update the target-wide automatic-probe interval, toggle probing per account, and run an immediate probe. A changed resolved multiplier for an enabled OpenAI API-key account creates an `upstream.rate_multiplier.changed` incident and enters the existing ntfy outbox workflow. Immediate probes may contact the account's upstream Sub2API deployment and are audited.

### Channel monitoring

The **Channel monitors** page aggregates target-owned OpenAI, Anthropic, Gemini, and Grok channel checks. It exposes the primary and extra models, latest state, latency, seven-day availability, schedule, and live target history. Channel definitions can be created, edited, deleted, and run immediately through the monitor; the upstream API key remains masked and is never persisted in the monitor database. A degraded, failed, or error primary model enters the existing incident, recovery, and ntfy outbox workflow.

### Native operations monitoring

The **Operations** page aggregates the monitored target's existing read-only Ops APIs. Its overview, capacity, request/error, and system views cover dashboard trends, QPS/TPS, latency distribution, OpenAI token statistics, platform and user concurrency, account availability, group inventory/usage/capacity, request and upstream errors, request details, alert events, background jobs, system logs, auth-cache health, ingress health, and log-pipeline health. The connector calls only a fixed endpoint allowlist with bounded page sizes and recursively removes credentials, tokens, headers, passwords, and request bodies before returning data to the monitor UI.

### Account usage analytics

The **Accounts** page shows each account's configured multiplier and group membership. Opening an account reads the target's native 7, 30, or 90-day usage statistics on demand: requests, tokens, account cost, user-billed cost, standard cost, response time, active days, daily trend, model distribution, and inbound/upstream endpoint distribution. The monitor does not fan this request out across the account list, does not persist the returned analytics, and keeps missing values distinct from explicit upstream zeroes.

For public database targets, use `sslmode=require` plus the separately supplied PEM certificate. The connector pins the resolved public IP, requires the supplied certificate, validates its trust chain, and enforces TLS 1.2 or newer. `sslmode=verify-full` remains rejected because DNS pinning cannot preserve hostname verification; the monitor does not silently downgrade that mode.

## Documentation

- [V1 scope](docs/V1_SCOPE.md)
- [Capability matrix](docs/CAPABILITY_MATRIX.md)
- [UI state matrix](docs/UI_STATE_MATRIX.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Connector contract](docs/CONNECTOR_CONTRACT.md)
- [Data and identity contract](docs/DATA_CONTRACT.md)
- [Security boundary](docs/SECURITY.md)
- [Requirement traceability](docs/TRACEABILITY.md)
- [Docker acceptance](docs/DOCKER_ACCEPTANCE.md)
- [Delivery plan](docs/DELIVERY_PLAN.md)
- [Testing strategy](docs/TESTING.md)
- [Agent-team workflow](docs/AGENT_TEAM_WORKFLOW.md)
- [Phase 0 progress record](docs/progress/phase-0.md)
- [Phase 1 progress record](docs/progress/phase-1.md)
- [Phase 2 progress record](docs/progress/phase-2.md)
- [Phase evidence template](docs/progress/TEMPLATE.md)
- [Technology decision](docs/decisions/ADR-001-python-react.md)

## Scope Control

Each phase begins by updating its goals and acceptance criteria in `docs/STATUS.md` and `docs/progress/phase-N.md`. Scope changes require a documented change record and an update to the capability matrix before implementation.
