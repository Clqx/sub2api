# Sub2API Monitor

Independent monitoring center for multiple Sub2API deployments. It observes account availability and quota, evaluates alert policies, and delivers notifications through ntfy without changing monitored Sub2API source code.

## Project Status

Phase 1, the first Phase 2 FULL slice, and the active-quota refresh increment are complete. The runnable system supports multiple API-only or API+read-only-DB targets, account availability, passive and explicitly opted-in active quota observations, alert incidents, durable ntfy delivery, and an operations UI. Real `sub2api-local` integration and independent QA passed; remaining provider mappings and V1 noise-control workflows stay in Phase 2. The current source of truth is [docs/STATUS.md](docs/STATUS.md).

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

Use `postgresql://sub2api_monitor_ro:<password>@<host>:5432/<database>` in the FULL target form. Adjust the column grant only when a compatible Sub2API schema omits a listed column. Do not grant `credentials`. The connector rejects roles without access to `id`, roles with `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`, and transactions that are not read-only. It queries only fixed allowlisted account columns and quota keys.

FULL scheduled collection remains passive until active quota refresh is explicitly authorized. OpenAI Codex 5-hour/7-day snapshots, configured local limits, and supported provider snapshots include source, observation time, reset time, and freshness. Snapshots older than `MONITOR_TARGET_QUOTA_STALE_SECONDS` (default one hour), or past their reset time, remain visible as expired but do not fire or recover low-quota incidents.

### Opt-in active quota refresh

Set `MONITOR_ACTIVE_QUOTA_REFRESH_ENABLED=true` to permit active quota work globally, restart the API and worker, then enable **Active quota refresh** in the target capability panel and confirm its side effects. Both switches are required. The scheduler calls the existing Sub2API admin usage API with `source=active`; it never sends `force=true`. Defaults limit target attempts to every five minutes, each account to every fifteen minutes, and each run to twenty accounts. Attempts and outcomes are retained in the monitor database without raw provider payloads or secrets.

Active usage may make Sub2API contact the upstream provider, refresh a token, update its quota cache, or clear a recoverable account error. Disabling either switch stops new active calls without disabling passive account monitoring. Unsupported account types, including an OpenAI API key without configured local limits, remain quota-unknown rather than zero.

For public database targets, DNS-pinned connections currently reject `sslmode=verify-full` because asyncpg cannot preserve the original hostname for certificate verification while connecting to a validated IP. Use a trusted private target network or another supported SSL mode; the monitor does not silently downgrade hostname verification.

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
