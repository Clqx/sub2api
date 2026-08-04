# Backend

FastAPI API and independent worker for Sub2API Monitor. It supports `api_only`
and API+read-only-DB `full` targets, passive account/quota collection, and an
explicitly opted-in scheduled active-usage capability. Scheduled active calls
use `source=active` and never send `force=true`.

## Configuration

Required environment variables:

```text
MONITOR_DATABASE_URL=postgresql+asyncpg://monitor:password@postgres:5432/monitor
MONITOR_MASTER_KEY=a-long-random-application-key
MONITOR_ADMIN_USERNAME=admin
MONITOR_ADMIN_PASSWORD=a-long-random-admin-password
```

Important optional settings:

```text
MONITOR_ALLOW_PRIVATE_TARGETS=false
MONITOR_CONNECTOR_TIMEOUT_SECONDS=10
MONITOR_CONNECTOR_MAX_PAGES=100
MONITOR_WORKER_CONCURRENCY=8
MONITOR_WORKER_POLL_SECONDS=2
```

Private RFC1918/loopback targets are rejected unless
`MONITOR_ALLOW_PRIVATE_TARGETS=true`. Target credentials and ntfy tokens are
encrypted before storage and are never returned by the API.

## Local Start

With PostgreSQL available and the environment configured:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
.venv/bin/python -m app.worker
```

The API process never schedules background collection. `POST
/api/v1/targets/{id}/collect` creates a durable queued run consumed by the
worker.

## Main API

```text
POST   /api/v1/auth/login
GET    /api/v1/auth/me
CRUD   /api/v1/targets
POST   /api/v1/targets/{id}/probe
POST   /api/v1/targets/{id}/collect
GET    /api/v1/targets/{id}/capabilities
GET    /api/v1/accounts
GET    /api/v1/accounts/{id}/quota
POST/GET/PUT /api/v1/policies
GET    /api/v1/incidents
POST   /api/v1/incidents/{id}/ack
POST   /api/v1/notification-channels
POST   /api/v1/notification-channels/{id}/test
GET    /api/v1/runs
GET    /api/v1/outbox
GET    /api/v1/system/status
GET    /health
GET    /ready
```

Target onboarding accepts `x_api_key`, `bearer`, or `token_pair` credentials.
Only the configured status is returned. Connection probe calls exactly public
health, authenticated version, and bounded paginated account inventory.

## Tests

```bash
.venv/bin/pytest
```

Tests use an isolated SQLite database and fake HTTP transports. Production
state is PostgreSQL; Alembic is the only supported schema upgrade path.
