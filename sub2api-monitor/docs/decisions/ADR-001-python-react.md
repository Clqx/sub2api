# ADR-001: Python and React Stack

Status: accepted for planning

Date: 2026-08-03

## Context

The product needs pluggable HTTP/PostgreSQL collectors, policy evaluation, a multi-target operations UI, Docker deployment, and a future analysis Agent boundary. The first release prioritizes common monitoring workflows and maintainability over maximum throughput.

## Decision

Use:

- Python 3.13 with FastAPI, Pydantic, SQLAlchemy 2, Alembic, httpx, asyncpg, and pytest.
- React with TypeScript, Vite, React Router, TanStack Query, TanStack Table, and Playwright.
- PostgreSQL as the monitor-owned state, lease, incident, and notification outbox store.
- Separate API and worker processes from one backend codebase/image.
- OpenAPI as the frontend/backend contract source.
- Docker Compose as the V1 reference deployment.

## Consequences

- Provider adapters and the future Agent ecosystem are straightforward to extend in Python.
- React supports a dense operational interface and generated typed API client.
- Worker correctness must not rely on in-process scheduling; PostgreSQL leases and durable state are required.
- Async code, database pooling, bounded collection concurrency, and strict timeouts are mandatory.
- Redis/Celery are deferred until measured scale demonstrates a need.

## Alternatives Considered

- Go backend: smaller runtime and stronger compile-time guarantees, but slower iteration for future analysis integrations and user preference favors Python.
- Celery/Redis in V1: mature job processing but adds deployment and failure modes before workload evidence exists.
- Background tasks in FastAPI workers: rejected because scaling/restarts would duplicate or lose scheduled work.
