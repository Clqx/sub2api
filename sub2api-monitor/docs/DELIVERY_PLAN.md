# Delivery Plan

## Phase 0 - Scope and Contract

Deliverables:

- V1 scope and requirements
- architecture and ADRs
- connector capability matrix
- normalized account/quota DTOs
- threat model and test plan
- sanitized fixtures from representative Sub2API versions

Gate: documents reviewed, requirements traceable, unresolved scope questions recorded.

## Phase 1 - Executable Skeleton

Deliverables:

- FastAPI and worker process skeletons
- monitor PostgreSQL model and Alembic migrations
- local administrator authentication
- Target CRUD and connection probe
- fake Sub2API API and database targets
- React application shell and target onboarding
- Dockerfiles and Compose startup from an empty volume

Gate: API-only smoke path works end to end; migrations and health checks pass. Full mode remains a Phase 2 gate.

## Phase 2 - V1 Common Features

Deliverables:

- multi-target account inventory
- API-only and full-mode connectors
- account availability normalization
- common OpenAI/Codex, Anthropic, Grok, Gemini, Antigravity, and Ollama quota mappings where supported
- stale-data semantics
- policy engine, incident transitions, acknowledgement, silence, and recovery
- ntfy channel, test publish, routing, outbox, and delivery history
- target, account, incident, policy, notification, and system UI

Gate: V1 requirement matrix passes for API-only and full-mode fixtures; unsupported data is never presented as healthy.

## Phase 3 - Hardening and Release

Deliverables:

- API 401/429/5xx and DB outage recovery
- performance and collection concurrency validation
- security review, SSRF policy, secret/log scanning
- backup, restore, upgrade, and rollback runbooks
- dependency/SBOM/container scans
- release candidate and compatibility report

Gate: independent QA sign-off, no unwaived high/critical image findings, fresh and upgrade Compose rehearsals pass.

## Phase 4 - Enhanced Operations

Candidates after V1 evidence:

- quota trends and estimated exhaustion time
- group/platform capacity forecasting
- notification digest and additional channels
- OIDC and multi-user RBAC
- edge Collector Agent deployment mode

## Phase 5 - Collector and Analysis Agents

Agents are implemented only after normalized observation and incident contracts are stable. The Collector Agent provides enrollment, heartbeat, local buffering, and observation upload. The Analysis Agent begins with read-only findings and recommendations. Management actions require explicit approval, authorization, idempotency, and audit.

## Estimate

- Phase 0: 1-3 engineering days depending on fixture availability.
- Phase 1: 3-4 engineering days.
- Phase 2: 6-9 engineering days.
- Phase 3: 3-5 engineering days.

Expected production V1 effort is 15-23 engineering days. With three implementation/review agents working on stable contracts, expected calendar time is roughly 8-12 working days plus compatibility buffer.

## Scope Change Rule

A phase scope changes only through a short change record containing rationale, affected requirements, contract/data migration impact, test impact, and schedule impact. `STATUS.md`, the active `docs/progress/phase-N.md`, and this plan are updated before implementation continues.
