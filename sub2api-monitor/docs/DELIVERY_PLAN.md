# Delivery Plan

Last updated: 2026-08-30

This plan separates functional implementation from production readiness. A completed feature slice is not a release approval.

| Phase | Current status | Progress statement |
|---|---|---|
| Phase 0 - Scope and contract | Partially complete | Product boundary and contracts exist; supported-version decision, representative fixtures, final contract freeze, and performance baseline remain open. |
| Phase 1 - Executable skeleton | Complete | API-only end-to-end workflow, durable state, UI shell, worker, and Compose baseline are closed. |
| Phase 2 - V1 functional slices | Functionally complete | API/FULL collection, quota, operations, channel/TTFT, rate/cost routing, incidents, notifications, and bounded automation are implemented and locally verified. |
| Phase 3 - Hardening and release | Active with Phase 0 evidence carryovers | Compatibility/version fixtures, capacity, data-quality, disaster-recovery, security, supply-chain, and production-like E2E evidence remain. |
| Phase 4 - Enhanced operations | Backlog | No Phase 4 candidate is release scope until Phase 3 exits. |
| Phase 5 - Collector and analysis agents | Backlog | Contracts must remain stable before distributed agents are started. |

## Phase 0 - Scope and Contract (Partially Complete)

Deliverables:

- V1 scope and requirements
- architecture and ADRs
- connector capability matrix
- normalized account/quota DTOs
- threat model and test plan
- sanitized fixtures from representative Sub2API versions

Gate: documents reviewed, requirements traceable, unresolved scope questions recorded. The gate remains open for supported-version fixtures, contract freeze, and a capacity baseline.

## Phase 1 - Executable Skeleton (Complete)

Deliverables:

- FastAPI and worker process skeletons
- monitor PostgreSQL model and Alembic migrations
- local administrator authentication
- Target CRUD and connection probe
- fake Sub2API API and ntfy targets
- React application shell and target onboarding
- Dockerfiles and Compose startup from an empty volume

Gate: API-only smoke path works end to end; migrations and health checks pass. Full mode remains a Phase 2 gate.

## Phase 2 - V1 Functional Slices (Complete with Release Carryovers)

Deliverables:

- multi-target account inventory
- API-only and full-mode connectors
- account availability normalization
- common OpenAI/Codex, Anthropic, Grok, Gemini, Antigravity, and Ollama quota mappings where supported
- stale-data semantics
- policy engine, incident transitions, acknowledgement, hysteresis, deduplication, and recovery; durable silence/reminder semantics remain a Phase 3 carryover
- ntfy channel, test publish, routing, outbox, and delivery history
- target, account, incident, policy, notification, and system UI
- native operations, group capacity, account usage, channel quality, and streaming TTFT
- upstream multiplier discovery, bounded cost-routing recommendation/execute modes, and actual account-switch events
- Telegram and HMAC-signed Webhook delivery
- allowlisted account-recovery recommendation, approval, execution, audit, and post-action verification

Functional gate: current candidate tests pass and unsupported or stale data is never presented as healthy. Cross-version fixtures, durable silence/reminder semantics, production-like notification exercises, and the Phase 3 release gates are explicit carryovers.

## Phase 3 - Hardening and Release (Active)

Deliverables:

- API 401/429/5xx and DB outage recovery
- performance and collection concurrency validation
- security review, SSRF policy, secret/log scanning
- backup, restore, upgrade, and rollback runbooks
- versioned secret envelope or equivalent KMS integration, key rotation/escrow, and key-loss recovery rehearsal
- dependency/SBOM/container scans
- release candidate and compatibility report
- durable silence/reminder, restart compensation, timezone, audit, and multi-instance semantics
- production-like ntfy, Telegram, and signed Webhook failure/recovery exercises
- release artifact provenance, image digest, and retained test/rehearsal reports

Gate: independent QA sign-off, no unwaived high/critical image findings, fresh and upgrade Compose rehearsals pass.

### Active Phase 3 Execution Order

1. Complete [SUPPORTED_VERSIONS.md](SUPPORTED_VERSIONS.md): freeze supported versions, collect at least two sanitized API/FULL fixtures, version the contract, and add missing/unknown/breaking-field regressions.
2. Establish collection and UI capacity limits; test 401/429/5xx, timeouts, database outage, backpressure, restart, duplicate/out-of-order data, and long-running stability.
3. Rehearse backup, restore, schema/config upgrade, failed migration recovery, queue recovery, and rollback with agreed RPO/RTO.
4. Close silence/reminder semantics and controlled-action multi-instance fencing; exercise notification provider outages and at-least-once consumer deduplication.
5. Run security, dependency, license, SBOM, secret, log, and container scans; produce the compatibility report and reproducible release candidate.

## Phase 4 - Enhanced Operations (Backlog)

Candidates after V1 evidence:

- quota trends and estimated exhaustion time
- group/platform capacity forecasting
- notification digest and additional channels
- OIDC and multi-user RBAC
- edge Collector Agent deployment mode

## Phase 5 - Collector and Analysis Agents (Backlog)

Agents are implemented only after normalized observation and incident contracts are stable. The Collector Agent provides enrollment, heartbeat, local buffering, and observation upload. The Analysis Agent begins with read-only findings and recommendations. Management actions require explicit approval, authorization, idempotency, and audit.

## Original Estimate (Historical)

- Phase 0: 1-3 engineering days depending on fixture availability.
- Phase 1: 3-4 engineering days.
- Phase 2: 6-9 engineering days.
- Phase 3: 3-5 engineering days.

The original production V1 estimate was 15-23 engineering days, or roughly 8-12 working days with three agents plus compatibility buffer. It is retained only as the initial planning baseline. No production date is committed until fixture access, capacity assumptions, external notification environments, and security/release gates are known.

## Scope Change Rule

A phase scope changes only through a short change record containing rationale, affected requirements, contract/data migration impact, test impact, and schedule impact. `STATUS.md`, the active `docs/progress/phase-N.md`, and this plan are updated before implementation continues.
