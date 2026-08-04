# Phase 0 Progress - Scope and Contract

Date: 2026-08-03

## Goal

Define the V1 boundary and delivery process for an independent multi-target Sub2API monitoring project before runtime implementation begins.

## Planned Requirements

- Python/FastAPI backend and React/TypeScript frontend
- multiple independent Sub2API targets
- API-only and full API+DB capability levels
- account availability, quota warning, recovery, and ntfy delivery
- Docker deployment
- future Collector Agent and Analysis Agent extension points
- agent-team implementation, non-author review, independent QA, and phase evidence

## Completed

- Product scope and requirement IDs documented.
- Independent capability support/runtime/freshness states, source semantics, and quota model documented.
- API-only and full-mode boundaries documented; DB-only moved outside the V1 release contract.
- Backend/frontend module boundaries and Docker topology selected.
- Security boundary and high-risk active-probe behavior documented.
- Development, review, QA, and documentation gates documented.
- Requirement traceability, Docker acceptance, threat matrix, and phase evidence template documented.
- Full-mode binding, field precedence, unknown capability state, and transport-neutral identity contracts documented.

## Decisions

- Build a separate project and do not modify monitored Sub2API source code.
- Use one Hub with isolated per-target scheduling and credentials.
- Use PostgreSQL leases/outbox in V1; do not add Redis or Celery before measured need.
- Never convert unknown, stale, denied, or unsupported values to zero/healthy.
- Keep active provider probes opt-in and scheduled `force=true` disabled.
- Keep both Collector Agent and Analysis Agent implementation after V1 contract stabilization.

## Deviations

- The initial draft exposed DB-only as a primary mode. It was narrowed to an optional post-V1 compatibility path to match the required API-only/full product contract.

## Review and Test Evidence

- Backend architecture, frontend workflow, and QA/release plans received independent agent reviews.
- Non-author UX-contract review found conflated capability dimensions, missing monitoring readiness, and missing active-probe enablement state; the contracts and UI matrix were corrected.
- Non-author QA review found missing traceability and Docker acceptance matrices plus inconsistent authentication/notification decisions; the planning documents were corrected while Phase 0 remains open.
- Non-author backend/security review found ambiguous active-probe writes, missing unknown state, incomplete full-mode binding/precedence, and unstable cross-target identities; the contracts were corrected while fixture validation remains open.
- Documentation structure and repository isolation were checked locally.
- No runtime tests exist in Phase 0 because implementation has not started.

## Open Items and Risks

- Obtain sanitized fixtures from at least two representative Sub2API versions.
- Confirm oldest supported version, target API credential strategies, and representative account scale against fixtures.
- Validate API and DB binding evidence and one-hour/24-hour trust windows against fixtures; a future common deployment ID remains preferable.
- Define the exact allowlist for account and quota payloads before connector code is accepted.
- Complete non-author backend/security and QA consistency sign-off on the corrected contracts.
- Place this currently untracked directory in its own version-controlled repository before implementation evidence is accepted.

## Exit Status

Planning baseline is ready for stakeholder review. Phase 0 remains open until fixtures and the initial OpenAPI/database contracts are reviewed.
