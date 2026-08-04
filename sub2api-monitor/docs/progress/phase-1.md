# Phase 1 Progress - Executable Skeleton and API-Only Slice

Date opened: 2026-08-03

## Ownership and Build Identity

- Coordinator: root agent
- Backend author: backend_arch agent, owns `backend/**`
- Frontend author: frontend_plan agent, owns `frontend/**`
- QA/reviewer: qa_delivery agent, owns `qa/**` and independent findings
- Integration author: root agent, owns root Docker/contracts/docs files
- Commit SHA: not created; this delivery remains an isolated workspace project
- Backend image ID: `sha256:ab16de0096759d43013b413d9cbdb64036ecc5c034d14ed670a6129f25fea865`
- Web image ID: `sha256:ecbb61691f3bdeaf3de4131b9c4873f25f200d996a8fbf45e43d76b1525751d7`

## Goal and Requirement IDs

Implement TGT-01, TGT-02, TGT-03, CAP-01, CAP-02, ACC-01, ACC-02, QTA-01, QTA-02, ALT-01, ALT-02, NTF-01, OPS-01, SEC-01, and the Phase 1 subset of DEP-01. Acceptance IDs are defined in `docs/TRACEABILITY.md`.

## Planned Changes

- FastAPI API and separate worker from one Python package/image.
- PostgreSQL schema/migrations for targets, secrets, capabilities, observations, incidents, policies, runs, and notification outbox.
- API-only Sub2API adapter with public health, version, paginated accounts, and passive usage collection.
- Local single-admin authentication and write-only encrypted target secrets.
- React operations UI for onboarding and core monitoring workflows.
- Docker Compose with monitor PostgreSQL, API, worker, web, fake Sub2API, fake ntfy, and migration job.
- Unit, contract, integration, frontend, and clean-volume smoke verification.

## Contract and Compatibility Constraints

- Current local Sub2API source is the first concrete fixture reference; a second representative version remains required before claiming broad compatibility.
- Scheduled active usage calls and `force=true` remain disabled in this wave.
- Unknown support/runtime/freshness dimensions remain independent.
- Existing Sub2API source code is not modified.

## Actual Changes

- Added a FastAPI API and separate worker with PostgreSQL/Alembic persistence, encrypted write-only secrets, local administrator sessions, capability state, observations, policies, incidents, audit records, and durable notification outbox.
- Added bounded API-only collection for health, version, paginated account inventory, normalized availability, local quota, and passive Anthropic quota. Active/force collection remains disabled.
- Added stale-run recovery, background worker heartbeat, per-target schedule locking, independent token-rotation persistence, DNS address pinning, decompressed response limits, and login throttling/non-blocking password verification.
- Added React target onboarding/enablement/deletion, capability detail, exact dashboard aggregates, cursor account loading, quota detail, incident acknowledgement, explicit ntfy channel creation/enablement/deletion/testing/delivery history, and system diagnostics.
- Added non-root read-only API/worker/web containers, migration job, worker health check, direct or `*_FILE` runtime secret inputs, QA fakes, repeatable smoke script, and CI workflow.

## Deviations and Decisions

- Development starts with one current-version fixture because a second deployment fixture is not yet available. The adapter must fail explicitly on unknown contracts and cannot claim universal compatibility.
- Silence, sustain duration, cooldown, reminders, group-capacity alerts, and FULL DB binding remain Phase 2; the Phase 1 UI does not expose controls that return placeholders.
- The reference deployment supports one worker replica. Cross-replica collection semantics and performance testing remain Phase 2/3 even though target row locking prevents ordinary duplicate scheduling.

## Review Evidence

- Backend/QA non-author review found two blockers and five high findings: stale running jobs, missing test gates, token-rotation rollback, incorrect latest-quota grouping, blocking/unbounded login work, SSRF/response-size gaps, and missing secret-file/worker-health support.
- Frontend non-author review found two critical workflow findings plus target lifecycle, aggregate truncation, capability visibility, system diagnostics, quota detail, error-state, mobile-action, and accessibility gaps.
- Closed in this wave: stale-run recovery and real restart test; stable frontend/backend gates; independent token commit and rollback test; latest-per-window quota aggregation; login bounds/throttle/thread offload; pinned target connection and response cap; secret files/worker health; target enablement; exact dashboard; explicit notification channel/outbox flow; capability/system/quota views; hidden unimplemented silence; sticky mobile actions and dialog/search labels.
- Open blockers: none for the Phase 1 API-only gate.
- Open major findings: none within the Phase 1 boundary. Multi-replica scale, distributed login limiting, richer focus trapping, and complete V1 noise controls are recorded as Phase 2/3 residual work.
- Approved exceptions and approver: none

## Test Evidence

- Backend: 19 pytest tests passed; Ruff lint and format passed; strict mypy passed; application coverage 72% with a 70% gate.
- Frontend: ESLint passed; 2 Vitest component tests passed; TypeScript/Vite production build passed; production dependency audit reported 0 vulnerabilities.
- E2E: Playwright Chromium passed desktop and Pixel 7 projects, including login, target capability detail, account quota detail, worker system status, and viewport overflow assertion.
- Docker: Compose config/build/fresh migration/idempotent start passed; API, PostgreSQL, worker, web, and both QA fakes became healthy.
- Integration: target probe/enable/collect succeeded with 3 accounts; exact dashboard reported 1 ready target, 2/3 available accounts, 1 low-quota account, and 2 active incidents; ntfy outbox reached `sent`.
- Recovery: an injected same-container `running` collection was marked failed after worker restart with `worker stopped before collection completed`; the target was no longer blocked.
- Migration: revision `588940ec7204` is head; upgrade/downgrade/upgrade and model drift check passed during author/QA validation.

### Real `sub2api-loc` Integration Addendum

- Date: 2026-08-03 UTC.
- Deployment: existing `sub2api-loc` container on the private `sub2api-loc-network`; monitored version `0.1.170`.
- Authentication: existing dedicated Sub2API Admin API Key, stored write-only and encrypted by the monitor. Administrator password and target account credentials were not copied into monitor configuration or test output.
- Network: `compose.sub2api-local.target.yaml` and `compose.sub2api-local.yaml` create a dedicated external network containing only `sub2api-loc`, monitor API, and monitor worker. Connectivity checks confirm the target API is reachable while target PostgreSQL and Redis names/ports are not reachable from monitor containers.
- Probe: public health, authenticated version, paginated account inventory, and availability capabilities reported supported/healthy/fresh; target readiness became `ready` and API connection state `connected`.
- Collection: one manual run and two scheduled runs completed successfully, each observing 2 accounts and no error. Both normalized accounts were available.
- Read-only oracle: aggregate query against target PostgreSQL reported 2 non-deleted, active, schedulable accounts, matching the API and monitor observations. No target writes or active/`force=true` quota calls were issued.
- Quota result: both real accounts are OpenAI accounts with no local quota limit fields configured. The API therefore yielded 0 quota windows. `quota.passive` was reported unavailable with reason `no eligible Anthropic OAuth/SetupToken accounts`; missing quota remained unknown rather than zero.
- Alert result: no real-target incident fired because both accounts were available and no quota threshold could be evaluated. ntfy delivery success/retry behavior remains covered by the Phase 1 fake-target integration evidence.
- UI automation: the live web/API endpoints remained healthy, but the host Playwright launch was not executed because the installed Chromium runtime lacked `libatk-1.0.so.0`. Existing container/fixture Playwright evidence remains valid; a real-target browser rerun is pending a host or container image with browser system dependencies.
- Restart regression: real-target network integration exposed Nginx caching the API container's old address after API recreation. The web proxy now resolves `api` through Docker DNS with a bounded TTL. A controlled test changed the API address from `172.20.0.6` to `172.20.0.8`; without restarting web, `/healthz` recovered to HTTP 200 and authenticated API routes remained available.
- Addendum web image: `sha256:a3a572b345fa143fff4601ed35d59b2bb2ab7f75fa8a200130543b20307e25ae`, built from `compose.yaml` plus both `sub2api-local` network overrides. The original Phase 1 image ID above remains the pre-addendum evidence.
- Test-image gate: the Docker `test` stage now installs the project editable so coverage observes the code under test. Ruff check/format, strict mypy for `app`, 19 pytest tests, and the 70% coverage gate passed at 71.58%.

## Residual Risks and Deferred Work

- Second-version fixtures and full-mode database binding remain Phase 2 prerequisites.
- Formal independent repository initialization remains pending; all work stays isolated under `sub2api-monitor/`.

## Exit Decision

Closed for the API-only Phase 1 gate on 2026-08-03. This is not a V1 release decision; Phase 2 and Phase 3 gates remain mandatory.
