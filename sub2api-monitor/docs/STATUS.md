# Project Status

Last updated: 2026-08-03

## Current Phase

Phase 1, the Phase 2 FULL cached-quota slice, and the explicitly authorized active-quota refresh slice are closed. Remaining Phase 2 work covers broader providers and V1 noise-control workflows.

## Phase Goal

Expand the runnable Hub from API-only monitoring to securely bound API+read-only-DB collection, expose real cached quota with honest freshness, and retain passive-by-default alert behavior.

The current Phase 2 increment adds fresh provider quota through the existing Sub2API admin usage API without changing Sub2API source. It remains disabled globally and per target by default; scheduled calls never use `force=true` and are rate-limited per account.

## Completed

- [x] Confirmed multi-target product boundary.
- [x] Selected Python/FastAPI and React/TypeScript.
- [x] Defined `api_only` and `full` as the required V1 connection modes.
- [x] Defined capability-driven degradation semantics.
- [x] Reserved future edge Collector Agent and Analysis Agent modules outside V1.
- [x] Established development, independent review, test, and Docker release gates.
- [x] Recorded Phase 0 decisions, risks, and scope in `docs/progress/phase-0.md`.
- [x] Selected local single-administrator authentication and ntfy-only notifications for V1.
- [x] Added requirement traceability, UI-state, Docker acceptance, and phase-evidence matrices.

## Phase 1 Completed

- [x] FastAPI application, worker role, monitor database model, and migrations.
- [x] API-only Sub2API connector, capability probe, target CRUD, account observations, and passive quota collection.
- [x] React operations shell, target onboarding/enablement, capability detail, overview, accounts/quota detail, incidents, notifications, and system diagnostics.
- [x] Initial policy evaluation, incident acknowledgement/recovery, ntfy durable outbox, and delivery history.
- [x] Dockerfiles, Compose, fake target/ntfy services, worker health check, secret-file inputs, and retained-volume smoke tests.
- [x] Non-author frontend/backend review, independent QA findings, remediation, CI gates, and phase evidence.

## Phase 2 FULL Slice Completed

- [x] Separately encrypted per-target DB credentials and FULL onboarding/probe state.
- [x] Fixed allowlisted PostgreSQL reads, enforced read-only transactions, write-capable-role rejection, timeouts, and account bounds.
- [x] API/DB account-ID fingerprint binding with mismatch and expiry failure handling.
- [x] OpenAI Codex 5-hour/7-day and local persisted quota normalization with source/reset/observed/freshness.
- [x] Stale quota remains visible but cannot trigger or resolve low-quota incidents.
- [x] Dedicated target DB Docker network, real `sub2api-local` read-only role, browser verification, and independent test gates.

## Phase 2 Active Quota Slice Completed

- [x] Add a global emergency switch and an explicit per-target opt-in with side-effect confirmation.
- [x] Normalize supported active usage responses without storing raw provider payloads or secrets.
- [x] Enforce per-target/per-account refresh intervals and keep scheduled `force=true` disabled.
- [x] Record capability attempt/success/error state and configuration audit events.
- [x] Preserve the last valid quota when an active call fails; missing unsupported quota remains unknown, not zero.
- [x] Expose complete quota-window details and account scheduling/expiry state in the React UI.
- [x] Verify active OpenAI OAuth observations and responsive UI against `sub2api-local`.
- [x] Complete independent QA with no open blocker, major, or minor findings.

## Pending Phase 0 Decisions

- [ ] Confirm the oldest Sub2API version that V1 must support.
- [ ] Collect sanitized API and schema fixtures from at least two representative Sub2API versions.
- [ ] Freeze the initial OpenAPI contract and monitor database model against those fixtures.
- [ ] Set the V1 performance baseline after real account counts are known.

## Exit Criteria

- Every V1 requirement has an acceptance criterion.
- Connector DTOs and capability states are reviewed.
- API-only and full-mode probe fixtures exist.
- The initial OpenAPI contract and monitoring database model are approved.
- Threat model covers target credentials, SSRF, log redaction, and read-only DB access.

## Next Phase

Phase 2 - full API+DB connector, field precedence, binding verification, expanded provider quota mappings, and V1 workflow completion.

## Change Log

- 2026-08-03: Initial planning baseline created. Existing Sub2API source files were not modified.
- 2026-08-03: V1 onboarding modes narrowed to API-only and full; DB-only retained as a future compatibility option.
- 2026-08-03: V1 authentication fixed to local single-admin and notifications fixed to ntfy; OIDC and other channels deferred.
- 2026-08-03: Phase 1 implementation started after user approval; Phase 0 fixture gaps remain tracked as compatibility risks rather than silently closed.
- 2026-08-03: Phase 1 API-only slice closed after independent review and remediation; FULL mode, silence/cooldown/reminders, second-version fixtures, and release hardening remain open.
- 2026-08-03: Connected the running `sub2api-loc` deployment as a real API-only target. Probe and repeated collection passed against Sub2API `0.1.170`; evidence and quota limitations are recorded in the Phase 1 progress report.
- 2026-08-03: Opened Phase 2 FULL read-only quota slice after the real OpenAI target exposed persisted Codex quota snapshots not available through the account-list API.
- 2026-08-03: Verified the first FULL slice against `sub2api-local`: API/DB binding passed for two accounts, two cached Codex windows were classified stale, the API-key account remained quota-unknown, and no target write or stale-quota incident occurred.
- 2026-08-03: Opened the explicitly authorized active-quota increment after the user reported that current remaining quota was still incomplete. Scope is limited to the existing Sub2API usage API, opt-in scheduling, normalized observations, and UI detail; no Sub2API source changes or account management writes are authorized.
- 2026-08-03: Deployed the active-quota increment against `sub2api-local`. Four scheduled OAuth refreshes each returned two normalized Codex windows; the 7-day window is fresh at 100% remaining, while the upstream 5-hour reset remains in the past and is honestly marked stale. Desktop/mobile real-target E2E, 48 backend tests, 6 frontend tests, lint, type-check, build, and Docker health passed before final independent review.
- 2026-08-03: First active-increment QA found account starvation beyond the per-run limit and non-atomic active success/sample persistence. Remediation now filters account cooldowns before the run limit and commits each active sample with its success audit/capability state; dedicated rotation, rollback, and empty-response regressions pass. QA re-review is in progress.
- 2026-08-03: Second QA pass found per-account attempt-query growth and a missing alert retry after downstream rollback. Remediation uses one grouped attempt query for the full account pool and merges still-fresh persisted active samples into every collection, so policy/ntfy work retries without another upstream call. A 1000-account query bound and failed-then-retried low-quota incident test pass.
- 2026-08-03: Independent QA approved closure after all active-quota findings were remediated. Final gates: 48 backend tests at 73.12% coverage, Ruff, mypy, 6 frontend tests, lint/build, migration and Compose checks, healthy runtime image `sha256:483ec546...`, and real desktop/mobile E2E 2/2.
