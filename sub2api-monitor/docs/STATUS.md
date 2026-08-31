# Project Status

Last updated: 2026-08-30

## Current Phase

Phase 1 and the functional Phase 2 slices are closed. Phase 3 release hardening is active, while Phase 0 supported-version,
fixture and capacity evidence carryovers remain open. The current system is a tested candidate worktree, not a production V1 release.

## Phase Goal

Turn the completed monitoring and controlled-action workflows into a reproducible release: freeze supported Sub2API contracts, prove compatibility and capacity, rehearse failure/backup/upgrade paths, and close supply-chain and runtime security gates.

Passive collection remains the default. Active quota requires global and per-target opt-in; every account-recovery action requires a separate audited manual approval; cost-routing execute mode requires side-effect confirmation. Missing or stale evidence remains unknown and cannot be presented as healthy.

## Completed

- [x] Confirmed multi-target product boundary.
- [x] Selected Python/FastAPI and React/TypeScript.
- [x] Defined `api_only` and `full` as the required V1 connection modes.
- [x] Defined capability-driven degradation semantics.
- [x] Reserved future edge Collector Agent and Analysis Agent modules outside V1.
- [x] Established development, independent review, test, and Docker release gates.
- [x] Recorded Phase 0 decisions, risks, and scope in `docs/progress/phase-0.md`.
- [x] Selected local single-administrator authentication and ntfy as the original Phase 1 notification baseline; later Phase 2 slices added Telegram and signed Webhooks.
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

## Phase 2 Upstream Rate and Channel Monitoring Completed

- [x] Preserve account cost multipliers and sanitized upstream billing probe snapshots during API and FULL-mode collection.
- [x] Expose target-wide probe settings, per-account enablement, and audited immediate probes.
- [x] Aggregate channel monitor status, latency, seven-day availability, model coverage, and target history across deployments.
- [x] Proxy complete channel create, edit, delete, and immediate-run workflows without storing plaintext channel API keys.
- [x] Route degraded/failed channel states and recovery through the existing incident and ntfy outbox engine.
- [x] Alert on resolved upstream multiplier changes for enabled OpenAI API-key accounts.
- [x] Accept an encrypted per-target PostgreSQL PEM certificate and expose database configuration for existing targets.
- [x] Add responsive React operations pages, migration coverage, connector contract tests, strict type checks, and desktop/mobile browser verification.

## Native Sub2API Operations Monitoring Completed

- [x] Probe and aggregate the target's native dashboard, traffic, latency, concurrency, account-availability, request/error, token, alert, log, and system-health APIs.
- [x] Expose group inventory, usage, and capacity with real per-capability support/runtime/freshness results.
- [x] Bound every upstream list request and recursively redact secrets and request bodies.
- [x] Add overview, capacity, request/error, and system views with responsive internal table scrolling.
- [x] Verify the live `whiles` FULL target: API and database connected, identity binding verified, and all native Ops capabilities healthy.

## Native Account Usage Analytics Completed

- [x] Proxy native per-account usage statistics through a bounded, recursively sanitized read-only endpoint.
- [x] Expose 7/30/90-day requests, tokens, account/user/standard cost, response time, active days, daily trend, models, and inbound/upstream endpoints.
- [x] Add account multiplier and group membership to the cross-target inventory without replacing missing values with zero.
- [x] Verify the live `whiles` target plus desktop and 390px mobile layouts with no page-level overflow or application console errors.

## Fault Discovery and Automation Completed

- [x] Mirror firing native Ops alerts and resolve them only from complete evidence.
- [x] Create deduplicated scheduled-collection failure and recovery incidents.
- [x] Add target/event/severity subscriptions for ntfy, Telegram, and HMAC-signed Webhooks on the durable outbox.
- [x] Add recommendations and separate audited manual approval for five allowlisted account recovery actions; unattended execution and re-enabling disabled legacy execute rules are rejected.
- [x] Enforce cooldown, event-transition uniqueness, target idempotency keys, bounded result persistence, audit, and post-action collection.
- [x] Keep destructive account, credential, routing, system, data-management, and backup APIs outside the executor.

## Phase 2 Cost Routing, TTFT, and Delivery Safety Completed

- [x] Add a fixed-budget cost-routing controller with recommendation and explicitly confirmed execute modes.
- [x] Recheck policy state before priority-only writes, fail closed on missing inventory or unhealthy quality bindings, and reconcile unknown write outcomes after worker interruption.
- [x] Preserve fallback baselines, recover priorities after rate improvements, and emit durable rate-recovery events.
- [x] Read only a bounded safe recent-usage projection and emit deduplicated actual account-switch events without prompts, bodies, or credentials.
- [x] Evaluate streaming TTFT only with an exact sample-count gate, configurable percentile thresholds, and recovery hysteresis.
- [x] Deliver through ntfy, Telegram, and HMAC-signed Webhooks with encrypted credentials, destination validation, expiring claims, retries, and explicit at-least-once semantics.
- [x] Pause model-detection mutations before upstream access and suppress frozen detection snapshots from current dashboards.

## Open Release Gates

- [ ] Confirm the oldest Sub2API version that V1 must support.
- [ ] Collect sanitized API and schema fixtures from at least two representative Sub2API versions.
- [ ] Freeze the initial OpenAPI contract and monitor database model against those fixtures.
- [ ] Set the V1 performance baseline after real account counts are known.
- [ ] Validate collection concurrency, backpressure, response-size bounds, long-running stability, and large frontend lists against the agreed capacity envelope.
- [ ] Rehearse API 401/429/5xx, database outage, notification timeout/provider outage, worker interruption, and stale/duplicate/out-of-order evidence.
- [ ] Close durable silence, reminder, restart-recovery, timezone, audit, and multi-instance semantics; automation cooldown does not satisfy this gate.
- [ ] Rehearse database backup/restore, schema and configuration upgrade, failed migration recovery, notification-queue recovery, and rollback with recorded RPO/RTO.
- [ ] Pass dependency, license, SBOM, container, secret, and log scans; record the release image digest and signed compatibility report.
- [ ] Exercise supported Sub2API versions and ntfy, Telegram, and Webhook failure/recovery paths in a production-like environment.

Current compatibility evidence and its gaps are recorded in [SUPPORTED_VERSIONS.md](SUPPORTED_VERSIONS.md).

## Exit Criteria

- Every V1 requirement has an acceptance criterion and links to current automated or rehearsal evidence.
- API-only and full-mode fixtures cover every supported version plus missing/unknown/breaking-field cases.
- Connector DTOs, capability degradation, quota/rate freshness, TTFT sampling, and cost authority are frozen and reviewed.
- Performance, recovery, backup/restore, upgrade/rollback, notification, and controlled-action gates pass on the release candidate.
- Threat model and scans cover target credentials, SSRF/DNS rebinding, notification destinations, log redaction, read-only DB access, dependencies, and images.
- Independent QA signs off with no unwaived high or critical finding.

## Next Phase

Phase 3 - compatibility baseline, reliability/capacity evidence, disaster recovery, security scanning, and a reproducible release candidate. Phase 4 enhancements remain backlog until this gate closes.

## Latest Local Validation

- 2026-08-30: backend `pytest -q` completed with 160 tests passing.
- 2026-08-30: frontend `npm test` completed with 25 tests passing; `npm run build` completed successfully.
- These results cover the current candidate worktree. They are development regression evidence, not a released commit, cross-version compatibility report, production provider exercise, or SLA.

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
- 2026-08-08: Added multi-target upstream billing-rate discovery and target-owned channel monitoring. Final local gates: 51 backend tests, Ruff, mypy, 6 frontend tests, ESLint, production build, a single Alembic head, and desktop/mobile browser layout checks with no application console errors.
- 2026-08-08: Enabled five-minute upstream-rate discovery for OpenAI API-key accounts, added multiplier-change incidents, and added encrypted PEM certificate input for existing and new FULL targets. Final local gates: 55 backend tests, Ruff, mypy, 8 frontend tests, ESLint, production build, live collection, and desktop/mobile form checks.
- 2026-08-08: Added native Sub2API operations aggregation and the four-view Operations page. Final gates: 57 backend tests, Ruff, strict mypy, 9 frontend tests, ESLint, production build, live target reprobe, and desktop/mobile browser checks with no page overflow.
- 2026-08-08: Added native per-account usage analytics with 7/30/90-day summaries, trends, model and endpoint distributions. Final gates: 59 backend tests, Ruff, strict mypy, 10 frontend tests, ESLint, production build, live `whiles` reads, and 1280px/390px browser checks with no page overflow.
- 2026-08-09: Added native Ops alert ingestion, collection-failure incidents, filtered ntfy/Webhook subscriptions, signed Webhook delivery, and explicitly confirmed account-recovery automation with idempotent execution and verification runs.
- 2026-08-30: Closed the current cost-routing, actual account-switch, TTFT policy, Telegram safety, model-detection pause, worker-reconciliation, and UI regression slices. Promoted the project to Phase 3 hardening with 160 backend tests, 25 frontend tests, and a successful production frontend build; compatibility, performance, disaster-recovery, durable silence/reminder, security/SBOM, and real-provider release gates remain open.
