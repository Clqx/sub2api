# Phase 2 Progress - Full Read-Only Quota Slice

Date opened: 2026-08-03

## Ownership and Build Identity

- Coordinator/integration: root agent, owns contracts, deployment, target read-only role, and integration.
- Backend author: backend_arch agent, owns `backend/**` FULL connector implementation and tests.
- Frontend authors: root agent for the FULL slice; frontend_plan agent for active-refresh controls and complete account/quota presentation.
- Non-author reviewer and independent QA: qa_delivery agent.
- Commit SHA: not created; work remains isolated under `sub2api-monitor/`.
- Backend runtime image ID: `sha256:483ec54651b20acde073c9dbff439aa11902f891149f1d82dfe96067e88e424c`.
- Web runtime image ID: `sha256:5e678ee506718308ef197ca9ee52adc1e6ba43b4ebb1d398b252e82c4658bcc8`.

## Goal and Requirement IDs

- TGT-03: implement the first usable `full` connection path.
- CAP-01/CAP-02: probe API and DB capabilities independently; keep active upstream refresh disabled.
- ACC-01/ACC-02: bind API and DB inventory by stable target-local account ID.
- QTA-01/QTA-02: read persisted OpenAI Codex and local quota snapshots with source, reset time, and freshness.
- SEC-01/DEP-01: use a dedicated read-only PostgreSQL role, bounded queries, encrypted credentials, and a dedicated Docker network.
- Acceptance: FULL probe rejects write-capable or mismatched connections; collection exposes real cached quota without target writes or active provider calls.

### Active quota increment opened 2026-08-03

- Trigger: the real OAuth account only has a persisted snapshot observed on 2026-07-29, so database listening cannot provide current remaining quota.
- Scope: call the existing Sub2API admin account usage endpoint from this independent monitor, normalize supported windows, and present the latest value with source and freshness.
- Authorization boundary: no Sub2API source changes and no account-management actions. The documented usage call may refresh tokens or quota cache inside Sub2API, so it requires a global switch plus explicit per-target confirmation.
- Safety defaults: both switches off by default; scheduled calls use `source=active` without `force=true`; per-account interval at least ten minutes; failures retain prior valid observations; raw responses and secrets are not persisted or logged.
- Acceptance: backend contract/rate-limit/audit/error tests, frontend state tests and responsive browser checks, Docker deployment, a fresh real OAuth observation from `sub2api-local`, and independent QA with all blocker/major findings closed.

## Planned and Actual Changes

Planned:

- Add encrypted per-target PostgreSQL connection configuration and separate API/DB connection state.
- Add a fixed read-only DB adapter with permission/schema probing, bounded timeouts, and an allowlist for `accounts` plus quota-related `extra` keys.
- Cross-check API and DB account-ID fingerprints before merging observations.
- Normalize `codex_5h_*`, `codex_7d_*`, and configured local quota fields into existing quota windows.
- Add FULL target onboarding and clearly display source, freshness, reset time, and genuinely unavailable quota.
- Add dedicated target-DB Docker network and local read-only role bootstrap instructions.

Actual changes:

- Added `TargetDatabaseSecret`, migration `9c2b1e7d4a10`, separate DB/binding states, and encrypted FULL create/update contracts.
- Added a fixed PostgreSQL adapter for `public.accounts`, allowlisted columns and quota keys, bounded result size/timeouts, read-only transaction validation, and rejection of missing-read or write-capable roles.
- Added API/DB stable account-identity fingerprints (ID/name/platform/type), API-version and DB-schema evidence, verification expiry/renewal, per-collection recheck, and bounded DB fallback after recent successful binding.
- Added OpenAI Codex 5-hour/7-day and local quota mappings, freshness classification, stale-aware merge precedence, and stale exclusion from policy transitions.
- Added FULL onboarding, target capability details, account type, quota-window source/reset/observation/freshness, and explicit missing-quota UI.
- Added `sub2api-monitor-target-db-net`, containing only target PostgreSQL and monitor API/worker.
- Added globally disabled and per-target confirmed `quota.active_refresh` controls. Enabled scheduled API-only and FULL collections may call `GET /api/v1/admin/accounts/{id}/usage?source=active`; FULL performs API/DB identity verification first, probe/manual paths never call it, and no `force` parameter is sent.
- Added persistent five-minute target and fifteen-minute account rate limits, a twenty-account run bound applied after account-cooldown filtering, supported credential/provider filtering, partial-failure isolation, and recovery of capability health from the last successful active sample while rate-limited.
- Active quota samples, successful attempt outcome, and capability freshness are committed together before downstream account/policy persistence. Empty normalized results fail instead of reporting false freshness; later collector failure cannot leave a successful attempt without its samples. Still-fresh persisted active samples are re-evaluated on later collections so failed alert transactions retry during account cooldown without another upstream call.
- Account selection obtains all last-attempt times with one grouped query, orders never/least-recently attempted accounts first, then applies the per-run bound. Query count is constant with account-pool size.
- Added `active_quota_attempts` through migration `d3a4e8c1f920`, recording correlation, target/account, scheduler actor, result, and before/after timestamps without raw responses or credentials.
- Added migration `e6b8f01c2d33` to canonicalize active OpenAI windows as `codex.five_hour` and `codex.seven_day` and remove duplicate generic active keys.
- Added target capability enablement with a side-effect confirmation, complete account scheduling/expiry state, active/passive source labels, and full quota value/reset/observation/freshness presentation. Unknown quota is not rendered as zero.

## Deviations and Decisions

- The original FULL slice is cache-only. The separately authorized active increment calls only `/usage?source=active` after both switches are enabled; it never calls `/wham/usage` or uses `force=true`.
- Missing persisted utilization remains unknown. Reset timestamps alone are not used to invent remaining percentages.
- The current real target has one OpenAI OAuth account with persisted 5-hour and 7-day utilization snapshots, and one OpenAI API Key account without a configured quota limit. Only the former is expected to gain quota windows.
- DB failure degrades FULL coverage; API inventory remains available, but DB-derived quota is not advanced.
- A successful active response can still contain an already-expired provider window. Observation time and reset-time freshness remain separate facts; the monitor does not relabel such a window as fresh.
- Public PostgreSQL DSNs using `sslmode=verify-full` are rejected because DNS pinning cannot safely preserve hostname verification through asyncpg. Trusted private target networks remain supported without a TLS downgrade.

## Review Evidence

- Backend author report: Ruff, mypy, 26 tests, migration cycle, and real DB smoke passed before coordinator review.
- Coordinator review: added write-capable-role, missing-SELECT, non-read-only transaction rejection, column-level grants excluding `credentials`, and stale policy checks.
- First independent QA rejected the slice with 1 blocker and 3 major findings: FULL was excluded from scheduling; ID-only binding could accept the wrong DB; normal inventory changes stopped monitoring; public DB DNS was resolved twice. One minor unknown-availability rendering issue was also found.
- Remediation: scheduled all ready/enabled modes; added FULL scheduler regression; upgraded binding evidence and medium confidence; allowed matching API/DB inventory changes to renew binding; pinned public DB connections to the validated IP; corrected unknown detail rendering.
- Cached FULL non-author QA confirmed the prior scheduler, binding, inventory-change, DNS-pinning, and unknown-rendering remediations. Active-increment QA found and the implementation remediated account starvation, success/sample transaction mismatch, stale documentation, per-account query growth, and missing alert retry after downstream rollback.
- Final independent QA approved closure with no open blocker, major, or minor findings.
- Blocker findings open/closed: 0 open; 2 closed.
- Major findings open/closed: 0 open; 6 closed.
- Approved exceptions and approver: none.

## Test Evidence

- Final backend gate after QA remediation: Ruff format/check passed for 34 files; mypy strict passed for 20 source files; 48 tests passed; coverage 73.12% (required 70%).
- Migration: PostgreSQL upgrade/downgrade/upgrade passed through active-attempt migration `d3a4e8c1f920` and canonical-key migration `e6b8f01c2d33`; the retained monitor volume is at `e6b8f01c2d33`.
- Permission negative: write-capable role, missing SELECT, and non-read-only transaction tests passed; real `sub2api_monitor_ro` has column-level SELECT only for the connector allowlist, no access to `credentials`, and write privileges=false; an UPDATE attempt was denied.
- Frontend: ESLint passed; 6 unit/component tests passed; TypeScript/Vite production build passed.
- Docker: both merged Compose configurations passed; API, worker, web, and both PostgreSQL containers are healthy. The target DB network contains exactly target PostgreSQL plus monitor API/worker.
- Real target: FULL probe ready, API connected, DB connected, binding verified, 2 accounts. Collection succeeded with 2 accounts and 2 quota windows.
- Binding evidence: method `account_identity_set+api_version+public_accounts_schema_v1`, confidence `medium`; same-ID/different-identity test is rejected, while a matching add/remove inventory test renews an expired binding.
- Scheduler evidence: after re-enabling the real FULL target, worker automatically created run `432b61bd-5703-4e43-a487-2b08126967ef` at 08:43:25 UTC; it succeeded with 2 accounts and 2 quota windows and advanced the next collection time.
- DNS evidence: public DB unit test asserts `asyncpg` receives the validated IP as its `host`; trusted private Docker targets continue through the explicit private-network allow policy.
- Real quota: OAuth Codex 5-hour and 7-day show 100% cached remaining from `sub2api_db_passive`, observed 2026-07-29, both stale. API-key account is `missing`, not zero.
- Alert safety: real target has 0 incidents and pending outbox is 0 after stale quota collection.
- Browser: live login, FULL target mode, account list, missing quota, both Codex windows, source/reset/observation, and stale labels passed in Playwright on desktop and Pixel 7 with no page overflow; screenshots `frontend/test-results/phase2-full.png` and `frontend/test-results/phase2-full-mobile.png`.
- Active contract: disabled defaults, mandatory side-effect confirmation, scheduled-only/no-force behavior, target/account rate limits, audit success/error, partial failure, passive preservation, and FULL identity mismatch before active calls are covered by backend tests.
- Active remediation: a three-account/two-per-run test proves the cooled first pair no longer starves account three; a forced downstream policy failure proves every `succeeded` attempt already has its active sample; a healthy-but-empty response is recorded as failed/missing.
- Scale and alert retry: a 1000-account pool performs two attempt SELECTs total (target bound plus grouped account history); a forced first-run policy failure persists a 1% sample, and the next run creates the low-quota incident while the account remains in cooldown and upstream call count stays one.
- Active real target: four scheduled OAuth attempts from 09:08:49 through 09:54:33 UTC each succeeded with two windows, for 4 successful audits and 8 active samples. The final-remediation runtime produced the 09:54:33 observation. It reports 100% remaining for both windows; `codex.seven_day` resets 2026-08-05 and is fresh, while `codex.five_hour` retains the upstream past reset 2026-07-29 and is stale. The API-key account remains quota-missing because the source provides no quota or configured limit.
- Active browser: the gated real-target Playwright suite passed on desktop and mobile (2/2), checking the enabled/supported/healthy capability, account status fields, two active-source quota cards, remaining percentages, and no horizontal overflow.
- Runtime: API, worker, web, and monitor PostgreSQL are healthy at port `18081`; real target incidents remain zero.

## Residual Risks and Deferred Work

- Active quota is currently normalized only for the common windows returned by supported OpenAI/Anthropic OAuth or setup-token accounts. Broader provider mappings and group-capacity merge remain later Phase 2 waves.
- The current `sub2api-local` OpenAI source continues to return a past reset timestamp for its 5-hour window; the monitor exposes it as stale and cannot infer a replacement reset time.

## Exit Decision

Closed. Implementation, real integration, coordinator regression gates, and independent QA all passed with no approved exceptions.
