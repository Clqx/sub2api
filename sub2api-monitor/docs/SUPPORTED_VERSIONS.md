# Supported Sub2API Versions

Last reviewed: 2026-08-30

Release status: **provisional and release-gated**. The oldest supported Sub2API version has not been selected, and the current evidence does not justify a broad compatibility claim.

## Current Evidence Inventory

| Target/version evidence | Mode | Evidence captured | What it proves | Why it is insufficient for release |
|---|---|---|---|---|
| Sub2API `0.1.170`, historical live target | API_ONLY | 2026-08-03 Phase 1 probe and repeated collection | Basic reachability, target isolation, account inventory, passive observation, and API-only UI flow for that version | Predates FULL, native Ops, channel/TTFT, routing, Telegram, and automation slices |
| `sub2api-local`, version not recorded in the evidence | FULL | 2026-08-03 API/DB binding, two-account merge, cached and active Codex quota | The first API plus read-only DB path and honest stale/unknown quota semantics | Missing an immutable version, fixture digest, and later feature contracts |
| `whiles` target, version not recorded in the evidence | FULL | 2026-08-08 native Ops, group capacity, account analytics, desktop/mobile checks | Current target APIs can drive the operations and account-usage views | A named environment without versioned sanitized fixtures is not compatibility evidence |
| Current repository candidate worktree on HEAD `a438d9ee1` | Source fixture | 2026-08-30 local automated regressions | Current code paths and mocks agree with the candidate implementation | The worktree is uncommitted and is not an independent older/newer deployment fixture |

## Release Gate

The compatibility gate closes only when all of the following are recorded:

1. The oldest supported Sub2API version and the support window are approved.
2. At least two representative released versions have sanitized API_ONLY and, where supported, FULL fixtures.
3. Every fixture records version, capture date, endpoint/schema inventory, capability probe result, sanitization review, and content digest.
4. Contract tests cover missing endpoints, missing/null/unknown fields, renamed or type-drifted fields, partial native Ops, API/DB identity mismatch, stale observations, and oversized responses.
5. The OpenAPI/JSON contracts and monitor database model are versioned against those fixtures.
6. A compatibility report states each capability as supported, degraded, unsupported, or blocked for every supported version.

## Required Degradation Behavior

- Missing optional endpoints reduce capability coverage; they never become zero or healthy values.
- Missing required account inventory keeps a target not ready.
- FULL identity mismatch blocks API/DB merge and every active side effect.
- Stale observations may remain visible with timestamps but cannot fire or resolve freshness-dependent incidents.
- Unknown response fields may be ignored only at validated DTO boundaries; raw unvalidated provider payloads are not persisted.
- Breaking type or identity drift fails closed for the affected capability and remains observable without stopping healthy targets.

Until this gate closes, documentation and UI must say “verified against current recorded fixtures,” not “supports all Sub2API versions.”
