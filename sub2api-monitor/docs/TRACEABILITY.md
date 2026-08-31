# V1 Requirement Traceability

Last reviewed: 2026-08-30

Status values are `planned`, `implemented`, `verified`, `release-gated`, or `blocked`. `Verified` means the current candidate worktree has automated evidence; it does not imply broad version compatibility or production release approval.

| Requirement | Design/contract | Interface or data | Acceptance test IDs | Phase | Status/evidence |
|---|---|---|---|---|---|
| TGT-01 | V1 Scope; Architecture | Target CRUD/probe/collect; `targets` | CT-TGT-01, FE-TGT-01 | 1 | verified: API and Playwright smoke |
| TGT-02 | Architecture/Reliability | leases, runs, per-target isolation/backoff | IT-TGT-02 | 2-3 | verified for target isolation, ready-target scheduling, worker restart, and stale-loop detection; production capacity/backoff rehearsal is release-gated |
| TGT-03 | Capability/UI matrices | mode, connector, capability DTOs | CT-TGT-03, FE-TGT-03 | 1-3 | implemented; current candidate CI verifies API-only, while earlier local real FULL read-only target evidence is not version-frozen and representative FULL CI remains release-gated |
| CAP-01 | Connector Contract/Capability Model | capability dimensions/timestamps | CT-CAP-01, FE-CAP-01 | 1 | verified for API-only probe/UI |
| CAP-02 | Connector Contract/Probe Safety | side-effect, enabled, audit fields | CT-CAP-02, SEC-CAP-02 | 2 | verified for disabled defaults, dual opt-in, scheduled-only calls, persistent rate limits, and audit attempts |
| ACC-01 | V1 Scope; Data Contract | accounts and observations | IT-ACC-01, FE-ACC-01 | 2-3 | verified for current fixtures; representative cross-version fixtures remain release-gated |
| ACC-02 | Connector Contract | availability observation/reasons | UT-ACC-02, IT-ACC-02 | 2 | verified for API fields and missing inventory |
| QTA-01 | Connector Contract/Quota Window | quota samples/current | UT-QTA-01, CT-QTA-01 | 2 | verified for percent/local/passive windows and active OpenAI Codex 5-hour/7-day windows |
| QTA-02 | Capability/UI matrices | freshness and observed timestamps | UT-QTA-02, FE-QTA-02 | 2 | verified for missing/stale/fresh active and passive samples plus responsive account detail UI |
| ALT-01 | V1 Scope; Data Contract | policies, incidents, transitions | UT-ALT-01, IT-ALT-01 | 2 | verified for account availability, quota, channel, rate, TTFT, native alert, collection failure, and recovery transitions |
| ALT-02 | V1 Scope/Architecture | silence, outbox, incident fingerprint | UT-ALT-02, IT-ALT-02 | 2-3 | verified for dedup/ack/hysteresis/recovery and action cooldown; durable silence/reminder, restart, timezone, audit, and multi-instance semantics are release-gated |
| NTF-01 | Architecture/Collection Flow | ntfy/Telegram/Webhook, outbox, delivery | IT-NTF-01, FE-NTF-01 | 2-3 | verified locally for encrypted credentials, destination safety, signed Webhooks, retry/lease recovery, and at-least-once delivery; real-provider outage/recovery is release-gated |
| OPS-01 | Architecture/Reliability | health/readiness/runs/outbox API | IT-OPS-01, FE-OPS-01 | 1-2 | verified: status UI, heartbeat, stale-run restart recovery |
| RAT-01 | Connector Contract; Rate Adaptation | upstream multiplier snapshots/probes | CT-RAT-01, IT-RAT-01, FE-RAT-01 | 2 | verified for bounded discovery, configured/resolved multiplier distinction, change incidents, and safe probe errors |
| CHN-01 | Capability/UI matrices | channel health/history and TTFT policy | CT-CHN-01, UT-TTFT-01, FE-CHN-01 | 2 | verified for bounded channel operations, exact streaming sample counts, percentile gates, hysteresis, disable, and retarget behavior |
| NOP-01 | Connector Contract | native Ops and group capacity snapshot | CT-NOP-01, FE-NOP-01 | 2 | verified for allowlisted bounded reads, recursive redaction, target diagnostics, group usage, and capacity |
| USA-01 | Data Contract | on-demand account usage analytics | CT-USA-01, FE-USA-01 | 2 | verified for bounded 7/30/90-day reads, sanitization, nullable values, trends, models, and endpoints; not a financial ledger |
| RTR-01 | Rate Adaptation | cost-routing policy/intent/outcome | UT-RTR-01, IT-RTR-01, FE-RTR-01 | 2-3 | verified for recommend/confirmed execute, priority-only writes, fail-closed quality binding, worker claims, crash/unknown-outcome reconciliation, and rate recovery; production control-loop capacity remains release-gated |
| EVT-01 | Data Contract; Event Subscription | bounded recent usage and account-switch event | CT-EVT-01, IT-EVT-01 | 2 | verified for safe projection, first-observation baseline, deduplication, target/event filtering, and no prompt/body/credential persistence |
| AUT-01 | Fault Automation | recommendation/manual approval/action/verification | IT-AUT-01, FE-AUT-01, SEC-AUT-01 | 2-3 | verified for the fixed five-action allowlist, separate audited approval, stale-evidence rejection, idempotency, cooldown, dispatch deadline, and post-action verification; unattended execution, legacy execute re-enable, and broader remediation are blocked |
| MOD-01 | Connector Safety | model-detection mutation pause | CT-MOD-01, FE-MOD-01 | 2 | verified: mutations pause before upstream access and frozen snapshots are suppressed from current dashboard state |
| SEC-01 | Security Boundary | target and notification secrets, SSRF, audit | SEC-SEC-01 | 1-3 | implemented and locally verified for current single-key encryption, redaction, DNS pinning, size bounds, secret files, destination allowlists, read-only transactions, and DB-role rejection; versioned envelope/KMS, key rotation/escrow/loss recovery, backup restore, and dependency/SBOM/container/secret scans remain release-gated |
| DEP-01 | Docker Acceptance | Compose services/volumes/secrets | DKR-DEP-01..08 | 1-3 | Phase 1 DKR-01..04 and 06 verified; dependency-failure, backup/restore, upgrade, rollback, queue recovery, and release-image gates remain Phase 3 |
| REL-01 | Delivery Plan; Supported Versions | supported versions, capacity, DR, scans, release artifact | REL-01..08 | 3 | release-gated: [version evidence](SUPPORTED_VERSIONS.md), at least two representative fixtures, contract freeze, performance/soak, RPO/RTO rehearsals, scans, production-like notification E2E, and independent release sign-off remain open |

## Acceptance Predicates

Predicates attached to `release-gated` rows are target release conditions and are not claims that the current worktree already passes them.

- `CT-TGT-01`: Given two valid target payloads, when CRUD/probe APIs are called independently, then identities, schedules, and secrets remain isolated and secrets are never returned.
- `IT-TGT-02`: Given one timing out target and one healthy target, when a collection interval elapses, then the healthy target finishes within its interval and the failed target enters bounded backoff.
- `CT/FE-TGT-03`: Given API-only, valid full, partial full, and fingerprint-mismatch fixtures, when probed, then each receives the documented mode/readiness/coverage and only ready targets can enable monitoring.
- `CT/FE-CAP-01`: Given a supported call that later times out, when old data crosses its threshold, then support remains supported, runtime becomes unavailable, freshness becomes stale, and the UI displays all three facts.
- `CT/SEC-CAP-02`: Given active quota support, when an operator has not separately confirmed enablement, then no active request occurs; after confirmation it is rate-limited, audited, and stopped by either kill switch.
- `IT/FE-ACC-01`: Given accounts with equal external IDs on two targets, when listed and filtered, then both remain distinct under stable global IDs with cursor pagination.
- `UT/IT-ACC-02`: Given scheduling status, expiry, throttling, overload, and quarantine combinations, when normalized, then effective availability and every contributing reason match the fixture truth table.
- `UT/CT-QTA-01`: Given percentage, balance, credit, reset, and missing quota fixtures, when normalized, then provider meaning, units, nullable values, source, and times are preserved.
- `UT/FE-QTA-02`: Given missing/expired quota, when evaluated and rendered, then it is stale/missing and never displayed or counted as zero/healthy.
- `UT/IT-ALT-01`: Given warning/critical/exhausted/unavailable/group/stale conditions sustained for policy duration, then exactly one firing incident transition is created per fingerprint.
- `UT/IT-ALT-02` (release predicate): Given flapping values and an active silence/cooldown, then hysteresis, deduplication, acknowledgement, reminder, recovery, restart compensation, and notification suppression follow policy configuration.
- `IT/FE-NTF-01`: Given ntfy, Telegram, or Webhook delivery, retryable failure, lease expiry, and ambiguous timeout, then durable delivery state is visible, redacted, bounded, reclaimable, and documented as at-least-once.
- `IT/FE-OPS-01`: Given healthy, stalled, and failing worker/outbox states, then health/readiness and system UI distinguish them with run evidence.
- `CT/IT/FE-RAT-01`: Given supported, unsupported, failed, stale, and changed upstream rate evidence, then configured and resolved values remain distinct and only eligible changes create incidents.
- `CT/UT/FE-CHN-01`: Given channel evidence and streaming TTFT samples, then bounded health/history renders honestly and alerts require the configured percentile, minimum sample count, and recovery threshold.
- `CT/FE-NOP-01`: Given native Ops responses, then only allowlisted bounded fields reach the UI and nested secrets, headers, credentials, and request bodies are absent.
- `CT/FE-USA-01`: Given 7/30/90-day account usage, then statistics are read on demand, bounded and sanitized, and missing values remain unknown rather than zero.
- `UT/IT/FE-RTR-01`: Given multiplier, availability, quality, worker interruption, and unknown write outcomes, then recommendations and priority-only writes obey confirmation, fencing, recheck, fail-closed, reconciliation, and audit rules.
- `CT/IT-EVT-01`: Given bounded recent usage for one session, then the first account establishes a baseline and a later change emits one filtered event without retaining request content.
- `IT/FE/SEC-AUT-01`: Given an account-unavailable incident, then only a compatible allowlisted action can be recommended and separately approved, executed idempotently, audited, and verified; stale evidence, missing approval, or an unattended execute rule cannot dispatch.
- `CT/FE-MOD-01`: Given model-detection mutation is paused, then no upstream mutation occurs and frozen snapshots do not masquerade as current dashboard truth.
- `SEC-SEC-01`: Given API/log/trace/backup/error export paths, then target secrets and raw account payloads are absent; DB writes and unsafe SSRF destinations fail closed.
- `DKR-DEP-01..08`: All scenarios and predicates in `DOCKER_ACCEPTANCE.md` pass on the release image digest.
- `REL-01..08`: Supported-version, compatibility, capacity, data-quality, backup/restore, upgrade/rollback, supply-chain, notification-provider, and independent QA reports are attached to one immutable release candidate.
