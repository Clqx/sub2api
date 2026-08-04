# V1 Requirement Traceability

Status values are `planned`, `implemented`, `verified`, or `blocked`. Phase 0 uses planned test IDs; execution evidence is added to the active phase record.

| Requirement | Design/contract | Interface or data | Acceptance test IDs | Phase | Status/evidence |
|---|---|---|---|---|---|
| TGT-01 | V1 Scope; Architecture | Target CRUD/probe/collect; `targets` | CT-TGT-01, FE-TGT-01 | 1 | verified: API and Playwright smoke |
| TGT-02 | Architecture/Reliability | leases, runs, per-target backoff | IT-TGT-02 | 2 | planned |
| TGT-03 | Capability/UI matrices | mode, connector, capability DTOs | CT-TGT-03, FE-TGT-03 | 1-2 | verified for API-only and real FULL read-only target |
| CAP-01 | Connector Contract/Capability Model | capability dimensions/timestamps | CT-CAP-01, FE-CAP-01 | 1 | verified for API-only probe/UI |
| CAP-02 | Connector Contract/Probe Safety | side-effect, enabled, audit fields | CT-CAP-02, SEC-CAP-02 | 2 | verified for disabled defaults, dual opt-in, scheduled-only calls, persistent rate limits, and audit attempts |
| ACC-01 | V1 Scope; Data Contract | accounts and observations | IT-ACC-01, FE-ACC-01 | 2 | implemented; cross-version fixture verification remains Phase 2 |
| ACC-02 | Connector Contract | availability observation/reasons | UT-ACC-02, IT-ACC-02 | 2 | verified for API fields and missing inventory |
| QTA-01 | Connector Contract/Quota Window | quota samples/current | UT-QTA-01, CT-QTA-01 | 2 | verified for percent/local/passive windows and active OpenAI Codex 5-hour/7-day windows |
| QTA-02 | Capability/UI matrices | freshness and observed timestamps | UT-QTA-02, FE-QTA-02 | 2 | verified for missing/stale/fresh active and passive samples plus responsive account detail UI |
| ALT-01 | V1 Scope; Data Contract | policies, incidents, transitions | UT-ALT-01, IT-ALT-01 | 2 | implemented for unavailable/low quota/recovery |
| ALT-02 | V1 Scope/Architecture | silence, outbox, incident fingerprint | UT-ALT-02, IT-ALT-02 | 2 | implemented for dedup/ack/hysteresis/recovery; silence/cooldown/reminder pending |
| NTF-01 | Architecture/Collection Flow | channel, outbox, delivery | IT-NTF-01, FE-NTF-01 | 2 | verified for channel/test/sent/retry/dead visibility |
| OPS-01 | Architecture/Reliability | health/readiness/runs/outbox API | IT-OPS-01, FE-OPS-01 | 1-2 | verified: status UI, heartbeat, stale-run restart recovery |
| SEC-01 | Security Boundary | target secrets and audit | SEC-SEC-01 | 1-3 | implemented: encryption, redaction, URL pinning, size bounds, secret files, read-only transaction and DB-role rejection; Phase 3 scan pending |
| DEP-01 | Docker Acceptance | Compose services/volumes/secrets | DKR-DEP-01..08 | 1-3 | Phase 1 DKR-01..04 and 06 verified; dependency-failure, backup, and upgrade gates remain Phase 3 |

## Acceptance Predicates

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
- `UT/IT-ALT-02`: Given flapping values and an active silence/cooldown, then hysteresis, deduplication, acknowledgement, reminder, recovery, and notification suppression follow policy configuration.
- `IT/FE-NTF-01`: Given ntfy success, retryable failure, and ambiguous timeout, then durable delivery state is visible, redacted, retried, and no durable event is lost.
- `IT/FE-OPS-01`: Given healthy, stalled, and failing worker/outbox states, then health/readiness and system UI distinguish them with run evidence.
- `SEC-SEC-01`: Given API/log/trace/backup/error export paths, then target secrets and raw account payloads are absent; DB writes and unsafe SSRF destinations fail closed.
- `DKR-DEP-01..08`: All scenarios and predicates in `DOCKER_ACCEPTANCE.md` pass on the release image digest.
