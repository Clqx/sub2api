# Testing Strategy

## Test Layers

### Unit

- connector mappings and missing/unknown fields
- capability probing and permission degradation
- effective availability and time boundaries
- quota normalization and remaining calculation
- stale-data classification
- sustain, hysteresis, cooldown, deduplication, reminder, and recovery
- sensitive-data redaction

Test IDs use `UT-*`, `CT-*`, `IT-*`, `FE-*`, `SEC-*`, and `DKR-*`. Requirement-to-test mappings and exact acceptance predicates live in `TRACEABILITY.md`; release evidence records the executed IDs, commit SHA, and image digest.

### Contract

- monitor OpenAPI schema and generated TypeScript client
- sanitized Sub2API API fixtures for representative versions
- database schema fixtures with optional/missing columns
- forward-compatible unknown fields
- Problem Details error schema

### Integration

Use test containers/Compose for monitor PostgreSQL, fake Sub2API API, read-only target PostgreSQL, and ntfy mock. Validate collection through durable notification delivery.

### Frontend

- Vitest/React Testing Library for available, unsupported, stale, loading, and error states
- Playwright for target onboarding, capability degradation, account filtering, incident acknowledgement/silence, and ntfy test publish
- Playwright states for API-only without quota, expired API token, full-mode DB-only failure, API/DB fingerprint mismatch, partial provider support, and supported-but-disabled active quota

### Resilience

- API 401, 403, 429, 5xx, timeout, malformed and partial responses
- API-only degradation and full-mode API/DB identity mismatch
- target DB disconnect and schema drift
- target/account/incident/outbox cross-contamination attempts
- ntfy failures and ambiguous timeouts
- API/worker restart during collection/outbox delivery
- clock/reset boundaries and stale recovery
- one failed target while other targets continue

### Security

- SSRF target validation
- target DB read-only enforcement
- secret/log/API-response redaction
- administrator API credential handling and raw `extra` rejection
- active quota probe disabled-by-default and side-effect labeling
- target DB before/after diff for active probes and connection tests
- future Agent batch replay, duplicate sequence, out-of-order delivery, and assignment mismatch contract tests
- authentication and authorization
- dependency, secret, static, SBOM, and image scanning

## CI Gates

Pull requests must pass:

- Python: Ruff format/lint, mypy, pytest unit/contract, migration checks
- React: ESLint, TypeScript, Vitest, production build
- OpenAPI generated-client drift check
- Docker Compose validation and image build
- secret, dependency, and static security scans

Core connector and policy modules target at least 90% branch coverage; overall backend and frontend target at least 80% without excluding meaningful code solely to raise the number.

Release candidates additionally pass integration, Playwright, clean-volume Compose startup, upgrade rehearsal, backup/restore test, SBOM generation, and container vulnerability review.

## Initial Scale Baseline

The provisional V1 scenario is 20 targets and 10,000 accounts. Collection must finish inside its configured interval, enforce per-target concurrency/rate limits, and keep target failures isolated. Final latency/resource thresholds are frozen after representative account counts are supplied.

## Release Evidence

Each phase stores a test report containing environment, image digest, migrations, commands, results, accepted exceptions, and unresolved risks. The report is referenced from `STATUS.md` before the phase is closed.
