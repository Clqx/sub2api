# Security Boundary

## Trust Zones

- The monitor owns its PostgreSQL database and may write only there.
- A target Sub2API API is an external privileged system.
- A target Sub2API PostgreSQL connection is external and strictly read-only.
- ntfy is an outbound notification destination and receives redacted incident content only.
- The browser never connects directly to target APIs, target databases, or ntfy credentials.

## Assets and Actors

Protected assets are target administrator credentials, DB credentials, the monitor master key, normalized account/quota data, alert destinations, audit history, backups, and service availability. Threat actors include an unauthenticated network client, a compromised local administrator session, a malicious/compromised target, a compromised ntfy endpoint, and an operator with accidental over-broad configuration.

## Threat Model

| Entry/threat | Primary control | Verification | Residual risk |
|---|---|---|---|
| Target URL SSRF, redirect, DNS rebinding | Resolve and enforce network policy at connect time; block unsafe redirects and credential forwarding | Security integration tests with private/loopback/link-local and DNS changes | Allowed internal targets remain privileged by design. |
| Target response secret/data exfiltration | Size limits, schema validation, field allowlists, raw-payload rejection | Malformed/oversized fixture and redaction tests | A newly allowlisted field can be classified incorrectly. |
| DB mutation or expensive query | Dedicated read-only role, transaction read-only, fixed queries, timeout | Permission and timeout integration tests | Target DBA can grant unsafe rights after setup. |
| Credential disclosure in API/log/backup | Write-only API, centralized redaction, encrypted columns, encrypted restricted backups | API snapshots, log scans, restore drill | Compromise of the running process/master key exposes active secrets. |
| Master-key loss or rotation failure | Versioned envelope encryption, tested rotation and escrow/recovery runbook | Rotation and restore rehearsal | Loss of all key copies makes credentials unrecoverable. |
| ntfy content leakage or forged destination | Redacted templates, destination allowlist, TLS, test-publish preview | Content and redirect tests | ntfy operator sees intended notification content. |
| Active-probe unintended target mutation | DB connector always read-only; active API default off, second confirmation, side-effect contract, rate limit, audit, kill switches | Contract, UI, target-DB before/after, rate-limit, and emergency-stop tests | Target implementation may have undocumented side effects; disable when unbounded. |
| Cross-target observation merge | Stable `(target_id, external_id)`, API/DB fingerprint check | Mismatch and isolation integration tests | Weak fingerprints may require operator confirmation. |

## Required Controls

- Encrypt target credentials at rest using a master key supplied outside the monitor database.
- Return secret fields as write-only configuration state and exclude them from logs, traces, errors, and frontend payloads.
- Treat supplied Sub2API API keys as administrator credentials until a target proves a narrower scope.
- Reject unsafe target URLs and redirects according to an explicit SSRF/network policy; never forward authorization across an untrusted redirect.
- Use fixed parameterized SQL, schema/column/JSON-key allowlists, read-only transactions, and a database role with no write grants.
- Drop raw `credentials` and `extra` fields at the connector boundary. Persist only normalized, explicitly allowlisted monitoring fields.
- Cross-check API and DB target identity before enabling full-mode merge.
- Mark and audit active probes that call upstream providers or may mutate target-side snapshots/state. They are disabled by default.
- Prevent secrets from entering unencrypted backups; document master-key rotation, escrow, loss, and restore behavior.
- Record configuration and management actions in an immutable audit trail without recording secrets.

## Future Agent Controls

Collector Agent enrollment uses per-agent credentials, narrow target assignment, heartbeat expiry, replay protection, and revocation. Analysis Agent access is limited to normalized observations and incidents. Proposed management actions require explicit approval, scoped authorization, idempotency, and a complete audit record.
