# Docker Acceptance Matrix

V1 reference deployment contains `web`, `api`, `worker`, `monitor-postgres`, and an idempotent one-shot `migrate` job. API/worker use the same immutable image; application containers run non-root with `no-new-privileges`, read-only root filesystems where practical, and only explicit writable volumes/tmpfs.

| ID | Scenario | Success predicate |
|---|---|---|
| DKR-DEP-01 | Validate/build | `docker compose config --quiet` and all pinned image builds succeed with no secret baked into image history. |
| DKR-DEP-02 | Fresh install | From an empty named data volume, migration completes once and all required health checks become healthy within the documented timeout. |
| DKR-DEP-03 | Idempotent start | Repeating `up -d --wait` applies no destructive migration and preserves targets/incidents. |
| DKR-DEP-04 | Worker restart | Restart during collection releases/expires leases, resumes schedules, and preserves outbox events without duplicate incident transitions. |
| DKR-DEP-05 | Dependency failure | API readiness fails when monitor DB/migration is unavailable; liveness remains meaningful; worker exposes a stale heartbeat. |
| DKR-DEP-06 | Secrets/network | Secrets enter through Docker secrets or `*_FILE`; only the configured web/API port is host-published; target DB and monitor DB are not public by default. |
| DKR-DEP-07 | Backup/restore | Restoring monitor data plus the matching key material recovers configuration/history; missing key material fails with an explicit unrecoverable-secret diagnostic. |
| DKR-DEP-08 | Upgrade/rollback | Supported previous release upgrades on a copied volume; rollback follows the documented compatibility path and never runs a destructive downgrade implicitly. |

Release evidence records Compose version, platform, command transcript, commit SHA, image digests, migration revision, timings, and retained-volume checks. Development tags may be mutable; release tags are semantic-version and commit-SHA immutable references.
