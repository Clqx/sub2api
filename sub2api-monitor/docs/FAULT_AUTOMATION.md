# Fault Discovery, Event Subscription, and Automation

## Admin API Boundary

The target Admin API key is a global full-privilege credential. The monitor therefore exposes a fixed action catalog rather than a generic HTTP proxy.

| Monitor action | Target Admin API | Intended condition |
|---|---|---|
| `recover_state` | `POST /api/v1/admin/accounts/:id/recover-state` | Recover error, rate-limit, overload, temporary-unschedulable, and related runtime state through Sub2API's unified recovery service. |
| `clear_error` | `POST /api/v1/admin/accounts/:id/clear-error` | Clear a persisted account error after external verification. |
| `clear_rate_limit` | `POST /api/v1/admin/accounts/:id/clear-rate-limit` | Clear a stale rate-limit state. |
| `clear_temp_unschedulable` | `DELETE /api/v1/admin/accounts/:id/temp-unschedulable` | Remove a stale temporary quarantine. |
| `set_schedulable` | `POST /api/v1/admin/accounts/:id/schedulable` | Re-enable an account that was incorrectly left unschedulable. |

The monitor never exposes a generic method/path/body action. Account deletion, credential changes, imports/exports, proxy/routing changes, quota resets, system restart/upgrade, data management, and backup/restore APIs are outside the automation allowlist.

## Fault Sources

- Account availability, quota, upstream-rate, and channel incidents remain normalized by the monitor policy engine.
- Every failed scheduled collection creates a deduplicated `target.collection_failed` incident; the next successful collection resolves it.
- The worker polls the target's firing `/api/v1/admin/ops/alert-events` records. They are mirrored as `target.native_alert` incidents and resolved only when a complete firing snapshot no longer contains the source event.
- Unsupported or permission-denied Ops alert APIs degrade the capability and do not resolve previously known incidents from incomplete evidence.

## Automation Lifecycle

1. An `account.unavailable` incident transition is committed with a stable transition ID.
2. Enabled rules are matched by target and normalized availability reason. A fixed server-side action/reason map prevents broad rules from clearing unrelated state such as expiration or exhausted quota.
3. Cooldown and unique `(rule_id, transition_id)` constraints prevent duplicate work.
4. `recommend` rules create a reviewable execution without calling the target.
5. An operator may approve a recommendation with explicit side-effect confirmation.
6. `execute` rules enter the worker queue directly after the same confirmation was supplied when enabling the rule.
7. The target request carries `Idempotency-Key: monitor-auto-<rule>-<transition>`.
8. Success or failure, attempt count, bounded result metadata, and audit events are stored. A successful action queues an `automation_verify` collection.

The action response body is not persisted. This avoids retaining future target fields that might contain credentials.

## Event Subscription Contract

Subscriptions may be global or target-scoped and filter `incident.firing`, `incident.escalated`, and `incident.resolved` by severity. ntfy and Webhook deliveries use the same durable outbox and retry policy.

Webhook requests contain a JSON event with the stable transition ID, event type, occurrence time, target ID, and normalized incident fields. Optional authentication headers are:

```http
Authorization: Bearer <configured-token>
X-Sub2API-Monitor-Event: incident.firing
X-Sub2API-Monitor-Delivery: <outbox-id>
X-Sub2API-Monitor-Signature: sha256=<hex-hmac>
```

The signature is HMAC-SHA256 over the exact UTF-8 request body using deterministic, compact, key-sorted JSON. Consumers should compare it in constant time and deduplicate on `X-Sub2API-Monitor-Delivery` or `event_id`.

## Operational Safeguards

- New automation rules are disabled by default and use recommendation mode by default.
- Enabled automatic execution requires an explicit `confirm_side_effects` request.
- Cooldown is at least five minutes.
- Target credentials, Webhook bearer tokens, and signing secrets are encrypted and write-only.
- Notification destinations are revalidated and DNS-pinned for every attempt. Private destinations require the independent `MONITOR_ALLOW_PRIVATE_NOTIFICATION_TARGETS=true` opt-in.
- Every rule mutation, approval, queue decision, outcome, and target action is audited without secret values.
- Disabling a rule causes queued executions to be skipped; it does not roll back already completed target actions.
