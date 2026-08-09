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
| Cost routing priority | `PUT /api/v1/admin/accounts/:id` with a priority-only body | Reconcile OpenAI API-key scheduling order from fresh effective upstream cost and availability. |

The monitor never exposes a generic method/path/body action. Account deletion, credential changes, imports/exports, proxy/routing changes, quota resets, system restart/upgrade, data management, and backup/restore APIs are outside the automation allowlist.

## One-Minute Cost Routing

Cost routing is target-scoped, disabled by default, and starts in `recommend` mode. Enabling either mode requires explicit side-effect confirmation because the controller invokes the upstream billing probe every 30 seconds. Each run has a 25-second hard budget, leaving margin for worker polling so a newly observed change can be applied within one minute when the worker and target are not overloaded.

Only accounts whose normalized identity is `platform=openai` and `type=apikey` are eligible. Every cycle refreshes the target account inventory, immediately inserts newly discovered eligible accounts, splits billing probes into the target API's maximum batch size of 20, runs batches concurrently within the hard budget, and uses `effective_rate_multiplier` before the resolved or synchronized fallback value.

Healthy account priority is deterministic:

```text
priority = clamp(round(effective_multiplier * priority_scale), minimum_priority, unhealthy_priority - 1)
```

Lower numeric priority is preferred by Sub2API. An unavailable account or account-specific billing-probe failure receives `unhealthy_priority`, so the next healthy cost band takes over. Operators may explicitly bind an eligible account to one or more OpenAI channel monitors. A missing, disabled, stale, degraded, failed, error, or unknown bound monitor fails closed and applies the same unhealthy priority. Recovery restores the account to its calculated cost band. Equal desired and current priorities are not rewritten.

The worker claims due policies with `FOR UPDATE SKIP LOCKED`, records a renewable owner lease, advances the next due time before network calls, and does not hold row locks while probing or updating the target. A second worker cannot execute the same target policy while that lease is active; an abandoned lease expires automatically. The worker re-reads policy enablement, mode, and lease ownership after probing and immediately before every bounded, idempotent priority `PUT`. Disabling the policy, switching to recommendation mode, or losing the lease cancels pending writes.

Recommendations are deduplicated while the desired priority remains unchanged. Decisions are retained for 30 days by default and can be configured with `MONITOR_COST_ROUTING_DECISION_RETENTION_DAYS`. Successes, failures, multiplier changes, account failures, quality failures, and probe failures are stored as decisions/incidents; every distinct multiplier or routing-condition change emits another firing transition through the existing ntfy/Webhook outbox.

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
- New cost-routing policies are disabled by default, use recommendation mode, and have a fixed 30-second controller interval with a 25-second hard execution budget.
- Enabled automatic execution requires an explicit `confirm_side_effects` request.
- Cooldown is at least five minutes.
- Target credentials, Webhook bearer tokens, and signing secrets are encrypted and write-only.
- Notification destinations are revalidated and DNS-pinned for every attempt. Private destinations require the independent `MONITOR_ALLOW_PRIVATE_NOTIFICATION_TARGETS=true` opt-in.
- Every rule mutation, approval, queue decision, outcome, and target action is audited without secret values.
- Disabling a rule causes queued executions to be skipped; it does not roll back already completed target actions.
