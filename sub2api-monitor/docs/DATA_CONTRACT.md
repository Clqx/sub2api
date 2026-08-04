# Data and Identity Contract

All persisted and transported entities carry a schema version. External IDs are meaningful only inside a target boundary.

## Stable Keys

| Entity | Isolation/deduplication key |
|---|---|
| Target | `target_id` (Hub UUID) |
| Account | `(target_id, external_account_id)` |
| Group | `(target_id, external_group_id)` |
| Quota window | `(target_id, external_account_id, provider, quota_key, window_start_or_reset)` |
| Collection run | `(target_id, run_id)` |
| Observation | `(target_id, observation_id)`; replay key `(producer_id, batch_id, sequence)` |
| Incident | `(target_id, policy_id, subject_type, subject_id, rule_key, window_key)` fingerprint |
| Notification outbox | `(incident_id, transition_id, channel_id)` |

Display names, email addresses, provider labels, and array positions are never identity keys.

## Observation Envelope

```json
{
  "schema_version": 1,
  "observation_id": "uuid",
  "producer_id": "hub-worker-or-agent-id",
  "target_id": "hub-target-uuid",
  "run_id": "uuid",
  "batch_id": "uuid",
  "sequence": 12,
  "subject": {"type": "account", "external_id": "target-local-id"},
  "kind": "quota.window",
  "observed_at": "2026-08-03T09:58:00Z",
  "received_at": "2026-08-03T09:58:02Z",
  "source": "sub2api_api",
  "quality": {"freshness": "fresh", "runtime_state": "healthy"},
  "payload": {}
}
```

Hub workers inject `target_id` from the claimed job. Future Collector Agents are assigned target IDs at enrollment; the Hub ignores or validates any self-reported target and rejects observations outside that assignment. `(producer_id, batch_id, sequence)` makes retries idempotent and exposes gaps/out-of-order delivery. `observed_at` is producer time; `received_at` is Hub time, and excessive skew lowers quality rather than rewriting history.

## Incident and Action Boundary

Incident fingerprints always contain `target_id`, so equal account IDs on different targets cannot deduplicate together. Events reference immutable source observation IDs and collection runs. A future Analysis Agent may emit only versioned Finding/Recommendation objects referencing existing observations/incidents. Approved actions are created and executed by a Hub executor; Agent output is never itself an executable command.

## Retention and Evolution

Current-state tables point to immutable recent observations while history follows configurable retention. Schema additions are backward compatible within a major envelope version. Unknown payload fields are ignored at read time but raw unvalidated payloads are not persisted.
