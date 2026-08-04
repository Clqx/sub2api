# V1 UI State Matrix

The React UI never derives target health from a single status or color. It presents reachability, readiness, coverage, and freshness separately.

| Condition | Display | Counts as healthy | Main action |
|---|---|---:|---|
| API and required account capabilities usable | Ready | Yes | View accounts |
| Public health works but account API is unsupported/denied | Not ready | No | Fix credentials or target version |
| Full mode, API works and DB fails | Full / Degraded | No | Test DB connection |
| Full mode, DB works and API fails | Full / Degraded | No | Refresh API credential |
| API/DB fingerprint mismatch | Configuration mismatch | No | Correct connector pairing |
| Capability supported, last call failed, sample still fresh | Temporarily unavailable | No | Retry/inspect run |
| Capability supported, runtime unavailable, sample stale | Stale data | No | Retry/inspect run |
| Capability unsupported | Unsupported | Excluded from that metric | Review coverage |
| Capability permission denied | Permission denied | No for required capability | Fix permission |
| Capability not conclusively probed | Unknown | No for required capability | Retry probe/inspect target |
| Active quota supported but disabled | Available, not enabled | Excluded from active coverage | Enable explicitly |
| Target disabled by operator | Disabled | Excluded | Enable target |

Target onboarding follows: connection details, mode, secret entry, connector tests, capability probe, policy/schedule, enablement. A target may be saved in `not_ready` state for correction, but the enable-monitoring command is unavailable until `accounts.inventory` and `accounts.availability` are supported and usable.

For active quota, the UI separately shows provider/account scope, target support, operator enablement, side-effect warning, schedule, last attempt, last success, and last error. No Agent navigation or placeholder page is rendered in V1.
