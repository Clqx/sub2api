export type SupportState = 'unknown' | 'supported' | 'unsupported' | 'permission_denied'
export type RuntimeState = 'healthy' | 'unavailable' | 'misconfigured' | 'disabled'
export type Freshness = 'fresh' | 'stale' | 'missing'
export type Readiness = 'ready' | 'degraded' | 'not_ready'

export interface Target {
  id: string
  name: string
  base_url: string
  mode: 'api_only' | 'full'
  enabled: boolean
  monitoring_readiness: Readiness
  api_connection_state?: string
  db_connection_state?: string
  binding_state?: string
  binding_confidence?: string | null
  database_configured?: boolean
  connection_state?: Record<string, string>
  coverage_level?: string[]
  last_success_at?: string | null
  last_probe_at?: string | null
  last_error?: string | null
}

export interface Account {
  id: string
  target_id: string
  target_name?: string
  external_account_id: string
  name: string
  platform: string
  account_type: string
  status: string
  schedulable: boolean
  available: boolean | null
  availability_reasons: string[]
  group_ids?: string[]
  priority?: number | null
  remaining_percent?: number | null
  quota_freshness?: Freshness
  observed_at?: string | null
  expires_at?: string | null
  rate_limit_reset_at?: string | null
  overload_until?: string | null
  temp_unschedulable_until?: string | null
  rate_multiplier?: number | null
  upstream_billing_probe_enabled: boolean
  upstream_billing_rate_sync_enabled: boolean
  upstream_billing_probe?: UpstreamBillingProbeSnapshot | null
  routing_desired_priority?: number | null
  routing_status?: 'recommend' | 'recommended' | 'in_sync' | 'succeeded' | 'failed' | 'cancelled' | null
  routing_updated_at?: string | null
  routing_applied_at?: string | null
}

export interface UpstreamBillingProbeSnapshot {
  status: 'ok' | 'unsupported' | 'failed'
  data?: Record<string, unknown>
  received_at?: string
  fresh_until?: string
  last_attempt_at?: string
  next_probe_at?: string
  failure_count?: number
  http_status?: number
  last_error?: string
  synced_rate_multiplier?: number
}

export interface UpstreamBillingSettings { enabled:boolean; interval_minutes:number }

export interface CostRoutingPolicy {
  id?:string|null
  target_id:string
  enabled:boolean
  mode:'recommend'|'execute'
  probe_interval_seconds:number
  priority_scale:number
  unhealthy_priority:number
  minimum_priority:number
  quality_bindings:Record<string,string[]>
  fallback_account_ids?:string[]
  fallback_priorities?:Record<string,number>
  last_run_at?:string|null
  next_run_at?:string|null
  last_error?:string|null
  last_account_count:number
  last_change_count:number
  created_at?:string|null
  updated_at?:string|null
}

export interface RoutingDecision {
  id:string
  policy_id?:string|null
  target_id?:string|null
  external_account_id:string
  account_name:string
  observed_multiplier?:number|null
  previous_priority?:number|null
  desired_priority:number
  reason:'cost_increase'|'cost_decrease'|'cost_discovered'|'unavailable'|'probe_failed'|'quality_failed'|'fallback_protected'|'recovery'|'priority_reconcile'|'in_sync'
  mode:'recommend'|'execute'
  status:'recommended'|'running'|'succeeded'|'failed'|'cancelled'
  result:Record<string,unknown>
  last_error?:string|null
  created_at:string
  finished_at?:string|null
}

export interface Incident {
  id: string
  target_id: string
  target_name?: string
  severity: 'warning' | 'critical' | 'info'
  rule_key: string
  subject_name: string
  status: 'firing' | 'acknowledged' | 'silenced' | 'resolved'
  summary: string
  started_at: string
  updated_at: string
}

export interface AlertPolicy {
  id:string
  target_id?:string|null
  name:string
  enabled:boolean
  unavailable_enabled:boolean
  channel_failure_enabled:boolean
  native_alerts_enabled:boolean
  collection_failure_enabled:boolean
  ttft_enabled:boolean
  ttft_percentile:'p50'|'p90'|'p95'|'p99'|'avg'|'max'
  ttft_min_samples:number
  ttft_warning_ms:number
  ttft_critical_ms:number
  ttft_recovery_ms:number
  quota_warning_remaining:number
  quota_critical_remaining:number
  quota_recovery_remaining:number
  created_at:string
  updated_at:string
}

export interface Dashboard {
  targets_total: number
  targets_ready: number
  accounts_total: number
  accounts_available: number
  low_quota_accounts: number
  active_incidents: number
  failed_collections_24h: number
  channels_total: number
  channels_unhealthy: number
}

export type ChannelMonitorStatus = '' | 'operational' | 'degraded' | 'failed' | 'error'

export interface ChannelMonitor {
  id:string
  target_id:string
  target_name?:string | null
  external_monitor_id:string
  name:string
  provider:'openai'|'anthropic'|'gemini'|'grok'
  api_mode:'chat_completions'|'responses'
  endpoint:string
  api_key_masked:string
  api_key_decrypt_failed:boolean
  primary_model:string
  extra_models:string[]
  group_name:string
  enabled:boolean
  interval_seconds:number
  jitter_seconds:number
  last_checked_at?:string | null
  primary_status:ChannelMonitorStatus
  primary_latency_ms?:number | null
  availability_7d:number
  extra_models_status:Array<{model:string;status:ChannelMonitorStatus;latency_ms?:number|null}>
  template_id?:string|null
  extra_headers:Record<string,string>
  body_override_mode:'off'|'merge'|'replace'
  body_override?:Record<string,unknown>|null
  observed_at:string
}

export interface ChannelCheck {
  model:string
  status:Exclude<ChannelMonitorStatus,''>
  latency_ms?:number|null
  ping_latency_ms?:number|null
  message:string
  checked_at:string
}

export type ChannelQualityTimeRange = '6h'|'24h'|'7d'|'30d'

export interface ChannelQualityLatency {
  sample_count:number
  p50_ms?:number|null
  p90_ms?:number|null
  p95_ms?:number|null
  avg_ms?:number|null
}

export interface ChannelQualityMetrics {
  success_requests:number
  error_requests:number
  request_count:number
  input_tokens:number
  output_tokens:number
  cache_creation_tokens:number
  cache_read_tokens:number
  token_count:number
  rpm:number
  tpm:number
  error_rate:number
  success_rate:number
  cache_rate:number
  cache_rate_numerator:number
  cache_rate_denominator:number
  ttft:ChannelQualityLatency
  duration:ChannelQualityLatency
}

export interface ChannelQualityHealth {
  overall:'healthy'|'warning'|'critical'|'unknown'
  error_rate:'healthy'|'warning'|'critical'|'unknown'
  ttft:'healthy'|'warning'|'critical'|'unknown'
  cache:'healthy'|'warning'|'critical'|'unknown'
  score?:number|null
  minimum_sample:number
}

export interface ChannelQualityTrendPoint {
  bucket_start:string
  metrics:ChannelQualityMetrics
  health:ChannelQualityHealth
}

export interface ChannelQualityRow {
  platform:string
  group_id?:number|null
  group_name?:string|null
  rate_multiplier?:number|null
  group_status:string
  metrics:ChannelQualityMetrics
  health:ChannelQualityHealth
  buckets:ChannelQualityTrendPoint[]
}

export interface ChannelQualitySnapshot {
  target_id:string
  target_name:string
  generated_at:string
  time_range:ChannelQualityTimeRange
  coverage:{
    requested_start:string
    requested_end:string
    coverage_start:string
    data_through:string
    computed_at:string
    aggregation_lag_seconds:number
    coverage_complete:boolean
    bucket_seconds:number
  }
  items:ChannelQualityRow[]
  failures:Record<string,string>
}

export interface Capability {
  id: string
  key: string
  scope_type?: string
  scope_id?: string
  support_state: SupportState
  runtime_state: RuntimeState
  freshness: Freshness
  enabled: boolean
  source: string
  side_effect: string
  reason?: string | null
}

export interface QuotaWindow {
  id: string
  quota_key: string
  label: string
  utilization_percent?: number | null
  remaining_percent?: number | null
  used_value?: number | null
  remaining_value?: number | null
  limit_value?: number | null
  unit: string
  reset_at?: string | null
  observed_at: string
  source: string
  freshness: Freshness
}

export interface AccountUsageHistory {
  date?: string | null
  label?: string | null
  requests?: number | null
  tokens?: number | null
  cost?: number | null
  actual_cost?: number | null
  user_cost?: number | null
}

export interface AccountUsageDay {
  date?: string | null
  label?: string | null
  requests?: number | null
  tokens?: number | null
  cost?: number | null
  user_cost?: number | null
}

export interface AccountUsageSummary {
  days?: number | null
  actual_days_used?: number | null
  total_cost?: number | null
  total_user_cost?: number | null
  total_standard_cost?: number | null
  total_requests?: number | null
  total_tokens?: number | null
  avg_daily_cost?: number | null
  avg_daily_user_cost?: number | null
  avg_daily_requests?: number | null
  avg_daily_tokens?: number | null
  avg_duration_ms?: number | null
  today?: AccountUsageDay | null
  highest_cost_day?: AccountUsageDay | null
  highest_request_day?: AccountUsageDay | null
}

export interface AccountModelStat {
  model?: string | null
  requests?: number | null
  input_tokens?: number | null
  output_tokens?: number | null
  cache_creation_tokens?: number | null
  cache_read_tokens?: number | null
  total_tokens?: number | null
  cost?: number | null
  actual_cost?: number | null
  account_cost?: number | null
}

export interface AccountEndpointStat {
  endpoint?: string | null
  requests?: number | null
  total_tokens?: number | null
  cost?: number | null
  actual_cost?: number | null
}

export interface AccountUsageStats {
  history: AccountUsageHistory[]
  summary: AccountUsageSummary
  models: AccountModelStat[]
  endpoints: AccountEndpointStat[]
  upstream_endpoints: AccountEndpointStat[]
}

export interface NotificationChannel {
  id: string
  target_id?: string | null
  name: string
  kind: 'ntfy' | 'telegram' | 'webhook'
  server_url: string
  topic: string
  enabled: boolean
  event_types: Array<'incident.firing' | 'incident.escalated' | 'incident.resolved' | 'routing.account_switched' | 'routing.rate_recovered'>
  severities: Array<'info' | 'warning' | 'critical'>
  token_configured: boolean
  signing_secret_configured: boolean
  created_at: string
}

export interface OutboxItem {
  id: string
  channel_id: string
  channel_name?: string | null
  channel_kind?: 'ntfy' | 'telegram' | 'webhook' | null
  status: 'pending' | 'sent' | 'dead'
  attempts: number
  last_error?: string | null
  sent_at?: string | null
  created_at: string
}

export type AutomationAction = 'recover_state' | 'clear_error' | 'clear_rate_limit' | 'clear_temp_unschedulable' | 'set_schedulable'

export interface AutomationRule {
  id: string
  target_id?: string | null
  name: string
  enabled: boolean
  trigger_rule_key: 'account.unavailable'
  action: AutomationAction
  mode: 'recommend' | 'execute'
  reason_match_mode: 'any' | 'all'
  reason_filters: string[]
  cooldown_seconds: number
  created_at: string
  updated_at: string
}

export interface AutomationExecution {
  id: string
  rule_id: string | null
  incident_id: string | null
  transition_id: string
  target_id: string | null
  external_account_id: string
  action: AutomationAction
  mode: 'recommend' | 'execute'
  status: 'recommended' | 'approved' | 'queued' | 'running' | 'applied' | 'verified' | 'verification_failed' | 'skipped_stale' | 'skipped_unverifiable' | 'cancelled' | 'failed' | 'succeeded' | 'skipped'
  attempts: number
  result: Record<string, unknown>
  last_error?: string | null
  started_at?: string | null
  finished_at?: string | null
  created_at: string
}

export interface SystemStatus {
  database: string
  ready: boolean
  worker_last_seen_at?: string | null
  worker_stale: boolean
  worker_stalled_loops: string[]
  pending_outbox: number
  failed_runs_24h: number
}

export interface User { id: string; username: string; is_admin: boolean }

export interface Page<T> { items: T[]; total: number; next_cursor?: string | null }

export interface OperationsCapability {
  support_state:string
  runtime_state:string
  freshness:string
  reason?:string|null
}

export interface OpsRateSummary { current:number; peak:number; avg:number }
export interface OpsPercentiles { p50_ms?:number|null; p90_ms?:number|null; p95_ms?:number|null; p99_ms?:number|null; avg_ms?:number|null; max_ms?:number|null }
export interface OpsOverview {
  health_score?:number
  success_count:number
  error_count_total:number
  request_count_total:number
  token_consumed:number
  sla:number
  error_rate:number
  upstream_error_rate:number
  qps:OpsRateSummary
  tps:OpsRateSummary
  duration:OpsPercentiles
  ttft:OpsPercentiles
  ttft_sample_count?:number
  system_metrics?:Record<string,unknown>|null
  job_heartbeats?:Array<Record<string,unknown>>|null
}
export interface OpsTrendPoint { bucket_start:string; request_count:number; token_consumed:number; switch_count?:number; qps:number; tps:number }
export interface OpsErrorTrendPoint { bucket_start:string; error_count_total:number; business_limited_count:number; error_count_sla:number; upstream_error_count_excl_429_529:number; upstream_429_count:number; upstream_529_count:number }
export interface OpsSnapshotResource { generated_at:string; overview:OpsOverview; throughput_trend:{bucket:string;points:OpsTrendPoint[]}; error_trend:{bucket:string;points:OpsErrorTrendPoint[]} }
export interface OpsListResource<T=Record<string,unknown>> { items:T[]; total:number; page?:number; page_size?:number; pages?:number }
export interface OpsGroup { id:number; name:string; platform:string; status:string; rate_multiplier:number; subscription_type?:string }
export interface OpsGroupUsage { group_id:number; today_cost:number; total_cost:number }
export interface OpsGroupCapacity { group_id:number; concurrency_used:number; concurrency_max:number; sessions_used:number; sessions_max:number; rpm_used:number; rpm_max:number }
export interface OpsErrorItem { id?:number; created_at?:string; fired_at?:string; request_id?:string; platform?:string; model?:string; status_code?:number; severity?:string; phase?:string; title?:string; description?:string; message?:string; account_name?:string; resolved?:boolean; status?:string }
export interface OpsRequestItem { created_at?:string; request_id?:string; kind?:string; platform?:string; model?:string; duration_ms?:number|null; status_code?:number|null; phase?:string; message?:string }
export interface OperationsResources {
  ops_snapshot?:OpsSnapshotResource
  latency_histogram?:{total_requests:number;buckets:Array<{range:string;count:number}>}
  error_distribution?:{total:number;items:Array<{status_code:number;total:number;sla:number;business_limited:number}>}
  openai_token_stats?:OpsListResource<{model:string;request_count:number;avg_tokens_per_sec?:number|null;avg_first_token_ms?:number|null;total_output_tokens:number;avg_duration_ms:number}>
  concurrency?:{enabled:boolean;platform:Record<string,Record<string,unknown>>;group:Record<string,Record<string,unknown>>;account:Record<string,Record<string,unknown>>;timestamp?:string}
  user_concurrency?:{enabled:boolean;user:Record<string,Record<string,unknown>>;timestamp?:string}
  account_availability?:{enabled:boolean;platform:Record<string,Record<string,unknown>>;group:Record<string,Record<string,unknown>>;account:Record<string,Record<string,unknown>>;timestamp?:string}
  realtime_traffic?:{enabled:boolean;summary?:{qps:OpsRateSummary;tps:OpsRateSummary;window:string}|null;timestamp?:string}
  request_errors?:OpsListResource<OpsErrorItem>
  upstream_errors?:OpsListResource<OpsErrorItem>
  requests?:OpsListResource<OpsRequestItem>
  alert_events?:OpsErrorItem[]
  system_logs?:OpsListResource<OpsErrorItem & {level?:string;component?:string;host?:string}>
  system_log_health?:Record<string,unknown>
  auth_cache_health?:Record<string,unknown>
  ingress_health?:Record<string,unknown>
  groups?:OpsGroup[]
  group_usage?:OpsGroupUsage[]
  group_capacity?:OpsGroupCapacity[]
}
export interface OperationsSnapshot {
  target_id:string
  target_name:string
  generated_at:string
  time_range:'5m'|'30m'|'1h'|'6h'|'24h'
  resources:OperationsResources
  failures:Record<string,string>
  capabilities:Record<string,OperationsCapability>
}
