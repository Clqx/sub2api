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
  name: string
  server_url: string
  topic: string
  enabled: boolean
  token_configured: boolean
}

export interface OutboxItem {
  id: string
  channel_id: string
  status: 'pending' | 'sent' | 'dead'
  attempts: number
  last_error?: string | null
  sent_at?: string | null
  created_at: string
}

export interface SystemStatus {
  database: string
  ready: boolean
  worker_last_seen_at?: string | null
  worker_stale: boolean
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
