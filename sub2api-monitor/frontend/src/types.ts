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
  remaining_percent?: number | null
  quota_freshness?: Freshness
  observed_at?: string | null
  expires_at?: string | null
  rate_limit_reset_at?: string | null
  overload_until?: string | null
  temp_unschedulable_until?: string | null
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

export interface Dashboard {
  targets_total: number
  targets_ready: number
  accounts_total: number
  accounts_available: number
  low_quota_accounts: number
  active_incidents: number
  failed_collections_24h: number
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
