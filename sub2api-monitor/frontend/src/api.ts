import type {
  Account,
  Capability,
  Dashboard,
  Incident,
  NotificationChannel,
  OutboxItem,
  Page,
  QuotaWindow,
  SystemStatus,
  Target,
  User,
} from './types'

const API_ROOT = import.meta.env.VITE_API_ROOT ?? '/api/v1'

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem('monitor_token')
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...init?.headers },
    credentials: 'same-origin',
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: string; message?: string } | null
    throw new ApiError(response.status, payload?.detail ?? payload?.message ?? `请求失败 (${response.status})`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  login: async (username: string, password: string) => {
    const result = await request<{ access_token: string }>('/auth/login', { method:'POST', body:JSON.stringify({username,password}) })
    localStorage.setItem('monitor_token', result.access_token)
    return result
  },
  me: () => request<User>('/auth/me'),
  logout: async () => { await request<void>('/auth/session', { method:'DELETE' }).catch(()=>undefined); localStorage.removeItem('monitor_token') },
  dashboard: () => request<Dashboard>('/dashboard'),
  targets: async () => { const items=(await request<Target[]>('/targets')).map(normalizeTarget); return {items,total:items.length} },
  createTarget: async (body: Record<string, unknown>) => normalizeTarget(await request<Target>('/targets', { method: 'POST', body: JSON.stringify(body) })),
  updateTarget: async (id: string, body: Record<string, unknown>) => normalizeTarget(await request<Target>(`/targets/${id}`, { method:'PATCH', body:JSON.stringify(body) })),
  deleteTarget: (id: string) => request<void>(`/targets/${id}`, { method:'DELETE' }),
  probeTarget: async (id: string) => normalizeTarget((await request<{target:Target}>(`/targets/${id}/probe`, { method: 'POST' })).target),
  collectTarget: async (id: string) => { const run=await request<{id:string}>(`/targets/${id}/collect`, { method: 'POST' }); return {run_id:run.id} },
  capabilities: (id: string) => request<Capability[]>(`/targets/${id}/capabilities`),
  setActiveQuotaRefresh: (id: string, body: { enabled:boolean; confirm_side_effects:boolean }) => request<Capability>(`/targets/${id}/capabilities/quota.active_refresh`, { method:'PUT', body:JSON.stringify(body) }),
  accounts: (query = '') => request<Page<Account>>(`/accounts${query}`),
  accountQuota: (id: string) => request<QuotaWindow[]>(`/accounts/${id}/quota`),
  incidents: async () => { const raw=await request<RawIncident[]>('/incidents'); const items=raw.map(mapIncident); return {items,total:items.length} },
  ackIncident: async (id: string) => mapIncident(await request<RawIncident>(`/incidents/${id}/ack`, { method: 'POST' })),
  channels: () => request<NotificationChannel[]>('/notification-channels'),
  createChannel: (body: Record<string, unknown>) => request<NotificationChannel>('/notification-channels',{method:'POST',body:JSON.stringify(body)}),
  updateChannel: (id: string, body: Record<string, unknown>) => request<NotificationChannel>(`/notification-channels/${id}`,{method:'PATCH',body:JSON.stringify(body)}),
  deleteChannel: (id: string) => request<void>(`/notification-channels/${id}`,{method:'DELETE'}),
  testChannel: (id: string) => request<OutboxItem>(`/notification-channels/${id}/test`,{method:'POST'}),
  outbox: () => request<OutboxItem[]>('/outbox?limit=100'),
  systemStatus: () => request<SystemStatus>('/system/status'),
}

interface RawIncident { id:string; target_id:string; severity:'warning'|'critical'|'info'; rule_key:string; subject_id:string; status:'firing'|'acknowledged'|'resolved'; title:string; message:string; fired_at:string; updated_at:string }
const mapIncident=(i:RawIncident):Incident=>({id:i.id,target_id:i.target_id,severity:i.severity,rule_key:i.rule_key,subject_name:i.title||i.subject_id,status:i.status,summary:i.message,started_at:i.fired_at,updated_at:i.updated_at})
const normalizeTarget=(target:Target):Target=>({...target,connection_state:target.connection_state??{
  api:target.api_connection_state??'unknown',
  ...(target.mode==='full'?{database:target.db_connection_state??'unknown',binding:target.binding_state??'pending'}:{}),
},last_success_at:target.last_success_at??target.last_probe_at})
