import { FormEvent, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ListTree, Plus, Power, PowerOff, RefreshCw, Satellite, Trash2, X } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'

export function TargetsPage() {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const q = useQuery({ queryKey: ['targets'], queryFn: api.targets })
  const refresh = () => qc.invalidateQueries({ queryKey: ['targets'] })
  const probe = useMutation({ mutationFn: api.probeTarget, onSuccess: refresh })
  const collect = useMutation({ mutationFn: api.collectTarget })
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateTarget(id, { enabled }),
    onSuccess: refresh,
  })
  const remove = useMutation({ mutationFn:api.deleteTarget, onSuccess:refresh })
  const operationError = probe.error ?? collect.error ?? toggle.error ?? remove.error

  return <>
    <div className="page-title"><div><h1>监控目标</h1><p>每个 Sub2API 实例独立采集、退避和告警</p></div><button className="primary" onClick={() => setAdding(true)}><Plus size={17}/>添加目标</button></div>
    {operationError && <ErrorState error={operationError}/>}
    {q.isError ? <ErrorState error={q.error}/> : <div className="table-wrap"><table><thead><tr><th>目标</th><th>模式</th><th>启用</th><th>能力就绪度</th><th>连接</th><th>最近成功</th><th></th></tr></thead><tbody>{q.data?.items.map(t => <TargetRows key={t.id} target={t} expanded={expanded === t.id} onExpand={() => setExpanded(expanded === t.id ? null : t.id)} onProbe={() => probe.mutate(t.id)} onCollect={() => collect.mutate(t.id)} onToggle={() => toggle.mutate({ id:t.id, enabled:!t.enabled })} onDelete={() => { if (window.confirm(`删除目标 ${t.name} 及其监控历史？`)) remove.mutate(t.id) }} pending={probe.isPending || collect.isPending || toggle.isPending || remove.isPending}/>)}</tbody></table>{q.data?.items.length === 0 && <Empty title="还没有目标" detail="添加第一个 Sub2API 实例并探测可用能力"/>}</div>}
    {adding && <TargetDialog onClose={() => setAdding(false)}/>}
  </>
}

function TargetRows({ target:t, expanded, onExpand, onProbe, onCollect, onToggle, onDelete, pending }: {
  target: Awaited<ReturnType<typeof api.targets>>['items'][number]
  expanded: boolean
  onExpand: () => void
  onProbe: () => void
  onCollect: () => void
  onToggle: () => void
  onDelete: () => void
  pending: boolean
}) {
  return <>
    <tr><td><strong>{t.name}</strong><small>{t.base_url}</small></td><td><span className="mode">{t.mode === 'full' ? 'FULL' : 'API ONLY'}</span></td><td><Status value={t.enabled ? 'enabled' : 'disabled'}/></td><td><Status value={t.monitoring_readiness}/>{t.last_error && <small className="danger-text">{t.last_error}</small>}</td><td>{Object.entries(t.connection_state ?? {}).map(([k,v]) => <span className="connection" key={k}>{k.toUpperCase()}: {v}</span>)}</td><td>{formatTime(t.last_success_at)}</td><td className="actions sticky-actions"><button className="icon-button" aria-label={`${t.name} 能力详情`} title="能力详情" onClick={onExpand}><ListTree/></button><button className="icon-button" aria-label={`${t.name} 重新探测`} title="重新探测" disabled={pending} onClick={onProbe}><Satellite/></button><button className="icon-button" aria-label={`${t.name} 立即采集`} title="立即采集" disabled={pending || !t.enabled || t.monitoring_readiness !== 'ready'} onClick={onCollect}><RefreshCw/></button><button className="icon-button" aria-label={`${t.name} ${t.enabled ? '停用' : '启用'}监控`} title={t.enabled ? '停用监控' : '启用监控'} disabled={pending || (!t.enabled && t.monitoring_readiness !== 'ready')} onClick={onToggle}>{t.enabled ? <PowerOff/> : <Power/>}</button><button className="icon-button" aria-label={`删除 ${t.name}`} title="删除目标" disabled={pending} onClick={onDelete}><Trash2/></button></td></tr>
    {expanded && <tr className="detail-row"><td colSpan={7}><Capabilities targetId={t.id}/></td></tr>}
  </>
}

function Capabilities({ targetId }: { targetId:string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey:['capabilities', targetId], queryFn:() => api.capabilities(targetId) })
  const update = useMutation({
    mutationFn:(enabled:boolean) => api.setActiveQuotaRefresh(targetId, { enabled, confirm_side_effects:enabled }),
    onSuccess:async() => {
      await q.refetch()
      await qc.invalidateQueries({ queryKey:['targets'] })
    },
  })
  function toggleActiveQuota(enabled:boolean) {
    if (enabled && !window.confirm('开启主动额度刷新后，监控服务会调用上游额度接口，并可能让 Sub2API 写入额度缓存或刷新令牌。确认继续？')) return
    update.mutate(enabled)
  }
  if (q.isLoading) return <div className="inline-loading">正在读取能力</div>
  if (q.isError) return <ErrorState error={q.error}/>
  return <>{update.isError && <div className="form-error capability-operation-error" role="alert">能力设置失败：{update.error.message}</div>}<div className="capability-grid">{q.data?.map(c => {
    const activeQuota = c.key === 'quota.active_refresh' && (c.scope_type == null || c.scope_type === 'target') && !c.scope_id
    const cannotEnable = !c.enabled && ['unsupported', 'permission_denied'].includes(c.support_state)
    return <div className={activeQuota ? 'capability-card active-quota-capability' : 'capability-card'} key={`${c.id}:${c.scope_type ?? 'target'}:${c.scope_id ?? ''}`}><strong>{activeQuota ? '主动额度刷新' : c.key}</strong><span><Status value={c.support_state}/><Status value={c.runtime_state}/><Status value={c.freshness}/></span><small>{c.reason ?? `${c.source} · ${c.side_effect}`}</small>{activeQuota && <div className="capability-control"><label className="switch-label"><input type="checkbox" role="switch" checked={c.enabled} disabled={update.isPending || cannotEnable} onChange={event => toggleActiveQuota(event.target.checked)}/><span>{c.enabled ? '已启用主动刷新' : '主动刷新已关闭'}</span></label><small className="side-effect-note">开启后会调用上游，目标可能写入额度缓存或刷新令牌。</small>{update.isPending && <span className="operation-pending" role="status">正在更新能力设置</span>}</div>}</div>
  })}</div></>
}

function TargetDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [mode, setMode] = useState<'api_only' | 'full'>('api_only')
  useEffect(() => { const close = (event:KeyboardEvent) => { if (event.key === 'Escape') onClose() }; window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close) }, [onClose])
  const create = useMutation({
    mutationFn: async ({ body, enable }: { body:Record<string,unknown>; enable:boolean }) => {
      const target = await api.createTarget(body)
      const probed = await api.probeTarget(target.id)
      if (enable && probed.monitoring_readiness === 'ready') await api.updateTarget(target.id, { enabled:true })
      return probed
    },
    onSuccess: async () => { await qc.invalidateQueries({ queryKey:['targets'] }); onClose() },
  })
  function submit(e:FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    const authType = String(f.get('auth_type'))
    const secret = String(f.get('api_key'))
    const databaseUrl = String(f.get('database_url') ?? '')
    create.mutate({ enable:f.get('enable') === 'on', body:{ name:f.get('name'), base_url:f.get('base_url'), mode, enabled:false, collection_interval_seconds:60, credential:{ auth_type:authType, ...(authType === 'x_api_key' ? { api_key:secret } : { access_token:secret }) }, ...(mode === 'full' ? { database:{ database_url:databaseUrl } } : {}) } })
  }
  return <div className="modal-backdrop"><div className="modal" role="dialog" aria-modal="true" aria-labelledby="target-dialog-title"><div className="modal-head"><div><h2 id="target-dialog-title">添加监控目标</h2><p>凭据仅写入后端加密存储</p></div><button className="icon-button" onClick={onClose} aria-label="关闭添加目标"><X/></button></div><form onSubmit={submit}><label>目标名称<input name="name" required placeholder="生产环境"/></label><label>Sub2API 地址<input name="base_url" required type="url" placeholder="https://sub.example.com"/></label><div className="form-row"><label>接入模式<select name="mode" value={mode} onChange={event => setMode(event.target.value as 'api_only' | 'full')}><option value="api_only">API ONLY</option><option value="full">FULL</option></select></label><label>认证方式<select name="auth_type"><option value="x_api_key">x-api-key</option><option value="bearer">Bearer JWT</option></select></label></div><label>管理员凭据<input name="api_key" required type="password" autoComplete="new-password"/></label>{mode === 'full' && <label>只读 PostgreSQL 地址<input name="database_url" required type="password" autoComplete="new-password" placeholder="postgresql://monitor_ro:password@postgres:5432/sub2api"/></label>}<label className="check-label"><input name="enable" type="checkbox" defaultChecked/>探测通过后启用自动监控</label><div className="callout">保存后执行 API 与只读数据库能力探测。FULL 模式会校验两侧账号身份，且不会主动调用上游额度接口。</div>{create.isError && <div className="form-error" role="alert">{create.error.message}</div>}<div className="modal-actions"><button type="button" onClick={onClose}>取消</button><button className="primary" disabled={create.isPending}>{create.isPending ? '保存并探测中' : '保存并探测'}</button></div></form></div></div>
}

const formatTime = (value?:string|null) => value ? new Intl.DateTimeFormat('zh-CN',{ dateStyle:'short', timeStyle:'medium' }).format(new Date(value)) : '尚无'
