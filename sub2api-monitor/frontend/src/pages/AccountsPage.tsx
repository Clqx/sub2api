import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Eye, Search, X } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import { formatDateTime, quotaRemainingText, quotaSourceLabel, quotaUsageText } from '../quotaPresentation'
import type {
  Account,
  AccountEndpointStat,
  AccountModelStat,
  AccountUsageDay,
  AccountUsageHistory,
  AccountUsageStats,
} from '../types'

type DetailView = 'usage' | 'status'
type StatsDays = 7 | 30 | 90

export function AccountsPage() {
  const [search,setSearch] = useState('')
  const [selected,setSelected] = useState<Account | null>(null)
  const q = useInfiniteQuery({
    queryKey:['accounts',search],
    initialPageParam:null as string | null,
    queryFn:({ pageParam }) => {
      const params = new URLSearchParams({ limit:'100' })
      if (search) params.set('search', search)
      if (pageParam) params.set('cursor', pageParam)
      return api.accounts(`?${params}`)
    },
    getNextPageParam:page => page.next_cursor ?? undefined,
  })
  const accounts = q.data?.pages.flatMap(page => page.items) ?? []
  return <><div className="page-title"><div><h1>账号</h1><p>账号身份按目标隔离，额度未知不会显示为零</p></div><label className="search"><Search size={17}/><span className="sr-only">搜索账号或平台</span><input value={search} onChange={e => setSearch(e.target.value)} placeholder="搜索账号或平台"/></label></div>{q.isError ? <ErrorState error={q.error}/> : <div className="table-wrap"><table className="account-table"><thead><tr><th>账号</th><th>目标</th><th>平台</th><th>账号倍率</th><th>分组</th><th>可用性</th><th>剩余额度</th><th>观测时间</th><th></th></tr></thead><tbody>{accounts.map(a => <tr key={a.id}><td><strong>{a.name}</strong><small>ID {a.external_account_id} · {a.account_type}</small></td><td>{a.target_name ?? a.target_id}</td><td><span className="platform">{a.platform}</span></td><td>{a.rate_multiplier == null ? <span className="unknown-value">--</span> : `×${formatMultiplier(a.rate_multiplier)}`}</td><td><span className="account-groups" title={(a.group_ids ?? []).join(', ')}>{a.group_ids?.length ? a.group_ids.join(', ') : '--'}</span></td><td>{a.available === null ? <Status value="unknown"/> : <Status value={a.available ? 'available' : 'unavailable'}/>}<small>{a.availability_reasons.join(' · ')}</small></td><td>{a.remaining_percent == null ? <span className="unknown-value">未提供额度 <Status value={a.quota_freshness ?? 'missing'}/></span> : <div className="quota"><div><i style={{ width:`${Math.max(0,Math.min(100,a.remaining_percent))}%` }}/></div><span>{a.remaining_percent.toFixed(1)}%</span><Status value={a.quota_freshness ?? 'missing'}/></div>}</td><td>{a.observed_at ? new Date(a.observed_at).toLocaleString('zh-CN') : '--'}</td><td className="actions sticky-actions"><button className="icon-button" aria-label={`查看 ${a.name} 账号详情`} onClick={() => setSelected(a)}><Eye/></button></td></tr>)}</tbody></table>{accounts.length === 0 && <Empty title="没有账号观测" detail="目标完成首次采集后，账号会出现在这里"/>}{q.hasNextPage && <div className="load-more"><button disabled={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>{q.isFetchingNextPage ? '加载中' : '加载更多'}</button></div>}</div>}{selected && <AccountDetail account={selected} onClose={() => setSelected(null)}/>}</>
}

function AccountDetail({ account, onClose }: { account:Account; onClose:()=>void }) {
  const [view,setView] = useState<DetailView>('usage')
  const [days,setDays] = useState<StatsDays>(30)
  const stats = useQuery({
    queryKey:['account-stats',account.id,days],
    queryFn:() => api.accountStats(account.id,days),
    enabled:view === 'usage',
  })
  const quota = useQuery({
    queryKey:['account-quota',account.id],
    queryFn:() => api.accountQuota(account.id),
    enabled:view === 'status',
  })
  return <div className="modal-backdrop"><div className="modal account-detail" role="dialog" aria-modal="true" aria-labelledby="account-detail-title"><div className="modal-head"><div><h2 id="account-detail-title">{account.name}</h2><p>{account.target_name ?? account.target_id} · {account.platform} · {account.account_type} · ID {account.external_account_id}</p></div><button className="icon-button" onClick={onClose} aria-label="关闭账号详情"><X/></button></div><div className="detail-content"><div className="account-detail-overview"><div className="availability-detail"><Status value={account.available === null ? 'unknown' : account.available ? 'available' : 'unavailable'}/><span>{account.available === null ? '可用性未知' : account.availability_reasons.length ? account.availability_reasons.join(' · ') : '当前可用'}</span></div><dl><div><dt>账号倍率</dt><dd>{account.rate_multiplier == null ? '--' : `×${formatMultiplier(account.rate_multiplier)}`}</dd></div><div><dt>分组</dt><dd>{account.group_ids?.length ? account.group_ids.join(', ') : '--'}</dd></div></dl></div><div className="view-tabs account-detail-tabs" role="tablist" aria-label="账号详情视图"><button role="tab" aria-selected={view === 'usage'} className={view === 'usage' ? 'active' : ''} onClick={() => setView('usage')}>使用统计</button><button role="tab" aria-selected={view === 'status'} className={view === 'status' ? 'active' : ''} onClick={() => setView('status')}>额度与状态</button></div>{view === 'usage' ? <UsageStatistics days={days} onDaysChange={setDays} query={stats}/> : <QuotaAndStatus account={account} query={quota}/>}</div></div></div>
}

function UsageStatistics({ days, onDaysChange, query }:{ days:StatsDays; onDaysChange:(days:StatsDays)=>void; query:ReturnType<typeof useQuery<AccountUsageStats>> }) {
  return <div className="account-usage"><div className="usage-toolbar"><div><h3>账号使用统计</h3><p>来自上游 Sub2API 的账号归因数据</p></div><div className="period-switch" aria-label="统计周期">{([7,30,90] as StatsDays[]).map(value => <button key={value} className={days === value ? 'active' : ''} aria-pressed={days === value} onClick={() => onDaysChange(value)}>{value} 天</button>)}</div></div>{query.isLoading ? <div className="inline-loading">正在读取账号统计</div> : query.isError ? <ErrorState error={query.error}/> : query.data ? <UsageStatisticsContent stats={query.data} requestedDays={days}/> : <Empty title="没有使用统计" detail="上游没有返回该账号的统计数据"/>}</div>
}

function UsageStatisticsContent({ stats, requestedDays }:{ stats:AccountUsageStats; requestedDays:StatsDays }) {
  const summary = stats.summary
  return <><section className="usage-metrics" aria-label="账号统计摘要"><UsageMetric label="总请求" value={formatNumber(summary.total_requests)}/><UsageMetric label="总 Token" value={formatCompact(summary.total_tokens)}/><UsageMetric label="账号成本" value={formatCost(summary.total_cost)}/><UsageMetric label="用户计费" value={formatCost(summary.total_user_cost)}/><UsageMetric label="标准成本" value={formatCost(summary.total_standard_cost)}/><UsageMetric label="日均请求" value={formatNumber(summary.avg_daily_requests)}/><UsageMetric label="平均响应" value={formatDuration(summary.avg_duration_ms)}/><UsageMetric label="活跃天数" value={summary.actual_days_used == null ? '--' : `${summary.actual_days_used} / ${requestedDays}`}/></section><section className="usage-section"><h3>当日与峰值</h3><div className="usage-highlights"><UsageHighlight title="今日" item={summary.today} primaryLabel="请求" primaryValue={formatNumber(summary.today?.requests)} secondaryLabel="账号成本" secondaryValue={formatCost(summary.today?.cost)}/><UsageHighlight title="成本峰值日" item={summary.highest_cost_day} primaryLabel="账号成本" primaryValue={formatCost(summary.highest_cost_day?.cost)} secondaryLabel="用户计费" secondaryValue={formatCost(summary.highest_cost_day?.user_cost)}/><UsageHighlight title="请求峰值日" item={summary.highest_request_day} primaryLabel="请求" primaryValue={formatNumber(summary.highest_request_day?.requests)} secondaryLabel="账号成本" secondaryValue={formatCost(summary.highest_request_day?.cost)}/></div></section><DailyTrend history={stats.history}/><section className="usage-section"><h3>模型分布</h3><ModelStatsTable items={stats.models}/></section><div className="usage-distributions"><section className="usage-section"><h3>请求端点</h3><EndpointStatsTable items={stats.endpoints}/></section><section className="usage-section"><h3>上游端点</h3><EndpointStatsTable items={stats.upstream_endpoints}/></section></div></>
}

function UsageMetric({ label,value }:{ label:string; value:string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function UsageHighlight({ title,item,primaryLabel,primaryValue,secondaryLabel,secondaryValue }:{ title:string; item?:AccountUsageDay|null; primaryLabel:string; primaryValue:string; secondaryLabel:string; secondaryValue:string }) {
  return <div><header><strong>{title}</strong><span>{item?.label ?? item?.date ?? '--'}</span></header><dl><div><dt>{primaryLabel}</dt><dd>{primaryValue}</dd></div><div><dt>{secondaryLabel}</dt><dd>{secondaryValue}</dd></div></dl></div>
}

function DailyTrend({ history }:{ history:AccountUsageHistory[] }) {
  if (!history.length) return <section className="usage-section"><h3>每日请求趋势</h3><div className="distribution-empty">暂无趋势数据</div></section>
  const maxRequests = Math.max(...history.map(item => item.requests ?? 0),1)
  const labelInterval = history.length > 45 ? 15 : history.length > 20 ? 5 : 1
  return <section className="usage-section"><h3>每日请求趋势</h3><div className="usage-trend-scroll"><div className="usage-trend" style={{ '--trend-columns':history.length } as React.CSSProperties}>{history.map((item,index) => { const height=item.requests == null ? 0 : Math.max(3,(item.requests/maxRequests)*100); const label=item.label ?? item.date ?? ''; return <div className="trend-column" key={`${item.date ?? label}-${index}`} title={`${label} · 请求 ${formatNumber(item.requests)} · Token ${formatCompact(item.tokens)} · 账号成本 ${formatCost(item.actual_cost)}`}><span className="trend-value">{item.requests == null ? '' : formatCompact(item.requests)}</span><i className={item.requests == null ? 'missing' : ''} style={{ height:`${height}%` }}/><small>{index % labelInterval === 0 || index === history.length-1 ? shortDate(label) : ''}</small></div> })}</div></div></section>
}

function ModelStatsTable({ items }:{ items:AccountModelStat[] }) {
  if (!items.length) return <div className="distribution-empty">暂无模型数据</div>
  return <div className="stats-table-wrap"><table className="stats-table"><thead><tr><th>模型</th><th>请求</th><th>Token</th><th>账号成本</th><th>用户计费</th><th>标准成本</th></tr></thead><tbody>{items.map((item,index) => <tr key={`${item.model ?? 'unknown'}-${index}`}><td title={item.model ?? ''}>{item.model ?? '未知模型'}</td><td>{formatNumber(item.requests)}</td><td>{formatCompact(item.total_tokens)}</td><td>{formatCost(item.account_cost)}</td><td>{formatCost(item.actual_cost)}</td><td>{formatCost(item.cost)}</td></tr>)}</tbody></table></div>
}

function EndpointStatsTable({ items }:{ items:AccountEndpointStat[] }) {
  if (!items.length) return <div className="distribution-empty">暂无端点数据</div>
  return <div className="stats-table-wrap"><table className="stats-table endpoint-stats-table"><thead><tr><th>端点</th><th>请求</th><th>Token</th><th>用户计费</th><th>标准成本</th></tr></thead><tbody>{items.map((item,index) => <tr key={`${item.endpoint ?? 'unknown'}-${index}`}><td title={item.endpoint ?? ''}>{item.endpoint ?? '未知端点'}</td><td>{formatNumber(item.requests)}</td><td>{formatCompact(item.total_tokens)}</td><td>{formatCost(item.actual_cost)}</td><td>{formatCost(item.cost)}</td></tr>)}</tbody></table></div>
}

function QuotaAndStatus({ account, query }:{ account:Account; query:ReturnType<typeof useQuery<Awaited<ReturnType<typeof api.accountQuota>>>> }) {
  return <><section className="account-state-grid" aria-label="账号状态详情"><StateField label="账号状态" value={account.status || '未知'}/><StateField label="可调度" value={account.schedulable ? '是' : '否'}/><StateField label="账号过期时间" value={formatDateTime(account.expires_at)}/><StateField label="限流解除时间" value={formatDateTime(account.rate_limit_reset_at)}/><StateField label="过载解除时间" value={formatDateTime(account.overload_until)}/><StateField label="临时不可调度至" value={formatDateTime(account.temp_unschedulable_until)}/></section><div className="quota-section-title"><h3>额度窗口</h3><p>额度值保留各来源语义，未知值不会换算为零</p></div>{query.isLoading ? <div className="inline-loading">正在读取额度窗口</div> : query.isError ? <ErrorState error={query.error}/> : <div className="quota-windows">{query.data?.map(window => <article className="quota-window" key={window.id}><div className="quota-window-head"><strong>{window.label}</strong><Status value={window.freshness}/></div><div className="quota-remaining"><span>剩余</span><b>{quotaRemainingText(window)}</b></div><p className="quota-used">{quotaUsageText(window)}</p><dl><div><dt>重置时间</dt><dd>{formatDateTime(window.reset_at)}</dd></div><div><dt>采样时间</dt><dd>{formatDateTime(window.observed_at)}</dd></div><div><dt>数据来源</dt><dd title={window.source}>{quotaSourceLabel(window.source)}</dd></div></dl></article>)}{query.data?.length === 0 && <Empty title="没有额度数据" detail="目标未配置额度，或当前接入能力没有提供可比较的额度窗口"/>}</div>}</>
}

function StateField({ label, value }:{ label:string; value:string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function formatMultiplier(value:number) {
  return value.toFixed(4).replace(/\.?0+$/,'')
}

function formatNumber(value:number|null|undefined) {
  return value == null || !Number.isFinite(value) ? '--' : value.toLocaleString('zh-CN',{maximumFractionDigits:2})
}

function formatCompact(value:number|null|undefined) {
  if (value == null || !Number.isFinite(value)) return '--'
  if (Math.abs(value) >= 1_000_000_000) return `${(value/1_000_000_000).toFixed(2)}B`
  if (Math.abs(value) >= 1_000_000) return `${(value/1_000_000).toFixed(2)}M`
  if (Math.abs(value) >= 1_000) return `${(value/1_000).toFixed(2)}K`
  return value.toLocaleString('zh-CN',{maximumFractionDigits:2})
}

function formatCost(value:number|null|undefined) {
  if (value == null || !Number.isFinite(value)) return '--'
  const digits = Math.abs(value) >= 1 ? 2 : Math.abs(value) >= .01 ? 3 : 4
  return `$${value.toFixed(digits)}`
}

function formatDuration(value:number|null|undefined) {
  if (value == null || !Number.isFinite(value)) return '--'
  return value >= 1000 ? `${(value/1000).toFixed(2)} s` : `${Math.round(value)} ms`
}

function shortDate(value:string) {
  const match=value.match(/(\d{2})-(\d{2})(?:$|\D)/)
  return match ? `${match[1]}/${match[2]}` : value
}
