import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Eye, Search, X } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import { formatDateTime, quotaRemainingText, quotaSourceLabel, quotaUsageText } from '../quotaPresentation'
import type { Account } from '../types'

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
  return <><div className="page-title"><div><h1>账号</h1><p>账号身份按目标隔离，额度未知不会显示为零</p></div><label className="search"><Search size={17}/><span className="sr-only">搜索账号或平台</span><input value={search} onChange={e => setSearch(e.target.value)} placeholder="搜索账号或平台"/></label></div>{q.isError ? <ErrorState error={q.error}/> : <div className="table-wrap"><table><thead><tr><th>账号</th><th>目标</th><th>平台</th><th>可用性</th><th>剩余额度</th><th>观测时间</th><th></th></tr></thead><tbody>{accounts.map(a => <tr key={a.id}><td><strong>{a.name}</strong><small>ID {a.external_account_id} · {a.account_type}</small></td><td>{a.target_name ?? a.target_id}</td><td><span className="platform">{a.platform}</span></td><td>{a.available === null ? <Status value="unknown"/> : <Status value={a.available ? 'available' : 'unavailable'}/>}<small>{a.availability_reasons.join(' · ')}</small></td><td>{a.remaining_percent == null ? <span className="unknown-value">未提供额度 <Status value={a.quota_freshness ?? 'missing'}/></span> : <div className="quota"><div><i style={{ width:`${Math.max(0,Math.min(100,a.remaining_percent))}%` }}/></div><span>{a.remaining_percent.toFixed(1)}%</span><Status value={a.quota_freshness ?? 'missing'}/></div>}</td><td>{a.observed_at ? new Date(a.observed_at).toLocaleString('zh-CN') : '--'}</td><td className="actions sticky-actions"><button className="icon-button" aria-label={`查看 ${a.name} 额度详情`} onClick={() => setSelected(a)}><Eye/></button></td></tr>)}</tbody></table>{accounts.length === 0 && <Empty title="没有账号观测" detail="目标完成首次采集后，账号会出现在这里"/>}{q.hasNextPage && <div className="load-more"><button disabled={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>{q.isFetchingNextPage ? '加载中' : '加载更多'}</button></div>}</div>}{selected && <AccountDetail account={selected} onClose={() => setSelected(null)}/>}</>
}

function AccountDetail({ account, onClose }: { account:Account; onClose:()=>void }) {
  const q = useQuery({ queryKey:['account-quota',account.id], queryFn:() => api.accountQuota(account.id) })
  return <div className="modal-backdrop"><div className="modal account-detail" role="dialog" aria-modal="true" aria-labelledby="account-detail-title"><div className="modal-head"><div><h2 id="account-detail-title">{account.name}</h2><p>{account.target_name ?? account.target_id} · {account.platform} · {account.account_type}</p></div><button className="icon-button" onClick={onClose} aria-label="关闭账号详情"><X/></button></div><div className="detail-content"><div className="availability-detail"><Status value={account.available === null ? 'unknown' : account.available ? 'available' : 'unavailable'}/><span>{account.available === null ? '可用性未知' : account.availability_reasons.length ? account.availability_reasons.join(' · ') : '无不可用原因'}</span></div><section className="account-state-grid" aria-label="账号状态详情"><StateField label="账号状态" value={account.status || '未知'}/><StateField label="可调度" value={account.schedulable ? '是' : '否'}/><StateField label="账号过期时间" value={formatDateTime(account.expires_at)}/><StateField label="限流解除时间" value={formatDateTime(account.rate_limit_reset_at)}/><StateField label="过载解除时间" value={formatDateTime(account.overload_until)}/><StateField label="临时不可调度至" value={formatDateTime(account.temp_unschedulable_until)}/></section><div className="quota-section-title"><h3>额度窗口</h3><p>额度值保留各来源语义，未知值不会换算为零</p></div>{q.isLoading ? <div className="inline-loading">正在读取额度窗口</div> : q.isError ? <ErrorState error={q.error}/> : <div className="quota-windows">{q.data?.map(window => <article className="quota-window" key={window.id}><div className="quota-window-head"><strong>{window.label}</strong><Status value={window.freshness}/></div><div className="quota-remaining"><span>剩余</span><b>{quotaRemainingText(window)}</b></div><p className="quota-used">{quotaUsageText(window)}</p><dl><div><dt>重置时间</dt><dd>{formatDateTime(window.reset_at)}</dd></div><div><dt>采样时间</dt><dd>{formatDateTime(window.observed_at)}</dd></div><div><dt>数据来源</dt><dd title={window.source}>{quotaSourceLabel(window.source)}</dd></div></dl></article>)}{q.data?.length === 0 && <Empty title="没有额度数据" detail="目标未配置额度，或当前接入能力没有提供可比较的额度窗口"/>}</div>}</div></div></div>
}

function StateField({ label, value }:{ label:string; value:string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}
