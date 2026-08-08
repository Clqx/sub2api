import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, CircleDollarSign, RadioTower, Server, Users } from 'lucide-react'
import { api } from '../api'
import { ErrorState } from '../components/Status'

export function OverviewPage() {
  const query = useQuery({ queryKey:['dashboard'], queryFn:api.dashboard, refetchInterval:30_000 })
  if (query.isError) return <><PageTitle/><ErrorState error={query.error}/></>
  const d = query.data
  const metrics = [
    ['目标就绪', d ? `${d.targets_ready}/${d.targets_total}` : '--', Server],
    ['可用账号', d ? `${d.accounts_available}/${d.accounts_total}` : '--', CheckCircle2],
    ['低额度账号', d?.low_quota_accounts ?? '--', CircleDollarSign],
    ['未恢复告警', d?.active_incidents ?? '--', AlertTriangle],
    ['健康渠道', d ? `${Math.max(0,d.channels_total-d.channels_unhealthy)}/${d.channels_total}` : '--', RadioTower],
    ['24h 采集失败', d?.failed_collections_24h ?? '--', Users],
  ] as const
  return <><PageTitle/><section className="metric-grid">{metrics.map(([label,value,Icon])=><div className="metric" key={label}><div><span>{label}</span><strong>{value}</strong></div><Icon size={20}/></div>)}</section>
    <section className="content-band"><div className="section-title"><div><h2>运行状态</h2><p>只有已启用且能力就绪的目标计入正常监控</p></div></div><div className="health-line"><span className="pulse"/><div><strong>{query.isLoading ? '正在读取监控状态' : d?.targets_total === 0 ? '尚未配置监控目标' : d?.targets_ready === d?.targets_total ? '所有已配置目标均在监控' : '存在未启用、未就绪或降级目标'}</strong><small>低额度和不可用账号将由策略持续评估并发送恢复通知</small></div></div></section>
  </>
}
function PageTitle(){ return <div className="page-title"><div><h1>总览</h1><p>跨实例账号可用性、额度与告警状态</p></div></div> }
