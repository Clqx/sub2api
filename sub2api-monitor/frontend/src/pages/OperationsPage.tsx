import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, Clock3, Cpu, Database, RefreshCw, ServerCog, Users } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import type { OperationsResources, OpsErrorItem, OpsRequestItem } from '../types'

type View = 'overview'|'capacity'|'errors'|'system'
type TimeRange = '5m'|'30m'|'1h'|'6h'|'24h'

export function OperationsPage() {
  const targets = useQuery({ queryKey:['targets'], queryFn:api.targets })
  const [targetId,setTargetId] = useState('')
  const [timeRange,setTimeRange] = useState<TimeRange>('1h')
  const [view,setView] = useState<View>('overview')
  useEffect(() => {
    if (!targetId && targets.data?.items.length) setTargetId(targets.data.items[0].id)
  },[targetId,targets.data])
  const query = useQuery({
    queryKey:['target-operations',targetId,timeRange],
    queryFn:()=>api.targetOperations(targetId,timeRange),
    enabled:Boolean(targetId),
    refetchInterval:30_000,
  })
  const resources = query.data?.resources
  return <>
    <div className="page-title"><div><h1>运行监控</h1><p>目标运行态、流量、容量、错误与系统健康</p></div><div className="page-actions"><label>目标<select value={targetId} onChange={event=>setTargetId(event.target.value)}>{targets.data?.items.map(target=><option key={target.id} value={target.id}>{target.name}</option>)}</select></label><label>时间窗口<select value={timeRange} onChange={event=>setTimeRange(event.target.value as TimeRange)}><option value="5m">5 分钟</option><option value="30m">30 分钟</option><option value="1h">1 小时</option><option value="6h">6 小时</option><option value="24h">24 小时</option></select></label><button className="icon-button" title="刷新" aria-label="刷新运行监控" disabled={query.isFetching||!targetId} onClick={()=>query.refetch()}><RefreshCw/></button></div></div>
    <div className="view-tabs" role="tablist" aria-label="运行监控视图">{([['overview','概览'],['capacity','容量'],['errors','请求与错误'],['system','系统']] as const).map(([key,label])=><button key={key} role="tab" aria-selected={view===key} className={view===key?'active':''} onClick={()=>setView(key)}>{label}</button>)}</div>
    {targets.isError ? <ErrorState error={targets.error}/> : !targets.isLoading && !targets.data?.items.length ? <Empty title="没有监控目标" detail="先添加并探测一个 Sub2API 目标"/> : query.isError ? <ErrorState error={query.error}/> : query.isLoading || !resources ? <div className="inline-loading">正在读取目标运行指标…</div> : <>
      {Object.keys(query.data?.failures??{}).length>0 && <div className="coverage-warning"><AlertTriangle size={16}/><span>部分接口不可用：{Object.keys(query.data?.failures??{}).join('、')}</span></div>}
      {view==='overview' && <Overview resources={resources}/>} {view==='capacity' && <Capacity resources={resources}/>} {view==='errors' && <Errors resources={resources}/>} {view==='system' && <System resources={resources}/>}
    </>}
  </>
}

function Overview({resources}:{resources:OperationsResources}) {
  const snapshot=resources.ops_snapshot
  const overview=snapshot?.overview
  const metrics=[
    ['健康评分',overview?.health_score==null?'--':overview.health_score.toFixed(0),Activity],
    ['请求总数',formatNumber(overview?.request_count_total),ServerCog],
    ['SLA',overview?formatRatioPercent(overview.sla):'--',Activity],
    ['错误率',overview?formatRatioPercent(overview.error_rate):'--',AlertTriangle],
    ['当前 QPS',formatRate(overview?.qps.current),RefreshCw],
    ['当前 TPS',formatRate(overview?.tps.current),Clock3],
    ['Token 消耗',formatNumber(overview?.token_consumed),Database],
    ['P95 延迟',formatDuration(overview?.duration.p95_ms),Clock3],
  ] as const
  return <>
    <section className="metric-grid ops-metrics">{metrics.map(([label,value,Icon])=><div className="metric" key={label}><div><span>{label}</span><strong>{value}</strong></div><Icon size={20}/></div>)}</section>
    <section className="content-band ops-section"><SectionTitle title="吞吐趋势" detail={`${snapshot?.throughput_trend.bucket??'--'} 聚合`}/><TrendBars points={snapshot?.throughput_trend.points??[]}/></section>
    <div className="ops-two-column"><section className="content-band ops-section"><SectionTitle title="延迟分布" detail={`${formatNumber(resources.latency_histogram?.total_requests)} 个请求`}/><SimpleRows items={(resources.latency_histogram?.buckets??[]).map(item=>({label:item.range,value:formatNumber(item.count)}))}/></section><section className="content-band ops-section"><SectionTitle title="OpenAI Token 指标" detail="按模型统计"/><table className="ops-table"><thead><tr><th>模型</th><th>请求</th><th>Token/s</th><th>首 Token</th></tr></thead><tbody>{resources.openai_token_stats?.items.map(item=><tr key={item.model}><td><strong>{item.model}</strong></td><td>{formatNumber(item.request_count)}</td><td>{formatRate(item.avg_tokens_per_sec)}</td><td>{formatDuration(item.avg_first_token_ms)}</td></tr>)}</tbody></table></section></div>
  </>
}

function Capacity({resources}:{resources:OperationsResources}) {
  const groups=useMemo(()=>{
    const usage=new Map((resources.group_usage??[]).map(item=>[String(item.group_id),item]))
    const capacity=new Map((resources.group_capacity??[]).map(item=>[String(item.group_id),item]))
    return (resources.groups??[]).map(group=>({group,usage:usage.get(String(group.id)),capacity:capacity.get(String(group.id))}))
  },[resources])
  const platformConcurrency=Object.values(resources.concurrency?.platform??{})
  const platformAvailability=Object.values(resources.account_availability?.platform??{})
  const users=Object.values(resources.user_concurrency?.user??{}).sort((a,b)=>(number(b,'current_in_use')??0)-(number(a,'current_in_use')??0))
  return <>
    <section className="content-band ops-section"><SectionTitle title="平台容量" detail="并发、排队与账号可用性"/><table className="ops-table"><thead><tr><th>平台</th><th>使用中</th><th>容量</th><th>负载</th><th>排队</th><th>可用账号</th><th>限流</th><th>错误</th></tr></thead><tbody>{platformConcurrency.map(item=>{const platform=String(item.platform??'unknown');const availability=platformAvailability.find(value=>String(value.platform??'')===platform);return <tr key={platform}><td><strong>{platform}</strong></td><td>{formatNumber(number(item,'current_in_use'))}</td><td>{formatNumber(number(item,'max_capacity'))}</td><td>{formatPercent(number(item,'load_percentage'))}</td><td>{formatNumber(number(item,'waiting_in_queue'))}</td><td>{formatNumber(number(availability,'available_count'))}/{formatNumber(number(availability,'total_accounts'))}</td><td>{formatNumber(number(availability,'rate_limit_count'))}</td><td>{formatNumber(number(availability,'error_count'))}</td></tr>})}</tbody></table></section>
    <section className="content-band ops-section"><SectionTitle title="分组用量与容量" detail={`${groups.length} 个分组`}/><table className="ops-table"><thead><tr><th>分组</th><th>平台</th><th>状态</th><th>倍率</th><th>今日成本</th><th>总成本</th><th>并发</th><th>会话</th><th>RPM</th></tr></thead><tbody>{groups.map(({group,usage,capacity})=><tr key={group.id}><td><strong>{group.name}</strong></td><td>{group.platform}</td><td><Status value={group.status}/></td><td>×{group.rate_multiplier}</td><td>{formatMoney(usage?.today_cost)}</td><td>{formatMoney(usage?.total_cost)}</td><td>{ratio(capacity?.concurrency_used,capacity?.concurrency_max)}</td><td>{ratio(capacity?.sessions_used,capacity?.sessions_max)}</td><td>{ratio(capacity?.rpm_used,capacity?.rpm_max)}</td></tr>)}</tbody></table></section>
    <section className="content-band ops-section"><SectionTitle title="用户并发" detail={`${users.length} 个活跃用户`}/><table className="ops-table"><thead><tr><th>用户</th><th>使用中</th><th>容量</th><th>负载</th><th>排队</th></tr></thead><tbody>{users.map((item,index)=><tr key={String(item.user_id??index)}><td><strong>{String(item.username??item.user_email??item.user_id??'--')}</strong></td><td>{formatNumber(number(item,'current_in_use'))}</td><td>{formatNumber(number(item,'max_capacity'))}</td><td>{formatPercent(number(item,'load_percentage'))}</td><td>{formatNumber(number(item,'waiting_in_queue'))}</td></tr>)}</tbody></table></section>
  </>
}

function Errors({resources}:{resources:OperationsResources}) {
  const errorPoints=resources.ops_snapshot?.error_trend.points??[]
  return <>
    <div className="ops-two-column"><section className="content-band ops-section"><SectionTitle title="错误趋势" detail="SLA 与上游错误"/><ErrorBars points={errorPoints}/></section><section className="content-band ops-section"><SectionTitle title="状态码分布" detail={`${formatNumber(resources.error_distribution?.total)} 个错误`}/><table className="ops-table"><thead><tr><th>状态码</th><th>总数</th><th>SLA</th><th>业务限流</th></tr></thead><tbody>{resources.error_distribution?.items.map(item=><tr key={item.status_code}><td><strong>{item.status_code}</strong></td><td>{item.total}</td><td>{item.sla}</td><td>{item.business_limited}</td></tr>)}</tbody></table></section></div>
    <ErrorTable title="请求错误" items={resources.request_errors?.items??[]}/><ErrorTable title="上游错误" items={resources.upstream_errors?.items??[]}/><RequestTable items={resources.requests?.items??[]}/>
  </>
}

function System({resources}:{resources:OperationsResources}) {
  const metrics=resources.ops_snapshot?.overview.system_metrics??{}
  const jobs=resources.ops_snapshot?.overview.job_heartbeats??[]
  const health=[['系统日志',resources.system_log_health],['认证缓存',resources.auth_cache_health],['入口拒绝',resources.ingress_health]] as const
  return <>
    <section className="system-grid ops-system-grid"><SystemMetric icon={Cpu} label="CPU" value={formatPercent(number(metrics,'cpu_usage_percent'))}/><SystemMetric icon={Database} label="内存" value={formatPercent(number(metrics,'memory_usage_percent'))}/><SystemMetric icon={Database} label="数据库" value={boolean(metrics,'db_ok')?'正常':'异常'}/><SystemMetric icon={ServerCog} label="Redis" value={boolean(metrics,'redis_ok')?'正常':'异常'}/><SystemMetric icon={Activity} label="Goroutine" value={formatNumber(number(metrics,'goroutine_count'))}/><SystemMetric icon={Users} label="并发队列" value={formatNumber(number(metrics,'concurrency_queue_depth'))}/></section>
    <section className="content-band ops-section"><SectionTitle title="监控管线健康" detail="日志、缓存与入口采集"/><div className="health-grid">{health.map(([label,data])=><div key={label}><span>{label}</span><Status value={healthState(label,data)}/><small>{healthSummary(label,data)}</small></div>)}</div></section>
    <section className="content-band ops-section"><SectionTitle title="后台任务" detail={`${jobs.length} 个心跳`}/><table className="ops-table"><thead><tr><th>任务</th><th>最近运行</th><th>最近成功</th><th>结果</th><th>错误</th></tr></thead><tbody>{jobs.map((job,index)=><tr key={String(job.job_name??index)}><td><strong>{String(job.job_name??'--')}</strong></td><td>{formatTime(job.last_run_at)}</td><td>{formatTime(job.last_success_at)}</td><td><Status value={String(job.last_result??'unknown')}/></td><td>{String(job.last_error??'--')}</td></tr>)}</tbody></table></section>
    <section className="content-band ops-section"><SectionTitle title="目标告警事件" detail="来自 Sub2API 原生 Ops"/><table className="ops-table"><thead><tr><th>状态</th><th>严重度</th><th>标题</th><th>触发时间</th></tr></thead><tbody>{resources.alert_events?.map((item,index)=><tr key={item.id??index}><td><Status value={item.status??'unknown'}/></td><td><span className={`severity ${item.severity??''}`}>{item.severity??'--'}</span></td><td><strong>{item.title??'--'}</strong><small>{item.description??''}</small></td><td>{formatTime(item.fired_at??item.created_at)}</td></tr>)}</tbody></table></section>
    <section className="content-band ops-section"><SectionTitle title="系统日志" detail={`${formatNumber(resources.system_logs?.total)} 条`}/><table className="ops-table"><thead><tr><th>级别</th><th>组件</th><th>消息</th><th>时间</th></tr></thead><tbody>{resources.system_logs?.items.map((item,index)=><tr key={item.id??index}><td><Status value={item.level??'unknown'}/></td><td>{item.component??'--'}</td><td><strong>{item.message??'--'}</strong><small>{item.host??''}</small></td><td>{formatTime(item.created_at)}</td></tr>)}</tbody></table></section>
  </>
}

function ErrorTable({title,items}:{title:string;items:OpsErrorItem[]}) { return <section className="content-band ops-section"><SectionTitle title={title} detail={`${items.length} 条最近记录`}/><table className="ops-table"><thead><tr><th>状态</th><th>平台/模型</th><th>阶段</th><th>消息</th><th>时间</th></tr></thead><tbody>{items.map((item,index)=><tr key={item.id??index}><td><Status value={String(item.status_code??item.severity??'error')}/></td><td><strong>{item.platform??'--'}</strong><small>{item.model??item.account_name??''}</small></td><td>{item.phase??'--'}</td><td className="ops-message">{item.message??item.description??item.title??'--'}</td><td>{formatTime(item.created_at??item.fired_at)}</td></tr>)}</tbody></table></section> }
function RequestTable({items}:{items:OpsRequestItem[]}) { return <section className="content-band ops-section"><SectionTitle title="请求明细" detail={`${items.length} 条最近记录`}/><table className="ops-table"><thead><tr><th>结果</th><th>请求 ID</th><th>平台/模型</th><th>耗时</th><th>时间</th></tr></thead><tbody>{items.map((item,index)=><tr key={`${item.request_id??index}-${item.created_at??''}`}><td><Status value={item.kind??String(item.status_code??'unknown')}/></td><td className="mono-value">{item.request_id??'--'}</td><td><strong>{item.platform??'--'}</strong><small>{item.model??''}</small></td><td>{formatDuration(item.duration_ms)}</td><td>{formatTime(item.created_at)}</td></tr>)}</tbody></table></section> }
function SectionTitle({title,detail}:{title:string;detail:string}) { return <div className="section-title"><div><h2>{title}</h2><p>{detail}</p></div></div> }
function SimpleRows({items}:{items:Array<{label:string;value:string}>}) { const max=Math.max(1,...items.map(item=>Number(item.value.replaceAll(',',''))||0));return <div className="distribution-list">{items.map(item=><div key={item.label}><span>{item.label}</span><i><b style={{width:`${Math.max(2,(Number(item.value.replaceAll(',',''))||0)/max*100)}%`}}/></i><strong>{item.value}</strong></div>)}</div> }
function TrendBars({points}:{points:Array<{bucket_start:string;request_count:number;token_consumed:number}>}) { const shown=points.slice(-36);const max=Math.max(1,...shown.map(point=>point.request_count));return <div className="trend-bars" aria-label="吞吐趋势">{shown.map(point=><div key={point.bucket_start} title={`${formatTime(point.bucket_start)} · ${point.request_count} 请求`}><i style={{height:`${Math.max(3,point.request_count/max*100)}%`}}/><span>{shortTime(point.bucket_start)}</span></div>)}</div> }
function ErrorBars({points}:{points:Array<{bucket_start:string;error_count_total:number}>}) { const shown=points.slice(-36);const max=Math.max(1,...shown.map(point=>point.error_count_total));return <div className="trend-bars error-bars" aria-label="错误趋势">{shown.map(point=><div key={point.bucket_start} title={`${formatTime(point.bucket_start)} · ${point.error_count_total} 错误`}><i style={{height:`${Math.max(3,point.error_count_total/max*100)}%`}}/><span>{shortTime(point.bucket_start)}</span></div>)}</div> }
function SystemMetric({icon:Icon,label,value}:{icon:typeof Activity;label:string;value:string}) { return <div className="system-item"><Icon/><div><small>{label}</small><span>{value}</span></div></div> }
function number(value:Record<string,unknown>|undefined,key:string) { const item=value?.[key];return typeof item==='number'&&Number.isFinite(item)?item:undefined }
function boolean(value:Record<string,unknown>|undefined,key:string) { return value?.[key]===true }
function formatNumber(value?:number|null) { return value==null?'--':new Intl.NumberFormat('zh-CN',{maximumFractionDigits:1}).format(value) }
function formatRate(value?:number|null) { return value==null?'--':value.toFixed(value<10?2:0) }
function formatPercent(value?:number|null) { return value==null?'--':`${value.toFixed(2)}%` }
function formatRatioPercent(value?:number|null) { return value==null?'--':formatPercent(value*100) }
function formatDuration(value?:number|null) { return value==null?'--':value>=1000?`${(value/1000).toFixed(2)} s`:`${Math.round(value)} ms` }
function formatMoney(value?:number|null) { return value==null?'--':new Intl.NumberFormat('zh-CN',{style:'currency',currency:'USD',maximumFractionDigits:2}).format(value) }
function formatTime(value:unknown) { return typeof value==='string'&&value?new Date(value).toLocaleString('zh-CN'):'--' }
function shortTime(value:string) { return new Date(value).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'}) }
function ratio(used?:number,max?:number) { return used==null||max==null?'--':`${used}/${max}` }
function healthState(label:string,data?:Record<string,unknown>) { if(!data)return 'missing';if(label==='入口拒绝')return data.accepting===true?'healthy':'unavailable';if(label==='系统日志')return Number(data.write_failed_count??0)===0?'healthy':'unavailable';const outbox=data.outbox as Record<string,unknown>|undefined;const subscriber=data.subscriber as Record<string,unknown>|undefined;return outbox?.running===true&&subscriber?.connected===true?'healthy':'unavailable' }
function healthSummary(label:string,data?:Record<string,unknown>) { if(!data)return '无数据';if(label==='入口拒绝')return `待处理 ${String(data.pending_rows??0)} · 丢弃 ${String(data.dropped_count??0)}`;if(label==='系统日志')return `已写入 ${String(data.written_count??0)} · 失败 ${String(data.write_failed_count??0)}`;const outbox=data.outbox as Record<string,unknown>|undefined;return `待处理 ${String(outbox?.pending??0)} · 失败 ${String(outbox?.failures??0)}` }
