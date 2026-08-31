import { useEffect, useMemo, useState } from 'react'
import { Activity, Clock3, RefreshCw, ScanSearch } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import type { ReactNode } from 'react'
import type {
  ChannelQualityHealth,
  ChannelQualityRow,
  ChannelQualityTimeRange,
} from '../types'

type QualitySort = 'default'|'multiplier'|'speed'|'cache'|'availability'

const timeRanges: Array<{value:ChannelQualityTimeRange;label:string}> = [
  {value:'6h',label:'6h'},
  {value:'24h',label:'24h'},
  {value:'7d',label:'7d'},
  {value:'30d',label:'30d'},
]

const sortOptions: Array<{value:QualitySort;label:string}> = [
  {value:'default',label:'默认'},
  {value:'multiplier',label:'倍率'},
  {value:'speed',label:'用户速度'},
  {value:'cache',label:'缓存命中'},
  {value:'availability',label:'可用率'},
]

export function ChannelsPage() {
  const targets = useQuery({queryKey:['targets'],queryFn:api.targets})
  const [targetId,setTargetId] = useState('')
  const [timeRange,setTimeRange] = useState<ChannelQualityTimeRange>('6h')
  const [sort,setSort] = useState<QualitySort>('default')

  useEffect(()=>{
    if(!targetId&&targets.data?.items.length)setTargetId(targets.data.items[0].id)
  },[targetId,targets.data])

  const query = useQuery({
    queryKey:['channel-quality',targetId,timeRange],
    queryFn:()=>api.targetChannelQuality(targetId,timeRange),
    enabled:Boolean(targetId),
    staleTime:30_000,
    refetchInterval:60_000,
  })
  const rows=useMemo(()=>sortRows(query.data?.items??[],sort),[query.data?.items,sort])

  return <>
    <div className="page-title">
      <div><h1>渠道质量</h1><p>基于真实用户流量的缓存、可用性与首字速度</p></div>
      <div className="page-actions">
        <label>目标<select value={targetId} onChange={event=>setTargetId(event.target.value)}>{targets.data?.items.map(target=><option key={target.id} value={target.id}>{target.name}</option>)}</select></label>
        <button className="icon-button" title="刷新" aria-label="刷新渠道质量" disabled={!targetId||query.isFetching} onClick={()=>query.refetch()}><RefreshCw/></button>
      </div>
    </div>

    <div className="view-tabs channel-quality-tabs" role="tablist" aria-label="渠道监测功能">
      <button role="tab" aria-selected="true" className="active">质量监测</button>
      <button role="tab" aria-selected="false" disabled title="暂未启用">模型检测</button>
    </div>

    <section className="quality-toolbar" aria-label="渠道质量筛选">
      <ControlGroup label="时间维度">
        <div className="segmented-control">{timeRanges.map(option=><button key={option.value} type="button" aria-pressed={timeRange===option.value} onClick={()=>setTimeRange(option.value)}>{option.label}</button>)}</div>
      </ControlGroup>
      <ControlGroup label="排序">
        <div className="segmented-control quality-sort">{sortOptions.map(option=><button key={option.value} type="button" aria-pressed={sort===option.value} onClick={()=>setSort(option.value)}>{option.label}</button>)}</div>
      </ControlGroup>
      <div className="quality-updated"><Clock3 size={15}/><span>{formatUpdated(query.data?.coverage.data_through)}</span></div>
    </section>

    {targets.isError?<ErrorState error={targets.error}/>:!targets.isLoading&&!targets.data?.items.length?<Empty title="没有监控目标" detail="先添加并探测一个 Sub2API 目标"/>:query.isError?<ErrorState error={query.error}/>:query.isLoading?<div className="inline-loading">正在读取渠道质量…</div>:<>
      {query.data&&!query.data.coverage.coverage_complete&&<div className="coverage-warning"><Activity size={16}/><span>当前时间窗口的历史数据仍在补齐</span></div>}
      {query.data&&Object.keys(query.data.failures).length>0&&<div className="coverage-warning"><Activity size={16}/><span>分组倍率暂不可用，质量指标仍保持更新</span></div>}
      <div className="table-wrap channel-quality-table">
        <table>
          <thead><tr><th>分组 / 渠道</th><th>倍率</th><th>状态</th><th>缓存命中率</th><th>可用率</th><th>用户首字速度</th><th>窗口趋势</th><th>模型检测</th></tr></thead>
          <tbody>{rows.map((row,index)=><QualityRow key={`${row.platform}:${row.group_id??'none'}:${index}`} row={row}/>)}</tbody>
        </table>
        {!rows.length&&<Empty title="没有质量样本" detail="上游产生真实请求并完成被动聚合后会显示分组质量"/>}
      </div>
    </>}
  </>
}

function ControlGroup({label,children}:{label:string;children:ReactNode}) {
  return <div className="control-group"><span>{label}</span>{children}</div>
}

function QualityRow({row}:{row:ChannelQualityRow}) {
  const cacheKnown=row.metrics.cache_rate_denominator>0
  const availabilityKnown=row.metrics.request_count>0
  const speed=row.metrics.ttft.p50_ms
  const groupActive=row.group_status==='active'||row.group_status==='enabled'
  return <tr>
    <td><strong>{row.group_name||'未分组'}</strong><small>{row.platform} · {formatNumber(row.metrics.request_count)} 个用户请求</small></td>
    <td className="numeric-value">{formatMultiplier(row.rate_multiplier)}</td>
    <td><Status value={!groupActive&&row.group_status!=='unknown'?'disabled':row.health.overall}/><small>{healthDetail(row.health)}</small></td>
    <td><QualityGauge value={cacheKnown?row.metrics.cache_rate:null} label={cacheKnown?formatPercent(row.metrics.cache_rate):'--'} state={row.health.cache}/><small>{cacheKnown?`${formatCompact(row.metrics.cache_rate_numerator)} / ${formatCompact(row.metrics.cache_rate_denominator)} Token`:'暂无可比较缓存 Token'}</small></td>
    <td><QualityGauge value={availabilityKnown?row.metrics.success_rate:null} label={availabilityKnown?formatPercent(row.metrics.success_rate):'--'} state={row.health.error_rate}/><small>{availabilityKnown?`${formatNumber(row.metrics.success_requests)} 成功 · ${formatNumber(row.metrics.error_requests)} 失败`:'暂无请求样本'}</small></td>
    <td><SpeedGauge value={speed} state={row.health.ttft}/><small>{speed==null?'暂无首 Token 样本':`P90 ${formatDuration(row.metrics.ttft.p90_ms)} · ${formatNumber(row.metrics.ttft.sample_count)} 样本`}</small></td>
    <td><QualityTrend row={row}/></td>
    <td><button className="icon-button model-detection-entry" disabled title="暂未启用" aria-label={`${row.group_name||'未分组'} 模型检测暂未启用`}><ScanSearch/></button><small>暂缓</small></td>
  </tr>
}

function QualityGauge({value,label,state}:{value:number|null;label:string;state:ChannelQualityHealth['overall']}) {
  const width=value==null?0:Math.max(0,Math.min(100,value*100))
  return <div className={`quality-gauge ${state}`}><strong>{label}</strong><span><i style={{width:`${width}%`}}/></span></div>
}

function SpeedGauge({value,state}:{value?:number|null;state:ChannelQualityHealth['overall']}) {
  const score=value==null?0:Math.max(4,100-Math.min(100,value/60))
  return <div className={`quality-gauge ${state}`}><strong>{formatDuration(value)}</strong><span><i style={{width:`${score}%`}}/></span></div>
}

function QualityTrend({row}:{row:ChannelQualityRow}) {
  const buckets=row.buckets.slice(-18)
  if(!buckets.length)return <span className="unknown-value">--</span>
  return <div className="quality-sparkline" aria-label={`${row.group_name||'未分组'} 窗口健康趋势`}>{buckets.map(bucket=>{
    const score=bucket.health.score
    const height=score==null?12:Math.max(12,Math.min(100,score))
    const availability=bucket.metrics.request_count>0?formatPercent(bucket.metrics.success_rate):'--'
    const cache=bucket.metrics.cache_rate_denominator>0?formatPercent(bucket.metrics.cache_rate):'--'
    return <i key={bucket.bucket_start} className={bucket.health.overall} style={{height:`${height}%`}} title={`${formatTime(bucket.bucket_start)} · 可用 ${availability} · 缓存 ${cache} · 首字 ${formatDuration(bucket.metrics.ttft.p50_ms)}`}/>
  })}</div>
}

function sortRows(rows:ChannelQualityRow[],sort:QualitySort) {
  const copy=[...rows]
  if(sort==='multiplier')return copy.sort((a,b)=>nullable(a.rate_multiplier,b.rate_multiplier,false))
  if(sort==='speed')return copy.sort((a,b)=>nullable(a.metrics.ttft.p50_ms,b.metrics.ttft.p50_ms,false))
  if(sort==='cache')return copy.sort((a,b)=>nullable(knownCacheRate(a),knownCacheRate(b),true))
  if(sort==='availability')return copy.sort((a,b)=>nullable(knownAvailability(a),knownAvailability(b),true))
  return copy.sort((a,b)=>healthRank(a.health.overall)-healthRank(b.health.overall)||b.metrics.request_count-a.metrics.request_count)
}

function knownCacheRate(row:ChannelQualityRow) {
  return row.metrics.cache_rate_denominator>0?row.metrics.cache_rate:null
}

function knownAvailability(row:ChannelQualityRow) {
  return row.metrics.request_count>0?row.metrics.success_rate:null
}

function nullable(left:number|null|undefined,right:number|null|undefined,descending:boolean) {
  if(left==null)return right==null?0:1
  if(right==null)return -1
  return descending?right-left:left-right
}

function healthRank(value:ChannelQualityHealth['overall']) {
  return {critical:0,warning:1,unknown:2,healthy:3}[value]
}

function healthDetail(health:ChannelQualityHealth) {
  if(health.score==null)return `至少 ${health.minimum_sample} 个样本后评估`
  return `健康评分 ${health.score.toFixed(0)}`
}

function formatPercent(value:number) { return `${(value*100).toFixed(1)}%` }
function formatMultiplier(value?:number|null) { return value==null?'--':`${value.toFixed(4).replace(/0+$/,'').replace(/\.$/,'')}x` }
function formatDuration(value?:number|null) { return value==null?'--':`${Math.round(value).toLocaleString('zh-CN')} ms` }
function formatNumber(value:number) { return value.toLocaleString('zh-CN') }
function formatCompact(value:number) { return new Intl.NumberFormat('zh-CN',{notation:'compact',maximumFractionDigits:1}).format(value) }
function formatTime(value:string) { return new Date(value).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}) }
function formatUpdated(value?:string) { return value?`数据更新至 ${new Date(value).toLocaleString('zh-CN')}`:'等待聚合数据' }
