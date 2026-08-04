import { useQuery } from '@tanstack/react-query'
import { BellRing, CheckCircle2, Database, ServerCog, XCircle } from 'lucide-react'
import { api } from '../api'
import { ErrorState, Status } from '../components/Status'

export function SystemPage() {
  const q = useQuery({ queryKey:['system-status'], queryFn:api.systemStatus, refetchInterval:15_000 })
  return <><div className="page-title"><div><h1>系统</h1><p>Hub API、Worker 与数据库运行诊断</p></div></div>{q.isError ? <ErrorState error={q.error}/> : <section className="system-grid">
    <SystemItem icon={Database} label="监控数据库" value={q.data?.database ?? '读取中'} ok={q.data?.database === 'ok'}/>
    <SystemItem icon={ServerCog} label="采集 Worker" value={q.data ? (q.data.worker_stale ? '心跳过期' : '运行中') : '读取中'} ok={q.data ? !q.data.worker_stale : undefined} detail={q.data?.worker_last_seen_at ? new Date(q.data.worker_last_seen_at).toLocaleString('zh-CN') : '尚无心跳'}/>
    <SystemItem icon={BellRing} label="通知队列" value={q.data ? `${q.data.pending_outbox} 条待处理` : '读取中'} ok={q.data ? q.data.pending_outbox === 0 : undefined}/>
    <SystemItem icon={q.data?.ready ? CheckCircle2 : XCircle} label="整体就绪" value={q.data ? (q.data.ready ? '就绪' : '未就绪') : '读取中'} ok={q.data?.ready} detail={q.data ? `24 小时失败采集 ${q.data.failed_runs_24h} 次` : undefined}/>
  </section>}</>
}

function SystemItem({ icon:Icon, label, value, ok, detail }: { icon:typeof Database; label:string; value:string; ok?:boolean; detail?:string }) {
  return <div className="system-item"><Icon/><div><strong>{label}</strong><span>{value}</span>{detail && <small>{detail}</small>}</div>{ok === undefined ? <Status value="unknown"/> : <Status value={ok ? 'healthy' : 'unavailable'}/>}</div>
}
