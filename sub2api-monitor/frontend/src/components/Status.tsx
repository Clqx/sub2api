import type { Freshness, Readiness } from '../types'

export function Status({ value }: { value: Readiness | Freshness | string }) {
  const tone = ['ready','fresh','healthy','available','resolved','enabled','supported','sent'].includes(value) ? 'ok' : ['degraded','stale','warning','acknowledged','pending'].includes(value) ? 'warn' : ['not_ready','missing','critical','firing','unavailable','misconfigured','permission_denied','dead'].includes(value) ? 'bad' : 'muted'
  const labels: Record<string,string> = { ready:'就绪', degraded:'降级', not_ready:'未就绪', fresh:'新鲜', stale:'已过期', missing:'无数据', firing:'告警中', acknowledged:'已确认', silenced:'已静默', resolved:'已恢复', healthy:'正常', unavailable:'不可用', disabled:'已停用', enabled:'已启用', available:'可用', supported:'支持', unsupported:'不支持', permission_denied:'权限不足', unknown:'未知', pending:'等待投递', sent:'已送达', dead:'投递失败' }
  return <span className={`status ${tone}`}><i />{labels[value] ?? value}</span>
}

export function Empty({ title, detail }: { title: string; detail: string }) { return <div className="empty"><strong>{title}</strong><span>{detail}</span></div> }
export function ErrorState({ error }: { error: unknown }) { return <div className="error-state"><strong>数据加载失败</strong><span>{error instanceof Error ? error.message : '未知错误'}</span></div> }
