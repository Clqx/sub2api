import type { Freshness, Readiness } from '../types'

export function Status({ value }: { value: Readiness | Freshness | string }) {
  const tone = ['ready','fresh','healthy','available','resolved','enabled','supported','sent','succeeded','verified'].includes(value) ? 'ok' : ['degraded','stale','warning','acknowledged','pending','recommended','approved','queued','running','applied','legacy_succeeded'].includes(value) ? 'warn' : ['not_ready','missing','critical','firing','unavailable','misconfigured','permission_denied','dead','failed','verification_failed'].includes(value) ? 'bad' : 'muted'
  const labels: Record<string,string> = { ready:'就绪', degraded:'降级', not_ready:'未就绪', fresh:'新鲜', stale:'已过期', missing:'无数据', firing:'告警中', acknowledged:'已确认', silenced:'已静默', resolved:'已恢复', healthy:'正常', unavailable:'不可用', disabled:'已停用', enabled:'已启用', available:'可用', supported:'支持', unsupported:'不支持', permission_denied:'权限不足', unknown:'未知', pending:'等待投递', sent:'已送达', dead:'投递失败', recommended:'待人工审批', approved:'已批准', queued:'排队中', running:'执行中', applied:'已应用，待复检', verified:'复检通过', succeeded:'已成功', legacy_succeeded:'已调用（旧状态）', verification_failed:'复检未通过', failed:'执行失败', cancelled:'已取消', skipped_stale:'状态已变化，跳过', skipped_unverifiable:'缺少可验证的账号版本，未执行', skipped:'已跳过', legacy_skipped:'已跳过（旧状态）' }
  return <span className={`status ${tone}`}><i />{labels[value] ?? value}</span>
}

export function Empty({ title, detail }: { title: string; detail: string }) { return <div className="empty"><strong>{title}</strong><span>{detail}</span></div> }
export function ErrorState({ error }: { error: unknown }) { return <div className="error-state"><strong>数据加载失败</strong><span>{error instanceof Error ? error.message : '未知错误'}</span></div> }
