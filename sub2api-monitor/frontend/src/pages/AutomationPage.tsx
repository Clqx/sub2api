import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Play, Plus, Power, PowerOff, Trash2 } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import type { AutomationAction, AutomationRule } from '../types'

const actionLabels: Record<AutomationAction,string> = {
  recover_state:'统一恢复运行状态',
  clear_error:'清除账号错误',
  clear_rate_limit:'清除限流状态',
  clear_temp_unschedulable:'清除临时不可调度',
  set_schedulable:'恢复可调度',
}

const reasonOptions = [
  ['status:error','账号错误'],
  ['rate_limited','限流'],
  ['overloaded','上游过载'],
  ['temporarily_unschedulable','临时不可调度'],
  ['manually_unschedulable','手动不可调度'],
] as const

export function AutomationPage() {
  const qc = useQueryClient()
  const [mode,setMode] = useState<'recommend'|'execute'>('recommend')
  const [createEnabled,setCreateEnabled] = useState(false)
  const targets = useQuery({queryKey:['targets'],queryFn:api.targets})
  const rules = useQuery({queryKey:['automation-rules'],queryFn:api.automationRules})
  const executions = useQuery({queryKey:['automation-executions'],queryFn:api.automationExecutions,refetchInterval:3_000})
  const refreshRules = () => qc.invalidateQueries({queryKey:['automation-rules']})
  const refreshExecutions = () => qc.invalidateQueries({queryKey:['automation-executions']})
  const create = useMutation({mutationFn:api.createAutomationRule,onSuccess:async()=>{await refreshRules();await refreshExecutions()}})
  const update = useMutation({mutationFn:({id,body}:{id:string;body:Record<string,unknown>})=>api.updateAutomationRule(id,body),onSuccess:refreshRules})
  const remove = useMutation({mutationFn:api.deleteAutomationRule,onSuccess:async()=>{await refreshRules();await refreshExecutions()}})
  const approve = useMutation({mutationFn:api.approveAutomationExecution,onSuccess:refreshExecutions})
  const operationError = create.error ?? update.error ?? remove.error ?? approve.error

  function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const enabled = form.get('enabled') === 'on'
    create.mutate({
      name:form.get('name'),
      target_id:form.get('target_id') || null,
      enabled,
      trigger_rule_key:'account.unavailable',
      action:form.get('action'),
      mode,
      reason_filters:form.getAll('reason_filters'),
      cooldown_seconds:Number(form.get('cooldown_minutes')) * 60,
      confirm_side_effects:mode === 'execute' && enabled && form.get('confirm_side_effects') === 'on',
    })
  }

  function toggleRule(rule:AutomationRule) {
    const enabled = !rule.enabled
    if (enabled && rule.mode === 'execute' && !window.confirm(`启用自动执行规则“${rule.name}”？`)) return
    update.mutate({id:rule.id,body:ruleBody(rule,enabled)})
  }

  return <>
    <div className="page-title"><div><h1>故障自动化</h1><p>Admin API 白名单处置与事件级执行审计</p></div></div>
    {operationError && <ErrorState error={operationError}/>}
    <div className="split-layout automation-layout">
      <section className="content-band"><div className="section-title"><div><h2>新增规则</h2><p>触发条件：账号不可用</p></div></div>
        <form className="settings-form" onSubmit={submit}>
          <label>规则名称<input name="name" required placeholder="临时故障恢复"/></label>
          <label>目标<select name="target_id"><option value="">全部目标</option>{targets.data?.items.map(target=><option value={target.id} key={target.id}>{target.name}</option>)}</select></label>
          <label>处置动作<select name="action" defaultValue="recover_state">{Object.entries(actionLabels).map(([value,label])=><option value={value} key={value}>{label}</option>)}</select></label>
          <fieldset><legend>匹配原因</legend><div className="check-grid">{reasonOptions.map(([value,label])=><label className="check-label" key={value}><input type="checkbox" name="reason_filters" value={value} defaultChecked={value==='status:error'||value==='temporarily_unschedulable'}/>{label}</label>)}</div></fieldset>
          <label>冷却时间（分钟）<input name="cooldown_minutes" type="number" min="5" max="1440" defaultValue="15" required/></label>
          <fieldset><legend>执行模式</legend><div className="segmented"><button type="button" className={mode==='recommend'?'active':''} onClick={()=>setMode('recommend')}>生成建议</button><button type="button" className={mode==='execute'?'active':''} onClick={()=>setMode('execute')}>自动执行</button></div></fieldset>
          {mode==='execute'&&<label className="check-label confirmation"><input name="confirm_side_effects" type="checkbox" required={createEnabled}/>确认允许监控端修改目标账号运行状态</label>}
          <label className="check-label"><input name="enabled" type="checkbox" checked={createEnabled} onChange={event=>setCreateEnabled(event.target.checked)}/>创建后启用</label>
          <button className="primary" disabled={create.isPending}><Plus size={17}/>{create.isPending?'保存中':'保存规则'}</button>
        </form>
      </section>
      <section className="content-band"><div className="section-title"><div><h2>自动化规则</h2><p>{rules.data?.length??0} 条配置</p></div></div>
        {rules.isError?<ErrorState error={rules.error}/>:<div className="automation-list">{rules.data?.map(rule=><div className="automation-row" key={rule.id}><div><strong>{rule.name}</strong><small>{targetName(targets.data?.items,rule.target_id)} · {actionLabels[rule.action]}</small><span className="filter-summary">{rule.reason_filters.length?rule.reason_filters.join(' / '):'全部不可用原因'} · {rule.cooldown_seconds/60} 分钟</span></div><div className="automation-state"><Status value={rule.enabled?'enabled':'disabled'}/><span className={`mode ${rule.mode}`}>{rule.mode==='execute'?'自动执行':'建议'}</span></div><span className="channel-actions"><button className="icon-button" title={rule.enabled?'停用规则':'启用规则'} aria-label={`${rule.enabled?'停用':'启用'} ${rule.name}`} disabled={update.isPending} onClick={()=>toggleRule(rule)}>{rule.enabled?<PowerOff/>:<Power/>}</button><button className="icon-button" title="删除规则" aria-label={`删除 ${rule.name}`} disabled={remove.isPending} onClick={()=>{if(window.confirm(`删除规则“${rule.name}”？`))remove.mutate(rule.id)}}><Trash2/></button></span></div>)}{rules.data?.length===0&&<Empty title="没有自动化规则" detail="新增规则后，事件会生成建议或进入执行队列"/>}</div>}
      </section>
    </div>
    <section className="content-band execution-band"><div className="section-title"><div><h2>执行记录</h2><p>建议、审批、执行和复检状态</p></div></div>
      {executions.isError?<ErrorState error={executions.error}/>:<div className="table-wrap"><table><thead><tr><th>状态</th><th>账号</th><th>动作</th><th>时间</th><th>结果</th><th></th></tr></thead><tbody>{executions.data?.map(item=><tr key={item.id}><td><Status value={item.status}/></td><td><strong>{item.external_account_id}</strong><small>{targetName(targets.data?.items,item.target_id)}</small></td><td>{actionLabels[item.action]}</td><td>{new Date(item.created_at).toLocaleString('zh-CN')}</td><td><small className={item.last_error?'danger-text':''}>{item.last_error??resultText(item.result)}</small></td><td className="actions sticky-actions">{['recommended','failed'].includes(item.status)&&<button className="icon-button" title={item.status==='recommended'?'批准执行':'重新执行'} aria-label={`${item.status==='recommended'?'批准':'重试'} ${item.external_account_id}`} disabled={approve.isPending} onClick={()=>{if(window.confirm(`执行“${actionLabels[item.action]}”？`))approve.mutate(item.id)}}>{item.status==='recommended'?<CheckCircle2/>:<Play/>}</button>}</td></tr>)}</tbody></table>{executions.data?.length===0&&<Empty title="没有执行记录" detail="匹配故障事件后会显示在这里"/>}</div>}
    </section>
  </>
}

function ruleBody(rule:AutomationRule,enabled:boolean) {
  return {name:rule.name,target_id:rule.target_id??null,enabled,trigger_rule_key:rule.trigger_rule_key,action:rule.action,mode:rule.mode,reason_filters:rule.reason_filters,cooldown_seconds:rule.cooldown_seconds,confirm_side_effects:enabled&&rule.mode==='execute'}
}

function targetName(targets:{id:string;name:string}[]|undefined,targetId:string|null|undefined) {
  if(!targetId)return '全部目标'
  return targets?.find(target=>target.id===targetId)?.name??targetId
}

function resultText(result:Record<string,unknown>) {
  if(result.http_status)return `HTTP ${result.http_status}${result.idempotency_replayed?' · 幂等重放':''}`
  const reasons=Array.isArray(result.availability_reasons)?result.availability_reasons.join(' / '):''
  return reasons||'等待执行'
}
