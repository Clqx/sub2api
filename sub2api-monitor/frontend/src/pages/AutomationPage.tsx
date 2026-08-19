import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Plus, Power, PowerOff, RotateCcw, Trash2 } from 'lucide-react'
import { api } from '../api'
import { Empty, ErrorState, Status } from '../components/Status'
import type { AutomationAction, AutomationExecution, AutomationRule } from '../types'

const actionLabels: Record<AutomationAction,string> = {
  recover_state:'统一恢复运行状态（旧规则）',
  clear_error:'清除账号错误',
  clear_rate_limit:'清除限流状态',
  clear_temp_unschedulable:'清除临时不可调度',
  set_schedulable:'恢复可调度（仅人工）',
}

type SafeAutomationAction = Extract<AutomationAction,'clear_error'|'clear_rate_limit'|'clear_temp_unschedulable'>
type AutomationReason = 'status:error'|'rate_limited'|'temporarily_unschedulable'

const safeActionOptions: Array<{value:SafeAutomationAction;label:string;reasons:Array<{value:AutomationReason;label:string}>}> = [
  {value:'clear_temp_unschedulable',label:'清除临时不可调度',reasons:[{value:'temporarily_unschedulable',label:'临时不可调度'}]},
  {value:'clear_rate_limit',label:'清除限流状态',reasons:[{value:'rate_limited',label:'限流'}]},
  {value:'clear_error',label:'清除账号错误',reasons:[{value:'status:error',label:'账号错误'}]},
]

const reasonLabels:Record<string,string> = {
  'status:error':'账号错误',
  rate_limited:'限流',
  overloaded:'上游过载',
  temporarily_unschedulable:'临时不可调度',
  manually_unschedulable:'手动不可调度',
}

const compatibleReasons:Record<AutomationAction,string[]> = {
  recover_state:['status:error','rate_limited','overloaded','temporarily_unschedulable'],
  clear_error:['status:error'],
  clear_rate_limit:['rate_limited'],
  clear_temp_unschedulable:['temporarily_unschedulable'],
  set_schedulable:['manually_unschedulable'],
}

export function AutomationPage() {
  const qc = useQueryClient()
  const [action,setAction] = useState<SafeAutomationAction>('clear_temp_unschedulable')
  const [reasonFilters,setReasonFilters] = useState<AutomationReason[]>(['temporarily_unschedulable'])
  const [createEnabled,setCreateEnabled] = useState(false)
  const targets = useQuery({queryKey:['targets'],queryFn:api.targets})
  const rules = useQuery({queryKey:['automation-rules'],queryFn:api.automationRules})
  const executions = useQuery({queryKey:['automation-executions'],queryFn:api.automationExecutions,refetchInterval:3_000})
  const refreshRules = () => qc.invalidateQueries({queryKey:['automation-rules']})
  const refreshExecutions = () => qc.invalidateQueries({queryKey:['automation-executions']})
  const create = useMutation({mutationFn:api.createAutomationRule,onSuccess:async()=>{await refreshRules();await refreshExecutions()}})
  const update = useMutation({mutationFn:({id,body}:{id:string;body:Record<string,unknown>})=>api.updateAutomationRule(id,body),onSuccess:refreshRules})
  const remove = useMutation({mutationFn:api.deleteAutomationRule,onSuccess:async()=>{await refreshRules();await refreshExecutions()}})
  const approve = useMutation({mutationFn:api.approveAutomationExecution,onSettled:refreshExecutions})
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
      action,
      mode:'recommend',
      reason_match_mode:'any',
      reason_filters:reasonFilters,
      cooldown_seconds:Number(form.get('cooldown_minutes')) * 60,
      confirm_side_effects:false,
    })
  }

  function selectAction(nextAction:SafeAutomationAction) {
    const compatibleReasons = safeActionOptions.find(option=>option.value===nextAction)?.reasons.map(reason=>reason.value)??[]
    setAction(nextAction)
    setReasonFilters(compatibleReasons)
  }

  function toggleReason(reason:AutomationReason,checked:boolean) {
    setReasonFilters(current=>checked?[...new Set([...current,reason])]:current.filter(item=>item!==reason))
  }

  function toggleRule(rule:AutomationRule) {
    const enabled = !rule.enabled
    if (enabled && !canEnableRule(rule)) return
    update.mutate({id:rule.id,body:ruleBody(rule,enabled)})
  }

  const selectedAction = safeActionOptions.find(option=>option.value===action) ?? safeActionOptions[0]

  return <>
    <div className="page-title"><div><h1>故障自动化</h1><p>故障只生成处置建议，人工审批后执行并复检</p></div></div>
    {operationError && <ErrorState error={operationError}/>}
    <div className="split-layout automation-layout">
      <section className="content-band"><div className="section-title"><div><h2>新增规则</h2><p>触发条件：账号不可用</p></div></div>
        <form className="settings-form" onSubmit={submit}>
          <label>规则名称<input name="name" required placeholder="临时故障恢复"/></label>
          <label>目标<select name="target_id"><option value="">全部目标</option>{targets.data?.items.map(target=><option value={target.id} key={target.id}>{target.name}</option>)}</select></label>
          <label>建议动作<select name="action" value={action} onChange={event=>selectAction(event.target.value as SafeAutomationAction)}>{safeActionOptions.map(option=><option value={option.value} key={option.value}>{option.label}</option>)}</select></label>
          <fieldset><legend>匹配原因（任一匹配）</legend><div className="check-grid">{selectedAction.reasons.map(reason=><label className="check-label" key={reason.value}><input type="checkbox" name="reason_filters" value={reason.value} checked={reasonFilters.includes(reason.value)} onChange={event=>toggleReason(reason.value,event.target.checked)}/>{reason.label}</label>)}</div></fieldset>
          <label>冷却时间（分钟）<input name="cooldown_minutes" type="number" min="5" max="1440" defaultValue="15" required/></label>
          <div className="automation-safety"><strong>人工审批</strong><span>账号不可用告警不会直接恢复账号。审批时会校验故障快照未变化，过期建议将跳过。</span></div>
          <label className="check-label"><input name="enabled" type="checkbox" checked={createEnabled} onChange={event=>setCreateEnabled(event.target.checked)}/>创建后启用</label>
          <button className="primary" disabled={create.isPending||reasonFilters.length===0}><Plus size={17}/>{create.isPending?'保存中':'保存规则'}</button>
        </form>
      </section>
      <section className="content-band"><div className="section-title"><div><h2>自动化规则</h2><p>{rules.data?.length??0} 条配置</p></div></div>
        {rules.isError?<ErrorState error={rules.error}/>:<div className="automation-list">{rules.data?.map(rule=><div className="automation-row" key={rule.id}><div><strong>{rule.name}</strong><small>{targetName(targets.data?.items,rule.target_id)} · {actionLabels[rule.action]}</small><span className="filter-summary">{formatReasons(rule.reason_filters)} · {rule.reason_match_mode==='all'?'全部匹配':'任一匹配'} · {rule.cooldown_seconds/60} 分钟</span></div><div className="automation-state"><Status value={rule.enabled?'enabled':'disabled'}/><span className={`mode ${rule.mode}`}>{rule.mode==='execute'?'旧版自动执行（已阻止）':'人工审批'}</span></div><span className="channel-actions"><button className="icon-button" title={rule.enabled?'停用规则':canEnableRule(rule)?'启用规则':'旧版危险规则不可重新启用'} aria-label={`${rule.enabled?'停用':'启用'} ${rule.name}`} disabled={update.isPending||(!rule.enabled&&!canEnableRule(rule))} onClick={()=>toggleRule(rule)}>{rule.enabled?<PowerOff/>:<Power/>}</button><button className="icon-button" title="删除规则" aria-label={`删除 ${rule.name}`} disabled={remove.isPending} onClick={()=>{if(window.confirm(`删除规则“${rule.name}”？`))remove.mutate(rule.id)}}><Trash2/></button></span></div>)}{rules.data?.length===0&&<Empty title="没有自动化规则" detail="新增规则后，匹配的故障事件会生成待审批建议"/>}</div>}
      </section>
    </div>
    <section className="content-band execution-band"><div className="section-title"><div><h2>执行记录</h2><p>建议、审批、执行和复检状态</p></div></div>
      {executions.isError?<ErrorState error={executions.error}/>:<div className="table-wrap"><table><thead><tr><th>状态</th><th>账号</th><th>动作</th><th>时间</th><th>结果</th><th></th></tr></thead><tbody>{executions.data?.map(item=><tr key={item.id}><td><Status value={automationStatus(item.status)}/></td><td><strong>{item.external_account_id}</strong><small>{targetName(targets.data?.items,item.target_id)}</small></td><td>{actionLabels[item.action]}</td><td>{new Date(item.created_at).toLocaleString('zh-CN')}</td><td><small className={isExecutionFailure(item.status)?'danger-text':''}>{resultText(item.result,item.status,item.last_error)}</small></td><td className="actions sticky-actions">{['recommended','failed'].includes(item.status)&&<button className="icon-button" title={item.status==='failed'?'重新审批并校验故障快照':'确认执行并校验故障快照'} aria-label={`${item.status==='failed'?'重新审批':'批准'} ${item.external_account_id}`} disabled={approve.isPending} onClick={()=>{if(window.confirm(`${item.status==='failed'?'重新批准':'批准'}“${actionLabels[item.action]}”？系统将校验故障快照未变化。`))approve.mutate(item.id)}}>{item.status==='failed'?<RotateCcw/>:<CheckCircle2/>}</button>}</td></tr>)}</tbody></table>{executions.data?.length===0&&<Empty title="没有执行记录" detail="匹配故障事件后会显示在这里"/>}</div>}
    </section>
  </>
}

function ruleBody(rule:AutomationRule,enabled:boolean) {
  return {name:rule.name,target_id:rule.target_id??null,enabled,trigger_rule_key:rule.trigger_rule_key,action:rule.action,mode:rule.mode,reason_match_mode:rule.reason_match_mode,reason_filters:rule.reason_filters.length?rule.reason_filters:compatibleReasons[rule.action],cooldown_seconds:rule.cooldown_seconds,confirm_side_effects:false}
}

function canEnableRule(rule:AutomationRule) {
  return rule.mode==='recommend'&&safeActionOptions.some(option=>option.value===rule.action)
}

function targetName(targets:{id:string;name:string}[]|undefined,targetId:string|null|undefined) {
  if(!targetId)return '全部目标'
  return targets?.find(target=>target.id===targetId)?.name??targetId
}

function formatReasons(reasons:string[]) {
  return reasons.length?reasons.map(reason=>reasonLabels[reason]??reason).join(' / '):'全部兼容原因'
}

function automationStatus(status:AutomationExecution['status']) {
  if(status==='succeeded')return 'legacy_succeeded'
  if(status==='skipped')return 'legacy_skipped'
  return status
}

function isExecutionFailure(status:AutomationExecution['status']) {
  return status==='failed'||status==='verification_failed'
}

function resultText(result:Record<string,unknown>,status:AutomationExecution['status'],lastError?:string|null) {
  if(status==='verified')return '账号状态复检通过'
  if(status==='verification_failed')return '动作已应用，但账号仍不可用'
  if(status==='skipped_stale')return '账号状态已变化，未执行旧建议'
  if(status==='skipped_unverifiable')return '目标未提供账号版本，无法安全校验故障快照'
  if(status==='cancelled')return '规则已停用或任务已取消'
  if(lastError)return lastError
  if(result.http_status)return `已调用目标 API（HTTP ${result.http_status}），等待复检${result.idempotency_replayed?' · 幂等重放':''}`
  const reasons=Array.isArray(result.availability_reasons)?result.availability_reasons.map(reason=>reasonLabels[String(reason)]??String(reason)).join(' / '):''
  return reasons||(status==='recommended'?'等待人工审批':'等待处理')
}
