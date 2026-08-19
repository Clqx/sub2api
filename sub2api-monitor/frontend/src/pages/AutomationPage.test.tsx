import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import type { AutomationExecution, AutomationRule } from '../types'
import { AutomationPage } from './AutomationPage'

function renderPage() {
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={client}><AutomationPage/></QueryClientProvider>)
}

function mockBaseQueries(rules:AutomationRule[]=[],executions:AutomationExecution[]=[]) {
  vi.spyOn(api,'targets').mockResolvedValue({items:[{id:'target-1',name:'Prod',base_url:'https://example.com',mode:'api_only',enabled:true,monitoring_readiness:'ready'}],total:1})
  vi.spyOn(api,'automationRules').mockResolvedValue(rules)
  vi.spyOn(api,'automationExecutions').mockResolvedValue(executions)
}

function execution(id:string,status:AutomationExecution['status']):AutomationExecution {
  return {id,rule_id:'rule-1',incident_id:'incident-1',transition_id:`transition-${id}`,target_id:'target-1',external_account_id:id,action:'clear_temp_unschedulable',mode:'recommend',status,attempts:0,result:{},created_at:'2026-08-09T00:00:00Z'}
}

describe('AutomationPage safety controls',()=>{
  afterEach(()=>{
    cleanup()
    vi.restoreAllMocks()
  })

  it('creates recommendation-only rules with an explicit any-match payload',async()=>{
    mockBaseQueries()
    const created:AutomationRule = {id:'rule-1',target_id:null,name:'Temporary isolation review',enabled:true,trigger_rule_key:'account.unavailable',action:'clear_temp_unschedulable',mode:'recommend',reason_match_mode:'any',reason_filters:['temporarily_unschedulable'],cooldown_seconds:900,created_at:'2026-08-09T00:00:00Z',updated_at:'2026-08-09T00:00:00Z'}
    const create = vi.spyOn(api,'createAutomationRule').mockResolvedValue(created)

    renderPage()

    expect(await screen.findByText('没有自动化规则')).toBeTruthy()
    expect(screen.queryByRole('button',{name:'自动执行'})).toBeNull()
    expect(screen.queryByRole('checkbox',{name:'账号错误'})).toBeNull()
    fireEvent.change(screen.getByRole('textbox',{name:'规则名称'}),{target:{value:'Temporary isolation review'}})
    fireEvent.click(screen.getByRole('checkbox',{name:'创建后启用'}))
    fireEvent.click(screen.getByRole('button',{name:'保存规则'}))

    await vi.waitFor(()=>expect(create.mock.calls[0]?.[0]).toEqual({
      name:'Temporary isolation review',
      target_id:null,
      enabled:true,
      trigger_rule_key:'account.unavailable',
      action:'clear_temp_unschedulable',
      mode:'recommend',
      reason_match_mode:'any',
      reason_filters:['temporarily_unschedulable'],
      cooldown_seconds:900,
      confirm_side_effects:false,
    }))
  })

  it('only exposes reasons compatible with the selected action',async()=>{
    mockBaseQueries()

    renderPage()

    await screen.findByText('没有自动化规则')
    const action = screen.getByRole('combobox',{name:'建议动作'})
    expect(screen.getByRole('checkbox',{name:'临时不可调度'})).toBeTruthy()
    fireEvent.change(action,{target:{value:'clear_error'}})
    expect(screen.getByRole('checkbox',{name:'账号错误'})).toBeTruthy()
    expect(screen.queryByRole('checkbox',{name:'临时不可调度'})).toBeNull()
    expect(screen.queryByText('上游过载')).toBeNull()
    expect(screen.getByText('匹配原因（任一匹配）')).toBeTruthy()
  })

  it('does not allow a disabled legacy execute rule to be re-enabled',async()=>{
    mockBaseQueries([{
      id:'legacy-rule',target_id:null,name:'Legacy auto recovery',enabled:false,trigger_rule_key:'account.unavailable',action:'recover_state',mode:'execute',reason_match_mode:'any',reason_filters:['overloaded'],cooldown_seconds:900,created_at:'2026-08-09T00:00:00Z',updated_at:'2026-08-09T00:00:00Z',
    }])

    renderPage()

    expect(await screen.findByText('旧版自动执行（已阻止）')).toBeTruthy()
    expect((screen.getByRole('button',{name:'启用 Legacy auto recovery'}) as HTMLButtonElement).disabled).toBe(true)
  })

  it('can disable an enabled legacy execute rule with a schema-valid payload',async()=>{
    const legacy:AutomationRule = {
      id:'legacy-enabled',target_id:null,name:'Enabled legacy recovery',enabled:true,trigger_rule_key:'account.unavailable',action:'recover_state',mode:'execute',reason_match_mode:'any',reason_filters:[],cooldown_seconds:900,created_at:'2026-08-09T00:00:00Z',updated_at:'2026-08-09T00:00:00Z',
    }
    mockBaseQueries([legacy])
    const update = vi.spyOn(api,'updateAutomationRule').mockResolvedValue({...legacy,enabled:false,reason_filters:['status:error','rate_limited','overloaded','temporarily_unschedulable']})

    renderPage()

    fireEvent.click(await screen.findByRole('button',{name:'停用 Enabled legacy recovery'}))
    await vi.waitFor(()=>expect(update.mock.calls[0]?.[0]).toEqual('legacy-enabled'))
    expect(update.mock.calls[0]?.[1]).toEqual({
      name:'Enabled legacy recovery',
      target_id:null,
      enabled:false,
      trigger_rule_key:'account.unavailable',
      action:'recover_state',
      mode:'execute',
      reason_match_mode:'any',
      reason_filters:['status:error','rate_limited','overloaded','temporarily_unschedulable'],
      cooldown_seconds:900,
      confirm_side_effects:false,
    })
  })

  it('shows the recovery lifecycle and only allows approving recommendations',async()=>{
    const statuses:AutomationExecution['status'][] = ['recommended','approved','queued','applied','verified','verification_failed','skipped_stale','skipped_unverifiable','cancelled','failed','succeeded','skipped']
    mockBaseQueries([],statuses.map((status,index)=>execution(String(index+1),status)))
    vi.spyOn(api,'approveAutomationExecution').mockResolvedValue(execution('1','queued'))
    vi.spyOn(window,'confirm').mockReturnValue(false)

    renderPage()

    expect(await screen.findByText('待人工审批')).toBeTruthy()
    expect(screen.getByText('已批准')).toBeTruthy()
    expect(screen.getByText('排队中')).toBeTruthy()
    expect(screen.getByText('已应用，待复检')).toBeTruthy()
    expect(screen.getByText('复检通过')).toBeTruthy()
    expect(screen.getByText('复检未通过')).toBeTruthy()
    expect(screen.getByText('状态已变化，跳过')).toBeTruthy()
    expect(screen.getByText('缺少可验证的账号版本，未执行')).toBeTruthy()
    expect(screen.getByText('目标未提供账号版本，无法安全校验故障快照')).toBeTruthy()
    expect(screen.getByText('已取消')).toBeTruthy()
    expect(screen.getByText('已调用（旧状态）')).toBeTruthy()
    expect(screen.getByText('已跳过（旧状态）')).toBeTruthy()
    expect(screen.getAllByRole('button',{name:/^批准 /})).toHaveLength(1)
    expect(screen.getByRole('button',{name:/^重新审批 /})).toBeTruthy()
  })
})
