import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { ChannelsPage } from './ChannelsPage'
import { AccountsPage } from './AccountsPage'
import { RatesPage } from './RatesPage'
import { OperationsPage } from './OperationsPage'
import { AutomationPage } from './AutomationPage'
import { NotificationsPage } from './NotificationsPage'
import { TargetsPage } from './TargetsPage'

function renderPage(page: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}>{page}</QueryClientProvider>)
}

describe('monitoring expansion pages', () => {
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('renders declared and configured upstream multipliers distinctly', async () => {
    vi.spyOn(api, 'targets').mockResolvedValue({
      items: [{ id: 'target-1', name: 'Prod', base_url: 'https://example.com', mode: 'api_only', enabled: true, monitoring_readiness: 'ready' }],
      total: 1,
    })
    vi.spyOn(api, 'upstreamBillingSettings').mockResolvedValue({ enabled: true, interval_minutes: 30 })
    const routingPolicy={ id:'routing-1',target_id:'target-1',enabled:true,mode:'recommend' as const,probe_interval_seconds:30,priority_scale:1000,unhealthy_priority:100000,minimum_priority:1,quality_bindings:{'9':['5']},fallback_account_ids:['9'],fallback_priorities:{'9':200},last_account_count:1,last_change_count:0 }
    vi.spyOn(api, 'costRoutingPolicy').mockResolvedValue(routingPolicy)
    const saveRouting=vi.spyOn(api, 'updateCostRoutingPolicy').mockResolvedValue(routingPolicy)
    const channelMonitors=vi.spyOn(api, 'channelMonitors')
    vi.spyOn(api, 'routingDecisions').mockResolvedValue([{id:'decision-1',policy_id:'routing-1',target_id:'target-1',external_account_id:'9',account_name:'Relay',observed_multiplier:.16,previous_priority:200,desired_priority:160,reason:'cost_decrease',mode:'recommend',status:'recommended',result:{},created_at:'2026-08-09T00:00:00Z'}])
    const accounts = vi.spyOn(api, 'accounts').mockResolvedValue({
      items: [{
        id: 'account-1', target_id: 'target-1', target_name: 'Prod', external_account_id: '9', name: 'Relay', platform: 'openai', account_type: 'apikey', status: 'active', schedulable: true, available: true, availability_reasons: [], priority:200, routing_desired_priority:160, routing_status:'recommend', rate_multiplier: 0.2, upstream_billing_probe_enabled: true, upstream_billing_rate_sync_enabled: false, upstream_billing_probe: { status: 'ok', data: { resolved_rate_multiplier: 0.16 } },
      }, {
        id: 'account-2', target_id: 'target-1', target_name: 'Prod', external_account_id: '10', name: 'OAuth account', platform: 'openai', account_type: 'oauth', status: 'active', schedulable: true, available: true, availability_reasons: [], rate_multiplier: 1, upstream_billing_probe_enabled: false, upstream_billing_rate_sync_enabled: false,
      }],
      total: 1,
      next_cursor: null,
    })

    renderPage(<RatesPage />)

    expect((await screen.findAllByText('Relay')).length).toBeGreaterThan(0)
    expect(screen.getByText('一分钟成本路由')).toBeTruthy()
    expect(screen.getByText('×0.2')).toBeTruthy()
    expect(screen.getAllByText('×0.16').length).toBeGreaterThan(0)
    expect(screen.getAllByText('200').length).toBeGreaterThan(0)
    expect(screen.getAllByText('160').length).toBeGreaterThan(0)
    expect(screen.getByText('倍率下降')).toBeTruthy()
    expect(screen.queryByText('OAuth account')).toBeNull()
    expect(screen.queryByText('服务质量绑定')).toBeNull()
    expect(channelMonitors).not.toHaveBeenCalled()
    expect((screen.getByRole('checkbox',{name:'Relay 设为兜底账号'}) as HTMLInputElement).checked).toBe(true)
    expect(accounts.mock.calls[0]?.[0]).toContain('platform=openai')
    expect(accounts.mock.calls[0]?.[0]).toContain('account_type=apikey')
    vi.spyOn(window,'confirm').mockReturnValue(true)
    fireEvent.click(screen.getByRole('button',{name:'保存成本路由'}))
    await vi.waitFor(()=>expect(saveRouting).toHaveBeenCalled())
    expect(saveRouting.mock.calls[0]?.[1].quality_bindings).toEqual({'9':['5']})
  })

  it('renders aggregated channel health and availability', async () => {
    vi.spyOn(api, 'targets').mockResolvedValue({ items: [{id:'target-1',name:'Prod',base_url:'https://example.com',mode:'full',enabled:true,monitoring_readiness:'ready'}], total: 1 })
    const quality=vi.spyOn(api,'targetChannelQuality').mockResolvedValue({
      target_id:'target-1',target_name:'Prod',generated_at:'2026-08-23T06:00:00Z',time_range:'6h',failures:{},
      coverage:{requested_start:'2026-08-23T00:00:00Z',requested_end:'2026-08-23T06:00:00Z',coverage_start:'2026-08-23T00:00:00Z',data_through:'2026-08-23T05:59:00Z',computed_at:'2026-08-23T06:00:00Z',aggregation_lag_seconds:60,coverage_complete:true,bucket_seconds:3600},
      items:[{
        platform:'openai',group_id:7,group_name:'Low rate',rate_multiplier:.21,group_status:'active',
        metrics:{success_requests:99,error_requests:1,request_count:100,input_tokens:1000,output_tokens:500,cache_creation_tokens:0,cache_read_tokens:910,token_count:2410,rpm:.3,tpm:12,error_rate:.01,success_rate:.99,cache_rate:.91,cache_rate_numerator:910,cache_rate_denominator:1000,ttft:{sample_count:80,p50_ms:850,p90_ms:1200},duration:{sample_count:100,p50_ms:2600}},
        health:{overall:'healthy',error_rate:'healthy',ttft:'healthy',cache:'healthy',score:96,minimum_sample:20},
        buckets:[
          {bucket_start:'2026-08-23T05:30:00Z',metrics:{success_requests:10,error_requests:0,request_count:10,input_tokens:100,output_tokens:50,cache_creation_tokens:0,cache_read_tokens:90,token_count:240,rpm:.3,tpm:12,error_rate:0,success_rate:1,cache_rate:.9,cache_rate_numerator:90,cache_rate_denominator:100,ttft:{sample_count:8,p50_ms:800},duration:{sample_count:10,p50_ms:2500}},health:{overall:'healthy',error_rate:'healthy',ttft:'healthy',cache:'healthy',score:98,minimum_sample:5}},
          {bucket_start:'2026-08-23T06:00:00Z',metrics:{success_requests:0,error_requests:0,request_count:0,input_tokens:0,output_tokens:0,cache_creation_tokens:0,cache_read_tokens:0,token_count:0,rpm:0,tpm:0,error_rate:0,success_rate:0,cache_rate:0,cache_rate_numerator:0,cache_rate_denominator:0,ttft:{sample_count:0},duration:{sample_count:0}},health:{overall:'unknown',error_rate:'unknown',ttft:'unknown',cache:'unknown',score:null,minimum_sample:5}},
        ],
      }],
    })
    const activeRun=vi.spyOn(api,'runChannelMonitor')

    renderPage(<ChannelsPage />)

    expect(await screen.findByText('Low rate')).toBeTruthy()
    expect(screen.getByText('0.21x')).toBeTruthy()
    expect(screen.getByText('91.0%')).toBeTruthy()
    expect(screen.getByText('99.0%')).toBeTruthy()
    expect(screen.getByText('850 ms')).toBeTruthy()
    expect(screen.getByText('健康评分 96')).toBeTruthy()
    const trend=screen.getByLabelText('Low rate 窗口健康趋势')
    expect(trend.querySelectorAll('i')[1]?.title).toContain('可用 -- · 缓存 -- · 首字 --')
    expect((screen.getByRole('tab',{name:'模型检测'}) as HTMLButtonElement).disabled).toBe(true)
    expect(activeRun).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button',{name:'24h'}))
    await vi.waitFor(()=>expect(quality.mock.calls.some(([,range])=>range==='24h')).toBe(true))
  })

  it('renders native target operations and group capacity', async () => {
    vi.spyOn(api, 'targets').mockResolvedValue({ items: [{ id:'target-1', name:'Prod', base_url:'https://example.com', mode:'full', enabled:true, monitoring_readiness:'ready' }], total:1 })
    vi.spyOn(api, 'targetOperations').mockResolvedValue({
      target_id:'target-1', target_name:'Prod', generated_at:'2026-08-08T00:00:00Z', time_range:'1h', failures:{}, capabilities:{},
      resources:{
        ops_snapshot:{ generated_at:'2026-08-08T00:00:00Z', overview:{ health_score:98, success_count:120, error_count_total:2, request_count_total:122, token_consumed:5000, sla:0.995, error_rate:0.005, upstream_error_rate:0.002, qps:{current:2,peak:4,avg:1}, tps:{current:50,peak:80,avg:30}, duration:{p95_ms:420}, ttft:{p95_ms:850}, ttft_sample_count:37 }, throughput_trend:{bucket:'5m',points:[{bucket_start:'2026-08-08T00:00:00Z',request_count:20,token_consumed:400,qps:2,tps:40}]}, error_trend:{bucket:'5m',points:[]} },
        latency_histogram:{total_requests:122,buckets:[]}, openai_token_stats:{items:[],total:0},
        concurrency:{enabled:true,platform:{openai:{platform:'openai',current_in_use:2,max_capacity:10,load_percentage:20,waiting_in_queue:0}},group:{},account:{}},
        account_availability:{enabled:true,platform:{openai:{platform:'openai',available_count:6,total_accounts:7,rate_limit_count:1,error_count:0}},group:{},account:{}},
        user_concurrency:{enabled:true,user:{}},
        groups:[{id:3,name:'Default',platform:'openai',status:'active',rate_multiplier:1}], group_usage:[{group_id:3,today_cost:2,total_cost:30}], group_capacity:[{group_id:3,concurrency_used:2,concurrency_max:10,sessions_used:1,sessions_max:5,rpm_used:3,rpm_max:100}],
      },
    })
    vi.spyOn(api,'policies').mockResolvedValue([{id:'policy-1',target_id:'target-1',name:'Prod',enabled:true,unavailable_enabled:true,channel_failure_enabled:true,native_alerts_enabled:true,collection_failure_enabled:true,ttft_enabled:true,ttft_percentile:'p95',ttft_min_samples:5,ttft_warning_ms:3000,ttft_critical_ms:6000,ttft_recovery_ms:2500,quota_warning_remaining:20,quota_critical_remaining:5,quota_recovery_remaining:30,created_at:'2026-08-08T00:00:00Z',updated_at:'2026-08-08T00:00:00Z'}])

    renderPage(<OperationsPage />)

    expect(await screen.findByText('98')).toBeTruthy()
    expect(screen.getByText('122')).toBeTruthy()
    expect(screen.getByText('99.50%')).toBeTruthy()
    expect(screen.getByText('0.50%')).toBeTruthy()
    expect(screen.getByText('850 ms')).toBeTruthy()
    expect(screen.getByText('37')).toBeTruthy()
    expect(screen.getByText('首 Token 告警')).toBeTruthy()
    fireEvent.click(screen.getByRole('button',{name:'Token'}))
    expect(screen.getByRole('button',{name:'Token'}).getAttribute('aria-pressed')).toBe('true')
    expect(screen.getAllByText('400').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('tab',{name:'容量'}))
    expect(await screen.findByText('Default')).toBeTruthy()
    expect(screen.getByText(/2\.00/)).toBeTruthy()
  })

  it('renders native per-account usage statistics and changes the period', async () => {
    vi.spyOn(api, 'accounts').mockResolvedValue({
      items:[{ id:'account-1', target_id:'target-1', target_name:'Prod', external_account_id:'9', name:'Codex Key', platform:'openai', account_type:'apikey', status:'active', schedulable:true, available:true, availability_reasons:[], group_ids:['2','5'], rate_multiplier:.16, upstream_billing_probe_enabled:true, upstream_billing_rate_sync_enabled:false }],
      total:1,
      next_cursor:null,
    })
    const stats = vi.spyOn(api, 'accountStats').mockResolvedValue({
      history:[{date:'2026-08-08',label:'08-08',requests:120,tokens:64000,cost:3,actual_cost:.48,user_cost:.72}],
      summary:{days:30,actual_days_used:8,total_cost:.48,total_user_cost:.72,total_standard_cost:3,total_requests:120,total_tokens:64000,avg_duration_ms:420,today:{date:'2026-08-08',requests:12,tokens:6000,cost:.05,user_cost:.08},highest_cost_day:{date:'2026-08-08',label:'08-08',requests:12,cost:.05,user_cost:.08},highest_request_day:{date:'2026-08-08',label:'08-08',requests:12,cost:.05,user_cost:.08}},
      models:[{model:'gpt-5.3-codex',requests:120,total_tokens:64000,cost:3,actual_cost:.72,account_cost:.48}],
      endpoints:[{endpoint:'/v1/responses',requests:120,total_tokens:64000,cost:3,actual_cost:.72}],
      upstream_endpoints:[{endpoint:'/v1/responses',requests:120,total_tokens:64000,cost:3,actual_cost:.72}],
    })
    vi.spyOn(api, 'accountQuota').mockResolvedValue([])

    renderPage(<AccountsPage />)

    expect(await screen.findByText('Codex Key')).toBeTruthy()
    fireEvent.click(screen.getByRole('button',{name:'查看 Codex Key 账号详情'}))
    expect((await screen.findAllByText('64.00K')).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button',{name:'账号成本'}))
    expect(screen.getByRole('button',{name:'账号成本'}).getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByText('gpt-5.3-codex')).toBeTruthy()
    expect(screen.getAllByText('/v1/responses')).toHaveLength(2)
    fireEvent.click(screen.getByRole('button',{name:'7 天'}))
    expect(await vi.waitFor(() => stats.mock.calls.some(([,days]) => days === 7))).toBe(true)
    fireEvent.click(screen.getByRole('tab',{name:'额度与状态'}))
    expect(await screen.findByText('账号状态')).toBeTruthy()
  })

  it('renders automation recommendations and approves an execution', async () => {
    vi.spyOn(api,'targets').mockResolvedValue({items:[{id:'target-1',name:'Prod',base_url:'https://example.com',mode:'api_only',enabled:true,monitoring_readiness:'ready'}],total:1})
    vi.spyOn(api,'automationRules').mockResolvedValue([{id:'rule-1',target_id:'target-1',name:'Recover temporary faults',enabled:true,trigger_rule_key:'account.unavailable',action:'recover_state',mode:'recommend',reason_match_mode:'any',reason_filters:['temporarily_unschedulable'],cooldown_seconds:900,created_at:'2026-08-09T00:00:00Z',updated_at:'2026-08-09T00:00:00Z'}])
    vi.spyOn(api,'automationExecutions').mockResolvedValue([{id:'execution-1',rule_id:'rule-1',incident_id:'incident-1',transition_id:'transition-1',target_id:'target-1',external_account_id:'9',action:'recover_state',mode:'recommend',status:'recommended',attempts:0,result:{availability_reasons:['temporarily_unschedulable']},created_at:'2026-08-09T00:00:00Z'}])
    const approve=vi.spyOn(api,'approveAutomationExecution').mockResolvedValue({id:'execution-1',rule_id:'rule-1',incident_id:'incident-1',transition_id:'transition-1',target_id:'target-1',external_account_id:'9',action:'recover_state',mode:'execute',status:'queued',attempts:0,result:{},created_at:'2026-08-09T00:00:00Z'})
    vi.spyOn(window,'confirm').mockReturnValue(true)

    renderPage(<AutomationPage/>)

    expect(await screen.findByText('Recover temporary faults')).toBeTruthy()
    fireEvent.click(await screen.findByRole('button',{name:'批准 9'}))
    await vi.waitFor(()=>expect(approve.mock.calls[0]?.[0]).toBe('execution-1'))
  })

  it('renders signed webhook subscriptions and delivery type', async () => {
    vi.spyOn(api,'targets').mockResolvedValue({items:[],total:0})
    vi.spyOn(api,'channels').mockResolvedValue([{id:'hook-1',target_id:null,name:'Event bus',kind:'webhook',server_url:'https://events.example.com/sub2api',topic:'',enabled:true,event_types:['incident.firing','incident.resolved'],severities:['critical'],token_configured:false,signing_secret_configured:true,created_at:'2026-08-09T00:00:00Z'}])
    vi.spyOn(api,'outbox').mockResolvedValue([{id:'delivery-1',channel_id:'hook-1',channel_name:'Event bus',channel_kind:'webhook',status:'sent',attempts:0,sent_at:'2026-08-09T00:00:01Z',created_at:'2026-08-09T00:00:00Z'}])

    renderPage(<NotificationsPage/>)

    expect((await screen.findAllByText('Event bus')).length).toBeGreaterThan(0)
    expect(screen.getByText('HMAC')).toBeTruthy()
    expect(screen.getByText('故障触发 / 故障恢复 · 严重')).toBeTruthy()
    fireEvent.click(screen.getByRole('button',{name:'Webhook'}))
    expect((screen.getByRole('textbox',{name:'Webhook 地址'}) as HTMLInputElement).value).toBe('')
    fireEvent.click(screen.getByRole('button',{name:'Telegram'}))
    expect((screen.getByRole('textbox',{name:'Telegram Bot API 地址'}) as HTMLInputElement).value).toBe('https://api.telegram.org')
    expect(screen.getByRole('textbox',{name:'Chat ID / @频道'})).toBeTruthy()
  })

  it('retries a failed target probe without creating a duplicate target', async () => {
    vi.spyOn(api,'targets').mockResolvedValue({items:[],total:0})
    const target = {id:'target-new',name:'Prod',base_url:'https://example.com',mode:'api_only' as const,enabled:false,monitoring_readiness:'not_ready' as const}
    const readyTarget = {...target,monitoring_readiness:'ready' as const}
    const create = vi.spyOn(api,'createTarget').mockResolvedValue(target)
    const probe = vi.spyOn(api,'probeTarget')
      .mockRejectedValueOnce(new Error('target probe failed'))
      .mockResolvedValueOnce(readyTarget)
    vi.spyOn(api,'updateTarget').mockResolvedValue({...readyTarget,enabled:true})

    renderPage(<TargetsPage/>)
    fireEvent.click(await screen.findByRole('button',{name:'添加目标'}))
    fireEvent.change(screen.getByLabelText('目标名称'),{target:{value:'Prod'}})
    fireEvent.change(screen.getByLabelText('Sub2API 地址'),{target:{value:'https://example.com'}})
    fireEvent.change(screen.getByLabelText('管理员凭据'),{target:{value:'admin-key'}})
    fireEvent.click(screen.getByRole('button',{name:'保存并探测'}))

    expect(await screen.findByText('target probe failed')).toBeTruthy()
    expect(create).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button',{name:'重新探测'}))
    await vi.waitFor(()=>expect(probe).toHaveBeenCalledTimes(2))
    expect(create).toHaveBeenCalledTimes(1)
    await vi.waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull())
  })
})
