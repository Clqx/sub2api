import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { ChannelsPage } from './ChannelsPage'
import { AccountsPage } from './AccountsPage'
import { RatesPage } from './RatesPage'
import { OperationsPage } from './OperationsPage'

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
    const accounts = vi.spyOn(api, 'accounts').mockResolvedValue({
      items: [{
        id: 'account-1', target_id: 'target-1', target_name: 'Prod', external_account_id: '9', name: 'Relay', platform: 'openai', account_type: 'apikey', status: 'active', schedulable: true, available: true, availability_reasons: [], rate_multiplier: 0.2, upstream_billing_probe_enabled: true, upstream_billing_rate_sync_enabled: false, upstream_billing_probe: { status: 'ok', data: { resolved_rate_multiplier: 0.16 } },
      }, {
        id: 'account-2', target_id: 'target-1', target_name: 'Prod', external_account_id: '10', name: 'OAuth account', platform: 'openai', account_type: 'oauth', status: 'active', schedulable: true, available: true, availability_reasons: [], rate_multiplier: 1, upstream_billing_probe_enabled: false, upstream_billing_rate_sync_enabled: false,
      }],
      total: 1,
      next_cursor: null,
    })

    renderPage(<RatesPage />)

    expect(await screen.findByText('Relay')).toBeTruthy()
    expect(screen.getByText('×0.2')).toBeTruthy()
    expect(screen.getByText('×0.16')).toBeTruthy()
    expect(screen.queryByText('OAuth account')).toBeNull()
    expect(accounts.mock.calls[0]?.[0]).toContain('platform=openai')
    expect(accounts.mock.calls[0]?.[0]).toContain('account_type=apikey')
  })

  it('renders aggregated channel health and availability', async () => {
    vi.spyOn(api, 'targets').mockResolvedValue({ items: [], total: 0 })
    vi.spyOn(api, 'channelMonitors').mockResolvedValue([{
      id: 'channel-1', target_id: 'target-1', target_name: 'Prod', external_monitor_id: '5', name: 'Codex', provider: 'openai', api_mode: 'responses', endpoint: 'https://example.com', api_key_masked: 'sk-***', api_key_decrypt_failed: false, primary_model: 'gpt-5.3-codex', extra_models: [], group_name: 'Primary', enabled: true, interval_seconds: 60, jitter_seconds: 0, last_checked_at: '2026-08-08T00:00:00Z', primary_status: 'operational', primary_latency_ms: 420, availability_7d: 99.9, extra_models_status: [], extra_headers: {}, body_override_mode: 'off', observed_at: '2026-08-08T00:00:00Z',
    }])

    renderPage(<ChannelsPage />)

    expect(await screen.findByText('Codex')).toBeTruthy()
    expect(screen.getByText('420 ms')).toBeTruthy()
    expect(screen.getByText('99.90%')).toBeTruthy()
  })

  it('renders native target operations and group capacity', async () => {
    vi.spyOn(api, 'targets').mockResolvedValue({ items: [{ id:'target-1', name:'Prod', base_url:'https://example.com', mode:'full', enabled:true, monitoring_readiness:'ready' }], total:1 })
    vi.spyOn(api, 'targetOperations').mockResolvedValue({
      target_id:'target-1', target_name:'Prod', generated_at:'2026-08-08T00:00:00Z', time_range:'1h', failures:{}, capabilities:{},
      resources:{
        ops_snapshot:{ generated_at:'2026-08-08T00:00:00Z', overview:{ health_score:98, success_count:120, error_count_total:2, request_count_total:122, token_consumed:5000, sla:0.995, error_rate:0.005, upstream_error_rate:0.002, qps:{current:2,peak:4,avg:1}, tps:{current:50,peak:80,avg:30}, duration:{p95_ms:420}, ttft:{} }, throughput_trend:{bucket:'5m',points:[]}, error_trend:{bucket:'5m',points:[]} },
        latency_histogram:{total_requests:122,buckets:[]}, openai_token_stats:{items:[],total:0},
        concurrency:{enabled:true,platform:{openai:{platform:'openai',current_in_use:2,max_capacity:10,load_percentage:20,waiting_in_queue:0}},group:{},account:{}},
        account_availability:{enabled:true,platform:{openai:{platform:'openai',available_count:6,total_accounts:7,rate_limit_count:1,error_count:0}},group:{},account:{}},
        user_concurrency:{enabled:true,user:{}},
        groups:[{id:3,name:'Default',platform:'openai',status:'active',rate_multiplier:1}], group_usage:[{group_id:3,today_cost:2,total_cost:30}], group_capacity:[{group_id:3,concurrency_used:2,concurrency_max:10,sessions_used:1,sessions_max:5,rpm_used:3,rpm_max:100}],
      },
    })

    renderPage(<OperationsPage />)

    expect(await screen.findByText('98')).toBeTruthy()
    expect(screen.getByText('122')).toBeTruthy()
    expect(screen.getByText('99.50%')).toBeTruthy()
    expect(screen.getByText('0.50%')).toBeTruthy()
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
    expect(screen.getByText('gpt-5.3-codex')).toBeTruthy()
    expect(screen.getAllByText('/v1/responses')).toHaveLength(2)
    fireEvent.click(screen.getByRole('button',{name:'7 天'}))
    expect(await vi.waitFor(() => stats.mock.calls.some(([,days]) => days === 7))).toBe(true)
    fireEvent.click(screen.getByRole('tab',{name:'额度与状态'}))
    expect(await screen.findByText('账号状态')).toBeTruthy()
  })
})
