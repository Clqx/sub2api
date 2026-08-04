import { describe, expect, it } from 'vitest'
import { formatDateTime, quotaRemainingText, quotaSourceLabel, quotaUsageText } from './quotaPresentation'
import type { QuotaWindow } from './types'

const quota = (overrides: Partial<QuotaWindow> = {}): QuotaWindow => ({
  id:'quota-1', quota_key:'five_hour', label:'5 hour quota', unit:'requests',
  observed_at:'2026-08-03T10:00:00Z', source:'sub2api_api_passive', freshness:'fresh',
  ...overrides,
})

describe('quota presentation', () => {
  it('keeps missing quota values unknown instead of inventing zero', () => {
    expect(quotaRemainingText(quota())).toBe('未知')
    expect(quotaUsageText(quota())).toBe('已用未知')
    expect(formatDateTime(null)).toBe('未知')
    expect(quotaRemainingText(quota({ remaining_percent:0 }))).toBe('0%')
  })

  it('renders percentage and absolute quota information when both exist', () => {
    const window = quota({ remaining_percent:12.5, remaining_value:25, used_value:175, limit_value:200 })
    expect(quotaRemainingText(window)).toBe('12.5% / 25 requests')
    expect(quotaUsageText(window)).toBe('已用 175 requests / 200 requests')
  })

  it('prefers utilization and translates known collection sources', () => {
    expect(quotaUsageText(quota({ utilization_percent:87.5, used_value:175, limit_value:200 }))).toBe('已用 87.5%')
    expect(quotaSourceLabel('sub2api_api_active')).toBe('主动 API')
    expect(quotaSourceLabel('sub2api_api_passive')).toBe('被动 API')
    expect(quotaSourceLabel('sub2api_db_passive')).toBe('被动 DB')
    expect(quotaSourceLabel('sub2api_api_inventory')).toBe('账号库存')
  })
})
