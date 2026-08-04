import type { QuotaWindow } from './types'

const SOURCE_LABELS: Record<string, string> = {
  sub2api_api: '主动 API',
  sub2api_api_active: '主动 API',
  sub2api_api_passive: '被动 API',
  sub2api_db_passive: '被动 DB',
  sub2api_api_inventory: '账号库存',
}

function finite(value: number | null | undefined): value is number {
  return value != null && Number.isFinite(value)
}

export function formatNumber(value: number | null | undefined): string | null {
  if (!finite(value)) return null
  return new Intl.NumberFormat('zh-CN', { maximumFractionDigits:2 }).format(value)
}

export function formatQuotaValue(value: number | null | undefined, unit: string): string | null {
  const formatted = formatNumber(value)
  if (formatted == null) return null
  if (unit === 'percent') return `${formatted}%`
  return unit ? `${formatted} ${unit}` : formatted
}

export function quotaRemainingText(window: QuotaWindow): string {
  const values: string[] = []
  const percent = formatNumber(window.remaining_percent)
  const absolute = formatQuotaValue(window.remaining_value, window.unit)
  if (percent != null) values.push(`${percent}%`)
  if (absolute != null && absolute !== `${percent}%`) values.push(absolute)
  return values.length ? values.join(' / ') : '未知'
}

export function quotaUsageText(window: QuotaWindow): string {
  const utilization = formatNumber(window.utilization_percent)
  if (utilization != null) return `已用 ${utilization}%`
  const used = formatQuotaValue(window.used_value, window.unit)
  const limit = formatQuotaValue(window.limit_value, window.unit)
  if (used != null && limit != null) return `已用 ${used} / ${limit}`
  if (used != null) return `已用 ${used}`
  return '已用未知'
}

export function quotaSourceLabel(source: string): string {
  if (SOURCE_LABELS[source]) return SOURCE_LABELS[source]
  const normalized = source.toLowerCase()
  if (normalized.includes('inventory')) return '账号库存'
  if (normalized.includes('db')) return '被动 DB'
  if (normalized.includes('passive')) return '被动 API'
  if (normalized.includes('active') || normalized.includes('api')) return '主动 API'
  return source ? `其他来源 (${source})` : '未知来源'
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '未知'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '未知' : date.toLocaleString('zh-CN')
}
