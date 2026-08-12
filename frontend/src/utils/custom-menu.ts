import type { CustomMenuItem } from '@/types'

export function getCustomMenuLabel(item: CustomMenuItem, locale: string): string {
  const fallback = item.label?.trim() || ''
  if (String(locale).toLowerCase().startsWith('zh')) return fallback
  return item.label_en?.trim() || fallback
}
