import { describe, expect, it } from 'vitest'
import { getCustomMenuLabel } from '@/utils/custom-menu'
import type { CustomMenuItem } from '@/types'

const menuItem: CustomMenuItem = {
  id: 'redeem-center',
  label: '兑换中心',
  label_en: 'Redemption Center',
  icon_svg: '',
  url: 'https://example.com/redeem',
  visibility: 'user',
  sort_order: 0,
}

describe('getCustomMenuLabel', () => {
  it('selects the label matching the current locale', () => {
    expect(getCustomMenuLabel(menuItem, 'zh')).toBe('兑换中心')
    expect(getCustomMenuLabel(menuItem, 'zh-CN')).toBe('兑换中心')
    expect(getCustomMenuLabel(menuItem, 'en')).toBe('Redemption Center')
    expect(getCustomMenuLabel(menuItem, 'en-US')).toBe('Redemption Center')
  })

  it('falls back to the default label when the English label is empty', () => {
    expect(getCustomMenuLabel({ ...menuItem, label_en: '  ' }, 'en')).toBe('兑换中心')
    expect(getCustomMenuLabel({ ...menuItem, label_en: undefined }, 'en')).toBe('兑换中心')
  })
})
