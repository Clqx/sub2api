import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ChartMetricSwitch, InteractiveBarChart } from './InteractiveBarChart'

const points = [
  {
    id: 'first',
    label: '2026/8/9 10:00',
    shortLabel: '10:00',
    value: 10,
    details: [{ label: 'Token', value: '100' }],
  },
  {
    id: 'second',
    label: '2026/8/9 10:01',
    shortLabel: '10:01',
    value: 20,
    details: [{ label: 'Token', value: '200' }],
  },
]

afterEach(cleanup)

describe('InteractiveBarChart', () => {
  it('supports preview, pinned selection, and keyboard navigation', () => {
    const { getByRole, getByText, rerender } = render(
      <InteractiveBarChart
        ariaLabel="请求趋势"
        points={points}
        valueLabel="请求数"
        valueFormatter={(value) => (value == null ? '--' : String(value))}
      />,
    )

    const first = screen.getByRole('button', { name: /2026\/8\/9 10:00，请求数 10/ })
    const second = getByRole('button', { name: /2026\/8\/9 10:01，请求数 20/ })
    expect(getByText('2026/8/9 10:01')).toBeTruthy()

    fireEvent.mouseEnter(first)
    expect(screen.getByText('2026/8/9 10:00')).toBeTruthy()

    fireEvent.click(first)
    fireEvent.mouseEnter(second)
    expect(screen.getByText('2026/8/9 10:00')).toBeTruthy()
    expect(first.getAttribute('aria-pressed')).toBe('true')

    rerender(
      <InteractiveBarChart
        ariaLabel="请求趋势"
        points={[...points, { id: 'third', label: '2026/8/9 10:02', shortLabel: '10:02', value: 30 }]}
        valueLabel="请求数"
        valueFormatter={(value) => (value == null ? '--' : String(value))}
      />,
    )
    expect(screen.getByText('2026/8/9 10:00')).toBeTruthy()
    expect(first.getAttribute('aria-pressed')).toBe('true')

    fireEvent.keyDown(first, { key: 'Escape' })
    expect(screen.getByText('2026/8/9 10:02')).toBeTruthy()

    fireEvent.mouseEnter(second)
    expect(screen.getByText('2026/8/9 10:01')).toBeTruthy()

    fireEvent.keyDown(first, { key: 'ArrowRight' })
    expect(document.activeElement).toBe(second)
  })

  it('exposes metric choices as a segmented control', () => {
    const onChange = vi.fn()
    render(
      <ChartMetricSwitch
        ariaLabel="趋势指标"
        value="requests"
        options={[
          { value: 'requests', label: '请求' },
          { value: 'tokens', label: 'Token' },
        ]}
        onChange={onChange}
      />,
    )

    const requests = screen.getByRole('button', { name: '请求' })
    expect(requests.getAttribute('aria-pressed')).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: 'Token' }))
    expect(onChange).toHaveBeenCalledWith('tokens')
  })

  it('keeps a pinned point selected when a rolling window shifts', () => {
    const rollingPoints = [
      ...points,
      { id: 'third', label: '2026/8/9 10:02', shortLabel: '10:02', value: 30 },
    ]
    const { rerender } = render(
      <InteractiveBarChart
        ariaLabel="请求趋势"
        points={rollingPoints}
        valueLabel="请求数"
        valueFormatter={(value) => (value == null ? '--' : String(value))}
      />,
    )

    const second = screen.getByRole('button', { name: /2026\/8\/9 10:01，请求数 20/ })
    fireEvent.click(second)
    rerender(
      <InteractiveBarChart
        ariaLabel="请求趋势"
        points={[
          rollingPoints[1],
          rollingPoints[2],
          { id: 'fourth', label: '2026/8/9 10:03', shortLabel: '10:03', value: 40 },
        ]}
        valueLabel="请求数"
        valueFormatter={(value) => (value == null ? '--' : String(value))}
      />,
    )

    expect(screen.getByText('2026/8/9 10:01')).toBeTruthy()
    expect(second.getAttribute('aria-pressed')).toBe('true')
  })
})
