import { useEffect, useRef, useState } from 'react'
import type { CSSProperties, KeyboardEvent } from 'react'

export interface InteractiveChartDetail {
  label: string
  value: string
}

export interface InteractiveChartPoint {
  id: string
  label: string
  shortLabel: string
  value: number | null
  details?: InteractiveChartDetail[]
}

interface InteractiveBarChartProps {
  ariaLabel: string
  points: InteractiveChartPoint[]
  valueLabel: string
  valueFormatter: (value: number | null) => string
  tone?: 'success' | 'danger' | 'info'
  emptyLabel?: string
}

export interface ChartMetricOption<T extends string> {
  value: T
  label: string
}

export function ChartMetricSwitch<T extends string>({
  ariaLabel,
  value,
  options,
  onChange,
}: {
  ariaLabel: string
  value: T
  options: ChartMetricOption<T>[]
  onChange: (value: T) => void
}) {
  return (
    <div className="chart-metric-switch" role="group" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

export function InteractiveBarChart({
  ariaLabel,
  points,
  valueLabel,
  valueFormatter,
  tone = 'success',
  emptyLabel = '暂无趋势数据',
}: InteractiveBarChartProps) {
  const lastIndex = points.length - 1
  const firstPointId = points[0]?.id
  const lastPointId = points[lastIndex]?.id
  const [activePointId, setActivePointId] = useState<string | undefined>(lastPointId)
  const [pinned, setPinned] = useState(false)
  const activePointIdRef = useRef<string | undefined>(lastPointId)
  const pointRefs = useRef<Array<HTMLButtonElement | null>>([])
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const followLatest = useRef(true)

  useEffect(() => {
    const activePointStillExists = points.some((point) => point.id === activePointIdRef.current)
    if (!followLatest.current && activePointStillExists) return
    followLatest.current = true
    activePointIdRef.current = lastPointId
    setActivePointId(lastPointId)
    setPinned(false)
  }, [firstPointId, lastIndex, lastPointId, points])

  useEffect(() => {
    const container = scrollRef.current
    if (container && followLatest.current) container.scrollLeft = container.scrollWidth
  }, [lastIndex, lastPointId])

  if (!points.length) return <div className="chart-empty">{emptyLabel}</div>

  const values = points
    .map((point) => point.value)
    .filter((value): value is number => value != null && Number.isFinite(value))
    .map((value) => Math.max(0, value))
  const maximum = Math.max(0, ...values)
  const average = values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : null
  const activeIndex = points.findIndex((point) => point.id === activePointId)
  const resolvedIndex = activeIndex >= 0 ? activeIndex : lastIndex
  const activePoint = points[resolvedIndex]

  function selectPoint(pointId: string | undefined) {
    activePointIdRef.current = pointId
    setActivePointId(pointId)
  }

  function focusPoint(index: number) {
    const nextIndex = Math.max(0, Math.min(lastIndex, index))
    followLatest.current = nextIndex === lastIndex
    selectPoint(points[nextIndex]?.id)
    pointRefs.current[nextIndex]?.focus()
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === 'ArrowLeft') {
      event.preventDefault()
      focusPoint(index - 1)
    } else if (event.key === 'ArrowRight') {
      event.preventDefault()
      focusPoint(index + 1)
    } else if (event.key === 'Home') {
      event.preventDefault()
      focusPoint(0)
    } else if (event.key === 'End') {
      event.preventDefault()
      focusPoint(lastIndex)
    } else if (event.key === 'Escape') {
      followLatest.current = true
      setPinned(false)
      selectPoint(lastPointId)
      if (scrollRef.current) scrollRef.current.scrollLeft = scrollRef.current.scrollWidth
    }
  }

  const chartStyle = {
    '--chart-columns': points.length,
  } as CSSProperties

  return (
    <div className={`interactive-chart chart-tone-${tone}`}>
      <div className="chart-readout" aria-live="polite">
        <div className="chart-selected-time">
          <span>时间</span>
          <strong>{activePoint.label}</strong>
        </div>
        <div>
          <span>{valueLabel}</span>
          <strong>{valueFormatter(activePoint.value)}</strong>
        </div>
        <div>
          <span>平均</span>
          <strong>{valueFormatter(average)}</strong>
        </div>
        <div>
          <span>峰值</span>
          <strong>{valueFormatter(maximum)}</strong>
        </div>
        {activePoint.details?.length ? (
          <dl className="chart-detail-list">
            {activePoint.details.map((detail) => (
              <div key={detail.label}>
                <dt>{detail.label}</dt>
                <dd>{detail.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </div>
      <div
        className="interactive-chart-scroll"
        ref={scrollRef}
        onScroll={(event) => {
          const element = event.currentTarget
          followLatest.current =
            element.scrollWidth - element.clientWidth - element.scrollLeft < 32
        }}
      >
        <div className="interactive-chart-canvas" style={chartStyle} aria-label={ariaLabel}>
          <div className="chart-y-axis" aria-hidden="true">
            <span>{valueFormatter(maximum)}</span>
            <span>{valueFormatter(maximum / 2)}</span>
            <span>{valueFormatter(0)}</span>
          </div>
          <div className="chart-plot">
            <i className="chart-gridline chart-gridline-top" />
            <i className="chart-gridline chart-gridline-middle" />
            <i className="chart-gridline chart-gridline-bottom" />
            {points.map((point, index) => {
              const normalized = point.value == null ? null : Math.max(0, point.value)
              const height = normalized == null || maximum === 0 ? 0 : (normalized / maximum) * 100
              const pointStyle = {
                '--bar-height': `${height}%`,
              } as CSSProperties
              const detailText = point.details
                ?.map((detail) => `${detail.label} ${detail.value}`)
                .join('，')
              const selected = activePoint.id === point.id
              const explicitlySelected = activePointId === point.id
              return (
                <button
                  key={point.id}
                  type="button"
                  ref={(element) => {
                    pointRefs.current[index] = element
                  }}
                  className={`chart-point${selected ? ' active' : ''}${normalized == null ? ' missing' : ''}${normalized === 0 ? ' zero' : ''}`}
                  style={pointStyle}
                  aria-label={`${point.label}，${valueLabel} ${valueFormatter(point.value)}${detailText ? `，${detailText}` : ''}`}
                  aria-pressed={pinned && explicitlySelected}
                  title={`${point.label} · ${valueLabel} ${valueFormatter(point.value)}${detailText ? ` · ${detailText}` : ''}`}
                  onMouseEnter={() => {
                    if (!pinned) selectPoint(point.id)
                  }}
                  onMouseLeave={() => {
                    if (!pinned) selectPoint(lastPointId)
                  }}
                  onFocus={() => selectPoint(point.id)}
                  onClick={() => {
                    const nextPinned = selected ? !pinned : true
                    followLatest.current = !nextPinned && index === lastIndex
                    selectPoint(point.id)
                    setPinned(nextPinned)
                  }}
                  onKeyDown={(event) => handleKeyDown(event, index)}
                >
                  <span className="chart-bar-area" aria-hidden="true">
                    <i className="chart-bar" />
                  </span>
                  <small aria-hidden="true">{point.shortLabel}</small>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
