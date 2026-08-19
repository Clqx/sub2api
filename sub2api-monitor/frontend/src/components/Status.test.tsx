import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Status } from './Status'

describe('Status', () => {
  it('keeps stale data distinct from a healthy value', () => {
    render(<Status value="stale" />)
    expect(screen.getByText('已过期').className).toContain('warn')
  })

  it('renders an unknown capability without inventing health', () => {
    render(<Status value="unknown" />)
    const status = screen.getByText('未知')
    expect(status.className).toContain('muted')
    expect(status.className).not.toContain('ok')
  })

  it('does not present an applied recovery as verified', () => {
    render(<Status value="applied" />)
    expect(screen.getByText('已应用，待复检').className).toContain('warn')
  })

  it('presents verification failure as an error', () => {
    render(<Status value="verification_failed" />)
    expect(screen.getByText('复检未通过').className).toContain('bad')
  })

  it('does not treat the legacy succeeded status as verified', () => {
    render(<Status value="legacy_succeeded" />)
    expect(screen.getByText('已调用（旧状态）').className).toContain('warn')
  })

  it('explains when execution is refused without a verifiable account version', () => {
    render(<Status value="skipped_unverifiable" />)
    expect(screen.getByText('缺少可验证的账号版本，未执行').className).toContain('muted')
  })
})
