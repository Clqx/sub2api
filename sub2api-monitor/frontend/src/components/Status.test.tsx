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
})
