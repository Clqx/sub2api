import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

describe('active quota capability API', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('uses the confirmed dedicated capability contract', async () => {
    vi.stubGlobal('localStorage', { getItem: () => 'session-token' })
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id:'cap-1' }), {
      status:200,
      headers:{ 'Content-Type':'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await api.setActiveQuotaRefresh('target-1', { enabled:true, confirm_side_effects:true })

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/targets/target-1/capabilities/quota.active_refresh',
      expect.objectContaining({
        method:'PUT',
        body:JSON.stringify({ enabled:true, confirm_side_effects:true }),
      }),
    )
  })
})
