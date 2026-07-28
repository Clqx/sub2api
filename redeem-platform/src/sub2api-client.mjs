export class UpstreamError extends Error {
  constructor(message, {
    httpStatus = 0,
    reason = '',
    response = null,
    retryable = false,
    latencyMs = 0,
  } = {}) {
    super(message)
    this.name = 'UpstreamError'
    this.httpStatus = httpStatus
    this.reason = reason
    this.response = response
    this.retryable = retryable
    this.latencyMs = latencyMs
  }
}

function responseReason(body) {
  return String(body?.reason || body?.code || '')
}

function isRetryable(status, reason) {
  if (!status || status >= 500 || status === 408 || status === 429) return true
  return status === 409 && [
    'IDEMPOTENCY_IN_PROGRESS',
    'IDEMPOTENCY_RETRY_BACKOFF',
  ].includes(reason)
}

async function readResponse(response) {
  const text = await response.text()
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    return { message: text.slice(0, 1000) }
  }
}

export class Sub2APIClient {
  constructor(config, fetchImpl = globalThis.fetch) {
    this.baseURL = config.sub2apiBaseURL
    this.adminApiKey = config.adminApiKey
    this.adminJWT = config.adminJWT
    this.timeoutMs = config.upstreamTimeoutMs
    this.fetch = fetchImpl
  }

  adminHeaders(idempotencyKey = '') {
    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    }
    if (this.adminApiKey) headers['x-api-key'] = this.adminApiKey
    else headers.Authorization = `Bearer ${this.adminJWT}`
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey
    return headers
  }

  async verifyUser(accessToken) {
    const started = Date.now()
    let response
    try {
      response = await this.fetch(`${this.baseURL}/api/v1/auth/me`, {
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (error) {
      throw new UpstreamError('无法连接 Sub2API 验证用户', {
        retryable: true,
        latencyMs: Date.now() - started,
        response: { cause: error?.name || 'network_error' },
      })
    }
    const body = await readResponse(response)
    if (!response.ok || body?.code !== 0 || !body?.data?.id) {
      const reason = responseReason(body)
      throw new UpstreamError('用户登录状态无效或已过期', {
        httpStatus: response.status,
        reason,
        response: body,
        retryable: isRetryable(response.status, reason),
        latencyMs: Date.now() - started,
      })
    }
    return {
      id: Number(body.data.id),
      email: String(body.data.email || ''),
      username: String(body.data.username || ''),
    }
  }

  async fulfill(redemption) {
    const body = {
      code: redemption.upstream_code,
      type: redemption.benefit_type,
      value: Number(redemption.value),
      user_id: Number(redemption.user_id),
      notes: `redeem-platform:${redemption.id}`,
    }
    if (redemption.benefit_type === 'subscription') {
      body.group_id = Number(redemption.group_id)
      body.validity_days = Number(redemption.validity_days)
    }

    const started = Date.now()
    let response
    try {
      response = await this.fetch(
        `${this.baseURL}/api/v1/admin/redeem-codes/create-and-redeem`,
        {
          method: 'POST',
          headers: this.adminHeaders(redemption.idempotency_key),
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      )
    } catch (error) {
      throw new UpstreamError('Sub2API 履约请求失败', {
        retryable: true,
        latencyMs: Date.now() - started,
        response: { cause: error?.name || 'network_error' },
      })
    }

    const responseBody = await readResponse(response)
    const reason = responseReason(responseBody)
    const latencyMs = Date.now() - started
    if (!response.ok || responseBody?.code !== 0) {
      throw new UpstreamError(
        String(responseBody?.message || 'Sub2API 拒绝了履约请求'),
        {
          httpStatus: response.status,
          reason,
          response: responseBody,
          retryable: isRetryable(response.status, reason),
          latencyMs,
        },
      )
    }
    return {
      httpStatus: response.status,
      reason,
      data: responseBody.data || {},
      latencyMs,
      request: body,
    }
  }

  async listGroups() {
    const response = await this.fetch(`${this.baseURL}/api/v1/admin/groups/all`, {
      headers: this.adminHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    })
    const body = await readResponse(response)
    if (!response.ok || body?.code !== 0 || !Array.isArray(body?.data)) {
      const reason = responseReason(body)
      throw new UpstreamError('无法读取 Sub2API 分组', {
        httpStatus: response.status,
        reason,
        response: body,
        retryable: isRetryable(response.status, reason),
      })
    }
    return body.data
  }
}

export class DemoSub2APIClient {
  async verifyUser(accessToken) {
    const match = /(?:demo-user-|user-)?(\d+)/.exec(String(accessToken))
    const id = Number(match?.[1] || 10001)
    return {
      id,
      email: `demo${id}@example.com`,
      username: `演示用户 ${id}`,
    }
  }

  async fulfill(redemption) {
    await new Promise((resolve) => setTimeout(resolve, 180))
    return {
      httpStatus: 200,
      reason: '',
      latencyMs: 180,
      data: {
        redeem_code: {
          code: redemption.upstream_code,
          type: redemption.benefit_type,
          used_by: redemption.user_id,
          status: 'used',
        },
      },
    }
  }

  async listGroups() {
    return [
      {
        id: 8,
        name: 'Coding Pro 月度订阅',
        platform: 'openai',
        status: 'active',
        subscription_type: 'subscription',
        daily_limit_usd: 20,
        monthly_limit_usd: 300,
      },
      {
        id: 12,
        name: 'Claude Team 月度订阅',
        platform: 'anthropic',
        status: 'active',
        subscription_type: 'subscription',
        daily_limit_usd: 30,
        monthly_limit_usd: 450,
      },
    ]
  }
}
