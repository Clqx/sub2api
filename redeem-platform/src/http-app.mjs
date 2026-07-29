import fs from 'node:fs'
import path from 'node:path'
import { AppError, asAppError } from './errors.mjs'
import {
  createSessionToken,
  parseManagerAuthorization,
  verifySessionToken,
} from './security.mjs'
import { UpstreamError } from './sub2api-client.mjs'

const STATIC_FILES = new Map([
  ['/assets/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/assets/user.js', ['user.js', 'text/javascript; charset=utf-8']],
  ['/assets/admin.js', ['admin.js', 'text/javascript; charset=utf-8']],
  ['/assets/logo.svg', ['logo.svg', 'image/svg+xml']],
])

function securityHeaders(config, isAPI = false) {
  return {
    'Cache-Control': isAPI ? 'no-store' : 'no-cache',
    'Content-Security-Policy': [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data: http: https:",
      "connect-src 'self'",
      "form-action 'self'",
      `frame-ancestors ${config.frameAncestors}`,
    ].join('; '),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  }
}

function send(res, status, headers, body = '') {
  res.writeHead(status, headers)
  res.end(body)
}

function sendJSON(res, config, status, data, message = 'success', extraHeaders = {}) {
  send(
    res,
    status,
    {
      ...securityHeaders(config, true),
      ...extraHeaders,
      'Content-Type': 'application/json; charset=utf-8',
    },
    JSON.stringify({ code: status < 400 ? 0 : status, message, data }),
  )
}

function catalogHeaders(req, config) {
  const origin = String(req.headers.origin || '').trim()
  if (!origin) return {}
  if (!config.catalogOrigins.includes(origin)) {
    throw new AppError(403, 'CATALOG_ORIGIN_FORBIDDEN', '当前来源不能读取商品目录')
  }
  return {
    'Access-Control-Allow-Origin': origin,
    Vary: 'Origin',
  }
}

function sendError(res, config, error) {
  const appError = asAppError(error)
  send(
    res,
    appError.status,
    {
      ...securityHeaders(config, true),
      'Content-Type': 'application/json; charset=utf-8',
    },
    JSON.stringify({
      code: appError.status,
      reason: appError.code,
      message: appError.message,
      ...(appError.details ? { metadata: appError.details } : {}),
    }),
  )
}

async function readJSON(req, maxBytes = 32768) {
  const contentType = String(req.headers['content-type'] || '').split(';')[0]
  if (contentType !== 'application/json') {
    throw new AppError(415, 'JSON_REQUIRED', '请求必须使用 application/json')
  }
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > maxBytes) throw new AppError(413, 'BODY_TOO_LARGE', '请求体过大')
    chunks.push(chunk)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
  } catch {
    throw new AppError(400, 'INVALID_JSON', 'JSON 格式无效')
  }
}

function bearerToken(req) {
  const header = String(req.headers.authorization || '')
  return header.startsWith('Bearer ') ? header.slice(7).trim() : ''
}

function authenticatedUser(req, config) {
  const token = bearerToken(req)
  if (!token) throw new AppError(401, 'SESSION_REQUIRED', '请重新进入兑换中心')
  try {
    return verifySessionToken(token, config.sessionSecret)
  } catch {
    throw new AppError(401, 'SESSION_EXPIRED', '兑换会话已过期，请重新进入')
  }
}

function requireManager(req, res, config, limiter) {
  if (config.managerAuthDisabled) return true
  if (parseManagerAuthorization(
    req.headers.authorization,
    config.managerUsername,
    config.managerPassword,
  )) {
    return true
  }
  const ip = clientIP(req, config)
  if (!limiter.check(`manager-auth:${ip}`, 10, 60000)) {
    send(res, 429, {
      ...securityHeaders(config, true),
      'Content-Type': 'application/json; charset=utf-8',
      'Retry-After': '60',
    }, JSON.stringify({
      code: 429,
      reason: 'MANAGER_AUTH_RATE_LIMITED',
      message: '管理员身份验证请求过于频繁',
    }))
    return false
  }
  send(res, 401, {
    ...securityHeaders(config, true),
    'Content-Type': 'application/json; charset=utf-8',
    'WWW-Authenticate': 'Basic realm="Redeem Platform", charset="UTF-8"',
  }, JSON.stringify({
    code: 401,
    reason: 'MANAGER_AUTH_REQUIRED',
    message: '管理员身份验证失败',
  }))
  return false
}

function clientIP(req, config) {
  if (config.trustProxy) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    if (forwarded) return forwarded
  }
  return req.socket.remoteAddress || 'unknown'
}

class FixedWindowLimiter {
  constructor() {
    this.entries = new Map()
  }

  check(key, limit, windowMs) {
    const now = Date.now()
    const existing = this.entries.get(key)
    if (!existing || existing.resetAt <= now) {
      this.entries.set(key, { count: 1, resetAt: now + windowMs })
      return true
    }
    if (existing.count >= limit) return false
    existing.count += 1
    if (this.entries.size > 10000) {
      for (const [entryKey, value] of this.entries) {
        if (value.resetAt <= now) this.entries.delete(entryKey)
      }
    }
    return true
  }
}

function queryFilters(url) {
  const filters = {
    status: url.searchParams.get('status') || '',
    type: url.searchParams.get('type') || '',
    search: url.searchParams.get('search') || '',
    page: url.searchParams.get('page') || '1',
    pageSize: url.searchParams.get('page_size') || '25',
  }
  const from = url.searchParams.get('from')
  const to = url.searchParams.get('to')
  if (from) {
    const date = new Date(`${from}T00:00:00.000Z`)
    if (Number.isFinite(date.getTime())) filters.from = date.toISOString()
  }
  if (to) {
    const date = new Date(`${to}T00:00:00.000Z`)
    if (Number.isFinite(date.getTime())) {
      date.setUTCDate(date.getUTCDate() + 1)
      filters.to = date.toISOString()
    }
  }
  return filters
}

function csvCell(value) {
  let text = String(value ?? '')
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text
}

async function redemptionsCSV(database, filters) {
  const columns = [
    'id',
    'created_at',
    'completed_at',
    'status',
    'user_id',
    'user_email',
    'benefit_type',
    'product_sku',
    'product_name',
    'value',
    'group_id',
    'validity_days',
    'campaign',
    'code_mask',
    'attempt_count',
    'upstream_reason',
    'last_error',
  ]
  const rows = [columns.join(',')]
  let page = 1
  let exported = 0
  while (exported < 10000) {
    const result = await database.listRedemptions({
      ...filters,
      page,
      pageSize: 100,
    })
    for (const item of result.items) {
      rows.push(columns.map((column) => csvCell(item[column])).join(','))
      exported += 1
      if (exported >= 10000) break
    }
    if (page >= result.pages || !result.items.length) break
    page += 1
  }
  return `${rows.join('\r\n')}\r\n`
}

export function createHTTPHandler({ config, database, service, sub2api, logger = console }) {
  const limiter = new FixedWindowLimiter()

  return async function handler(req, res) {
    const started = Date.now()
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
    const method = req.method || 'GET'
    try {
      if (method === 'GET' && url.pathname === '/health') {
        await database.health()
        return sendJSON(res, config, 200, {
          status: 'ok',
          demo_mode: config.demoMode,
          database: 'ready',
        })
      }

      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const body = fs.readFileSync(path.join(config.publicDir, 'index.html'))
        return send(res, 200, {
          ...securityHeaders(config),
          'Content-Type': 'text/html; charset=utf-8',
        }, body)
      }

      if (method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
        if (!requireManager(req, res, config, limiter)) return
        const body = fs.readFileSync(path.join(config.publicDir, 'admin.html'))
        return send(res, 200, {
          ...securityHeaders(config),
          'Content-Type': 'text/html; charset=utf-8',
        }, body)
      }

      if (method === 'GET' && STATIC_FILES.has(url.pathname)) {
        const [file, contentType] = STATIC_FILES.get(url.pathname)
        const body = fs.readFileSync(path.join(config.publicDir, file))
        return send(res, 200, {
          ...securityHeaders(config),
          'Content-Type': contentType,
        }, body)
      }

      if (method === 'POST' && url.pathname === '/api/session/exchange') {
        const ip = clientIP(req, config)
        if (!limiter.check(`exchange:${ip}`, 20, 60000)) {
          throw new AppError(429, 'RATE_LIMITED', '身份验证请求过于频繁')
        }
        const body = await readJSON(req)
        const user = await service.exchangeUserToken(body.token, body.user_id)
        const sessionToken = createSessionToken(
          user,
          config.sessionSecret,
          config.sessionTTLSeconds,
        )
        return sendJSON(res, config, 200, {
          session_token: sessionToken,
          expires_in: config.sessionTTLSeconds,
          user,
        })
      }

      if (method === 'GET' && url.pathname === '/api/me') {
        const user = authenticatedUser(req, config)
        return sendJSON(res, config, 200, user)
      }

      if (method === 'GET' && url.pathname === '/api/public/products') {
        const headers = catalogHeaders(req, config)
        return sendJSON(
          res,
          config,
          200,
          await database.listProducts({ publicOnly: true }),
          'success',
          headers,
        )
      }

      if (method === 'GET' && url.pathname === '/api/products') {
        authenticatedUser(req, config)
        return sendJSON(res, config, 200, await database.listProducts({ publicOnly: true }))
      }

      if (method === 'POST' && url.pathname === '/api/redeem') {
        const user = authenticatedUser(req, config)
        const ip = clientIP(req, config)
        if (!limiter.check(`redeem:${ip}:${user.id}`, 10, 60000)) {
          throw new AppError(429, 'RATE_LIMITED', '兑换请求过于频繁，请稍后再试')
        }
        const body = await readJSON(req)
        const redemption = await service.redeem(body.code, user)
        return sendJSON(
          res,
          config,
          redemption.status === 'succeeded' ? 200 : 202,
          redemption,
          redemption.status === 'succeeded' ? '兑换成功' : '兑换处理中',
        )
      }

      if (method === 'GET' && url.pathname === '/api/my-redemptions') {
        const user = authenticatedUser(req, config)
        return sendJSON(res, config, 200, await database.listUserRedemptions(
          user.id,
          url.searchParams.get('page'),
          url.searchParams.get('page_size'),
        ))
      }

      if (url.pathname.startsWith('/api/admin/')) {
        if (!requireManager(req, res, config, limiter)) return
        const actor = `manager:${config.managerUsername}`

        if (method === 'GET' && url.pathname === '/api/admin/analytics') {
          return sendJSON(res, config, 200, await database.analytics(queryFilters(url)))
        }
        if (method === 'GET' && url.pathname === '/api/admin/products') {
          return sendJSON(res, config, 200, await database.listProducts())
        }
        if (method === 'POST' && url.pathname === '/api/admin/products') {
          const body = await readJSON(req)
          return sendJSON(res, config, 201, await service.createProduct(body, actor), '商品已创建')
        }
        const productMatch = /^\/api\/admin\/products\/([0-9a-f-]+)$/.exec(url.pathname)
        if (method === 'PUT' && productMatch) {
          const body = await readJSON(req)
          return sendJSON(res, config, 200, await service.updateProduct(productMatch[1], body, actor), '商品已更新')
        }
        if (method === 'GET' && url.pathname === '/api/admin/redemptions') {
          return sendJSON(res, config, 200, await database.listRedemptions(queryFilters(url)))
        }
        const redemptionMatch = /^\/api\/admin\/redemptions\/([0-9a-f-]+)$/.exec(url.pathname)
        if (method === 'GET' && redemptionMatch) {
          const detail = await database.getRedemptionDetail(redemptionMatch[1])
          if (!detail) throw new AppError(404, 'REDEMPTION_NOT_FOUND', '兑换记录不存在')
          return sendJSON(res, config, 200, detail)
        }
        const retryMatch = /^\/api\/admin\/redemptions\/([0-9a-f-]+)\/retry$/.exec(url.pathname)
        if (method === 'POST' && retryMatch) {
          await readJSON(req)
          return sendJSON(res, config, 200, await service.retry(retryMatch[1], actor))
        }
        if (method === 'GET' && url.pathname === '/api/admin/codes') {
          return sendJSON(res, config, 200, await database.listCodes({
            status: url.searchParams.get('status') || '',
            type: url.searchParams.get('type') || '',
            search: url.searchParams.get('search') || '',
            page: url.searchParams.get('page') || '1',
            pageSize: url.searchParams.get('page_size') || '20',
          }))
        }
        if (method === 'POST' && url.pathname === '/api/admin/codes/generate') {
          const body = await readJSON(req)
          return sendJSON(res, config, 201, await service.generateCodes(body, actor), '兑换码已生成')
        }
        const disableMatch = /^\/api\/admin\/codes\/([0-9a-f-]+)\/disable$/.exec(url.pathname)
        if (method === 'POST' && disableMatch) {
          await readJSON(req)
          const result = await database.disableCode(disableMatch[1], actor)
          if (result.kind === 'not_found') {
            throw new AppError(404, 'CODE_NOT_FOUND', '兑换码不存在')
          }
          if (result.kind === 'conflict') {
            throw new AppError(409, 'CODE_STATE_CONFLICT', '当前状态不能停用')
          }
          return sendJSON(res, config, 200, result.code)
        }
        if (method === 'GET' && url.pathname === '/api/admin/groups') {
          try {
            return sendJSON(res, config, 200, await sub2api.listGroups())
          } catch (error) {
            if (error instanceof UpstreamError) {
              throw new AppError(502, error.reason || 'UPSTREAM_GROUPS_FAILED', error.message)
            }
            throw error
          }
        }
        if (method === 'GET' && url.pathname === '/api/admin/audit') {
          return sendJSON(
            res,
            config,
            200,
            await database.auditEvents(url.searchParams.get('limit')),
          )
        }
        if (method === 'GET' && url.pathname === '/api/admin/export.csv') {
          const csv = await redemptionsCSV(database, queryFilters(url))
          return send(res, 200, {
            ...securityHeaders(config, true),
            'Content-Disposition': 'attachment; filename="redemptions.csv"',
            'Content-Type': 'text/csv; charset=utf-8',
          }, `\uFEFF${csv}`)
        }
      }

      throw new AppError(404, 'NOT_FOUND', '接口不存在')
    } catch (error) {
      if (!(error instanceof AppError)) {
        logger.error?.(JSON.stringify({
          event: 'http_request_failed',
          method,
          path: url.pathname,
          message: error?.message || 'unknown error',
        }))
      }
      sendError(res, config, error)
    } finally {
      logger.info?.(JSON.stringify({
        event: 'http_request',
        method,
        path: url.pathname,
        status: res.statusCode,
        duration_ms: Date.now() - started,
      }))
    }
  }
}
