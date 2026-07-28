import { fileURLToPath } from 'node:url'
import path from 'node:path'

function booleanValue(value, fallback = false) {
  if (value == null || value === '') return fallback
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase())
}

function integerValue(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (value == null || value === '') return fallback
  const parsed = Number.parseInt(value, 10)
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`invalid integer configuration: ${value}`)
  }
  return parsed
}

function requiredSecret(env, name, demoMode) {
  const value = String(env[name] || '')
  if (!demoMode && value.length < 32) {
    throw new Error(`${name} must contain at least 32 characters`)
  }
  return value || `demo-${name.toLowerCase()}-0123456789abcdef0123456789abcdef`
}

function normalizedBaseURL(value) {
  const url = new URL(value)
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('SUB2API_BASE_URL must use http or https')
  }
  return url.toString().replace(/\/+$/, '')
}

function frameAncestors(value) {
  const entries = String(value || "'self'")
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
  for (const entry of entries) {
    if (entry === "'self'" || entry === "'none'") continue
    const url = new URL(entry)
    if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/') {
      throw new Error(`invalid REDEEM_FRAME_ANCESTORS entry: ${entry}`)
    }
  }
  return entries.join(' ')
}

export function loadConfig(env = process.env) {
  const nodeEnv = String(env.NODE_ENV || 'development')
  const demoMode = booleanValue(env.REDEEM_DEMO_MODE)
  const managerAuthDisabled = booleanValue(env.REDEEM_MANAGER_AUTH_DISABLED)

  if (nodeEnv === 'production' && (demoMode || managerAuthDisabled)) {
    throw new Error('demo mode and disabled manager authentication are forbidden in production')
  }

  const adminApiKey = String(env.SUB2API_ADMIN_API_KEY || '').trim()
  const adminJWT = String(env.SUB2API_ADMIN_JWT || '').trim()
  const rawBaseURL = String(env.SUB2API_BASE_URL || '').trim()
  if (!demoMode && !rawBaseURL) throw new Error('SUB2API_BASE_URL is required')
  if (!demoMode && !adminApiKey && !adminJWT) {
    throw new Error('SUB2API_ADMIN_API_KEY or SUB2API_ADMIN_JWT is required')
  }

  const managerUsername = String(env.REDEEM_MANAGER_USERNAME || '').trim()
  const managerPassword = String(env.REDEEM_MANAGER_PASSWORD || '')
  if (!managerAuthDisabled && (!managerUsername || managerPassword.length < 12)) {
    throw new Error('manager username and a 12+ character password are required')
  }

  const moduleRoot = fileURLToPath(new URL('../', import.meta.url))
  const databasePath = path.resolve(
    String(env.REDEEM_DATABASE_PATH || path.join(moduleRoot, 'data', 'redeem-platform.db')),
  )

  return Object.freeze({
    nodeEnv,
    demoMode,
    host: String(env.REDEEM_HOST || '0.0.0.0'),
    port: integerValue(env.REDEEM_PORT, 8090, { min: 1, max: 65535 }),
    publicDir: path.join(moduleRoot, 'public'),
    migrationDir: path.join(moduleRoot, 'migrations'),
    databasePath,
    sub2apiBaseURL: rawBaseURL ? normalizedBaseURL(rawBaseURL) : 'http://demo.invalid',
    adminApiKey,
    adminJWT,
    codePepper: requiredSecret(env, 'REDEEM_CODE_PEPPER', demoMode),
    sessionSecret: requiredSecret(env, 'REDEEM_SESSION_SECRET', demoMode),
    sessionTTLSeconds: integerValue(env.REDEEM_SESSION_TTL_SECONDS, 900, {
      min: 60,
      max: 86400,
    }),
    managerUsername: managerUsername || 'demo-admin',
    managerPassword: managerPassword || 'demo-password-only',
    managerAuthDisabled,
    upstreamTimeoutMs: integerValue(env.REDEEM_UPSTREAM_TIMEOUT_MS, 15000, {
      min: 1000,
      max: 120000,
    }),
    retryIntervalMs: integerValue(env.REDEEM_RETRY_INTERVAL_MS, 30000, {
      min: 1000,
      max: 3600000,
    }),
    maxAttempts: integerValue(env.REDEEM_MAX_ATTEMPTS, 8, { min: 1, max: 50 }),
    trustProxy: booleanValue(env.REDEEM_TRUST_PROXY),
    frameAncestors: frameAncestors(env.REDEEM_FRAME_ANCESTORS),
  })
}
