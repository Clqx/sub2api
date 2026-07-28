import {
  createHash,
  createHmac,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto'

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
const AMOUNT_SCALE = 1_000_000

function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left))
  const b = Buffer.from(String(right))
  if (a.length !== b.length) {
    timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest())
    return false
  }
  return timingSafeEqual(a, b)
}

export function parseManagerAuthorization(header, username, password) {
  if (!header?.startsWith('Basic ')) return false
  let decoded
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8')
  } catch {
    return false
  }
  const separator = decoded.indexOf(':')
  if (separator < 0) return false
  return constantTimeEqual(decoded.slice(0, separator), username)
    && constantTimeEqual(decoded.slice(separator + 1), password)
}

export function normalizeRedeemCode(input) {
  const normalized = String(input || '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '')
  if (!/^[A-Z2-9]{8,64}$/.test(normalized)) {
    throw new Error('INVALID_REDEEM_CODE')
  }
  return normalized
}

export function hashRedeemCode(input, pepper) {
  return createHmac('sha256', pepper).update(normalizeRedeemCode(input)).digest('hex')
}

export function generateRedeemCode() {
  let raw = ''
  for (let i = 0; i < 12; i += 1) {
    raw += CODE_ALPHABET[randomInt(0, CODE_ALPHABET.length)]
  }
  return `S2-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`
}

export function maskRedeemCode(input) {
  const normalized = normalizeRedeemCode(input)
  return `${normalized.slice(0, 4)}••••${normalized.slice(-4)}`
}

export function parseAmountMicros(value, { allowNegative = true } = {}) {
  const text = String(value ?? '').trim()
  const match = /^(-?)(\d{1,9})(?:\.(\d{1,6}))?$/.exec(text)
  if (!match) throw new Error('INVALID_AMOUNT')
  const sign = match[1] === '-' ? -1 : 1
  if (sign < 0 && !allowNegative) throw new Error('NEGATIVE_AMOUNT_NOT_ALLOWED')
  const fraction = (match[3] || '').padEnd(6, '0')
  const micros = sign * (Number(match[2]) * AMOUNT_SCALE + Number(fraction))
  if (!Number.isSafeInteger(micros) || micros === 0) throw new Error('INVALID_AMOUNT')
  return micros
}

export function formatAmountMicros(micros) {
  const value = Number(micros)
  if (!Number.isSafeInteger(value)) throw new Error('INVALID_STORED_AMOUNT')
  const sign = value < 0 ? '-' : ''
  const absolute = Math.abs(value)
  const whole = Math.floor(absolute / AMOUNT_SCALE)
  const fraction = String(absolute % AMOUNT_SCALE).padStart(6, '0').replace(/0+$/, '')
  return `${sign}${whole}${fraction ? `.${fraction}` : ''}`
}

function base64urlJSON(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

export function createSessionToken(user, secret, ttlSeconds, now = Date.now()) {
  const issuedAt = Math.floor(now / 1000)
  const payload = {
    iss: 'sub2api-redeem-platform',
    aud: 'redeem-user',
    sub: String(user.id),
    email: String(user.email || ''),
    username: String(user.username || ''),
    iat: issuedAt,
    exp: issuedAt + ttlSeconds,
    jti: randomUUID(),
  }
  const encoded = base64urlJSON(payload)
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url')
  return `${encoded}.${signature}`
}

export function verifySessionToken(token, secret, now = Date.now()) {
  const [encoded, signature, extra] = String(token || '').split('.')
  if (!encoded || !signature || extra) throw new Error('INVALID_SESSION')
  const expected = createHmac('sha256', secret).update(encoded).digest('base64url')
  if (!constantTimeEqual(signature, expected)) throw new Error('INVALID_SESSION')

  let payload
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
  } catch {
    throw new Error('INVALID_SESSION')
  }
  if (
    payload?.iss !== 'sub2api-redeem-platform'
    || payload?.aud !== 'redeem-user'
    || !/^\d+$/.test(payload?.sub || '')
    || !Number.isInteger(payload?.exp)
    || payload.exp <= Math.floor(now / 1000)
  ) {
    throw new Error('INVALID_SESSION')
  }
  return {
    id: Number(payload.sub),
    email: String(payload.email || ''),
    username: String(payload.username || ''),
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  }
}

export function randomID() {
  return randomUUID()
}
