import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createSessionToken,
  hashRedeemCode,
  normalizeRedeemCode,
  verifySessionToken,
} from '../src/security.mjs'

const secret = 'session-test-secret-0123456789abcdef0123456789abcdef'

test('session tokens verify and reject tampering or expiration', () => {
  const now = Date.UTC(2026, 6, 28, 8, 0, 0)
  const token = createSessionToken({
    id: 42,
    email: 'user@example.com',
    username: 'Test User',
  }, secret, 300, now)

  assert.deepEqual(verifySessionToken(token, secret, now + 1000), {
    id: 42,
    email: 'user@example.com',
    username: 'Test User',
    expiresAt: new Date(now + 300000).toISOString(),
  })

  const [payload, signature] = token.split('.')
  assert.throws(() => verifySessionToken(`${payload}x.${signature}`, secret, now))
  assert.throws(() => verifySessionToken(token, secret, now + 300000))
})

test('code normalization makes formatting equivalent before hashing', () => {
  const pepper = 'code-test-pepper-0123456789abcdef0123456789abcdef'
  assert.equal(normalizeRedeemCode(' s2-abcd efgh-2345 '), 'S2ABCDEFGH2345')
  assert.equal(
    hashRedeemCode('S2-ABCD-EFGH-2345', pepper),
    hashRedeemCode(' s2 abcd efgh 2345 ', pepper),
  )
  assert.throws(() => normalizeRedeemCode('short'))
  assert.throws(() => normalizeRedeemCode('S2-ABCD-IO01-2345'))
})
