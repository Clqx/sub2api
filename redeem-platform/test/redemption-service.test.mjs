import assert from 'node:assert/strict'
import test from 'node:test'
import { AppError } from '../src/errors.mjs'
import { RedemptionService } from '../src/redemption-service.mjs'
import { UpstreamError } from '../src/sub2api-client.mjs'
import { silentLogger, temporaryDatabase, testConfig } from './helpers.mjs'

const user = {
  id: 101,
  email: 'user101@example.com',
  username: 'User 101',
}

function createService(t, fulfill) {
  const config = testConfig()
  const database = temporaryDatabase(t)
  const calls = []
  const sub2api = {
    async verifyUser() {
      return user
    },
    async fulfill(redemption) {
      calls.push({ ...redemption })
      return fulfill(redemption, calls.length)
    },
  }
  return {
    config,
    database,
    calls,
    service: new RedemptionService({
      config,
      database,
      sub2api,
      logger: silentLogger,
    }),
  }
}

function successfulResult(redemption) {
  return {
    httpStatus: 200,
    reason: '',
    latencyMs: 12,
    data: { code: redemption.upstream_code },
  }
}

test('balance code fulfillment stores a successful redemption', async (t) => {
  const { service, calls } = createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = service.generateCodes({
    count: 1,
    benefit_type: 'balance',
    value: '125.50',
    campaign: 'balance-test',
  }, 'manager:test')

  const result = await service.redeem(generated.code, user)
  assert.equal(result.status, 'succeeded')
  assert.equal(result.value, '125.5')
  assert.equal(result.benefit_type, 'balance')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].user_id, user.id)
  assert.match(calls[0].idempotency_key, /^rp-/)
})

test('subscription code fulfills the selected existing group and validity', async (t) => {
  const { service, calls } = createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = service.generateCodes({
    count: 1,
    benefit_type: 'subscription',
    value: '299',
    group_id: 8,
    validity_days: 45,
    campaign: 'renewal-test',
  }, 'manager:test')

  const result = await service.redeem(generated.code, user)
  assert.equal(result.status, 'succeeded')
  assert.equal(result.group_id, 8)
  assert.equal(result.validity_days, 45)
  assert.equal(calls[0].group_id, 8)
  assert.equal(calls[0].validity_days, 45)
})

test('retry reuses the same upstream code and idempotency key', async (t) => {
  const { service, calls } = createService(t, async (redemption, attempt) => {
    if (attempt === 1) {
      throw new UpstreamError('temporary outage', {
        httpStatus: 503,
        reason: 'UPSTREAM_UNAVAILABLE',
        retryable: true,
      })
    }
    return successfulResult(redemption)
  })
  const [generated] = service.generateCodes({
    count: 1,
    benefit_type: 'balance',
    value: '50',
  }, 'manager:test')

  const first = await service.redeem(generated.code, user)
  assert.equal(first.status, 'retryable')
  const second = await service.retry(first.id, 'manager:test')
  assert.equal(second.status, 'succeeded')
  assert.equal(calls.length, 2)
  assert.equal(calls[0].upstream_code, calls[1].upstream_code)
  assert.equal(calls[0].idempotency_key, calls[1].idempotency_key)
  assert.equal(second.attempt_count, 2)
})

test('a code claimed by one user is rejected for another user', async (t) => {
  const { service } = createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = service.generateCodes({
    count: 1,
    benefit_type: 'balance',
    value: '10',
  }, 'manager:test')
  await service.redeem(generated.code, user)

  await assert.rejects(
    service.redeem(generated.code, {
      id: 202,
      email: 'other@example.com',
      username: 'Other',
    }),
    (error) => error instanceof AppError
      && error.status === 409
      && error.code === 'CODE_ALREADY_USED',
  )
})
