import assert from 'node:assert/strict'
import { AppError } from '../src/errors.mjs'
import { RedemptionService } from '../src/redemption-service.mjs'
import { hashRedeemCode } from '../src/security.mjs'
import { UpstreamError } from '../src/sub2api-client.mjs'
import { databaseTest, silentLogger, temporaryDatabase, testConfig } from './helpers.mjs'

const user = {
  id: 101,
  email: 'user101@example.com',
  username: 'User 101',
}

async function createService(t, fulfill) {
  const config = testConfig()
  const database = await temporaryDatabase(t)
  const calls = []
  const sub2api = {
    async verifyUser() {
      return user
    },
    async fulfill(redemption) {
      calls.push({ ...redemption })
      return fulfill(redemption, calls.length)
    },
    async listGroups() {
      return [{ id: 8, status: 'active', subscription_type: 'subscription' }]
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

databaseTest('balance code fulfillment stores a successful redemption', async (t) => {
  const { service, calls } = await createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = await service.generateCodes({
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
  assert.match(calls[0].upstream_code, /^rp[0-9a-f]{30}$/)
  assert.equal(calls[0].upstream_code.length, 32)
})

databaseTest('subscription code fulfills the selected existing group and validity', async (t) => {
  const { service, calls } = await createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = await service.generateCodes({
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

databaseTest('subscription code generation rejects an unavailable or non-subscription group', async (t) => {
  const { service } = await createService(t, async (redemption) => successfulResult(redemption))

  await assert.rejects(
    service.generateCodes({
      count: 1,
      benefit_type: 'subscription',
      value: '299',
      group_id: 9,
      validity_days: 30,
    }, 'manager:test'),
    (error) => error instanceof AppError
      && error.status === 400
      && error.code === 'INVALID_SUBSCRIPTION_GROUP',
  )
})

databaseTest('product codes keep their benefit snapshot after the product changes', async (t) => {
  const { service, calls } = await createService(t, async (redemption) => successfulResult(redemption))
  const product = await service.createProduct({
    sku: 'BALANCE-100',
    name: '余额 100',
    description: '测试商品',
    price: '88',
    currency: 'CNY',
    benefit_type: 'balance',
    value: '100',
    purchase_url: 'https://store.example.com/balance-100',
    icon_url: 'https://cdn.example.com/balance-100.png',
    status: 'active',
    sort_order: 10,
  }, 'manager:test')
  const [generated] = await service.generateCodes({
    count: 1,
    product_id: product.id,
  }, 'manager:test')

  await service.updateProduct(product.id, {
    ...product,
    price: '188',
    value: '200',
  }, 'manager:test')
  const result = await service.redeem(generated.code, user)

  assert.equal(generated.product_id, product.id)
  assert.equal(product.icon_url, 'https://cdn.example.com/balance-100.png')
  assert.equal(result.product_name, '余额 100')
  assert.equal(result.value, '100')
  assert.equal(calls[0].value, '100')
})

databaseTest('draft products cannot issue codes and unsafe purchase URLs are rejected', async (t) => {
  const { service } = await createService(t, async (redemption) => successfulResult(redemption))
  await assert.rejects(
    service.createProduct({
      sku: 'BAD-LINK',
      name: '无效链接',
      price: '10',
      benefit_type: 'balance',
      value: '10',
      purchase_url: 'javascript:alert(1)',
    }, 'manager:test'),
    (error) => error instanceof AppError && error.code === 'INVALID_PURCHASE_URL',
  )

  await assert.rejects(
    service.createProduct({
      sku: 'BAD-ICON',
      name: '无效图标',
      price: '10',
      benefit_type: 'balance',
      value: '10',
      icon_url: 'data:image/svg+xml,unsafe',
    }, 'manager:test'),
    (error) => error instanceof AppError && error.code === 'INVALID_ICON_URL',
  )

  const product = await service.createProduct({
    sku: 'DRAFT-10',
    name: '草稿商品',
    price: '10',
    benefit_type: 'balance',
    value: '10',
    status: 'draft',
  }, 'manager:test')
  await assert.rejects(
    service.generateCodes({ count: 1, product_id: product.id }, 'manager:test'),
    (error) => error instanceof AppError && error.code === 'PRODUCT_NOT_ACTIVE',
  )
})

databaseTest('retry reuses the same upstream code and idempotency key', async (t) => {
  const { service, calls } = await createService(t, async (redemption, attempt) => {
    if (attempt === 1) {
      throw new UpstreamError('temporary outage', {
        httpStatus: 503,
        reason: 'UPSTREAM_UNAVAILABLE',
        retryable: true,
      })
    }
    return successfulResult(redemption)
  })
  const [generated] = await service.generateCodes({
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

databaseTest('a code claimed by one user is rejected for another user', async (t) => {
  const { service } = await createService(t, async (redemption) => successfulResult(redemption))
  const [generated] = await service.generateCodes({
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

databaseTest('an interrupted stale attempt cannot overwrite a later success', async (t) => {
  const { config, database, service } = await createService(
    t,
    async (redemption) => successfulResult(redemption),
  )
  const [generated] = await service.generateCodes({
    count: 1,
    benefit_type: 'balance',
    value: '10',
  }, 'manager:test')
  const claimed = await database.claimCode({
    codeHash: hashRedeemCode(generated.code, config.codePepper),
    user,
  })
  const first = await database.beginAttempt(claimed.redemption.id)
  await database.recoverInterrupted()
  const second = await database.beginAttempt(claimed.redemption.id)
  await database.completeAttemptSuccess(
    claimed.redemption.id,
    second.attempt,
    successfulResult(second.redemption),
  )
  await database.completeAttemptFailure(
    claimed.redemption.id,
    first.attempt,
    new UpstreamError('stale failure', { httpStatus: 503, retryable: true }),
    config.maxAttempts,
  )

  const result = await database.getRedemptionDetail(claimed.redemption.id)
  assert.equal(result.status, 'succeeded')
  assert.equal(result.retryable, false)
  assert.equal(result.attempts.find((attempt) => attempt.attempt_no === 1).reason, 'SERVICE_INTERRUPTED')
})
