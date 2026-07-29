import assert from 'node:assert/strict'
import http from 'node:http'
import test from 'node:test'
import { createHTTPHandler } from '../src/http-app.mjs'
import { RedemptionService } from '../src/redemption-service.mjs'
import { DemoSub2APIClient } from '../src/sub2api-client.mjs'
import { databaseTest, silentLogger, temporaryDatabase, testConfig } from './helpers.mjs'

async function jsonRequest(baseURL, path, options = {}) {
  const response = await fetch(`${baseURL}${path}`, options)
  const body = await response.json()
  return { response, body }
}

test('manager authentication failures are rate limited per client', async (t) => {
  const config = testConfig({
    managerAuthDisabled: false,
    managerUsername: 'manager',
    managerPassword: 'manager-password',
  })
  const server = http.createServer(createHTTPHandler({
    config,
    database: {},
    service: {},
    sub2api: {},
    logger: silentLogger,
  }))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => server.close(resolve)))
  const address = server.address()
  const baseURL = `http://127.0.0.1:${address.port}`
  const invalidAuthorization = `Basic ${Buffer.from('manager:wrong-password').toString('base64')}`

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const response = await fetch(`${baseURL}/admin`, {
      headers: { Authorization: invalidAuthorization },
    })
    assert.equal(response.status, 401)
  }
  const limited = await fetch(`${baseURL}/admin`, {
    headers: { Authorization: invalidAuthorization },
  })
  assert.equal(limited.status, 429)
  assert.equal(limited.headers.get('retry-after'), '60')

  const valid = await fetch(`${baseURL}/admin`, {
    headers: {
      Authorization: `Basic ${Buffer.from('manager:manager-password').toString('base64')}`,
    },
  })
  assert.equal(valid.status, 200)
})

databaseTest('HTTP flow exchanges identity, generates, redeems, and lists records', async (t) => {
  const config = testConfig()
  const database = await temporaryDatabase(t)
  const sub2api = new DemoSub2APIClient()
  const service = new RedemptionService({
    config,
    database,
    sub2api,
    logger: silentLogger,
  })
  const server = http.createServer(createHTTPHandler({
    config,
    database,
    service,
    sub2api,
    logger: silentLogger,
  }))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => server.close(resolve)))
  const address = server.address()
  const baseURL = `http://127.0.0.1:${address.port}`

  const health = await jsonRequest(baseURL, '/health')
  assert.equal(health.response.status, 200)
  assert.equal(health.body.data.status, 'ok')

  const page = await fetch(`${baseURL}/`)
  assert.equal(page.status, 200)
  assert.match(await page.text(), /兑换中心/)

  const exchange = await jsonRequest(baseURL, '/api/session/exchange', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'demo-user-7001', user_id: 7001 }),
  })
  assert.equal(exchange.response.status, 200)
  assert.equal(exchange.body.data.user.id, 7001)
  const authorization = {
    Authorization: `Bearer ${exchange.body.data.session_token}`,
    'Content-Type': 'application/json',
  }

  const createdProduct = await jsonRequest(baseURL, '/api/admin/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sku: 'SUB-30',
      name: '30 天订阅',
      description: '标准订阅商品',
      price: '149',
      currency: 'CNY',
      benefit_type: 'subscription',
      value: '199',
      group_id: 8,
      validity_days: 30,
      purchase_url: 'https://store.example.com/sub-30',
      icon_url: 'https://cdn.example.com/sub-30.png',
      status: 'active',
      sort_order: 1,
    }),
  })
  assert.equal(createdProduct.response.status, 201)
  assert.equal(createdProduct.body.data.sku, 'SUB-30')

  const catalog = await jsonRequest(baseURL, '/api/products', {
    headers: { Authorization: authorization.Authorization },
  })
  assert.equal(catalog.response.status, 200)
  assert.equal(catalog.body.data.length, 1)
  assert.equal(catalog.body.data[0].price, '149')
  assert.equal(catalog.body.data[0].icon_url, 'https://cdn.example.com/sub-30.png')
  assert.equal(catalog.body.data[0].created_by, undefined)
  assert.equal(catalog.body.data[0].status, undefined)

  const publicCatalog = await jsonRequest(baseURL, '/api/public/products', {
    headers: { Origin: 'http://sub2api.example.test' },
  })
  assert.equal(publicCatalog.response.status, 200)
  assert.equal(
    publicCatalog.response.headers.get('access-control-allow-origin'),
    'http://sub2api.example.test',
  )
  assert.equal(publicCatalog.body.data[0].sku, 'SUB-30')

  const forbiddenCatalog = await jsonRequest(baseURL, '/api/public/products', {
    headers: { Origin: 'https://attacker.example.test' },
  })
  assert.equal(forbiddenCatalog.response.status, 403)
  assert.equal(forbiddenCatalog.body.reason, 'CATALOG_ORIGIN_FORBIDDEN')

  const generated = await jsonRequest(baseURL, '/api/admin/codes/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      count: 1,
      product_id: createdProduct.body.data.id,
      campaign: '=http-test',
    }),
  })
  assert.equal(generated.response.status, 201)
  assert.equal(generated.body.data.length, 1)

  const redeemed = await jsonRequest(baseURL, '/api/redeem', {
    method: 'POST',
    headers: authorization,
    body: JSON.stringify({ code: generated.body.data[0].code }),
  })
  assert.equal(redeemed.response.status, 200)
  assert.equal(redeemed.body.data.status, 'succeeded')
  assert.equal(redeemed.body.data.user_id, 7001)
  assert.equal(redeemed.body.data.product_name, '30 天订阅')

  const history = await jsonRequest(baseURL, '/api/my-redemptions', {
    headers: { Authorization: authorization.Authorization },
  })
  assert.equal(history.body.data.total, 1)
  assert.equal(history.body.data.items[0].campaign, '=http-test')
  assert.equal(history.body.data.items[0].product_sku, 'SUB-30')

  const records = await jsonRequest(baseURL, '/api/admin/redemptions?search=7001')
  assert.equal(records.body.data.total, 1)

  const analytics = await jsonRequest(baseURL, '/api/admin/analytics')
  assert.equal(analytics.body.data.succeeded, 1)
  assert.equal(analytics.body.data.subscription_days, 30)

  const exported = await fetch(`${baseURL}/api/admin/export.csv`)
  assert.equal(exported.status, 200)
  assert.match(await exported.text(), /'=http-test/)
})
