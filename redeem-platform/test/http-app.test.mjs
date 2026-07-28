import assert from 'node:assert/strict'
import http from 'node:http'
import test from 'node:test'
import { createHTTPHandler } from '../src/http-app.mjs'
import { RedemptionService } from '../src/redemption-service.mjs'
import { DemoSub2APIClient } from '../src/sub2api-client.mjs'
import { silentLogger, temporaryDatabase, testConfig } from './helpers.mjs'

async function jsonRequest(baseURL, path, options = {}) {
  const response = await fetch(`${baseURL}${path}`, options)
  const body = await response.json()
  return { response, body }
}

test('HTTP flow exchanges identity, generates, redeems, and lists records', async (t) => {
  const config = testConfig()
  const database = temporaryDatabase(t)
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

  const generated = await jsonRequest(baseURL, '/api/admin/codes/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      count: 1,
      benefit_type: 'subscription',
      value: '199',
      group_id: 8,
      validity_days: 30,
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

  const history = await jsonRequest(baseURL, '/api/my-redemptions', {
    headers: { Authorization: authorization.Authorization },
  })
  assert.equal(history.body.data.total, 1)
  assert.equal(history.body.data.items[0].campaign, '=http-test')

  const records = await jsonRequest(baseURL, '/api/admin/redemptions?search=7001')
  assert.equal(records.body.data.total, 1)

  const analytics = await jsonRequest(baseURL, '/api/admin/analytics')
  assert.equal(analytics.body.data.succeeded, 1)
  assert.equal(analytics.body.data.subscription_days, 30)

  const exported = await fetch(`${baseURL}/api/admin/export.csv`)
  assert.equal(exported.status, 200)
  assert.match(await exported.text(), /'=http-test/)
})
