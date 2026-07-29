import assert from 'node:assert/strict'
import test from 'node:test'
import { loadConfig } from '../src/config.mjs'
import { Sub2APIClient } from '../src/sub2api-client.mjs'

const productionEnvironment = {
  NODE_ENV: 'production',
  SUB2API_BASE_URL: 'https://sub2api.example.com/',
  REDEEM_CODE_PEPPER: 'code-pepper-0123456789abcdef0123456789abcdef',
  REDEEM_SESSION_SECRET: 'session-secret-0123456789abcdef0123456789abcdef',
  REDEEM_MANAGER_USERNAME: 'redeem-manager',
  REDEEM_MANAGER_PASSWORD: 'a-long-manager-password',
  REDEEM_DATABASE_HOST: 'postgres',
  REDEEM_DATABASE_USER: 'redeem_platform',
  REDEEM_DATABASE_PASSWORD: 'test-database-password',
  REDEEM_DATABASE_NAME: 'redeem_platform',
}

test('production configuration requires a server-side administrator credential', () => {
  assert.throws(
    () => loadConfig(productionEnvironment),
    /SUB2API_ADMIN_API_KEY or SUB2API_ADMIN_JWT is required/,
  )
})

test('API key is preferred and administrator credentials stay in request headers', () => {
  const config = loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_API_KEY: 'scoped-admin-api-key',
    SUB2API_ADMIN_JWT: 'administrator-jwt',
  })
  const client = new Sub2APIClient(config, async () => {
    throw new Error('not called')
  })
  const headers = client.adminHeaders('stable-idempotency-key')

  assert.equal(headers['x-api-key'], 'scoped-admin-api-key')
  assert.equal(headers.Authorization, undefined)
  assert.equal(headers['Idempotency-Key'], 'stable-idempotency-key')
  assert.equal(config.sub2apiBaseURL, 'https://sub2api.example.com')
  assert.equal(config.database.host, 'postgres')
  assert.equal(config.database.database, 'redeem_platform')
})

test('database TLS mode rejects unknown values', () => {
  assert.throws(() => loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_API_KEY: 'scoped-admin-api-key',
    REDEEM_DATABASE_SSLMODE: 'prefer',
  }), /invalid REDEEM_DATABASE_SSLMODE/)
})

test('administrator JWT is used only when an API key is absent', () => {
  const config = loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_JWT: 'administrator-jwt',
  })
  const client = new Sub2APIClient(config, async () => {
    throw new Error('not called')
  })
  const headers = client.adminHeaders()

  assert.equal(headers.Authorization, 'Bearer administrator-jwt')
  assert.equal(headers['x-api-key'], undefined)
})

test('embedding is limited to explicitly configured Sub2API origins', () => {
  const config = loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_API_KEY: 'scoped-admin-api-key',
    REDEEM_FRAME_ANCESTORS: "'self',https://sub2api.example.com",
  })
  assert.equal(config.frameAncestors, "'self' https://sub2api.example.com")
  assert.deepEqual(config.catalogOrigins, ['https://sub2api.example.com'])

  assert.throws(() => loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_API_KEY: 'scoped-admin-api-key',
    REDEEM_FRAME_ANCESTORS: 'https://sub2api.example.com/not-an-origin',
  }), /invalid REDEEM_FRAME_ANCESTORS/)
})

test('catalog origins can be configured separately from iframe origins', () => {
  const config = loadConfig({
    ...productionEnvironment,
    SUB2API_ADMIN_API_KEY: 'scoped-admin-api-key',
    REDEEM_FRAME_ANCESTORS: "'self',https://app.example.com",
    REDEEM_CATALOG_ORIGINS: 'https://www.example.com,http://127.0.0.1:18080',
  })
  assert.deepEqual(config.catalogOrigins, [
    'https://www.example.com',
    'http://127.0.0.1:18080',
  ])
})
