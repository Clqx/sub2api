import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import test from 'node:test'
import pg from 'pg'
import { RedeemDatabase } from '../src/database.mjs'

const { Pool } = pg

const projectRoot = fileURLToPath(new URL('../', import.meta.url))

export function testConfig(overrides = {}) {
  return {
    nodeEnv: 'test',
    demoMode: true,
    host: '127.0.0.1',
    port: 0,
    publicDir: path.join(projectRoot, 'public'),
    migrationDir: path.join(projectRoot, 'migrations'),
    database: {},
    sub2apiBaseURL: 'http://demo.invalid',
    adminApiKey: '',
    adminJWT: '',
    codePepper: 'test-code-pepper-0123456789abcdef0123456789abcdef',
    sessionSecret: 'test-session-secret-0123456789abcdef0123456789abcdef',
    sessionTTLSeconds: 900,
    managerUsername: 'manager',
    managerPassword: 'manager-password',
    managerAuthDisabled: true,
    upstreamTimeoutMs: 1000,
    retryIntervalMs: 1000,
    maxAttempts: 3,
    trustProxy: false,
    frameAncestors: "'self'",
    ...overrides,
  }
}

export function databaseTest(name, fn) {
  return test(name, { skip: !process.env.REDEEM_TEST_DATABASE_URL }, fn)
}

export async function temporaryDatabase(t) {
  const connectionString = process.env.REDEEM_TEST_DATABASE_URL
  if (!connectionString) throw new Error('REDEEM_TEST_DATABASE_URL is required')
  const schema = `redeem_test_${randomUUID().replaceAll('-', '')}`
  const admin = new Pool({ connectionString })
  await admin.query(`CREATE SCHEMA ${schema}`)
  const database = new RedeemDatabase({
    connectionString,
    options: `-c search_path=${schema}`,
    max: 4,
  }, path.join(projectRoot, 'migrations'))
  await database.initialize()
  t.after(async () => {
    await database.close()
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
    await admin.end()
  })
  return database
}

export const silentLogger = {
  info() {},
  error() {},
}
