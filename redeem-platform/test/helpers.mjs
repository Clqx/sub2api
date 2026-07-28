import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RedeemDatabase } from '../src/database.mjs'

const projectRoot = fileURLToPath(new URL('../', import.meta.url))

export function testConfig(overrides = {}) {
  return {
    nodeEnv: 'test',
    demoMode: true,
    host: '127.0.0.1',
    port: 0,
    publicDir: path.join(projectRoot, 'public'),
    migrationDir: path.join(projectRoot, 'migrations'),
    databasePath: '',
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

export function temporaryDatabase(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redeem-platform-test-'))
  const database = new RedeemDatabase(
    path.join(directory, 'test.db'),
    path.join(projectRoot, 'migrations'),
  )
  t.after(() => {
    database.close()
    fs.rmSync(directory, { recursive: true, force: true })
  })
  return database
}

export const silentLogger = {
  info() {},
  error() {},
}
