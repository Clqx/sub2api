import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const userScriptURL = new URL('../public/user.js', import.meta.url)

test('user session credentials are read only from the URL fragment', () => {
  const source = fs.readFileSync(userScriptURL, 'utf8')

  assert.match(source, /new URLSearchParams\(url\.hash/)
  assert.match(source, /fragment\.get\('token'\)/)
  assert.doesNotMatch(source, /url\.searchParams\.get\('token'\)/)
})
