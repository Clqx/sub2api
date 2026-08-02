import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const userScriptURL = new URL('../public/user.js', import.meta.url)
const userPageURL = new URL('../public/index.html', import.meta.url)

test('user catalog uses DOM APIs available on the standalone page', () => {
  const source = fs.readFileSync(userScriptURL, 'utf8')

  assert.match(source, /article\.querySelector\('img'\)/)
  assert.doesNotMatch(source, /(^|[^\w$])\$\(/m)
})

test('user page cache-busts the catalog script', () => {
  const source = fs.readFileSync(userPageURL, 'utf8')

  assert.match(source, /src="\/assets\/user\.js\?v=[^"]+"/)
})
