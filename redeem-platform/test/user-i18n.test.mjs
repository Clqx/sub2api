import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import {
  createTranslator,
  localizedError,
  messages,
  resolveLocale,
} from '../public/user-i18n.js'

test('redeem locale follows the lang parameter and falls back to browser language', () => {
  assert.equal(resolveLocale('en', 'zh-CN'), 'en')
  assert.equal(resolveLocale('en-US', 'zh-CN'), 'en')
  assert.equal(resolveLocale('zh-CN', 'en-US'), 'zh')
  assert.equal(resolveLocale('', 'zh-TW'), 'zh')
  assert.equal(resolveLocale('', 'en-GB'), 'en')
})

test('user locale dictionaries expose the same keys', () => {
  assert.deepEqual(Object.keys(messages.en).sort(), Object.keys(messages.zh).sort())
})

test('translator interpolates localized benefit text', () => {
  const en = createTranslator('en')
  const zh = createTranslator('zh')

  assert.equal(en('subscriptionBenefit', { days: 30 }), 'Subscription renewal for 30 days')
  assert.equal(zh('subscriptionBenefit', { days: 30 }), '\u8ba2\u9605\u7eed\u671f 30 \u5929')
})

test('English mode does not expose Chinese API errors', () => {
  assert.equal(
    localizedError('en', 'CODE_EXPIRED', '\u5151\u6362\u7801\u5df2\u8fc7\u671f', 'Request failed'),
    'This redemption code has expired.',
  )
  assert.equal(
    localizedError('en', 'UNKNOWN_REASON', '\u672a\u77e5\u4e2d\u6587\u9519\u8bef', 'Request failed'),
    'Request failed',
  )
  assert.equal(
    localizedError('zh', 'CODE_EXPIRED', '\u5151\u6362\u7801\u5df2\u8fc7\u671f', '\u8bf7\u6c42\u5931\u8d25'),
    '\u5151\u6362\u7801\u5df2\u8fc7\u671f',
  )
})

test('user page declares the static localization hooks used by the script', () => {
  const source = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8')

  assert.match(source, /data-i18n="pageHeading"/)
  assert.match(source, /data-i18n="redeemAction"/)
  assert.match(source, /data-i18n="historyEmptyDetail"/)
  assert.match(source, /src="\/assets\/user\.js\?v=[^"]+"/)
})
