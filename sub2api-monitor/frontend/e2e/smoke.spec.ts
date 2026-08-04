import { expect, test } from '@playwright/test'

test('administrator can inspect targets, accounts, and incidents', async ({ page }, testInfo) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '管理员登录' })).toBeVisible()
  await page.getByLabel('密码').fill(process.env.MONITOR_ADMIN_PASSWORD ?? 'qa-admin-password')
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page.getByRole('heading', { name: '总览' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('overview.png'), fullPage: true })

  if (testInfo.project.name === 'mobile') {
    await page.getByRole('button', { name: '打开导航' }).click()
  }
  await page.getByRole('link', { name: '目标' }).click()
  await expect(page.getByRole('heading', { name: '监控目标' })).toBeVisible()
  await expect(page.getByText('QA Fixture')).toBeVisible()
  await page.getByRole('button', { name: 'QA Fixture 能力详情' }).click()
  await expect(page.getByText('accounts.inventory')).toBeVisible()

  if (testInfo.project.name === 'mobile') {
    await page.getByRole('button', { name: '打开导航' }).click()
  }
  await page.getByRole('link', { name: '账号' }).click()
  await expect(page.getByText('anthropic-low-quota')).toBeVisible()
  await page.getByRole('button', { name: '查看 anthropic-low-quota 额度详情' }).click()
  await expect(page.getByText('5 hour quota')).toBeVisible()
  await page.getByRole('button', { name: '关闭账号详情' }).click()

  if (testInfo.project.name === 'mobile') {
    await page.getByRole('button', { name: '打开导航' }).click()
  }
  await page.getByRole('link', { name: '通知' }).click()
  await expect(page.getByText('QA ntfy')).toBeVisible()
  await page.getByRole('button', { name: '测试 QA ntfy' }).click()
  await expect(page.getByText('测试通知已入队，等待 worker 投递')).toBeVisible()
  await expect(page.getByText('已送达').first()).toBeVisible()

  if (testInfo.project.name === 'mobile') {
    await page.getByRole('button', { name: '打开导航' }).click()
  }
  await page.getByRole('link', { name: '系统' }).click()
  await expect(page.getByText('采集 Worker')).toBeVisible()
  await expect(page.getByText('运行中')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})
