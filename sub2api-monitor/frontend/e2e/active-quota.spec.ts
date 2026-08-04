import { expect, test } from '@playwright/test'

test.skip(process.env.MONITOR_E2E_REAL_TARGET !== '1', 'requires the real sub2api-local target')

test('real FULL target exposes active quota and complete account state', async ({ page }, testInfo) => {
  await page.goto('/')
  await page.getByLabel('密码').fill(process.env.MONITOR_ADMIN_PASSWORD ?? '')
  await page.getByRole('button', { name:'登录' }).click()
  await expect(page.getByRole('heading', { name:'总览' })).toBeVisible()

  if (testInfo.project.name === 'mobile') await page.getByRole('button', { name:'打开导航' }).click()
  await page.getByRole('link', { name:'目标' }).click()
  await page.getByRole('button', { name:'sub2api-local 能力详情' }).click()
  const activeCard = page.locator('.active-quota-capability')
  await expect(activeCard.getByText('主动额度刷新', { exact:true })).toBeVisible()
  await expect(activeCard.getByRole('switch')).toBeChecked()
  await expect(activeCard.getByText('支持')).toBeVisible()
  await expect(activeCard.getByText('正常')).toBeVisible()

  if (testInfo.project.name === 'mobile') await page.getByRole('button', { name:'打开导航' }).click()
  await page.getByRole('link', { name:'账号' }).click()
  await page.getByPlaceholder('搜索账号或平台').fill('zhangyk73')
  await expect(page.getByText('zhangyk73')).toBeVisible()
  await page.getByRole('button', { name:'查看 zhangyk73 额度详情' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('账号状态')).toBeVisible()
  await expect(dialog.getByText('可调度', { exact: true })).toBeVisible()
  await expect(dialog.getByText('账号过期时间')).toBeVisible()
  await expect(dialog.locator('.quota-window')).toHaveCount(2)
  await expect(dialog.getByText('Codex 5 hour quota')).toBeVisible()
  await expect(dialog.getByText('Codex 7 day quota')).toBeVisible()
  await expect(dialog.getByText('主动 API')).toHaveCount(2)
  await expect(dialog.getByText('100%')).toHaveCount(2)
  await page.screenshot({ path:testInfo.outputPath('active-quota.png'), fullPage:true })

  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})
