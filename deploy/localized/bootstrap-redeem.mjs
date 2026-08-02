import fs from 'node:fs/promises'
import path from 'node:path'

const baseURL = String(process.env.SUB2API_BASE_URL || '').replace(/\/+$/, '')
const email = String(process.env.ADMIN_EMAIL || '')
const password = String(process.env.ADMIN_PASSWORD || '')
const outputFile = String(process.env.SUB2API_ADMIN_API_KEY_FILE || '')
const compliancePhrase = String(process.env.ADMIN_COMPLIANCE_ACK_PHRASE || '').trim()
const complianceLanguage = String(process.env.ADMIN_COMPLIANCE_LANGUAGE || 'zh').trim()
const redeemPublicURL = String(process.env.REDEEM_PUBLIC_URL || '').trim()
const redeemMenuIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12v10H4V12"/><path d="M2 7h20v5H2z"/><path d="M12 22V7"/><path d="M12 7H7.5a2.5 2.5 0 1 1 0-5C11 2 12 7 12 7Z"/><path d="M12 7h4.5a2.5 2.5 0 1 0 0-5C13 2 12 7 12 7Z"/></svg>'

if (!baseURL || !email || !password || !outputFile) {
  throw new Error('SUB2API_BASE_URL, ADMIN_EMAIL, ADMIN_PASSWORD, and SUB2API_ADMIN_API_KEY_FILE are required')
}
if (/(?:change[-_ ]?me|replace[-_ ]?with)/i.test(password)) {
  throw new Error('ADMIN_PASSWORD must not use an example placeholder value')
}

async function request(route, options = {}) {
  const response = await fetch(`${baseURL}${route}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    signal: AbortSignal.timeout(10000),
  })
  let body
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { response, body }
}

async function waitUntilHealthy() {
  for (let attempt = 1; attempt <= 90; attempt += 1) {
    try {
      const { response } = await request('/health')
      if (response.ok) return
    } catch {
      // The application may still be applying migrations.
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
  throw new Error('Sub2API did not become healthy before the bootstrap timeout')
}

async function existingKey() {
  try {
    const key = (await fs.readFile(outputFile, 'utf8')).trim()
    if (!key) return ''
    const { response, body } = await request('/api/v1/admin/groups/all', {
      headers: { 'x-api-key': key },
    })
    return response.ok && body?.code === 0 ? key : ''
  } catch {
    return ''
  }
}

async function ensureRedeemMenu(adminApiKey) {
  if (!redeemPublicURL) return false
  let menuURL
  try {
    const parsed = new URL(redeemPublicURL)
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
      throw new Error('unsupported URL')
    }
    menuURL = parsed.toString().replace(/\/$/, '')
  } catch {
    throw new Error('REDEEM_PUBLIC_URL must be an absolute HTTP(S) URL without credentials')
  }
  const headers = { 'x-api-key': adminApiKey }
  const current = await request('/api/v1/admin/settings', { headers })
  if (!current.response.ok || current.body?.code !== 0) {
    throw new Error(`cannot read custom menu settings: ${current.body?.message || current.response.status}`)
  }
  const items = Array.isArray(current.body?.data?.custom_menu_items)
    ? current.body.data.custom_menu_items
    : []
  const existing = items.find((item) => item.id === 'redeem-center')
  const sortOrder = existing?.sort_order ?? (
    items.reduce((maximum, item) => Math.max(maximum, Number(item.sort_order) || 0), -1) + 1
  )
  const menuItem = {
    id: 'redeem-center',
    label: '兑换中心',
    icon_svg: redeemMenuIcon,
    url: menuURL,
    visibility: 'user',
    sort_order: sortOrder,
  }
  const unchanged = existing
    && existing.label === menuItem.label
    && existing.icon_svg === menuItem.icon_svg
    && existing.url === menuItem.url
    && existing.visibility === menuItem.visibility
    && Number(existing.sort_order) === Number(menuItem.sort_order)
  if (unchanged) return true
  const updatedItems = [...items.filter((item) => item.id !== menuItem.id), menuItem]
  const updated = await request('/api/v1/admin/settings', {
    method: 'PUT',
    headers,
    body: JSON.stringify({ custom_menu_items: updatedItems }),
  })
  if (!updated.response.ok || updated.body?.code !== 0) {
    throw new Error(`cannot configure redeem menu: ${updated.body?.message || updated.response.status}`)
  }
  return true
}

await waitUntilHealthy()

const reusableKey = await existingKey()
if (reusableKey) {
  await fs.chown(outputFile, 1000, 1000)
  await fs.chmod(outputFile, 0o400)
  const menuConfigured = await ensureRedeemMenu(reusableKey)
  console.info(JSON.stringify({ event: 'redeem_admin_key_ready', reused: true, menu_configured: menuConfigured }))
  process.exit(0)
}

const login = await request('/api/v1/auth/login', {
  method: 'POST',
  body: JSON.stringify({ email, password }),
})
const accessToken = login.body?.data?.access_token
if (!login.response.ok || login.body?.code !== 0 || !accessToken) {
  if (login.body?.data?.requires_2fa) {
    throw new Error('automatic bootstrap cannot use an administrator account with 2FA enabled')
  }
  throw new Error(`administrator login failed: ${login.body?.message || login.response.status}`)
}

const compliance = await request('/api/v1/admin/compliance', {
  headers: { Authorization: `Bearer ${accessToken}` },
})
if (!compliance.response.ok || compliance.body?.code !== 0) {
  throw new Error(`cannot read administrator compliance status: ${compliance.body?.message || compliance.response.status}`)
}
if (compliance.body?.data?.required) {
  if (!compliancePhrase) {
    throw new Error(
      'administrator compliance acknowledgement is required; read docs/legal/admin-compliance.zh.md and set ADMIN_COMPLIANCE_ACK_PHRASE explicitly',
    )
  }
  const accepted = await request('/api/v1/admin/compliance/accept', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ phrase: compliancePhrase, language: complianceLanguage }),
  })
  if (!accepted.response.ok || accepted.body?.code !== 0 || accepted.body?.data?.required) {
    throw new Error(`administrator compliance acknowledgement failed: ${accepted.body?.message || accepted.response.status}`)
  }
}

const generated = await request('/api/v1/admin/settings/admin-api-key/regenerate', {
  method: 'POST',
  headers: { Authorization: `Bearer ${accessToken}` },
  body: '{}',
})
const adminApiKey = generated.body?.data?.key
if (!generated.response.ok || generated.body?.code !== 0 || !adminApiKey) {
  throw new Error(`Admin API Key generation failed: ${generated.body?.message || generated.response.status}`)
}

await fs.mkdir(path.dirname(outputFile), { recursive: true })
const temporaryFile = `${outputFile}.tmp`
await fs.writeFile(temporaryFile, `${adminApiKey}\n`, { mode: 0o600 })
await fs.chown(temporaryFile, 1000, 1000)
await fs.chmod(temporaryFile, 0o400)
await fs.rename(temporaryFile, outputFile)
const menuConfigured = await ensureRedeemMenu(adminApiKey)
console.info(JSON.stringify({ event: 'redeem_admin_key_ready', reused: false, menu_configured: menuConfigured }))
