import { createTranslator, localizedError, resolveLocale } from './user-i18n.js'

const SESSION_KEY = 'sub2api.redeem.session'

const authState = document.querySelector('#authState')
const userContent = document.querySelector('#userContent')
const identityChip = document.querySelector('#identityChip')
const identityAvatar = document.querySelector('#identityAvatar')
const identityName = document.querySelector('#identityName')
const identityEmail = document.querySelector('#identityEmail')
const redeemForm = document.querySelector('#redeemForm')
const redeemCode = document.querySelector('#redeemCode')
const redeemButton = document.querySelector('#redeemButton')
const redeemError = document.querySelector('#redeemError')
const redemptionResult = document.querySelector('#redemptionResult')
const historyList = document.querySelector('#historyList')
const historyEmpty = document.querySelector('#historyEmpty')
const refreshHistory = document.querySelector('#refreshHistory')
const productList = document.querySelector('#productList')
const productEmpty = document.querySelector('#productEmpty')

const entryURL = new URL(window.location.href)
const locale = resolveLocale(entryURL.searchParams.get('lang'), navigator.language)
const intlLocale = locale === 'zh' ? 'zh-CN' : 'en-US'
const t = createTranslator(locale)
let sessionToken = sessionStorage.getItem(SESSION_KEY) || ''

document.documentElement.lang = locale === 'zh' ? 'zh-CN' : 'en'
document.title = t('pageTitle')
document.querySelectorAll('[data-i18n]').forEach((element) => {
  element.textContent = t(element.dataset.i18n)
})
document.querySelectorAll('[data-i18n-aria-label]').forEach((element) => {
  element.setAttribute('aria-label', t(element.dataset.i18nAriaLabel))
})

if (entryURL.searchParams.get('ui_mode') === 'embedded' || window.self !== window.top) {
  document.body.classList.add('embedded')
}

const statusLabels = {
  pending: t('statusPending'),
  processing: t('statusProcessing'),
  retryable: t('statusRetryable'),
  succeeded: t('statusSucceeded'),
  failed: t('statusFailed'),
}

function escapeHTML(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
}

function formatDate(value) {
  if (!value) return '-'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '-'
  return new Intl.DateTimeFormat(intlLocale, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function benefitText(item) {
  if (item.benefit_type === 'subscription') {
    return t('subscriptionBenefit', { days: Number(item.validity_days || 0) })
  }
  return t('balanceBenefit', { value: item.value })
}

function formatPrice(item) {
  try {
    return new Intl.NumberFormat(intlLocale, {
      style: 'currency',
      currency: item.currency,
      minimumFractionDigits: 0,
      maximumFractionDigits: 6,
    }).format(Number(item.price))
  } catch {
    return `${item.currency} ${item.price}`
  }
}

function setAuthMessage(title, detail, failed = false) {
  authState.classList.toggle('error', failed)
  authState.innerHTML = `
    <span class="${failed ? 'state-icon' : 'spinner'}" aria-hidden="true">${failed ? '!' : ''}</span>
    <div>
      <strong>${escapeHTML(title)}</strong>
      <p>${escapeHTML(detail)}</p>
    </div>
  `
  authState.hidden = false
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (sessionToken) headers.set('Authorization', `Bearer ${sessionToken}`)
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(path, { ...options, headers })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    const reason = body.reason || ''
    const error = new Error(localizedError(locale, reason, body.message, t('requestFailed')))
    error.reason = reason
    error.status = response.status
    throw error
  }
  return body.data
}

function showIdentity(user) {
  const displayName = user.username || user.email || t('userWithId', { id: user.id })
  identityName.textContent = displayName
  identityEmail.textContent = user.email || `ID ${user.id}`
  identityAvatar.textContent = displayName.trim().charAt(0).toUpperCase() || 'U'
  identityChip.hidden = false
}

function showResult(redemption) {
  const succeeded = redemption.status === 'succeeded'
  const productName = locale === 'en' && redemption.product_name_en
    ? redemption.product_name_en
    : redemption.product_name
  redemptionResult.className = `redemption-result ${succeeded ? 'success' : 'pending'}`
  redemptionResult.innerHTML = `
    <span class="result-icon" aria-hidden="true">${succeeded ? '✓' : '…'}</span>
    <div>
      <strong>${succeeded ? t('statusSucceeded') : t('redeemAccepted')}</strong>
      <p>${productName ? `${escapeHTML(productName)}${locale === 'zh' ? '，' : ': '}` : ''}${escapeHTML(benefitText(redemption))}${succeeded ? t('benefitDelivered') : t('processingAutomatically')}</p>
    </div>
  `
  redemptionResult.hidden = false
}

function renderHistory(result) {
  const items = result?.items || []
  historyEmpty.hidden = items.length > 0
  historyList.replaceChildren()
  for (const item of items) {
    const productName = locale === 'en' && item.product_name_en
      ? item.product_name_en
      : item.product_name
    const article = document.createElement('article')
    article.className = 'history-item'
    article.innerHTML = `
      <span class="benefit-icon ${escapeHTML(item.benefit_type)}" aria-hidden="true">
        ${item.benefit_type === 'subscription' ? 'S' : '¥'}
      </span>
      <div class="history-copy">
        <div>
          <strong>${escapeHTML(productName || benefitText(item))}</strong>
          <span class="status-badge ${escapeHTML(item.status)}">${escapeHTML(statusLabels[item.status] || item.status)}</span>
        </div>
        <p>
          <span>${escapeHTML(item.code_mask)}</span>
          ${item.campaign ? `<span>${escapeHTML(item.campaign)}</span>` : ''}
          <time>${escapeHTML(formatDate(item.created_at))}</time>
        </p>
      </div>
    `
    historyList.append(article)
  }
}

function renderProducts(items) {
  productList.replaceChildren()
  productEmpty.hidden = items.length > 0
  for (const item of items) {
    const productName = locale === 'en' && item.name_en ? item.name_en : item.name
    const productDescription = locale === 'en' && item.description_en
      ? item.description_en
      : item.description
    const article = document.createElement('article')
    article.className = 'product-card'
    article.innerHTML = `
      <div class="product-card-heading">
        <span class="product-icon" aria-hidden="true">
          <span>${escapeHTML(productName.slice(0, 1).toUpperCase())}</span>
          ${item.icon_url ? `<img src="${escapeHTML(item.icon_url)}" alt="">` : ''}
        </span>
        <div class="product-title-copy">
          <small>${escapeHTML(item.sku)}</small>
          <h3>${escapeHTML(productName)}</h3>
        </div>
        <strong class="product-price">${escapeHTML(formatPrice(item))}</strong>
      </div>
      <p class="product-description">${escapeHTML(productDescription)}</p>
      <div class="product-card-footer">
        <span>${escapeHTML(benefitText(item))}</span>
        ${item.purchase_url
          ? `<a class="primary-button product-buy" href="${escapeHTML(item.purchase_url)}" target="_blank" rel="noopener noreferrer">${t('buy')} <span aria-hidden="true">↗</span></a>`
          : `<button class="secondary-button product-buy" type="button" disabled>${t('unavailable')}</button>`}
      </div>
    `
    const icon = article.querySelector('img')
    if (icon) icon.addEventListener('error', () => icon.remove(), { once: true })
    productList.append(article)
  }
}

async function loadProducts() {
  try {
    renderProducts(await request('/api/products'))
  } catch (error) {
    if (error.status === 401) throw error
    productList.innerHTML = `<p class="inline-error">${t('productsLoadFailed')}</p>`
  }
}

async function loadHistory() {
  refreshHistory.disabled = true
  try {
    renderHistory(await request('/api/my-redemptions?page_size=10'))
  } catch (error) {
    if (error.status === 401) {
      sessionStorage.removeItem(SESSION_KEY)
      setAuthMessage(t('sessionExpiredTitle'), t('sessionExpiredDetail'), true)
      userContent.hidden = true
    } else {
      historyEmpty.hidden = false
      historyList.innerHTML = `<p class="inline-error">${t('historyLoadFailed')}</p>`
    }
  } finally {
    refreshHistory.disabled = false
  }
}

async function establishSession() {
  const url = new URL(window.location.href)
  const fragment = new URLSearchParams(url.hash.replace(/^#/, ''))
  const sourceToken = fragment.get('token') || ''
  const hintedUserID = fragment.get('user_id') || ''

  if (sourceToken) {
    fragment.delete('token')
    fragment.delete('user_id')
    const remainingFragment = fragment.toString()
    history.replaceState(
      null,
      '',
      `${url.pathname}${url.search}${remainingFragment ? `#${remainingFragment}` : ''}`,
    )
    const exchanged = await request('/api/session/exchange', {
      method: 'POST',
      body: JSON.stringify({
        token: sourceToken,
        ...(hintedUserID ? { user_id: hintedUserID } : {}),
      }),
    })
    sessionToken = exchanged.session_token
    sessionStorage.setItem(SESSION_KEY, sessionToken)
    return exchanged.user
  }

  if (!sessionToken) {
    throw Object.assign(new Error(t('enterFromSub2api')), {
      reason: 'SESSION_REQUIRED',
    })
  }
  return request('/api/me')
}

redeemForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  redeemError.hidden = true
  redemptionResult.hidden = true
  const code = redeemCode.value.trim()
  if (!code) {
    redeemError.textContent = t('codeRequired')
    redeemError.hidden = false
    redeemCode.focus()
    return
  }

  redeemButton.disabled = true
  redeemButton.textContent = t('redeeming')
  try {
    const redemption = await request('/api/redeem', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    showResult(redemption)
    redeemCode.value = ''
    await loadHistory()
  } catch (error) {
    redeemError.textContent = error.message
    redeemError.hidden = false
  } finally {
    redeemButton.disabled = false
    redeemButton.textContent = t('redeemAction')
  }
})

redeemCode.addEventListener('input', () => {
  redeemCode.value = redeemCode.value.toUpperCase()
  redeemError.hidden = true
})

refreshHistory.addEventListener('click', loadHistory)

try {
  const user = await establishSession()
  showIdentity(user)
  authState.hidden = true
  userContent.hidden = false
  await Promise.all([loadProducts(), loadHistory()])
} catch (error) {
  sessionStorage.removeItem(SESSION_KEY)
  sessionToken = ''
  setAuthMessage(
    error.reason === 'SESSION_REQUIRED' ? t('loginRequired') : t('accountFailed'),
    error.message || t('reenterFromSub2api'),
    true,
  )
}
