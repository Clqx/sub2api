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

let sessionToken = sessionStorage.getItem(SESSION_KEY) || ''

const entryURL = new URL(window.location.href)
if (entryURL.searchParams.get('ui_mode') === 'embedded' || window.self !== window.top) {
  document.body.classList.add('embedded')
}

const statusLabels = {
  pending: '等待处理',
  processing: '处理中',
  retryable: '等待重试',
  succeeded: '兑换成功',
  failed: '处理失败',
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
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function benefitText(item) {
  if (item.benefit_type === 'subscription') {
    return `订阅续期 ${Number(item.validity_days || 0)} 天`
  }
  return `余额充值 ${item.value}`
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
    const error = new Error(body.message || '请求未完成，请稍后重试')
    error.reason = body.reason || ''
    error.status = response.status
    throw error
  }
  return body.data
}

function showIdentity(user) {
  const displayName = user.username || user.email || `用户 ${user.id}`
  identityName.textContent = displayName
  identityEmail.textContent = user.email || `ID ${user.id}`
  identityAvatar.textContent = displayName.trim().charAt(0).toUpperCase() || 'U'
  identityChip.hidden = false
}

function showResult(redemption) {
  const succeeded = redemption.status === 'succeeded'
  redemptionResult.className = `redemption-result ${succeeded ? 'success' : 'pending'}`
  redemptionResult.innerHTML = `
    <span class="result-icon" aria-hidden="true">${succeeded ? '✓' : '…'}</span>
    <div>
      <strong>${succeeded ? '兑换成功' : '兑换请求已受理'}</strong>
      <p>${escapeHTML(benefitText(redemption))}${succeeded ? '，权益已经发放到账户。' : '，系统正在自动处理。'}</p>
    </div>
  `
  redemptionResult.hidden = false
}

function renderHistory(result) {
  const items = result?.items || []
  historyEmpty.hidden = items.length > 0
  historyList.replaceChildren()
  for (const item of items) {
    const article = document.createElement('article')
    article.className = 'history-item'
    article.innerHTML = `
      <span class="benefit-icon ${escapeHTML(item.benefit_type)}" aria-hidden="true">
        ${item.benefit_type === 'subscription' ? 'S' : '¥'}
      </span>
      <div class="history-copy">
        <div>
          <strong>${escapeHTML(benefitText(item))}</strong>
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

async function loadHistory() {
  refreshHistory.disabled = true
  try {
    renderHistory(await request('/api/my-redemptions?page_size=10'))
  } catch (error) {
    if (error.status === 401) {
      sessionStorage.removeItem(SESSION_KEY)
      setAuthMessage('登录状态已失效', '请从 Sub2API 用户中心重新进入兑换页面', true)
      userContent.hidden = true
    } else {
      historyEmpty.hidden = false
      historyList.innerHTML = '<p class="inline-error">兑换记录暂时无法加载</p>'
    }
  } finally {
    refreshHistory.disabled = false
  }
}

async function establishSession() {
  const url = new URL(window.location.href)
  const sourceToken = url.searchParams.get('token') || ''
  const hintedUserID = url.searchParams.get('user_id') || ''

  if (sourceToken) {
    url.searchParams.delete('token')
    url.searchParams.delete('user_id')
    history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
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
    throw Object.assign(new Error('请从 Sub2API 用户中心进入兑换页面'), {
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
    redeemError.textContent = '请输入兑换码'
    redeemError.hidden = false
    redeemCode.focus()
    return
  }

  redeemButton.disabled = true
  redeemButton.textContent = '正在兑换'
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
    redeemButton.textContent = '确认兑换'
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
  await loadHistory()
} catch (error) {
  sessionStorage.removeItem(SESSION_KEY)
  sessionToken = ''
  setAuthMessage(
    error.reason === 'SESSION_REQUIRED' ? '需要登录' : '无法确认账户',
    error.message || '请从 Sub2API 用户中心重新进入',
    true,
  )
}
