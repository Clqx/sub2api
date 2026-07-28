const $ = (selector, root = document) => root.querySelector(selector)
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)]

const state = {
  tab: 'overview',
  redemptionPage: 1,
  codePage: 1,
  generatedCodes: [],
  groupNames: new Map(),
}

const statusLabels = {
  unused: '未使用',
  pending: '等待处理',
  processing: '处理中',
  retryable: '待重试',
  succeeded: '成功',
  redeemed: '已兑换',
  failed: '失败',
  disabled: '已停用',
}

function escapeHTML(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
}

function formatDate(value, withSeconds = false) {
  if (!value) return '-'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '-'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    ...(withSeconds ? { second: '2-digit' } : {}),
  }).format(date)
}

function benefitText(item) {
  if (item.benefit_type === 'subscription') {
    const group = state.groupNames.get(Number(item.group_id))
    return `${group || `分组 ${item.group_id}`} · ${Number(item.validity_days || 0)} 天`
  }
  return `余额 ${item.value}`
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: 'same-origin',
  })
  const contentType = response.headers.get('content-type') || ''
  const body = contentType.includes('application/json')
    ? await response.json().catch(() => ({}))
    : {}
  if (!response.ok) {
    const error = new Error(body.message || `请求失败（${response.status}）`)
    error.reason = body.reason || ''
    error.status = response.status
    throw error
  }
  return body.data
}

function toast(message, tone = 'success') {
  const item = document.createElement('div')
  item.className = `toast ${tone}`
  item.textContent = message
  $('#toastRegion').append(item)
  window.setTimeout(() => item.remove(), 3600)
}

function formQuery(form, page = 1) {
  const params = new URLSearchParams()
  for (const [key, value] of new FormData(form)) {
    if (String(value).trim()) params.set(key, String(value).trim())
  }
  params.set('page', String(page))
  return params
}

function pagination(container, result, onPage) {
  container.replaceChildren()
  if (!result || result.pages <= 1) return
  const previous = document.createElement('button')
  previous.type = 'button'
  previous.textContent = '上一页'
  previous.disabled = result.page <= 1
  previous.addEventListener('click', () => onPage(result.page - 1))

  const label = document.createElement('span')
  label.textContent = `第 ${result.page} / ${result.pages} 页，共 ${result.total} 条`

  const next = document.createElement('button')
  next.type = 'button'
  next.textContent = '下一页'
  next.disabled = result.page >= result.pages
  next.addEventListener('click', () => onPage(result.page + 1))
  container.append(previous, label, next)
}

function switchTab(tab) {
  state.tab = tab
  $$('.tab-button').forEach((button) => {
    const active = button.dataset.tab === tab
    button.classList.toggle('active', active)
    button.setAttribute('aria-selected', String(active))
  })
  $$('.tab-view').forEach((view) => view.classList.toggle('active', view.dataset.view === tab))
  history.replaceState(null, '', tab === 'overview' ? '#overview' : `#${tab}`)
  if (tab === 'overview') loadAnalytics()
  if (tab === 'redemptions') loadRedemptions()
  if (tab === 'codes') loadCodes()
}

async function checkHealth() {
  const indicator = $('#healthIndicator')
  try {
    const data = await api('/health')
    indicator.classList.add('healthy')
    indicator.innerHTML = `<span></span>${data.demo_mode ? '演示服务正常' : '服务正常'}`
  } catch {
    indicator.classList.remove('healthy')
    indicator.innerHTML = '<span></span>服务异常'
  }
}

function renderTrend(items) {
  const chart = $('#trendChart')
  chart.replaceChildren()
  if (!items.length) {
    chart.innerHTML = '<div class="chart-empty">当前范围内暂无兑换数据</div>'
    return
  }
  const max = Math.max(1, ...items.map((item) => Number(item.total || 0)))
  for (const item of items) {
    const column = document.createElement('div')
    column.className = 'trend-column'
    column.title = `${item.day}：余额 ${item.balance_count || 0}，订阅 ${item.subscription_count || 0}`
    const bars = document.createElement('div')
    bars.className = 'trend-bars'
    for (const [type, value] of [
      ['balance', item.balance_count],
      ['subscription', item.subscription_count],
    ]) {
      const bar = document.createElement('i')
      bar.className = type
      bar.style.height = `${Math.max(Number(value) ? 8 : 2, (Number(value || 0) / max) * 100)}%`
      bars.append(bar)
    }
    const label = document.createElement('span')
    label.textContent = item.day.slice(5)
    column.append(bars, label)
    chart.append(column)
  }
}

function renderRanks(container, items, descriptor) {
  container.replaceChildren()
  if (!items.length) {
    container.innerHTML = '<p class="rank-empty">暂无数据</p>'
    return
  }
  const max = Math.max(1, ...items.map((item) => Number(item.redemptions || 0)))
  items.forEach((item, index) => {
    const name = item.campaign || state.groupNames.get(Number(item.group_id)) || `分组 ${item.group_id}`
    const row = document.createElement('div')
    row.className = 'rank-item'
    row.innerHTML = `
      <span class="rank-index">${index + 1}</span>
      <div>
        <div class="rank-copy">
          <strong>${escapeHTML(name)}</strong>
          <span>${escapeHTML(descriptor(item))}</span>
        </div>
        <i><b style="width:${Math.max(4, (Number(item.redemptions || 0) / max) * 100)}%"></b></i>
      </div>
    `
    container.append(row)
  })
}

async function loadAnalytics() {
  const params = new URLSearchParams()
  if ($('#overviewFrom').value) params.set('from', $('#overviewFrom').value)
  if ($('#overviewTo').value) params.set('to', $('#overviewTo').value)
  try {
    const data = await api(`/api/admin/analytics?${params}`)
    $('#metricTotal').textContent = data.total.toLocaleString('zh-CN')
    $('#metricRate').textContent = `${data.success_rate}%`
    $('#metricBalance').textContent = data.balance_value
    $('#metricDays').textContent = Number(data.subscription_days).toLocaleString('zh-CN')
    $('#metricPending').textContent = `${data.pending} 条处理中`
    $('#metricSucceeded').textContent = `${data.succeeded} 条成功`
    $('#metricFailed').textContent = `${data.failed} 条失败`
    renderTrend(data.trend || [])
    renderRanks($('#campaignList'), data.campaigns || [], (item) => (
      `${item.succeeded}/${item.redemptions} 成功`
    ))
    renderRanks($('#groupList'), data.groups || [], (item) => (
      `${item.redemptions} 次 · ${item.validity_days} 天`
    ))
  } catch (error) {
    toast(error.message, 'error')
  }
}

function emptyTable(tbody, columns, message) {
  tbody.innerHTML = `<tr><td colspan="${columns}" class="table-empty">${escapeHTML(message)}</td></tr>`
}

async function loadRedemptions(page = state.redemptionPage) {
  state.redemptionPage = page
  const params = formQuery($('#redemptionFilters'), page)
  params.set('page_size', '25')
  $('#exportRedemptions').href = `/api/admin/export.csv?${params}`
  const rows = $('#redemptionRows')
  emptyTable(rows, 7, '正在加载')
  try {
    const result = await api(`/api/admin/redemptions?${params}`)
    rows.replaceChildren()
    if (!result.items.length) emptyTable(rows, 7, '没有符合条件的兑换记录')
    for (const item of result.items) {
      const tr = document.createElement('tr')
      tr.innerHTML = `
        <td><time>${escapeHTML(formatDate(item.created_at))}</time></td>
        <td>
          <strong class="table-primary">${escapeHTML(item.user_email || `用户 ${item.user_id}`)}</strong>
          <small>ID ${escapeHTML(item.user_id)}</small>
        </td>
        <td>
          <strong class="table-primary">${escapeHTML(benefitText(item))}</strong>
          <small>${escapeHTML(item.code_mask)}</small>
        </td>
        <td>${escapeHTML(item.campaign || '未分类')}</td>
        <td><span class="status-badge ${escapeHTML(item.status)}">${escapeHTML(statusLabels[item.status] || item.status)}</span></td>
        <td>${Number(item.attempt_count || 0)}</td>
        <td><button class="row-action" type="button" data-detail="${escapeHTML(item.id)}">查看</button></td>
      `
      rows.append(tr)
    }
    $$('[data-detail]', rows).forEach((button) => {
      button.addEventListener('click', () => openRedemptionDetail(button.dataset.detail))
    })
    pagination($('#redemptionPagination'), result, loadRedemptions)
  } catch (error) {
    emptyTable(rows, 7, error.message)
  }
}

async function loadCodes(page = state.codePage) {
  state.codePage = page
  const params = formQuery($('#codeFilters'), page)
  params.set('page_size', '20')
  const rows = $('#codeRows')
  emptyTable(rows, 7, '正在加载')
  try {
    const result = await api(`/api/admin/codes?${params}`)
    rows.replaceChildren()
    if (!result.items.length) emptyTable(rows, 7, '没有符合条件的兑换码')
    for (const item of result.items) {
      const canDisable = item.status === 'unused'
      const tr = document.createElement('tr')
      tr.innerHTML = `
        <td><strong class="code-mask">${escapeHTML(item.code_mask)}</strong></td>
        <td>
          <strong class="table-primary">${escapeHTML(benefitText(item))}</strong>
          <small>${item.benefit_type === 'subscription' ? '订阅续期' : '余额充值'}</small>
        </td>
        <td>${escapeHTML(item.campaign || '未分类')}</td>
        <td>${escapeHTML(item.expires_at ? formatDate(item.expires_at) : '长期有效')}</td>
        <td><span class="status-badge ${escapeHTML(item.status)}">${escapeHTML(statusLabels[item.status] || item.status)}</span></td>
        <td><time>${escapeHTML(formatDate(item.created_at))}</time></td>
        <td>${canDisable ? `<button class="row-action danger" type="button" data-disable="${escapeHTML(item.id)}">停用</button>` : ''}</td>
      `
      rows.append(tr)
    }
    $$('[data-disable]', rows).forEach((button) => {
      button.addEventListener('click', () => disableCode(button.dataset.disable))
    })
    pagination($('#codePagination'), result, loadCodes)
  } catch (error) {
    emptyTable(rows, 7, error.message)
  }
}

async function disableCode(id) {
  if (!window.confirm('停用后该兑换码将无法继续使用。确认停用？')) return
  try {
    await api(`/api/admin/codes/${id}/disable`, {
      method: 'POST',
      body: '{}',
    })
    toast('兑换码已停用')
    await loadCodes()
  } catch (error) {
    toast(error.message, 'error')
  }
}

function detailField(label, value, wide = false) {
  return `
    <div class="detail-field${wide ? ' wide' : ''}">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value ?? '-')}</strong>
    </div>
  `
}

async function openRedemptionDetail(id) {
  const dialog = $('#redemptionDetail')
  $('#redemptionDetailBody').innerHTML = '<p class="drawer-loading">正在加载兑换详情</p>'
  $('#redemptionDetailActions').replaceChildren()
  dialog.showModal()
  try {
    const item = await api(`/api/admin/redemptions/${id}`)
    const attempts = item.attempts || []
    $('#redemptionDetailBody').innerHTML = `
      <div class="detail-status">
        <span class="status-badge ${escapeHTML(item.status)}">${escapeHTML(statusLabels[item.status] || item.status)}</span>
        <span>${escapeHTML(item.code_mask)}</span>
      </div>
      <div class="detail-grid">
        ${detailField('用户', item.user_email || `用户 ${item.user_id}`)}
        ${detailField('用户 ID', item.user_id)}
        ${detailField('权益', benefitText(item), true)}
        ${detailField('活动', item.campaign || '未分类')}
        ${detailField('创建时间', formatDate(item.created_at, true))}
        ${detailField('完成时间', formatDate(item.completed_at, true))}
        ${detailField('上游业务码', item.upstream_code)}
        ${detailField('幂等键', item.idempotency_key)}
        ${detailField('最近错误', item.last_error || '无', true)}
      </div>
      <section class="attempt-section">
        <h3>履约尝试</h3>
        <div class="attempt-list">
          ${attempts.length ? attempts.map((attempt) => `
            <article>
              <span class="attempt-no">#${Number(attempt.attempt_no)}</span>
              <div>
                <strong>${escapeHTML(statusLabels[attempt.status] || attempt.status)}</strong>
                <small>${escapeHTML(formatDate(attempt.created_at, true))} · ${Number(attempt.latency_ms || 0)} ms</small>
                ${attempt.error_message ? `<p>${escapeHTML(attempt.error_message)}</p>` : ''}
              </div>
              <span>${escapeHTML(attempt.http_status || '-')}</span>
            </article>
          `).join('') : '<p class="rank-empty">尚未开始履约</p>'}
        </div>
      </section>
    `
    if (item.status !== 'succeeded') {
      const retry = document.createElement('button')
      retry.type = 'button'
      retry.className = 'primary-button'
      retry.textContent = '立即重试'
      retry.addEventListener('click', async () => {
        retry.disabled = true
        retry.textContent = '正在重试'
        try {
          await api(`/api/admin/redemptions/${id}/retry`, {
            method: 'POST',
            body: '{}',
          })
          toast('重试已执行')
          dialog.close()
          await loadRedemptions()
        } catch (error) {
          toast(error.message, 'error')
          retry.disabled = false
          retry.textContent = '立即重试'
        }
      })
      $('#redemptionDetailActions').append(retry)
    }
  } catch (error) {
    $('#redemptionDetailBody').innerHTML = `<p class="inline-error">${escapeHTML(error.message)}</p>`
  }
}

async function loadGroups() {
  const select = $('#groupSelect')
  select.innerHTML = '<option value="">正在读取分组</option>'
  try {
    const groups = await api('/api/admin/groups')
    state.groupNames = new Map(groups.map((group) => [Number(group.id), group.name]))
    select.replaceChildren()
    const eligible = groups.filter((group) => (
      group.subscription_type === 'subscription' && group.status === 'active'
    ))
    for (const group of eligible) {
      const option = document.createElement('option')
      option.value = group.id
      option.textContent = `${group.name}（ID ${group.id}）`
      select.append(option)
    }
    if (!eligible.length) select.innerHTML = '<option value="">无可用订阅分组</option>'
  } catch (error) {
    select.innerHTML = '<option value="">分组读取失败</option>'
    toast(error.message, 'error')
  }
}

function updateBenefitFields() {
  const subscription = $('[name="benefit_type"]:checked').value === 'subscription'
  $$('.subscription-field').forEach((field) => { field.hidden = !subscription })
  $('[name="group_id"]').required = subscription
  $('[name="validity_days"]').required = subscription
}

async function generateCodes(event) {
  event.preventDefault()
  const form = event.currentTarget
  const error = $('#generateError')
  error.hidden = true
  const values = Object.fromEntries(new FormData(form))
  if (values.expires_at) values.expires_at = new Date(values.expires_at).toISOString()
  const submit = $('#generateSubmit')
  submit.disabled = true
  submit.textContent = '正在生成'
  try {
    const codes = await api('/api/admin/codes/generate', {
      method: 'POST',
      body: JSON.stringify(values),
    })
    state.generatedCodes = codes
    $('#generatedCount').textContent = `${codes.length} 个兑换码`
    $('#generatedCodeList').textContent = codes.map((item) => item.code).join('\n')
    $('#generateCodesModal').close()
    $('#generatedCodesModal').showModal()
    await loadCodes(1)
    if (state.tab === 'overview') await loadAnalytics()
  } catch (requestError) {
    error.textContent = requestError.message
    error.hidden = false
  } finally {
    submit.disabled = false
    submit.textContent = '生成'
  }
}

async function copyGenerated() {
  const text = state.generatedCodes.map((item) => item.code).join('\n')
  try {
    await navigator.clipboard.writeText(text)
    toast('兑换码已复制')
  } catch {
    toast('浏览器拒绝了剪贴板访问，请使用下载', 'error')
  }
}

function downloadGenerated() {
  const text = `${state.generatedCodes.map((item) => item.code).join('\r\n')}\r\n`
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `redeem-codes-${new Date().toISOString().slice(0, 10)}.txt`
  link.click()
  URL.revokeObjectURL(url)
}

$$('.tab-button').forEach((button) => {
  button.addEventListener('click', () => switchTab(button.dataset.tab))
})
$('#applyOverviewDates').addEventListener('click', loadAnalytics)
$('#redemptionFilters').addEventListener('submit', (event) => {
  event.preventDefault()
  loadRedemptions(1)
})
$('#codeFilters').addEventListener('submit', (event) => {
  event.preventDefault()
  loadCodes(1)
})
$('#globalRefresh').addEventListener('click', async () => {
  await checkHealth()
  switchTab(state.tab)
})
$('#openGenerateCodes').addEventListener('click', async () => {
  $('#generateError').hidden = true
  $('#generateCodesModal').showModal()
  await loadGroups()
})
$$('[name="benefit_type"]').forEach((radio) => {
  radio.addEventListener('change', updateBenefitFields)
})
$('#generateCodesForm').addEventListener('submit', generateCodes)
$$('[data-close-dialog]').forEach((button) => {
  button.addEventListener('click', () => $('#generateCodesModal').close())
})
$$('[data-close-generated]').forEach((button) => {
  button.addEventListener('click', () => $('#generatedCodesModal').close())
})
$('[data-close-detail]').addEventListener('click', () => $('#redemptionDetail').close())
$('#copyGenerated').addEventListener('click', copyGenerated)
$('#downloadGenerated').addEventListener('click', downloadGenerated)

for (const dialog of $$('dialog')) {
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close()
  })
}

await checkHealth()
await loadGroups()
const initialTab = ['overview', 'redemptions', 'codes'].includes(location.hash.slice(1))
  ? location.hash.slice(1)
  : 'overview'
switchTab(initialTab)
