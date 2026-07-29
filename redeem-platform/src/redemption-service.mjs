import { AppError } from './errors.mjs'
import { UpstreamError } from './sub2api-client.mjs'
import {
  generateRedeemCode,
  hashRedeemCode,
  maskRedeemCode,
  parseAmountMicros,
  randomID,
} from './security.mjs'

function cleanText(value, maxLength) {
  return String(value || '').trim().slice(0, maxLength)
}

function validateExpiration(value) {
  if (!value) return null
  const date = new Date(value)
  if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) {
    throw new AppError(400, 'INVALID_EXPIRATION', '兑换码过期时间必须晚于当前时间')
  }
  return date.toISOString()
}

function parsePositiveAmount(value, code, message) {
  try {
    return parseAmountMicros(value, { allowNegative: false })
  } catch {
    throw new AppError(400, code, message)
  }
}

function validatePurchaseURL(value) {
  const text = cleanText(value, 2048)
  if (!text) return ''
  let url
  try {
    url = new URL(text)
  } catch {
    throw new AppError(400, 'INVALID_PURCHASE_URL', '购买链接必须是完整的 HTTP 或 HTTPS 地址')
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new AppError(400, 'INVALID_PURCHASE_URL', '购买链接必须是无账号信息的 HTTP 或 HTTPS 地址')
  }
  return url.href
}

function validateIconURL(value) {
  const text = cleanText(value, 2048)
  if (!text) return ''
  let url
  try {
    url = new URL(text)
  } catch {
    throw new AppError(400, 'INVALID_ICON_URL', '商品图标必须是完整的 HTTP 或 HTTPS 地址')
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new AppError(400, 'INVALID_ICON_URL', '商品图标必须是无账号信息的 HTTP 或 HTTPS 地址')
  }
  return url.href
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(String(value))
}

export class RedemptionService {
  constructor({ database, sub2api, config, logger = console }) {
    this.database = database
    this.sub2api = sub2api
    this.config = config
    this.logger = logger
    this.inFlight = new Set()
    this.retryTimer = null
  }

  async exchangeUserToken(accessToken, hintedUserID) {
    if (!accessToken || String(accessToken).length > 8192) {
      throw new AppError(401, 'USER_TOKEN_REQUIRED', '用户登录凭证缺失')
    }
    let user
    try {
      user = await this.sub2api.verifyUser(String(accessToken))
    } catch (error) {
      if (error instanceof UpstreamError) {
        throw new AppError(
          error.retryable ? 503 : 401,
          error.reason || 'USER_TOKEN_INVALID',
          error.message,
        )
      }
      throw error
    }
    if (hintedUserID && Number(hintedUserID) !== Number(user.id)) {
      throw new AppError(403, 'USER_ID_MISMATCH', '用户身份校验不一致')
    }
    return user
  }

  async generateCodes(input, actor) {
    const count = Number(input.count)
    if (!Number.isInteger(count) || count < 1 || count > 100) {
      throw new AppError(400, 'INVALID_COUNT', '单次生成数量必须在 1 到 100 之间')
    }
    let product = null
    if (input.product_id) {
      if (!validUUID(input.product_id)) {
        throw new AppError(400, 'INVALID_PRODUCT_ID', '商品编号无效')
      }
      product = await this.database.getProduct(String(input.product_id))
      if (!product) throw new AppError(404, 'PRODUCT_NOT_FOUND', '商品不存在')
      if (product.status !== 'active') {
        throw new AppError(409, 'PRODUCT_NOT_ACTIVE', '只有已上架商品可以生成关联兑换码')
      }
    }

    const benefit = await this.validateBenefit(product || input)
    const { benefitType, valueMicros, groupID, validityDays } = benefit

    const campaign = cleanText(input.campaign || product?.sku, 100)
    const notes = cleanText(input.notes, 500)
    const expiresAt = validateExpiration(input.expires_at)
    const records = []
    for (let index = 0; index < count; index += 1) {
      const code = generateRedeemCode()
      records.push({
        id: randomID(),
        code,
        codeHash: hashRedeemCode(code, this.config.codePepper),
        codeMask: maskRedeemCode(code),
        productID: product?.id || null,
        productName: product?.name || '',
        productSKU: product?.sku || '',
        benefitType,
        valueMicros,
        groupID,
        validityDays,
        campaign,
        notes,
        expiresAt,
      })
    }
    return this.database.insertCodes(records, actor)
  }

  async validateBenefit(input, { requireActiveGroup = true } = {}) {
    const benefitType = String(input.benefit_type || input.type || '')
    if (!['balance', 'subscription'].includes(benefitType)) {
      throw new AppError(400, 'INVALID_BENEFIT_TYPE', '权益类型无效')
    }
    const valueMicros = parsePositiveAmount(
      input.value,
      'INVALID_VALUE',
      '记账金额必须是大于零的数字，最多六位小数',
    )
    let groupID = null
    let validityDays = null
    if (benefitType === 'subscription') {
      groupID = Number(input.group_id)
      validityDays = Number(input.validity_days)
      if (!Number.isInteger(groupID) || groupID <= 0) {
        throw new AppError(400, 'INVALID_GROUP_ID', '订阅权益必须选择有效分组')
      }
      if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 36500) {
        throw new AppError(400, 'INVALID_VALIDITY_DAYS', '订阅天数必须在 1 到 36500 之间')
      }
      if (requireActiveGroup) {
        let groups
        try {
          groups = await this.sub2api.listGroups()
        } catch (error) {
          if (error instanceof UpstreamError) {
            throw new AppError(502, error.reason || 'UPSTREAM_GROUPS_FAILED', '无法验证订阅分组')
          }
          throw error
        }
        const group = groups.find((item) => Number(item.id) === groupID)
        if (!group || group.subscription_type !== 'subscription' || group.status !== 'active') {
          throw new AppError(400, 'INVALID_SUBSCRIPTION_GROUP', '订阅分组不存在、未启用或不支持订阅')
        }
      }
    }
    return { benefitType, valueMicros, groupID, validityDays }
  }

  async validateProduct(input) {
    const sku = cleanText(input.sku, 50).toUpperCase()
    if (!/^[A-Z0-9][A-Z0-9._-]{1,49}$/.test(sku)) {
      throw new AppError(400, 'INVALID_PRODUCT_SKU', '商品 SKU 需为 2 到 50 位字母、数字、点、横线或下划线')
    }
    const name = cleanText(input.name, 100)
    if (!name) throw new AppError(400, 'INVALID_PRODUCT_NAME', '商品名称不能为空')
    const description = cleanText(input.description, 1000)
    const priceMicros = parsePositiveAmount(
      input.price,
      'INVALID_PRODUCT_PRICE',
      '商品价格必须是大于零的数字，最多六位小数',
    )
    const currency = cleanText(input.currency || 'CNY', 3).toUpperCase()
    if (!/^[A-Z]{3}$/.test(currency)) {
      throw new AppError(400, 'INVALID_CURRENCY', '货币代码必须是三位大写字母')
    }
    const status = String(input.status || 'draft')
    if (!['draft', 'active', 'archived'].includes(status)) {
      throw new AppError(400, 'INVALID_PRODUCT_STATUS', '商品状态无效')
    }
    const sortOrder = Number(input.sort_order || 0)
    if (!Number.isInteger(sortOrder) || sortOrder < -100000 || sortOrder > 100000) {
      throw new AppError(400, 'INVALID_SORT_ORDER', '展示顺序必须是 -100000 到 100000 的整数')
    }
    const benefit = await this.validateBenefit(input, { requireActiveGroup: status !== 'archived' })
    return {
      sku,
      name,
      description,
      priceMicros,
      currency,
      purchaseURL: validatePurchaseURL(input.purchase_url),
      iconURL: validateIconURL(input.icon_url),
      status,
      sortOrder,
      ...benefit,
    }
  }

  async createProduct(input, actor) {
    const product = await this.validateProduct(input)
    const result = await this.database.insertProduct({ id: randomID(), ...product }, actor)
    if (result.kind === 'duplicate') {
      throw new AppError(409, 'PRODUCT_SKU_EXISTS', '商品 SKU 已存在')
    }
    return result.product
  }

  async updateProduct(id, input, actor) {
    if (!validUUID(id)) {
      throw new AppError(400, 'INVALID_PRODUCT_ID', '商品编号无效')
    }
    const product = await this.validateProduct(input)
    const result = await this.database.updateProduct(id, product, actor)
    if (result.kind === 'not_found') throw new AppError(404, 'PRODUCT_NOT_FOUND', '商品不存在')
    if (result.kind === 'duplicate') throw new AppError(409, 'PRODUCT_SKU_EXISTS', '商品 SKU 已存在')
    return result.product
  }

  async redeem(rawCode, user) {
    let codeHash
    try {
      codeHash = hashRedeemCode(rawCode, this.config.codePepper)
    } catch {
      throw new AppError(404, 'CODE_NOT_FOUND', '兑换码不存在或格式错误')
    }
    const claimed = await this.database.claimCode({ codeHash, user })
    switch (claimed.kind) {
      case 'not_found':
        throw new AppError(404, 'CODE_NOT_FOUND', '兑换码不存在或格式错误')
      case 'disabled':
        throw new AppError(409, 'CODE_DISABLED', '兑换码已停用')
      case 'expired':
        throw new AppError(409, 'CODE_EXPIRED', '兑换码已过期')
      case 'claimed_by_other':
        throw new AppError(409, 'CODE_ALREADY_USED', '兑换码已被其他用户使用')
      case 'unavailable':
        throw new AppError(409, 'CODE_UNAVAILABLE', '兑换码当前不可使用')
      case 'existing':
        if (claimed.redemption.status === 'succeeded') return claimed.redemption
        if (claimed.redemption.status === 'processing') return claimed.redemption
        if (claimed.redemption.status === 'failed') {
          throw new AppError(409, 'REDEMPTION_REQUIRES_REVIEW', '该兑换需要管理员处理')
        }
        return this.fulfill(claimed.redemption.id)
      case 'claimed':
        return this.fulfill(claimed.redemption.id)
      default:
        throw new AppError(500, 'CLAIM_STATE_INVALID', '兑换状态异常')
    }
  }

  async fulfill(id) {
    if (this.inFlight.has(id)) return this.database.getRedemption(id)
    this.inFlight.add(id)
    try {
      const attemptState = await this.database.beginAttempt(id)
      if (!attemptState) return this.database.getRedemption(id)
      try {
        const result = await this.sub2api.fulfill(attemptState.redemption)
        return await this.database.completeAttemptSuccess(id, attemptState.attempt, result)
      } catch (error) {
        const failure = error instanceof UpstreamError
          ? error
          : new UpstreamError('未知履约错误', { retryable: true })
        this.logger.error?.(JSON.stringify({
          event: 'redemption_fulfillment_failed',
          redemption_id: id,
          attempt: attemptState.attempt,
          reason: failure.reason,
          retryable: failure.retryable,
        }))
        return await this.database.completeAttemptFailure(
          id,
          attemptState.attempt,
          failure,
          this.config.maxAttempts,
        )
      }
    } finally {
      this.inFlight.delete(id)
    }
  }

  async retry(id, actor) {
    const queued = await this.database.forceRetry(id, actor)
    if (queued.kind === 'not_found') {
      throw new AppError(404, 'REDEMPTION_NOT_FOUND', '兑换记录不存在')
    }
    if (queued.kind === 'succeeded') return queued.redemption
    return this.fulfill(id)
  }

  async runRetries() {
    for (const id of await this.database.dueRetries(10)) {
      await this.fulfill(id)
    }
  }

  startRetryWorker() {
    if (this.retryTimer) return
    this.retryTimer = setInterval(() => {
      this.runRetries().catch((error) => {
        this.logger.error?.(JSON.stringify({
          event: 'retry_worker_failed',
          message: error?.message || 'unknown error',
        }))
      })
    }, this.config.retryIntervalMs)
    this.retryTimer.unref()
  }

  stopRetryWorker() {
    if (this.retryTimer) clearInterval(this.retryTimer)
    this.retryTimer = null
  }
}
