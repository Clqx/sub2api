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
    const benefitType = String(input.benefit_type || input.type || '')
    if (!['balance', 'subscription'].includes(benefitType)) {
      throw new AppError(400, 'INVALID_BENEFIT_TYPE', '权益类型无效')
    }
    let valueMicros
    try {
      valueMicros = parseAmountMicros(input.value, { allowNegative: false })
    } catch {
      throw new AppError(400, 'INVALID_VALUE', '记账金额必须是大于零的数字，最多六位小数')
    }

    let groupID = null
    let validityDays = null
    if (benefitType === 'subscription') {
      groupID = Number(input.group_id)
      validityDays = Number(input.validity_days)
      if (!Number.isInteger(groupID) || groupID <= 0) {
        throw new AppError(400, 'INVALID_GROUP_ID', '订阅兑换码必须选择有效分组')
      }
      if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 36500) {
        throw new AppError(400, 'INVALID_VALIDITY_DAYS', '订阅天数必须在 1 到 36500 之间')
      }
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

    const campaign = cleanText(input.campaign, 100)
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
