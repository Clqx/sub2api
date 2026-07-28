import fs from 'node:fs'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { formatAmountMicros, randomID } from './security.mjs'

function nowISO() {
  return new Date().toISOString()
}

function plain(row) {
  return row ? { ...row } : null
}

function clampPage(value, fallback = 1) {
  const parsed = Number.parseInt(value, 10)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

function displayCode(row) {
  if (!row) return null
  return {
    ...plain(row),
    value: formatAmountMicros(row.value_micros),
    value_micros: undefined,
    claimed_by_user_id: row.claimed_by_user_id || null,
  }
}

function displayRedemption(row) {
  if (!row) return null
  return {
    ...plain(row),
    value: formatAmountMicros(row.value_micros),
    value_micros: undefined,
    retryable: Boolean(row.retryable),
  }
}

function whereFromFilters(filters = {}, { alias = 'r' } = {}) {
  const clauses = []
  const params = []
  if (filters.status) {
    clauses.push(`${alias}.status = ?`)
    params.push(filters.status)
  }
  if (filters.type) {
    clauses.push(`${alias}.benefit_type = ?`)
    params.push(filters.type)
  }
  if (filters.from) {
    clauses.push(`${alias}.created_at >= ?`)
    params.push(filters.from)
  }
  if (filters.to) {
    clauses.push(`${alias}.created_at < ?`)
    params.push(filters.to)
  }
  if (filters.search) {
    clauses.push(`(
      ${alias}.user_email LIKE ?
      OR CAST(${alias}.user_id AS TEXT) LIKE ?
      OR ${alias}.upstream_code LIKE ?
      OR c.code_mask LIKE ?
      OR c.campaign LIKE ?
    )`)
    const needle = `%${String(filters.search).slice(0, 100)}%`
    params.push(needle, needle, needle, needle, needle)
  }
  return {
    sql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  }
}

export class RedeemDatabase {
  constructor(databasePath, migrationDir) {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true })
    this.db = new DatabaseSync(databasePath)
    this.db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
    this.migrate(migrationDir)
    this.recoverInterrupted()
  }

  migrate(migrationDir) {
    const files = fs.readdirSync(migrationDir)
      .filter((name) => /^\d+.*\.sql$/.test(name))
      .sort()
    for (const file of files) {
      this.db.exec(fs.readFileSync(path.join(migrationDir, file), 'utf8'))
    }
  }

  close() {
    this.db.close()
  }

  transaction(callback) {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const result = callback()
      this.db.exec('COMMIT')
      return result
    } catch (error) {
      try {
        this.db.exec('ROLLBACK')
      } catch {
        // Preserve the original failure.
      }
      throw error
    }
  }

  audit(actor, action, targetType, targetID = '', metadata = {}) {
    this.db.prepare(`
      INSERT INTO audit_events (actor, action, target_type, target_id, metadata_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(actor, action, targetType, targetID, JSON.stringify(metadata), nowISO())
  }

  insertCodes(records, actor) {
    const insert = this.db.prepare(`
      INSERT INTO redeem_codes (
        id, code_hash, code_mask, benefit_type, value_micros, group_id,
        validity_days, status, campaign, notes, expires_at, created_by,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'unused', ?, ?, ?, ?, ?, ?)
    `)
    const createdAt = nowISO()
    this.transaction(() => {
      for (const record of records) {
        insert.run(
          record.id,
          record.codeHash,
          record.codeMask,
          record.benefitType,
          record.valueMicros,
          record.groupID,
          record.validityDays,
          record.campaign,
          record.notes,
          record.expiresAt,
          actor,
          createdAt,
          createdAt,
        )
      }
      this.audit(actor, 'codes.generate', 'redeem_code_batch', '', {
        count: records.length,
        benefit_type: records[0]?.benefitType || '',
        campaign: records[0]?.campaign || '',
      })
    })
    return records.map((record) => ({
      id: record.id,
      code: record.code,
      code_mask: record.codeMask,
      benefit_type: record.benefitType,
      value: formatAmountMicros(record.valueMicros),
      group_id: record.groupID,
      validity_days: record.validityDays,
      expires_at: record.expiresAt,
      campaign: record.campaign,
    }))
  }

  listCodes(filters = {}) {
    const page = clampPage(filters.page)
    const pageSize = Math.min(clampPage(filters.pageSize, 20), 100)
    const clauses = []
    const params = []
    if (filters.status) {
      clauses.push('status = ?')
      params.push(filters.status)
    }
    if (filters.type) {
      clauses.push('benefit_type = ?')
      params.push(filters.type)
    }
    if (filters.search) {
      clauses.push('(code_mask LIKE ? OR campaign LIKE ? OR notes LIKE ?)')
      const needle = `%${String(filters.search).slice(0, 100)}%`
      params.push(needle, needle, needle)
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
    const total = Number(this.db.prepare(`SELECT COUNT(*) AS total FROM redeem_codes ${where}`)
      .get(...params).total)
    const rows = this.db.prepare(`
      SELECT * FROM redeem_codes
      ${where}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, pageSize, (page - 1) * pageSize)
    return {
      items: rows.map(displayCode),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  disableCode(id, actor) {
    return this.transaction(() => {
      const existing = plain(this.db.prepare('SELECT * FROM redeem_codes WHERE id = ?').get(id))
      if (!existing) return { kind: 'not_found' }
      if (existing.status !== 'unused') {
        return { kind: 'conflict', status: existing.status }
      }
      const at = nowISO()
      this.db.prepare(`
        UPDATE redeem_codes SET status = 'disabled', updated_at = ? WHERE id = ?
      `).run(at, id)
      this.audit(actor, 'code.disable', 'redeem_code', id, {
        previous_status: existing.status,
      })
      return { kind: 'disabled', code: displayCode({ ...existing, status: 'disabled', updated_at: at }) }
    })
  }

  claimCode({ codeHash, user }) {
    return this.transaction(() => {
      const code = plain(this.db.prepare('SELECT * FROM redeem_codes WHERE code_hash = ?').get(codeHash))
      if (!code) return { kind: 'not_found' }

      const existing = plain(this.db.prepare(`
        SELECT r.*, c.code_mask, c.campaign
        FROM redemptions r
        JOIN redeem_codes c ON c.id = r.code_id
        WHERE r.code_id = ?
      `).get(code.id))
      if (existing) {
        if (Number(existing.user_id) !== Number(user.id)) {
          return { kind: 'claimed_by_other' }
        }
        return { kind: 'existing', redemption: displayRedemption(existing) }
      }

      if (code.status === 'disabled') return { kind: 'disabled' }
      if (code.status !== 'unused') return { kind: 'unavailable', status: code.status }
      if (code.expires_at && new Date(code.expires_at).getTime() <= Date.now()) {
        this.db.prepare(`
          UPDATE redeem_codes SET status = 'disabled', updated_at = ? WHERE id = ?
        `).run(nowISO(), code.id)
        return { kind: 'expired' }
      }

      const id = randomID()
      const compactID = id.replaceAll('-', '')
      const at = nowISO()
      this.db.prepare(`
        INSERT INTO redemptions (
          id, code_id, user_id, user_email, benefit_type, value_micros,
          group_id, validity_days, status, idempotency_key, upstream_code,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
      `).run(
        id,
        code.id,
        user.id,
        user.email || '',
        code.benefit_type,
        code.value_micros,
        code.group_id,
        code.validity_days,
        `rp-${compactID}`,
        `rp_${compactID}`,
        at,
        at,
      )
      this.db.prepare(`
        UPDATE redeem_codes
        SET status = 'processing', claimed_by_user_id = ?, updated_at = ?
        WHERE id = ?
      `).run(user.id, at, code.id)
      this.audit(`user:${user.id}`, 'redemption.claim', 'redemption', id, {
        code_id: code.id,
        benefit_type: code.benefit_type,
      })
      return { kind: 'claimed', redemption: this.getRedemption(id) }
    })
  }

  getRedemption(id) {
    const row = this.db.prepare(`
      SELECT r.*, c.code_mask, c.campaign, c.notes
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      WHERE r.id = ?
    `).get(id)
    return displayRedemption(row)
  }

  getRedemptionDetail(id) {
    const redemption = this.getRedemption(id)
    if (!redemption) return null
    const attempts = this.db.prepare(`
      SELECT * FROM redemption_attempts
      WHERE redemption_id = ?
      ORDER BY attempt_no DESC
    `).all(id).map(plain)
    return { ...redemption, attempts }
  }

  beginAttempt(id) {
    return this.transaction(() => {
      const row = plain(this.db.prepare('SELECT * FROM redemptions WHERE id = ?').get(id))
      if (!row || row.status === 'succeeded') return null
      const attempt = Number(row.attempt_count) + 1
      const at = nowISO()
      this.db.prepare(`
        UPDATE redemptions
        SET status = 'processing', attempt_count = ?, started_at = COALESCE(started_at, ?),
            next_retry_at = NULL, updated_at = ?
        WHERE id = ?
      `).run(attempt, at, at, id)
      this.db.prepare(`
        INSERT INTO redemption_attempts (
          redemption_id, attempt_no, status, created_at
        ) VALUES (?, ?, 'processing', ?)
      `).run(id, attempt, at)
      return { redemption: this.getRedemption(id), attempt }
    })
  }

  completeAttemptSuccess(id, attempt, result) {
    const at = nowISO()
    return this.transaction(() => {
      this.db.prepare(`
        UPDATE redemption_attempts
        SET status = 'succeeded', http_status = ?, reason = ?,
            latency_ms = ?, completed_at = ?
        WHERE redemption_id = ? AND attempt_no = ?
      `).run(result.httpStatus || 200, result.reason || '', result.latencyMs || 0, at, id, attempt)
      this.db.prepare(`
        UPDATE redemptions
        SET status = 'succeeded', retryable = 0, upstream_http_status = ?,
            upstream_reason = ?, upstream_response = ?, last_error = '',
            next_retry_at = NULL, completed_at = ?, updated_at = ?
        WHERE id = ?
      `).run(
        result.httpStatus || 200,
        result.reason || '',
        JSON.stringify(result.data || {}),
        at,
        at,
        id,
      )
      const row = plain(this.db.prepare('SELECT code_id, user_id FROM redemptions WHERE id = ?').get(id))
      this.db.prepare(`
        UPDATE redeem_codes
        SET status = 'redeemed', redeemed_at = ?, updated_at = ?
        WHERE id = ?
      `).run(at, at, row.code_id)
      this.audit(`system:user:${row.user_id}`, 'redemption.succeeded', 'redemption', id, {
        attempt,
      })
      return this.getRedemption(id)
    })
  }

  completeAttemptFailure(id, attempt, failure, maxAttempts) {
    const at = nowISO()
    return this.transaction(() => {
      const current = plain(this.db.prepare(`
        SELECT code_id, user_id, attempt_count FROM redemptions WHERE id = ?
      `).get(id))
      if (!current) return null
      const canRetry = Boolean(failure.retryable) && Number(current.attempt_count) < maxAttempts
      const delaySeconds = Math.min(300, 5 * (2 ** Math.max(0, attempt - 1)))
      const nextRetryAt = canRetry
        ? new Date(Date.now() + delaySeconds * 1000).toISOString()
        : null
      this.db.prepare(`
        UPDATE redemption_attempts
        SET status = 'failed', http_status = ?, reason = ?, latency_ms = ?,
            error_message = ?, completed_at = ?
        WHERE redemption_id = ? AND attempt_no = ?
      `).run(
        failure.httpStatus || null,
        failure.reason || '',
        failure.latencyMs || 0,
        String(failure.message || 'upstream request failed').slice(0, 1000),
        at,
        id,
        attempt,
      )
      this.db.prepare(`
        UPDATE redemptions
        SET status = ?, retryable = ?, upstream_http_status = ?,
            upstream_reason = ?, upstream_response = ?, last_error = ?,
            next_retry_at = ?, updated_at = ?
        WHERE id = ?
      `).run(
        canRetry ? 'retryable' : 'failed',
        canRetry ? 1 : 0,
        failure.httpStatus || null,
        failure.reason || '',
        failure.response ? JSON.stringify(failure.response) : '',
        String(failure.message || 'upstream request failed').slice(0, 1000),
        nextRetryAt,
        at,
        id,
      )
      this.db.prepare(`
        UPDATE redeem_codes SET status = 'failed', updated_at = ? WHERE id = ?
      `).run(at, current.code_id)
      this.audit('system', 'redemption.failed', 'redemption', id, {
        attempt,
        retryable: canRetry,
        reason: failure.reason || '',
      })
      return this.getRedemption(id)
    })
  }

  recoverInterrupted() {
    const at = nowISO()
    this.transaction(() => {
      this.db.prepare(`
        UPDATE redemptions
        SET status = 'retryable', retryable = 1, next_retry_at = ?,
            last_error = CASE
              WHEN last_error = '' THEN 'service restarted during fulfillment'
              ELSE last_error
            END,
            updated_at = ?
        WHERE status = 'processing'
      `).run(at, at)
      this.db.prepare(`
        UPDATE redeem_codes
        SET status = 'failed', updated_at = ?
        WHERE status = 'processing'
          AND id IN (SELECT code_id FROM redemptions WHERE status = 'retryable')
      `).run(at)
    })
  }

  dueRetries(limit = 10) {
    return this.db.prepare(`
      SELECT id FROM redemptions
      WHERE status = 'retryable' AND retryable = 1
        AND (next_retry_at IS NULL OR next_retry_at <= ?)
      ORDER BY next_retry_at ASC
      LIMIT ?
    `).all(nowISO(), limit).map((row) => String(row.id))
  }

  forceRetry(id, actor) {
    return this.transaction(() => {
      const row = plain(this.db.prepare('SELECT * FROM redemptions WHERE id = ?').get(id))
      if (!row) return { kind: 'not_found' }
      if (row.status === 'succeeded') return { kind: 'succeeded', redemption: displayRedemption(row) }
      const at = nowISO()
      this.db.prepare(`
        UPDATE redemptions
        SET status = 'retryable', retryable = 1, next_retry_at = ?,
            updated_at = ?
        WHERE id = ?
      `).run(at, at, id)
      this.audit(actor, 'redemption.retry', 'redemption', id, {
        previous_status: row.status,
      })
      return { kind: 'queued', redemption: this.getRedemption(id) }
    })
  }

  listUserRedemptions(userID, pageValue = 1, pageSizeValue = 20) {
    const page = clampPage(pageValue)
    const pageSize = Math.min(clampPage(pageSizeValue, 20), 50)
    const total = Number(this.db.prepare(`
      SELECT COUNT(*) AS total FROM redemptions WHERE user_id = ?
    `).get(userID).total)
    const rows = this.db.prepare(`
      SELECT r.*, c.code_mask, c.campaign
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      WHERE r.user_id = ?
      ORDER BY r.created_at DESC
      LIMIT ? OFFSET ?
    `).all(userID, pageSize, (page - 1) * pageSize)
    return {
      items: rows.map(displayRedemption),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  listRedemptions(filters = {}) {
    const page = clampPage(filters.page)
    const pageSize = Math.min(clampPage(filters.pageSize, 25), 100)
    const where = whereFromFilters(filters)
    const total = Number(this.db.prepare(`
      SELECT COUNT(*) AS total
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      ${where.sql}
    `).get(...where.params).total)
    const rows = this.db.prepare(`
      SELECT r.*, c.code_mask, c.campaign
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      ${where.sql}
      ORDER BY r.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...where.params, pageSize, (page - 1) * pageSize)
    return {
      items: rows.map(displayRedemption),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  analytics(filters = {}) {
    const where = whereFromFilters(filters)
    const baseJoin = 'FROM redemptions r JOIN redeem_codes c ON c.id = r.code_id'
    const totals = plain(this.db.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN r.status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
        SUM(CASE WHEN r.status IN ('pending', 'processing', 'retryable') THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN r.status = 'failed' THEN 1 ELSE 0 END) AS failed,
        COALESCE(SUM(CASE
          WHEN r.status = 'succeeded' AND r.benefit_type = 'balance'
          THEN r.value_micros ELSE 0 END), 0) AS balance_micros,
        COALESCE(SUM(CASE
          WHEN r.status = 'succeeded' AND r.benefit_type = 'subscription'
          THEN r.validity_days ELSE 0 END), 0) AS subscription_days
      ${baseJoin}
      ${where.sql}
    `).get(...where.params))
    const trend = this.db.prepare(`
      SELECT
        substr(r.created_at, 1, 10) AS day,
        COUNT(*) AS total,
        SUM(CASE WHEN r.status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
        SUM(CASE WHEN r.benefit_type = 'balance' AND r.status = 'succeeded' THEN 1 ELSE 0 END) AS balance_count,
        SUM(CASE WHEN r.benefit_type = 'subscription' AND r.status = 'succeeded' THEN 1 ELSE 0 END) AS subscription_count
      ${baseJoin}
      ${where.sql}
      GROUP BY substr(r.created_at, 1, 10)
      ORDER BY day ASC
      LIMIT 90
    `).all(...where.params).map(plain)
    const statuses = this.db.prepare(`
      SELECT r.status, COUNT(*) AS count
      ${baseJoin}
      ${where.sql}
      GROUP BY r.status
      ORDER BY count DESC
    `).all(...where.params).map(plain)
    const groups = this.db.prepare(`
      SELECT r.group_id, COUNT(*) AS redemptions,
        COALESCE(SUM(r.validity_days), 0) AS validity_days
      ${baseJoin}
      ${where.sql}${where.sql ? ' AND' : ' WHERE'} r.status = 'succeeded'
        AND r.benefit_type = 'subscription'
      GROUP BY r.group_id
      ORDER BY redemptions DESC
      LIMIT 10
    `).all(...where.params).map(plain)
    const campaigns = this.db.prepare(`
      SELECT COALESCE(NULLIF(c.campaign, ''), '未分类') AS campaign,
        COUNT(*) AS redemptions,
        SUM(CASE WHEN r.status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded
      ${baseJoin}
      ${where.sql}
      GROUP BY COALESCE(NULLIF(c.campaign, ''), '未分类')
      ORDER BY redemptions DESC
      LIMIT 10
    `).all(...where.params).map(plain)
    const total = Number(totals.total || 0)
    const succeeded = Number(totals.succeeded || 0)
    return {
      total,
      succeeded,
      pending: Number(totals.pending || 0),
      failed: Number(totals.failed || 0),
      success_rate: total ? Number(((succeeded / total) * 100).toFixed(1)) : 0,
      balance_value: formatAmountMicros(Number(totals.balance_micros || 0)),
      subscription_days: Number(totals.subscription_days || 0),
      trend,
      statuses,
      groups,
      campaigns,
    }
  }

  auditEvents(limit = 50) {
    return this.db.prepare(`
      SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?
    `).all(Math.min(clampPage(limit, 50), 200)).map((row) => ({
      ...plain(row),
      metadata: JSON.parse(row.metadata_json || '{}'),
      metadata_json: undefined,
    }))
  }
}
