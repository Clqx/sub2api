import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import pg from 'pg'
import { formatAmountMicros, randomID } from './security.mjs'

const { Pool } = pg
const MIGRATION_LOCK_ID = 725_331_902

function nowISO() {
  return new Date().toISOString()
}

function plain(row) {
  if (!row) return null
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [
    key,
    value instanceof Date ? value.toISOString() : value,
  ]))
}

function numeric(value) {
  return value == null ? null : Number(value)
}

function clampPage(value, fallback = 1) {
  const parsed = Number.parseInt(value, 10)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

function displayCode(row) {
  if (!row) return null
  const result = plain(row)
  return {
    ...result,
    value: formatAmountMicros(result.value_micros),
    value_micros: undefined,
    group_id: numeric(result.group_id),
    validity_days: numeric(result.validity_days),
    claimed_by_user_id: numeric(result.claimed_by_user_id),
  }
}

function displayProduct(row) {
  if (!row) return null
  const result = plain(row)
  return {
    ...result,
    price: formatAmountMicros(result.price_micros),
    price_micros: undefined,
    value: formatAmountMicros(result.value_micros),
    value_micros: undefined,
    group_id: numeric(result.group_id),
    validity_days: numeric(result.validity_days),
    sort_order: Number(result.sort_order || 0),
  }
}

function displayPublicProduct(row) {
  const product = displayProduct(row)
  if (!product) return null
  return {
    id: product.id,
    sku: product.sku,
    name: product.name,
    description: product.description,
    price: product.price,
    currency: product.currency,
    benefit_type: product.benefit_type,
    value: product.value,
    group_id: product.group_id,
    validity_days: product.validity_days,
    purchase_url: product.purchase_url,
    icon_url: product.icon_url,
  }
}

function displayRedemption(row) {
  if (!row) return null
  const result = plain(row)
  return {
    ...result,
    value: formatAmountMicros(result.value_micros),
    value_micros: undefined,
    user_id: numeric(result.user_id),
    group_id: numeric(result.group_id),
    validity_days: numeric(result.validity_days),
    attempt_count: Number(result.attempt_count || 0),
    retryable: Boolean(result.retryable),
  }
}

function whereFromFilters(filters = {}, { alias = 'r' } = {}) {
  const clauses = []
  const params = []
  const add = (clause, ...values) => {
    clauses.push(clause.replaceAll('?', () => {
      params.push(values.shift())
      return `$${params.length}`
    }))
  }
  if (filters.status) add(`${alias}.status = ?`, filters.status)
  if (filters.type) add(`${alias}.benefit_type = ?`, filters.type)
  if (filters.from) add(`${alias}.created_at >= ?`, filters.from)
  if (filters.to) add(`${alias}.created_at < ?`, filters.to)
  if (filters.search) {
    const needle = `%${String(filters.search).slice(0, 100)}%`
    add(`(
      ${alias}.user_email ILIKE ?
      OR CAST(${alias}.user_id AS TEXT) ILIKE ?
      OR ${alias}.upstream_code ILIKE ?
      OR c.code_mask ILIKE ?
      OR c.campaign ILIKE ?
    )`, needle, needle, needle, needle, needle)
  }
  return {
    sql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  }
}

export class RedeemDatabase {
  constructor(databaseConfig, migrationDir, { PoolClass = Pool } = {}) {
    this.pool = new PoolClass(databaseConfig)
    this.migrationDir = migrationDir
  }

  async initialize() {
    await this.pool.query('SELECT 1')
    await this.migrate()
    await this.recoverInterrupted()
  }

  async migrate() {
    const client = await this.pool.connect()
    try {
      await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID])
      await client.query(`
        CREATE TABLE IF NOT EXISTS redeem_schema_migrations (
          filename TEXT PRIMARY KEY,
          checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `)
      const files = fs.readdirSync(this.migrationDir)
        .filter((name) => /^\d+.*\.sql$/.test(name))
        .sort()
      for (const filename of files) {
        const sql = fs.readFileSync(path.join(this.migrationDir, filename), 'utf8').trim()
        const checksum = createHash('sha256').update(sql).digest('hex')
        const existing = await client.query(
          'SELECT checksum FROM redeem_schema_migrations WHERE filename = $1',
          [filename],
        )
        if (existing.rowCount) {
          if (existing.rows[0].checksum !== checksum) {
            throw new Error(`migration checksum mismatch: ${filename}`)
          }
          continue
        }
        await client.query('BEGIN')
        try {
          await client.query(sql)
          await client.query(
            'INSERT INTO redeem_schema_migrations (filename, checksum) VALUES ($1, $2)',
            [filename, checksum],
          )
          await client.query('COMMIT')
        } catch (error) {
          await client.query('ROLLBACK')
          throw error
        }
      }
    } finally {
      try {
        await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID])
      } finally {
        client.release()
      }
    }
  }

  async health() {
    await this.pool.query('SELECT 1')
  }

  async close() {
    await this.pool.end()
  }

  async transaction(callback) {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      const result = await callback(client)
      await client.query('COMMIT')
      return result
    } catch (error) {
      try {
        await client.query('ROLLBACK')
      } catch {
        // Preserve the original failure.
      }
      throw error
    } finally {
      client.release()
    }
  }

  async audit(client, actor, action, targetType, targetID = '', metadata = {}) {
    await client.query(`
      INSERT INTO audit_events (actor, action, target_type, target_id, metadata_json, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [actor, action, targetType, targetID, metadata, nowISO()])
  }

  async insertCodes(records, actor) {
    const createdAt = nowISO()
    await this.transaction(async (client) => {
      for (const record of records) {
        await client.query(`
          INSERT INTO redeem_codes (
            id, code_hash, code_mask, product_id, benefit_type, value_micros, group_id,
            validity_days, status, campaign, notes, expires_at, created_by,
            created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'unused', $9, $10, $11, $12, $13, $14)
        `, [
          record.id, record.codeHash, record.codeMask, record.productID, record.benefitType,
          record.valueMicros, record.groupID, record.validityDays, record.campaign,
          record.notes, record.expiresAt, actor, createdAt, createdAt,
        ])
      }
      await this.audit(client, actor, 'codes.generate', 'redeem_code_batch', '', {
        count: records.length,
        product_id: records[0]?.productID || '',
        benefit_type: records[0]?.benefitType || '',
        campaign: records[0]?.campaign || '',
      })
    })
    return records.map((record) => ({
      id: record.id,
      code: record.code,
      code_mask: record.codeMask,
      product_id: record.productID,
      product_name: record.productName,
      product_sku: record.productSKU,
      benefit_type: record.benefitType,
      value: formatAmountMicros(record.valueMicros),
      group_id: record.groupID,
      validity_days: record.validityDays,
      expires_at: record.expiresAt,
      campaign: record.campaign,
    }))
  }

  async listCodes(filters = {}) {
    const page = clampPage(filters.page)
    const pageSize = Math.min(clampPage(filters.pageSize, 20), 100)
    const clauses = []
    const params = []
    if (filters.status) {
      params.push(filters.status)
      clauses.push(`c.status = $${params.length}`)
    }
    if (filters.type) {
      params.push(filters.type)
      clauses.push(`c.benefit_type = $${params.length}`)
    }
    if (filters.search) {
      const needle = `%${String(filters.search).slice(0, 100)}%`
      params.push(needle)
      clauses.push(`(c.code_mask ILIKE $${params.length} OR c.campaign ILIKE $${params.length} OR c.notes ILIKE $${params.length} OR p.name ILIKE $${params.length} OR p.sku ILIKE $${params.length})`)
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
    const totalResult = await this.pool.query(`
      SELECT COUNT(*) AS total FROM redeem_codes c
      LEFT JOIN products p ON p.id = c.product_id ${where}
    `, params)
    const total = Number(totalResult.rows[0].total)
    const rows = await this.pool.query(`
      SELECT c.*, p.name AS product_name, p.sku AS product_sku
      FROM redeem_codes c
      LEFT JOIN products p ON p.id = c.product_id
      ${where}
      ORDER BY c.created_at DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, pageSize, (page - 1) * pageSize])
    return {
      items: rows.rows.map(displayCode),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  async listProducts({ publicOnly = false } = {}) {
    const result = await this.pool.query(`
      SELECT * FROM products
      ${publicOnly ? "WHERE status = 'active'" : ''}
      ORDER BY sort_order ASC, created_at DESC
    `)
    return result.rows.map(publicOnly ? displayPublicProduct : displayProduct)
  }

  async getProduct(id, queryable = this.pool) {
    const result = await queryable.query('SELECT * FROM products WHERE id = $1', [id])
    return displayProduct(result.rows[0])
  }

  async insertProduct(product, actor) {
    const at = nowISO()
    try {
      return await this.transaction(async (client) => {
        const result = await client.query(`
          INSERT INTO products (
            id, sku, name, description, price_micros, currency, benefit_type,
            value_micros, group_id, validity_days, purchase_url, icon_url, status,
            sort_order, created_by, created_at, updated_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
          ) RETURNING *
        `, [
          product.id, product.sku, product.name, product.description, product.priceMicros,
          product.currency, product.benefitType, product.valueMicros, product.groupID,
          product.validityDays, product.purchaseURL, product.iconURL, product.status, product.sortOrder,
          actor, at, at,
        ])
        await this.audit(client, actor, 'product.create', 'product', product.id, {
          sku: product.sku,
          status: product.status,
        })
        return { kind: 'created', product: displayProduct(result.rows[0]) }
      })
    } catch (error) {
      if (error?.code === '23505') return { kind: 'duplicate' }
      throw error
    }
  }

  async updateProduct(id, product, actor) {
    try {
      return await this.transaction(async (client) => {
        const found = await client.query('SELECT status FROM products WHERE id = $1 FOR UPDATE', [id])
        if (!found.rowCount) return { kind: 'not_found' }
        const result = await client.query(`
          UPDATE products SET
            sku = $1, name = $2, description = $3, price_micros = $4,
            currency = $5, benefit_type = $6, value_micros = $7, group_id = $8,
            validity_days = $9, purchase_url = $10, icon_url = $11, status = $12,
            sort_order = $13, updated_at = $14
          WHERE id = $15 RETURNING *
        `, [
          product.sku, product.name, product.description, product.priceMicros,
          product.currency, product.benefitType, product.valueMicros, product.groupID,
          product.validityDays, product.purchaseURL, product.iconURL, product.status, product.sortOrder,
          nowISO(), id,
        ])
        await this.audit(client, actor, 'product.update', 'product', id, {
          sku: product.sku,
          previous_status: found.rows[0].status,
          status: product.status,
        })
        return { kind: 'updated', product: displayProduct(result.rows[0]) }
      })
    } catch (error) {
      if (error?.code === '23505') return { kind: 'duplicate' }
      throw error
    }
  }

  async disableCode(id, actor) {
    return this.transaction(async (client) => {
      const found = await client.query('SELECT * FROM redeem_codes WHERE id = $1 FOR UPDATE', [id])
      const existing = plain(found.rows[0])
      if (!existing) return { kind: 'not_found' }
      if (existing.status !== 'unused') return { kind: 'conflict', status: existing.status }
      const at = nowISO()
      await client.query("UPDATE redeem_codes SET status = 'disabled', updated_at = $1 WHERE id = $2", [at, id])
      await this.audit(client, actor, 'code.disable', 'redeem_code', id, {
        previous_status: existing.status,
      })
      return { kind: 'disabled', code: displayCode({ ...existing, status: 'disabled', updated_at: at }) }
    })
  }

  async claimCode({ codeHash, user }) {
    return this.transaction(async (client) => {
      const found = await client.query('SELECT * FROM redeem_codes WHERE code_hash = $1 FOR UPDATE', [codeHash])
      const code = plain(found.rows[0])
      if (!code) return { kind: 'not_found' }

      const existingResult = await client.query(`
        SELECT r.*, c.code_mask, c.campaign, c.product_id,
          p.name AS product_name, p.sku AS product_sku
        FROM redemptions r
        JOIN redeem_codes c ON c.id = r.code_id
        LEFT JOIN products p ON p.id = c.product_id
        WHERE r.code_id = $1
      `, [code.id])
      const existing = plain(existingResult.rows[0])
      if (existing) {
        if (Number(existing.user_id) !== Number(user.id)) return { kind: 'claimed_by_other' }
        return { kind: 'existing', redemption: displayRedemption(existing) }
      }

      if (code.status === 'disabled') return { kind: 'disabled' }
      if (code.status !== 'unused') return { kind: 'unavailable', status: code.status }
      if (code.expires_at && new Date(code.expires_at).getTime() <= Date.now()) {
        await client.query("UPDATE redeem_codes SET status = 'disabled', updated_at = $1 WHERE id = $2", [nowISO(), code.id])
        return { kind: 'expired' }
      }

      const id = randomID()
      const compactID = id.replaceAll('-', '')
      const at = nowISO()
      await client.query(`
        INSERT INTO redemptions (
          id, code_id, user_id, user_email, benefit_type, value_micros,
          group_id, validity_days, status, idempotency_key, upstream_code,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $12)
      `, [
        id, code.id, user.id, user.email || '', code.benefit_type, code.value_micros,
        code.group_id, code.validity_days, `rp-${compactID}`, `rp${compactID.slice(0, 30)}`, at, at,
      ])
      await client.query(`
        UPDATE redeem_codes
        SET status = 'processing', claimed_by_user_id = $1, updated_at = $2
        WHERE id = $3
      `, [user.id, at, code.id])
      await this.audit(client, `user:${user.id}`, 'redemption.claim', 'redemption', id, {
        code_id: code.id,
        benefit_type: code.benefit_type,
      })
      return { kind: 'claimed', redemption: await this.getRedemption(id, client) }
    })
  }

  async getRedemption(id, queryable = this.pool) {
    const result = await queryable.query(`
      SELECT r.*, c.code_mask, c.campaign, c.notes, c.product_id,
        p.name AS product_name, p.sku AS product_sku
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      LEFT JOIN products p ON p.id = c.product_id
      WHERE r.id = $1
    `, [id])
    return displayRedemption(result.rows[0])
  }

  async getRedemptionDetail(id) {
    const redemption = await this.getRedemption(id)
    if (!redemption) return null
    const attempts = await this.pool.query(`
      SELECT * FROM redemption_attempts
      WHERE redemption_id = $1
      ORDER BY attempt_no DESC
    `, [id])
    return {
      ...redemption,
      attempts: attempts.rows.map((row) => ({
        ...plain(row),
        id: Number(row.id),
        attempt_no: Number(row.attempt_no),
      })),
    }
  }

  async beginAttempt(id) {
    return this.transaction(async (client) => {
      const found = await client.query('SELECT * FROM redemptions WHERE id = $1 FOR UPDATE', [id])
      const row = plain(found.rows[0])
      if (!row || !['pending', 'retryable'].includes(row.status)) return null
      const attempt = Number(row.attempt_count) + 1
      const at = nowISO()
      await client.query(`
        UPDATE redemptions
        SET status = 'processing', attempt_count = $1, started_at = COALESCE(started_at, $2),
            next_retry_at = NULL, updated_at = $3
        WHERE id = $4
      `, [attempt, at, at, id])
      await client.query(`
        INSERT INTO redemption_attempts (redemption_id, attempt_no, status, created_at)
        VALUES ($1, $2, 'processing', $3)
      `, [id, attempt, at])
      return { redemption: await this.getRedemption(id, client), attempt }
    })
  }

  async completeAttemptSuccess(id, attempt, result) {
    const at = nowISO()
    return this.transaction(async (client) => {
      const found = await client.query(`
        SELECT code_id, user_id, status FROM redemptions WHERE id = $1 FOR UPDATE
      `, [id])
      const current = found.rows[0]
      if (!current) return null
      const completed = await client.query(`
        UPDATE redemption_attempts
        SET status = 'succeeded', http_status = $1, reason = $2,
            latency_ms = $3, completed_at = $4
        WHERE redemption_id = $5 AND attempt_no = $6 AND status = 'processing'
        RETURNING id
      `, [result.httpStatus || 200, result.reason || '', result.latencyMs || 0, at, id, attempt])
      if (!completed.rowCount || current.status === 'succeeded') {
        return this.getRedemption(id, client)
      }
      await client.query(`
        UPDATE redemptions
        SET status = 'succeeded', retryable = FALSE, upstream_http_status = $1,
            upstream_reason = $2, upstream_response = $3, last_error = '',
            next_retry_at = NULL, completed_at = $4, updated_at = $5
        WHERE id = $6
      `, [result.httpStatus || 200, result.reason || '', result.data || {}, at, at, id])
      await client.query(`
        UPDATE redeem_codes SET status = 'redeemed', redeemed_at = $1, updated_at = $2
        WHERE id = $3
      `, [at, at, current.code_id])
      await this.audit(client, `system:user:${current.user_id}`, 'redemption.succeeded', 'redemption', id, { attempt })
      return this.getRedemption(id, client)
    })
  }

  async completeAttemptFailure(id, attempt, failure, maxAttempts) {
    const at = nowISO()
    return this.transaction(async (client) => {
      const found = await client.query(`
        SELECT code_id, user_id, status, attempt_count FROM redemptions WHERE id = $1 FOR UPDATE
      `, [id])
      const current = found.rows[0]
      if (!current) return null
      const completed = await client.query(`
        UPDATE redemption_attempts
        SET status = 'failed', http_status = $1, reason = $2, latency_ms = $3,
            error_message = $4, completed_at = $5
        WHERE redemption_id = $6 AND attempt_no = $7 AND status = 'processing'
        RETURNING id
      `, [
        failure.httpStatus || null, failure.reason || '', failure.latencyMs || 0,
        String(failure.message || 'upstream request failed').slice(0, 1000), at, id, attempt,
      ])
      if (
        !completed.rowCount
        || current.status !== 'processing'
        || Number(current.attempt_count) !== Number(attempt)
      ) {
        return this.getRedemption(id, client)
      }
      const canRetry = Boolean(failure.retryable) && Number(current.attempt_count) < maxAttempts
      const delaySeconds = Math.min(300, 5 * (2 ** Math.max(0, attempt - 1)))
      const nextRetryAt = canRetry ? new Date(Date.now() + delaySeconds * 1000).toISOString() : null
      await client.query(`
        UPDATE redemptions
        SET status = $1, retryable = $2, upstream_http_status = $3,
            upstream_reason = $4, upstream_response = $5, last_error = $6,
            next_retry_at = $7, updated_at = $8
        WHERE id = $9
      `, [
        canRetry ? 'retryable' : 'failed', canRetry, failure.httpStatus || null,
        failure.reason || '', failure.response || {},
        String(failure.message || 'upstream request failed').slice(0, 1000),
        nextRetryAt, at, id,
      ])
      await client.query("UPDATE redeem_codes SET status = 'failed', updated_at = $1 WHERE id = $2", [at, current.code_id])
      await this.audit(client, 'system', 'redemption.failed', 'redemption', id, {
        attempt,
        retryable: canRetry,
        reason: failure.reason || '',
      })
      return this.getRedemption(id, client)
    })
  }

  async recoverInterrupted() {
    const at = nowISO()
    await this.transaction(async (client) => {
      await client.query(`
        UPDATE redemption_attempts AS a
        SET status = 'failed', reason = 'SERVICE_INTERRUPTED',
            error_message = 'service restarted during fulfillment', completed_at = $1
        FROM redemptions AS r
        WHERE a.redemption_id = r.id
          AND a.status = 'processing'
          AND r.status = 'processing'
      `, [at])
      await client.query(`
        UPDATE redemptions
        SET status = 'retryable', retryable = TRUE, next_retry_at = $1,
            last_error = CASE
              WHEN last_error = '' THEN 'service restarted during fulfillment'
              ELSE last_error
            END,
            updated_at = $2
        WHERE status = 'processing'
      `, [at, at])
      await client.query(`
        UPDATE redeem_codes
        SET status = 'failed', updated_at = $1
        WHERE status = 'processing'
          AND id IN (SELECT code_id FROM redemptions WHERE status = 'retryable')
      `, [at])
    })
  }

  async dueRetries(limit = 10) {
    const result = await this.pool.query(`
      SELECT id FROM redemptions
      WHERE status = 'retryable' AND retryable = TRUE
        AND (next_retry_at IS NULL OR next_retry_at <= $1)
      ORDER BY next_retry_at ASC NULLS FIRST
      LIMIT $2
    `, [nowISO(), limit])
    return result.rows.map((row) => String(row.id))
  }

  async forceRetry(id, actor) {
    return this.transaction(async (client) => {
      const found = await client.query('SELECT * FROM redemptions WHERE id = $1 FOR UPDATE', [id])
      const row = plain(found.rows[0])
      if (!row) return { kind: 'not_found' }
      if (row.status === 'succeeded') return { kind: 'succeeded', redemption: displayRedemption(row) }
      const at = nowISO()
      await client.query(`
        UPDATE redemptions
        SET status = 'retryable', retryable = TRUE, next_retry_at = $1, updated_at = $2
        WHERE id = $3
      `, [at, at, id])
      await this.audit(client, actor, 'redemption.retry', 'redemption', id, {
        previous_status: row.status,
      })
      return { kind: 'queued', redemption: await this.getRedemption(id, client) }
    })
  }

  async listUserRedemptions(userID, pageValue = 1, pageSizeValue = 20) {
    const page = clampPage(pageValue)
    const pageSize = Math.min(clampPage(pageSizeValue, 20), 50)
    const totalResult = await this.pool.query('SELECT COUNT(*) AS total FROM redemptions WHERE user_id = $1', [userID])
    const total = Number(totalResult.rows[0].total)
    const rows = await this.pool.query(`
      SELECT r.*, c.code_mask, c.campaign, c.product_id,
        p.name AS product_name, p.sku AS product_sku
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      LEFT JOIN products p ON p.id = c.product_id
      WHERE r.user_id = $1
      ORDER BY r.created_at DESC
      LIMIT $2 OFFSET $3
    `, [userID, pageSize, (page - 1) * pageSize])
    return {
      items: rows.rows.map(displayRedemption),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  async listRedemptions(filters = {}) {
    const page = clampPage(filters.page)
    const pageSize = Math.min(clampPage(filters.pageSize, 25), 100)
    const where = whereFromFilters(filters)
    const totalResult = await this.pool.query(`
      SELECT COUNT(*) AS total
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      ${where.sql}
    `, where.params)
    const total = Number(totalResult.rows[0].total)
    const rows = await this.pool.query(`
      SELECT r.*, c.code_mask, c.campaign, c.product_id,
        p.name AS product_name, p.sku AS product_sku
      FROM redemptions r
      JOIN redeem_codes c ON c.id = r.code_id
      LEFT JOIN products p ON p.id = c.product_id
      ${where.sql}
      ORDER BY r.created_at DESC
      LIMIT $${where.params.length + 1} OFFSET $${where.params.length + 2}
    `, [...where.params, pageSize, (page - 1) * pageSize])
    return {
      items: rows.rows.map(displayRedemption),
      total,
      page,
      page_size: pageSize,
      pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  }

  async analytics(filters = {}) {
    const where = whereFromFilters(filters)
    const baseJoin = 'FROM redemptions r JOIN redeem_codes c ON c.id = r.code_id'
    const totalsResult = await this.pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE r.status = 'succeeded') AS succeeded,
        COUNT(*) FILTER (WHERE r.status IN ('pending', 'processing', 'retryable')) AS pending,
        COUNT(*) FILTER (WHERE r.status = 'failed') AS failed,
        COALESCE(SUM(r.value_micros) FILTER (
          WHERE r.status = 'succeeded' AND r.benefit_type = 'balance'
        ), 0) AS balance_micros,
        COALESCE(SUM(r.validity_days) FILTER (
          WHERE r.status = 'succeeded' AND r.benefit_type = 'subscription'
        ), 0) AS subscription_days
      ${baseJoin}
      ${where.sql}
    `, where.params)
    const totals = totalsResult.rows[0]
    const trendResult = await this.pool.query(`
      SELECT
        TO_CHAR(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE r.status = 'succeeded') AS succeeded,
        COUNT(*) FILTER (WHERE r.benefit_type = 'balance' AND r.status = 'succeeded') AS balance_count,
        COUNT(*) FILTER (WHERE r.benefit_type = 'subscription' AND r.status = 'succeeded') AS subscription_count
      ${baseJoin}
      ${where.sql}
      GROUP BY day
      ORDER BY day ASC
      LIMIT 90
    `, where.params)
    const statusResult = await this.pool.query(`
      SELECT r.status, COUNT(*) AS count ${baseJoin} ${where.sql}
      GROUP BY r.status ORDER BY count DESC
    `, where.params)
    const groupsResult = await this.pool.query(`
      SELECT r.group_id, COUNT(*) AS redemptions, COALESCE(SUM(r.validity_days), 0) AS validity_days
      ${baseJoin}
      ${where.sql}${where.sql ? ' AND' : ' WHERE'} r.status = 'succeeded'
        AND r.benefit_type = 'subscription'
      GROUP BY r.group_id ORDER BY redemptions DESC LIMIT 10
    `, where.params)
    const campaignsResult = await this.pool.query(`
      SELECT COALESCE(NULLIF(c.campaign, ''), '未分类') AS campaign,
        COUNT(*) AS redemptions,
        COUNT(*) FILTER (WHERE r.status = 'succeeded') AS succeeded
      ${baseJoin}
      ${where.sql}
      GROUP BY COALESCE(NULLIF(c.campaign, ''), '未分类')
      ORDER BY redemptions DESC LIMIT 10
    `, where.params)
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
      trend: trendResult.rows.map((row) => ({
        ...row,
        total: Number(row.total),
        succeeded: Number(row.succeeded),
        balance_count: Number(row.balance_count),
        subscription_count: Number(row.subscription_count),
      })),
      statuses: statusResult.rows.map((row) => ({ ...row, count: Number(row.count) })),
      groups: groupsResult.rows.map((row) => ({
        ...row,
        group_id: numeric(row.group_id),
        redemptions: Number(row.redemptions),
        validity_days: Number(row.validity_days),
      })),
      campaigns: campaignsResult.rows.map((row) => ({
        ...row,
        redemptions: Number(row.redemptions),
        succeeded: Number(row.succeeded),
      })),
    }
  }

  async auditEvents(limit = 50) {
    const result = await this.pool.query(`
      SELECT * FROM audit_events ORDER BY created_at DESC LIMIT $1
    `, [Math.min(clampPage(limit, 50), 200)])
    return result.rows.map((row) => ({
      ...plain(row),
      id: Number(row.id),
      metadata: row.metadata_json || {},
      metadata_json: undefined,
    }))
  }
}
