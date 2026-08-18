BEGIN;

-- Phase2-A 只补齐现有内存状态的持久化骨架，不生成 Recovery Root、Share 或 Manifest。

ALTER TABLE integration_operations
    ALTER COLUMN target_id DROP NOT NULL,
    ADD COLUMN target_external_id text,
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT' CHECK (
        migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE')
    ),
    ADD COLUMN request_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN fencing_token bigint NOT NULL DEFAULT 0,
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT ck_integration_operations_target_identity CHECK (
        target_id IS NOT NULL OR target_external_id IS NOT NULL
    ),
    ADD CONSTRAINT ck_integration_operations_target_external_id CHECK (
        target_external_id IS NULL OR length(trim(target_external_id)) BETWEEN 1 AND 128
    ),
    ADD CONSTRAINT ck_integration_operations_request_snapshot CHECK (
        jsonb_typeof(request_snapshot) = 'object'
    ),
    ADD CONSTRAINT ck_integration_operations_lease CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL) OR
        (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND
         length(trim(lease_owner)) BETWEEN 1 AND 128)
    ),
    ADD CONSTRAINT ck_integration_operations_fencing_token CHECK (fencing_token >= 0),
    ADD CONSTRAINT ck_integration_operations_version CHECK (version > 0);

-- 001 的 Pool/Seat 操作仍有内部 UUID 时可无损恢复公开 ID；其他旧目标不得伪造可重放身份。
UPDATE integration_operations io
SET target_external_id = pool.external_id
FROM pools pool
WHERE io.target_external_id IS NULL
  AND io.target_type = 'POOL'
  AND io.target_id = pool.id;

UPDATE integration_operations io
SET target_external_id = seat.external_id
FROM seats seat
WHERE io.target_external_id IS NULL
  AND io.target_type = 'SEAT'
  AND io.target_id = seat.id;

-- 旧记录的 request_snapshot 只能得到默认空对象，无法证明完整意图；即使目标可回填也禁止重放。
UPDATE integration_operations
SET migration_state = 'LEGACY_UNRECOVERABLE';

ALTER TABLE integration_operations
    ADD CONSTRAINT ck_integration_operations_migration_state CHECK (
        (migration_state = 'CURRENT' AND target_external_id IS NOT NULL AND
         request_snapshot <> '{}'::jsonb) OR
        (migration_state = 'LEGACY_UNRECOVERABLE' AND
         target_id IS NOT NULL AND request_snapshot = '{}'::jsonb)
    );

COMMENT ON COLUMN integration_operations.target_external_id IS
    '稳定公开目标 ID；Provision 在本地 Seat UUID 创建前依靠该字段建立幂等操作';
COMMENT ON COLUMN integration_operations.request_snapshot IS
    '去敏后的规范化请求快照；与 request_hash 一同构成不可变幂等意图';
COMMENT ON COLUMN integration_operations.migration_state IS
    '001 旧记录缺少完整请求快照时标记 LEGACY_UNRECOVERABLE；可保留已回填目标供诊断，但禁止重放';
COMMENT ON COLUMN integration_operations.fencing_token IS
    '每次租约换主必须严格递增，防止失效 worker 回写新状态';

CREATE INDEX idx_integration_operations_external_target
    ON integration_operations(target_type, target_external_id, created_at DESC)
    WHERE target_external_id IS NOT NULL;
CREATE INDEX idx_integration_operations_lease
    ON integration_operations(lease_expires_at, fencing_token)
    WHERE migration_state = 'CURRENT' AND lease_owner IS NOT NULL
      AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED');

ALTER TABLE seats
    ADD COLUMN owner_member_id uuid REFERENCES members(id) ON DELETE RESTRICT;

CREATE INDEX idx_seats_owner_member
    ON seats(owner_member_id, status) WHERE owner_member_id IS NOT NULL;

COMMENT ON COLUMN seats.owner_member_id IS
    'Seat 当前领取责任人；成员换位必须与 Assignment 和 claim 在同一业务事务中协调';

ALTER TABLE pools
    ADD COLUMN credential_epoch_floor integer NOT NULL DEFAULT 0
        CHECK (credential_epoch_floor >= 0);

COMMENT ON COLUMN pools.credential_epoch_floor IS
    '控制凭据最小可写 Membership Epoch；永久换员提交后只允许不低于该值的批次 Seal/Activate';

CREATE TABLE credential_claims (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_operation_id uuid NOT NULL UNIQUE
        REFERENCES integration_operations(id) ON DELETE RESTRICT,
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    target_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    claim_operation_id varchar(128) NOT NULL UNIQUE
        CHECK (length(trim(claim_operation_id)) BETWEEN 1 AND 128),
    status text NOT NULL DEFAULT 'READY' CHECK (
        status IN (
            'READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED',
            'CLAIMED', 'EXPIRED', 'REJECTED'
        )
    ),
    claim_intent_hash bytea NOT NULL CHECK (octet_length(claim_intent_hash) = 32),
    claim_token_hash bytea,
    credential_fingerprint bytea NOT NULL CHECK (octet_length(credential_fingerprint) = 32),
    envelope_algorithm text CHECK (
        envelope_algorithm IS NULL OR length(trim(envelope_algorithm)) BETWEEN 1 AND 64
    ),
    envelope_key_ref text CHECK (
        envelope_key_ref IS NULL OR length(trim(envelope_key_ref)) BETWEEN 1 AND 512
    ),
    envelope_ciphertext bytea,
    envelope_nonce bytea,
    envelope_aad_hash bytea CHECK (
        envelope_aad_hash IS NULL OR octet_length(envelope_aad_hash) = 32
    ),
    wrapped_dek_kms bytea,
    ack_response_snapshot jsonb CHECK (
        ack_response_snapshot IS NULL OR jsonb_typeof(ack_response_snapshot) = 'object'
    ),
    error_code text CHECK (error_code IS NULL OR length(trim(error_code)) BETWEEN 1 AND 128),
    expires_at timestamptz NOT NULL,
    lease_owner text,
    lease_expires_at timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    claimed_at timestamptz,
    terminal_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL) OR
        (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND
         length(trim(lease_owner)) BETWEEN 1 AND 128)
    ),
    CHECK (
        status NOT IN ('CLAIMED', 'EXPIRED', 'REJECTED') OR
        (lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK (
        (status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED') AND
         claim_token_hash IS NOT NULL AND octet_length(claim_token_hash) = 32 AND
         envelope_algorithm IS NOT NULL AND envelope_key_ref IS NOT NULL AND
         envelope_ciphertext IS NOT NULL AND octet_length(envelope_ciphertext) > 0 AND
         envelope_nonce IS NOT NULL AND octet_length(envelope_nonce) > 0 AND
         envelope_aad_hash IS NOT NULL AND
         wrapped_dek_kms IS NOT NULL AND octet_length(wrapped_dek_kms) > 0 AND
         terminal_at IS NULL AND claimed_at IS NULL) OR
        (status IN ('CLAIMED', 'EXPIRED', 'REJECTED') AND
         claim_token_hash IS NULL AND envelope_algorithm IS NULL AND
         envelope_key_ref IS NULL AND envelope_ciphertext IS NULL AND
         envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND
         wrapped_dek_kms IS NULL AND
         terminal_at IS NOT NULL AND
         ((status = 'CLAIMED' AND claimed_at IS NOT NULL) OR
          (status IN ('EXPIRED', 'REJECTED') AND claimed_at IS NULL)))
    )
);

COMMENT ON TABLE credential_claims IS
    '一次性凭据领取；只保存 token SHA-256 与 KMS 单包装包络，终态强制清除可交付秘密';
COMMENT ON COLUMN credential_claims.claim_operation_id IS
    '调用 Sub2API credential:ack 的稳定幂等操作 ID，重试和对账不得重新生成';
COMMENT ON COLUMN credential_claims.claim_intent_hash IS
    '规范化领取意图 SHA-256；终态保留用于清密后的幂等漂移检测，不包含可交付秘密';
COMMENT ON COLUMN credential_claims.wrapped_dek_kms IS
    '仅用于在线交付的 KMS 包装 DEK；本迁移不伪造 Recovery Root 双包装';
COMMENT ON COLUMN credential_claims.credential_fingerprint IS
    '凭据 SHA-256 指纹，用于核对 Sub2API ack；不等同于可恢复凭据';
COMMENT ON COLUMN credential_claims.ack_response_snapshot IS
    'Provision 上游成功后的七字段去敏快照；ACK_PENDING marker 可为空，非空及 CLAIMED 时严格复核';

CREATE INDEX idx_credential_claims_expiry
    ON credential_claims(expires_at, status)
    WHERE status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED');
CREATE INDEX idx_credential_claims_lease
    ON credential_claims(lease_expires_at, fencing_token)
    WHERE lease_owner IS NOT NULL;
CREATE INDEX idx_credential_claims_member_history
    ON credential_claims(target_member_id, created_at DESC);
CREATE INDEX idx_credential_claims_seat_history
    ON credential_claims(seat_id, created_at DESC);

-- 复合唯一键供轮换证据以一条 FK 固定批次范围和类型；状态在证据提交前动态复核。
ALTER TABLE credential_batches
    ADD CONSTRAINT uq_credential_batches_rotation_reference UNIQUE (
        id, pool_id, resource_account_ref, membership_epoch, batch_type
    );

CREATE TABLE control_rotation_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id text NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    resource_account_ref text NOT NULL
        CHECK (length(trim(resource_account_ref)) BETWEEN 1 AND 128),
    from_membership_epoch integer NOT NULL CHECK (from_membership_epoch > 0),
    to_membership_epoch integer NOT NULL CHECK (to_membership_epoch > 0),
    provider_attestation_ref text NOT NULL
        CHECK (length(trim(provider_attestation_ref)) BETWEEN 1 AND 512),
    status text NOT NULL DEFAULT 'ISSUED'
        CHECK (status IN ('ISSUED', 'COMMITTED', 'INVALIDATED')),
    committed_at timestamptz,
    invalidated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, pool_id, resource_account_ref, from_membership_epoch, to_membership_epoch),
    FOREIGN KEY (pool_id, from_membership_epoch)
        REFERENCES membership_epochs(pool_id, epoch) ON DELETE RESTRICT,
    FOREIGN KEY (pool_id, to_membership_epoch)
        REFERENCES membership_epochs(pool_id, epoch) ON DELETE RESTRICT,
    CHECK (to_membership_epoch = from_membership_epoch + 1),
    CHECK (
        (status = 'ISSUED' AND committed_at IS NULL AND invalidated_at IS NULL) OR
        (status = 'COMMITTED' AND committed_at IS NOT NULL AND invalidated_at IS NULL) OR
        (status = 'INVALIDATED' AND committed_at IS NULL AND invalidated_at IS NOT NULL)
    )
);

COMMENT ON TABLE control_rotation_evidence IS
    '永久换员控制凭据轮换证据；provider attestation 是外部已核验的不透明引用，平台不伪称自行验真';

CREATE INDEX idx_control_rotation_evidence_scope
    ON control_rotation_evidence(
        pool_id, resource_account_ref, from_membership_epoch, to_membership_epoch, status
    );

CREATE TABLE control_rotation_evidence_batches (
    evidence_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    resource_account_ref text NOT NULL,
    from_membership_epoch integer NOT NULL,
    to_membership_epoch integer NOT NULL,
    epoch_role text NOT NULL CHECK (epoch_role IN ('FROM', 'TO')),
    batch_type text NOT NULL CHECK (batch_type IN ('LOGIN', 'MFA', 'RECOVERY', 'OWNERSHIP')),
    batch_membership_epoch integer NOT NULL CHECK (batch_membership_epoch > 0),
    required_batch_status text NOT NULL CHECK (required_batch_status IN ('RETIRED', 'ACTIVE')),
    credential_batch_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (evidence_id, epoch_role, batch_type),
    FOREIGN KEY (
        evidence_id, pool_id, resource_account_ref,
        from_membership_epoch, to_membership_epoch
    ) REFERENCES control_rotation_evidence(
        id, pool_id, resource_account_ref,
        from_membership_epoch, to_membership_epoch
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        credential_batch_id, pool_id, resource_account_ref,
        batch_membership_epoch, batch_type
    ) REFERENCES credential_batches(
        id, pool_id, resource_account_ref,
        membership_epoch, batch_type
    ) ON DELETE RESTRICT,
    CHECK (
        (epoch_role = 'FROM' AND
         batch_membership_epoch = from_membership_epoch AND
         required_batch_status = 'RETIRED') OR
        (epoch_role = 'TO' AND
         batch_membership_epoch = to_membership_epoch AND
         required_batch_status = 'ACTIVE')
    )
);

COMMENT ON TABLE control_rotation_evidence_batches IS
    '每份证据必须恰好引用旧 Epoch 四个 RETIRED 与新 Epoch 四个 ACTIVE 控制批次';

CREATE INDEX idx_control_rotation_evidence_batches_batch
    ON control_rotation_evidence_batches(credential_batch_id);

CREATE OR REPLACE FUNCTION enforce_current_operation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- LEGACY_UNRECOVERABLE 只由本迁移标记历史行，新请求不得主动降级绕过完整意图快照。
    IF NEW.migration_state <> 'CURRENT' OR NEW.target_external_id IS NULL OR
       NEW.request_snapshot = '{}'::jsonb THEN
        RAISE EXCEPTION 'new integration operation requires a recoverable external target and request snapshot';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER integration_operations_current_insert
BEFORE INSERT ON integration_operations
FOR EACH ROW EXECUTE FUNCTION enforce_current_operation_insert();

CREATE OR REPLACE FUNCTION enforce_operation_update_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'integration_operations is an immutable operation ledger';
    END IF;
    IF OLD.migration_state = 'LEGACY_UNRECOVERABLE' THEN
        RAISE EXCEPTION 'legacy integration operation is unrecoverable and cannot be replayed';
    END IF;

    IF NEW.integration_client_id IS DISTINCT FROM OLD.integration_client_id OR
       NEW.operation_id IS DISTINCT FROM OLD.operation_id OR
       NEW.operation_type IS DISTINCT FROM OLD.operation_type OR
       NEW.target_type IS DISTINCT FROM OLD.target_type OR
       NEW.target_external_id IS DISTINCT FROM OLD.target_external_id OR
       NEW.migration_state IS DISTINCT FROM OLD.migration_state OR
       NEW.request_hash IS DISTINCT FROM OLD.request_hash OR
       NEW.request_snapshot IS DISTINCT FROM OLD.request_snapshot OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'integration operation intent is immutable';
    END IF;

    IF OLD.target_id IS NOT NULL AND NEW.target_id IS DISTINCT FROM OLD.target_id THEN
        RAISE EXCEPTION 'integration operation target_id cannot be changed or cleared';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'integration operation version must increase by exactly one';
    END IF;
    IF NEW.fencing_token < OLD.fencing_token OR
       (NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND NEW.lease_owner IS NOT NULL AND
        NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'integration operation fencing token is stale';
    END IF;
    IF OLD.status IN ('SUCCEEDED', 'FAILED') THEN
        RAISE EXCEPTION 'terminal integration operation is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER integration_operations_invariants
BEFORE UPDATE OR DELETE ON integration_operations
FOR EACH ROW EXECUTE FUNCTION enforce_operation_update_invariants();

CREATE OR REPLACE FUNCTION validate_credential_claim_binding(
    bound_operation_id uuid,
    bound_seat_id uuid,
    bound_target_member_id uuid
)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    bound_operation_type text;
    bound_owner_member_id uuid;
BEGIN
    SELECT io.operation_type, seat.owner_member_id
    INTO bound_operation_type, bound_owner_member_id
    FROM integration_operations io
    JOIN seats seat
      ON seat.id = bound_seat_id
     AND seat.external_id = io.target_external_id
     AND seat.status = 'ACTIVE'
    WHERE io.id = bound_operation_id
      AND io.target_type = 'SEAT'
      AND io.migration_state = 'CURRENT'
      AND io.status = 'SUCCEEDED'
      AND io.operation_type IN (
          'PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY'
      )
    FOR SHARE OF io, seat;

    IF bound_operation_type IS NULL THEN
        RAISE EXCEPTION 'credential claim is not bound to a recoverable succeeded Seat operation';
    END IF;

    PERFORM 1
    FROM seat_assignments assignment
    JOIN members target_member ON target_member.id = assignment.member_id
    WHERE assignment.seat_id = bound_seat_id
      AND assignment.member_id = bound_target_member_id
      AND assignment.status = 'ACTIVE'
      AND (assignment.starts_at IS NULL OR assignment.starts_at <= CURRENT_TIMESTAMP)
      AND (assignment.ends_at IS NULL OR assignment.ends_at > CURRENT_TIMESTAMP)
      AND target_member.status = 'ACTIVE'
    FOR SHARE OF assignment, target_member;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'credential claim target is not the Seat current active member';
    END IF;

    IF bound_operation_type = 'PROVISION' AND
       bound_owner_member_id IS DISTINCT FROM bound_target_member_id THEN
        RAISE EXCEPTION 'provision credential claim target is not the Seat owner';
    END IF;
    RETURN bound_operation_type;
END;
$$;

CREATE OR REPLACE FUNCTION credential_claim_ack_snapshot_matches(
    ack_snapshot jsonb,
    bound_operation_id uuid,
    bound_seat_id uuid,
    bound_target_member_id uuid,
    bound_claim_operation_id text,
    bound_credential_fingerprint bytea
)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    expected_operation_id text;
    expected_operation_type text;
    expected_seat_external_id text;
    expected_member_external_id text;
    snapshot_key_count integer;
    snapshot_claimed_at timestamptz;
BEGIN
    IF ack_snapshot IS NULL OR jsonb_typeof(ack_snapshot) <> 'object' OR NOT (
        ack_snapshot ?& ARRAY[
            'external_seat_id', 'provision_operation_id', 'claim_operation_id',
            'claimed_by', 'credential_fingerprint', 'credential_claimed', 'claimed_at'
        ]
    ) THEN
        RETURN false;
    END IF;

    SELECT count(*) INTO snapshot_key_count FROM jsonb_object_keys(ack_snapshot);
    IF snapshot_key_count <> 7 OR
       jsonb_typeof(ack_snapshot -> 'external_seat_id') <> 'string' OR
       jsonb_typeof(ack_snapshot -> 'provision_operation_id') <> 'string' OR
       jsonb_typeof(ack_snapshot -> 'claim_operation_id') <> 'string' OR
       jsonb_typeof(ack_snapshot -> 'claimed_by') <> 'string' OR
       jsonb_typeof(ack_snapshot -> 'credential_fingerprint') <> 'string' OR
       jsonb_typeof(ack_snapshot -> 'credential_claimed') <> 'boolean' OR
       jsonb_typeof(ack_snapshot -> 'claimed_at') <> 'string' OR
       ack_snapshot -> 'credential_claimed' <> 'true'::jsonb THEN
        RETURN false;
    END IF;

    SELECT io.operation_id, io.operation_type,
           seat.external_id, target_member.external_id
    INTO expected_operation_id, expected_operation_type,
         expected_seat_external_id, expected_member_external_id
    FROM integration_operations io
    JOIN seats seat ON seat.id = bound_seat_id
    JOIN members target_member ON target_member.id = bound_target_member_id
    WHERE io.id = bound_operation_id;

    IF expected_operation_type IS DISTINCT FROM 'PROVISION' OR
       ack_snapshot ->> 'provision_operation_id' IS DISTINCT FROM expected_operation_id OR
       ack_snapshot ->> 'claim_operation_id' IS DISTINCT FROM bound_claim_operation_id OR
       ack_snapshot ->> 'external_seat_id' IS DISTINCT FROM expected_seat_external_id OR
       ack_snapshot ->> 'claimed_by' IS DISTINCT FROM expected_member_external_id OR
       ack_snapshot ->> 'credential_fingerprint' IS DISTINCT FROM encode(bound_credential_fingerprint, 'hex') THEN
        RETURN false;
    END IF;

    BEGIN
        snapshot_claimed_at := (ack_snapshot ->> 'claimed_at')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN snapshot_claimed_at IS NOT NULL AND isfinite(snapshot_claimed_at);
END;
$$;

CREATE OR REPLACE FUNCTION enforce_credential_claim_insert_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM validate_credential_claim_binding(
        NEW.integration_operation_id, NEW.seat_id, NEW.target_member_id
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER credential_claims_insert_binding
BEFORE INSERT ON credential_claims
FOR EACH ROW EXECUTE FUNCTION enforce_credential_claim_insert_binding();

CREATE OR REPLACE FUNCTION enforce_credential_claim_update_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    claim_operation_type text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'credential_claims is an immutable delivery ledger';
    END IF;

    IF OLD.status IN ('CLAIMED', 'EXPIRED', 'REJECTED') THEN
        RAISE EXCEPTION 'terminal credential claim is immutable';
    END IF;
    IF NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
       NEW.target_member_id IS DISTINCT FROM OLD.target_member_id OR
       NEW.claim_operation_id IS DISTINCT FROM OLD.claim_operation_id OR
       NEW.claim_intent_hash IS DISTINCT FROM OLD.claim_intent_hash OR
       NEW.credential_fingerprint IS DISTINCT FROM OLD.credential_fingerprint OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'credential claim binding and audit metadata are immutable';
    END IF;
    IF NEW.status IN ('READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED') AND
       (NEW.claim_token_hash IS DISTINCT FROM OLD.claim_token_hash OR
        NEW.envelope_algorithm IS DISTINCT FROM OLD.envelope_algorithm OR
        NEW.envelope_key_ref IS DISTINCT FROM OLD.envelope_key_ref OR
        NEW.envelope_ciphertext IS DISTINCT FROM OLD.envelope_ciphertext OR
        NEW.envelope_nonce IS DISTINCT FROM OLD.envelope_nonce OR
        NEW.envelope_aad_hash IS DISTINCT FROM OLD.envelope_aad_hash OR
        NEW.wrapped_dek_kms IS DISTINCT FROM OLD.wrapped_dek_kms) THEN
        RAISE EXCEPTION 'non-terminal credential claim secret envelope is immutable';
    END IF;
    IF OLD.status = 'ACK_PENDING' AND OLD.ack_response_snapshot IS NOT NULL AND
       NEW.ack_response_snapshot IS DISTINCT FROM OLD.ack_response_snapshot THEN
        RAISE EXCEPTION 'durable credential acknowledgement snapshot is immutable';
    END IF;
    IF OLD.status = 'ACK_PENDING' AND OLD.ack_response_snapshot IS NOT NULL AND
       NEW.status NOT IN ('ACK_PENDING', 'CLAIMED', 'EXPIRED') THEN
        -- 已持久确认成功的上游 ack 不得降级为未知或拒绝；TTL 到期仍可失败关闭并清密。
        RAISE EXCEPTION 'successful credential acknowledgement cannot be downgraded';
    END IF;
    IF NEW.status IN ('ACK_PENDING', 'CLAIMED') THEN
        claim_operation_type := validate_credential_claim_binding(
            NEW.integration_operation_id, NEW.seat_id, NEW.target_member_id
        );

        -- ACK_PENDING 先于上游调用持久化，允许 NULL；明确成功后写入非空快照时必须完整匹配。
        IF claim_operation_type = 'PROVISION' AND NEW.status = 'ACK_PENDING' AND
           NEW.ack_response_snapshot IS NOT NULL AND NOT
           credential_claim_ack_snapshot_matches(
               NEW.ack_response_snapshot, NEW.integration_operation_id, NEW.seat_id,
               NEW.target_member_id, NEW.claim_operation_id, NEW.credential_fingerprint
           ) THEN
            RAISE EXCEPTION 'provision ACK_PENDING requires a matching structured acknowledgement snapshot';
        END IF;
    END IF;
    IF NEW.status = 'CLAIMED' THEN

        IF claim_operation_type IS NULL OR claim_operation_type NOT IN (
            'PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY'
        ) THEN
            RAISE EXCEPTION 'operation type % cannot produce a credential claim',
                COALESCE(claim_operation_type, '<unknown>');
        END IF;
        -- Provision 只有在持久化明确 ack 快照后才能披露；三类换员无需该上游 ack。
        IF claim_operation_type = 'PROVISION' AND
           (OLD.status <> 'ACK_PENDING' OR NOT credential_claim_ack_snapshot_matches(
               OLD.ack_response_snapshot, OLD.integration_operation_id, OLD.seat_id,
               OLD.target_member_id, OLD.claim_operation_id, OLD.credential_fingerprint
           )) THEN
            RAISE EXCEPTION 'provision credential cannot be claimed before durable Sub2API ack';
        END IF;
        IF OLD.status = 'READY' AND claim_operation_type = 'PROVISION' THEN
            RAISE EXCEPTION 'provision credential cannot claim directly from READY';
        END IF;
    END IF;
    IF NOT (
        -- 首次 ack 结果未知可从 READY 进入 RECONCILE 并保留秘密；明确拒绝进入 REJECTED 后强制清密。
        -- 状态边允许换员直领；上面的操作类型门禁确保 Provision 和未知类型失败关闭。
        (OLD.status = 'READY' AND NEW.status IN (
            'READY', 'ACK_PENDING', 'ACK_RECONCILE_REQUIRED',
            'CLAIMED', 'EXPIRED', 'REJECTED'
        )) OR
        (OLD.status = 'ACK_PENDING' AND NEW.status IN (
            'ACK_PENDING', 'ACK_RECONCILE_REQUIRED', 'CLAIMED', 'EXPIRED', 'REJECTED'
        )) OR
        (OLD.status = 'ACK_RECONCILE_REQUIRED' AND NEW.status IN (
            'ACK_RECONCILE_REQUIRED', 'ACK_PENDING', 'CLAIMED', 'EXPIRED', 'REJECTED'
        ))
    ) THEN
        RAISE EXCEPTION 'illegal credential claim status transition: % -> %', OLD.status, NEW.status;
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'credential claim version must increase by exactly one';
    END IF;
    IF NEW.fencing_token < OLD.fencing_token OR
       (NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND NEW.lease_owner IS NOT NULL AND
        NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'credential claim fencing token is stale';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER credential_claims_invariants
BEFORE UPDATE OR DELETE ON credential_claims
FOR EACH ROW EXECUTE FUNCTION enforce_credential_claim_update_invariants();

CREATE OR REPLACE FUNCTION enforce_pool_credential_epoch_floor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.credential_epoch_floor < OLD.credential_epoch_floor THEN
        RAISE EXCEPTION 'pool credential_epoch_floor cannot decrease';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM credential_batches
        WHERE pool_id = NEW.id
          AND membership_epoch < NEW.credential_epoch_floor
          AND status IN ('SEALED', 'DISTRIBUTED', 'ACTIVE')
    ) THEN
        RAISE EXCEPTION 'pool credential_epoch_floor would strand a writable old credential batch';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER pools_credential_epoch_floor_monotonic
BEFORE UPDATE OF credential_epoch_floor ON pools
FOR EACH ROW EXECUTE FUNCTION enforce_pool_credential_epoch_floor();

CREATE OR REPLACE FUNCTION enforce_credential_batch_epoch_floor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    epoch_floor integer;
BEGIN
    SELECT credential_epoch_floor INTO epoch_floor
    FROM pools
    WHERE id = NEW.pool_id
    FOR SHARE;

    IF NEW.status IN ('SEALED', 'DISTRIBUTED', 'ACTIVE') AND
       NEW.membership_epoch < epoch_floor THEN
        RAISE EXCEPTION 'credential batch epoch % is below pool floor %',
            NEW.membership_epoch, epoch_floor;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER credential_batches_epoch_floor
BEFORE INSERT OR UPDATE OF pool_id, membership_epoch, status ON credential_batches
FOR EACH ROW EXECUTE FUNCTION enforce_credential_batch_epoch_floor();

CREATE OR REPLACE FUNCTION enforce_control_rotation_evidence_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'control rotation evidence is append-only';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.pool_id IS DISTINCT FROM OLD.pool_id OR
       NEW.resource_account_ref IS DISTINCT FROM OLD.resource_account_ref OR
       NEW.from_membership_epoch IS DISTINCT FROM OLD.from_membership_epoch OR
       NEW.to_membership_epoch IS DISTINCT FROM OLD.to_membership_epoch OR
       NEW.provider_attestation_ref IS DISTINCT FROM OLD.provider_attestation_ref OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'control rotation evidence scope is immutable';
    END IF;
    IF OLD.status <> 'ISSUED' OR NEW.status NOT IN ('COMMITTED', 'INVALIDATED') THEN
        RAISE EXCEPTION 'illegal control rotation evidence status transition: % -> %',
            OLD.status, NEW.status;
    END IF;
    IF NEW.status = 'COMMITTED' AND NOT EXISTS (
        SELECT 1
        FROM pools
        WHERE id = NEW.pool_id
          AND credential_epoch_floor >= NEW.to_membership_epoch
    ) THEN
        RAISE EXCEPTION 'control rotation evidence cannot commit before pool epoch floor advances';
    END IF;
    IF NEW.status = 'COMMITTED' THEN
        -- COMMIT 时重新读取批次现状，不能只信任签发时保存的状态快照。
        PERFORM assert_control_rotation_evidence_has_eight_batches(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_rotation_evidence_invariants
BEFORE UPDATE OR DELETE ON control_rotation_evidence
FOR EACH ROW EXECUTE FUNCTION enforce_control_rotation_evidence_invariants();

CREATE OR REPLACE FUNCTION reject_control_rotation_batch_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control rotation evidence batch references are immutable';
END;
$$;

CREATE TRIGGER control_rotation_evidence_batches_immutable
BEFORE UPDATE OR DELETE ON control_rotation_evidence_batches
FOR EACH ROW EXECUTE FUNCTION reject_control_rotation_batch_mutation();

CREATE OR REPLACE FUNCTION protect_issued_control_rotation_batch_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND EXISTS (
        SELECT 1
        FROM control_rotation_evidence_batches evidence_batch
        JOIN control_rotation_evidence evidence
          ON evidence.id = evidence_batch.evidence_id
        WHERE evidence_batch.credential_batch_id = OLD.id
          AND evidence.status = 'ISSUED'
          AND evidence_batch.required_batch_status IS DISTINCT FROM NEW.status
    ) THEN
        RAISE EXCEPTION 'credential batch status is pinned by issued control rotation evidence';
    END IF;
    RETURN NEW;
END;
$$;

-- ISSUED 证据尚可能被永久换员消费，因此临时固定当前状态；COMMITTED 后允许进入下一轮合法退休。
CREATE TRIGGER credential_batches_issued_evidence_status
BEFORE UPDATE OF status ON credential_batches
FOR EACH ROW EXECUTE FUNCTION protect_issued_control_rotation_batch_status();

CREATE OR REPLACE FUNCTION assert_control_rotation_evidence_has_eight_batches(target_evidence_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    reference_count integer;
    valid_reference_count integer;
BEGIN
    SELECT count(*) INTO reference_count
    FROM control_rotation_evidence_batches
    WHERE evidence_id = target_evidence_id;

    IF reference_count <> 8 THEN
        RAISE EXCEPTION 'control rotation evidence % must reference exactly eight batches, got %',
            target_evidence_id, reference_count;
    END IF;

    SELECT count(*) INTO valid_reference_count
    FROM control_rotation_evidence_batches evidence_batch
    JOIN credential_batches batch
      ON batch.id = evidence_batch.credential_batch_id
     AND batch.pool_id = evidence_batch.pool_id
     AND batch.resource_account_ref = evidence_batch.resource_account_ref
     AND batch.membership_epoch = evidence_batch.batch_membership_epoch
     AND batch.batch_type = evidence_batch.batch_type
    WHERE evidence_batch.evidence_id = target_evidence_id
      AND batch.status = evidence_batch.required_batch_status;

    IF valid_reference_count <> 8 THEN
        RAISE EXCEPTION 'control rotation evidence % has batch status drift', target_evidence_id;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_rotation_evidence_parent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM assert_control_rotation_evidence_has_eight_batches(NEW.id);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_control_rotation_evidence_batch_set()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM assert_control_rotation_evidence_has_eight_batches(COALESCE(NEW.evidence_id, OLD.evidence_id));
    RETURN NULL;
END;
$$;

-- 延迟到事务提交，允许先插入证据主记录，再原子插入八条受约束引用。
CREATE CONSTRAINT TRIGGER control_rotation_evidence_complete
AFTER INSERT ON control_rotation_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_rotation_evidence_parent();

CREATE CONSTRAINT TRIGGER control_rotation_evidence_batch_set_complete
AFTER INSERT OR UPDATE OR DELETE ON control_rotation_evidence_batches
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_control_rotation_evidence_batch_set();

COMMIT;
