BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id text NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    sub2api_user_id bigint NOT NULL UNIQUE CHECK (sub2api_user_id > 0),
    display_name text NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 120),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'LEFT')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE members IS '业务成员；可信身份只能来自 Sub2API /auth/me 的成功响应';
COMMENT ON COLUMN members.sub2api_user_id IS 'Sub2API 用户 ID，不接受浏览器提示值作为可信来源';

CREATE TABLE pools (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id text NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    name text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (
        status IN ('DRAFT', 'PROVISIONING', 'WAITING_MEMBERS', 'ACTIVE', 'FROZEN', 'FAILED', 'CLOSED')
    ),
    member_limit smallint NOT NULL DEFAULT 5 CHECK (member_limit BETWEEN 2 AND 20),
    membership_epoch integer NOT NULL DEFAULT 0 CHECK (membership_epoch >= 0),
    sub2api_group_id bigint UNIQUE CHECK (sub2api_group_id IS NULL OR sub2api_group_id > 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE pools IS '可信成员池；每个 Pool 独占一个 Sub2API Group';
COMMENT ON COLUMN pools.membership_epoch IS '仅正式成员集合或恢复根变化时递增，临时换员不递增';

CREATE TABLE seats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id text NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    seat_no smallint NOT NULL CHECK (seat_no > 0),
    status text NOT NULL DEFAULT 'PROVISIONING' CHECK (
        status IN (
            'PROVISIONING', 'ACTIVE', 'SUSPEND_PENDING', 'DRAINING', 'FROZEN',
            'ASSIGNMENT_PENDING', 'REPLACEMENT_PENDING', 'FAILED', 'CLOSED'
        )
    ),
    assignment_epoch bigint NOT NULL DEFAULT 0 CHECK (assignment_epoch >= 0),
    sub2api_principal_id bigint UNIQUE CHECK (sub2api_principal_id IS NULL OR sub2api_principal_id > 0),
    sub2api_subscription_id bigint UNIQUE CHECK (sub2api_subscription_id IS NULL OR sub2api_subscription_id > 0),
    active_api_key_version integer NOT NULL DEFAULT 0 CHECK (active_api_key_version >= 0),
    frozen_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pool_id, seat_no),
    UNIQUE (id, pool_id)
);

COMMENT ON TABLE seats IS '稳定 Seat；成员换位时 Seat Principal 与 UserSubscription 保持不变';
COMMENT ON COLUMN seats.external_id IS 'Phase 1 API 公开的稳定 Seat ID；Repository 解析为内部 UUID';
COMMENT ON COLUMN seats.assignment_epoch IS '授权代际；暂停开始和 Assignment 变化时递增，使旧授权失效';
COMMENT ON COLUMN seats.active_api_key_version IS '只保存版本号，不保存 API Key 明文';

CREATE TABLE seat_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seat_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    assignment_type text NOT NULL CHECK (assignment_type IN ('PERMANENT', 'TEMPORARY')),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'ENDED', 'CANCELLED')),
    assignment_epoch bigint NOT NULL CHECK (assignment_epoch > 0),
    starts_at timestamptz,
    ends_at timestamptz,
    ended_reason text,
    created_by uuid REFERENCES members(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (seat_id, pool_id) REFERENCES seats(id, pool_id) ON DELETE RESTRICT,
    CHECK (ends_at IS NULL OR starts_at IS NULL OR ends_at > starts_at)
);

-- 数据库直接保证一个 Seat 只有一个活动成员。
CREATE UNIQUE INDEX uq_seat_assignments_active_seat
    ON seat_assignments(seat_id) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX uq_seat_assignments_active_member_pool
    ON seat_assignments(pool_id, member_id) WHERE status = 'ACTIVE';
CREATE INDEX idx_seat_assignments_member_status ON seat_assignments(member_id, status);

COMMENT ON TABLE seat_assignments IS 'Seat 成员分配历史；临时分配不授予恢复与治理权';

CREATE TABLE suspension_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    operation_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(operation_id)) BETWEEN 1 AND 128),
    status text NOT NULL DEFAULT 'SUSPEND_PENDING' CHECK (
        status IN ('SUSPEND_PENDING', 'DRAINING', 'FROZEN', 'CANCELLED', 'FAILED')
    ),
    reason_code text NOT NULL CHECK (length(trim(reason_code)) BETWEEN 1 AND 64),
    reason_detail text,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_refs) = 'array'),
    requested_by uuid REFERENCES members(id) ON DELETE SET NULL,
    expected_assignment_epoch bigint NOT NULL CHECK (expected_assignment_epoch >= 0),
    blocked_at timestamptz,
    frozen_at timestamptz,
    freeze_snapshot jsonb,
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'FROZEN' OR (frozen_at IS NOT NULL AND freeze_snapshot IS NOT NULL))
);

CREATE INDEX idx_suspension_cases_seat_status ON suspension_cases(seat_id, status, created_at DESC);
COMMENT ON TABLE suspension_cases IS '暂停、排空和冻结证据；未确认冻结时不得换员';

CREATE TABLE device_registrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    fingerprint_version smallint NOT NULL CHECK (fingerprint_version > 0),
    fingerprint_hmac bytea NOT NULL CHECK (octet_length(fingerprint_hmac) >= 16),
    label text,
    status text NOT NULL DEFAULT 'OBSERVED' CHECK (status IN ('OBSERVED', 'TRUSTED', 'RETIRED')),
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    observation_count bigint NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (seat_id, fingerprint_version, fingerprint_hmac),
    CHECK (last_seen_at >= first_seen_at)
);

COMMENT ON TABLE device_registrations IS '设备风险观察；只保存 HMAC 指纹，不保存原始硬件信息';

CREATE TABLE risk_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    level text NOT NULL CHECK (level IN ('NORMAL', 'WATCH', 'LIMITED', 'SUSPEND')),
    finding_type text NOT NULL CHECK (length(trim(finding_type)) BETWEEN 1 AND 64),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    metrics jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metrics) = 'object'),
    explanation text,
    source_event_id text,
    observed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (window_end > window_start)
);

CREATE INDEX idx_risk_findings_seat_observed ON risk_findings(seat_id, observed_at DESC);
COMMENT ON TABLE risk_findings IS '风险观察结果；不得通过触发器或后台任务自动修改 Seat 状态';

CREATE TABLE membership_epochs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    epoch integer NOT NULL CHECK (epoch > 0),
    status text NOT NULL DEFAULT 'PREPARING' CHECK (status IN ('PREPARING', 'ACTIVE', 'RETIRED', 'FAILED')),
    governance_threshold smallint NOT NULL CHECK (governance_threshold > 0),
    recovery_threshold smallint NOT NULL CHECK (recovery_threshold > 0),
    previous_manifest_hash bytea,
    activated_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pool_id, epoch),
    CHECK (recovery_threshold <= governance_threshold)
);

CREATE UNIQUE INDEX uq_membership_epochs_active_pool
    ON membership_epochs(pool_id) WHERE status = 'ACTIVE';
COMMENT ON TABLE membership_epochs IS '正式成员治理代际；治理阈值与密码学恢复阈值相互独立';

CREATE TABLE membership_epoch_members (
    epoch_id uuid NOT NULL REFERENCES membership_epochs(id) ON DELETE RESTRICT,
    member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    member_role text NOT NULL DEFAULT 'MEMBER' CHECK (member_role IN ('MEMBER', 'OWNER')),
    signing_public_key bytea NOT NULL,
    share_index smallint NOT NULL CHECK (share_index > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch_id, member_id),
    UNIQUE (epoch_id, share_index)
);

COMMENT ON TABLE membership_epoch_members IS 'Epoch 正式成员快照；临时成员不得写入';

CREATE TABLE credential_batches (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    membership_epoch integer NOT NULL CHECK (membership_epoch > 0),
    resource_account_ref text NOT NULL CHECK (length(trim(resource_account_ref)) BETWEEN 1 AND 128),
    batch_type text NOT NULL CHECK (batch_type IN ('OPERATIONAL', 'LOGIN', 'MFA', 'RECOVERY', 'OWNERSHIP')),
    batch_version integer NOT NULL CHECK (batch_version > 0),
    status text NOT NULL DEFAULT 'PREPARED' CHECK (
        status IN ('PREPARED', 'SEALED', 'DISTRIBUTED', 'ACTIVE', 'RETIRED', 'FAILED')
    ),
    encryption_algorithm text,
    ciphertext bytea,
    nonce bytea,
    aad_hash bytea,
    content_hash bytea,
    encrypted_dek_kms bytea,
    encrypted_dek_recovery bytea,
    activated_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pool_id, resource_account_ref, batch_type, membership_epoch, batch_version),
    FOREIGN KEY (pool_id, membership_epoch)
        REFERENCES membership_epochs(pool_id, epoch) ON DELETE RESTRICT,
    CHECK (
        status IN ('PREPARED', 'FAILED') OR
        (encryption_algorithm IS NOT NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND
         aad_hash IS NOT NULL AND content_hash IS NOT NULL AND encrypted_dek_kms IS NOT NULL AND
         encrypted_dek_recovery IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_credential_batches_active
    ON credential_batches(pool_id, resource_account_ref, batch_type, membership_epoch)
    WHERE status = 'ACTIVE';
COMMENT ON TABLE credential_batches IS '分阶段加密凭据；数据库只保存密文和包装后的 DEK';

CREATE TABLE manifests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    epoch_id uuid NOT NULL REFERENCES membership_epochs(id) ON DELETE RESTRICT,
    protocol_version text NOT NULL,
    canonical_payload jsonb NOT NULL CHECK (jsonb_typeof(canonical_payload) = 'object'),
    manifest_hash bytea NOT NULL UNIQUE CHECK (octet_length(manifest_hash) >= 32),
    platform_signature bytea NOT NULL,
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SIGNING', 'ACTIVE', 'RETIRED', 'INVALID')),
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, protocol_version),
    UNIQUE (id, epoch_id)
);

CREATE UNIQUE INDEX uq_manifests_active_epoch ON manifests(epoch_id) WHERE status = 'ACTIVE';
COMMENT ON TABLE manifests IS '规范化恢复清单；包含批次散列、成员快照、阈值和前序散列';

CREATE TABLE manifest_signatures (
    manifest_id uuid NOT NULL,
    epoch_id uuid NOT NULL,
    member_id uuid NOT NULL,
    signature bytea NOT NULL,
    signed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (manifest_id, member_id),
    FOREIGN KEY (manifest_id, epoch_id)
        REFERENCES manifests(id, epoch_id) ON DELETE RESTRICT,
    FOREIGN KEY (epoch_id, member_id)
        REFERENCES membership_epoch_members(epoch_id, member_id) ON DELETE RESTRICT
);

CREATE TABLE recovery_share_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    epoch_id uuid NOT NULL,
    member_id uuid NOT NULL,
    encrypted_share bytea NOT NULL,
    share_hash bytea NOT NULL CHECK (octet_length(share_hash) >= 32),
    delivery_status text NOT NULL DEFAULT 'PENDING' CHECK (
        delivery_status IN ('PENDING', 'DELIVERED', 'ACKNOWLEDGED', 'FAILED', 'REVOKED')
    ),
    delivery_proof jsonb,
    delivered_at timestamptz,
    acknowledged_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, member_id),
    FOREIGN KEY (epoch_id, member_id)
        REFERENCES membership_epoch_members(epoch_id, member_id) ON DELETE RESTRICT
);

COMMENT ON TABLE recovery_share_deliveries IS '正式成员加密 Share 的交付状态；临时成员无对应记录';

CREATE TABLE integration_operations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_client_id text NOT NULL CHECK (length(trim(integration_client_id)) BETWEEN 1 AND 128),
    operation_id varchar(128) NOT NULL CHECK (length(trim(operation_id)) BETWEEN 1 AND 128),
    operation_type text NOT NULL CHECK (length(trim(operation_type)) BETWEEN 1 AND 64),
    target_type text NOT NULL CHECK (target_type IN ('POOL', 'SEAT', 'CREDENTIAL_BATCH')),
    target_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    status text NOT NULL DEFAULT 'RUNNING' CHECK (
        status IN ('RUNNING', 'SUCCEEDED', 'RETRYABLE', 'RECONCILE_REQUIRED', 'FAILED')
    ),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    response_snapshot jsonb,
    error_code text,
    error_detail text,
    next_attempt_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (integration_client_id, operation_id)
);

CREATE INDEX idx_integration_operations_retry
    ON integration_operations(status, next_attempt_at)
    WHERE status IN ('RUNNING', 'RETRYABLE');
COMMENT ON TABLE integration_operations IS '跨服务幂等命令；相同 operation_id 的 request_hash 必须相同';

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    delivered_at timestamptz,
    last_error text
);

CREATE INDEX idx_outbox_events_pending
    ON outbox_events(available_at, occurred_at) WHERE delivered_at IS NULL;
COMMENT ON TABLE outbox_events IS '与业务状态同事务写入的可靠事件发件箱';

CREATE TABLE trust_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id uuid REFERENCES pools(id) ON DELETE RESTRICT,
    seat_id uuid REFERENCES seats(id) ON DELETE RESTRICT,
    actor_type text NOT NULL CHECK (actor_type IN ('MEMBER', 'OPERATOR', 'SYSTEM', 'SUB2API')),
    actor_ref text NOT NULL,
    event_type text NOT NULL CHECK (length(trim(event_type)) BETWEEN 1 AND 128),
    event_payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(event_payload) = 'object'),
    previous_event_hash bytea,
    event_hash bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) >= 32),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_trust_events_pool_time ON trust_events(pool_id, occurred_at, id);
CREATE INDEX idx_trust_events_seat_time ON trust_events(seat_id, occurred_at, id);
COMMENT ON TABLE trust_events IS '只追加可信审计；敏感数据必须在写入前脱敏';

CREATE OR REPLACE FUNCTION reject_trust_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'trust_events is append-only';
END;
$$;

CREATE TRIGGER trust_events_append_only
BEFORE UPDATE OR DELETE ON trust_events
FOR EACH ROW EXECUTE FUNCTION reject_trust_event_mutation();

COMMIT;
