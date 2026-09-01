-- Phase2-G：Pool 级永久轮换必须完整 prepare、原子安装，再由独立 commit 一次性启用。
-- 准备阶段的新凭据不写入 api_keys；安装后的 held 阶段仍保持 Key/订阅不可用。

ALTER TABLE trusted_pool_seats
    DROP CONSTRAINT IF EXISTS trusted_pool_seats_state_check;
ALTER TABLE trusted_pool_seats
    ALTER COLUMN state TYPE VARCHAR(64);
ALTER TABLE trusted_pool_seats
    ADD CONSTRAINT trusted_pool_seats_state_check
    CHECK (state IN ('active', 'draining', 'frozen', 'rotating', 'rotation_prepared', 'rotation_activated_pending_commit'));

CREATE TABLE IF NOT EXISTS trusted_pool_permanent_rotations (
    client_id              VARCHAR(64) NOT NULL,
    prepare_operation_id   VARCHAR(128) NOT NULL,
    protocol_version       VARCHAR(64) NOT NULL,
    external_pool_id       VARCHAR(128) NOT NULL,
    plan_id                VARCHAR(128) NOT NULL,
    ceremony_type          VARCHAR(32) NOT NULL,
    from_epoch             BIGINT NOT NULL CHECK (from_epoch > 0),
    to_epoch               BIGINT NOT NULL CHECK (to_epoch = from_epoch + 1),
    request_hash           CHAR(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    child_set_hash         CHAR(64) NOT NULL CHECK (child_set_hash ~ '^[0-9a-f]{64}$'),
    prepared_set_hash      CHAR(64) NOT NULL CHECK (prepared_set_hash ~ '^[0-9a-f]{64}$'),
    seat_count             INTEGER NOT NULL CHECK (seat_count > 0),
    status                 VARCHAR(40) NOT NULL DEFAULT 'prepared'
                           CHECK (status IN ('prepared', 'activated_pending_commit', 'committed', 'retiring', 'superseded')),
    activation_operation_id VARCHAR(128),
    activation_request_hash CHAR(64),
    commit_operation_id     VARCHAR(128),
    commit_request_hash     CHAR(64),
    prepared_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at           TIMESTAMPTZ,
    committed_at           TIMESTAMPTZ,
    superseded_by_prepare_operation_id VARCHAR(128),
    superseded_at          TIMESTAMPTZ,
    PRIMARY KEY (client_id, prepare_operation_id),
    UNIQUE (client_id, plan_id),
    FOREIGN KEY (client_id, external_pool_id)
        REFERENCES trusted_pool_integration_clients(client_id, external_pool_id),
    CHECK (
        (status = 'prepared' AND activation_operation_id IS NULL AND activation_request_hash IS NULL AND activated_at IS NULL
         AND commit_operation_id IS NULL AND commit_request_hash IS NULL AND committed_at IS NULL
         AND superseded_by_prepare_operation_id IS NULL AND superseded_at IS NULL)
        OR
        (status = 'activated_pending_commit' AND activation_operation_id IS NOT NULL AND activation_request_hash ~ '^[0-9a-f]{64}$'
         AND activated_at IS NOT NULL AND commit_operation_id IS NULL AND commit_request_hash IS NULL AND committed_at IS NULL
         AND superseded_by_prepare_operation_id IS NULL AND superseded_at IS NULL)
        OR
        (status IN ('committed','retiring') AND activation_operation_id IS NOT NULL AND activation_request_hash ~ '^[0-9a-f]{64}$'
         AND activated_at IS NOT NULL AND commit_operation_id IS NOT NULL AND commit_request_hash ~ '^[0-9a-f]{64}$'
         AND committed_at IS NOT NULL AND superseded_by_prepare_operation_id IS NULL AND superseded_at IS NULL)
        OR
        (status = 'superseded' AND activation_operation_id IS NOT NULL AND activation_request_hash ~ '^[0-9a-f]{64}$'
         AND activated_at IS NOT NULL AND commit_operation_id IS NOT NULL AND commit_request_hash ~ '^[0-9a-f]{64}$'
         AND committed_at IS NOT NULL AND superseded_by_prepare_operation_id IS NOT NULL AND superseded_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS trusted_pool_permanent_rotation_seats (
    client_id              VARCHAR(64) NOT NULL,
    prepare_operation_id   VARCHAR(128) NOT NULL,
    external_seat_id       VARCHAR(128) NOT NULL,
    target_member_id       VARCHAR(128) NOT NULL,
    seat_id                BIGINT NOT NULL REFERENCES trusted_pool_seats(id),
    principal_user_id      BIGINT NOT NULL,
    group_id               BIGINT NOT NULL,
    subscription_id        BIGINT NOT NULL,
    api_key_id             BIGINT NOT NULL,
    from_epoch             BIGINT NOT NULL CHECK (from_epoch > 0),
    to_epoch               BIGINT NOT NULL CHECK (to_epoch = from_epoch + 1),
    expected_assignment_epoch BIGINT NOT NULL CHECK (expected_assignment_epoch > 0),
    target_assignment_epoch BIGINT NOT NULL CHECK (target_assignment_epoch = expected_assignment_epoch + 1),
    from_api_key_version   BIGINT NOT NULL CHECK (from_api_key_version > 0),
    to_api_key_version     BIGINT NOT NULL CHECK (to_api_key_version = from_api_key_version + 1),
    CHECK (to_api_key_version = expected_assignment_epoch + 1),
    child_operation_id     VARCHAR(128) NOT NULL,
    child_request_hash     CHAR(64) NOT NULL CHECK (child_request_hash ~ '^[0-9a-f]{64}$'),
    credential_fingerprint CHAR(64) NOT NULL CHECK (credential_fingerprint ~ '^[0-9a-f]{64}$'),
    prepared_rotation_ref  VARCHAR(128) NOT NULL,
    prepared_credential    TEXT,
    activated_at           TIMESTAMPTZ,
    committed_at           TIMESTAMPTZ,
    PRIMARY KEY (client_id, prepare_operation_id, external_seat_id),
    UNIQUE (client_id, prepare_operation_id, child_operation_id),
    FOREIGN KEY (client_id, prepare_operation_id)
        REFERENCES trusted_pool_permanent_rotations(client_id, prepare_operation_id),
    CHECK (
        (prepared_credential IS NOT NULL AND activated_at IS NULL AND committed_at IS NULL)
        OR (prepared_credential IS NULL AND activated_at IS NOT NULL AND committed_at IS NULL)
        OR (prepared_credential IS NULL AND activated_at IS NOT NULL AND committed_at IS NOT NULL)
    )
);

-- 同一 Seat 同时只能属于一个尚未 commit 的集合；held 阶段不得开始下一轮。
CREATE UNIQUE INDEX IF NOT EXISTS uq_trusted_pool_one_open_permanent_rotation_per_seat
    ON trusted_pool_permanent_rotation_seats (seat_id)
    WHERE committed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_trusted_pool_permanent_rotations_pool
    ON trusted_pool_permanent_rotations (external_pool_id, prepared_at);

-- 永久轮换使用独立最小权限身份；普通、通配及混合 scope 均不得调用。
UPDATE trusted_pool_integration_clients
SET status = 'disabled', updated_at = NOW()
WHERE status = 'active'
  AND 'seat:permanent-rotate' = ANY(scopes)
  AND NOT (cardinality(scopes) = 1 AND scopes[1] = 'seat:permanent-rotate');

ALTER TABLE trusted_pool_integration_clients
    DROP CONSTRAINT IF EXISTS ck_trusted_pool_permanent_rotate_scope_isolation;
ALTER TABLE trusted_pool_integration_clients
    ADD CONSTRAINT ck_trusted_pool_permanent_rotate_scope_isolation CHECK (
        status <> 'active' OR
        NOT ('seat:permanent-rotate' = ANY(scopes)) OR
        (cardinality(scopes) = 1 AND scopes[1] = 'seat:permanent-rotate')
    );

CREATE OR REPLACE FUNCTION guard_trusted_pool_permanent_rotation_parent()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'trusted_pool_permanent_rotations is append-only' USING ERRCODE = '55000';
    END IF;
    IF NOT (
        (OLD.status='prepared' AND NEW.status='activated_pending_commit'
         AND NEW.superseded_by_prepare_operation_id IS NULL AND NEW.superseded_at IS NULL)
        OR
        (OLD.status='activated_pending_commit' AND NEW.status='committed'
         AND NEW.activation_operation_id=OLD.activation_operation_id
         AND NEW.activation_request_hash=OLD.activation_request_hash
         AND NEW.activated_at=OLD.activated_at
         AND NEW.commit_operation_id IS NOT NULL AND NEW.commit_request_hash IS NOT NULL AND NEW.committed_at IS NOT NULL
         AND NEW.superseded_by_prepare_operation_id IS NULL AND NEW.superseded_at IS NULL)
        OR
        (OLD.status='committed' AND NEW.status='retiring'
         AND NEW.activation_operation_id=OLD.activation_operation_id
         AND NEW.activation_request_hash=OLD.activation_request_hash
         AND NEW.activated_at=OLD.activated_at
         AND NEW.commit_operation_id=OLD.commit_operation_id
         AND NEW.commit_request_hash=OLD.commit_request_hash
         AND NEW.committed_at=OLD.committed_at
         AND NEW.superseded_by_prepare_operation_id IS NULL AND NEW.superseded_at IS NULL)
        OR
        (OLD.status='retiring' AND NEW.status='superseded'
         AND NEW.activation_operation_id=OLD.activation_operation_id
         AND NEW.activation_request_hash=OLD.activation_request_hash
         AND NEW.activated_at=OLD.activated_at
         AND NEW.commit_operation_id=OLD.commit_operation_id
         AND NEW.commit_request_hash=OLD.commit_request_hash
         AND NEW.committed_at=OLD.committed_at
         AND NEW.superseded_by_prepare_operation_id IS NOT NULL AND NEW.superseded_at IS NOT NULL)
       )
       OR NEW.client_id <> OLD.client_id
       OR NEW.prepare_operation_id <> OLD.prepare_operation_id
       OR NEW.external_pool_id <> OLD.external_pool_id
       OR NEW.protocol_version <> OLD.protocol_version
       OR NEW.plan_id <> OLD.plan_id
       OR NEW.ceremony_type <> OLD.ceremony_type
       OR NEW.from_epoch <> OLD.from_epoch OR NEW.to_epoch <> OLD.to_epoch
       OR NEW.request_hash <> OLD.request_hash
       OR NEW.child_set_hash <> OLD.child_set_hash
       OR NEW.prepared_set_hash <> OLD.prepared_set_hash
       OR NEW.seat_count <> OLD.seat_count
       OR NEW.activation_operation_id IS NULL OR NEW.activation_request_hash IS NULL OR NEW.activated_at IS NULL THEN
        RAISE EXCEPTION 'invalid trusted pool permanent rotation transition' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_parent_guard
    ON trusted_pool_permanent_rotations;
CREATE TRIGGER trg_trusted_pool_permanent_rotation_parent_guard
    BEFORE UPDATE OR DELETE ON trusted_pool_permanent_rotations
    FOR EACH ROW EXECUTE FUNCTION guard_trusted_pool_permanent_rotation_parent();

CREATE OR REPLACE FUNCTION guard_trusted_pool_permanent_rotation_seat()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'trusted_pool_permanent_rotation_seats is append-only' USING ERRCODE = '55000';
    END IF;
    IF NEW.client_id <> OLD.client_id
       OR NEW.prepare_operation_id <> OLD.prepare_operation_id
       OR NEW.external_seat_id <> OLD.external_seat_id OR NEW.target_member_id <> OLD.target_member_id OR NEW.seat_id <> OLD.seat_id
       OR NEW.principal_user_id <> OLD.principal_user_id OR NEW.group_id <> OLD.group_id
       OR NEW.subscription_id <> OLD.subscription_id OR NEW.api_key_id <> OLD.api_key_id
       OR NEW.from_epoch <> OLD.from_epoch OR NEW.to_epoch <> OLD.to_epoch
       OR NEW.expected_assignment_epoch <> OLD.expected_assignment_epoch OR NEW.target_assignment_epoch <> OLD.target_assignment_epoch
       OR NEW.from_api_key_version <> OLD.from_api_key_version OR NEW.to_api_key_version <> OLD.to_api_key_version
       OR NEW.child_operation_id <> OLD.child_operation_id
       OR NEW.child_request_hash <> OLD.child_request_hash
       OR NEW.credential_fingerprint <> OLD.credential_fingerprint
       OR NEW.prepared_rotation_ref <> OLD.prepared_rotation_ref
       OR NOT (
           (OLD.prepared_credential IS NOT NULL AND OLD.activated_at IS NULL AND OLD.committed_at IS NULL
            AND NEW.prepared_credential IS NULL AND NEW.activated_at IS NOT NULL AND NEW.committed_at IS NULL)
           OR
           (OLD.prepared_credential IS NULL AND OLD.activated_at IS NOT NULL AND OLD.committed_at IS NULL
            AND NEW.prepared_credential IS NULL AND NEW.activated_at=OLD.activated_at AND NEW.committed_at IS NOT NULL)
       ) THEN
        RAISE EXCEPTION 'invalid trusted pool permanent rotation seat transition' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_seat_guard
    ON trusted_pool_permanent_rotation_seats;
CREATE TRIGGER trg_trusted_pool_permanent_rotation_seat_guard
    BEFORE UPDATE OR DELETE ON trusted_pool_permanent_rotation_seats
    FOR EACH ROW EXECUTE FUNCTION guard_trusted_pool_permanent_rotation_seat();

-- 已激活证据只约束它仍是当前生效代际的期间。后续 suspend/freeze 首次让任一 Seat
-- 退出 active 时，数据库自动把父记录转为 retiring；只有完整相邻 successor 才能再 supersede。
CREATE OR REPLACE FUNCTION retire_trusted_pool_permanent_rotation_on_seat_exit()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.state='active' AND NEW.state <> 'active' THEN
        UPDATE trusted_pool_permanent_rotations AS p
        SET status='retiring'
        WHERE p.status='committed'
          AND EXISTS (
              SELECT 1 FROM trusted_pool_permanent_rotation_seats c
              WHERE c.client_id=p.client_id AND c.prepare_operation_id=p.prepare_operation_id
                AND c.seat_id=OLD.id
          );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_retire_on_seat_exit
    ON trusted_pool_seats;
CREATE TRIGGER trg_trusted_pool_permanent_rotation_retire_on_seat_exit
    BEFORE UPDATE OF state ON trusted_pool_seats
    FOR EACH ROW EXECUTE FUNCTION retire_trusted_pool_permanent_rotation_on_seat_exit();

COMMENT ON TABLE trusted_pool_permanent_rotations IS
    'Pool 级永久轮换父操作；完整 prepared set 原子安装后必须独立 commit 才能启用';
COMMENT ON COLUMN trusted_pool_permanent_rotation_seats.prepared_credential IS
    '准备期受限明文；激活事务复制到稳定 api_key_id 后立即清空，禁止日志与审计输出';

CREATE OR REPLACE FUNCTION trusted_pool_frame_text_phase2g(value TEXT)
RETURNS BYTEA IMMUTABLE STRICT LANGUAGE SQL AS $$
    SELECT int4send(octet_length(convert_to(value, 'UTF8'))) || convert_to(value, 'UTF8')
$$;

CREATE OR REPLACE FUNCTION trusted_pool_permanent_child_set_hash_phase2g(target_client_id TEXT, target_operation_id TEXT)
RETURNS TEXT STABLE LANGUAGE SQL AS $$
    SELECT encode(sha256(
        trusted_pool_frame_text_phase2g('trusted-pool/permanent-rotation-child-set/v1') ||
        int4send(COUNT(*)::INTEGER) ||
        COALESCE(string_agg(
            trusted_pool_frame_text_phase2g(c.external_seat_id) ||
            trusted_pool_frame_text_phase2g(c.child_operation_id) ||
            decode(c.child_request_hash, 'hex'),
            ''::BYTEA ORDER BY c.external_seat_id
        ), ''::BYTEA)), 'hex')
    FROM trusted_pool_permanent_rotation_seats c
    WHERE c.client_id=target_client_id AND c.prepare_operation_id=target_operation_id
$$;

CREATE OR REPLACE FUNCTION trusted_pool_permanent_prepared_set_hash_phase2g(target_client_id TEXT, target_operation_id TEXT)
RETURNS TEXT STABLE LANGUAGE SQL AS $$
    SELECT encode(sha256(
        trusted_pool_frame_text_phase2g('trusted-pool/permanent-prepared-seat-set/v1') ||
        int4send(COUNT(*)::INTEGER) ||
        COALESCE(string_agg(
            trusted_pool_frame_text_phase2g(c.external_seat_id) ||
            trusted_pool_frame_text_phase2g(c.target_member_id) ||
            int8send(c.expected_assignment_epoch) || int8send(c.principal_user_id) || int8send(c.subscription_id) || int8send(c.api_key_id) ||
            int8send(c.to_api_key_version) || decode(c.credential_fingerprint, 'hex') ||
            trusted_pool_frame_text_phase2g(c.prepared_rotation_ref) ||
            trusted_pool_frame_text_phase2g(c.child_operation_id) || decode(c.child_request_hash, 'hex'),
            ''::BYTEA ORDER BY c.external_seat_id
        ), ''::BYTEA)), 'hex')
    FROM trusted_pool_permanent_rotation_seats c
    WHERE c.client_id=target_client_id AND c.prepare_operation_id=target_operation_id
$$;

CREATE OR REPLACE FUNCTION trusted_pool_permanent_prepare_hash_phase2g(p trusted_pool_permanent_rotations)
RETURNS TEXT IMMUTABLE LANGUAGE SQL AS $$
    SELECT encode(sha256(
        trusted_pool_frame_text_phase2g('trusted-pool/permanent-pool-rotation-prepare/v1') ||
        trusted_pool_frame_text_phase2g(p.prepare_operation_id) || trusted_pool_frame_text_phase2g(p.plan_id) ||
        trusted_pool_frame_text_phase2g(p.ceremony_type) || trusted_pool_frame_text_phase2g(p.external_pool_id) ||
        int8send(p.from_epoch) || int8send(p.to_epoch) || decode(p.child_set_hash, 'hex')
        ), 'hex')
$$;

CREATE OR REPLACE FUNCTION trusted_pool_permanent_activate_hash_phase2g(p trusted_pool_permanent_rotations)
RETURNS TEXT IMMUTABLE LANGUAGE SQL AS $$
    SELECT encode(sha256(
        trusted_pool_frame_text_phase2g('trusted-pool/permanent-pool-rotation-activate/v1') ||
        trusted_pool_frame_text_phase2g(p.activation_operation_id) || trusted_pool_frame_text_phase2g(p.prepare_operation_id) ||
        trusted_pool_frame_text_phase2g(p.plan_id) ||
        trusted_pool_frame_text_phase2g(p.ceremony_type) || trusted_pool_frame_text_phase2g(p.external_pool_id) ||
        int8send(p.from_epoch) || int8send(p.to_epoch) || decode(p.prepared_set_hash, 'hex')
        ), 'hex')
$$;

CREATE OR REPLACE FUNCTION trusted_pool_permanent_commit_hash_phase2g(p trusted_pool_permanent_rotations)
RETURNS TEXT IMMUTABLE LANGUAGE SQL AS $$
    SELECT encode(sha256(
        trusted_pool_frame_text_phase2g('trusted-pool/permanent-pool-rotation-commit/v1') ||
        trusted_pool_frame_text_phase2g(p.commit_operation_id) || trusted_pool_frame_text_phase2g(p.prepare_operation_id) ||
        trusted_pool_frame_text_phase2g(p.activation_operation_id) || decode(p.activation_request_hash, 'hex') ||
        trusted_pool_frame_text_phase2g(p.plan_id) || trusted_pool_frame_text_phase2g(p.ceremony_type) ||
        trusted_pool_frame_text_phase2g(p.external_pool_id) || int8send(p.from_epoch) || int8send(p.to_epoch) ||
        decode(p.prepared_set_hash, 'hex')
        ), 'hex')
$$;

-- 提交时验证完整聚合，防止绕过仓储直接把父操作或单个 Seat 伪造为已激活。
-- 该控制面操作低频，采用全量一致性扫描换取所有关联表都能触发同一条安全断言。
CREATE OR REPLACE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM trusted_pool_permanent_rotations AS p
        WHERE
            (SELECT COUNT(*) FROM trusted_pool_permanent_rotation_seats c
             WHERE c.client_id=p.client_id AND c.prepare_operation_id=p.prepare_operation_id) <> p.seat_count
            OR (p.status IN ('prepared','activated_pending_commit','committed') AND
                (SELECT COUNT(*) FROM trusted_pool_seats live_seat
                 WHERE live_seat.external_pool_id=p.external_pool_id) <> p.seat_count)
            OR (p.status IN ('prepared','activated_pending_commit','committed') AND EXISTS (
                SELECT 1 FROM trusted_pool_seats live_seat
                WHERE live_seat.external_pool_id=p.external_pool_id
                  AND NOT EXISTS (
                    SELECT 1 FROM trusted_pool_permanent_rotation_seats child
                    WHERE child.client_id=p.client_id
                      AND child.prepare_operation_id=p.prepare_operation_id
                      AND child.seat_id=live_seat.id
                  )
            ))
            OR p.child_set_hash <> trusted_pool_permanent_child_set_hash_phase2g(p.client_id, p.prepare_operation_id)
            OR p.prepared_set_hash <> trusted_pool_permanent_prepared_set_hash_phase2g(p.client_id, p.prepare_operation_id)
            OR p.request_hash <> trusted_pool_permanent_prepare_hash_phase2g(p)
            OR (p.status IN ('activated_pending_commit','committed','retiring','superseded') AND p.activation_request_hash <> trusted_pool_permanent_activate_hash_phase2g(p))
            OR (p.status IN ('committed','retiring','superseded') AND p.commit_request_hash <> trusted_pool_permanent_commit_hash_phase2g(p))
            OR (p.status='retiring' AND NOT EXISTS (
                SELECT 1
                FROM trusted_pool_permanent_rotation_seats retiring_child
                JOIN trusted_pool_seats retiring_seat ON retiring_seat.id=retiring_child.seat_id
                WHERE retiring_child.client_id=p.client_id
                  AND retiring_child.prepare_operation_id=p.prepare_operation_id
                  AND retiring_seat.state <> 'active'
            ))
            OR (p.status='superseded' AND NOT EXISTS (
                SELECT 1
                FROM trusted_pool_permanent_rotations successor
                WHERE successor.client_id=p.client_id
                  AND successor.prepare_operation_id=p.superseded_by_prepare_operation_id
                  AND successor.external_pool_id=p.external_pool_id
                  AND successor.from_epoch=p.to_epoch AND successor.to_epoch=p.to_epoch+1
                  AND successor.seat_count=p.seat_count
                  AND NOT EXISTS (
                      SELECT 1 FROM trusted_pool_permanent_rotation_seats old_child
                      WHERE old_child.client_id=p.client_id AND old_child.prepare_operation_id=p.prepare_operation_id
                        AND NOT EXISTS (
                            SELECT 1 FROM trusted_pool_permanent_rotation_seats new_child
                            WHERE new_child.client_id=successor.client_id
                              AND new_child.prepare_operation_id=successor.prepare_operation_id
                              AND new_child.seat_id=old_child.seat_id
                        )
                  )
            ))
            OR EXISTS (
                SELECT 1
                FROM trusted_pool_permanent_rotation_seats AS c
                LEFT JOIN trusted_pool_seats AS s ON s.id=c.seat_id
                LEFT JOIN api_keys AS k ON k.id=c.api_key_id AND k.deleted_at IS NULL
                LEFT JOIN user_subscriptions AS u ON u.id=c.subscription_id AND u.deleted_at IS NULL
                WHERE c.client_id=p.client_id AND c.prepare_operation_id=p.prepare_operation_id
                  AND (
                    s.id IS NULL OR s.external_pool_id <> p.external_pool_id
                    OR s.external_seat_id <> c.external_seat_id
                    OR s.principal_user_id <> c.principal_user_id OR s.group_id <> c.group_id
                    OR s.subscription_id <> c.subscription_id OR s.api_key_id <> c.api_key_id
                    OR c.from_epoch <> p.from_epoch OR c.to_epoch <> p.to_epoch
                    OR c.child_request_hash <> encode(sha256(
                        trusted_pool_frame_text_phase2g(p.protocol_version) ||
                        trusted_pool_frame_text_phase2g(c.child_operation_id) ||
                        trusted_pool_frame_text_phase2g(p.plan_id) ||
                        trusted_pool_frame_text_phase2g(p.ceremony_type) ||
                        trusted_pool_frame_text_phase2g(p.external_pool_id) ||
                        int8send(p.from_epoch) || int8send(p.to_epoch) ||
                        trusted_pool_frame_text_phase2g(c.external_seat_id) ||
                        trusted_pool_frame_text_phase2g(c.target_member_id) ||
                        int8send(c.expected_assignment_epoch) || int8send(c.principal_user_id) ||
                        int8send(c.subscription_id) || int8send(c.api_key_id) ||
                        int8send(c.from_api_key_version) || int8send(c.to_api_key_version)), 'hex')
                    OR k.id IS NULL OR u.id IS NULL
                    OR (
                        p.status='prepared' AND (
                            c.prepared_credential IS NULL OR c.prepared_credential=''
                            OR c.activated_at IS NOT NULL
                            OR encode(sha256(convert_to(c.prepared_credential, 'UTF8')), 'hex') <> c.credential_fingerprint
                            OR s.state <> 'rotation_prepared' OR s.assignment_epoch <> c.expected_assignment_epoch
                            OR k.status <> 'disabled' OR u.status <> 'suspended'
                        )
                    )
                    OR (
                        p.status='activated_pending_commit' AND (
                            c.prepared_credential IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NOT NULL
                            OR s.state <> 'rotation_activated_pending_commit' OR s.assignment_epoch <> c.target_assignment_epoch
                            OR k.status <> 'disabled' OR u.status <> 'suspended'
                            OR encode(sha256(convert_to(k.key, 'UTF8')), 'hex') <> c.credential_fingerprint
                        )
                    )
                    OR (
                        p.status='committed' AND (
                            c.prepared_credential IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NULL
                            OR s.state <> 'active' OR s.assignment_epoch <> c.target_assignment_epoch
                            OR k.status <> 'active' OR u.status <> 'active'
                            OR encode(sha256(convert_to(k.key, 'UTF8')), 'hex') <> c.credential_fingerprint
                        )
                    )
                    OR (p.status IN ('retiring','superseded') AND (c.prepared_credential IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NULL))
                  )
            )
    ) THEN
        RAISE EXCEPTION 'trusted pool permanent rotation aggregate is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_aggregate_parent
    ON trusted_pool_permanent_rotations;
CREATE CONSTRAINT TRIGGER trg_trusted_pool_permanent_rotation_aggregate_parent
    AFTER INSERT OR UPDATE OR DELETE ON trusted_pool_permanent_rotations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate();

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_aggregate_child
    ON trusted_pool_permanent_rotation_seats;
CREATE CONSTRAINT TRIGGER trg_trusted_pool_permanent_rotation_aggregate_child
    AFTER INSERT OR UPDATE OR DELETE ON trusted_pool_permanent_rotation_seats
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate();

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_aggregate_seat
    ON trusted_pool_seats;
CREATE CONSTRAINT TRIGGER trg_trusted_pool_permanent_rotation_aggregate_seat
    AFTER INSERT OR UPDATE OR DELETE ON trusted_pool_seats
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate();

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_aggregate_api_key
    ON api_keys;
CREATE CONSTRAINT TRIGGER trg_trusted_pool_permanent_rotation_aggregate_api_key
    AFTER INSERT OR UPDATE OR DELETE ON api_keys
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate();

DROP TRIGGER IF EXISTS trg_trusted_pool_permanent_rotation_aggregate_subscription
    ON user_subscriptions;
CREATE CONSTRAINT TRIGGER trg_trusted_pool_permanent_rotation_aggregate_subscription
    AFTER INSERT OR UPDATE OR DELETE ON user_subscriptions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enforce_trusted_pool_permanent_rotation_aggregate();
