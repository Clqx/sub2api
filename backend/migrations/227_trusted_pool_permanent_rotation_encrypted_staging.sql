-- Encrypt Phase2-G PREPARED credentials with a per-record DEK wrapped by an independent KEK.
-- Existing plaintext must be activated before this forward-only migration is applied.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM trusted_pool_permanent_rotation_seats
        WHERE prepared_credential IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 227 blocked: activate all legacy PREPARED permanent rotations before upgrading'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE trusted_pool_permanent_rotation_seats
    ADD COLUMN prepared_credential_envelope_version SMALLINT,
    ADD COLUMN prepared_credential_key_id VARCHAR(128),
    ADD COLUMN prepared_credential_wrap_nonce BYTEA,
    ADD COLUMN prepared_credential_wrapped_dek BYTEA,
    ADD COLUMN prepared_credential_nonce BYTEA,
    ADD COLUMN prepared_credential_ciphertext BYTEA,
    ADD COLUMN prepared_credential_expires_at TIMESTAMPTZ;

-- Drop the unnamed 226 row-state CHECK before removing its referenced column.
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    FOR constraint_name IN
        SELECT c.conname
        FROM pg_constraint c
        WHERE c.conrelid = 'trusted_pool_permanent_rotation_seats'::regclass
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) ~ '(^|[^a-z0-9_])prepared_credential([^a-z0-9_]|$)'
    LOOP
        EXECUTE format('ALTER TABLE trusted_pool_permanent_rotation_seats DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$$;

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
           (OLD.prepared_credential_envelope_version IS NOT NULL AND OLD.activated_at IS NULL AND OLD.committed_at IS NULL
            AND NEW.prepared_credential_envelope_version IS NULL AND NEW.prepared_credential_key_id IS NULL
            AND NEW.prepared_credential_wrap_nonce IS NULL AND NEW.prepared_credential_wrapped_dek IS NULL
            AND NEW.prepared_credential_nonce IS NULL AND NEW.prepared_credential_ciphertext IS NULL
            AND NEW.prepared_credential_expires_at IS NULL AND NEW.activated_at IS NOT NULL AND NEW.committed_at IS NULL)
           OR
           (OLD.prepared_credential_envelope_version IS NULL AND OLD.prepared_credential_key_id IS NULL
            AND OLD.prepared_credential_wrap_nonce IS NULL AND OLD.prepared_credential_wrapped_dek IS NULL
            AND OLD.prepared_credential_nonce IS NULL AND OLD.prepared_credential_ciphertext IS NULL
            AND OLD.prepared_credential_expires_at IS NULL AND OLD.activated_at IS NOT NULL AND OLD.committed_at IS NULL
            AND NEW.prepared_credential_envelope_version IS NULL AND NEW.prepared_credential_key_id IS NULL
            AND NEW.prepared_credential_wrap_nonce IS NULL AND NEW.prepared_credential_wrapped_dek IS NULL
            AND NEW.prepared_credential_nonce IS NULL AND NEW.prepared_credential_ciphertext IS NULL
            AND NEW.prepared_credential_expires_at IS NULL AND NEW.activated_at=OLD.activated_at AND NEW.committed_at IS NOT NULL)
       ) THEN
        RAISE EXCEPTION 'invalid trusted pool permanent rotation seat transition' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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
                            c.prepared_credential_envelope_version IS NULL OR c.prepared_credential_envelope_version <> 1
                            OR c.prepared_credential_key_id IS NULL OR c.prepared_credential_key_id=''
                            OR c.prepared_credential_wrap_nonce IS NULL OR octet_length(c.prepared_credential_wrap_nonce) <> 12
                            OR c.prepared_credential_wrapped_dek IS NULL OR octet_length(c.prepared_credential_wrapped_dek) <> 48
                            OR c.prepared_credential_nonce IS NULL OR octet_length(c.prepared_credential_nonce) <> 12
                            OR c.prepared_credential_ciphertext IS NULL OR octet_length(c.prepared_credential_ciphertext) < 16
                            OR c.prepared_credential_expires_at IS NULL OR c.prepared_credential_expires_at <= p.prepared_at
                            OR c.activated_at IS NOT NULL OR c.committed_at IS NOT NULL
                            OR s.state <> 'rotation_prepared' OR s.assignment_epoch <> c.expected_assignment_epoch
                            OR k.status <> 'disabled' OR u.status <> 'suspended'
                        )
                    )
                    OR (
                        p.status='activated_pending_commit' AND (
                            c.prepared_credential_envelope_version IS NOT NULL OR c.prepared_credential_key_id IS NOT NULL
                            OR c.prepared_credential_wrap_nonce IS NOT NULL OR c.prepared_credential_wrapped_dek IS NOT NULL
                            OR c.prepared_credential_nonce IS NOT NULL OR c.prepared_credential_ciphertext IS NOT NULL
                            OR c.prepared_credential_expires_at IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NOT NULL
                            OR s.state <> 'rotation_activated_pending_commit' OR s.assignment_epoch <> c.target_assignment_epoch
                            OR k.status <> 'disabled' OR u.status <> 'suspended'
                            OR encode(sha256(convert_to(k.key, 'UTF8')), 'hex') <> c.credential_fingerprint
                        )
                    )
                    OR (
                        p.status='committed' AND (
                            c.prepared_credential_envelope_version IS NOT NULL OR c.prepared_credential_key_id IS NOT NULL
                            OR c.prepared_credential_wrap_nonce IS NOT NULL OR c.prepared_credential_wrapped_dek IS NOT NULL
                            OR c.prepared_credential_nonce IS NOT NULL OR c.prepared_credential_ciphertext IS NOT NULL
                            OR c.prepared_credential_expires_at IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NULL
                            OR s.state <> 'active' OR s.assignment_epoch <> c.target_assignment_epoch
                            OR k.status <> 'active' OR u.status <> 'active'
                            OR encode(sha256(convert_to(k.key, 'UTF8')), 'hex') <> c.credential_fingerprint
                        )
                    )
                    OR (p.status IN ('retiring','superseded') AND (
                        c.prepared_credential_envelope_version IS NOT NULL OR c.prepared_credential_key_id IS NOT NULL
                        OR c.prepared_credential_wrap_nonce IS NOT NULL OR c.prepared_credential_wrapped_dek IS NOT NULL
                        OR c.prepared_credential_nonce IS NOT NULL OR c.prepared_credential_ciphertext IS NOT NULL
                        OR c.prepared_credential_expires_at IS NOT NULL OR c.activated_at IS NULL OR c.committed_at IS NULL
                    ))
                  )
            )
    ) THEN
        RAISE EXCEPTION 'trusted pool permanent rotation aggregate is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE trusted_pool_permanent_rotation_seats
    DROP COLUMN prepared_credential;

ALTER TABLE trusted_pool_permanent_rotation_seats
    ADD CONSTRAINT ck_trusted_pool_permanent_rotation_seat_envelope_state CHECK (
        (
            prepared_credential_envelope_version IS NOT NULL
            AND prepared_credential_envelope_version = 1
            AND prepared_credential_key_id IS NOT NULL AND prepared_credential_key_id <> ''
            AND prepared_credential_wrap_nonce IS NOT NULL AND octet_length(prepared_credential_wrap_nonce) = 12
            AND prepared_credential_wrapped_dek IS NOT NULL AND octet_length(prepared_credential_wrapped_dek) = 48
            AND prepared_credential_nonce IS NOT NULL AND octet_length(prepared_credential_nonce) = 12
            AND prepared_credential_ciphertext IS NOT NULL AND octet_length(prepared_credential_ciphertext) >= 16
            AND prepared_credential_expires_at IS NOT NULL
            AND activated_at IS NULL AND committed_at IS NULL
        )
        OR (
            prepared_credential_envelope_version IS NULL
            AND prepared_credential_key_id IS NULL
            AND prepared_credential_wrap_nonce IS NULL
            AND prepared_credential_wrapped_dek IS NULL
            AND prepared_credential_nonce IS NULL
            AND prepared_credential_ciphertext IS NULL
            AND prepared_credential_expires_at IS NULL
            AND activated_at IS NOT NULL
        )
    );

COMMENT ON COLUMN trusted_pool_permanent_rotation_seats.prepared_credential_ciphertext IS
    'AES-256-GCM credential ciphertext under a random per-row DEK; all envelope columns are cleared atomically on activation';
COMMENT ON COLUMN trusted_pool_permanent_rotation_seats.prepared_credential_wrapped_dek IS
    'Per-row 32-byte DEK wrapped by the key identified by prepared_credential_key_id; retain that KEK while PREPARED rows exist';
COMMENT ON COLUMN trusted_pool_permanent_rotation_seats.prepared_credential_expires_at IS
    'Exact PREPARE replay redisclosure deadline; expiry does not block authenticated fail-forward activation';
