BEGIN;

-- Phase2-H 只建立公共验证证据与 Reveal 授权账本。成员 Share 仍由外部成员通道持有；
-- 本迁移不创建任何 Root/Share/DEK/credential 明文列，也不保存 bundle blob。

ALTER TABLE recovery_epoch_plans
    ADD COLUMN portable_format_version varchar(128),
    ADD COLUMN root_trust_profile_id varchar(256),
    ADD COLUMN crypto_suite_id varchar(256),
    ADD COLUMN provider_proof_profile varchar(256),
    ADD COLUMN ceremony_attestation_algorithm varchar(128),
    ADD CONSTRAINT ck_recovery_epoch_plan_portable_profile CHECK (
        (portable_format_version IS NULL AND root_trust_profile_id IS NULL AND crypto_suite_id IS NULL AND
         provider_proof_profile IS NULL AND ceremony_attestation_algorithm IS NULL) OR
        (length(trim(portable_format_version)) BETWEEN 1 AND 128 AND
         length(trim(root_trust_profile_id)) BETWEEN 1 AND 256 AND
         length(trim(crypto_suite_id)) BETWEEN 1 AND 256 AND
         length(trim(provider_proof_profile)) BETWEEN 1 AND 256 AND
         length(trim(ceremony_attestation_algorithm)) BETWEEN 1 AND 128)
    );

CREATE OR REPLACE FUNCTION enforce_phase2h_plan_profile_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.portable_format_version IS DISTINCT FROM OLD.portable_format_version OR
       NEW.root_trust_profile_id IS DISTINCT FROM OLD.root_trust_profile_id OR
       NEW.crypto_suite_id IS DISTINCT FROM OLD.crypto_suite_id OR
       NEW.provider_proof_profile IS DISTINCT FROM OLD.provider_proof_profile OR
       NEW.ceremony_attestation_algorithm IS DISTINCT FROM OLD.ceremony_attestation_algorithm THEN
        RAISE EXCEPTION 'Recovery portable trust profile is immutable and cannot be backfilled';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_epoch_plans_phase2h_profile_immutable
BEFORE UPDATE ON recovery_epoch_plans
FOR EACH ROW EXECUTE FUNCTION enforce_phase2h_plan_profile_immutable();

ALTER TABLE manifests
    ADD COLUMN platform_signature_domain varchar(256),
    ADD CONSTRAINT ck_manifest_platform_signature_domain_phase2h CHECK (
        platform_signature_domain IS NULL OR
        platform_signature_domain = 'trusted-pool/platform-manifest-signature/v2'
    );

ALTER TABLE recovery_root_artifacts
    ADD COLUMN attestation_algorithm varchar(128),
    ADD COLUMN attestation_issuer varchar(256),
    ADD COLUMN portable_attestation_key_id varchar(512),
    ADD COLUMN attestation_protocol_version varchar(128),
    ADD COLUMN portable_attestation_signature bytea,
    ADD CONSTRAINT ck_recovery_root_portable_proof_phase2h CHECK (
        (attestation_algorithm IS NULL AND attestation_issuer IS NULL AND portable_attestation_key_id IS NULL AND
         attestation_protocol_version IS NULL AND portable_attestation_signature IS NULL) OR
        (length(trim(attestation_algorithm)) BETWEEN 1 AND 128 AND
         length(trim(attestation_issuer)) BETWEEN 1 AND 256 AND
         length(trim(portable_attestation_key_id)) BETWEEN 1 AND 512 AND
         length(trim(attestation_protocol_version)) BETWEEN 1 AND 128 AND
         octet_length(portable_attestation_signature) > 0)
    );

ALTER TABLE recovery_share_deliveries
    ADD COLUMN provider_proof_algorithm varchar(128),
    ADD COLUMN provider_proof_key_id varchar(512),
    ADD COLUMN provider_proof_protocol_version varchar(128),
    ADD COLUMN portable_provider_proof_signature bytea,
    ADD CONSTRAINT ck_recovery_share_portable_proof_phase2h CHECK (
        (provider_proof_algorithm IS NULL AND provider_proof_key_id IS NULL AND
         provider_proof_protocol_version IS NULL AND portable_provider_proof_signature IS NULL) OR
        (length(trim(provider_proof_algorithm)) BETWEEN 1 AND 128 AND
         length(trim(provider_proof_key_id)) BETWEEN 1 AND 512 AND
         length(trim(provider_proof_protocol_version)) BETWEEN 1 AND 128 AND
         octet_length(portable_provider_proof_signature) > 0)
    );

-- 旧控制权证据只有 digest/issuer/key/version，无法供离线 verifier 验签；新计划必须保存 typed proof。
ALTER TABLE recovery_plan_resource_accounts
    ADD COLUMN control_attestation_algorithm varchar(128),
    ADD COLUMN control_attestation_signature bytea,
    ADD COLUMN control_attestation_protocol_version varchar(128),
    ADD CONSTRAINT ck_recovery_plan_account_portable_proof_phase2h CHECK (
        (control_attestation_algorithm IS NULL AND control_attestation_signature IS NULL AND
         control_attestation_protocol_version IS NULL) OR
        (length(trim(control_attestation_algorithm)) BETWEEN 1 AND 128 AND
         octet_length(control_attestation_signature) > 0 AND
         length(trim(control_attestation_protocol_version)) BETWEEN 1 AND 128)
    );

ALTER TABLE recovery_control_evidence
    ADD COLUMN provider_attestation_algorithm varchar(128),
    ADD COLUMN provider_attestation_signature bytea,
    ADD COLUMN provider_attestation_protocol_version varchar(128),
    ADD CONSTRAINT ck_recovery_control_portable_proof_phase2h CHECK (
        (provider_attestation_algorithm IS NULL AND provider_attestation_signature IS NULL AND
         provider_attestation_protocol_version IS NULL) OR
        (length(trim(provider_attestation_algorithm)) BETWEEN 1 AND 128 AND
         octet_length(provider_attestation_signature) > 0 AND
         length(trim(provider_attestation_protocol_version)) BETWEEN 1 AND 128)
    );

-- 008 允许在 DELIVERED -> ACKNOWLEDGED 时补 ACK 字段，但遗漏了一组本应冻结的证据字段。
CREATE OR REPLACE FUNCTION enforce_phase2h_share_evidence_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.epoch_id IS DISTINCT FROM OLD.epoch_id OR NEW.member_id IS DISTINCT FROM OLD.member_id OR
       NEW.recovery_plan_id IS DISTINCT FROM OLD.recovery_plan_id OR
       NEW.root_artifact_id IS DISTINCT FROM OLD.root_artifact_id OR
       NEW.migration_state IS DISTINCT FROM OLD.migration_state OR
       NEW.encrypted_share IS DISTINCT FROM OLD.encrypted_share OR NEW.share_hash IS DISTINCT FROM OLD.share_hash OR
       NEW.share_index IS DISTINCT FROM OLD.share_index OR
       NEW.encryption_algorithm IS DISTINCT FROM OLD.encryption_algorithm OR
       NEW.recipient_key_id IS DISTINCT FROM OLD.recipient_key_id OR
       NEW.recipient_key_fingerprint IS DISTINCT FROM OLD.recipient_key_fingerprint OR
       NEW.provider_share_commitment IS DISTINCT FROM OLD.provider_share_commitment OR
       NEW.provider_proof_digest IS DISTINCT FROM OLD.provider_proof_digest OR
       NEW.provider_proof_signature IS DISTINCT FROM OLD.provider_proof_signature OR
       NEW.provider_proof_algorithm IS DISTINCT FROM OLD.provider_proof_algorithm OR
       NEW.provider_proof_key_id IS DISTINCT FROM OLD.provider_proof_key_id OR
       NEW.provider_proof_protocol_version IS DISTINCT FROM OLD.provider_proof_protocol_version OR
       NEW.portable_provider_proof_signature IS DISTINCT FROM OLD.portable_provider_proof_signature OR
       NEW.delivery_proof IS DISTINCT FROM OLD.delivery_proof OR
       NEW.delivered_at IS DISTINCT FROM OLD.delivered_at OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Recovery Share public evidence scope is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_share_deliveries_phase2h_immutable
BEFORE UPDATE ON recovery_share_deliveries
FOR EACH ROW EXECUTE FUNCTION enforce_phase2h_share_evidence_immutable();

CREATE OR REPLACE FUNCTION enforce_phase2h_manifest_evidence_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.protocol_version IS DISTINCT FROM OLD.protocol_version OR
       NEW.migration_state IS DISTINCT FROM OLD.migration_state OR
       NEW.platform_signature_domain IS DISTINCT FROM OLD.platform_signature_domain THEN
        RAISE EXCEPTION 'Manifest portable signature scope is immutable';
    END IF;
    IF OLD.status = 'DRAFT' AND NEW.status = 'ACTIVE' THEN
        IF OLD.published_at IS NOT NULL OR NEW.published_at IS NULL THEN
            RAISE EXCEPTION 'Manifest activation requires one immutable publication timestamp';
        END IF;
    ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'RETIRED' AND
          NEW.published_at IS DISTINCT FROM OLD.published_at THEN
        RAISE EXCEPTION 'published Manifest timestamp is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER manifests_phase2h_immutable
BEFORE UPDATE ON manifests
FOR EACH ROW EXECUTE FUNCTION enforce_phase2h_manifest_evidence_immutable();

CREATE OR REPLACE FUNCTION enforce_phase2h_control_evidence_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE trusted record;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT control_attestation_algorithm, control_attestation_signature,
               control_attestation_protocol_version INTO trusted
        FROM recovery_plan_resource_accounts account
        WHERE account.plan_id = NEW.plan_id AND account.resource_account_id = NEW.resource_account_id;
        IF NOT FOUND OR
           NEW.provider_attestation_algorithm IS DISTINCT FROM trusted.control_attestation_algorithm OR
           NEW.provider_attestation_signature IS DISTINCT FROM trusted.control_attestation_signature OR
           NEW.provider_attestation_protocol_version IS DISTINCT FROM trusted.control_attestation_protocol_version THEN
            RAISE EXCEPTION 'control evidence typed proof differs from the immutable plan account';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.verified_at IS DISTINCT FROM OLD.verified_at OR
       NEW.provider_attestation_algorithm IS DISTINCT FROM OLD.provider_attestation_algorithm OR
       NEW.provider_attestation_signature IS DISTINCT FROM OLD.provider_attestation_signature OR
       NEW.provider_attestation_protocol_version IS DISTINCT FROM OLD.provider_attestation_protocol_version THEN
        RAISE EXCEPTION 'control evidence verification time is immutable';
    END IF;
    IF OLD.status = 'VERIFIED' AND NEW.status = 'COMMITTED' AND
       (OLD.committed_at IS NOT NULL OR NEW.committed_at IS NULL OR NEW.committed_at < OLD.verified_at) THEN
        RAISE EXCEPTION 'control evidence commit requires one terminal timestamp';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_control_evidence_phase2h_immutable
BEFORE INSERT OR UPDATE ON recovery_control_evidence
FOR EACH ROW EXECUTE FUNCTION enforce_phase2h_control_evidence_immutable();

-- 新 portable generation 在进入成员签名完成态前必须有每位正式成员的已验签发布回执。
CREATE TABLE recovery_member_artifact_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    delivery_id uuid NOT NULL REFERENCES recovery_share_deliveries(id) ON DELETE RESTRICT,
    manifest_id uuid NOT NULL REFERENCES manifests(id) ON DELETE RESTRICT,
    epoch_id uuid NOT NULL REFERENCES membership_epochs(id) ON DELETE RESTRICT,
    member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    artifact_digest bytea NOT NULL CHECK (octet_length(artifact_digest) = 32),
    receipt_external_id varchar(512) NOT NULL UNIQUE CHECK (length(trim(receipt_external_id)) BETWEEN 1 AND 512),
    receipt_digest bytea NOT NULL UNIQUE CHECK (octet_length(receipt_digest) = 32),
    provider_proof bytea NOT NULL CHECK (octet_length(provider_proof) > 0),
    provider_proof_digest bytea NOT NULL CHECK (octet_length(provider_proof_digest) = 32),
    provider_proof_algorithm varchar(128) NOT NULL CHECK (length(trim(provider_proof_algorithm)) BETWEEN 1 AND 128),
    provider_proof_key_id varchar(512) NOT NULL CHECK (length(trim(provider_proof_key_id)) BETWEEN 1 AND 512),
    provider_proof_protocol_version varchar(128) NOT NULL
        CHECK (length(trim(provider_proof_protocol_version)) BETWEEN 1 AND 128),
    published_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (plan_id, delivery_id),
    UNIQUE (manifest_id, member_id),
    CHECK (provider_proof_digest = digest(provider_proof, 'sha256'))
);

CREATE OR REPLACE FUNCTION enforce_member_artifact_receipt_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'member artifact receipt is append-only'; END IF;
    IF NEW.published_at > CURRENT_TIMESTAMP + interval '5 minutes' THEN
        RAISE EXCEPTION 'member artifact receipt publication time is in the future';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM recovery_epoch_plans plan
        JOIN manifests manifest ON manifest.id = NEW.manifest_id AND manifest.recovery_plan_id = plan.id
        JOIN recovery_share_deliveries delivery ON delivery.id = NEW.delivery_id
          AND delivery.recovery_plan_id = plan.id AND delivery.epoch_id = manifest.epoch_id
        WHERE plan.id = NEW.plan_id AND plan.status NOT IN ('PLANNED','ROOT_COMMITTED','SHARES_COMMITTED','FAILED')
          AND manifest.epoch_id = NEW.epoch_id AND delivery.member_id = NEW.member_id
          AND manifest.migration_state = 'CURRENT' AND delivery.migration_state = 'CURRENT'
          AND (plan.status = 'MANIFEST_DRAFT' OR
               (delivery.delivery_status = 'ACKNOWLEDGED' AND
                manifest.manifest_hash = delivery.acknowledged_manifest_hash))
    ) THEN RAISE EXCEPTION 'member artifact receipt is not bound to the exact plan artifact'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_member_artifact_receipts_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_member_artifact_receipts
FOR EACH ROW EXECUTE FUNCTION enforce_member_artifact_receipt_phase2h();

CREATE OR REPLACE FUNCTION require_portable_member_receipts_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'MANIFEST_SIGNED' AND OLD.status = 'MANIFEST_DRAFT' AND
       NEW.portable_format_version IS NOT NULL AND
       (SELECT count(*) FROM recovery_member_artifact_receipts receipt WHERE receipt.plan_id = NEW.id) <>
       NEW.expected_member_count THEN
        RAISE EXCEPTION 'portable plan requires one member artifact receipt per formal member';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_epoch_plan_portable_receipts_phase2h
BEFORE UPDATE ON recovery_epoch_plans
FOR EACH ROW EXECUTE FUNCTION require_portable_member_receipts_phase2h();

CREATE TABLE recovery_verification_exports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    manifest_id uuid NOT NULL REFERENCES manifests(id) ON DELETE RESTRICT,
    format_version varchar(128) NOT NULL CHECK (length(trim(format_version)) BETWEEN 1 AND 128),
    capability text NOT NULL CHECK (capability IN ('LEGACY_EXPORT_LIMITED','REVEAL_CAPABLE')),
    missing_evidence_codes text[] NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','AVAILABLE','RECONCILE_REQUIRED','FAILED')),
    inventory_digest bytea,
    bundle_digest bytea,
    signer_domain varchar(256),
    signer_algorithm varchar(128),
    signer_key_id varchar(512),
    signature bytea,
    generated_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (plan_id, external_id),
    CHECK ((capability = 'LEGACY_EXPORT_LIMITED' AND cardinality(missing_evidence_codes) > 0) OR
           (capability = 'REVEAL_CAPABLE' AND cardinality(missing_evidence_codes) = 0)),
    CHECK ((status <> 'AVAILABLE' AND inventory_digest IS NULL AND bundle_digest IS NULL AND
            signer_domain IS NULL AND signer_algorithm IS NULL AND signer_key_id IS NULL AND
            signature IS NULL AND generated_at IS NULL) OR
           (status = 'AVAILABLE' AND octet_length(inventory_digest) = 32 AND octet_length(bundle_digest) = 32 AND
            signer_domain = 'trusted-pool/verification-export-signature/v1' AND
            length(trim(signer_algorithm)) BETWEEN 1 AND 128 AND
            length(trim(signer_key_id)) BETWEEN 1 AND 512 AND octet_length(signature) > 0 AND
            generated_at IS NOT NULL))
);

CREATE OR REPLACE FUNCTION enforce_verification_export_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'verification export is an immutable ledger'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.version <> 1 OR NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN manifests manifest ON manifest.id = NEW.manifest_id AND manifest.recovery_plan_id = plan.id
            JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
            JOIN recovery_pool_provider_commit_attempts provider_commit ON provider_commit.plan_id = plan.id
            JOIN integration_operations operation ON operation.id = NEW.integration_operation_id
            WHERE plan.id = NEW.plan_id AND plan.status = 'FINALIZED' AND manifest.status = 'ACTIVE'
              AND replacement.status = 'FINALIZED' AND provider_commit.status = 'RELEASED'
              AND operation.operation_type = 'EXPORT_RECOVERY_VERIFICATION'
              AND operation.target_type = 'POOL' AND operation.target_id = plan.pool_id
              AND operation.status = 'RUNNING' AND operation.fencing_token > 0
        ) THEN RAISE EXCEPTION 'verification export requires a fully released finalized plan'; END IF;
        IF NEW.capability = 'REVEAL_CAPABLE' AND NOT EXISTS (
            SELECT 1 FROM recovery_epoch_plans plan
            JOIN manifests manifest ON manifest.id = NEW.manifest_id
            JOIN recovery_root_artifacts root ON root.plan_id = plan.id
            WHERE plan.id = NEW.plan_id AND plan.portable_format_version IS NOT NULL
              AND plan.portable_format_version = 'trusted-pool/offline-evidence-bundle/v1'
              AND plan.root_trust_profile_id IS NOT NULL AND plan.crypto_suite_id IS NOT NULL
              AND plan.provider_proof_profile IS NOT NULL AND plan.ceremony_attestation_algorithm IS NOT NULL
              AND plan.provider_proof_profile = 'trusted-pool/provider-proof-statement/v1'
              AND plan.ceremony_attestation_algorithm = 'Ed25519'
              AND octet_length(plan.bootstrap_attestation_signature) = 64
              AND NEW.format_version = plan.portable_format_version
              AND manifest.platform_signature_domain = 'trusted-pool/platform-manifest-signature/v2'
              AND manifest.platform_algorithm = 'Ed25519'
              AND octet_length(manifest.platform_signature) = 64
              AND root.attestation_algorithm IS NOT NULL AND root.attestation_issuer IS NOT NULL
              AND root.portable_attestation_key_id IS NOT NULL
              AND root.attestation_algorithm = 'Ed25519'
              AND root.attestation_protocol_version = 'trusted-pool/provider-proof-statement/v1'
              AND octet_length(root.portable_attestation_signature) = 64
              AND NOT EXISTS (SELECT 1 FROM recovery_share_deliveries delivery
                WHERE delivery.recovery_plan_id = plan.id AND
                  (delivery.provider_proof_algorithm IS DISTINCT FROM 'Ed25519' OR
                   delivery.provider_proof_key_id IS NULL OR
                   delivery.provider_proof_protocol_version IS DISTINCT FROM 'trusted-pool/provider-proof-statement/v1' OR
                   octet_length(delivery.portable_provider_proof_signature) IS DISTINCT FROM 64))
              AND (SELECT count(*) FROM recovery_member_artifact_receipts receipt WHERE receipt.plan_id = plan.id)
                  = plan.expected_member_count
              AND (SELECT count(*) FROM manifest_signatures signature
                   WHERE signature.manifest_id = manifest.id AND signature.migration_state = 'CURRENT'
                     AND signature.signing_algorithm = 'Ed25519' AND octet_length(signature.signature) = 64)
                  >= plan.governance_threshold
              AND (SELECT count(*) FROM recovery_share_deliveries acknowledged
                   WHERE acknowledged.recovery_plan_id = plan.id AND acknowledged.migration_state = 'CURRENT'
                     AND acknowledged.delivery_status = 'ACKNOWLEDGED'
                     AND acknowledged.acknowledgement_algorithm = 'Ed25519'
                     AND octet_length(acknowledged.acknowledgement_signature) = 64)
                  = plan.expected_member_count
              AND (SELECT count(*) FROM recovery_control_evidence evidence
                   WHERE evidence.plan_id = plan.id AND evidence.status = 'COMMITTED'
                     AND evidence.provider_attestation_algorithm = 'Ed25519'
                     AND octet_length(evidence.provider_attestation_signature) = 64
                     AND evidence.provider_attestation_protocol_version = 'trusted-pool/provider-proof-statement/v1')
                  = plan.expected_resource_count
        ) THEN RAISE EXCEPTION 'REVEAL_CAPABLE export lacks portable v2 evidence'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.plan_id IS DISTINCT FROM OLD.plan_id OR NEW.manifest_id IS DISTINCT FROM OLD.manifest_id OR
       NEW.format_version IS DISTINCT FROM OLD.format_version OR NEW.capability IS DISTINCT FROM OLD.capability OR
       NEW.missing_evidence_codes IS DISTINCT FROM OLD.missing_evidence_codes OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.version <> OLD.version + 1 OR NOT (
          (OLD.status = 'PENDING' AND NEW.status IN ('AVAILABLE','RECONCILE_REQUIRED','FAILED')) OR
          (OLD.status = 'RECONCILE_REQUIRED' AND NEW.status IN ('AVAILABLE','FAILED'))
       ) THEN RAISE EXCEPTION 'illegal verification export transition'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_verification_exports_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_verification_exports
FOR EACH ROW EXECUTE FUNCTION enforce_verification_export_phase2h();

-- Reveal 在线账本只描述授权和外部执行结果；scope/challenge/transcript/sink 均为非秘密摘要。
CREATE TABLE recovery_reveal_authorizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    verification_export_id uuid NOT NULL REFERENCES recovery_verification_exports(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    manifest_id uuid NOT NULL REFERENCES manifests(id) ON DELETE RESTRICT,
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    membership_epoch integer NOT NULL CHECK (membership_epoch > 0),
    purpose varchar(128) NOT NULL CHECK (length(trim(purpose)) BETWEEN 1 AND 128),
    scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
    challenge_hash bytea NOT NULL UNIQUE CHECK (octet_length(challenge_hash) = 32),
    governance_threshold smallint NOT NULL CHECK (governance_threshold > 0),
    recovery_threshold smallint NOT NULL CHECK (recovery_threshold > 0),
    status text NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (status IN (
        'PENDING_APPROVAL','AUTHORIZED','AUTHORIZATION_EXPORTED','COMPLETED',
        'CANCELLED','EXPIRED','ABORTED','OPERATOR_REVIEW_REQUIRED'
    )),
    authorization_digest bytea,
    authorization_signer_domain varchar(256),
    authorization_signer_algorithm varchar(128),
    authorization_signer_key_id varchar(512),
    authorization_signature bytea,
    expires_at timestamptz NOT NULL,
    authorized_at timestamptz,
    authorization_exported_at timestamptz,
    completed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, plan_id, manifest_id),
    CHECK (recovery_threshold <= governance_threshold),
    CHECK ((status = 'PENDING_APPROVAL' AND authorized_at IS NULL AND
            authorization_digest IS NULL AND authorization_signature IS NULL AND
            authorization_exported_at IS NULL AND completed_at IS NULL) OR
           (status = 'AUTHORIZED' AND authorized_at IS NOT NULL AND
            authorization_digest IS NULL AND authorization_signature IS NULL AND
            authorization_exported_at IS NULL AND completed_at IS NULL) OR
           (status IN ('CANCELLED','EXPIRED') AND authorization_digest IS NULL AND
            authorization_signature IS NULL AND authorization_exported_at IS NULL AND completed_at IS NOT NULL) OR
           (status IN ('AUTHORIZATION_EXPORTED','OPERATOR_REVIEW_REQUIRED') AND
             authorized_at IS NOT NULL AND
             octet_length(authorization_digest) = 32 AND
            length(trim(authorization_signer_domain)) BETWEEN 1 AND 256 AND
            length(trim(authorization_signer_algorithm)) BETWEEN 1 AND 128 AND
            length(trim(authorization_signer_key_id)) BETWEEN 1 AND 512 AND
            octet_length(authorization_signature) > 0 AND authorization_exported_at IS NOT NULL AND
            completed_at IS NULL) OR
           (status IN ('COMPLETED','ABORTED') AND authorized_at IS NOT NULL AND
             octet_length(authorization_digest) = 32 AND
            octet_length(authorization_signature) > 0 AND authorization_exported_at IS NOT NULL AND
            completed_at IS NOT NULL))
);

CREATE TABLE recovery_reveal_approval_intents (
    reveal_id uuid NOT NULL REFERENCES recovery_reveal_authorizations(id) ON DELETE RESTRICT,
    epoch_id uuid NOT NULL REFERENCES membership_epochs(id) ON DELETE RESTRICT,
    member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    expected_message_hash bytea NOT NULL CHECK (octet_length(expected_message_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (reveal_id, member_id),
    UNIQUE (reveal_id, expected_message_hash),
    FOREIGN KEY (epoch_id, member_id) REFERENCES membership_epoch_members(epoch_id, member_id) ON DELETE RESTRICT
);

CREATE TABLE recovery_reveal_approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reveal_id uuid NOT NULL REFERENCES recovery_reveal_authorizations(id) ON DELETE RESTRICT,
    epoch_id uuid NOT NULL REFERENCES membership_epochs(id) ON DELETE RESTRICT,
    member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    signing_algorithm varchar(128) NOT NULL,
    signing_key_id varchar(512) NOT NULL,
    message_hash bytea NOT NULL CHECK (octet_length(message_hash) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    verified_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (reveal_id, member_id),
    FOREIGN KEY (epoch_id, member_id) REFERENCES membership_epoch_members(epoch_id, member_id) ON DELETE RESTRICT
);

CREATE TABLE recovery_reveal_executor_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reveal_id uuid NOT NULL UNIQUE REFERENCES recovery_reveal_authorizations(id) ON DELETE RESTRICT,
    disposition text NOT NULL CHECK (disposition IN ('COMPLETED','ABORTED')),
    receipt_digest bytea NOT NULL UNIQUE CHECK (octet_length(receipt_digest) = 32),
    transcript_digest bytea NOT NULL CHECK (octet_length(transcript_digest) = 32),
    sink_attestation_digest bytea NOT NULL CHECK (octet_length(sink_attestation_digest) = 32),
    executor_profile varchar(256) NOT NULL,
    executor_algorithm varchar(128) NOT NULL,
    executor_key_id varchar(512) NOT NULL,
    executor_signature bytea NOT NULL CHECK (octet_length(executor_signature) > 0),
    completed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION recovery_reveal_event_hash(previous_hash bytea, canonical_bytes bytea)
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT digest(convert_to('trusted-pool/reveal-event/v1', 'UTF8') ||
                  COALESCE(previous_hash, decode(repeat('00', 32), 'hex')) || canonical_bytes, 'sha256');
$$;

CREATE TABLE recovery_reveal_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reveal_id uuid NOT NULL REFERENCES recovery_reveal_authorizations(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'REQUESTED','APPROVALS_COMMITTED','AUTHORIZED','AUTHORIZATION_EXPORTED',
        'COMPLETED','CANCELLED','EXPIRED','ABORTED','OPERATOR_REVIEW_REQUIRED'
    )),
    event_payload jsonb NOT NULL CHECK (jsonb_typeof(event_payload) = 'object'),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) > 0),
    previous_event_hash bytea,
    event_hash bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (reveal_id, sequence),
    CHECK (event_payload = convert_from(canonical_bytes, 'UTF8')::jsonb),
    CHECK ((sequence = 1 AND previous_event_hash IS NULL) OR
           (sequence > 1 AND octet_length(previous_event_hash) = 32)),
    CHECK (event_hash = recovery_reveal_event_hash(previous_event_hash, canonical_bytes))
);

CREATE OR REPLACE FUNCTION enforce_reveal_authorization_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Reveal authorization is an immutable ledger'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING_APPROVAL' OR NEW.version <> 1 OR
           NEW.expires_at <= CURRENT_TIMESTAMP OR NEW.expires_at > CURRENT_TIMESTAMP + interval '24 hours' OR
           NOT EXISTS (
             SELECT 1 FROM recovery_verification_exports export
             JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
             JOIN manifests manifest ON manifest.id = export.manifest_id
             JOIN membership_epochs epoch ON epoch.id = manifest.epoch_id
             JOIN pools pool ON pool.id = plan.pool_id
             JOIN integration_operations operation ON operation.id = NEW.integration_operation_id
             WHERE export.id = NEW.verification_export_id AND export.status = 'AVAILABLE'
               AND export.capability = 'REVEAL_CAPABLE' AND plan.id = NEW.plan_id
               AND manifest.id = NEW.manifest_id AND manifest.status = 'ACTIVE'
               AND epoch.status = 'ACTIVE' AND epoch.epoch = NEW.membership_epoch
               AND pool.id = NEW.pool_id AND pool.membership_epoch = NEW.membership_epoch
               AND operation.operation_type = 'AUTHORIZE_RECOVERY_REVEAL'
               AND operation.target_type = 'POOL' AND operation.target_id = pool.id
               AND operation.status = 'RUNNING' AND operation.fencing_token > 0
               AND NEW.governance_threshold = epoch.governance_threshold
               AND NEW.recovery_threshold = epoch.recovery_threshold
           ) THEN RAISE EXCEPTION 'Reveal requires a current REVEAL_CAPABLE export'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.status NOT IN ('PENDING_APPROVAL','CANCELLED','EXPIRED') THEN
        RAISE EXCEPTION 'online Reveal authorization and execution are unavailable in Phase2-H';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.verification_export_id IS DISTINCT FROM OLD.verification_export_id OR
       NEW.plan_id IS DISTINCT FROM OLD.plan_id OR NEW.manifest_id IS DISTINCT FROM OLD.manifest_id OR
       NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.membership_epoch IS DISTINCT FROM OLD.membership_epoch OR
       NEW.purpose IS DISTINCT FROM OLD.purpose OR NEW.scope_hash IS DISTINCT FROM OLD.scope_hash OR
       NEW.challenge_hash IS DISTINCT FROM OLD.challenge_hash OR
       NEW.governance_threshold IS DISTINCT FROM OLD.governance_threshold OR
       NEW.recovery_threshold IS DISTINCT FROM OLD.recovery_threshold OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.version <> OLD.version + 1 OR NOT (
         (OLD.status = 'PENDING_APPROVAL' AND NEW.status IN ('AUTHORIZED','CANCELLED','EXPIRED')) OR
         (OLD.status = 'AUTHORIZED' AND NEW.status IN ('AUTHORIZATION_EXPORTED','CANCELLED','EXPIRED')) OR
         (OLD.status = 'AUTHORIZATION_EXPORTED' AND NEW.status IN ('COMPLETED','ABORTED','OPERATOR_REVIEW_REQUIRED')) OR
         (OLD.status = 'OPERATOR_REVIEW_REQUIRED' AND NEW.status IN ('COMPLETED','ABORTED'))
       ) THEN RAISE EXCEPTION 'illegal Reveal authorization transition'; END IF;
    IF NEW.status = 'AUTHORIZED' AND
       (SELECT count(*) FROM recovery_reveal_approvals approval WHERE approval.reveal_id = NEW.id) <
       NEW.governance_threshold THEN RAISE EXCEPTION 'Reveal governance threshold is not met'; END IF;
    IF NEW.status = 'AUTHORIZATION_EXPORTED' AND
       NEW.authorization_signer_domain <> 'trusted-pool/reveal-authorization/v1' THEN
        RAISE EXCEPTION 'Reveal authorization requires the portable v1 signature domain';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_reveal_authorizations_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_reveal_authorizations
FOR EACH ROW EXECUTE FUNCTION enforce_reveal_authorization_phase2h();

CREATE OR REPLACE FUNCTION reject_reveal_approval_intent_mutation_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Reveal approval intent is append-only'; END IF;
    IF NOT EXISTS (
      SELECT 1 FROM recovery_reveal_authorizations reveal
      JOIN membership_epochs epoch ON epoch.pool_id = reveal.pool_id AND epoch.epoch = reveal.membership_epoch
      JOIN membership_epoch_members snapshot ON snapshot.epoch_id = epoch.id AND snapshot.member_id = NEW.member_id
      WHERE reveal.id = NEW.reveal_id AND reveal.status = 'PENDING_APPROVAL' AND epoch.id = NEW.epoch_id
        AND snapshot.migration_state = 'CURRENT'
    ) THEN RAISE EXCEPTION 'Reveal approval intent member is outside the trusted Epoch'; END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER recovery_reveal_approval_intents_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_reveal_approval_intents
FOR EACH ROW EXECUTE FUNCTION reject_reveal_approval_intent_mutation_phase2h();

CREATE OR REPLACE FUNCTION enforce_reveal_approval_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE trusted record;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Reveal approval evidence is append-only'; END IF;
    RAISE EXCEPTION 'online Reveal approval execution is unavailable in Phase2-H';
    SELECT reveal.status, reveal.expires_at, snapshot.signing_algorithm, snapshot.signing_key_id,
           intent.expected_message_hash INTO trusted
    FROM recovery_reveal_authorizations reveal
    JOIN recovery_reveal_approval_intents intent ON intent.reveal_id = reveal.id AND intent.member_id = NEW.member_id
    JOIN membership_epoch_members snapshot ON snapshot.epoch_id = intent.epoch_id AND snapshot.member_id = intent.member_id
    WHERE reveal.id = NEW.reveal_id AND intent.epoch_id = NEW.epoch_id AND snapshot.migration_state = 'CURRENT';
    IF NOT FOUND OR trusted.status IS DISTINCT FROM 'PENDING_APPROVAL' OR trusted.expires_at IS NULL OR
       trusted.expires_at <= CURRENT_TIMESTAMP OR
       NEW.verified_at < (SELECT created_at FROM recovery_reveal_authorizations WHERE id = NEW.reveal_id) OR
       NEW.verified_at > CURRENT_TIMESTAMP + interval '5 minutes' OR
       NEW.signing_algorithm IS DISTINCT FROM trusted.signing_algorithm OR
       NEW.signing_key_id IS DISTINCT FROM trusted.signing_key_id OR
       NEW.message_hash IS DISTINCT FROM trusted.expected_message_hash THEN
        RAISE EXCEPTION 'Reveal approval is not verified against its immutable Epoch intent';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_reveal_approvals_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_reveal_approvals
FOR EACH ROW EXECUTE FUNCTION enforce_reveal_approval_phase2h();

CREATE OR REPLACE FUNCTION enforce_reveal_executor_receipt_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Reveal executor receipt is append-only'; END IF;
    RAISE EXCEPTION 'online Reveal executor execution is unavailable in Phase2-H';
    IF NOT EXISTS (SELECT 1 FROM recovery_reveal_authorizations reveal WHERE reveal.id = NEW.reveal_id
                   AND reveal.status IN ('AUTHORIZATION_EXPORTED','OPERATOR_REVIEW_REQUIRED')
                   AND reveal.authorization_exported_at IS NOT NULL
                   AND NEW.completed_at >= reveal.authorization_exported_at
                   AND NEW.completed_at <= CURRENT_TIMESTAMP + interval '5 minutes') THEN
        RAISE EXCEPTION 'executor receipt requires an irreversibly exported authorization';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_reveal_executor_receipts_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_reveal_executor_receipts
FOR EACH ROW EXECUTE FUNCTION enforce_reveal_executor_receipt_phase2h();

CREATE OR REPLACE FUNCTION enforce_reveal_event_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous_sequence bigint; previous_hash bytea; parent_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Reveal event chain is append-only'; END IF;
    SELECT id INTO parent_id FROM recovery_reveal_authorizations WHERE id = NEW.reveal_id FOR UPDATE;
    IF parent_id IS NULL THEN RAISE EXCEPTION 'Reveal event lacks its parent'; END IF;
    SELECT sequence, event_hash INTO previous_sequence, previous_hash FROM recovery_reveal_events
      WHERE reveal_id = NEW.reveal_id ORDER BY sequence DESC LIMIT 1;
    IF (previous_sequence IS NULL AND (NEW.sequence <> 1 OR NEW.previous_event_hash IS NOT NULL)) OR
       (previous_sequence IS NOT NULL AND
        (NEW.sequence <> previous_sequence + 1 OR NEW.previous_event_hash IS DISTINCT FROM previous_hash)) THEN
        RAISE EXCEPTION 'Reveal event chain fork or sequence gap';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_reveal_events_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_reveal_events
FOR EACH ROW EXECUTE FUNCTION enforce_reveal_event_phase2h();

CREATE OR REPLACE FUNCTION assert_reveal_aggregate_phase2h(target_reveal_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE target recovery_reveal_authorizations%ROWTYPE;
        approvals integer;
        receipt_id uuid;
        receipt_disposition text;
        receipt_completed_at timestamptz;
        latest_sequence bigint;
        latest_event_type text;
BEGIN
    SELECT * INTO target FROM recovery_reveal_authorizations WHERE id = target_reveal_id;
    IF target.id IS NULL THEN RETURN; END IF;
    SELECT count(*) INTO approvals FROM recovery_reveal_approvals WHERE reveal_id = target.id;
    SELECT sequence, event_type INTO latest_sequence, latest_event_type FROM recovery_reveal_events
      WHERE reveal_id = target.id ORDER BY sequence DESC LIMIT 1;
    SELECT id, disposition, completed_at INTO receipt_id, receipt_disposition, receipt_completed_at
      FROM recovery_reveal_executor_receipts WHERE reveal_id = target.id;
    IF latest_sequence IS NULL THEN RAISE EXCEPTION 'Reveal authorization lacks its event chain'; END IF;
    IF (SELECT count(*) FROM recovery_reveal_approval_intents intent WHERE intent.reveal_id = target.id) <>
       (SELECT expected_member_count FROM recovery_epoch_plans plan WHERE plan.id = target.plan_id) THEN
        RAISE EXCEPTION 'Reveal authorization lacks its exact member approval intent set';
    END IF;
    IF target.status = 'PENDING_APPROVAL' AND
       (approvals >= target.governance_threshold OR latest_event_type NOT IN ('REQUESTED','APPROVALS_COMMITTED')) THEN
        RAISE EXCEPTION 'pending Reveal aggregate is inconsistent';
    ELSIF target.status = 'AUTHORIZED' AND
       (approvals < target.governance_threshold OR latest_event_type <> 'AUTHORIZED') THEN
        RAISE EXCEPTION 'authorized Reveal aggregate is inconsistent';
    ELSIF target.status = 'AUTHORIZATION_EXPORTED' AND latest_event_type <> 'AUTHORIZATION_EXPORTED' THEN
        RAISE EXCEPTION 'exported Reveal aggregate is inconsistent';
    ELSIF target.status IN ('COMPLETED','ABORTED') AND
       (receipt_id IS NULL OR receipt_disposition <> target.status OR latest_event_type <> target.status OR
        target.completed_at IS DISTINCT FROM receipt_completed_at) THEN
        RAISE EXCEPTION 'terminal Reveal aggregate lacks its exact executor receipt';
    ELSIF target.status IN ('CANCELLED','EXPIRED','OPERATOR_REVIEW_REQUIRED') AND
       latest_event_type <> target.status THEN
        RAISE EXCEPTION 'fail-closed Reveal aggregate lacks its terminal event';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_reveal_aggregate_phase2h()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_reveal_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'recovery_reveal_authorizations' THEN
        target_reveal_id := NEW.id;
    ELSE
        target_reveal_id := NEW.reveal_id;
    END IF;
    PERFORM assert_reveal_aggregate_phase2h(target_reveal_id);
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER recovery_reveal_authorizations_aggregate
AFTER INSERT OR UPDATE ON recovery_reveal_authorizations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_reveal_aggregate_phase2h();
CREATE CONSTRAINT TRIGGER recovery_reveal_approvals_aggregate
AFTER INSERT ON recovery_reveal_approvals DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_reveal_aggregate_phase2h();
CREATE CONSTRAINT TRIGGER recovery_reveal_receipts_aggregate
AFTER INSERT ON recovery_reveal_executor_receipts DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_reveal_aggregate_phase2h();
CREATE CONSTRAINT TRIGGER recovery_reveal_events_aggregate
AFTER INSERT ON recovery_reveal_events DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_reveal_aggregate_phase2h();

-- 专用 aggregate 与 integration operation 必须在同一事务闭合，通用 CommitOperation 无法绕过。
CREATE OR REPLACE FUNCTION assert_phase2h_operation_aggregate(target_operation_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE operation_status text; operation_kind text; aggregate_status text;
BEGIN
    SELECT status, operation_type INTO operation_status, operation_kind
      FROM integration_operations WHERE id = target_operation_id;
    IF operation_kind = 'EXPORT_RECOVERY_VERIFICATION' THEN
        SELECT status INTO aggregate_status FROM recovery_verification_exports
          WHERE integration_operation_id = target_operation_id;
        IF aggregate_status IS NULL OR
           (operation_status = 'SUCCEEDED') <> (aggregate_status = 'AVAILABLE') OR
           (operation_status = 'FAILED' AND aggregate_status NOT IN ('FAILED','RECONCILE_REQUIRED')) THEN
            RAISE EXCEPTION 'verification export operation/aggregate is inconsistent';
        END IF;
    ELSIF operation_kind = 'AUTHORIZE_RECOVERY_REVEAL' THEN
        SELECT status INTO aggregate_status FROM recovery_reveal_authorizations
          WHERE integration_operation_id = target_operation_id;
        IF aggregate_status IS NULL OR
           (operation_status = 'SUCCEEDED') <> (aggregate_status = 'COMPLETED') OR
           (operation_status = 'FAILED' AND aggregate_status NOT IN ('ABORTED','CANCELLED','EXPIRED')) OR
           (aggregate_status IN ('COMPLETED','ABORTED') AND operation_status NOT IN ('SUCCEEDED','FAILED')) THEN
            RAISE EXCEPTION 'Reveal operation/aggregate is inconsistent';
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_phase2h_operation_aggregate()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_operation_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'integration_operations' THEN
        target_operation_id := NEW.id;
    ELSE
        target_operation_id := NEW.integration_operation_id;
    END IF;
    PERFORM assert_phase2h_operation_aggregate(target_operation_id);
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER integration_operations_phase2h_aggregate
AFTER INSERT OR UPDATE ON integration_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_phase2h_operation_aggregate();
CREATE CONSTRAINT TRIGGER recovery_verification_exports_operation_aggregate
AFTER INSERT OR UPDATE ON recovery_verification_exports DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_phase2h_operation_aggregate();
CREATE CONSTRAINT TRIGGER recovery_reveal_authorizations_operation_aggregate
AFTER INSERT OR UPDATE ON recovery_reveal_authorizations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_phase2h_operation_aggregate();

-- 007/008 的跨表 deferred trigger 使用 CASE 读取动态 NEW 记录的不同字段。
-- PostgreSQL 可能在未选择的分支仍解析不存在的字段；010 覆盖函数以安全升级已有 ledger。
CREATE OR REPLACE FUNCTION validate_credential_batch_history_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_batch_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'credential_batch_transitions' THEN
        target_batch_id := NEW.credential_batch_id;
    ELSE
        target_batch_id := NEW.id;
    END IF;
    PERFORM assert_credential_batch_transition_history(target_batch_id);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_recovery_plan_snapshot_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_plan_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'recovery_epoch_plans' THEN
        target_plan_id := NEW.id;
    ELSE
        target_plan_id := NEW.plan_id;
    END IF;
    PERFORM assert_recovery_plan_authoritative_snapshot(target_plan_id);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_manifest_batch_intent_projection_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_manifest_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'manifests' THEN
        target_manifest_id := NEW.id;
    ELSE
        target_manifest_id := NEW.manifest_id;
    END IF;
    PERFORM assert_manifest_batch_intent_projection(target_manifest_id);
    RETURN NULL;
END;
$$;

COMMENT ON TABLE recovery_verification_exports IS
  '公共离线验证包的 intent/摘要/签名账本；不保存 bundle、Share ciphertext、批次密文或 wrapped DEK';
COMMENT ON TABLE recovery_reveal_authorizations IS
  'Reveal 在线授权状态；scope/challenge 仅存摘要，Root/Share/DEK/credential 永不进入本表';
COMMENT ON TABLE recovery_reveal_executor_receipts IS
  '外部离线执行器的非秘密结果回执；禁止保存输出或任何 secret-derived digest';

COMMIT;
