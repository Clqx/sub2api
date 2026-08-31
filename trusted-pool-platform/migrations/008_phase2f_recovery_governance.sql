BEGIN;

-- Phase2-F 将恢复治理建模为 Pool 级可恢复聚合。历史 Root/Share/Manifest 缺少完整
-- 密钥来源、PoP、规范字节和验签证据，只能保留为 LEGACY_UNVERIFIED，禁止推断补齐。

CREATE TABLE pool_resource_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    registration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    provider varchar(64) NOT NULL CHECK (length(trim(provider)) BETWEEN 1 AND 64),
    provider_account_ref varchar(512) NOT NULL CHECK (length(trim(provider_account_ref)) BETWEEN 1 AND 512),
    inventory_version bigint NOT NULL CHECK (inventory_version > 0),
    provider_key_ref varchar(512) NOT NULL CHECK (length(trim(provider_key_ref)) BETWEEN 1 AND 512),
    attestation_digest bytea NOT NULL CHECK (octet_length(attestation_digest) = 32),
    attestation_signature bytea NOT NULL CHECK (octet_length(attestation_signature) > 0),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'RETIRED')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (pool_id, provider, provider_account_ref),
    UNIQUE (id, pool_id)
);

CREATE TABLE pool_resource_account_seats (
    resource_account_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    seat_id uuid NOT NULL,
    mapping_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    inventory_version bigint NOT NULL CHECK (inventory_version > 0),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'RETIRED')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at timestamptz,
    PRIMARY KEY (resource_account_id, seat_id, inventory_version),
    FOREIGN KEY (resource_account_id, pool_id)
        REFERENCES pool_resource_accounts(id, pool_id) ON DELETE RESTRICT,
    FOREIGN KEY (seat_id, pool_id) REFERENCES seats(id, pool_id) ON DELETE RESTRICT,
    CHECK ((status = 'ACTIVE' AND retired_at IS NULL) OR (status = 'RETIRED' AND retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_pool_resource_account_seats_active
    ON pool_resource_account_seats(resource_account_id, seat_id) WHERE status = 'ACTIVE';
CREATE INDEX idx_pool_resource_account_seats_seat
    ON pool_resource_account_seats(pool_id, seat_id) WHERE status = 'ACTIVE';

COMMENT ON TABLE pool_resource_accounts IS
    'Pool 权威供应商账号清单；不能从批次 account_ref 或 Seat 数量反向猜测历史账号';
COMMENT ON TABLE pool_resource_account_seats IS
    '账号与 Seat 的显式多对多范围；每次映射有独立幂等 operation 和 inventory version';

ALTER TABLE membership_epoch_members
    ADD COLUMN source_seat_id uuid,
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT'
        CHECK (migration_state IN ('CURRENT', 'LEGACY_UNVERIFIED')),
    ADD COLUMN signing_algorithm varchar(64),
    ADD COLUMN signing_key_id varchar(512),
    ADD COLUMN signing_key_fingerprint bytea,
    ADD COLUMN signing_proof_algorithm varchar(64),
    ADD COLUMN signing_proof bytea,
    ADD COLUMN recovery_key_algorithm varchar(64),
    ADD COLUMN recovery_key_id varchar(512),
    ADD COLUMN recovery_encryption_public_key bytea,
    ADD COLUMN recovery_key_fingerprint bytea,
    ADD COLUMN recovery_key_proof_algorithm varchar(64),
    ADD COLUMN recovery_key_proof bytea;

UPDATE membership_epoch_members SET migration_state = 'LEGACY_UNVERIFIED';

ALTER TABLE membership_epoch_members
    ADD CONSTRAINT fk_membership_epoch_member_source_seat
        FOREIGN KEY (source_seat_id) REFERENCES seats(id) ON DELETE RESTRICT,
    ADD CONSTRAINT ck_membership_epoch_member_phase2f_shape CHECK (
        migration_state = 'LEGACY_UNVERIFIED' OR (
            source_seat_id IS NOT NULL AND
            length(trim(signing_algorithm)) BETWEEN 1 AND 64 AND
            length(trim(signing_key_id)) BETWEEN 1 AND 512 AND
            signing_public_key IS NOT NULL AND octet_length(signing_public_key) > 0 AND
            signing_key_fingerprint IS NOT NULL AND octet_length(signing_key_fingerprint) = 32 AND
            length(trim(signing_proof_algorithm)) BETWEEN 1 AND 64 AND
            signing_proof IS NOT NULL AND octet_length(signing_proof) > 0 AND
            length(trim(recovery_key_algorithm)) BETWEEN 1 AND 64 AND
            length(trim(recovery_key_id)) BETWEEN 1 AND 512 AND
            recovery_encryption_public_key IS NOT NULL AND octet_length(recovery_encryption_public_key) > 0 AND
            recovery_key_fingerprint IS NOT NULL AND octet_length(recovery_key_fingerprint) = 32 AND
            length(trim(recovery_key_proof_algorithm)) BETWEEN 1 AND 64 AND
            recovery_key_proof IS NOT NULL AND octet_length(recovery_key_proof) > 0 AND
            signing_key_id <> recovery_key_id AND
            signing_key_fingerprint <> recovery_key_fingerprint
        )
    );

CREATE TABLE recovery_epoch_plans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    ceremony_type text NOT NULL CHECK (ceremony_type IN ('BOOTSTRAP', 'ROTATE')),
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    from_epoch integer NOT NULL CHECK (from_epoch > 0),
    to_epoch integer NOT NULL CHECK (to_epoch = from_epoch + 1),
    status text NOT NULL DEFAULT 'PLANNED' CHECK (status IN (
        'PLANNED', 'ROOT_COMMITTED', 'SHARES_COMMITTED', 'MANIFEST_DRAFT',
        'MANIFEST_SIGNED', 'ACKNOWLEDGED', 'BATCHES_STAGED', 'READY', 'FINALIZED', 'FAILED'
    )),
    governance_threshold smallint NOT NULL CHECK (governance_threshold > 0),
    recovery_threshold smallint NOT NULL CHECK (recovery_threshold > 0),
    required_share_ack_count smallint NOT NULL CHECK (required_share_ack_count > 0),
    expected_member_count smallint NOT NULL CHECK (expected_member_count > 0),
    expected_seat_count smallint NOT NULL CHECK (expected_seat_count > 0),
    expected_resource_count integer NOT NULL CHECK (expected_resource_count > 0),
    expected_control_batch_count integer NOT NULL CHECK (expected_control_batch_count > 0),
    provider_attestation_set_hash bytea NOT NULL CHECK (octet_length(provider_attestation_set_hash) = 32),
    previous_manifest_hash bytea NOT NULL CHECK (octet_length(previous_manifest_hash) = 32),
    from_epoch_status text NOT NULL CHECK (from_epoch_status = 'ACTIVE'),
    from_governance_state text NOT NULL CHECK (from_governance_state IN ('LEGACY_UNVERIFIED', 'CURRENT')),
    bootstrap_attestation_ref varchar(1024),
    bootstrap_attestation_digest bytea,
    bootstrap_attestation_issuer varchar(512),
    bootstrap_attestation_key_id varchar(512),
    bootstrap_attestation_signature bytea,
    bootstrap_attestation_version bigint,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    ready_at timestamptz,
    finalized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, pool_id, from_epoch, to_epoch),
    UNIQUE (id, pool_id),
    FOREIGN KEY (pool_id, from_epoch) REFERENCES membership_epochs(pool_id, epoch)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (pool_id, to_epoch) REFERENCES membership_epochs(pool_id, epoch)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (recovery_threshold <= governance_threshold),
    CHECK (governance_threshold <= expected_member_count),
    CHECK (expected_member_count = expected_seat_count),
    CHECK (required_share_ack_count = expected_member_count),
    CHECK (expected_control_batch_count = expected_resource_count * 4),
    CHECK (
        (ceremony_type = 'BOOTSTRAP' AND from_governance_state = 'LEGACY_UNVERIFIED' AND
         previous_manifest_hash = decode(repeat('00', 32), 'hex') AND
         length(trim(bootstrap_attestation_ref)) BETWEEN 1 AND 1024 AND
         octet_length(bootstrap_attestation_digest) = 32 AND
         length(trim(bootstrap_attestation_issuer)) BETWEEN 1 AND 512 AND
         length(trim(bootstrap_attestation_key_id)) BETWEEN 1 AND 512 AND
         octet_length(bootstrap_attestation_signature) > 0 AND bootstrap_attestation_version > 0) OR
        (ceremony_type = 'ROTATE' AND from_governance_state = 'CURRENT' AND
         previous_manifest_hash <> decode(repeat('00', 32), 'hex') AND
         length(trim(bootstrap_attestation_ref)) BETWEEN 1 AND 1024 AND
         octet_length(bootstrap_attestation_digest) = 32 AND
         length(trim(bootstrap_attestation_issuer)) BETWEEN 1 AND 512 AND
         length(trim(bootstrap_attestation_key_id)) BETWEEN 1 AND 512 AND
         octet_length(bootstrap_attestation_signature) > 0 AND bootstrap_attestation_version > 0)
    ),
    CHECK ((status = 'READY') = (ready_at IS NOT NULL AND finalized_at IS NULL) OR status = 'FINALIZED'),
    CHECK ((status = 'FINALIZED') = (ready_at IS NOT NULL AND finalized_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_recovery_epoch_plans_open_pool
    ON recovery_epoch_plans(pool_id) WHERE status NOT IN ('FINALIZED', 'FAILED');

ALTER TABLE membership_epochs
    ADD COLUMN recovery_plan_id uuid UNIQUE REFERENCES recovery_epoch_plans(id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD COLUMN epoch_recovery_algorithm varchar(64),
    ADD COLUMN epoch_recovery_key_id varchar(512),
    ADD COLUMN epoch_recovery_key_fingerprint bytea,
    ADD COLUMN recovery_governance_state text NOT NULL DEFAULT 'LEGACY_UNVERIFIED'
        CHECK (recovery_governance_state IN ('LEGACY_UNVERIFIED', 'CURRENT'));

ALTER TABLE membership_epochs
    ADD CONSTRAINT uq_membership_epoch_plan_scope UNIQUE (id, pool_id, epoch, recovery_plan_id),
    ADD CONSTRAINT ck_membership_epoch_current_recovery_shape CHECK (
        recovery_governance_state = 'LEGACY_UNVERIFIED' OR (
            recovery_plan_id IS NOT NULL AND
            ((status = 'PREPARING' AND epoch_recovery_algorithm IS NULL AND
              epoch_recovery_key_id IS NULL AND epoch_recovery_key_fingerprint IS NULL) OR
             (length(trim(epoch_recovery_algorithm)) BETWEEN 1 AND 64 AND
              length(trim(epoch_recovery_key_id)) BETWEEN 1 AND 512 AND
              epoch_recovery_key_fingerprint IS NOT NULL AND
              octet_length(epoch_recovery_key_fingerprint) = 32))
        )
    );

CREATE TABLE recovery_plan_seats (
    plan_id uuid NOT NULL,
    pool_id uuid NOT NULL,
    from_epoch integer NOT NULL,
    to_epoch integer NOT NULL,
    seat_id uuid NOT NULL,
    from_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    to_member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
    expected_assignment_epoch bigint NOT NULL CHECK (expected_assignment_epoch > 0),
    expected_active_api_key_version integer NOT NULL CHECK (expected_active_api_key_version > 0),
    is_replacement boolean NOT NULL,
    freeze_suspension_case_id uuid REFERENCES suspension_cases(id) ON DELETE RESTRICT,
    freeze_operation_id varchar(128),
    freeze_snapshot_hash bytea,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id, seat_id),
    FOREIGN KEY (plan_id, pool_id, from_epoch, to_epoch)
        REFERENCES recovery_epoch_plans(id, pool_id, from_epoch, to_epoch) ON DELETE RESTRICT,
    FOREIGN KEY (seat_id, pool_id) REFERENCES seats(id, pool_id) ON DELETE RESTRICT,
    CHECK (to_epoch = from_epoch + 1),
    CHECK (freeze_suspension_case_id IS NOT NULL AND
           length(trim(freeze_operation_id)) BETWEEN 1 AND 128 AND octet_length(freeze_snapshot_hash) = 32),
    CHECK ((is_replacement AND from_member_id <> to_member_id) OR
           (NOT is_replacement AND from_member_id = to_member_id))
);

CREATE TABLE recovery_plan_resource_accounts (
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    resource_account_id uuid NOT NULL REFERENCES pool_resource_accounts(id) ON DELETE RESTRICT,
    pool_id uuid NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    account_external_id varchar(128) NOT NULL,
    provider varchar(64) NOT NULL,
    provider_account_ref varchar(512) NOT NULL,
    inventory_version bigint NOT NULL CHECK (inventory_version > 0),
    provider_key_ref varchar(512) NOT NULL,
    attestation_digest bytea NOT NULL CHECK (octet_length(attestation_digest) = 32),
    provider_binding varchar(1024) NOT NULL,
    control_evidence_external_id varchar(128) NOT NULL,
    control_attestation_digest bytea NOT NULL CHECK (octet_length(control_attestation_digest) = 32),
    control_attestation_issuer varchar(512) NOT NULL,
    control_attestation_key_id varchar(512) NOT NULL,
    control_attestation_version bigint NOT NULL CHECK (control_attestation_version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id, resource_account_id),
    UNIQUE (plan_id, account_external_id),
    FOREIGN KEY (resource_account_id, pool_id)
        REFERENCES pool_resource_accounts(id, pool_id) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id, pool_id)
        REFERENCES recovery_epoch_plans(id, pool_id) ON DELETE RESTRICT
);

CREATE TABLE recovery_plan_account_seats (
    plan_id uuid NOT NULL,
    resource_account_id uuid NOT NULL,
    seat_id uuid NOT NULL,
    inventory_version bigint NOT NULL CHECK (inventory_version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id, resource_account_id, seat_id),
    FOREIGN KEY (plan_id, resource_account_id)
        REFERENCES recovery_plan_resource_accounts(plan_id, resource_account_id) ON DELETE RESTRICT,
    FOREIGN KEY (seat_id) REFERENCES seats(id) ON DELETE RESTRICT
);

CREATE TABLE recovery_root_artifacts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE CHECK (length(trim(external_id)) BETWEEN 1 AND 128),
    plan_id uuid NOT NULL UNIQUE REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    provider varchar(128) NOT NULL CHECK (length(trim(provider)) BETWEEN 1 AND 128),
    provider_key_ref varchar(512) NOT NULL CHECK (length(trim(provider_key_ref)) BETWEEN 1 AND 512),
    root_handle varchar(1024) NOT NULL CHECK (length(trim(root_handle)) BETWEEN 1 AND 1024),
    root_key_version varchar(512) NOT NULL CHECK (length(trim(root_key_version)) BETWEEN 1 AND 512),
    epoch_recovery_algorithm varchar(64) NOT NULL,
    epoch_recovery_key_id varchar(512) NOT NULL,
    epoch_recovery_key_fingerprint bytea NOT NULL CHECK (octet_length(epoch_recovery_key_fingerprint) = 32),
    wrap_domain varchar(128) NOT NULL,
    wrap_algorithm varchar(64) NOT NULL,
    vss_algorithm varchar(64) NOT NULL,
    vss_commitment bytea NOT NULL CHECK (octet_length(vss_commitment) > 0),
    vss_commitment_hash bytea NOT NULL CHECK (octet_length(vss_commitment_hash) = 32),
    vss_proof bytea NOT NULL CHECK (octet_length(vss_proof) > 0),
    vss_proof_hash bytea NOT NULL CHECK (octet_length(vss_proof_hash) = 32),
    private_key_commitment bytea NOT NULL CHECK (octet_length(private_key_commitment) > 0),
    private_key_commitment_hash bytea NOT NULL CHECK (octet_length(private_key_commitment_hash) = 32),
    root_commitment_hash bytea NOT NULL CHECK (octet_length(root_commitment_hash) = 32),
    recovery_package_hash bytea NOT NULL CHECK (octet_length(recovery_package_hash) = 32),
    request_intent_hash bytea NOT NULL CHECK (octet_length(request_intent_hash) = 32),
    provider_attestation_ref varchar(1024) NOT NULL,
    attestation_digest bytea NOT NULL CHECK (octet_length(attestation_digest) = 32),
    attestation_signature bytea NOT NULL CHECK (octet_length(attestation_signature) > 0),
    attestation_key_id varchar(512) NOT NULL,
    migration_state text NOT NULL DEFAULT 'CURRENT' CHECK (migration_state IN ('CURRENT', 'LEGACY_UNVERIFIED')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, plan_id),
    CHECK (vss_commitment_hash = digest(vss_commitment, 'sha256')),
    CHECK (vss_proof_hash = digest(vss_proof, 'sha256')),
    CHECK (private_key_commitment_hash = digest(private_key_commitment, 'sha256'))
);

ALTER TABLE manifests
    ADD COLUMN external_id varchar(128),
    ADD COLUMN recovery_plan_id uuid REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    ADD COLUMN root_artifact_id uuid REFERENCES recovery_root_artifacts(id) ON DELETE RESTRICT,
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT'
        CHECK (migration_state IN ('CURRENT', 'LEGACY_UNVERIFIED')),
    ADD COLUMN canonical_bytes bytea,
    ADD COLUMN previous_manifest_hash bytea,
    ADD COLUMN batch_set_hash bytea,
    ADD COLUMN recovery_package_hash bytea,
    ADD COLUMN provider_attestation_digest bytea,
    ADD COLUMN platform_algorithm varchar(64),
    ADD COLUMN platform_key_ref varchar(512),
    ADD COLUMN platform_verified_at timestamptz;
UPDATE manifests SET external_id = id::text, migration_state = 'LEGACY_UNVERIFIED';
ALTER TABLE manifests
    ALTER COLUMN external_id SET NOT NULL,
    ADD CONSTRAINT uq_manifests_external_id UNIQUE (external_id),
    ADD CONSTRAINT fk_manifest_root_plan FOREIGN KEY (root_artifact_id, recovery_plan_id)
        REFERENCES recovery_root_artifacts(id, plan_id) ON DELETE RESTRICT,
    ADD CONSTRAINT ck_manifests_phase2f_shape CHECK (
        migration_state = 'LEGACY_UNVERIFIED' OR (
            recovery_plan_id IS NOT NULL AND root_artifact_id IS NOT NULL AND
            canonical_bytes IS NOT NULL AND octet_length(canonical_bytes) > 0 AND
            canonical_payload = convert_from(canonical_bytes, 'UTF8')::jsonb AND
            octet_length(manifest_hash) = 32 AND manifest_hash = digest(canonical_bytes, 'sha256') AND
            octet_length(previous_manifest_hash) = 32 AND octet_length(batch_set_hash) = 32 AND
            octet_length(recovery_package_hash) = 32 AND octet_length(provider_attestation_digest) = 32 AND
            length(trim(platform_algorithm)) BETWEEN 1 AND 64 AND
            length(trim(platform_key_ref)) BETWEEN 1 AND 512 AND platform_verified_at IS NOT NULL
        )
    );

ALTER TABLE manifest_signatures
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT'
        CHECK (migration_state IN ('CURRENT', 'LEGACY_UNVERIFIED')),
    ADD COLUMN signing_algorithm varchar(64),
    ADD COLUMN signing_key_id varchar(512),
    ADD COLUMN signing_key_fingerprint bytea,
    ADD COLUMN signed_message_hash bytea,
    ADD COLUMN verified_at timestamptz;
UPDATE manifest_signatures SET migration_state = 'LEGACY_UNVERIFIED';
ALTER TABLE manifest_signatures ADD CONSTRAINT ck_manifest_signature_phase2f_shape CHECK (
    migration_state = 'LEGACY_UNVERIFIED' OR (
        length(trim(signing_algorithm)) BETWEEN 1 AND 64 AND length(trim(signing_key_id)) BETWEEN 1 AND 512 AND
        octet_length(signing_key_fingerprint) = 32 AND octet_length(signed_message_hash) = 32 AND
        octet_length(signature) > 0 AND verified_at IS NOT NULL
    )
);

ALTER TABLE recovery_share_deliveries
    ADD COLUMN external_id varchar(128),
    ADD COLUMN recovery_plan_id uuid REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    ADD COLUMN root_artifact_id uuid REFERENCES recovery_root_artifacts(id) ON DELETE RESTRICT,
    ADD COLUMN migration_state text NOT NULL DEFAULT 'CURRENT'
        CHECK (migration_state IN ('CURRENT', 'LEGACY_UNVERIFIED')),
    ADD COLUMN share_index smallint,
    ADD COLUMN encryption_algorithm varchar(64),
    ADD COLUMN recipient_key_id varchar(512),
    ADD COLUMN recipient_key_fingerprint bytea,
    ADD COLUMN provider_share_commitment bytea,
    ADD COLUMN provider_proof_digest bytea,
    ADD COLUMN provider_proof_signature bytea,
    ADD COLUMN acknowledged_manifest_hash bytea,
    ADD COLUMN acknowledgement_algorithm varchar(64),
    ADD COLUMN acknowledgement_key_id varchar(512),
    ADD COLUMN acknowledgement_message_hash bytea,
    ADD COLUMN acknowledgement_signature bytea,
    ADD COLUMN acknowledgement_verified_at timestamptz;
UPDATE recovery_share_deliveries SET external_id = id::text, migration_state = 'LEGACY_UNVERIFIED';
ALTER TABLE recovery_share_deliveries
    ALTER COLUMN external_id SET NOT NULL,
    ADD CONSTRAINT uq_recovery_share_delivery_external_id UNIQUE (external_id),
    ADD CONSTRAINT fk_recovery_share_root_plan FOREIGN KEY (root_artifact_id, recovery_plan_id)
        REFERENCES recovery_root_artifacts(id, plan_id) ON DELETE RESTRICT,
    ADD CONSTRAINT ck_recovery_share_delivery_phase2f_shape CHECK (
        migration_state = 'LEGACY_UNVERIFIED' OR (
            recovery_plan_id IS NOT NULL AND root_artifact_id IS NOT NULL AND share_index > 0 AND
            length(trim(encryption_algorithm)) BETWEEN 1 AND 64 AND
            length(trim(recipient_key_id)) BETWEEN 1 AND 512 AND
            octet_length(recipient_key_fingerprint) = 32 AND octet_length(encrypted_share) > 0 AND
            octet_length(share_hash) = 32 AND share_hash = digest(encrypted_share, 'sha256') AND
            octet_length(provider_share_commitment) > 0 AND octet_length(provider_proof_digest) = 32 AND
            octet_length(provider_proof_signature) > 0 AND
            ((delivery_status <> 'ACKNOWLEDGED' AND acknowledged_manifest_hash IS NULL AND
              acknowledgement_signature IS NULL AND acknowledgement_verified_at IS NULL) OR
             (delivery_status = 'ACKNOWLEDGED' AND octet_length(acknowledged_manifest_hash) = 32 AND
              length(trim(acknowledgement_algorithm)) BETWEEN 1 AND 64 AND
              length(trim(acknowledgement_key_id)) BETWEEN 1 AND 512 AND
              octet_length(acknowledgement_message_hash) = 32 AND
              octet_length(acknowledgement_signature) > 0 AND acknowledgement_verified_at IS NOT NULL))
        )
    );

CREATE TABLE manifest_member_approval_intents (
    manifest_id uuid NOT NULL,
    epoch_id uuid NOT NULL,
    member_id uuid NOT NULL,
    expected_message_hash bytea NOT NULL CHECK (octet_length(expected_message_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (manifest_id, member_id),
    FOREIGN KEY (manifest_id, epoch_id)
        REFERENCES manifests(id, epoch_id) ON DELETE RESTRICT,
    FOREIGN KEY (epoch_id, member_id)
        REFERENCES membership_epoch_members(epoch_id, member_id) ON DELETE RESTRICT
);

CREATE TABLE share_acknowledgement_intents (
    delivery_id uuid PRIMARY KEY REFERENCES recovery_share_deliveries(id) ON DELETE RESTRICT,
    manifest_id uuid NOT NULL REFERENCES manifests(id) ON DELETE RESTRICT,
    expected_message_hash bytea NOT NULL CHECK (octet_length(expected_message_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (manifest_id, delivery_id)
);

CREATE TABLE manifest_batch_intents (
    manifest_id uuid NOT NULL REFERENCES manifests(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    resource_account_id uuid NOT NULL REFERENCES pool_resource_accounts(id) ON DELETE RESTRICT,
    epoch_role text NOT NULL CHECK (epoch_role IN ('FROM', 'TO')),
    batch_external_id varchar(128) NOT NULL,
    account_ref varchar(512) NOT NULL,
    batch_type text NOT NULL CHECK (batch_type IN ('LOGIN', 'MFA', 'RECOVERY', 'OWNERSHIP')),
    batch_version bigint NOT NULL CHECK (batch_version > 0),
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    recovery_wrap_hash bytea,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (manifest_id, resource_account_id, epoch_role, batch_type),
    UNIQUE (plan_id, batch_external_id, epoch_role),
    FOREIGN KEY (plan_id, resource_account_id)
        REFERENCES recovery_plan_resource_accounts(plan_id, resource_account_id) ON DELETE RESTRICT
    ,CHECK ((epoch_role = 'FROM' AND recovery_wrap_hash IS NULL) OR
            (epoch_role = 'TO' AND octet_length(recovery_wrap_hash) = 32))
);

CREATE TABLE recovery_control_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE,
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    resource_account_id uuid NOT NULL REFERENCES pool_resource_accounts(id) ON DELETE RESTRICT,
    provider_attestation_ref varchar(1024) NOT NULL,
    provider_attestation_digest bytea NOT NULL CHECK (octet_length(provider_attestation_digest) = 32),
    provider_attestation_issuer varchar(512) NOT NULL,
    provider_attestation_key_id varchar(512) NOT NULL,
    provider_attestation_version bigint NOT NULL CHECK (provider_attestation_version > 0),
    ceremony_type text NOT NULL CHECK (ceremony_type IN ('BOOTSTRAP', 'ROTATE')),
    attestation_purpose text NOT NULL CHECK (attestation_purpose IN ('BOOTSTRAP_GENESIS', 'ROTATION_CONTROL')),
    status text NOT NULL DEFAULT 'VERIFIED' CHECK (status IN ('VERIFIED', 'COMMITTED', 'INVALIDATED')),
    verified_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    committed_at timestamptz,
    UNIQUE (plan_id, resource_account_id),
    UNIQUE (id, plan_id, resource_account_id)
    ,CHECK ((ceremony_type = 'BOOTSTRAP' AND attestation_purpose = 'BOOTSTRAP_GENESIS') OR
            (ceremony_type = 'ROTATE' AND attestation_purpose = 'ROTATION_CONTROL'))
);

CREATE TABLE recovery_control_evidence_batches (
    evidence_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    resource_account_id uuid NOT NULL,
    epoch_role text NOT NULL CHECK (epoch_role IN ('FROM', 'TO')),
    batch_type text NOT NULL CHECK (batch_type IN ('LOGIN', 'MFA', 'RECOVERY', 'OWNERSHIP')),
    credential_batch_id uuid NOT NULL REFERENCES credential_batches(id) ON DELETE RESTRICT,
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    recovery_wrap_hash bytea,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (evidence_id, epoch_role, batch_type),
    FOREIGN KEY (evidence_id, plan_id, resource_account_id)
        REFERENCES recovery_control_evidence(id, plan_id, resource_account_id) ON DELETE RESTRICT
    ,CHECK ((epoch_role = 'FROM' AND recovery_wrap_hash IS NULL) OR
            (epoch_role = 'TO' AND octet_length(recovery_wrap_hash) = 32))
);

ALTER TABLE credential_batches
    DROP CONSTRAINT IF EXISTS credential_batches_status_check,
    DROP CONSTRAINT IF EXISTS credential_batches_check,
    DROP CONSTRAINT IF EXISTS ck_credential_batches_current_shape,
    ADD COLUMN recovery_plan_id uuid REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    ADD COLUMN recovery_root_artifact_id uuid REFERENCES recovery_root_artifacts(id) ON DELETE RESTRICT,
    ADD COLUMN resource_account_id uuid REFERENCES pool_resource_accounts(id) ON DELETE RESTRICT,
    ADD COLUMN recovery_key_fingerprint bytea,
    ADD COLUMN recovery_key_version varchar(512),
    ADD COLUMN recovery_wrap_attestation_digest bytea,
    ADD COLUMN recovery_wrap_attestation_signature bytea,
    ADD CONSTRAINT ck_credential_batches_phase2f_status CHECK (
        status IN ('PREPARED', 'SEALED', 'STAGED', 'DISTRIBUTED', 'ACTIVE', 'RETIRED', 'FAILED')
    ),
    ADD CONSTRAINT ck_credential_batches_phase2f_plan_scope CHECK (
        (recovery_plan_id IS NULL AND recovery_root_artifact_id IS NULL AND resource_account_id IS NULL AND
         recovery_key_fingerprint IS NULL AND recovery_key_version IS NULL AND
         recovery_wrap_attestation_digest IS NULL AND recovery_wrap_attestation_signature IS NULL AND
         status <> 'STAGED') OR
        (recovery_plan_id IS NOT NULL AND recovery_root_artifact_id IS NOT NULL AND resource_account_id IS NOT NULL AND
         recovery_key_fingerprint IS NOT NULL AND octet_length(recovery_key_fingerprint) = 32 AND
         length(trim(recovery_key_version)) BETWEEN 1 AND 512 AND
         octet_length(recovery_wrap_attestation_digest) = 32 AND
         octet_length(recovery_wrap_attestation_signature) > 0 AND
         status IN ('STAGED', 'ACTIVE', 'RETIRED'))
    ),
    ADD CONSTRAINT fk_credential_batch_recovery_root_plan
        FOREIGN KEY (recovery_root_artifact_id, recovery_plan_id)
        REFERENCES recovery_root_artifacts(id, plan_id) ON DELETE RESTRICT,
    ADD CONSTRAINT fk_credential_batch_recovery_account_plan
        FOREIGN KEY (recovery_plan_id, resource_account_id)
        REFERENCES recovery_plan_resource_accounts(plan_id, resource_account_id) ON DELETE RESTRICT;

CREATE TABLE recovery_plan_batch_bindings (
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    resource_account_id uuid NOT NULL REFERENCES pool_resource_accounts(id) ON DELETE RESTRICT,
    epoch_role text NOT NULL CHECK (epoch_role IN ('FROM', 'TO')),
    batch_type text NOT NULL CHECK (batch_type IN ('LOGIN', 'MFA', 'RECOVERY', 'OWNERSHIP')),
    credential_batch_id uuid NOT NULL REFERENCES credential_batches(id) ON DELETE RESTRICT,
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    recovery_wrap_hash bytea,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id, resource_account_id, epoch_role, batch_type),
    UNIQUE (plan_id, credential_batch_id, epoch_role),
    CHECK ((epoch_role = 'FROM' AND recovery_wrap_hash IS NULL) OR
           (epoch_role = 'TO' AND octet_length(recovery_wrap_hash) = 32))
);

CREATE TABLE recovery_seat_rotation_progress (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id uuid NOT NULL REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    seat_id uuid NOT NULL REFERENCES seats(id) ON DELETE RESTRICT,
    derived_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'PENDING' CHECK (
        status IN ('PENDING', 'RETRYABLE', 'ROTATED', 'COMMITTED', 'FAILED', 'EXPIRED')
    ),
    principal_user_id bigint,
    subscription_id bigint,
    api_key_id bigint,
    api_key_version integer,
    credential_fingerprint bytea,
    claim_operation_id varchar(128),
    claim_token_hash bytea,
    claim_intent_hash bytea,
    envelope_algorithm varchar(64),
    envelope_key_ref varchar(512),
    envelope_ciphertext bytea,
    envelope_nonce bytea,
    envelope_aad_hash bytea,
    wrapped_dek_kms bytea,
    claim_expires_at timestamptz,
    credential_claim_id uuid UNIQUE REFERENCES credential_claims(id) ON DELETE RESTRICT,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    error_code varchar(128),
    error_detail text,
    next_attempt_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (plan_id, seat_id),
    CHECK (
        (status = 'ROTATED' AND principal_user_id > 0 AND subscription_id > 0 AND api_key_id > 0 AND
         api_key_version > 0 AND octet_length(credential_fingerprint) = 32 AND
         length(trim(claim_operation_id)) BETWEEN 1 AND 128 AND octet_length(claim_token_hash) = 32 AND
         octet_length(claim_intent_hash) = 32 AND length(trim(envelope_algorithm)) BETWEEN 1 AND 64 AND
         length(trim(envelope_key_ref)) BETWEEN 1 AND 512 AND octet_length(envelope_ciphertext) > 0 AND
         octet_length(envelope_nonce) > 0 AND octet_length(envelope_aad_hash) = 32 AND
         octet_length(wrapped_dek_kms) > 0 AND claim_expires_at > created_at AND
         credential_claim_id IS NULL AND error_code IS NULL AND error_detail IS NULL AND next_attempt_at IS NULL) OR
        (status = 'COMMITTED' AND principal_user_id > 0 AND subscription_id > 0 AND api_key_id > 0 AND
         api_key_version > 0 AND octet_length(credential_fingerprint) = 32 AND credential_claim_id IS NOT NULL AND
         claim_operation_id IS NULL AND claim_token_hash IS NULL AND claim_intent_hash IS NULL AND
         envelope_algorithm IS NULL AND envelope_key_ref IS NULL AND envelope_ciphertext IS NULL AND
         envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND wrapped_dek_kms IS NULL AND
         claim_expires_at IS NULL AND error_code IS NULL AND error_detail IS NULL AND next_attempt_at IS NULL) OR
        (status IN ('PENDING', 'RETRYABLE', 'FAILED', 'EXPIRED') AND
         principal_user_id IS NULL AND subscription_id IS NULL AND api_key_id IS NULL AND
         api_key_version IS NULL AND credential_fingerprint IS NULL AND claim_operation_id IS NULL AND
         claim_token_hash IS NULL AND claim_intent_hash IS NULL AND envelope_algorithm IS NULL AND
         envelope_key_ref IS NULL AND envelope_ciphertext IS NULL AND envelope_nonce IS NULL AND
         envelope_aad_hash IS NULL AND wrapped_dek_kms IS NULL AND claim_expires_at IS NULL AND
         credential_claim_id IS NULL)
    )
);

CREATE TABLE permanent_replacement_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id varchar(128) NOT NULL UNIQUE,
    integration_operation_id uuid NOT NULL UNIQUE REFERENCES integration_operations(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL UNIQUE REFERENCES recovery_epoch_plans(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'READY' CHECK (status IN (
        'READY', 'ROTATING', 'RECONCILE_REQUIRED', 'OPERATOR_REVIEW_REQUIRED', 'FINALIZED', 'FAILED'
    )),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finalized_at timestamptz
);

CREATE OR REPLACE FUNCTION assert_recovery_plan_authoritative_snapshot(target_plan_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    target recovery_epoch_plans%ROWTYPE;
    authoritative_seats integer;
    planned_seats integer;
    from_members integer;
    to_members integer;
    authoritative_accounts integer;
    planned_accounts integer;
    authoritative_mappings integer;
    planned_mappings integer;
BEGIN
    SELECT * INTO target FROM recovery_epoch_plans WHERE id = target_plan_id;
    IF target.id IS NULL THEN RETURN; END IF;

    SELECT count(*) INTO authoritative_seats FROM seats
    WHERE pool_id = target.pool_id AND owner_member_id IS NOT NULL AND status <> 'CLOSED';
    SELECT count(*) INTO planned_seats FROM recovery_plan_seats WHERE plan_id = target.id;
    IF authoritative_seats <> target.expected_seat_count OR
       target.expected_member_count <> authoritative_seats OR
       target.required_share_ack_count <> authoritative_seats OR
       planned_seats <> authoritative_seats OR EXISTS (
        SELECT 1 FROM seats seat
        LEFT JOIN recovery_plan_seats planned ON planned.plan_id = target.id AND planned.seat_id = seat.id
        WHERE seat.pool_id = target.pool_id AND seat.owner_member_id IS NOT NULL AND seat.status <> 'CLOSED'
          AND (planned.seat_id IS NULL OR planned.from_member_id <> seat.owner_member_id OR
               planned.expected_assignment_epoch <> seat.assignment_epoch OR
               planned.expected_active_api_key_version <> seat.active_api_key_version OR seat.status <> 'FROZEN')
    ) THEN RAISE EXCEPTION 'recovery plan Seat snapshot is not authoritative'; END IF;

    IF target.ceremony_type = 'ROTATE' AND NOT EXISTS (
        SELECT 1 FROM membership_epochs epoch
        JOIN manifests manifest ON manifest.epoch_id = epoch.id
          AND manifest.status = 'ACTIVE' AND manifest.migration_state = 'CURRENT'
        JOIN recovery_root_artifacts root ON root.id = manifest.root_artifact_id
          AND root.migration_state = 'CURRENT'
        WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.from_epoch
          AND epoch.status = 'ACTIVE' AND epoch.recovery_governance_state = 'CURRENT'
          AND manifest.manifest_hash = target.previous_manifest_hash
    ) THEN RAISE EXCEPTION 'ROTATE source Epoch lacks a CURRENT active Manifest/Root governance chain'; END IF;
    IF target.ceremony_type = 'BOOTSTRAP' AND NOT EXISTS (
        SELECT 1 FROM membership_epochs epoch
        WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.from_epoch
          AND epoch.status = 'ACTIVE' AND epoch.recovery_governance_state = 'LEGACY_UNVERIFIED'
    ) THEN RAISE EXCEPTION 'BOOTSTRAP source must be the active LEGACY_UNVERIFIED Epoch'; END IF;

    -- ROTATE 的来源成员必须来自可信 CURRENT 快照；BOOTSTRAP 只信当前冻结 Seat owner，不能把旧公钥伪装成可信历史。
    IF target.ceremony_type = 'ROTATE' THEN
        SELECT count(*) INTO from_members
        FROM membership_epoch_members member_snapshot
        JOIN membership_epochs epoch ON epoch.id = member_snapshot.epoch_id
        WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.from_epoch
          AND member_snapshot.migration_state = 'CURRENT';
        IF from_members <> authoritative_seats OR EXISTS (
            SELECT 1 FROM seats seat
            LEFT JOIN membership_epochs epoch ON epoch.pool_id = seat.pool_id AND epoch.epoch = target.from_epoch
            LEFT JOIN membership_epoch_members member_snapshot
              ON member_snapshot.epoch_id = epoch.id AND member_snapshot.member_id = seat.owner_member_id
             AND member_snapshot.migration_state = 'CURRENT'
            WHERE seat.pool_id = target.pool_id AND seat.owner_member_id IS NOT NULL AND seat.status <> 'CLOSED'
              AND member_snapshot.member_id IS NULL
        ) THEN RAISE EXCEPTION 'ROTATE from Epoch members are not exactly all Seat owners'; END IF;
    END IF;

    SELECT count(*) INTO to_members
    FROM membership_epoch_members member_snapshot
    JOIN membership_epochs epoch ON epoch.id = member_snapshot.epoch_id
    WHERE epoch.pool_id = target.pool_id AND epoch.epoch = target.to_epoch
      AND epoch.recovery_plan_id = target.id AND member_snapshot.migration_state = 'CURRENT';
    IF to_members <> planned_seats OR EXISTS (
        SELECT 1 FROM recovery_plan_seats planned
        LEFT JOIN membership_epochs epoch
          ON epoch.pool_id = planned.pool_id AND epoch.epoch = planned.to_epoch AND epoch.recovery_plan_id = planned.plan_id
        LEFT JOIN membership_epoch_members member_snapshot
          ON member_snapshot.epoch_id = epoch.id AND member_snapshot.member_id = planned.to_member_id
         AND member_snapshot.source_seat_id = planned.seat_id AND member_snapshot.migration_state = 'CURRENT'
        WHERE planned.plan_id = target.id AND member_snapshot.member_id IS NULL
    ) THEN RAISE EXCEPTION 'to Epoch members differ from the plan-only replacement set'; END IF;

    SELECT count(*) INTO authoritative_accounts FROM pool_resource_accounts
    WHERE pool_id = target.pool_id AND status = 'ACTIVE';
    SELECT count(*) INTO planned_accounts FROM recovery_plan_resource_accounts WHERE plan_id = target.id;
    IF authoritative_accounts <> target.expected_resource_count OR planned_accounts <> authoritative_accounts OR EXISTS (
        SELECT 1 FROM pool_resource_accounts account
        LEFT JOIN recovery_plan_resource_accounts planned
          ON planned.plan_id = target.id AND planned.resource_account_id = account.id
         AND planned.inventory_version = account.inventory_version
         AND planned.attestation_digest = account.attestation_digest
        WHERE account.pool_id = target.pool_id AND account.status = 'ACTIVE' AND planned.resource_account_id IS NULL
    ) THEN RAISE EXCEPTION 'recovery plan resource-account snapshot is not authoritative'; END IF;

    SELECT count(*) INTO authoritative_mappings
    FROM pool_resource_account_seats mapping
    JOIN pool_resource_accounts account ON account.id = mapping.resource_account_id
    WHERE account.pool_id = target.pool_id AND account.status = 'ACTIVE' AND mapping.status = 'ACTIVE';
    SELECT count(*) INTO planned_mappings FROM recovery_plan_account_seats WHERE plan_id = target.id;
    IF planned_mappings <> authoritative_mappings OR EXISTS (
        SELECT 1 FROM pool_resource_account_seats mapping
        JOIN pool_resource_accounts account ON account.id = mapping.resource_account_id
        LEFT JOIN recovery_plan_account_seats planned
          ON planned.plan_id = target.id AND planned.resource_account_id = mapping.resource_account_id
         AND planned.seat_id = mapping.seat_id AND planned.inventory_version = mapping.inventory_version
        WHERE account.pool_id = target.pool_id AND account.status = 'ACTIVE' AND mapping.status = 'ACTIVE'
          AND planned.seat_id IS NULL
    ) OR EXISTS (
        SELECT 1 FROM recovery_plan_account_seats planned
        LEFT JOIN pool_resource_account_seats mapping
          ON mapping.resource_account_id = planned.resource_account_id AND mapping.seat_id = planned.seat_id
         AND mapping.inventory_version = planned.inventory_version AND mapping.status = 'ACTIVE'
        LEFT JOIN pool_resource_accounts account
          ON account.id = mapping.resource_account_id AND account.pool_id = target.pool_id AND account.status = 'ACTIVE'
        WHERE planned.plan_id = target.id AND account.id IS NULL
    ) THEN RAISE EXCEPTION 'recovery plan account-Seat mapping snapshot is incomplete or invented'; END IF;
    IF EXISTS (
        SELECT 1 FROM recovery_plan_resource_accounts account
        WHERE account.plan_id = target.id AND NOT EXISTS (
            SELECT 1 FROM recovery_plan_account_seats mapping
            WHERE mapping.plan_id = target.id AND mapping.resource_account_id = account.resource_account_id
        )
    ) OR EXISTS (
        SELECT 1 FROM recovery_plan_seats seat
        WHERE seat.plan_id = target.id AND NOT EXISTS (
            SELECT 1 FROM recovery_plan_account_seats mapping
            WHERE mapping.plan_id = target.id AND mapping.seat_id = seat.seat_id
        )
    ) THEN RAISE EXCEPTION 'every planned account and Seat requires an explicit authoritative mapping'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION validate_recovery_plan_snapshot_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_recovery_plan_authoritative_snapshot(
        CASE WHEN TG_TABLE_NAME = 'recovery_epoch_plans' THEN NEW.id ELSE NEW.plan_id END
    );
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER recovery_epoch_plan_snapshot_complete
AFTER INSERT ON recovery_epoch_plans DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_plan_snapshot_deferred();
CREATE CONSTRAINT TRIGGER recovery_plan_seats_snapshot_complete
AFTER INSERT OR UPDATE ON recovery_plan_seats DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_plan_snapshot_deferred();
CREATE CONSTRAINT TRIGGER recovery_plan_accounts_snapshot_complete
AFTER INSERT OR UPDATE ON recovery_plan_resource_accounts DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_plan_snapshot_deferred();

CREATE OR REPLACE FUNCTION enforce_recovery_plan_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n integer;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'recovery plan is an immutable ledger'; END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PLANNED' OR NEW.version <> 1 THEN
            RAISE EXCEPTION 'new recovery plan must begin PLANNED version one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
       NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
       NEW.ceremony_type IS DISTINCT FROM OLD.ceremony_type OR
       NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.from_epoch IS DISTINCT FROM OLD.from_epoch OR
       NEW.to_epoch IS DISTINCT FROM OLD.to_epoch OR NEW.governance_threshold IS DISTINCT FROM OLD.governance_threshold OR
       NEW.recovery_threshold IS DISTINCT FROM OLD.recovery_threshold OR
       NEW.required_share_ack_count IS DISTINCT FROM OLD.required_share_ack_count OR
       NEW.expected_member_count IS DISTINCT FROM OLD.expected_member_count OR
       NEW.expected_seat_count IS DISTINCT FROM OLD.expected_seat_count OR
       NEW.expected_resource_count IS DISTINCT FROM OLD.expected_resource_count OR
       NEW.expected_control_batch_count IS DISTINCT FROM OLD.expected_control_batch_count OR
       NEW.provider_attestation_set_hash IS DISTINCT FROM OLD.provider_attestation_set_hash OR
       NEW.previous_manifest_hash IS DISTINCT FROM OLD.previous_manifest_hash OR
       NEW.from_epoch_status IS DISTINCT FROM OLD.from_epoch_status OR
       NEW.from_governance_state IS DISTINCT FROM OLD.from_governance_state OR
       NEW.bootstrap_attestation_ref IS DISTINCT FROM OLD.bootstrap_attestation_ref OR
       NEW.bootstrap_attestation_digest IS DISTINCT FROM OLD.bootstrap_attestation_digest OR
       NEW.bootstrap_attestation_issuer IS DISTINCT FROM OLD.bootstrap_attestation_issuer OR
       NEW.bootstrap_attestation_key_id IS DISTINCT FROM OLD.bootstrap_attestation_key_id OR
       NEW.bootstrap_attestation_signature IS DISTINCT FROM OLD.bootstrap_attestation_signature OR
       NEW.bootstrap_attestation_version IS DISTINCT FROM OLD.bootstrap_attestation_version OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.version <> OLD.version + 1 THEN RAISE EXCEPTION 'recovery plan immutable intent/version changed'; END IF;
    -- 每个准备阶段都重新核对 live inventory；FINALIZED 时 Seat 已在同一事务内完成精确轮换。
    IF NEW.status NOT IN ('FINALIZED', 'FAILED') THEN
        PERFORM assert_recovery_plan_authoritative_snapshot(NEW.id);
    END IF;
    IF NOT ((OLD.status = 'PLANNED' AND NEW.status IN ('ROOT_COMMITTED', 'FAILED')) OR
            (OLD.status = 'ROOT_COMMITTED' AND NEW.status IN ('SHARES_COMMITTED', 'FAILED')) OR
            (OLD.status = 'SHARES_COMMITTED' AND NEW.status IN ('MANIFEST_DRAFT', 'FAILED')) OR
            (OLD.status = 'MANIFEST_DRAFT' AND NEW.status IN ('MANIFEST_SIGNED', 'FAILED')) OR
            (OLD.status = 'MANIFEST_SIGNED' AND NEW.status IN ('ACKNOWLEDGED', 'FAILED')) OR
            (OLD.status = 'ACKNOWLEDGED' AND NEW.status IN ('BATCHES_STAGED', 'FAILED')) OR
            (OLD.status = 'BATCHES_STAGED' AND NEW.status IN ('READY', 'FAILED')) OR
            (OLD.status = 'READY' AND NEW.status IN ('FINALIZED', 'FAILED'))) THEN
        RAISE EXCEPTION 'illegal recovery plan transition: % -> %', OLD.status, NEW.status;
    END IF;
    IF NEW.status = 'FAILED' AND EXISTS (
        SELECT 1 FROM recovery_seat_rotation_progress progress
        WHERE progress.plan_id = NEW.id AND progress.status IN ('ROTATED', 'COMMITTED')
    ) THEN RAISE EXCEPTION 'plan cannot fail after an external Seat rotation may have applied'; END IF;
    IF NEW.status = 'ROOT_COMMITTED' AND
       (SELECT count(*) FROM recovery_root_artifacts WHERE plan_id = NEW.id) <> 1 THEN
        RAISE EXCEPTION 'ROOT_COMMITTED requires one root artifact';
    ELSIF NEW.status = 'SHARES_COMMITTED' AND
       (SELECT count(*) FROM recovery_share_deliveries WHERE recovery_plan_id = NEW.id AND migration_state = 'CURRENT')
           <> NEW.expected_member_count THEN
        RAISE EXCEPTION 'SHARES_COMMITTED requires one encrypted share per formal member';
    ELSIF NEW.status = 'MANIFEST_DRAFT' AND
       (SELECT count(*) FROM manifests WHERE recovery_plan_id = NEW.id AND migration_state = 'CURRENT') <> 1 THEN
        RAISE EXCEPTION 'MANIFEST_DRAFT requires one canonical signed manifest';
    ELSIF NEW.status = 'MANIFEST_SIGNED' AND
       (SELECT count(*) FROM manifest_signatures signature
        JOIN manifests manifest ON manifest.id = signature.manifest_id
        WHERE manifest.recovery_plan_id = NEW.id AND signature.migration_state = 'CURRENT') < NEW.governance_threshold THEN
        RAISE EXCEPTION 'MANIFEST_SIGNED lacks verified member signatures';
    ELSIF NEW.status = 'ACKNOWLEDGED' AND
       (SELECT count(*) FROM recovery_share_deliveries
        WHERE recovery_plan_id = NEW.id AND migration_state = 'CURRENT' AND delivery_status = 'ACKNOWLEDGED')
           < NEW.required_share_ack_count THEN
        RAISE EXCEPTION 'ACKNOWLEDGED lacks Manifest-bound Share acknowledgements';
    ELSIF NEW.status = 'BATCHES_STAGED' AND
       (SELECT count(*) FROM recovery_plan_batch_bindings
        WHERE plan_id = NEW.id AND epoch_role = 'TO') <> NEW.expected_control_batch_count THEN
        RAISE EXCEPTION 'BATCHES_STAGED control batch set is incomplete';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_epoch_plans_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_epoch_plans
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_plan_transition();

CREATE OR REPLACE FUNCTION assert_recovery_plan_operation_closed(target_plan_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE plan_status text; operation_status text;
BEGIN
    SELECT plan.status, operation.status INTO plan_status, operation_status
    FROM recovery_epoch_plans plan
    JOIN integration_operations operation ON operation.id = plan.integration_operation_id
    WHERE plan.id = target_plan_id;
    IF plan_status IS NULL THEN RETURN; END IF;
    IF (plan_status = 'FINALIZED') <> (operation_status = 'SUCCEEDED') THEN
        RAISE EXCEPTION 'FINALIZED recovery plan and ceremony operation must close atomically';
    END IF;
END;
$$;
CREATE OR REPLACE FUNCTION validate_recovery_plan_operation_closed_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_plan_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'recovery_epoch_plans' THEN
        target_plan_id := NEW.id;
    ELSE
        SELECT id INTO target_plan_id FROM recovery_epoch_plans WHERE integration_operation_id = NEW.id;
    END IF;
    IF target_plan_id IS NOT NULL THEN PERFORM assert_recovery_plan_operation_closed(target_plan_id); END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER recovery_plan_operation_closed
AFTER UPDATE ON recovery_epoch_plans DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_plan_operation_closed_deferred();
CREATE CONSTRAINT TRIGGER recovery_operation_plan_closed
AFTER UPDATE ON integration_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_plan_operation_closed_deferred();

CREATE OR REPLACE FUNCTION enforce_recovery_root_artifact_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Recovery Root artifact is append-only'; END IF;
    IF NEW.migration_state <> 'CURRENT' OR NOT EXISTS (
        SELECT 1 FROM recovery_epoch_plans plan
        WHERE plan.id = NEW.plan_id AND plan.status = 'PLANNED'
    ) THEN RAISE EXCEPTION 'Root artifact requires its PLANNED ceremony'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_root_artifacts_immutable
BEFORE INSERT OR UPDATE OR DELETE ON recovery_root_artifacts
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_root_artifact_immutable();

CREATE OR REPLACE FUNCTION enforce_current_epoch_member_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN RETURN NEW; END IF;
    IF OLD.migration_state = 'CURRENT' THEN
        RAISE EXCEPTION 'CURRENT Epoch member key/PoP snapshot is immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'legacy Epoch member history cannot be deleted'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER membership_epoch_members_phase2f_immutable
BEFORE UPDATE OR DELETE ON membership_epoch_members
FOR EACH ROW EXECUTE FUNCTION enforce_current_epoch_member_immutable();

CREATE OR REPLACE FUNCTION reject_recovery_snapshot_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'recovery ceremony snapshot/intent is immutable'; END;
$$;
CREATE TRIGGER recovery_plan_seats_immutable
BEFORE UPDATE OR DELETE ON recovery_plan_seats FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();
CREATE TRIGGER recovery_plan_resource_accounts_immutable
BEFORE UPDATE OR DELETE ON recovery_plan_resource_accounts FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();
CREATE TRIGGER recovery_plan_account_seats_immutable
BEFORE UPDATE OR DELETE ON recovery_plan_account_seats FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();
CREATE TRIGGER manifest_member_approval_intents_immutable
BEFORE UPDATE OR DELETE ON manifest_member_approval_intents FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();
CREATE TRIGGER share_acknowledgement_intents_immutable
BEFORE UPDATE OR DELETE ON share_acknowledgement_intents FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();
CREATE TRIGGER manifest_batch_intents_immutable
BEFORE UPDATE OR DELETE ON manifest_batch_intents FOR EACH ROW EXECUTE FUNCTION reject_recovery_snapshot_mutation();

CREATE OR REPLACE FUNCTION enforce_recovery_share_sequence()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target recovery_epoch_plans%ROWTYPE; trusted record;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        IF OLD.migration_state = 'LEGACY_UNVERIFIED' OR NEW.recovery_plan_id IS DISTINCT FROM OLD.recovery_plan_id OR
           NEW.root_artifact_id IS DISTINCT FROM OLD.root_artifact_id OR NEW.epoch_id IS DISTINCT FROM OLD.epoch_id OR
           NEW.member_id IS DISTINCT FROM OLD.member_id OR NEW.encrypted_share IS DISTINCT FROM OLD.encrypted_share OR
           NEW.share_hash IS DISTINCT FROM OLD.share_hash THEN RAISE EXCEPTION 'recovery Share scope/ciphertext is immutable'; END IF;
        IF NOT (OLD.delivery_status = 'DELIVERED' AND NEW.delivery_status = 'ACKNOWLEDGED') THEN
            RAISE EXCEPTION 'only a post-Manifest acknowledgement may update a Share';
        END IF;
    END IF;
    IF NEW.migration_state <> 'CURRENT' THEN RETURN NEW; END IF;
    SELECT * INTO target FROM recovery_epoch_plans WHERE id = NEW.recovery_plan_id FOR SHARE;
    SELECT snapshot.* INTO trusted FROM membership_epoch_members snapshot
    JOIN membership_epochs epoch ON epoch.id = snapshot.epoch_id
    WHERE snapshot.epoch_id = NEW.epoch_id AND snapshot.member_id = NEW.member_id
      AND epoch.recovery_plan_id = NEW.recovery_plan_id AND epoch.epoch = target.to_epoch
      AND snapshot.migration_state = 'CURRENT';
    IF target.id IS NULL OR trusted.member_id IS NULL OR NEW.share_index <> trusted.share_index OR
       NEW.recipient_key_id <> trusted.recovery_key_id OR
       NEW.recipient_key_fingerprint <> trusted.recovery_key_fingerprint THEN
        RAISE EXCEPTION 'encrypted Share recipient is not the trusted to-Epoch member key';
    END IF;
    IF TG_OP = 'INSERT' AND (target.status <> 'ROOT_COMMITTED' OR EXISTS (
        SELECT 1 FROM manifests WHERE recovery_plan_id = target.id AND migration_state = 'CURRENT'
    )) THEN RAISE EXCEPTION 'encrypted Shares must be committed before Manifest creation'; END IF;
    IF TG_OP = 'UPDATE' AND (OLD.delivered_at IS NULL OR NEW.delivered_at IS DISTINCT FROM OLD.delivered_at OR
       NEW.acknowledged_at IS NULL OR NEW.acknowledged_at < OLD.delivered_at OR
       NEW.acknowledgement_message_hash IS DISTINCT FROM (SELECT expected_message_hash
           FROM share_acknowledgement_intents WHERE delivery_id = NEW.id) OR
       target.status <> 'MANIFEST_SIGNED' OR NOT EXISTS (
        SELECT 1 FROM manifests manifest WHERE manifest.recovery_plan_id = target.id
          AND manifest.manifest_hash = NEW.acknowledged_manifest_hash AND manifest.migration_state = 'CURRENT'
    )) THEN RAISE EXCEPTION 'Share acknowledgement must bind the signed Manifest'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_share_deliveries_phase2f_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_share_deliveries
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_share_sequence();

CREATE OR REPLACE FUNCTION enforce_recovery_manifest_sequence()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target recovery_epoch_plans%ROWTYPE; root recovery_root_artifacts%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Phase2-F Manifest is immutable'; END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.epoch_id IS DISTINCT FROM OLD.epoch_id OR
           NEW.recovery_plan_id IS DISTINCT FROM OLD.recovery_plan_id OR
           NEW.root_artifact_id IS DISTINCT FROM OLD.root_artifact_id OR
           NEW.canonical_payload IS DISTINCT FROM OLD.canonical_payload OR
           NEW.canonical_bytes IS DISTINCT FROM OLD.canonical_bytes OR
           NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash OR
           NEW.platform_signature IS DISTINCT FROM OLD.platform_signature OR
           NEW.previous_manifest_hash IS DISTINCT FROM OLD.previous_manifest_hash OR
           NEW.batch_set_hash IS DISTINCT FROM OLD.batch_set_hash OR
           NEW.recovery_package_hash IS DISTINCT FROM OLD.recovery_package_hash OR
           NEW.provider_attestation_digest IS DISTINCT FROM OLD.provider_attestation_digest OR
           NEW.platform_algorithm IS DISTINCT FROM OLD.platform_algorithm OR
           NEW.platform_key_ref IS DISTINCT FROM OLD.platform_key_ref OR
           NEW.platform_verified_at IS DISTINCT FROM OLD.platform_verified_at OR
           NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'Manifest cryptographic scope is immutable';
        END IF;
        IF OLD.status = 'DRAFT' AND NEW.status = 'ACTIVE' THEN
            IF NOT EXISTS (SELECT 1 FROM recovery_epoch_plans
                           WHERE id = OLD.recovery_plan_id AND status = 'READY') THEN
                RAISE EXCEPTION 'Manifest activates only during READY plan finalize';
            END IF;
        ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'RETIRED' THEN
            IF NOT EXISTS (SELECT 1 FROM recovery_epoch_plans
                           WHERE pool_id = (SELECT pool_id FROM membership_epochs WHERE id = OLD.epoch_id)
                             AND from_epoch = (SELECT epoch FROM membership_epochs WHERE id = OLD.epoch_id)
                             AND previous_manifest_hash = OLD.manifest_hash AND status = 'READY') THEN
                RAISE EXCEPTION 'Manifest retirement lacks a READY hash-linked successor plan';
            END IF;
        ELSE RAISE EXCEPTION 'illegal Phase2-F Manifest transition'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.migration_state <> 'CURRENT' THEN RAISE EXCEPTION 'new Manifest cannot claim legacy state'; END IF;
    SELECT * INTO target FROM recovery_epoch_plans WHERE id = NEW.recovery_plan_id FOR SHARE;
    SELECT * INTO root FROM recovery_root_artifacts WHERE id = NEW.root_artifact_id AND plan_id = target.id;
    IF target.id IS NULL OR root.id IS NULL OR target.status IS DISTINCT FROM 'SHARES_COMMITTED' OR
       NEW.epoch_id IS DISTINCT FROM (SELECT id FROM membership_epochs
                         WHERE pool_id = target.pool_id AND epoch = target.to_epoch
                           AND recovery_plan_id = target.id AND status = 'PREPARING') OR
       NEW.previous_manifest_hash IS DISTINCT FROM target.previous_manifest_hash OR
       NEW.recovery_package_hash IS DISTINCT FROM root.recovery_package_hash OR
       NEW.provider_attestation_digest IS DISTINCT FROM root.attestation_digest OR
       NEW.canonical_payload ->> 'protocol_version' IS DISTINCT FROM 'trusted-pool/recovery-governance/v1' OR
       jsonb_typeof(NEW.canonical_payload -> 'recovery_root') IS DISTINCT FROM 'object' OR
       NEW.canonical_payload ->> 'ceremony_type' IS DISTINCT FROM target.ceremony_type OR
       NEW.canonical_payload ->> 'operation_id' IS DISTINCT FROM
           (SELECT operation_id FROM integration_operations WHERE id = target.integration_operation_id) OR
       NEW.canonical_payload ->> 'pool_id' IS DISTINCT FROM
           (SELECT external_id FROM pools WHERE id = target.pool_id) OR
       (NEW.canonical_payload ->> 'from_epoch')::bigint IS DISTINCT FROM target.from_epoch OR
       NEW.canonical_payload ->> 'from_epoch_status' IS DISTINCT FROM target.from_epoch_status OR
       NEW.canonical_payload ->> 'from_governance_state' IS DISTINCT FROM target.from_governance_state OR
       NEW.canonical_payload ->> 'ceremony_attestation_digest' IS DISTINCT FROM encode(target.bootstrap_attestation_digest, 'hex') OR
       NEW.canonical_payload ->> 'ceremony_attestation_issuer' IS DISTINCT FROM target.bootstrap_attestation_issuer OR
       NEW.canonical_payload ->> 'ceremony_attestation_key_id' IS DISTINCT FROM target.bootstrap_attestation_key_id OR
       NEW.canonical_payload ->> 'ceremony_attestation_reference' IS DISTINCT FROM target.bootstrap_attestation_ref OR
       (NEW.canonical_payload ->> 'ceremony_attestation_version')::bigint IS DISTINCT FROM target.bootstrap_attestation_version OR
       NEW.canonical_payload ->> 'ceremony_attestation_purpose' IS DISTINCT FROM (
           CASE
               WHEN target.ceremony_type = 'BOOTSTRAP' THEN 'BOOTSTRAP_GENESIS'
               ELSE 'ROTATION_CONTROL'
           END
       ) OR
       NEW.canonical_payload ->> 'provider_attestation_set_hash' IS DISTINCT FROM
           encode(target.provider_attestation_set_hash, 'hex') OR
       (NEW.canonical_payload ->> 'epoch')::bigint IS DISTINCT FROM target.to_epoch OR
       (NEW.canonical_payload ->> 'governance_threshold')::integer IS DISTINCT FROM target.governance_threshold OR
       (NEW.canonical_payload ->> 'recovery_threshold')::integer IS DISTINCT FROM target.recovery_threshold OR
       (NEW.canonical_payload ->> 'required_share_acknowledges')::integer IS DISTINCT FROM target.required_share_ack_count OR
       COALESCE(NEW.canonical_payload ->> 'previous_manifest_hash', '') IS DISTINCT FROM (
           CASE
               WHEN target.ceremony_type = 'BOOTSTRAP' THEN ''
               ELSE encode(target.previous_manifest_hash, 'hex')
           END
       ) OR
       NEW.canonical_payload #>> '{recovery_root,public_handle}' IS DISTINCT FROM root.epoch_recovery_key_id OR
       NEW.canonical_payload #>> '{recovery_root,public_algorithm}' IS DISTINCT FROM root.epoch_recovery_algorithm OR
       NEW.canonical_payload #>> '{recovery_root,public_fingerprint}' IS DISTINCT FROM encode(root.epoch_recovery_key_fingerprint, 'hex') OR
       NEW.canonical_payload #>> '{recovery_root,wrap_domain}' IS DISTINCT FROM root.wrap_domain OR
       NEW.canonical_payload #>> '{recovery_root,wrap_algorithm}' IS DISTINCT FROM root.wrap_algorithm OR
       NEW.canonical_payload #>> '{recovery_root,provider_id}' IS DISTINCT FROM root.provider OR
       NEW.canonical_payload #>> '{recovery_root,key_version}' IS DISTINCT FROM root.root_key_version OR
       NEW.canonical_payload #>> '{recovery_root,private_commitment_hash}' IS DISTINCT FROM encode(root.private_key_commitment_hash, 'hex') OR
       NEW.canonical_payload #>> '{recovery_root,vss_algorithm}' IS DISTINCT FROM root.vss_algorithm OR
       NEW.canonical_payload #>> '{recovery_root,vss_commitment_hash}' IS DISTINCT FROM encode(root.vss_commitment_hash, 'hex') OR
       NEW.canonical_payload #>> '{recovery_root,vss_proof_hash}' IS DISTINCT FROM encode(root.vss_proof_hash, 'hex') OR
       NEW.canonical_payload #>> '{recovery_root,package_hash}' IS DISTINCT FROM encode(root.recovery_package_hash, 'hex') OR
       jsonb_typeof(NEW.canonical_payload -> 'members') IS DISTINCT FROM 'array' OR
       jsonb_typeof(NEW.canonical_payload -> 'seats') IS DISTINCT FROM 'array' OR
       jsonb_typeof(NEW.canonical_payload -> 'accounts') IS DISTINCT FROM 'array' OR
       jsonb_typeof(NEW.canonical_payload -> 'encrypted_shares') IS DISTINCT FROM 'array' OR
       jsonb_typeof(NEW.canonical_payload -> 'replacements') IS DISTINCT FROM 'array' OR
       jsonb_typeof(NEW.canonical_payload -> 'created_at') IS DISTINCT FROM 'string' OR
       jsonb_array_length(NEW.canonical_payload -> 'members') <> target.expected_member_count OR
       jsonb_array_length(NEW.canonical_payload -> 'seats') <> target.expected_seat_count OR
       jsonb_array_length(NEW.canonical_payload -> 'accounts') <> target.expected_resource_count OR
       jsonb_array_length(NEW.canonical_payload -> 'encrypted_shares') <> target.expected_member_count OR
       (SELECT count(*) FROM recovery_share_deliveries
        WHERE recovery_plan_id = target.id AND migration_state = 'CURRENT') <> target.expected_member_count OR
       EXISTS (
         SELECT 1 FROM membership_epoch_members snapshot JOIN members member ON member.id = snapshot.member_id
         WHERE snapshot.epoch_id = NEW.epoch_id AND snapshot.migration_state = 'CURRENT' AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(NEW.canonical_payload -> 'members') item
           WHERE item ->> 'member_id' = member.external_id
             AND item ->> 'role' = snapshot.member_role
             AND (item ->> 'share_index')::integer = snapshot.share_index
             AND item ->> 'signing_algorithm' = snapshot.signing_algorithm
             AND item ->> 'signing_key_id' = snapshot.signing_key_id
             AND item ->> 'signing_key_fingerprint' = encode(snapshot.signing_key_fingerprint, 'hex')
             AND decode(item ->> 'signing_public_key', 'base64') = snapshot.signing_public_key
             AND item ->> 'recovery_encryption_algorithm' = snapshot.recovery_key_algorithm
             AND item ->> 'recovery_encryption_key_id' = snapshot.recovery_key_id
             AND item ->> 'recovery_encryption_key_fingerprint' = encode(snapshot.recovery_key_fingerprint, 'hex')
             AND decode(item ->> 'recovery_encryption_public_key', 'base64') = snapshot.recovery_encryption_public_key
         )
       ) OR EXISTS (
         SELECT 1 FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
         JOIN members target_member ON target_member.id = planned.to_member_id
         WHERE planned.plan_id = target.id AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(NEW.canonical_payload -> 'seats') item
           WHERE item ->> 'seat_id' = seat.external_id AND item ->> 'member_id' = target_member.external_id
              AND (item ->> 'expected_assignment_epoch')::bigint = planned.expected_assignment_epoch
              AND (item ->> 'principal_user_id')::bigint = seat.sub2api_principal_id
              AND (item ->> 'subscription_id')::bigint = seat.sub2api_subscription_id
              AND (item ->> 'api_key_id')::bigint = seat.sub2api_api_key_id
              AND item ->> 'freeze_operation_id' = planned.freeze_operation_id
              AND item ->> 'freeze_snapshot_hash' = encode(planned.freeze_snapshot_hash, 'hex')
          )
        ) OR jsonb_array_length(NEW.canonical_payload -> 'replacements') <>
             (SELECT count(*) FROM recovery_plan_seats WHERE plan_id = target.id AND is_replacement) OR EXISTS (
          SELECT 1 FROM recovery_plan_seats planned
          JOIN seats seat ON seat.id = planned.seat_id
          JOIN members from_member ON from_member.id = planned.from_member_id
          JOIN members to_member ON to_member.id = planned.to_member_id
          WHERE planned.plan_id = target.id AND planned.is_replacement AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(NEW.canonical_payload -> 'replacements') item
            WHERE item ->> 'seat_id' = seat.external_id
              AND item ->> 'from_member_id' = from_member.external_id
              AND item ->> 'to_member_id' = to_member.external_id
              AND (item ->> 'expected_assignment_epoch')::bigint = planned.expected_assignment_epoch
              AND item ->> 'freeze_operation_id' = planned.freeze_operation_id
              AND item ->> 'freeze_snapshot_hash' = encode(planned.freeze_snapshot_hash, 'hex')
          )
        ) OR EXISTS (
         SELECT 1 FROM recovery_plan_resource_accounts planned
         WHERE planned.plan_id = target.id AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(NEW.canonical_payload -> 'accounts') item
           WHERE item ->> 'account_id' = planned.account_external_id
             AND item ->> 'account_ref' = planned.provider_account_ref
             AND item ->> 'provider_binding' = planned.provider_binding
             AND item ->> 'control_evidence_id' = planned.control_evidence_external_id
             AND item ->> 'provider_attestation_digest' = encode(planned.control_attestation_digest, 'hex')
             AND item ->> 'provider_attestation_issuer' = planned.control_attestation_issuer
              AND item ->> 'provider_attestation_key_id' = planned.control_attestation_key_id
              AND (item ->> 'provider_attestation_version')::bigint = planned.control_attestation_version
              AND jsonb_typeof(item -> 'seat_ids') = 'array'
              AND jsonb_array_length(item -> 'seat_ids') =
                  (SELECT count(*) FROM recovery_plan_account_seats mapping
                   WHERE mapping.plan_id = target.id AND mapping.resource_account_id = planned.resource_account_id)
              AND NOT EXISTS (
                  SELECT 1 FROM recovery_plan_account_seats mapping
                  JOIN seats mapped_seat ON mapped_seat.id = mapping.seat_id
                  WHERE mapping.plan_id = target.id AND mapping.resource_account_id = planned.resource_account_id
                    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(item -> 'seat_ids') seat_id
                                    WHERE seat_id = mapped_seat.external_id)
              )
          )
       ) OR EXISTS (
         SELECT 1 FROM recovery_share_deliveries delivery JOIN members member ON member.id = delivery.member_id
         WHERE delivery.recovery_plan_id = target.id AND delivery.migration_state = 'CURRENT' AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(NEW.canonical_payload -> 'encrypted_shares') item
           WHERE item ->> 'member_id' = member.external_id
             AND (item ->> 'share_index')::integer = delivery.share_index
             AND item ->> 'ciphertext_hash' = encode(delivery.share_hash, 'hex')
             AND item ->> 'provider_proof_hash' = encode(delivery.provider_proof_digest, 'hex')
             AND item ->> 'provider_commitment_hash' = encode(digest(delivery.provider_share_commitment, 'sha256'), 'hex')
         )
       ) THEN
        RAISE EXCEPTION 'Manifest is not bound after the complete encrypted Share set';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER manifests_phase2f_invariants
BEFORE INSERT OR UPDATE OR DELETE ON manifests
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_manifest_sequence();

CREATE OR REPLACE FUNCTION assert_manifest_batch_intent_projection(target_manifest_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE manifest_row manifests%ROWTYPE; plan_row recovery_epoch_plans%ROWTYPE; intent record;
BEGIN
    SELECT * INTO manifest_row FROM manifests WHERE id = target_manifest_id AND migration_state = 'CURRENT';
    IF manifest_row.id IS NULL THEN RETURN; END IF;
    SELECT * INTO plan_row FROM recovery_epoch_plans WHERE id = manifest_row.recovery_plan_id;
    IF plan_row.id IS NULL OR plan_row.status IS DISTINCT FROM 'MANIFEST_DRAFT' OR
       (SELECT count(*) FROM manifest_batch_intents WHERE manifest_id = manifest_row.id) <>
            plan_row.expected_resource_count * 8 THEN
        RAISE EXCEPTION 'Manifest batch intent projection is incomplete';
    END IF;
    FOR intent IN SELECT * FROM manifest_batch_intents WHERE manifest_id = manifest_row.id LOOP
        IF NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(manifest_row.canonical_payload -> 'accounts') account,
                          jsonb_array_elements(account -> 'batches') batch
            WHERE account ->> 'account_id' =
                    (SELECT account_external_id FROM recovery_plan_resource_accounts
                     WHERE plan_id = intent.plan_id AND resource_account_id = intent.resource_account_id)
              AND account ->> 'account_ref' = intent.account_ref
              AND batch ->> 'batch_type' = intent.batch_type
              AND ((intent.epoch_role = 'FROM' AND batch ->> 'from_batch_id' = intent.batch_external_id
                    AND (batch ->> 'from_batch_version')::bigint = intent.batch_version
                    AND batch ->> 'from_ciphertext_hash' = encode(intent.ciphertext_hash, 'hex')
                    AND intent.recovery_wrap_hash IS NULL) OR
                   (intent.epoch_role = 'TO' AND batch ->> 'to_batch_id' = intent.batch_external_id
                    AND (batch ->> 'to_batch_version')::bigint = intent.batch_version
                    AND batch ->> 'to_ciphertext_hash' = encode(intent.ciphertext_hash, 'hex')
                    AND batch ->> 'to_recovery_wrap_hash' = encode(intent.recovery_wrap_hash, 'hex')))
        ) THEN RAISE EXCEPTION 'Manifest canonical batch differs from durable batch intent'; END IF;
    END LOOP;
END;
$$;
CREATE OR REPLACE FUNCTION validate_manifest_batch_intent_projection_deferred()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM assert_manifest_batch_intent_projection(
        CASE WHEN TG_TABLE_NAME = 'manifests' THEN NEW.id ELSE NEW.manifest_id END);
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER manifests_batch_projection_complete
AFTER INSERT ON manifests DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_manifest_batch_intent_projection_deferred();
CREATE CONSTRAINT TRIGGER manifest_batch_intents_projection_complete
AFTER INSERT ON manifest_batch_intents DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_manifest_batch_intent_projection_deferred();

CREATE OR REPLACE FUNCTION enforce_manifest_signature_verification_evidence()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_status text;
    trusted_signing_algorithm text;
    trusted_signing_key_id text;
    trusted_signing_key_fingerprint bytea;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Manifest signature evidence is append-only'; END IF;
    IF NEW.migration_state <> 'CURRENT' THEN RAISE EXCEPTION 'new signature cannot claim legacy state'; END IF;
    SELECT plan.status, member.signing_algorithm, member.signing_key_id, member.signing_key_fingerprint
      INTO target_status, trusted_signing_algorithm, trusted_signing_key_id, trusted_signing_key_fingerprint
    FROM manifests manifest
    JOIN recovery_epoch_plans plan ON plan.id = manifest.recovery_plan_id
    JOIN membership_epoch_members member ON member.epoch_id = NEW.epoch_id AND member.member_id = NEW.member_id
    WHERE manifest.id = NEW.manifest_id AND manifest.epoch_id = NEW.epoch_id
      AND manifest.migration_state = 'CURRENT' AND member.migration_state = 'CURRENT';
    IF target_status <> 'MANIFEST_DRAFT' OR NEW.signing_algorithm <> trusted_signing_algorithm OR
       NEW.signing_key_id <> trusted_signing_key_id OR NEW.signing_key_fingerprint <> trusted_signing_key_fingerprint OR
       NEW.signed_message_hash IS DISTINCT FROM (SELECT expected_message_hash FROM manifest_member_approval_intents
                                   WHERE manifest_id = NEW.manifest_id AND member_id = NEW.member_id) THEN
        RAISE EXCEPTION 'member signature is not verified against the trusted Epoch signing key';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER manifest_signatures_phase2f_invariants
BEFORE INSERT OR UPDATE OR DELETE ON manifest_signatures
FOR EACH ROW EXECUTE FUNCTION enforce_manifest_signature_verification_evidence();

CREATE OR REPLACE FUNCTION enforce_recovery_batch_reference()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE plan recovery_epoch_plans%ROWTYPE; batch credential_batches%ROWTYPE;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'recovery batch reference is append-only'; END IF;
    SELECT * INTO plan FROM recovery_epoch_plans WHERE id = NEW.plan_id;
    SELECT * INTO batch FROM credential_batches WHERE id = NEW.credential_batch_id;
    IF plan.id IS NULL OR batch.id IS NULL OR batch.pool_id IS DISTINCT FROM plan.pool_id OR
       batch.batch_type IS DISTINCT FROM NEW.batch_type OR
       digest(batch.ciphertext, 'sha256') IS DISTINCT FROM NEW.ciphertext_hash OR
       (NEW.epoch_role = 'TO' AND NEW.recovery_wrap_hash <> batch.recovery_binding_hash) OR
       ((NEW.epoch_role = 'FROM') AND (batch.membership_epoch IS DISTINCT FROM plan.from_epoch OR
         batch.status IS DISTINCT FROM 'ACTIVE' OR
         (plan.ceremony_type = 'ROTATE' AND (batch.migration_state IS DISTINCT FROM 'CURRENT' OR
          batch.resource_account_id IS DISTINCT FROM NEW.resource_account_id)) OR
         (plan.ceremony_type = 'BOOTSTRAP' AND NOT
          (batch.migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE'))) OR
         batch.resource_account_ref IS DISTINCT FROM (SELECT provider_account_ref
             FROM recovery_plan_resource_accounts WHERE plan_id = plan.id
               AND resource_account_id = NEW.resource_account_id))) OR
       ((NEW.epoch_role = 'TO') AND (batch.resource_account_id IS DISTINCT FROM NEW.resource_account_id OR
         batch.membership_epoch IS DISTINCT FROM plan.to_epoch OR batch.status IS DISTINCT FROM 'STAGED' OR
         batch.recovery_plan_id IS DISTINCT FROM plan.id)) THEN
        RAISE EXCEPTION 'recovery plan batch reference scope/type/epoch/hash is inconsistent';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_plan_batch_bindings_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_plan_batch_bindings
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_batch_reference();

CREATE OR REPLACE FUNCTION enforce_recovery_evidence_batch_reference()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE evidence recovery_control_evidence%ROWTYPE; binding record;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'control evidence batch reference is append-only'; END IF;
    SELECT * INTO evidence FROM recovery_control_evidence WHERE id = NEW.evidence_id;
    SELECT * INTO binding FROM recovery_plan_batch_bindings
    WHERE plan_id = NEW.plan_id AND resource_account_id = NEW.resource_account_id
      AND epoch_role = NEW.epoch_role AND batch_type = NEW.batch_type;
    IF evidence.id IS NULL OR evidence.plan_id <> NEW.plan_id OR
       evidence.resource_account_id <> NEW.resource_account_id OR binding.credential_batch_id IS NULL OR
       NEW.credential_batch_id <> binding.credential_batch_id OR NEW.ciphertext_hash <> binding.ciphertext_hash OR
       NEW.recovery_wrap_hash IS DISTINCT FROM binding.recovery_wrap_hash THEN
        RAISE EXCEPTION 'control evidence does not bind the exact plan account batch set';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_control_evidence_batches_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_control_evidence_batches
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_evidence_batch_reference();

CREATE OR REPLACE FUNCTION enforce_recovery_plan_account_seat_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'plan account Seat snapshot is immutable'; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM recovery_plan_resource_accounts planned
        JOIN pool_resource_account_seats mapping
          ON mapping.resource_account_id = planned.resource_account_id
         AND mapping.pool_id = planned.pool_id AND mapping.seat_id = NEW.seat_id
         AND mapping.inventory_version = NEW.inventory_version AND mapping.status = 'ACTIVE'
        JOIN recovery_plan_seats planned_seat
          ON planned_seat.plan_id = planned.plan_id AND planned_seat.seat_id = NEW.seat_id
        WHERE planned.plan_id = NEW.plan_id AND planned.resource_account_id = NEW.resource_account_id
    ) THEN RAISE EXCEPTION 'plan account Seat mapping is not an authoritative inventory mapping'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_plan_account_seats_invariants
BEFORE INSERT OR UPDATE OR DELETE ON recovery_plan_account_seats
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_plan_account_seat_snapshot();

CREATE OR REPLACE FUNCTION enforce_open_recovery_seat_inventory()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_pool_id uuid;
    open_plan_id uuid;
BEGIN
    -- 与建计划/最终化统一先锁 Pool，闭合“检查后并发新增”的窗口。
    IF TG_OP = 'UPDATE' THEN
        PERFORM 1 FROM pools WHERE id IN (OLD.pool_id, NEW.pool_id) ORDER BY id FOR UPDATE;
        target_pool_id := OLD.pool_id;
    ELSE
        target_pool_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
        PERFORM 1 FROM pools WHERE id = target_pool_id FOR UPDATE;
    END IF;
    SELECT plan.id INTO open_plan_id FROM recovery_epoch_plans plan
    WHERE plan.pool_id IN (target_pool_id, CASE WHEN TG_OP = 'UPDATE' THEN NEW.pool_id ELSE target_pool_id END)
      AND plan.status NOT IN ('FINALIZED', 'FAILED')
    ORDER BY plan.pool_id LIMIT 1;
    IF open_plan_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND
       current_setting('trusted_pool.recovery_inventory_plan_id', true) = open_plan_id::text AND
       EXISTS (
        SELECT 1
        FROM recovery_plan_seats planned
        JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
        JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
        JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
        JOIN recovery_seat_rotation_progress progress
          ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
        WHERE planned.plan_id = open_plan_id AND planned.seat_id = OLD.id
          AND plan.status = 'READY' AND replacement.status = 'ROTATING'
          AND finalization.operation_type IN ('REPLACE_PERMANENTLY', 'FINALIZE_RECOVERY_BOOTSTRAP')
          AND finalization.target_type = 'POOL'
          AND finalization.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
          AND finalization.lease_owner IS NOT NULL
          AND finalization.lease_expires_at > CURRENT_TIMESTAMP
          AND progress.status = 'ROTATED' AND progress.claim_expires_at > CURRENT_TIMESTAMP
          AND OLD.owner_member_id = planned.from_member_id
          AND OLD.status = 'FROZEN'
          AND OLD.assignment_epoch = planned.expected_assignment_epoch
          AND OLD.active_api_key_version = planned.expected_active_api_key_version
          AND NEW.owner_member_id = planned.to_member_id
          AND NEW.status = 'ACTIVE'
          AND NEW.assignment_epoch = planned.expected_assignment_epoch + 1
          AND NEW.active_api_key_version = planned.expected_active_api_key_version + 1
          AND NEW.sub2api_principal_id = progress.principal_user_id
          AND NEW.sub2api_subscription_id = progress.subscription_id
          AND NEW.sub2api_api_key_id = progress.api_key_id
          AND NEW.active_api_key_version = progress.api_key_version
          AND NEW.id = OLD.id AND NEW.external_id = OLD.external_id
          AND NEW.pool_id = OLD.pool_id AND NEW.seat_no = OLD.seat_no
          AND NEW.sub2api_principal_id = OLD.sub2api_principal_id
          AND NEW.sub2api_subscription_id = OLD.sub2api_subscription_id
          AND NEW.sub2api_api_key_id = OLD.sub2api_api_key_id
          AND OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS NULL
          AND NEW.version = OLD.version + 1 AND NEW.created_at = OLD.created_at
       ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Seat inventory cannot drift during an open recovery ceremony';
END;
$$;
CREATE TRIGGER seats_open_recovery_inventory
BEFORE INSERT OR UPDATE OR DELETE ON seats
FOR EACH ROW EXECUTE FUNCTION enforce_open_recovery_seat_inventory();

CREATE OR REPLACE FUNCTION validate_recovery_seat_inventory_finalized()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- 不能依赖可在提交前重置的 GUC；仅从事件行和不可变计划快照识别恢复形状。
    IF NOT EXISTS (
        SELECT 1 FROM recovery_plan_seats planned
        JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
        WHERE planned.seat_id = NEW.id AND plan.status <> 'FAILED'
          AND OLD.owner_member_id = planned.from_member_id
          AND OLD.status = 'FROZEN'
          AND OLD.assignment_epoch = planned.expected_assignment_epoch
          AND OLD.active_api_key_version = planned.expected_active_api_key_version
          AND NEW.owner_member_id = planned.to_member_id
          AND NEW.status = 'ACTIVE'
          AND NEW.assignment_epoch = planned.expected_assignment_epoch + 1
          AND NEW.active_api_key_version = planned.expected_active_api_key_version + 1
          AND NEW.id = OLD.id AND NEW.external_id = OLD.external_id
          AND NEW.pool_id = OLD.pool_id AND NEW.pool_id = planned.pool_id
          AND NEW.seat_no = OLD.seat_no
          AND NEW.sub2api_principal_id = OLD.sub2api_principal_id
          AND NEW.sub2api_subscription_id = OLD.sub2api_subscription_id
          AND NEW.sub2api_api_key_id = OLD.sub2api_api_key_id
          AND OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS NULL
          AND NEW.version = OLD.version + 1 AND NEW.created_at = OLD.created_at
    ) THEN RETURN NULL; END IF;

    -- 识别为恢复写入后，提交时必须由完整恢复聚合证明该 Seat 已原子最终化。
    IF NOT EXISTS (
        SELECT 1
        FROM recovery_epoch_plans plan
        JOIN recovery_plan_seats planned ON planned.plan_id = plan.id AND planned.seat_id = NEW.id
        JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
        JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
        JOIN integration_operations ceremony ON ceremony.id = plan.integration_operation_id
        JOIN pools pool ON pool.id = plan.pool_id
        JOIN recovery_seat_rotation_progress progress
          ON progress.plan_id = plan.id AND progress.seat_id = planned.seat_id
        JOIN seats live_seat ON live_seat.id = planned.seat_id
        WHERE plan.status = 'FINALIZED'
          AND replacement.status = 'FINALIZED' AND progress.status = 'COMMITTED'
          AND finalization.operation_type IN ('REPLACE_PERMANENTLY', 'FINALIZE_RECOVERY_BOOTSTRAP')
          AND finalization.target_type = 'POOL' AND finalization.target_external_id = pool.external_id
          AND finalization.status = 'SUCCEEDED'
          AND ceremony.operation_type IN ('BOOTSTRAP_RECOVERY_EPOCH', 'ROTATE_RECOVERY_EPOCH')
          AND ceremony.status = 'SUCCEEDED'
          AND OLD.owner_member_id = planned.from_member_id
          AND OLD.status = 'FROZEN'
          AND OLD.assignment_epoch = planned.expected_assignment_epoch
          AND OLD.active_api_key_version = planned.expected_active_api_key_version
          AND NEW.owner_member_id = planned.to_member_id
          AND NEW.status = 'ACTIVE'
          AND NEW.assignment_epoch = planned.expected_assignment_epoch + 1
          AND NEW.active_api_key_version = planned.expected_active_api_key_version + 1
          AND live_seat.pool_id = planned.pool_id
          AND live_seat.owner_member_id = planned.to_member_id
          AND live_seat.status = 'ACTIVE'
          AND live_seat.assignment_epoch = planned.expected_assignment_epoch + 1
          AND live_seat.active_api_key_version = planned.expected_active_api_key_version + 1
          AND live_seat.sub2api_principal_id = NEW.sub2api_principal_id
          AND live_seat.sub2api_subscription_id = NEW.sub2api_subscription_id
          AND live_seat.sub2api_api_key_id = NEW.sub2api_api_key_id
          AND NEW.id = OLD.id AND NEW.external_id = OLD.external_id
          AND NEW.pool_id = OLD.pool_id AND NEW.seat_no = OLD.seat_no
          AND NEW.sub2api_principal_id = OLD.sub2api_principal_id
          AND NEW.sub2api_subscription_id = OLD.sub2api_subscription_id
          AND NEW.sub2api_api_key_id = OLD.sub2api_api_key_id
          AND OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS NULL
          AND NEW.version = OLD.version + 1 AND NEW.created_at = OLD.created_at
    ) THEN
        RAISE EXCEPTION 'recovery-authorized Seat inventory mutation did not finalize atomically';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER seats_recovery_inventory_finalized
AFTER UPDATE ON seats DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_recovery_seat_inventory_finalized();

CREATE OR REPLACE FUNCTION enforce_resource_account_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_pool_id uuid;
BEGIN
    target_pool_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
    PERFORM 1 FROM pools WHERE id = target_pool_id FOR UPDATE;
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'resource account inventory is append-preserving'; END IF;
    IF TG_OP = 'INSERT' AND EXISTS (
        SELECT 1 FROM recovery_epoch_plans plan WHERE plan.pool_id = NEW.pool_id
          AND plan.status NOT IN ('FINALIZED', 'FAILED')
    ) THEN RAISE EXCEPTION 'resource account cannot be added during an open ceremony'; END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
           NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.registration_operation_id IS DISTINCT FROM OLD.registration_operation_id OR
           NEW.provider IS DISTINCT FROM OLD.provider OR NEW.provider_account_ref IS DISTINCT FROM OLD.provider_account_ref OR
           NEW.inventory_version IS DISTINCT FROM OLD.inventory_version OR NEW.provider_key_ref IS DISTINCT FROM OLD.provider_key_ref OR
           NEW.attestation_digest IS DISTINCT FROM OLD.attestation_digest OR
           NEW.attestation_signature IS DISTINCT FROM OLD.attestation_signature OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
           NEW.version <> OLD.version + 1 OR OLD.status <> 'ACTIVE' OR NEW.status <> 'RETIRED' OR EXISTS (
               SELECT 1 FROM recovery_epoch_plans plan WHERE plan.pool_id = OLD.pool_id
                 AND plan.status NOT IN ('FINALIZED', 'FAILED')
           ) THEN RAISE EXCEPTION 'resource account cannot drift during an open ceremony'; END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER pool_resource_accounts_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON pool_resource_accounts
FOR EACH ROW EXECUTE FUNCTION enforce_resource_account_lifecycle();

CREATE OR REPLACE FUNCTION enforce_resource_account_mapping_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_pool_id uuid;
BEGIN
    target_pool_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.pool_id ELSE NEW.pool_id END;
    PERFORM 1 FROM pools WHERE id = target_pool_id FOR UPDATE;
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'resource account Seat mapping is append-preserving'; END IF;
    IF TG_OP = 'INSERT' AND EXISTS (
        SELECT 1 FROM recovery_epoch_plans plan WHERE plan.pool_id = NEW.pool_id
          AND plan.status NOT IN ('FINALIZED', 'FAILED')
    ) THEN RAISE EXCEPTION 'resource account Seat mapping cannot be added during an open ceremony'; END IF;
    IF TG_OP = 'UPDATE' AND (NEW.resource_account_id IS DISTINCT FROM OLD.resource_account_id OR
       NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
       NEW.mapping_operation_id IS DISTINCT FROM OLD.mapping_operation_id OR
       NEW.inventory_version IS DISTINCT FROM OLD.inventory_version OR OLD.status <> 'ACTIVE' OR
       NEW.status <> 'RETIRED' OR NEW.retired_at IS NULL OR EXISTS (
           SELECT 1 FROM recovery_epoch_plans plan WHERE plan.pool_id = OLD.pool_id
             AND plan.status NOT IN ('FINALIZED', 'FAILED')
       )) THEN RAISE EXCEPTION 'resource account Seat mapping cannot drift during an open ceremony'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER pool_resource_account_seats_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON pool_resource_account_seats
FOR EACH ROW EXECUTE FUNCTION enforce_resource_account_mapping_lifecycle();

CREATE OR REPLACE FUNCTION enforce_recovery_control_evidence_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE planned record; plan_type text; expected_purpose text;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'verified control evidence is append-only'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT account.*, plan.ceremony_type INTO planned
        FROM recovery_plan_resource_accounts account
        JOIN recovery_epoch_plans plan ON plan.id = account.plan_id
        WHERE account.plan_id = NEW.plan_id AND account.resource_account_id = NEW.resource_account_id;
        plan_type := planned.ceremony_type;
        expected_purpose := CASE WHEN plan_type = 'BOOTSTRAP' THEN 'BOOTSTRAP_GENESIS'
                                 ELSE 'ROTATION_CONTROL' END;
        IF planned.resource_account_id IS NULL OR
           NEW.external_id IS DISTINCT FROM planned.control_evidence_external_id OR
           NEW.provider_attestation_digest IS DISTINCT FROM planned.control_attestation_digest OR
           NEW.provider_attestation_issuer IS DISTINCT FROM planned.control_attestation_issuer OR
           NEW.provider_attestation_key_id IS DISTINCT FROM planned.control_attestation_key_id OR
           NEW.provider_attestation_version IS DISTINCT FROM planned.control_attestation_version OR
           NEW.ceremony_type IS DISTINCT FROM plan_type OR
           NEW.attestation_purpose IS DISTINCT FROM expected_purpose OR
           NEW.status IS DISTINCT FROM 'VERIFIED' OR NEW.verified_at IS NULL THEN
            RAISE EXCEPTION 'control evidence differs from the verified plan account attestation';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
           NEW.integration_operation_id IS DISTINCT FROM OLD.integration_operation_id OR
           NEW.plan_id IS DISTINCT FROM OLD.plan_id OR NEW.resource_account_id IS DISTINCT FROM OLD.resource_account_id OR
           NEW.provider_attestation_ref IS DISTINCT FROM OLD.provider_attestation_ref OR
           NEW.provider_attestation_digest IS DISTINCT FROM OLD.provider_attestation_digest OR
           NEW.provider_attestation_issuer IS DISTINCT FROM OLD.provider_attestation_issuer OR
           NEW.provider_attestation_key_id IS DISTINCT FROM OLD.provider_attestation_key_id OR
           NEW.provider_attestation_version IS DISTINCT FROM OLD.provider_attestation_version OR
           NEW.ceremony_type IS DISTINCT FROM OLD.ceremony_type OR
           NEW.attestation_purpose IS DISTINCT FROM OLD.attestation_purpose OR
           OLD.status <> 'VERIFIED' OR NEW.status <> 'COMMITTED' OR NEW.committed_at IS NULL OR NOT EXISTS (
               SELECT 1 FROM recovery_epoch_plans plan WHERE plan.id = OLD.plan_id AND plan.status = 'READY'
           ) THEN RAISE EXCEPTION 'illegal control evidence mutation'; END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_control_evidence_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON recovery_control_evidence
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_control_evidence_lifecycle();

CREATE OR REPLACE FUNCTION enforce_recovery_rotation_progress_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Seat rotation progress is an append-preserving ledger'; END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.plan_id IS DISTINCT FROM OLD.plan_id OR
           NEW.seat_id IS DISTINCT FROM OLD.seat_id OR
           (NEW.derived_operation_id IS DISTINCT FROM OLD.derived_operation_id AND
            NOT (OLD.status = 'EXPIRED' AND NEW.status = 'PENDING')) OR
           NEW.created_at IS DISTINCT FROM OLD.created_at OR NOT (
              (OLD.status IN ('PENDING', 'RETRYABLE') AND NEW.status IN ('PENDING', 'RETRYABLE', 'ROTATED', 'FAILED', 'EXPIRED')) OR
              (OLD.status = 'ROTATED' AND NEW.status IN ('COMMITTED', 'EXPIRED')) OR
              (OLD.status = 'EXPIRED' AND NEW.status = 'PENDING' AND
               NEW.claim_token_hash IS NULL AND NEW.envelope_ciphertext IS NULL AND NEW.wrapped_dek_kms IS NULL)
           ) THEN RAISE EXCEPTION 'illegal Seat rotation progress transition'; END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_seat_rotation_progress_lifecycle
BEFORE UPDATE OR DELETE ON recovery_seat_rotation_progress
FOR EACH ROW EXECUTE FUNCTION enforce_recovery_rotation_progress_lifecycle();

CREATE OR REPLACE FUNCTION enforce_phase2f_credential_batch_scope()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE plan recovery_epoch_plans%ROWTYPE; root recovery_root_artifacts%ROWTYPE; account record; epoch_status text;
BEGIN
    IF NEW.recovery_plan_id IS NULL THEN
        -- 原 Phase2-E trigger 继续负责普通批次；这里额外明确禁止普通调用写 PREPARING/STAGED。
        SELECT status INTO epoch_status FROM membership_epochs
        WHERE pool_id = NEW.pool_id AND epoch = NEW.membership_epoch;
        IF NEW.status = 'STAGED' OR (NEW.status IN ('PREPARED', 'SEALED', 'ACTIVE') AND epoch_status <> 'ACTIVE') THEN
            RAISE EXCEPTION 'ordinary Phase2-E batch cannot write a PREPARING Epoch or STAGED status';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO plan FROM recovery_epoch_plans WHERE id = NEW.recovery_plan_id FOR SHARE;
    SELECT * INTO root FROM recovery_root_artifacts
      WHERE id = NEW.recovery_root_artifact_id AND plan_id = plan.id;
    SELECT planned.* INTO account FROM recovery_plan_resource_accounts planned
      WHERE planned.plan_id = plan.id AND planned.resource_account_id = NEW.resource_account_id;
    SELECT status INTO epoch_status FROM membership_epochs
      WHERE pool_id = NEW.pool_id AND epoch = NEW.membership_epoch AND recovery_plan_id = plan.id;
    IF plan.id IS NULL OR root.id IS NULL OR account.resource_account_id IS NULL OR
       NEW.pool_id <> plan.pool_id OR NEW.membership_epoch <> plan.to_epoch OR
       NEW.resource_account_ref <> account.provider_account_ref OR
       NEW.recovery_wrap_algorithm <> root.wrap_algorithm OR NEW.recovery_wrapper_domain <> root.wrap_domain OR
       NEW.recovery_key_ref <> root.epoch_recovery_key_id OR
       NEW.recovery_key_version <> root.root_key_version OR
       NEW.recovery_key_fingerprint <> root.epoch_recovery_key_fingerprint OR
       NEW.recovery_binding_hash <> credential_recovery_binding_hash(
           NEW.recovery_wrapper_domain, NEW.recovery_wrap_algorithm, NEW.recovery_key_ref,
           NEW.aad_hash, NEW.encrypted_dek_recovery) THEN
        RAISE EXCEPTION 'STAGED batch is not bound to this plan Root public handle and account';
    END IF;
    IF TG_OP = 'INSERT' AND (epoch_status <> 'PREPARING' OR plan.status <> 'ACKNOWLEDGED' OR NEW.status <> 'STAGED' OR
       NEW.seal_integration_operation_id IS NOT NULL) THEN
        RAISE EXCEPTION 'recovery batch must enter as plan-scoped STAGED after acknowledgements';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.external_id IS DISTINCT FROM OLD.external_id OR
           NEW.pool_id IS DISTINCT FROM OLD.pool_id OR NEW.membership_epoch IS DISTINCT FROM OLD.membership_epoch OR
           NEW.resource_account_ref IS DISTINCT FROM OLD.resource_account_ref OR
           NEW.resource_account_id IS DISTINCT FROM OLD.resource_account_id OR
           NEW.batch_type IS DISTINCT FROM OLD.batch_type OR NEW.batch_version IS DISTINCT FROM OLD.batch_version OR
           NEW.migration_state IS DISTINCT FROM OLD.migration_state OR
           NEW.seal_integration_operation_id IS DISTINCT FROM OLD.seal_integration_operation_id OR
           NEW.aad_version IS DISTINCT FROM OLD.aad_version OR
           NEW.encryption_algorithm IS DISTINCT FROM OLD.encryption_algorithm OR
           NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR NEW.nonce IS DISTINCT FROM OLD.nonce OR
           NEW.aad_hash IS DISTINCT FROM OLD.aad_hash OR NEW.content_hash IS DISTINCT FROM OLD.content_hash OR
           NEW.encrypted_dek_kms IS DISTINCT FROM OLD.encrypted_dek_kms OR
           NEW.encrypted_dek_recovery IS DISTINCT FROM OLD.encrypted_dek_recovery OR
           NEW.kms_wrap_algorithm IS DISTINCT FROM OLD.kms_wrap_algorithm OR
           NEW.kms_key_ref IS DISTINCT FROM OLD.kms_key_ref OR
           NEW.kms_wrapper_domain IS DISTINCT FROM OLD.kms_wrapper_domain OR
           NEW.recovery_wrap_algorithm IS DISTINCT FROM OLD.recovery_wrap_algorithm OR
           NEW.recovery_key_ref IS DISTINCT FROM OLD.recovery_key_ref OR
           NEW.recovery_wrapper_domain IS DISTINCT FROM OLD.recovery_wrapper_domain OR
           NEW.recovery_binding_hash IS DISTINCT FROM OLD.recovery_binding_hash OR
           NEW.recovery_plan_id IS DISTINCT FROM OLD.recovery_plan_id OR
           NEW.recovery_root_artifact_id IS DISTINCT FROM OLD.recovery_root_artifact_id OR
           NEW.recovery_key_fingerprint IS DISTINCT FROM OLD.recovery_key_fingerprint OR
           NEW.recovery_key_version IS DISTINCT FROM OLD.recovery_key_version OR
           NEW.recovery_wrap_attestation_digest IS DISTINCT FROM OLD.recovery_wrap_attestation_digest OR
           NEW.recovery_wrap_attestation_signature IS DISTINCT FROM OLD.recovery_wrap_attestation_signature OR
           NEW.sealed_at IS DISTINCT FROM OLD.sealed_at OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
           NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'plan-scoped credential batch cryptographic scope is immutable';
        END IF;
        IF OLD.status = 'STAGED' AND NEW.status = 'ACTIVE' THEN
            IF plan.status <> 'READY' OR epoch_status <> 'PREPARING' THEN
                RAISE EXCEPTION 'STAGED batch activates only in its READY plan finalize';
            END IF;
        ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'RETIRED' THEN
            IF NOT EXISTS (
                SELECT 1 FROM recovery_plan_batch_bindings binding
                JOIN recovery_epoch_plans retiring_plan ON retiring_plan.id = binding.plan_id
                WHERE binding.credential_batch_id = OLD.id AND binding.epoch_role = 'FROM'
                  AND retiring_plan.status = 'READY' AND retiring_plan.pool_id = OLD.pool_id
                  AND retiring_plan.from_epoch = OLD.membership_epoch
            ) THEN RAISE EXCEPTION 'ACTIVE recovery batch retirement lacks a READY successor plan'; END IF;
        ELSE RAISE EXCEPTION 'illegal recovery batch transition'; END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER credential_batches_phase2f_scope
BEFORE INSERT OR UPDATE ON credential_batches
FOR EACH ROW EXECUTE FUNCTION enforce_phase2f_credential_batch_scope();

-- 007 的 Phase2-E trigger 不认识 STAGED；只让它处理普通批次，恢复批次由上面的专用 trigger 处理。
DROP TRIGGER credential_batches_phase2e_invariants ON credential_batches;
CREATE TRIGGER credential_batches_phase2e_invariants
BEFORE INSERT OR UPDATE ON credential_batches
FOR EACH ROW WHEN (NEW.recovery_plan_id IS NULL)
EXECUTE FUNCTION enforce_current_credential_batch_invariants();
CREATE OR REPLACE FUNCTION reject_credential_batch_delete_phase2f()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'credential batch is an immutable ledger'; END; $$;
CREATE TRIGGER credential_batches_delete_phase2f
BEFORE DELETE ON credential_batches FOR EACH ROW EXECUTE FUNCTION reject_credential_batch_delete_phase2f();

-- 007 的 LEGACY_UNRECOVERABLE 行永久只读。Bootstrap 通过新 CURRENT 批次和 epoch floor
-- 令旧密文不可达，而不是修改、补写或伪造旧批次的恢复历史。
CREATE OR REPLACE FUNCTION enforce_pool_credential_epoch_floor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.credential_epoch_floor < OLD.credential_epoch_floor THEN
        RAISE EXCEPTION 'pool credential_epoch_floor cannot decrease';
    END IF;
    IF EXISTS (
        SELECT 1 FROM credential_batches
        WHERE pool_id = NEW.id
          AND membership_epoch < NEW.credential_epoch_floor
          AND migration_state = 'CURRENT'
          AND status IN ('SEALED', 'DISTRIBUTED', 'ACTIVE')
    ) THEN
        RAISE EXCEPTION 'pool credential_epoch_floor would strand a writable CURRENT credential batch';
    END IF;
    RETURN NEW;
END;
$$;

-- Phase2-E 的历史校验只适用于独立 seal operation；plan-scoped 批次由 Phase2-F 聚合校验。
CREATE OR REPLACE FUNCTION assert_credential_batch_transition_history(target_batch_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE batch_row record; activate_row record; retire_row record;
BEGIN
    SELECT migration_state, status, version, recovery_plan_id INTO batch_row
    FROM credential_batches WHERE id = target_batch_id;
    IF batch_row.migration_state IS NULL OR batch_row.migration_state <> 'CURRENT' OR
       batch_row.recovery_plan_id IS NOT NULL THEN RETURN; END IF;
	IF EXISTS (
		SELECT 1 FROM recovery_plan_batch_bindings binding
		JOIN recovery_epoch_plans plan ON plan.id = binding.plan_id
		WHERE binding.credential_batch_id = target_batch_id AND binding.epoch_role = 'FROM'
		  AND plan.status = 'FINALIZED'
	) THEN RETURN; END IF;
    SELECT * INTO activate_row FROM credential_batch_transitions
      WHERE credential_batch_id = target_batch_id AND transition_type = 'ACTIVATE';
    SELECT * INTO retire_row FROM credential_batch_transitions
      WHERE credential_batch_id = target_batch_id AND transition_type = 'RETIRE';
    IF batch_row.status = 'SEALED' AND (batch_row.version <> 2 OR activate_row.id IS NOT NULL OR retire_row.id IS NOT NULL) THEN
        RAISE EXCEPTION 'sealed credential batch has an invalid transition history';
    ELSIF batch_row.status = 'ACTIVE' AND (activate_row.id IS NULL OR retire_row.id IS NOT NULL OR
        activate_row.expected_batch_version <> 2 OR activate_row.resulting_batch_version <> batch_row.version) THEN
        RAISE EXCEPTION 'active credential batch has an invalid transition history';
    ELSIF batch_row.status = 'RETIRED' AND (activate_row.id IS NULL OR retire_row.id IS NULL OR
        activate_row.expected_batch_version <> 2 OR retire_row.expected_batch_version <> activate_row.resulting_batch_version OR
        retire_row.resulting_batch_version <> batch_row.version OR retire_row.occurred_at < activate_row.occurred_at) THEN
        RAISE EXCEPTION 'retired credential batch has an invalid transition history';
    END IF;
END;
$$;

COMMIT;
