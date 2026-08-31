package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
	"trusted-pool-platform/backend/internal/recovery"
)

const recoveryPlanColumns = `plan.id, plan.external_id, plan.ceremony_type, plan.pool_id, pool.external_id,
plan.from_epoch, plan.to_epoch, plan.status, plan.governance_threshold, plan.recovery_threshold,
plan.expected_member_count, plan.expected_resource_count,
(SELECT count(*) FROM recovery_share_deliveries delivery WHERE delivery.recovery_plan_id = plan.id AND delivery.migration_state = 'CURRENT'),
(SELECT count(*) FROM manifest_signatures signature JOIN manifests manifest ON manifest.id = signature.manifest_id
 WHERE manifest.recovery_plan_id = plan.id AND signature.migration_state = 'CURRENT'),
(SELECT count(*) FROM recovery_share_deliveries delivery WHERE delivery.recovery_plan_id = plan.id
 AND delivery.migration_state = 'CURRENT' AND delivery.delivery_status = 'ACKNOWLEDGED'),
(SELECT count(*) FROM recovery_plan_batch_bindings binding WHERE binding.plan_id = plan.id AND binding.epoch_role = 'TO'),
(SELECT artifact.id::text FROM recovery_root_artifacts artifact WHERE artifact.plan_id = plan.id),
(SELECT manifest.id::text FROM manifests manifest WHERE manifest.recovery_plan_id = plan.id AND manifest.migration_state = 'CURRENT'),
(SELECT manifest.manifest_hash FROM manifests manifest WHERE manifest.recovery_plan_id = plan.id AND manifest.migration_state = 'CURRENT'),
plan.previous_manifest_hash, plan.bootstrap_attestation_ref, plan.bootstrap_attestation_digest,
plan.bootstrap_attestation_issuer, plan.bootstrap_attestation_key_id, plan.bootstrap_attestation_version,
plan.portable_format_version, plan.root_trust_profile_id, plan.crypto_suite_id,
plan.provider_proof_profile, plan.ceremony_attestation_algorithm,
plan.version, plan.created_at, plan.updated_at`

const recoveryPlanFrom = ` FROM recovery_epoch_plans plan JOIN pools pool ON pool.id = plan.pool_id `

var _ recovery.Store = (*Store)(nil)

func (s *Store) RegisterResourceAccount(ctx context.Context, input recovery.ResourceAccountRegistration) error {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryID(input.ExternalID) || !validRecoveryID(input.PoolExternalID) ||
		!validRecoveryID(input.Provider) || !validRecoveryID(input.ProviderAccountRef) ||
		!validRecoveryID(input.ProviderKeyRef) || input.InventoryVersion == 0 ||
		zeroRecoveryHash(input.AttestationDigest) || len(input.AttestationSignature) == 0 {
		return recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin resource account registration: %w", err)
	}
	defer tx.Rollback()
	op, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key, "REGISTER_RESOURCE_ACCOUNT",
		input.PoolExternalID, input.RequestHash, canonical, false, "", 0)
	if err != nil {
		return err
	}
	if !created {
		if op.Status != application.OperationSucceeded {
			return recovery.ErrInvalidState
		}
		var externalID string
		if err := tx.QueryRowContext(ctx, `SELECT account.external_id FROM pool_resource_accounts account
WHERE account.registration_operation_id = $1`, op.AggregateID).Scan(&externalID); err != nil {
			return translateRecoveryError("replay resource account registration", err)
		}
		if externalID != input.ExternalID {
			return recovery.ErrHashDrift
		}
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO pool_resource_accounts (
external_id, pool_id, registration_operation_id, provider, provider_account_ref, inventory_version,
provider_key_ref, attestation_digest, attestation_signature, status, version, created_at, updated_at
)
SELECT $1, pool.id, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM pools pool WHERE pool.external_id = $9 AND pool.status <> 'CLOSED'`, input.ExternalID, op.AggregateID,
		input.Provider, input.ProviderAccountRef, input.InventoryVersion, input.ProviderKeyRef,
		input.AttestationDigest[:], input.AttestationSignature, input.PoolExternalID)
	if err != nil {
		return translateRecoveryError("insert resource account", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return recovery.ErrInvalidState
	}
	if _, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
response_snapshot = jsonb_build_object('resource_account_id', $2::text), completed_at = CURRENT_TIMESTAMP,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1`, op.AggregateID, input.ExternalID); err != nil {
		return translateRecoveryError("complete resource account registration", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit resource account registration: %w", err)
	}
	return nil
}

func (s *Store) RegisterResourceAccountSeatMapping(ctx context.Context, input recovery.ResourceAccountSeatMappingRegistration) error {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryID(input.AccountExternalID) || !validRecoveryID(input.SeatExternalID) ||
		input.InventoryVersion == 0 {
		return recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin account Seat mapping: %w", err)
	}
	defer tx.Rollback()
	var poolExternalID string
	if err := tx.QueryRowContext(ctx, `SELECT pool.external_id FROM pool_resource_accounts account
	JOIN pools pool ON pool.id = account.pool_id WHERE account.external_id = $1 AND account.status = 'ACTIVE'
`, input.AccountExternalID).Scan(&poolExternalID); err != nil {
		return translateRecoveryError("load resource account for Seat mapping", err)
	}
	op, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key, "MAP_RESOURCE_ACCOUNT_SEAT",
		poolExternalID, input.RequestHash, canonical, false, "", 0)
	if err != nil {
		return err
	}
	if created {
		result, err := tx.ExecContext(ctx, `INSERT INTO pool_resource_account_seats (
resource_account_id, pool_id, seat_id, mapping_operation_id, inventory_version, status, created_at
)
SELECT account.id, account.pool_id, seat.id, $1, $2, 'ACTIVE', CURRENT_TIMESTAMP
FROM pool_resource_accounts account JOIN seats seat ON seat.pool_id = account.pool_id
WHERE account.external_id = $3 AND account.status = 'ACTIVE' AND seat.external_id = $4 AND seat.status <> 'CLOSED'`,
			op.AggregateID, input.InventoryVersion, input.AccountExternalID, input.SeatExternalID)
		if err != nil {
			return translateRecoveryError("insert resource account Seat mapping", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return recovery.ErrInvalidState
		}
		if _, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
response_snapshot = jsonb_build_object('resource_account_id', $2::text, 'seat_id', $3::text),
completed_at = CURRENT_TIMESTAMP, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
			op.AggregateID, input.AccountExternalID, input.SeatExternalID); err != nil {
			return translateRecoveryError("complete account Seat mapping", err)
		}
	} else if op.Status != application.OperationSucceeded {
		return recovery.ErrInvalidState
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit account Seat mapping: %w", err)
	}
	return nil
}

func (s *Store) BeginEpochPlan(ctx context.Context, input recovery.BeginEpochPlanInput) (*recovery.EpochPlanTarget, bool, error) {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryID(input.PlanExternalID) || !validRecoveryID(input.PoolExternalID) ||
		input.FromEpoch == 0 || input.ToEpoch != input.FromEpoch+1 || len(input.Members) == 0 ||
		input.GovernanceThreshold == 0 || input.RecoveryThreshold == 0 ||
		int(input.GovernanceThreshold) > len(input.Members) || input.RecoveryThreshold > input.GovernanceThreshold ||
		input.LeaseDuration <= 0 || !validRecoveryID(input.LeaseOwner) ||
		(input.CeremonyType != recovery.CeremonyBootstrap && input.CeremonyType != recovery.CeremonyRotate) {
		return nil, false, recovery.ErrInvalidData
	}
	if !validRecoveryID(input.BootstrapAttestationRef) || zeroRecoveryHash(input.BootstrapAttestationDigest) ||
		!validRecoveryID(input.BootstrapAttestationIssuer) || !validRecoveryID(input.BootstrapAttestationKeyID) ||
		len(input.BootstrapAttestationSignature) == 0 || input.BootstrapAttestationVersion == 0 {
		return nil, false, recovery.ErrInvalidData
	}
	if !validPortableEvidenceProfile(input.PortableProfile) {
		return nil, false, recovery.ErrInvalidData
	}
	if input.CeremonyType == recovery.CeremonyBootstrap {
		if !zeroRecoveryHash(input.PreviousManifestHash) || len(input.Replacements) != 0 {
			return nil, false, recovery.ErrInvalidData
		}
	} else if zeroRecoveryHash(input.PreviousManifestHash) {
		return nil, false, recovery.ErrInvalidData
	}
	if err := validateEpochMembers(input.Members); err != nil {
		return nil, false, err
	}
	providerAttestationSetHash, err := recovery.ProviderAttestationSetHash(input.Accounts)
	if err != nil {
		return nil, false, recovery.ErrInvalidData
	}
	freezes, err := validateEpochFreezes(input.SeatFreezes)
	if err != nil || len(freezes) != len(input.Members) {
		return nil, false, recovery.ErrInvalidData
	}
	replacements, err := validateEpochReplacements(input.Replacements)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin recovery epoch plan: %w", err)
	}
	defer tx.Rollback()
	operationKind := "ROTATE_RECOVERY_EPOCH"
	if input.CeremonyType == recovery.CeremonyBootstrap {
		operationKind = "BOOTSTRAP_RECOVERY_EPOCH"
	}
	op, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key, operationKind,
		input.PoolExternalID, input.RequestHash, canonical, true, input.LeaseOwner, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if !created {
		plan, loadErr := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+
			`JOIN integration_operations io ON io.id = plan.integration_operation_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2`, input.Key.ClientID, input.Key.OperationID))
		if loadErr != nil {
			return nil, false, translateRecoveryError("load replayed recovery plan", loadErr)
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit replayed recovery plan: %w", err)
		}
		return &recovery.EpochPlanTarget{Operation: toRecoveryOperation(op), Plan: plan}, false, nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, input.PoolExternalID); err != nil {
		return nil, false, fmt.Errorf("lock recovery Pool ceremony: %w", err)
	}

	var poolID string
	err = tx.QueryRowContext(ctx, `SELECT pool.id
FROM pools pool
JOIN membership_epochs epoch ON epoch.pool_id = pool.id AND epoch.epoch = $2 AND epoch.status = 'ACTIVE'
LEFT JOIN manifests manifest ON manifest.epoch_id = epoch.id AND manifest.status = 'ACTIVE'
 AND manifest.migration_state = 'CURRENT'
LEFT JOIN recovery_root_artifacts root ON root.id = manifest.root_artifact_id AND root.migration_state = 'CURRENT'
WHERE pool.external_id = $1 AND pool.membership_epoch = $2 AND pool.credential_epoch_floor <= $2
  AND (($3 = 'ROTATE' AND epoch.recovery_governance_state = 'CURRENT'
        AND manifest.manifest_hash = $4 AND root.id IS NOT NULL) OR
       ($3 = 'BOOTSTRAP' AND epoch.recovery_governance_state = 'LEGACY_UNVERIFIED'
        AND $4 = decode(repeat('00', 32), 'hex')))
FOR UPDATE OF pool, epoch`, input.PoolExternalID, input.FromEpoch,
		input.CeremonyType, input.PreviousManifestHash[:]).Scan(&poolID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, recovery.ErrInvalidState
	}
	if err != nil {
		return nil, false, fmt.Errorf("lock authoritative recovery Pool: %w", err)
	}
	var seatCount, frozenSeatCount, accountCount int
	if err := tx.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM seats WHERE pool_id = $1 AND owner_member_id IS NOT NULL AND status <> 'CLOSED'),
  (SELECT count(*) FROM seats WHERE pool_id = $1 AND owner_member_id IS NOT NULL AND status = 'FROZEN'),
  (SELECT count(*) FROM pool_resource_accounts WHERE pool_id = $1 AND status = 'ACTIVE')`, poolID).
		Scan(&seatCount, &frozenSeatCount, &accountCount); err != nil {
		return nil, false, fmt.Errorf("count authoritative recovery inventory: %w", err)
	}
	if seatCount != len(input.Members) || frozenSeatCount != seatCount || accountCount == 0 ||
		accountCount != len(input.Accounts) {
		return nil, false, recovery.ErrInvalidState
	}
	var planID string
	err = tx.QueryRowContext(ctx, `INSERT INTO recovery_epoch_plans (
external_id, integration_operation_id, ceremony_type, pool_id, from_epoch, to_epoch, status,
governance_threshold, recovery_threshold, required_share_ack_count,
expected_member_count, expected_seat_count, expected_resource_count, expected_control_batch_count,
previous_manifest_hash, from_epoch_status, from_governance_state,
bootstrap_attestation_ref, bootstrap_attestation_digest, bootstrap_attestation_issuer,
bootstrap_attestation_key_id, bootstrap_attestation_signature, bootstrap_attestation_version,
provider_attestation_set_hash, portable_format_version, root_trust_profile_id, crypto_suite_id,
provider_proof_profile, ceremony_attestation_algorithm, version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, 'PLANNED', $7, $8, $9, $9, $9, $10, $11, $12,
'ACTIVE', $13, $14, $15::bytea, $16, $17, $18::bytea, $19, $20::bytea,
$21, $22, $23, $24, $25, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
		input.PlanExternalID, op.AggregateID, input.CeremonyType, poolID, input.FromEpoch, input.ToEpoch,
		input.GovernanceThreshold, input.RecoveryThreshold, seatCount, accountCount, accountCount*4,
		input.PreviousManifestHash[:], sourceGovernanceState(input.CeremonyType), input.BootstrapAttestationRef,
		input.BootstrapAttestationDigest[:], input.BootstrapAttestationIssuer, input.BootstrapAttestationKeyID,
		input.BootstrapAttestationSignature, input.BootstrapAttestationVersion,
		providerAttestationSetHash[:], portableProfileField(input.PortableProfile, "format"),
		portableProfileField(input.PortableProfile, "trust"), portableProfileField(input.PortableProfile, "suite"),
		portableProfileField(input.PortableProfile, "proof"), portableProfileField(input.PortableProfile, "algorithm")).Scan(&planID)
	if err != nil {
		return nil, false, translateRecoveryError("insert recovery epoch plan", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold, previous_manifest_hash,
recovery_plan_id, recovery_governance_state, created_at
) VALUES ($1, $2, 'PREPARING', $3, $4, $5, $6, 'CURRENT', CURRENT_TIMESTAMP)`, poolID,
		input.ToEpoch, input.GovernanceThreshold, input.RecoveryThreshold, input.PreviousManifestHash[:], planID); err != nil {
		return nil, false, translateRecoveryError("insert preparing membership Epoch", err)
	}

	memberBySeat := make(map[string]recovery.EpochMember, len(input.Members))
	for _, member := range input.Members {
		memberBySeat[member.SeatExternalID] = member
	}
	rows, err := tx.QueryContext(ctx, `SELECT seat.external_id, owner.external_id, seat.assignment_epoch,
seat.active_api_key_version
FROM seats seat JOIN members owner ON owner.id = seat.owner_member_id
WHERE seat.pool_id = $1 AND seat.status = 'FROZEN' ORDER BY seat.seat_no FOR SHARE OF seat, owner`, poolID)
	if err != nil {
		return nil, false, fmt.Errorf("load authoritative Seat owners: %w", err)
	}
	owners := make([]recoverySeatOwner, 0, seatCount)
	for rows.Next() {
		var item recoverySeatOwner
		if err := rows.Scan(&item.seat, &item.owner, &item.assignment, &item.apiKeyVersion); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("scan authoritative Seat owner: %w", err)
		}
		owners = append(owners, item)
	}
	if err := rows.Close(); err != nil {
		return nil, false, fmt.Errorf("close authoritative Seat owners: %w", err)
	}
	for _, owner := range owners {
		member, exists := memberBySeat[owner.seat]
		if !exists {
			return nil, false, recovery.ErrInvalidData
		}
		replacement, changing := replacements[owner.seat]
		if changing {
			if replacement.FromMemberExternalID != owner.owner || replacement.ToMemberExternalID != member.MemberExternalID {
				return nil, false, recovery.ErrBindingMismatch
			}
		} else if member.MemberExternalID != owner.owner {
			return nil, false, recovery.ErrBindingMismatch
		}
		freeze, frozen := freezes[owner.seat]
		if !frozen || freeze.ExpectedAssignmentEpoch != owner.assignment {
			return nil, false, recovery.ErrBindingMismatch
		}
		if changing && ((replacement.ExpectedAssignmentEpoch != 0 &&
			replacement.ExpectedAssignmentEpoch != freeze.ExpectedAssignmentEpoch) ||
			(replacement.FreezeOperationID != "" && replacement.FreezeOperationID != freeze.FreezeOperationID) ||
			(!zeroRecoveryHash(replacement.FreezeSnapshotHash) &&
				replacement.FreezeSnapshotHash != freeze.FreezeSnapshotHash)) {
			return nil, false, recovery.ErrBindingMismatch
		}
		var freezeID string
		if err := tx.QueryRowContext(ctx, `SELECT suspension.id FROM suspension_cases suspension
JOIN seats seat ON seat.id = suspension.seat_id
WHERE seat.external_id = $1 AND suspension.status = 'FROZEN' AND suspension.operation_id = $2
  AND digest(convert_to(suspension.freeze_snapshot::text, 'UTF8'), 'sha256') = $3
 FOR SHARE OF suspension`, owner.seat, freeze.FreezeOperationID,
			freeze.FreezeSnapshotHash[:]).Scan(&freezeID); err != nil {
			return nil, false, translateRecoveryError("bind frozen ceremony Seat", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_seats (
plan_id, pool_id, from_epoch, to_epoch, seat_id, from_member_id, to_member_id,
expected_assignment_epoch, is_replacement, freeze_suspension_case_id, freeze_operation_id,
expected_active_api_key_version, freeze_snapshot_hash, created_at
) SELECT $1, $2, $3, $4, seat.id, old_owner.id, new_owner.id, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP
FROM seats seat JOIN members old_owner ON old_owner.external_id = $11
JOIN members new_owner ON new_owner.external_id = $12
WHERE seat.external_id = $13 AND seat.pool_id = $2`, planID, poolID, input.FromEpoch, input.ToEpoch,
			owner.assignment, changing, freezeID, freeze.FreezeOperationID, owner.apiKeyVersion,
			freeze.FreezeSnapshotHash[:], owner.owner, member.MemberExternalID, owner.seat); err != nil {
			return nil, false, translateRecoveryError("insert recovery plan Seat", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO membership_epoch_members (
epoch_id, member_id, member_role, signing_public_key, share_index, source_seat_id, migration_state,
signing_algorithm, signing_key_id, signing_key_fingerprint, signing_proof_algorithm, signing_proof,
recovery_key_algorithm, recovery_key_id, recovery_encryption_public_key, recovery_key_fingerprint,
recovery_key_proof_algorithm, recovery_key_proof, created_at
) SELECT epoch.id, member.id, $1, $2, $3, seat.id, 'CURRENT', $4, $5, $6, $7, $8,
$9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP
FROM membership_epochs epoch JOIN pools pool ON pool.id = epoch.pool_id
JOIN seats seat ON seat.pool_id = pool.id AND seat.external_id = $15
JOIN members member ON member.external_id = $16 AND member.status = 'ACTIVE'
WHERE epoch.recovery_plan_id = $17 AND epoch.epoch = $18`, member.Role, member.SigningPublicKey,
			member.ShareIndex, member.SigningAlgorithm, member.SigningKeyID, member.SigningKeyFingerprint[:],
			member.SigningProofAlgorithm, member.SigningProof, member.RecoveryKeyAlgorithm, member.RecoveryKeyID,
			member.RecoveryEncryptionPublicKey, member.RecoveryKeyFingerprint[:], member.RecoveryKeyProofAlgorithm,
			member.RecoveryKeyProof, owner.seat, member.MemberExternalID, planID, input.ToEpoch); err != nil {
			return nil, false, translateRecoveryError("insert to-Epoch member", err)
		}
	}
	if len(replacements) != countChangedOwners(owners, replacements) {
		return nil, false, recovery.ErrInvalidData
	}
	for _, accountIntent := range input.Accounts {
		controlDigest, decodeErr := decodeRecoveryHash(accountIntent.ProviderAttestationDigest)
		if decodeErr != nil {
			return nil, false, recovery.ErrInvalidData
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_resource_accounts (
plan_id, resource_account_id, pool_id, account_external_id, provider, provider_account_ref,
inventory_version, provider_key_ref, attestation_digest, provider_binding, control_evidence_external_id,
control_attestation_digest, control_attestation_issuer, control_attestation_key_id,
control_attestation_version, control_attestation_algorithm, control_attestation_signature,
control_attestation_protocol_version, created_at
)
SELECT $1, account.id, account.pool_id, account.external_id, account.provider, account.provider_account_ref,
account.inventory_version, account.provider_key_ref, account.attestation_digest, $2, $3, $4, $5, $6, $7, $8, $9, $10,
CURRENT_TIMESTAMP FROM pool_resource_accounts account
WHERE account.pool_id = $11 AND account.status = 'ACTIVE' AND account.external_id = $12
  AND account.provider_account_ref = $13`, planID, accountIntent.ProviderBinding,
			accountIntent.ControlEvidenceID, controlDigest[:], accountIntent.ProviderAttestationIssuer,
			accountIntent.ProviderAttestationKeyID, accountIntent.ProviderAttestationVersion,
			accountIntent.ProviderAttestationAlgorithm, accountIntent.ProviderAttestationSignature,
			accountIntent.ProviderAttestationProtocolVersion, poolID, accountIntent.AccountID, accountIntent.AccountRef)
		if err != nil {
			return nil, false, translateRecoveryError("snapshot recovery plan account", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrBindingMismatch
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_account_seats (
plan_id, resource_account_id, seat_id, inventory_version, created_at
)
SELECT $1, mapping.resource_account_id, mapping.seat_id, mapping.inventory_version, CURRENT_TIMESTAMP
FROM pool_resource_account_seats mapping JOIN pool_resource_accounts account ON account.id = mapping.resource_account_id
WHERE account.pool_id = $2 AND account.status = 'ACTIVE' AND mapping.status = 'ACTIVE'`, planID, poolID); err != nil {
		return nil, false, translateRecoveryError("snapshot recovery account Seat mappings", err)
	}
	plan, err := loadRecoveryPlanTx(ctx, tx, input.PlanExternalID, false)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit recovery epoch plan: %w", err)
	}
	return &recovery.EpochPlanTarget{Operation: toRecoveryOperation(op), Plan: plan}, true, nil
}

// AcquireEpochPlanLease 使用数据库时钟续租。活跃同 owner 心跳保持 fence，只有过期接管才递增 fence。
func (s *Store) AcquireEpochPlanLease(ctx context.Context, input recovery.AcquireEpochPlanLeaseInput) (*recovery.StoredOperation, error) {
	if !validRecoveryID(input.Key.ClientID) || !validRecoveryID(input.Key.OperationID) ||
		!validRecoveryID(input.LeaseOwner) || input.ExpectedFencingToken <= 0 ||
		input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `UPDATE integration_operations operation SET
lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
fencing_token = CASE WHEN operation.lease_owner = $3 AND operation.fencing_token = $5
                          AND operation.lease_expires_at > CURRENT_TIMESTAMP
                     THEN operation.fencing_token ELSE operation.fencing_token + 1 END,
attempt_count = CASE WHEN operation.lease_owner = $3 AND operation.fencing_token = $5
                          AND operation.lease_expires_at > CURRENT_TIMESTAMP
                     THEN operation.attempt_count ELSE operation.attempt_count + 1 END,
version = operation.version + 1, updated_at = CURRENT_TIMESTAMP
FROM (
  SELECT integration_operation_id, status AS plan_status
  FROM recovery_epoch_plans
) plan
WHERE plan.integration_operation_id = operation.id
  AND operation.integration_client_id = $1 AND operation.operation_id = $2
  AND operation.operation_type IN ('BOOTSTRAP_RECOVERY_EPOCH', 'ROTATE_RECOVERY_EPOCH')
  AND operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND plan.plan_status NOT IN ('FINALIZED', 'FAILED')
  AND operation.fencing_token = $5
  AND ((operation.lease_owner = $3 AND operation.fencing_token = $5
        AND operation.lease_expires_at > CURRENT_TIMESTAMP) OR
       operation.lease_expires_at IS NULL OR operation.lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.LeaseDuration.Seconds(), input.ExpectedFencingToken))
	if err == nil {
		return toRecoveryOperation(op), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("acquire recovery plan lease: %w", err)
	}
	var operationStatus, planStatus, currentOwner string
	var currentFence int64
	var leaseActive bool
	probeErr := s.db.QueryRowContext(ctx, `SELECT operation.status, plan.status,
COALESCE(operation.lease_owner, ''), operation.fencing_token,
COALESCE(operation.lease_expires_at > CURRENT_TIMESTAMP, false)
FROM integration_operations operation
JOIN recovery_epoch_plans plan ON plan.integration_operation_id = operation.id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2`,
		input.Key.ClientID, input.Key.OperationID).
		Scan(&operationStatus, &planStatus, &currentOwner, &currentFence, &leaseActive)
	if errors.Is(probeErr, sql.ErrNoRows) {
		return nil, recovery.ErrNotFound
	}
	if probeErr != nil {
		return nil, fmt.Errorf("inspect recovery plan lease conflict: %w", probeErr)
	}
	if planStatus == "FINALIZED" || planStatus == "FAILED" ||
		(operationStatus != "RUNNING" && operationStatus != "RETRYABLE" && operationStatus != "RECONCILE_REQUIRED") {
		return nil, recovery.ErrInvalidState
	}
	if currentFence != input.ExpectedFencingToken {
		return nil, recovery.ErrStaleFence
	}
	return nil, recovery.ErrLeaseHeld
}

func (s *Store) CommitRootArtifact(ctx context.Context, input recovery.RootArtifactInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validRecoveryID(input.ExternalID) || !validRecoveryID(input.Provider) ||
		!validRecoveryID(input.ProviderKeyRef) || !validRecoveryID(input.RootHandle) ||
		!validRecoveryID(input.RootKeyVersion) || !validRecoveryID(input.EpochRecoveryAlgorithm) ||
		!validRecoveryID(input.EpochRecoveryKeyID) || !validRecoveryID(input.WrapDomain) ||
		!validRecoveryID(input.WrapAlgorithm) || !validRecoveryID(input.VSSAlgorithm) ||
		!validRecoveryID(input.ProviderAttestationRef) || !validRecoveryID(input.AttestationKeyID) ||
		!validRecoveryID(input.PortableAttestationAlgorithm) || !validRecoveryID(input.PortableAttestationIssuer) ||
		input.PortableAttestationIssuer != input.Provider || !validRecoveryID(input.PortableAttestationKeyID) ||
		!validRecoveryID(input.PortableAttestationProtocolVersion) || len(input.PortableAttestationSignature) == 0 ||
		len(input.VSSCommitment) == 0 || len(input.VSSProof) == 0 || len(input.PrivateKeyCommitment) == 0 ||
		len(input.AttestationSignature) == 0 || sha256.Sum256(input.VSSCommitment) != input.VSSCommitmentHash ||
		sha256.Sum256(input.VSSProof) != input.VSSProofHash ||
		sha256.Sum256(input.PrivateKeyCommitment) != input.PrivateKeyCommitmentHash ||
		zeroRecoveryHash(input.RootCommitmentHash) || zeroRecoveryHash(input.AttestationDigest) ||
		zeroRecoveryHash(input.EpochRecoveryKeyFingerprint) || zeroRecoveryHash(input.RecoveryPackageHash) ||
		zeroRecoveryHash(input.RequestIntentHash) {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "PLANNED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_root_artifacts (
external_id, plan_id, provider, provider_key_ref, root_handle, root_key_version,
epoch_recovery_algorithm, epoch_recovery_key_id, epoch_recovery_key_fingerprint,
wrap_domain, wrap_algorithm, vss_algorithm, vss_commitment, vss_commitment_hash,
vss_proof, vss_proof_hash, private_key_commitment, private_key_commitment_hash,
root_commitment_hash, recovery_package_hash, request_intent_hash,
provider_attestation_ref, attestation_digest, attestation_signature,
attestation_key_id, attestation_algorithm, attestation_issuer, portable_attestation_key_id,
attestation_protocol_version, portable_attestation_signature, migration_state, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
'CURRENT', CURRENT_TIMESTAMP)`, input.ExternalID,
		plan.ID, input.Provider, input.ProviderKeyRef, input.RootHandle, input.RootKeyVersion,
		input.EpochRecoveryAlgorithm, input.EpochRecoveryKeyID, input.EpochRecoveryKeyFingerprint[:],
		input.WrapDomain, input.WrapAlgorithm, input.VSSAlgorithm, input.VSSCommitment,
		input.VSSCommitmentHash[:], input.VSSProof, input.VSSProofHash[:], input.PrivateKeyCommitment,
		input.PrivateKeyCommitmentHash[:], input.RootCommitmentHash[:], input.RecoveryPackageHash[:],
		input.RequestIntentHash[:], input.ProviderAttestationRef, input.AttestationDigest[:],
		input.AttestationSignature, input.AttestationKeyID, input.PortableAttestationAlgorithm,
		input.PortableAttestationIssuer, input.PortableAttestationKeyID,
		input.PortableAttestationProtocolVersion, input.PortableAttestationSignature); err != nil {
		return nil, translateRecoveryError("insert Recovery Root artifact", err)
	}
	if result, err := tx.ExecContext(ctx, `UPDATE membership_epochs SET
epoch_recovery_algorithm = $2, epoch_recovery_key_id = $3, epoch_recovery_key_fingerprint = $4
WHERE recovery_plan_id = $1 AND status = 'PREPARING' AND recovery_governance_state = 'CURRENT'`,
		plan.ID, input.EpochRecoveryAlgorithm, input.EpochRecoveryKeyID,
		input.EpochRecoveryKeyFingerprint[:]); err != nil {
		return nil, translateRecoveryError("bind Root to preparing Epoch", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrInvalidState
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "PLANNED", "ROOT_COMMITTED"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit Recovery Root artifact")
}

func (s *Store) CommitShareDeliveries(ctx context.Context, key recovery.OperationKey, leaseOwner string,
	fencingToken int64, deliveries []recovery.ShareDeliveryInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(key, leaseOwner, fencingToken) || len(deliveries) == 0 {
		return nil, recovery.ErrInvalidData
	}
	if err := validateShareDeliveries(deliveries); err != nil {
		return nil, err
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, key, leaseOwner, fencingToken, "ROOT_COMMITTED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if len(deliveries) != plan.ExpectedMemberCount {
		return nil, recovery.ErrInvalidData
	}
	for _, delivery := range deliveries {
		result, err := tx.ExecContext(ctx, `INSERT INTO recovery_share_deliveries (
external_id, recovery_plan_id, root_artifact_id, epoch_id, member_id, encrypted_share, share_hash,
delivery_status, delivered_at, created_at, migration_state, share_index, encryption_algorithm,
recipient_key_id, recipient_key_fingerprint, provider_share_commitment, provider_proof_digest,
provider_proof_signature, provider_proof_algorithm, provider_proof_key_id,
provider_proof_protocol_version, portable_provider_proof_signature
)
SELECT $1, plan.id, root.id, epoch.id, member.id, $2, $3, 'DELIVERED', CURRENT_TIMESTAMP,
CURRENT_TIMESTAMP, 'CURRENT', $4::smallint, $5::text, $6::text, $7::bytea, $8::bytea,
$9::bytea, $10::bytea, $11::text, $12::text, $13::text, $14::bytea
FROM recovery_epoch_plans plan
JOIN recovery_root_artifacts root ON root.plan_id = plan.id AND root.migration_state = 'CURRENT'
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN members member ON member.external_id = $15::text
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = epoch.id AND snapshot.member_id = member.id
 AND snapshot.migration_state = 'CURRENT'
WHERE plan.id = $16::uuid AND snapshot.share_index = $4::smallint AND snapshot.recovery_key_id = $6::text
  AND snapshot.recovery_key_fingerprint = $7::bytea`, delivery.ExternalID, delivery.Ciphertext,
			delivery.CiphertextHash[:], delivery.ShareIndex, delivery.EncryptionAlgorithm, delivery.RecipientKeyID,
			delivery.RecipientKeyFingerprint[:], delivery.ProviderShareCommitment, delivery.ProviderProofDigest[:],
			delivery.ProviderProofSignature, delivery.PortableProofAlgorithm, delivery.PortableProofKeyID,
			delivery.PortableProofProtocolVersion, delivery.PortableProofSignature,
			delivery.MemberExternalID, plan.ID)
		if err != nil {
			return nil, translateRecoveryError("insert encrypted Recovery Share", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "ROOT_COMMITTED", "SHARES_COMMITTED"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit encrypted Recovery Shares")
}

func (s *Store) CommitManifestDraft(ctx context.Context, input recovery.ManifestDraftInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validRecoveryID(input.ExternalID) || !validRecoveryID(input.ProtocolVersion) ||
		!validRecoveryID(input.PlatformKeyRef) || !validRecoveryID(input.PlatformAlgorithm) ||
		(input.PlatformSignatureDomain != "" && input.PlatformSignatureDomain != recovery.PlatformManifestSignatureV2) ||
		len(input.CanonicalPayload) == 0 || sha256.Sum256(input.CanonicalPayload) != input.ManifestHash ||
		zeroRecoveryHash(input.BatchSetHash) || zeroRecoveryHash(input.RecoveryPackageHash) ||
		zeroRecoveryHash(input.ProviderAttestationDigest) || len(input.PlatformSignature) == 0 ||
		input.PlatformVerifiedAt.IsZero() || len(input.BatchBindings) == 0 {
		return nil, recovery.ErrInvalidData
	}
	var manifestPayload recovery.ManifestPayload
	if err := json.Unmarshal(input.CanonicalPayload, &manifestPayload); err != nil ||
		recovery.ValidateManifestPayload(manifestPayload) != nil {
		return nil, recovery.ErrInvalidData
	}
	if manifestPayload.ProtocolVersion != input.ProtocolVersion {
		return nil, recovery.ErrBindingMismatch
	}
	typedJSON, err := json.Marshal(manifestPayload)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	typedCanonical, typedErr := canonicalJSONObject(typedJSON)
	inputCanonical, inputErr := canonicalJSONObject(input.CanonicalPayload)
	if typedErr != nil || inputErr != nil || !bytes.Equal(typedCanonical, inputCanonical) {
		return nil, recovery.ErrBindingMismatch
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "SHARES_COMMITTED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if plan.PortableProfile == nil {
		if input.PlatformSignatureDomain != "" {
			return nil, recovery.ErrBindingMismatch
		}
	} else if input.PlatformSignatureDomain != plan.PortableProfile.PlatformSignatureDomain ||
		input.PlatformAlgorithm != recovery.PortableSignatureAlgorithm || len(input.PlatformSignature) != 64 {
		return nil, recovery.ErrBindingMismatch
	}
	if err := validateManifestBatchBindings(input.BatchBindings, plan.ExpectedResourceCount); err != nil {
		return nil, err
	}
	if manifestPayload.OperationID != input.Key.OperationID {
		return nil, recovery.ErrBindingMismatch
	}
	recomputedBatchSetHash, err := recoveryBatchSetHash(input.BatchBindings)
	if err != nil || recomputedBatchSetHash != input.BatchSetHash {
		return nil, recovery.ErrBindingMismatch
	}
	if err := validateManifestProjection(ctx, tx, plan, manifestPayload, input.BatchBindings); err != nil {
		return nil, err
	}
	var manifestID, epochID string
	poolExternalID := plan.PoolExternalID
	err = tx.QueryRowContext(ctx, `INSERT INTO manifests (
external_id, epoch_id, protocol_version, canonical_payload, canonical_bytes, manifest_hash,
platform_signature, status, recovery_plan_id, root_artifact_id, migration_state,
previous_manifest_hash, batch_set_hash, recovery_package_hash, provider_attestation_digest,
platform_algorithm, platform_key_ref, platform_verified_at, platform_signature_domain, created_at
)
SELECT $1, epoch.id, $2, $3::jsonb, $4, $5, $6, 'DRAFT', plan.id, root.id, 'CURRENT',
plan.previous_manifest_hash, $7, $8, $9, $10, $11, $12, NULLIF($13::text, ''), CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN recovery_root_artifacts root ON root.plan_id = plan.id AND root.migration_state = 'CURRENT'
WHERE plan.id = $14 AND root.recovery_package_hash = $8 AND root.attestation_digest = $9
RETURNING id, epoch_id`, input.ExternalID, input.ProtocolVersion,
		input.CanonicalPayload, input.CanonicalPayload, input.ManifestHash[:], input.PlatformSignature,
		input.BatchSetHash[:], input.RecoveryPackageHash[:], input.ProviderAttestationDigest[:],
		input.PlatformAlgorithm, input.PlatformKeyRef, input.PlatformVerifiedAt,
		input.PlatformSignatureDomain, plan.ID).
		Scan(&manifestID, &epochID)
	if err != nil {
		return nil, translateRecoveryError("insert canonical Manifest", err)
	}
	for _, binding := range input.BatchBindings {
		result, err := tx.ExecContext(ctx, `INSERT INTO manifest_batch_intents (
manifest_id, plan_id, resource_account_id, epoch_role, batch_external_id, account_ref,
batch_type, batch_version, ciphertext_hash, recovery_wrap_hash, created_at
)
SELECT $1, plan.id, account.resource_account_id, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan JOIN recovery_plan_resource_accounts account ON account.plan_id = plan.id
WHERE plan.id = $9 AND account.account_external_id = $10 AND account.provider_account_ref = $4`,
			manifestID, binding.EpochRole, binding.BatchExternalID, binding.AccountRef, binding.BatchType,
			binding.BatchVersion, binding.CiphertextHash[:], nullableRecoveryWrapHash(binding), plan.ID,
			binding.ResourceAccountExternalID)
		if err != nil {
			return nil, translateRecoveryError("insert Manifest batch intent", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
	}
	memberRows, err := tx.QueryContext(ctx, `SELECT member.id, member.external_id
FROM membership_epoch_members snapshot JOIN members member ON member.id = snapshot.member_id
WHERE snapshot.epoch_id = $1 AND snapshot.migration_state = 'CURRENT' ORDER BY member.external_id`, epochID)
	if err != nil {
		return nil, fmt.Errorf("load Manifest approval members: %w", err)
	}
	type approvalMember struct{ id, externalID string }
	approvalMembers := make([]approvalMember, 0, plan.ExpectedMemberCount)
	for memberRows.Next() {
		var member approvalMember
		if err := memberRows.Scan(&member.id, &member.externalID); err != nil {
			memberRows.Close()
			return nil, fmt.Errorf("scan Manifest approval member: %w", err)
		}
		approvalMembers = append(approvalMembers, member)
	}
	if err := memberRows.Err(); err != nil {
		memberRows.Close()
		return nil, fmt.Errorf("iterate Manifest approval members: %w", err)
	}
	if err := memberRows.Close(); err != nil {
		return nil, fmt.Errorf("close Manifest approval members: %w", err)
	}
	for _, member := range approvalMembers {
		message, err := recovery.BuildMemberManifestSignatureMessage(recovery.MemberManifestApproval{
			Version: 1, CeremonyType: plan.CeremonyType, OperationID: input.Key.OperationID, PoolID: poolExternalID, Epoch: plan.ToEpoch,
			MemberID: member.externalID, ManifestHash: input.ManifestHash,
		})
		if err != nil {
			return nil, recovery.ErrInvalidData
		}
		messageHash := sha256.Sum256(message)
		if _, err := tx.ExecContext(ctx, `INSERT INTO manifest_member_approval_intents
(manifest_id, epoch_id, member_id, expected_message_hash, created_at)
VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`, manifestID, epochID, member.id, messageHash[:]); err != nil {
			return nil, translateRecoveryError("insert member approval intent", err)
		}
	}
	var rootHash, vssHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT root.root_commitment_hash, root.vss_commitment_hash
FROM recovery_root_artifacts root WHERE root.plan_id = $1`, plan.ID).Scan(&rootHash, &vssHash); err != nil {
		return nil, translateRecoveryError("load Share acknowledgement root", err)
	}
	deliveryRows, err := tx.QueryContext(ctx, `SELECT delivery.id, delivery.external_id, member.external_id,
delivery.share_index, delivery.share_hash
FROM recovery_share_deliveries delivery JOIN members member ON member.id = delivery.member_id
WHERE delivery.recovery_plan_id = $1 AND delivery.migration_state = 'CURRENT'`, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("load Share acknowledgement intents: %w", err)
	}
	type acknowledgementDelivery struct {
		id, externalID, memberExternalID string
		shareIndex                       uint16
		ciphertextHash                   []byte
	}
	acknowledgementDeliveries := make([]acknowledgementDelivery, 0, plan.ExpectedMemberCount)
	for deliveryRows.Next() {
		var delivery acknowledgementDelivery
		if err := deliveryRows.Scan(&delivery.id, &delivery.externalID, &delivery.memberExternalID,
			&delivery.shareIndex, &delivery.ciphertextHash); err != nil {
			deliveryRows.Close()
			return nil, fmt.Errorf("scan Share acknowledgement intent: %w", err)
		}
		acknowledgementDeliveries = append(acknowledgementDeliveries, delivery)
	}
	if err := deliveryRows.Err(); err != nil {
		deliveryRows.Close()
		return nil, fmt.Errorf("iterate Share acknowledgement intents: %w", err)
	}
	if err := deliveryRows.Close(); err != nil {
		return nil, fmt.Errorf("close Share acknowledgement intents: %w", err)
	}
	for _, delivery := range acknowledgementDeliveries {
		ack := recovery.ShareAcknowledgement{Version: 1, CeremonyType: plan.CeremonyType, OperationID: input.Key.OperationID,
			DeliveryID: delivery.externalID, PoolID: poolExternalID, Epoch: plan.ToEpoch,
			MemberID: delivery.memberExternalID, ShareIndex: delivery.shareIndex, VerifiedCommitment: true}
		copy(ack.CiphertextHash[:], delivery.ciphertextHash)
		ack.ManifestHash = input.ManifestHash
		copy(ack.RootCommitmentHash[:], rootHash)
		copy(ack.VSSCommitmentHash[:], vssHash)
		message, err := recovery.BuildShareAcknowledgementMessage(ack)
		if err != nil {
			return nil, recovery.ErrInvalidData
		}
		messageHash := sha256.Sum256(message)
		if _, err := tx.ExecContext(ctx, `INSERT INTO share_acknowledgement_intents
(delivery_id, manifest_id, expected_message_hash, created_at)
VALUES ($1, $2, $3, CURRENT_TIMESTAMP)`, delivery.id, manifestID, messageHash[:]); err != nil {
			return nil, translateRecoveryError("insert Share acknowledgement intent", err)
		}
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "SHARES_COMMITTED", "MANIFEST_DRAFT"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit canonical Manifest draft")
}

func (s *Store) CommitManifest(ctx context.Context, input recovery.CommitManifestInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) || len(input.Signatures) == 0 {
		return nil, recovery.ErrInvalidData
	}
	seen := make(map[string]struct{}, len(input.Signatures))
	for _, signature := range input.Signatures {
		if !validRecoveryID(signature.MemberExternalID) || !validRecoveryID(signature.Algorithm) ||
			!validRecoveryID(signature.KeyID) || zeroRecoveryHash(signature.MessageHash) ||
			len(signature.Signature) == 0 || signature.VerifiedAt.IsZero() {
			return nil, recovery.ErrInvalidData
		}
		if _, duplicate := seen[signature.MemberExternalID]; duplicate {
			return nil, recovery.ErrInvalidData
		}
		seen[signature.MemberExternalID] = struct{}{}
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "MANIFEST_DRAFT")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, signature := range input.Signatures {
		result, err := tx.ExecContext(ctx, `INSERT INTO manifest_signatures (
manifest_id, epoch_id, member_id, signature, signed_at, migration_state, signing_algorithm,
signing_key_id, signing_key_fingerprint, signed_message_hash, verified_at
)
SELECT manifest.id, manifest.epoch_id, member.id, $1, CURRENT_TIMESTAMP, 'CURRENT', $2, $3,
snapshot.signing_key_fingerprint, $4, $5
FROM manifests manifest
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = manifest.epoch_id AND snapshot.migration_state = 'CURRENT'
JOIN members member ON member.id = snapshot.member_id AND member.external_id = $6
WHERE manifest.recovery_plan_id = $7 AND manifest.migration_state = 'CURRENT'
  AND snapshot.signing_algorithm = $2 AND snapshot.signing_key_id = $3
  AND EXISTS (SELECT 1 FROM manifest_member_approval_intents intent
              WHERE intent.manifest_id = manifest.id AND intent.member_id = member.id
                AND intent.expected_message_hash = $4)`, signature.Signature, signature.Algorithm,
			signature.KeyID, signature.MessageHash[:], signature.VerifiedAt, signature.MemberExternalID, plan.ID)
		if err != nil {
			return nil, translateRecoveryError("insert verified member Manifest signature", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM manifest_signatures signature
JOIN manifests manifest ON manifest.id = signature.manifest_id
WHERE manifest.recovery_plan_id = $1 AND signature.migration_state = 'CURRENT'`, plan.ID).Scan(&count); err != nil {
		return nil, fmt.Errorf("count verified Manifest signatures: %w", err)
	}
	if count < int(plan.GovernanceThreshold) {
		return nil, recovery.ErrInvalidState
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "MANIFEST_DRAFT", "MANIFEST_SIGNED"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit member Manifest signatures")
}

func (s *Store) CommitShareAcknowledgements(ctx context.Context, input recovery.CommitShareAcknowledgementsInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) || len(input.Acknowledgements) == 0 {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "MANIFEST_SIGNED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if len(input.Acknowledgements) != plan.ExpectedMemberCount {
		return nil, recovery.ErrInvalidData
	}
	seen := make(map[string]struct{}, len(input.Acknowledgements))
	for _, ack := range input.Acknowledgements {
		if !ack.VerifiedCommitment || !validRecoveryID(ack.DeliveryExternalID) ||
			!validRecoveryID(ack.MemberExternalID) || !validRecoveryID(ack.Algorithm) ||
			!validRecoveryID(ack.KeyID) || zeroRecoveryHash(ack.ManifestHash) ||
			zeroRecoveryHash(ack.RootCommitmentHash) || zeroRecoveryHash(ack.VSSCommitmentHash) ||
			zeroRecoveryHash(ack.MessageHash) || len(ack.Signature) == 0 || ack.VerifiedAt.IsZero() {
			return nil, recovery.ErrInvalidData
		}
		if _, duplicate := seen[ack.DeliveryExternalID]; duplicate {
			return nil, recovery.ErrInvalidData
		}
		seen[ack.DeliveryExternalID] = struct{}{}
		result, err := tx.ExecContext(ctx, `UPDATE recovery_share_deliveries delivery SET
delivery_status = 'ACKNOWLEDGED', acknowledged_manifest_hash = $1,
acknowledgement_algorithm = $2, acknowledgement_key_id = $3,
acknowledgement_message_hash = $4, acknowledgement_signature = $5,
acknowledgement_verified_at = $6, acknowledged_at = CURRENT_TIMESTAMP
FROM members member, recovery_root_artifacts root, manifests manifest,
     share_acknowledgement_intents intent, membership_epoch_members snapshot
WHERE delivery.external_id = $7 AND delivery.recovery_plan_id = $8 AND delivery.delivery_status = 'DELIVERED'
  AND member.id = delivery.member_id AND member.external_id = $9
  AND root.id = delivery.root_artifact_id AND root.plan_id = delivery.recovery_plan_id
  AND root.root_commitment_hash = $10 AND root.vss_commitment_hash = $11
  AND manifest.recovery_plan_id = delivery.recovery_plan_id AND manifest.manifest_hash = $1
  AND intent.delivery_id = delivery.id AND intent.manifest_id = manifest.id AND intent.expected_message_hash = $4
  AND snapshot.epoch_id = delivery.epoch_id AND snapshot.member_id = delivery.member_id
  AND snapshot.signing_algorithm = $2 AND snapshot.signing_key_id = $3 AND snapshot.migration_state = 'CURRENT'`,
			ack.ManifestHash[:], ack.Algorithm, ack.KeyID, ack.MessageHash[:], ack.Signature, ack.VerifiedAt,
			ack.DeliveryExternalID, plan.ID, ack.MemberExternalID, ack.RootCommitmentHash[:],
			ack.VSSCommitmentHash[:])
		if err != nil {
			return nil, translateRecoveryError("commit Share acknowledgement", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "MANIFEST_SIGNED", "ACKNOWLEDGED"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit Share acknowledgements")
}

func (s *Store) CommitStagedBatches(ctx context.Context, input recovery.CommitStagedBatchesInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		zeroRecoveryHash(input.BatchSetHash) || len(input.Batches) == 0 {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "ACKNOWLEDGED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if len(input.Batches) != plan.ExpectedResourceCount*4 {
		return nil, recovery.ErrInvalidData
	}
	var root stagedRootBinding
	var rootFingerprint []byte
	if err := tx.QueryRowContext(ctx, `SELECT id, epoch_recovery_key_id, root_key_version,
wrap_domain, wrap_algorithm, epoch_recovery_key_fingerprint
FROM recovery_root_artifacts WHERE plan_id = $1 AND migration_state = 'CURRENT' FOR SHARE`, plan.ID).
		Scan(&root.ID, &root.Handle, &root.Version, &root.Domain, &root.Algorithm, &rootFingerprint); err != nil {
		return nil, translateRecoveryError("load staged batch Root binding", err)
	}
	copy(root.Fingerprint[:], rootFingerprint)
	seen := make(map[string]struct{}, len(input.Batches))
	for _, batch := range input.Batches {
		if err := validateStagedBatch(input.Key.OperationID, plan, root, batch); err != nil {
			return nil, err
		}
		key := batch.ResourceAccountExternalID + "\x00" + string(batch.Type)
		if _, duplicate := seen[key]; duplicate {
			return nil, recovery.ErrInvalidData
		}
		seen[key] = struct{}{}
		ciphertextHash := sha256.Sum256(batch.Ciphertext)
		result, err := tx.ExecContext(ctx, `INSERT INTO credential_batches (
external_id, pool_id, membership_epoch, resource_account_ref, resource_account_id,
batch_type, batch_version, status, migration_state, seal_integration_operation_id,
aad_version, encryption_algorithm, ciphertext, nonce, aad_hash, content_hash,
encrypted_dek_kms, encrypted_dek_recovery, kms_wrap_algorithm, kms_key_ref, kms_wrapper_domain,
recovery_wrap_algorithm, recovery_key_ref, recovery_wrapper_domain, recovery_binding_hash,
recovery_plan_id, recovery_root_artifact_id, recovery_key_fingerprint, recovery_key_version,
recovery_wrap_attestation_digest, recovery_wrap_attestation_signature,
sealed_at, version, created_at, updated_at
)
SELECT $1, plan.pool_id, plan.to_epoch, account.provider_account_ref, account.resource_account_id,
$2, $3, 'STAGED', 'CURRENT', NULL, 1, $4, $5, $6, $7, $8, $9, $10,
$11, $12, $13, $14, $15, $16, $17, plan.id, $18, $19, $20, $21, $22,
CURRENT_TIMESTAMP, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan JOIN recovery_plan_resource_accounts account ON account.plan_id = plan.id
WHERE plan.id = $23 AND account.account_external_id = $24 AND account.provider_account_ref = $25`,
			batch.ExternalID, batch.Type, batch.BatchVersion, batch.EncryptionAlgorithm, batch.Ciphertext,
			batch.Nonce, batch.AADHash[:], batch.ContentFingerprint[:], batch.WrappedDEKKMS,
			batch.WrappedDEKRecovery, batch.KMSWrapAlgorithm, batch.KMSKeyRef, batch.KMSWrapperDomain,
			batch.RecoveryWrapAlgorithm, batch.RecoveryKeyHandle, batch.RecoveryWrapDomain,
			batch.RecoveryBindingHash[:], root.ID, batch.RecoveryKeyFingerprint[:], batch.RecoveryKeyVersion,
			batch.ProviderWrapAttestationDigest[:], batch.ProviderWrapAttestationSignature,
			plan.ID, batch.ResourceAccountExternalID, batch.AccountRef)
		if err != nil {
			return nil, translateRecoveryError("insert plan-scoped STAGED batch", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
		result, err = tx.ExecContext(ctx, `INSERT INTO recovery_plan_batch_bindings (
plan_id, resource_account_id, epoch_role, batch_type, credential_batch_id, ciphertext_hash, recovery_wrap_hash, created_at
)
SELECT plan.id, account.resource_account_id, 'TO', batch.batch_type, batch.id, $1, $2, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan
JOIN recovery_plan_resource_accounts account ON account.plan_id = plan.id AND account.account_external_id = $3
JOIN credential_batches batch ON batch.recovery_plan_id = plan.id AND batch.external_id = $4
JOIN manifest_batch_intents intent ON intent.plan_id = plan.id AND intent.resource_account_id = account.resource_account_id
 AND intent.epoch_role = 'TO' AND intent.batch_type = batch.batch_type AND intent.batch_external_id = batch.external_id
 AND intent.batch_version = batch.batch_version
 AND intent.ciphertext_hash = $1 AND intent.recovery_wrap_hash = $2
WHERE plan.id = $5 AND batch.recovery_binding_hash = $2`, ciphertextHash[:], batch.RecoveryBindingHash[:],
			batch.ResourceAccountExternalID, batch.ExternalID, plan.ID)
		if err != nil {
			return nil, translateRecoveryError("bind STAGED batch to plan", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrBindingMismatch
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_plan_batch_bindings (
plan_id, resource_account_id, epoch_role, batch_type, credential_batch_id, ciphertext_hash, recovery_wrap_hash, created_at
)
SELECT intent.plan_id, intent.resource_account_id, 'FROM', intent.batch_type, batch.id,
intent.ciphertext_hash, NULL, CURRENT_TIMESTAMP
FROM manifest_batch_intents intent
JOIN recovery_epoch_plans plan ON plan.id = intent.plan_id
JOIN recovery_plan_resource_accounts account ON account.plan_id = intent.plan_id
 AND account.resource_account_id = intent.resource_account_id
JOIN credential_batches batch ON batch.external_id = intent.batch_external_id
WHERE intent.plan_id = $1 AND intent.epoch_role = 'FROM' AND batch.membership_epoch = $2
	AND batch.status = 'ACTIVE' AND batch.batch_version = intent.batch_version
	AND batch.resource_account_ref = account.provider_account_ref
	AND digest(batch.ciphertext, 'sha256') = intent.ciphertext_hash
	AND ((plan.ceremony_type = 'ROTATE' AND batch.migration_state = 'CURRENT'
	      AND batch.resource_account_id = intent.resource_account_id) OR
	     (plan.ceremony_type = 'BOOTSTRAP' AND batch.migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE')))`,
		plan.ID, plan.FromEpoch); err != nil {
		return nil, translateRecoveryError("bind from-Epoch batches to plan", err)
	}
	var manifestBatchSetHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT batch_set_hash FROM manifests WHERE recovery_plan_id = $1
AND migration_state = 'CURRENT'`, plan.ID).Scan(&manifestBatchSetHash); err != nil {
		return nil, translateRecoveryError("load Manifest batch set hash", err)
	}
	if !bytes.Equal(manifestBatchSetHash, input.BatchSetHash[:]) {
		return nil, recovery.ErrBindingMismatch
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "ACKNOWLEDGED", "BATCHES_STAGED"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "commit plan-scoped STAGED batches")
}

func (s *Store) MarkEpochPlanReady(ctx context.Context, input recovery.MarkEpochPlanReadyInput) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, err := s.lockRecoveryPlan(ctx, input.Key, input.LeaseOwner, input.FencingToken, "BATCHES_STAGED")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var evidenceCount, completeEvidenceCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE batch_count = 8) FROM (
SELECT evidence.id, count(reference.*) AS batch_count
FROM recovery_control_evidence evidence
LEFT JOIN recovery_control_evidence_batches reference ON reference.evidence_id = evidence.id
WHERE evidence.plan_id = $1 AND evidence.status = 'VERIFIED'
GROUP BY evidence.id
) complete`, plan.ID).Scan(&evidenceCount, &completeEvidenceCount); err != nil {
		return nil, fmt.Errorf("count verified account evidence: %w", err)
	}
	if evidenceCount != plan.ExpectedResourceCount || completeEvidenceCount != plan.ExpectedResourceCount {
		return nil, recovery.ErrInvalidState
	}
	if err := advanceRecoveryPlan(ctx, tx, plan.ID, "BATCHES_STAGED", "READY"); err != nil {
		return nil, err
	}
	return commitAndLoadRecoveryPlan(ctx, tx, plan.ExternalID, "mark recovery ceremony ready")
}

func (s *Store) GetEpochPlan(ctx context.Context, externalID string) (*recovery.StoredEpochPlan, error) {
	if !validRecoveryID(externalID) {
		return nil, recovery.ErrInvalidData
	}
	plan, err := scanRecoveryPlan(s.db.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+
		`WHERE plan.external_id = $1`, externalID))
	if err != nil {
		return nil, translateRecoveryError("get recovery epoch plan", err)
	}
	return plan, nil
}

func (s *Store) GetEpochPlanProgress(ctx context.Context, externalID string) (*recovery.EpochPlanTarget, error) {
	if !validRecoveryID(externalID) {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("begin recovery plan progress: %w", err)
	}
	defer tx.Rollback()
	plan, err := loadRecoveryPlanTx(ctx, tx, externalID, false)
	if err != nil {
		return nil, err
	}
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations operation
JOIN recovery_epoch_plans plan ON plan.integration_operation_id = operation.id
WHERE plan.external_id = $1
  AND operation.operation_type IN ('BOOTSTRAP_RECOVERY_EPOCH', 'ROTATE_RECOVERY_EPOCH')
  AND operation.migration_state = 'CURRENT'`, externalID))
	if err != nil {
		return nil, translateRecoveryError("get recovery epoch plan operation", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery plan progress read: %w", err)
	}
	return &recovery.EpochPlanTarget{Operation: toRecoveryOperation(op), Plan: plan}, nil
}

func (s *Store) GetEpochSecuritySnapshot(ctx context.Context, externalID string) (*recovery.EpochSecuritySnapshot, error) {
	if !validRecoveryID(externalID) {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("begin recovery security snapshot: %w", err)
	}
	defer tx.Rollback()
	plan, err := loadRecoveryPlanTx(ctx, tx, externalID, false)
	if err != nil {
		return nil, err
	}
	result := &recovery.EpochSecuritySnapshot{Plan: plan}
	var root recovery.StoredRootArtifact
	var rootFingerprint, vssHash, vssProofHash, privateCommitmentHash, rootCommitmentHash []byte
	var packageHash, requestIntentHash, attestationDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT external_id, provider, provider_key_ref, root_handle, root_key_version,
epoch_recovery_algorithm, epoch_recovery_key_id, epoch_recovery_key_fingerprint,
wrap_domain, wrap_algorithm, vss_algorithm, vss_commitment_hash, vss_proof_hash,
private_key_commitment_hash, root_commitment_hash, recovery_package_hash, request_intent_hash,
provider_attestation_ref, attestation_digest, attestation_signature, attestation_key_id,
attestation_algorithm, attestation_issuer, portable_attestation_key_id,
attestation_protocol_version, portable_attestation_signature
FROM recovery_root_artifacts WHERE plan_id = $1 AND migration_state = 'CURRENT'`, plan.ID).
		Scan(&root.ExternalID, &root.Provider, &root.ProviderKeyRef, &root.RootHandle, &root.RootKeyVersion,
			&root.EpochRecoveryAlgorithm, &root.EpochRecoveryKeyID, &rootFingerprint,
			&root.WrapDomain, &root.WrapAlgorithm, &root.VSSAlgorithm, &vssHash, &vssProofHash,
			&privateCommitmentHash, &rootCommitmentHash, &packageHash, &requestIntentHash,
			&root.ProviderAttestationRef, &attestationDigest, &root.AttestationSignature, &root.AttestationKeyID,
			&root.PortableAttestationAlgorithm, &root.PortableAttestationIssuer, &root.PortableAttestationKeyID,
			&root.PortableAttestationProtocolVersion, &root.PortableAttestationSignature)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("load trusted Recovery Root snapshot: %w", err)
	}
	if err == nil {
		copy(root.EpochRecoveryKeyFingerprint[:], rootFingerprint)
		copy(root.VSSCommitmentHash[:], vssHash)
		copy(root.VSSProofHash[:], vssProofHash)
		copy(root.PrivateKeyCommitmentHash[:], privateCommitmentHash)
		copy(root.RootCommitmentHash[:], rootCommitmentHash)
		copy(root.RecoveryPackageHash[:], packageHash)
		copy(root.RequestIntentHash[:], requestIntentHash)
		copy(root.AttestationDigest[:], attestationDigest)
		result.Root = &root
		result.RootCommitmentHash, result.VSSCommitmentHash = root.RootCommitmentHash, root.VSSCommitmentHash
	}
	rows, err := tx.QueryContext(ctx, `SELECT seat.external_id, member.external_id, snapshot.member_role,
snapshot.share_index, snapshot.signing_algorithm, snapshot.signing_key_id, snapshot.signing_public_key,
snapshot.signing_key_fingerprint, snapshot.signing_proof_algorithm, snapshot.signing_proof,
snapshot.recovery_key_algorithm, snapshot.recovery_key_id, snapshot.recovery_encryption_public_key,
snapshot.recovery_key_fingerprint, snapshot.recovery_key_proof_algorithm, snapshot.recovery_key_proof
FROM recovery_epoch_plans plan
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = epoch.id AND snapshot.migration_state = 'CURRENT'
JOIN seats seat ON seat.id = snapshot.source_seat_id
JOIN members member ON member.id = snapshot.member_id
WHERE plan.id = $1 ORDER BY member.external_id`, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("load trusted Epoch member snapshot: %w", err)
	}
	for rows.Next() {
		var member recovery.EpochMember
		var signingFingerprint, recoveryFingerprint []byte
		if err := rows.Scan(&member.SeatExternalID, &member.MemberExternalID, &member.Role,
			&member.ShareIndex, &member.SigningAlgorithm, &member.SigningKeyID, &member.SigningPublicKey,
			&signingFingerprint, &member.SigningProofAlgorithm, &member.SigningProof,
			&member.RecoveryKeyAlgorithm, &member.RecoveryKeyID, &member.RecoveryEncryptionPublicKey,
			&recoveryFingerprint, &member.RecoveryKeyProofAlgorithm, &member.RecoveryKeyProof); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan trusted Epoch member snapshot: %w", err)
		}
		copy(member.SigningKeyFingerprint[:], signingFingerprint)
		copy(member.RecoveryKeyFingerprint[:], recoveryFingerprint)
		result.Members = append(result.Members, member)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close trusted Epoch members: %w", err)
	}
	rows, err = tx.QueryContext(ctx, `SELECT delivery.external_id, member.external_id, delivery.share_index,
delivery.encryption_algorithm, delivery.recipient_key_id, delivery.recipient_key_fingerprint,
delivery.share_hash, delivery.provider_share_commitment, delivery.provider_proof_digest,
delivery.provider_proof_signature, root.root_commitment_hash, root.vss_commitment_hash,
root.recovery_package_hash, root.request_intent_hash,
delivery.provider_proof_algorithm, delivery.provider_proof_key_id,
delivery.provider_proof_protocol_version, delivery.portable_provider_proof_signature,
(delivery.delivery_status = 'ACKNOWLEDGED')
FROM recovery_share_deliveries delivery JOIN members member ON member.id = delivery.member_id
JOIN recovery_root_artifacts root ON root.id = delivery.root_artifact_id
WHERE delivery.recovery_plan_id = $1 AND delivery.migration_state = 'CURRENT'
ORDER BY member.external_id`, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("load trusted Share delivery snapshot: %w", err)
	}
	for rows.Next() {
		var delivery recovery.StoredShareDelivery
		var recipientFingerprint, ciphertextHash, proofDigest, rootHash, deliveryVSSHash []byte
		var deliveryPackageHash, deliveryRequestHash []byte
		if err := rows.Scan(&delivery.ExternalID, &delivery.MemberExternalID, &delivery.ShareIndex,
			&delivery.EncryptionAlgorithm, &delivery.RecipientKeyID, &recipientFingerprint,
			&ciphertextHash, &delivery.ProviderShareCommitment, &proofDigest,
			&delivery.ProviderProofSignature, &rootHash, &deliveryVSSHash,
			&deliveryPackageHash, &deliveryRequestHash, &delivery.PortableProofAlgorithm,
			&delivery.PortableProofKeyID, &delivery.PortableProofProtocolVersion,
			&delivery.PortableProofSignature, &delivery.Acknowledged); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan trusted Share delivery snapshot: %w", err)
		}
		copy(delivery.RecipientKeyFingerprint[:], recipientFingerprint)
		copy(delivery.CiphertextHash[:], ciphertextHash)
		copy(delivery.ProviderProofDigest[:], proofDigest)
		copy(delivery.RootCommitmentHash[:], rootHash)
		copy(delivery.VSSCommitmentHash[:], deliveryVSSHash)
		copy(delivery.RecoveryPackageHash[:], deliveryPackageHash)
		copy(delivery.RequestIntentHash[:], deliveryRequestHash)
		result.Deliveries = append(result.Deliveries, delivery)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close trusted Share deliveries: %w", err)
	}
	var manifestHash []byte
	err = tx.QueryRowContext(ctx, `SELECT canonical_bytes, manifest_hash, platform_signature_domain,
platform_algorithm, platform_key_ref, platform_signature, platform_verified_at FROM manifests
WHERE recovery_plan_id = $1 AND migration_state = 'CURRENT'`, plan.ID).
		Scan(&result.ManifestCanonical, &manifestHash, &result.ManifestPlatformDomain, &result.ManifestPlatformAlgorithm,
			&result.ManifestPlatformKeyRef, &result.ManifestPlatformSignature, &result.ManifestPlatformVerifiedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("load trusted Manifest snapshot: %w", err)
	}
	copy(result.ManifestHash[:], manifestHash)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery security snapshot: %w", err)
	}
	return result, nil
}

func (s *Store) IssueControlEvidence(ctx context.Context, input recovery.IssueControlEvidenceInput) error {
	canonical, err := canonicalControlEvidence(input)
	if err != nil || !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validRecoveryID(input.EvidenceExternalID) || !validRecoveryID(input.PlanExternalID) ||
		!validRecoveryID(input.ResourceExternalID) || !validRecoveryID(input.ProviderAttestationRef) ||
		!validRecoveryID(input.ProviderAttestationIssuer) || !validRecoveryID(input.ProviderAttestationKeyID) ||
		input.ProviderAttestationVersion == 0 || zeroRecoveryHash(input.ProviderAttestationDigest) ||
		!validRecoveryID(input.ProviderAttestationAlgorithm) || len(input.ProviderAttestationSignature) == 0 ||
		!validRecoveryID(input.ProviderAttestationProtocolVersion) ||
		len(input.BatchReferences) != 8 {
		return recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin control evidence issue: %w", err)
	}
	defer tx.Rollback()
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN integration_operations plan_operation ON plan_operation.id = plan.integration_operation_id
WHERE plan.external_id = $1 AND plan.status = 'BATCHES_STAGED'
  AND plan_operation.fencing_token = $2 AND plan_operation.lease_owner = $3
  AND plan_operation.lease_expires_at > CURRENT_TIMESTAMP
  AND plan_operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
FOR UPDATE OF plan, plan_operation`, input.PlanExternalID, input.FencingToken, input.LeaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		return recovery.ErrStaleFence
	}
	if err != nil {
		return fmt.Errorf("lock recovery plan for control evidence: %w", err)
	}
	evidenceOperation, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key,
		"VERIFY_RECOVERY_CONTROL", plan.PoolExternalID, input.RequestHash, canonical, false, "", 0)
	if err != nil {
		return err
	}
	if !created {
		if evidenceOperation.Status != application.OperationSucceeded {
			return recovery.ErrInvalidState
		}
		var evidenceExternalID, planExternalID, accountExternalID string
		var referenceCount int
		if err := tx.QueryRowContext(ctx, `SELECT evidence.external_id, plan.external_id, account.external_id,
count(reference.*) FROM recovery_control_evidence evidence
JOIN recovery_epoch_plans plan ON plan.id = evidence.plan_id
JOIN pool_resource_accounts account ON account.id = evidence.resource_account_id
LEFT JOIN recovery_control_evidence_batches reference ON reference.evidence_id = evidence.id
WHERE evidence.integration_operation_id = $1
GROUP BY evidence.id, plan.external_id, account.external_id`, evidenceOperation.AggregateID).
			Scan(&evidenceExternalID, &planExternalID, &accountExternalID, &referenceCount); err != nil {
			return translateRecoveryError("load replayed control evidence", err)
		}
		if evidenceExternalID != input.EvidenceExternalID || planExternalID != input.PlanExternalID ||
			accountExternalID != input.ResourceExternalID || referenceCount != len(input.BatchReferences) {
			return recovery.ErrHashDrift
		}
		return tx.Commit()
	}
	attestationPurpose := "ROTATION_CONTROL"
	if plan.CeremonyType == recovery.CeremonyBootstrap {
		attestationPurpose = "BOOTSTRAP_GENESIS"
	}
	var evidenceID, planID, accountID string
	err = tx.QueryRowContext(ctx, `INSERT INTO recovery_control_evidence (
external_id, integration_operation_id, plan_id, resource_account_id, provider_attestation_ref, provider_attestation_digest,
provider_attestation_issuer, provider_attestation_key_id, provider_attestation_version,
provider_attestation_algorithm, provider_attestation_signature, provider_attestation_protocol_version,
ceremony_type, attestation_purpose, status, verified_at
)
SELECT $1::text, $2::uuid, plan.id, account.resource_account_id, $3::text, $4::bytea,
       $5::text, $6::text, $7::bigint, $8::text, $9::bytea, $10::text, plan.ceremony_type, $11::text,
       'VERIFIED', CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan JOIN recovery_plan_resource_accounts account ON account.plan_id = plan.id
WHERE plan.id = $12::uuid AND plan.status = 'BATCHES_STAGED'
  AND account.account_external_id = $13::text
  AND account.control_evidence_external_id = $1::text
  AND account.control_attestation_digest = $4::bytea
  AND account.control_attestation_issuer = $5::text
  AND account.control_attestation_key_id = $6::text
  AND account.control_attestation_version = $7::bigint
  AND account.control_attestation_algorithm = $8::text
  AND account.control_attestation_signature = $9::bytea
  AND account.control_attestation_protocol_version = $10::text
RETURNING id, plan_id, resource_account_id`, input.EvidenceExternalID, evidenceOperation.AggregateID,
		input.ProviderAttestationRef,
		input.ProviderAttestationDigest[:], input.ProviderAttestationIssuer, input.ProviderAttestationKeyID,
		input.ProviderAttestationVersion, input.ProviderAttestationAlgorithm, input.ProviderAttestationSignature,
		input.ProviderAttestationProtocolVersion, attestationPurpose, plan.ID, input.ResourceExternalID).
		Scan(&evidenceID, &planID, &accountID)
	if err != nil {
		return translateRecoveryError("insert verified account control evidence", err)
	}
	seen := make(map[string]struct{}, len(input.BatchReferences))
	for _, reference := range input.BatchReferences {
		key := reference.EpochRole + "\x00" + reference.BatchType
		if (reference.EpochRole != "FROM" && reference.EpochRole != "TO") ||
			!validControlBatchType(reference.BatchType) || !validRecoveryID(reference.BatchExternalID) {
			return recovery.ErrInvalidData
		}
		if _, duplicate := seen[key]; duplicate {
			return recovery.ErrInvalidData
		}
		seen[key] = struct{}{}
		result, err := tx.ExecContext(ctx, `INSERT INTO recovery_control_evidence_batches (
evidence_id, plan_id, resource_account_id, epoch_role, batch_type, credential_batch_id,
ciphertext_hash, recovery_wrap_hash, created_at
)
SELECT $1, $2, $3, binding.epoch_role, binding.batch_type, binding.credential_batch_id,
binding.ciphertext_hash, binding.recovery_wrap_hash, CURRENT_TIMESTAMP
FROM recovery_plan_batch_bindings binding JOIN credential_batches batch ON batch.id = binding.credential_batch_id
WHERE binding.plan_id = $2 AND binding.resource_account_id = $3 AND binding.epoch_role = $4
  AND binding.batch_type = $5 AND batch.external_id = $6`, evidenceID, planID, accountID,
			reference.EpochRole, reference.BatchType, reference.BatchExternalID)
		if err != nil {
			return translateRecoveryError("insert control evidence batch reference", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return recovery.ErrBindingMismatch
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
response_snapshot = jsonb_build_object('control_evidence_id', $2::text), completed_at = CURRENT_TIMESTAMP,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'RUNNING'`, evidenceOperation.AggregateID, input.EvidenceExternalID)
	if err != nil {
		return translateRecoveryError("complete control evidence operation", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return recovery.ErrInvalidState
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit verified account control evidence: %w", err)
	}
	return nil
}

func (s *Store) BeginPermanentReplacement(ctx context.Context, input recovery.BeginPermanentReplacementInput) (*recovery.PermanentReplacementTarget, bool, error) {
	canonical, err := canonicalPermanentReplacement(input)
	if err != nil || !validRecoveryID(input.CaseExternalID) || !validRecoveryID(input.PlanExternalID) ||
		!validRecoveryID(input.LeaseOwner) || input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute ||
		input.ExpectedFencingToken < 0 || len(input.Seats) == 0 ||
		len(input.EvidenceExternalIDs) == 0 || !uniqueReplacementIntents(input.Seats) ||
		!uniqueRecoveryIDs(input.EvidenceExternalIDs) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin permanent replacement: %w", err)
	}
	defer tx.Rollback()
	if target, replayed, replayErr := loadCompletedPermanentReplacementReplay(ctx, tx, input.Key,
		"REPLACE_PERMANENTLY", input.RequestHash, canonical, input.CaseExternalID,
		input.PlanExternalID); replayErr != nil {
		return nil, false, replayErr
	} else if replayed {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit permanent replacement replay: %w", err)
		}
		return target, false, nil
	}
	var poolExternalID string
	if err := tx.QueryRowContext(ctx, `SELECT pool.external_id FROM recovery_epoch_plans plan
JOIN pools pool ON pool.id = plan.pool_id WHERE plan.external_id = $1 AND plan.status = 'READY'
   OR (plan.external_id = $1 AND plan.status = 'FINALIZED' AND EXISTS (
       SELECT 1 FROM permanent_replacement_cases replacement JOIN integration_operations operation
         ON operation.id = replacement.integration_operation_id
       WHERE replacement.plan_id = plan.id AND operation.integration_client_id = $2
         AND operation.operation_id = $3 AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')))
FOR SHARE OF plan, pool`, input.PlanExternalID, input.Key.ClientID, input.Key.OperationID).Scan(&poolExternalID); err != nil {
		return nil, false, translateRecoveryError("load finalizable recovery plan", err)
	}
	op, created, err := beginRecoveryPoolChildOperation(ctx, tx, input.Key, poolExternalID,
		"REPLACE_PERMANENTLY", input.RequestHash, canonical, input.LeaseOwner,
		input.ExpectedFencingToken, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		result, err := tx.ExecContext(ctx, `INSERT INTO permanent_replacement_cases (
external_id, integration_operation_id, plan_id, status, version, created_at, updated_at
)
SELECT $1, $2, plan.id, 'READY', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan WHERE plan.external_id = $3 AND plan.status = 'READY'
  AND (SELECT count(*) FROM recovery_plan_seats seat WHERE seat.plan_id = plan.id) = $4
  AND cardinality($5::text[]) = plan.expected_resource_count
  AND (SELECT count(*) FROM recovery_control_evidence evidence
       WHERE evidence.plan_id = plan.id AND evidence.status = 'VERIFIED'
         AND evidence.external_id = ANY($5)) = plan.expected_resource_count`, input.CaseExternalID,
			op.AggregateID, input.PlanExternalID, len(input.Seats), pq.Array(input.EvidenceExternalIDs))
		if err != nil {
			return nil, false, translateRecoveryError("insert permanent replacement case", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrBindingMismatch
		}
		for _, seat := range input.Seats {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM recovery_plan_seats planned
JOIN seats stable_seat ON stable_seat.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id
WHERE planned.plan_id = (SELECT id FROM recovery_epoch_plans WHERE external_id = $1)
  AND stable_seat.external_id = $2 AND target.external_id = $3`,
				input.PlanExternalID, seat.SeatExternalID, seat.TargetMemberExternalID).Scan(&count); err != nil || count != 1 {
				return nil, false, recovery.ErrBindingMismatch
			}
		}
	} else {
		var caseExternalID, planExternalID string
		if err := tx.QueryRowContext(ctx, `SELECT replacement.external_id, plan.external_id
FROM permanent_replacement_cases replacement JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
WHERE replacement.integration_operation_id = $1`, op.AggregateID).Scan(&caseExternalID, &planExternalID); err != nil {
			return nil, false, translateRecoveryError("load replayed permanent replacement", err)
		}
		if caseExternalID != input.CaseExternalID || planExternalID != input.PlanExternalID {
			return nil, false, recovery.ErrHashDrift
		}
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, op)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin permanent replacement: %w", err)
	}
	return target, created, nil
}

func (s *Store) BeginBootstrapFinalization(ctx context.Context, input recovery.BeginBootstrapFinalizationInput) (*recovery.PermanentReplacementTarget, bool, error) {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryID(input.CaseExternalID) || !validRecoveryID(input.PlanExternalID) ||
		!validRecoveryID(input.LeaseOwner) || input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute ||
		input.ExpectedFencingToken < 0 || len(input.EvidenceExternalIDs) == 0 ||
		!uniqueRecoveryIDs(input.EvidenceExternalIDs) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin bootstrap finalization: %w", err)
	}
	defer tx.Rollback()
	if target, replayed, replayErr := loadCompletedPermanentReplacementReplay(ctx, tx, input.Key,
		"FINALIZE_RECOVERY_BOOTSTRAP", input.RequestHash, canonical, input.CaseExternalID,
		input.PlanExternalID); replayErr != nil {
		return nil, false, replayErr
	} else if replayed {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit bootstrap finalization replay: %w", err)
		}
		return target, false, nil
	}
	var poolExternalID string
	if err := tx.QueryRowContext(ctx, `SELECT pool.external_id FROM recovery_epoch_plans plan
JOIN pools pool ON pool.id = plan.pool_id
WHERE plan.external_id = $1 AND plan.status = 'READY' AND plan.ceremony_type = 'BOOTSTRAP'
   OR (plan.external_id = $1 AND plan.status = 'FINALIZED' AND plan.ceremony_type = 'BOOTSTRAP' AND EXISTS (
       SELECT 1 FROM permanent_replacement_cases replacement JOIN integration_operations operation
         ON operation.id = replacement.integration_operation_id WHERE replacement.plan_id = plan.id
        AND operation.integration_client_id = $2 AND operation.operation_id = $3
        AND replacement.status IN ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')))
FOR SHARE OF plan, pool`, input.PlanExternalID, input.Key.ClientID, input.Key.OperationID).Scan(&poolExternalID); err != nil {
		return nil, false, translateRecoveryError("load READY bootstrap plan", err)
	}
	op, created, err := beginRecoveryPoolChildOperation(ctx, tx, input.Key, poolExternalID,
		"FINALIZE_RECOVERY_BOOTSTRAP", input.RequestHash, canonical, input.LeaseOwner,
		input.ExpectedFencingToken, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		result, err := tx.ExecContext(ctx, `INSERT INTO permanent_replacement_cases (
external_id, integration_operation_id, plan_id, status, version, created_at, updated_at
)
SELECT $1, $2, plan.id, 'READY', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan WHERE plan.external_id = $3 AND plan.ceremony_type = 'BOOTSTRAP'
  AND plan.status = 'READY'
  AND cardinality($4::text[]) = plan.expected_resource_count
  AND (SELECT count(*) FROM recovery_control_evidence evidence
       WHERE evidence.plan_id = plan.id AND evidence.status = 'VERIFIED'
         AND evidence.external_id = ANY($4)) = plan.expected_resource_count`, input.CaseExternalID,
			op.AggregateID, input.PlanExternalID, pq.Array(input.EvidenceExternalIDs))
		if err != nil {
			return nil, false, translateRecoveryError("insert bootstrap finalization case", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrBindingMismatch
		}
	} else {
		var caseExternalID, planExternalID string
		if err := tx.QueryRowContext(ctx, `SELECT replacement.external_id, plan.external_id
FROM permanent_replacement_cases replacement JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
WHERE replacement.integration_operation_id = $1`, op.AggregateID).Scan(&caseExternalID, &planExternalID); err != nil {
			return nil, false, translateRecoveryError("load replayed bootstrap finalization", err)
		}
		if caseExternalID != input.CaseExternalID || planExternalID != input.PlanExternalID {
			return nil, false, recovery.ErrHashDrift
		}
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, op)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin bootstrap finalization: %w", err)
	}
	return target, created, nil
}

// AcquireNextPermanentReplacementLease 只扫描 Pool 级 finalization；child 与普通 workflow scanner 隔离。
func (s *Store) AcquireNextPermanentReplacementLease(ctx context.Context,
	input recovery.AcquireNextPermanentReplacementLeaseInput) (*recovery.PermanentReplacementTarget, error) {
	if !validRecoveryID(input.LeaseOwner) || input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin next permanent replacement lease: %w", err)
	}
	defer tx.Rollback()
	op, err := scanOperation(tx.QueryRowContext(ctx, `WITH candidate AS (
    SELECT operation.id AS candidate_operation_id FROM integration_operations operation
    JOIN permanent_replacement_cases replacement ON replacement.integration_operation_id = operation.id
    JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
    WHERE operation.operation_type IN ('REPLACE_PERMANENTLY', 'FINALIZE_RECOVERY_BOOTSTRAP')
      AND operation.target_type = 'POOL' AND operation.migration_state = 'CURRENT'
      AND operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
      AND replacement.status IN ('READY', 'ROTATING', 'RECONCILE_REQUIRED', 'PROVIDER_COMMIT_PENDING')
      AND ((plan.status = 'READY' AND replacement.status <> 'PROVIDER_COMMIT_PENDING') OR
           (plan.status = 'FINALIZED' AND replacement.status = 'PROVIDER_COMMIT_PENDING'))
      AND (operation.next_attempt_at IS NULL OR operation.next_attempt_at <= CURRENT_TIMESTAMP)
      AND (operation.lease_expires_at IS NULL OR operation.lease_expires_at <= CURRENT_TIMESTAMP)
    ORDER BY COALESCE(operation.next_attempt_at, operation.created_at), operation.created_at
    FOR UPDATE OF operation SKIP LOCKED LIMIT 1
)
UPDATE integration_operations operation SET lease_owner = $1,
lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $2),
fencing_token = operation.fencing_token + 1, attempt_count = operation.attempt_count + 1,
version = operation.version + 1, updated_at = CURRENT_TIMESTAMP
FROM candidate WHERE operation.id = candidate.candidate_operation_id RETURNING `+operationColumns,
		input.LeaseOwner, input.LeaseDuration.Seconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("acquire next permanent replacement lease: %w", err)
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, op)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit next permanent replacement lease: %w", err)
	}
	return target, nil
}

func (s *Store) RenewPermanentReplacementLease(ctx context.Context,
	input recovery.RenewPermanentReplacementLeaseInput) (*recovery.PermanentReplacementTarget, error) {
	if !validRecoveryID(input.Key.ClientID) || !validRecoveryID(input.Key.OperationID) ||
		!validRecoveryID(input.LeaseOwner) || input.ExpectedFencingToken <= 0 ||
		input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin permanent replacement heartbeat: %w", err)
	}
	defer tx.Rollback()
	// Heartbeat 只延长当前租约，不改变 fencing token；过期后必须由 takeover 产生新 fence。
	op, err := scanOperation(tx.QueryRowContext(ctx, `WITH eligible AS (
  SELECT operation.id AS eligible_operation_id
  FROM integration_operations operation
  JOIN permanent_replacement_cases replacement ON replacement.integration_operation_id = operation.id
  JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
  WHERE operation.integration_client_id = $1 AND operation.operation_id = $2
    AND operation.fencing_token = $3 AND operation.lease_owner = $5
    AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
    AND operation.operation_type IN ('REPLACE_PERMANENTLY','FINALIZE_RECOVERY_BOOTSTRAP')
    AND replacement.status IN ('READY','ROTATING','RECONCILE_REQUIRED','READY_TO_COMMIT',
                               'PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')
    AND ((plan.status = 'READY' AND replacement.status IN
            ('READY','ROTATING','RECONCILE_REQUIRED','READY_TO_COMMIT')) OR
         (plan.status = 'FINALIZED' AND replacement.status IN
            ('PROVIDER_COMMIT_PENDING','READY_TO_ISSUE')))
  FOR UPDATE OF operation
)
UPDATE integration_operations SET
lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
version = integration_operations.version + 1, updated_at = CURRENT_TIMESTAMP
FROM eligible WHERE integration_operations.id = eligible.eligible_operation_id
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.ExpectedFencingToken,
		input.LeaseDuration.Seconds(), input.LeaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("renew permanent replacement lease: %w", err)
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, op)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit permanent replacement heartbeat: %w", err)
	}
	return target, nil
}

func (s *Store) RenewRecoveryChildOperationLease(ctx context.Context,
	input recovery.RenewRecoveryChildOperationLeaseInput) (*recovery.StoredOperation, error) {
	if !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryID(input.DerivedOperationID) ||
		!validRecoveryID(input.ChildLeaseOwner) || input.ExpectedChildFencingToken <= 0 ||
		input.ChildLeaseDuration <= 0 || input.ChildLeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `UPDATE integration_operations child SET
lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $7),
version = child.version + 1, updated_at = CURRENT_TIMESTAMP
WHERE child.integration_client_id = $1 AND child.operation_id = $5
  AND child.fencing_token = $6 AND child.lease_owner = $8
  AND child.lease_expires_at > CURRENT_TIMESTAMP AND child.status = 'RUNNING'
  AND EXISTS (
    SELECT 1 FROM permanent_replacement_cases replacement
    JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
    JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
    WHERE finalization.integration_client_id = $1 AND finalization.operation_id = $2
      AND finalization.fencing_token = $3 AND finalization.lease_owner = $4
      AND finalization.lease_expires_at > CURRENT_TIMESTAMP AND finalization.status = 'RUNNING'
      AND child.integration_client_id = finalization.integration_client_id
      AND (
        (plan.status = 'READY' AND replacement.status IN
           ('READY','ROTATING','RECONCILE_REQUIRED','READY_TO_COMMIT') AND (
          (child.operation_type = 'PREPARE_PERMANENT_REPLACEMENT' AND EXISTS (
             SELECT 1 FROM recovery_seat_rotation_progress progress
             WHERE progress.plan_id = plan.id AND progress.derived_operation_id = child.id)) OR
          (child.operation_type = 'PREPARE_PERMANENT_REPLACEMENT_SET' AND EXISTS (
             SELECT 1 FROM recovery_pool_preparation_attempts preparation
             WHERE preparation.plan_id = plan.id AND preparation.integration_operation_id = child.id)) OR
          (child.operation_type = 'ACTIVATE_PERMANENT_REPLACEMENT' AND EXISTS (
             SELECT 1 FROM recovery_pool_activation_attempts activation
             WHERE activation.plan_id = plan.id AND activation.integration_operation_id = child.id)))) OR
        (plan.status = 'FINALIZED' AND replacement.status = 'PROVIDER_COMMIT_PENDING' AND
         child.operation_type = 'COMMIT_PERMANENT_REPLACEMENT_PROVIDER' AND EXISTS (
           SELECT 1 FROM recovery_pool_provider_commit_attempts provider_commit
           WHERE provider_commit.plan_id = plan.id AND provider_commit.integration_operation_id = child.id))
      )
  )
RETURNING `+operationColumns, input.FinalizationKey.ClientID, input.FinalizationKey.OperationID,
		input.FinalizationFencingToken, input.FinalizationLeaseOwner, input.DerivedOperationID,
		input.ExpectedChildFencingToken, input.ChildLeaseDuration.Seconds(), input.ChildLeaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("renew recovery child operation lease: %w", err)
	}
	return toRecoveryOperation(op), nil
}

func (s *Store) BeginSeatRotation(ctx context.Context, input recovery.BeginSeatRotationInput) (*recovery.SeatRotationTarget, bool, error) {
	canonical, err := canonicalRecoveryProtocolSnapshot(input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryID(input.SeatExternalID) ||
		!validRecoveryID(input.DerivedOperationID) || !validRecoveryID(input.ChildLeaseOwner) ||
		input.ExpectedChildFencingToken < 0 || input.ChildLeaseDuration <= 0 ||
		input.ChildLeaseDuration > 5*time.Minute {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, caseID, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	expectedRequest, err := loadSeatPrepareRequestTx(ctx, tx, plan, input.SeatExternalID, input.DerivedOperationID)
	if err != nil {
		return nil, false, err
	}
	expectedHash := recovery.PermanentSeatRotationPrepareRequestHash(expectedRequest)
	expectedRequest.RequestHash = expectedHash
	// New operations must persist the current typed protocol. The compatibility
	// shape is accepted only when validating an operation that already exists.
	if !typedSeatPrepareSnapshotBindsRequest(canonical, input.RequestHash, expectedRequest) {
		return nil, false, recovery.ErrBindingMismatch
	}
	if _, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases
SET status = 'ROTATING', version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status IN ('READY', 'RECONCILE_REQUIRED')`, caseID); err != nil {
		return nil, false, translateRecoveryError("mark permanent replacement rotating", err)
	}
	derivedKey := recovery.OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	op, created, err := beginRecoverySeatOperation(ctx, tx, derivedKey, input.SeatExternalID,
		"PREPARE_PERMANENT_REPLACEMENT", input.RequestHash, canonical, expectedRequest, input.ChildLeaseOwner,
		input.ExpectedChildFencingToken, input.ChildLeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		result, err := tx.ExecContext(ctx, `INSERT INTO recovery_seat_rotation_progress (
plan_id, seat_id, derived_operation_id, status, attempt_count, created_at, updated_at
)
SELECT $1, planned.seat_id, $2, 'PREPARE_PENDING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
WHERE planned.plan_id = $1 AND seat.external_id = $3
ON CONFLICT (plan_id, seat_id) DO NOTHING`, plan.ID, op.AggregateID, input.SeatExternalID)
		if err != nil {
			return nil, false, translateRecoveryError("insert Seat rotation progress", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrBindingMismatch
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE recovery_seat_rotation_progress
SET attempt_count = attempt_count + 1,
status = CASE WHEN status IN ('PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED')
              THEN 'PREPARE_PENDING' ELSE status END,
error_code = NULL, error_detail = NULL, next_attempt_at = NULL, updated_at = CURRENT_TIMESTAMP
WHERE derived_operation_id = $1
  AND status IN ('PREPARE_PENDING', 'PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED')`, op.AggregateID); err != nil {
		return nil, false, translateRecoveryError("resume Seat rotation progress", err)
	}
	progress, err := loadSeatRotationProgressTx(ctx, tx, op.AggregateID)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin Seat rotation: %w", err)
	}
	return &recovery.SeatRotationTarget{Operation: toRecoveryOperation(op), Progress: progress}, created, nil
}

func (s *Store) CommitSeatRotationProgress(ctx context.Context, input recovery.CommitSeatRotationProgressInput) (*recovery.StoredSeatRotationProgress, error) {
	if !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner, input.FinalizationFencingToken) ||
		!validRecoveryCommit(recovery.OperationKey{ClientID: input.FinalizationKey.ClientID,
			OperationID: input.DerivedOperationID}, input.ChildLeaseOwner, input.ChildFencingToken) ||
		!validRecoveryID(input.SeatExternalID) || !validRecoveryID(input.DerivedOperationID) ||
		(input.Status != "PREPARED" && input.Status != "PREPARE_RETRYABLE" &&
			input.Status != "PREPARE_RECONCILE_REQUIRED" && input.Status != "FAILED") {
		return nil, recovery.ErrInvalidData
	}
	if input.Status == "PREPARED" {
		if input.Claim == nil || input.PrincipalUserID <= 0 || input.SubscriptionID <= 0 || input.APIKeyID <= 0 ||
			input.APIKeyVersion == 0 || errReplacementClaim(input.Claim) != nil ||
			input.Claim.SeatExternalID != input.SeatExternalID ||
			input.Claim.CredentialFingerprint == ([sha256.Size]byte{}) ||
			!validRecoveryCommit(input.PreparationKey, input.PreparationLeaseOwner,
				input.PreparationFencingToken) || zeroRecoveryHash(input.PreparationSetHash) {
			return nil, recovery.ErrInvalidData
		}
	} else if input.Claim != nil || input.PrincipalUserID != 0 || input.SubscriptionID != 0 ||
		input.APIKeyID != 0 || input.APIKeyVersion != 0 {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var operationID, targetMemberExternalID string
	var childRequestHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT io.id, target.external_id, io.request_hash FROM recovery_seat_rotation_progress progress
JOIN integration_operations io ON io.id = progress.derived_operation_id
JOIN seats seat ON seat.id = progress.seat_id
JOIN recovery_plan_seats planned ON planned.plan_id = progress.plan_id AND planned.seat_id = progress.seat_id
JOIN members target ON target.id = planned.to_member_id
WHERE progress.plan_id = $1 AND seat.external_id = $2 AND io.operation_id = $3
	AND io.integration_client_id = $4 AND io.operation_type = 'PREPARE_PERMANENT_REPLACEMENT'
	AND io.fencing_token = $5 AND io.lease_owner = $6 AND io.lease_expires_at > CURRENT_TIMESTAMP
	AND progress.status = 'PREPARE_PENDING'
	AND ($7 <> 'PREPARED' OR $8 = planned.expected_active_api_key_version + 1)
FOR UPDATE OF progress, io`, plan.ID, input.SeatExternalID, input.DerivedOperationID,
		input.FinalizationKey.ClientID, input.ChildFencingToken, input.ChildLeaseOwner,
		input.Status, input.APIKeyVersion).Scan(&operationID, &targetMemberExternalID, &childRequestHash); err != nil {
		return nil, translateRecoveryError("lock Seat rotation progress", err)
	}
	if input.Status == "PREPARED" {
		claim := input.Claim
		if claim.TargetMemberExternalID != targetMemberExternalID {
			return nil, recovery.ErrBindingMismatch
		}
		var typedChildHash [sha256.Size]byte
		if len(childRequestHash) != sha256.Size {
			return nil, recovery.ErrInvalidState
		}
		copy(typedChildHash[:], childRequestHash)
		expectedAAD := sha256.Sum256(recovery.ReplacementCredentialClaimAAD(input.FinalizationKey.ClientID,
			plan.ExternalID, input.DerivedOperationID, input.SeatExternalID, targetMemberExternalID,
			typedChildHash, claim.CredentialFingerprint))
		if claim.EnvelopeAADHash != expectedAAD {
			return nil, recovery.ErrBindingMismatch
		}
		var storedPreparationSetHash []byte
		if err := tx.QueryRowContext(ctx, `SELECT attempt.intent_set_hash
FROM recovery_pool_preparation_attempts attempt
JOIN integration_operations operation ON operation.id = attempt.integration_operation_id
WHERE attempt.plan_id = $1 AND attempt.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND operation.integration_client_id = $2 AND operation.operation_id = $3
  AND operation.fencing_token = $4 AND operation.lease_owner = $5
  AND operation.lease_expires_at > CURRENT_TIMESTAMP
  AND operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') FOR UPDATE OF attempt, operation`,
			plan.ID, input.PreparationKey.ClientID, input.PreparationKey.OperationID,
			input.PreparationFencingToken, input.PreparationLeaseOwner).Scan(&storedPreparationSetHash); err != nil {
			return nil, translateRecoveryError("lock Pool preparation operation", err)
		}
		if !bytes.Equal(storedPreparationSetHash, input.PreparationSetHash[:]) {
			return nil, recovery.ErrBindingMismatch
		}
		if _, err := tx.ExecContext(ctx, `UPDATE recovery_seat_rotation_progress SET
status = 'PREPARED', principal_user_id = $2, subscription_id = $3, api_key_id = $4, api_key_version = $5,
credential_fingerprint = $6, prepared_reference = $7, provider_result_digest = $8,
envelope_algorithm = $9, envelope_key_ref = $10,
envelope_ciphertext = $11, envelope_nonce = $12, envelope_aad_hash = $13,
wrapped_dek_kms = $14,
error_code = NULL, error_detail = NULL, next_attempt_at = NULL, updated_at = CURRENT_TIMESTAMP
WHERE derived_operation_id = $1`, operationID, input.PrincipalUserID, input.SubscriptionID, input.APIKeyID,
			input.APIKeyVersion, claim.CredentialFingerprint[:], claim.PreparedReference,
			claim.ProviderResultDigest[:], claim.EnvelopeAlgorithm, claim.EnvelopeKeyRef,
			claim.EnvelopeCiphertext, claim.EnvelopeNonce, claim.EnvelopeAADHash[:], claim.WrappedDEK); err != nil {
			return nil, translateRecoveryError("commit encrypted Seat rotation result", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE recovery_seat_rotation_progress SET status = $2,
principal_user_id = NULL, subscription_id = NULL, api_key_id = NULL, api_key_version = NULL,
credential_fingerprint = NULL, claim_operation_id = NULL, claim_token_hash = NULL, claim_intent_hash = NULL,
envelope_algorithm = NULL, envelope_key_ref = NULL, envelope_ciphertext = NULL, envelope_nonce = NULL,
envelope_aad_hash = NULL, wrapped_dek_kms = NULL, claim_expires_at = NULL,
error_code = NULLIF($3, ''), error_detail = NULLIF($4, ''), next_attempt_at = $5,
updated_at = CURRENT_TIMESTAMP WHERE derived_operation_id = $1`, operationID, input.Status,
			input.ErrorCode, input.ErrorDetail, input.NextAttemptAt); err != nil {
			return nil, translateRecoveryError("commit failed Seat rotation progress", err)
		}
		caseStatus := "OPERATOR_REVIEW_REQUIRED"
		if input.Status == "PREPARE_RETRYABLE" || input.Status == "PREPARE_RECONCILE_REQUIRED" {
			caseStatus = "RECONCILE_REQUIRED"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = $2,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE plan_id = $1 AND status = 'ROTATING'`,
			plan.ID, caseStatus); err != nil {
			return nil, translateRecoveryError("mark replacement reconciliation state", err)
		}
	}
	operationStatus := "SUCCEEDED"
	if input.Status == "PREPARE_RETRYABLE" {
		operationStatus = "RETRYABLE"
	} else if input.Status == "PREPARE_RECONCILE_REQUIRED" {
		operationStatus = "RECONCILE_REQUIRED"
	} else if input.Status == "FAILED" {
		operationStatus = "FAILED"
	}
	if result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = $2,
error_code = NULLIF($3, ''), error_detail = NULLIF($4, ''), next_attempt_at = $5,
completed_at = CASE WHEN $2 IN ('SUCCEEDED', 'FAILED') THEN CURRENT_TIMESTAMP ELSE NULL END,
lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND fencing_token = $6 AND lease_owner = $7 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status = 'RUNNING' AND operation_type = 'PREPARE_PERMANENT_REPLACEMENT'`, operationID,
		operationStatus, input.ErrorCode, input.ErrorDetail, input.NextAttemptAt,
		input.ChildFencingToken, input.ChildLeaseOwner); err != nil {
		return nil, translateRecoveryError("complete Seat prepare child operation", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrStaleFence
	}
	if input.Status == "PREPARED" {
		var prepared, expected int
		if err := tx.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM recovery_seat_rotation_progress WHERE plan_id = $1 AND status = 'PREPARED'),
(SELECT count(*) FROM recovery_plan_seats WHERE plan_id = $1)`, plan.ID).Scan(&prepared, &expected); err != nil {
			return nil, fmt.Errorf("count completed Pool preparation set: %w", err)
		}
		if prepared == expected {
			if result, err := tx.ExecContext(ctx, `UPDATE recovery_pool_preparation_attempts SET
status = 'PREPARED', version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE plan_id = $1 AND intent_set_hash = $2 AND status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')`,
				plan.ID, input.PreparationSetHash[:]); err != nil {
				return nil, translateRecoveryError("complete Pool preparation attempt", err)
			} else if affected, _ := result.RowsAffected(); affected != 1 {
				return nil, recovery.ErrInvalidState
			}
			if result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
completed_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND operation_type = 'PREPARE_PERMANENT_REPLACEMENT_SET'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')`, input.PreparationKey.ClientID,
				input.PreparationKey.OperationID, input.PreparationFencingToken,
				input.PreparationLeaseOwner); err != nil {
				return nil, translateRecoveryError("complete Pool preparation operation", err)
			} else if affected, _ := result.RowsAffected(); affected != 1 {
				return nil, recovery.ErrStaleFence
			}
		}
	}
	progress, err := loadSeatRotationProgressTx(ctx, tx, operationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Seat rotation progress: %w", err)
	}
	return progress, nil
}

func (s *Store) BeginPoolPreparation(ctx context.Context,
	input recovery.BeginPoolPreparationInput) (*recovery.PoolPreparationTarget, bool, error) {
	canonical, err := canonicalRecoveryProtocolSnapshot(input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryID(input.DerivedOperationID) ||
		!validRecoveryID(input.LeaseOwner) || input.ExpectedFencingToken < 0 ||
		input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	requests, err := loadSeatPrepareRequestsTx(ctx, tx, plan)
	if err != nil {
		return nil, false, err
	}
	intentSetHash, err := recovery.PermanentRotationChildSetHash(requests)
	expectedRequest := recovery.PermanentPoolRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1, OperationID: input.DerivedOperationID,
		PlanID: plan.ExternalID, CeremonyType: plan.CeremonyType, PoolID: plan.PoolExternalID,
		FromEpoch: plan.FromEpoch, ToEpoch: plan.ToEpoch, ChildSetHash: intentSetHash, Seats: requests,
	}
	expectedRequestHash := recovery.PermanentPoolRotationPrepareRequestHash(expectedRequest)
	expectedRequest.RequestHash = expectedRequestHash
	if err != nil || input.RequestHash != expectedRequestHash ||
		!rotationSnapshotBindsRequest(canonical, "child_set_hash", intentSetHash, expectedRequest) {
		return nil, false, recovery.ErrBindingMismatch
	}
	key := recovery.OperationKey{ClientID: input.FinalizationKey.ClientID,
		OperationID: input.DerivedOperationID}
	op, created, err := beginRecoveryPoolChildOperation(ctx, tx, key, plan.PoolExternalID,
		"PREPARE_PERMANENT_REPLACEMENT_SET", input.RequestHash, canonical, input.LeaseOwner,
		input.ExpectedFencingToken, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		result, err := tx.ExecContext(ctx, `INSERT INTO recovery_pool_preparation_attempts (
plan_id, integration_operation_id, intent_set_hash, status, version, created_at, updated_at
) VALUES ($1, $2, $3, 'PENDING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			plan.ID, op.AggregateID, intentSetHash[:])
		if err != nil {
			return nil, false, translateRecoveryError("insert Pool preparation attempt", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
	} else {
		var storedHash []byte
		if err := tx.QueryRowContext(ctx, `UPDATE recovery_pool_preparation_attempts SET
status = CASE WHEN status IN ('RETRYABLE', 'RECONCILE_REQUIRED') THEN 'PENDING' ELSE status END,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING intent_set_hash`, op.AggregateID).Scan(&storedHash); err != nil {
			return nil, false, translateRecoveryError("resume Pool preparation attempt", err)
		}
		if !bytes.Equal(storedHash, intentSetHash[:]) {
			return nil, false, recovery.ErrHashDrift
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = 'ROTATING',
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE plan_id = $1 AND status = 'RECONCILE_REQUIRED'`, plan.ID); err != nil {
		return nil, false, translateRecoveryError("resume replacement for Pool preparation", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin Pool preparation: %w", err)
	}
	return &recovery.PoolPreparationTarget{Operation: toRecoveryOperation(op), Plan: plan,
		IntentSetHash: intentSetHash}, created, nil
}

func (s *Store) CommitPoolPreparationFailure(ctx context.Context,
	input recovery.CommitPoolPreparationFailureInput) (*recovery.StoredOperation, error) {
	if !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryCommit(input.PreparationKey,
		input.PreparationLeaseOwner, input.PreparationFencingToken) ||
		(input.Status != "RETRYABLE" && input.Status != "RECONCILE_REQUIRED" && input.Status != "FAILED") ||
		!validRecoveryID(input.ErrorCode) || strings.TrimSpace(input.ErrorDetail) == "" {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE recovery_pool_preparation_attempts attempt SET
status = $6, version = version + 1, updated_at = CURRENT_TIMESTAMP
FROM integration_operations operation
WHERE attempt.plan_id = $1 AND operation.id = attempt.integration_operation_id
  AND operation.integration_client_id = $2 AND operation.operation_id = $3
  AND operation.fencing_token = $4 AND operation.lease_owner = $5
  AND operation.lease_expires_at > CURRENT_TIMESTAMP
  AND attempt.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')`, plan.ID,
		input.PreparationKey.ClientID, input.PreparationKey.OperationID, input.PreparationFencingToken,
		input.PreparationLeaseOwner, input.Status)
	if err != nil {
		return nil, translateRecoveryError("fail Pool preparation attempt", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrStaleFence
	}
	op, err := scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET status = $5,
error_code = $6, error_detail = $7, next_attempt_at = $8,
completed_at = CASE WHEN $5 = 'FAILED' THEN CURRENT_TIMESTAMP ELSE NULL END,
lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND operation_type = 'PREPARE_PERMANENT_REPLACEMENT_SET'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') RETURNING `+operationColumns,
		input.PreparationKey.ClientID, input.PreparationKey.OperationID, input.PreparationFencingToken,
		input.PreparationLeaseOwner, input.Status, input.ErrorCode, input.ErrorDetail, input.NextAttemptAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("complete Pool preparation failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Pool preparation failure: %w", err)
	}
	return toRecoveryOperation(op), nil
}

func (s *Store) BeginPoolActivation(ctx context.Context,
	input recovery.BeginPoolActivationInput) (*recovery.PoolActivationTarget, bool, error) {
	canonical, err := canonicalRecoveryProtocolSnapshot(input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryID(input.DerivedOperationID) ||
		!validRecoveryID(input.ChildLeaseOwner) || input.ExpectedChildFencingToken < 0 ||
		input.ChildLeaseDuration <= 0 || input.ChildLeaseDuration > 5*time.Minute {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	bindings, err := loadPreparedActivationBindingsTx(ctx, tx, plan)
	if err != nil {
		return nil, false, err
	}
	preparedSetHash, err := recovery.PermanentPreparedSeatSetHash(bindings)
	var prepareOperationID string
	if err == nil {
		err = tx.QueryRowContext(ctx, `SELECT operation.operation_id
FROM recovery_pool_preparation_attempts attempt JOIN integration_operations operation
  ON operation.id = attempt.integration_operation_id WHERE attempt.plan_id = $1 AND attempt.status = 'PREPARED'
  AND operation.status = 'SUCCEEDED'`, plan.ID).Scan(&prepareOperationID)
	}
	expectedRequest := recovery.PermanentPoolRotationActivateRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1, OperationID: input.DerivedOperationID,
		PrepareOperationID: prepareOperationID, PlanID: plan.ExternalID, CeremonyType: plan.CeremonyType,
		PoolID: plan.PoolExternalID, FromEpoch: plan.FromEpoch, ToEpoch: plan.ToEpoch,
		PreparedSetHash: preparedSetHash, Seats: bindings,
	}
	expectedRequestHash := recovery.PermanentPoolRotationActivateRequestHash(expectedRequest)
	expectedRequest.RequestHash = expectedRequestHash
	if err != nil || input.RequestHash != expectedRequestHash ||
		!rotationSnapshotBindsRequest(canonical, "prepared_set_hash", preparedSetHash, expectedRequest) {
		return nil, false, recovery.ErrBindingMismatch
	}
	var preparationReady bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM recovery_pool_preparation_attempts attempt
JOIN integration_operations operation ON operation.id = attempt.integration_operation_id
WHERE attempt.plan_id = $1 AND attempt.status = 'PREPARED' AND operation.status = 'SUCCEEDED')`,
		plan.ID).Scan(&preparationReady); err != nil || !preparationReady {
		return nil, false, recovery.ErrInvalidState
	}
	key := recovery.OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	op, created, err := beginRecoveryPoolChildOperation(ctx, tx, key, plan.PoolExternalID,
		"ACTIVATE_PERMANENT_REPLACEMENT", input.RequestHash, canonical, input.ChildLeaseOwner,
		input.ExpectedChildFencingToken, input.ChildLeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		if result, err := tx.ExecContext(ctx, `INSERT INTO recovery_pool_activation_attempts (
plan_id, integration_operation_id, prepared_set_hash, status, version, created_at, updated_at
) VALUES ($1, $2, $3, 'PENDING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			plan.ID, op.AggregateID, preparedSetHash[:]); err != nil {
			return nil, false, translateRecoveryError("insert Pool activation attempt", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
	} else {
		var storedHash []byte
		if err := tx.QueryRowContext(ctx, `UPDATE recovery_pool_activation_attempts SET
status = CASE WHEN status IN ('RETRYABLE', 'RECONCILE_REQUIRED') THEN 'PENDING' ELSE status END,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING prepared_set_hash`, op.AggregateID).Scan(&storedHash); err != nil {
			return nil, false, translateRecoveryError("resume Pool activation attempt", err)
		}
		if !bytes.Equal(storedHash, preparedSetHash[:]) {
			return nil, false, recovery.ErrHashDrift
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = 'ROTATING',
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE plan_id = $1 AND status = 'RECONCILE_REQUIRED'`, plan.ID); err != nil {
		return nil, false, translateRecoveryError("resume replacement for Pool activation", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin Pool activation: %w", err)
	}
	return &recovery.PoolActivationTarget{Operation: toRecoveryOperation(op), Plan: plan,
		PreparedSetHash: preparedSetHash}, created, nil
}

func (s *Store) CommitPoolActivation(ctx context.Context,
	input recovery.CommitPoolActivationInput) (*recovery.PermanentReplacementTarget, error) {
	if !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryCommit(recovery.OperationKey{
		ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID,
	}, input.ChildLeaseOwner, input.ChildFencingToken) || zeroRecoveryHash(input.PreparedSetHash) ||
		(input.Status != "ACTIVATED" && input.Status != "RETRYABLE" &&
			input.Status != "RECONCILE_REQUIRED" && input.Status != "FAILED") {
		return nil, recovery.ErrInvalidData
	}
	if input.Status == "ACTIVATED" {
		if !input.OldCredentialSetInvalidated || !input.CredentialFingerprintGateEnforced ||
			!input.AuthorizationCacheDurableOutbox || input.AuthCacheMinimumEvents < 2*len(input.Seats) ||
			!validRecoveryID(input.ProviderAttestationRef) || zeroRecoveryHash(input.ProviderAttestationDigest) ||
			!validRecoveryID(input.ProviderAttestationIssuer) || !validRecoveryID(input.ProviderAttestationKeyID) ||
			input.ProviderAttestationVersion == 0 || len(input.ProviderAttestationSignature) == 0 ||
			len(input.Seats) == 0 || !uniquePoolActivatedSeats(input.Seats) {
			return nil, recovery.ErrInvalidData
		}
	} else if !validRecoveryID(input.ErrorCode) || strings.TrimSpace(input.ErrorDetail) == "" || len(input.Seats) != 0 {
		return nil, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockPermanentReplacementCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	bindings, err := loadPreparedActivationBindingsTx(ctx, tx, plan)
	if err != nil {
		return nil, err
	}
	preparedSetHash, err := recovery.PermanentPreparedSeatSetHash(bindings)
	if err != nil || preparedSetHash != input.PreparedSetHash {
		return nil, recovery.ErrBindingMismatch
	}
	var attemptID, operationAggregateID string
	var storedHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT attempt.id, operation.id, attempt.prepared_set_hash
FROM recovery_pool_activation_attempts attempt
JOIN integration_operations operation ON operation.id = attempt.integration_operation_id
WHERE attempt.plan_id = $1 AND operation.integration_client_id = $2 AND operation.operation_id = $3
  AND operation.fencing_token = $4 AND operation.lease_owner = $5
  AND operation.lease_expires_at > CURRENT_TIMESTAMP
  AND operation.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND attempt.status IN ('PENDING', 'RETRYABLE', 'RECONCILE_REQUIRED')
FOR UPDATE OF attempt, operation`, plan.ID, input.FinalizationKey.ClientID, input.DerivedOperationID,
		input.ChildFencingToken, input.ChildLeaseOwner).Scan(&attemptID, &operationAggregateID, &storedHash); err != nil {
		return nil, translateRecoveryError("lock Pool activation attempt", err)
	}
	if !bytes.Equal(storedHash, input.PreparedSetHash[:]) {
		return nil, recovery.ErrHashDrift
	}
	if input.Status == "ACTIVATED" {
		if len(input.Seats) != len(bindings) {
			return nil, recovery.ErrBindingMismatch
		}
		for index, binding := range bindings {
			seat := input.Seats[index]
			if seat.SeatExternalID != binding.SeatID || seat.TargetMemberExternalID != binding.TargetMemberID ||
				seat.PreparedReference != binding.PreparedRotationRef || seat.PrincipalUserID != binding.PrincipalUserID ||
				seat.SubscriptionID != binding.SubscriptionID || seat.APIKeyID != binding.APIKeyID ||
				seat.APIKeyVersion != binding.ActiveAPIKeyVersion ||
				seat.CredentialFingerprint != binding.CredentialFingerprint ||
				seat.CurrentConcurrency != 0 || seat.PendingSettlements != 0 {
				return nil, recovery.ErrBindingMismatch
			}
			result, err := tx.ExecContext(ctx, `INSERT INTO recovery_pool_activation_seats (
activation_attempt_id, plan_id, seat_id, target_member_id, prepared_reference,
principal_user_id, subscription_id, api_key_id, api_key_version, credential_fingerprint,
current_concurrency, pending_settlements, created_at)
SELECT $1, planned.plan_id, planned.seat_id, planned.to_member_id, $4,
$5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP
FROM recovery_plan_seats planned JOIN seats stable ON stable.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id
WHERE planned.plan_id = $2 AND stable.external_id = $3 AND target.external_id = $12`,
				attemptID, plan.ID, seat.SeatExternalID, seat.PreparedReference, seat.PrincipalUserID,
				seat.SubscriptionID, seat.APIKeyID, seat.APIKeyVersion, seat.CredentialFingerprint[:],
				seat.CurrentConcurrency, seat.PendingSettlements, seat.TargetMemberExternalID)
			if err != nil {
				return nil, translateRecoveryError("insert Pool activation Seat proof", err)
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				return nil, recovery.ErrBindingMismatch
			}
		}
		if result, err := tx.ExecContext(ctx, `UPDATE recovery_seat_rotation_progress
SET status = 'ACTIVATED', updated_at = CURRENT_TIMESTAMP
WHERE plan_id = $1 AND status = 'PREPARED'`, plan.ID); err != nil {
			return nil, translateRecoveryError("activate exact Seat progress set", err)
		} else if affected, _ := result.RowsAffected(); affected != int64(len(bindings)) {
			return nil, recovery.ErrInvalidState
		}
		if result, err := tx.ExecContext(ctx, `UPDATE recovery_pool_activation_attempts SET status = 'ACTIVATED',
provider_attestation_ref = $2, provider_attestation_digest = $3,
provider_attestation_issuer = $4, provider_attestation_key_id = $5,
provider_attestation_version = $6, provider_attestation_signature = $7,
old_credential_set_invalidated = $8, credential_fingerprint_gate_enforced = $9,
authorization_cache_invalidated = $10, authorization_cache_durable_outbox = $11,
auth_cache_minimum_events = $12, activated_at = CURRENT_TIMESTAMP,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, attemptID,
			input.ProviderAttestationRef, input.ProviderAttestationDigest[:], input.ProviderAttestationIssuer,
			input.ProviderAttestationKeyID, input.ProviderAttestationVersion, input.ProviderAttestationSignature,
			input.OldCredentialSetInvalidated, input.CredentialFingerprintGateEnforced,
			input.AuthorizationCacheInvalidated, input.AuthorizationCacheDurableOutbox,
			input.AuthCacheMinimumEvents); err != nil {
			return nil, translateRecoveryError("commit Pool activation proof", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrInvalidState
		}
		if result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = 'READY_TO_COMMIT',
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE plan_id = $1 AND status = 'ROTATING'`, plan.ID); err != nil {
			return nil, translateRecoveryError("mark replacement ready to commit", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrInvalidState
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE recovery_pool_activation_attempts SET status = $2,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, attemptID, input.Status); err != nil {
			return nil, translateRecoveryError("commit Pool activation failure", err)
		}
		caseStatus := "OPERATOR_REVIEW_REQUIRED"
		if input.Status == "RETRYABLE" || input.Status == "RECONCILE_REQUIRED" {
			caseStatus = "RECONCILE_REQUIRED"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = $2,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE plan_id = $1 AND status = 'ROTATING'`,
			plan.ID, caseStatus); err != nil {
			return nil, translateRecoveryError("mark activation reconciliation state", err)
		}
	}
	opStatus := "SUCCEEDED"
	if input.Status != "ACTIVATED" {
		opStatus = input.Status
	}
	if result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = $2,
response_snapshot = CASE WHEN $2 = 'SUCCEEDED' THEN jsonb_build_object('prepared_set_hash', encode($3::bytea, 'hex')) ELSE NULL END,
error_code = NULLIF($4, ''), error_detail = NULLIF($5, ''), next_attempt_at = $6,
completed_at = CASE WHEN $2 IN ('SUCCEEDED', 'FAILED') THEN CURRENT_TIMESTAMP ELSE NULL END,
lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND fencing_token = $7 AND lease_owner = $8 AND lease_expires_at > CURRENT_TIMESTAMP`,
		operationAggregateID, opStatus, input.PreparedSetHash[:], input.ErrorCode, input.ErrorDetail,
		input.NextAttemptAt, input.ChildFencingToken, input.ChildLeaseOwner); err != nil {
		return nil, translateRecoveryError("complete Pool activation operation", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrStaleFence
	}
	parentOp, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2`,
		input.FinalizationKey.ClientID, input.FinalizationKey.OperationID))
	if err != nil {
		return nil, translateRecoveryError("reload finalization operation", err)
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, parentOp)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Pool activation: %w", err)
	}
	return target, nil
}

func (s *Store) BeginProviderRelease(ctx context.Context,
	input recovery.BeginProviderReleaseInput) (*recovery.ProviderReleaseTarget, bool, error) {
	canonical, err := canonicalRecoveryProtocolSnapshot(input.RequestHash, input.RequestSnapshot)
	if err != nil || !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner,
		input.FinalizationFencingToken) || !validRecoveryID(input.DerivedOperationID) ||
		!validRecoveryID(input.ChildLeaseOwner) || input.ExpectedChildFencingToken < 0 ||
		input.ChildLeaseDuration <= 0 || input.ChildLeaseDuration > 5*time.Minute {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, _, err := s.lockProviderPendingCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var activationID, activationOperationID, prepareOperationID string
	var activationRequestHash, preparedHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT activation.id, activation_operation.operation_id,
activation_operation.request_hash, preparation_operation.operation_id, activation.prepared_set_hash
FROM recovery_pool_activation_attempts activation JOIN integration_operations operation
  ON operation.id = activation.integration_operation_id
JOIN integration_operations activation_operation ON activation_operation.id = activation.integration_operation_id
JOIN recovery_pool_preparation_attempts preparation ON preparation.plan_id = activation.plan_id
JOIN integration_operations preparation_operation ON preparation_operation.id = preparation.integration_operation_id
WHERE activation.plan_id = $1 AND activation.status = 'ACTIVATED' AND operation.status = 'SUCCEEDED'`,
		plan.ID).Scan(&activationID, &activationOperationID, &activationRequestHash,
		&prepareOperationID, &preparedHash); err != nil {
		return nil, false, translateRecoveryError("load provider release binding", err)
	}
	var setHash [sha256.Size]byte
	copy(setHash[:], preparedHash)
	var typedActivationHash [sha256.Size]byte
	copy(typedActivationHash[:], activationRequestHash)
	bindings, err := loadCommittedActivationBindingsTx(ctx, tx, plan)
	expectedRequest := recovery.PermanentPoolRotationCommitRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1, OperationID: input.DerivedOperationID,
		PrepareOperationID: prepareOperationID, ActivationOperationID: activationOperationID,
		ActivationRequestHash: typedActivationHash, PlanID: plan.ExternalID,
		CeremonyType: plan.CeremonyType, PoolID: plan.PoolExternalID,
		FromEpoch: plan.FromEpoch, ToEpoch: plan.ToEpoch, PreparedSetHash: setHash, Seats: bindings,
	}
	expectedRequestHash := recovery.PermanentPoolRotationCommitRequestHash(expectedRequest)
	expectedRequest.RequestHash = expectedRequestHash
	if err != nil || len(preparedHash) != sha256.Size || len(activationRequestHash) != sha256.Size ||
		input.RequestHash != expectedRequestHash ||
		!rotationSnapshotBindsRequest(canonical, "prepared_set_hash", setHash, expectedRequest) {
		return nil, false, recovery.ErrBindingMismatch
	}
	key := recovery.OperationKey{ClientID: input.FinalizationKey.ClientID, OperationID: input.DerivedOperationID}
	op, created, err := beginRecoveryPoolChildOperation(ctx, tx, key, plan.PoolExternalID,
		"COMMIT_PERMANENT_REPLACEMENT_PROVIDER", input.RequestHash, canonical, input.ChildLeaseOwner,
		input.ExpectedChildFencingToken, input.ChildLeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if created {
		_, err = tx.ExecContext(ctx, `INSERT INTO recovery_pool_provider_commit_attempts
(plan_id, activation_attempt_id, integration_operation_id, prepared_set_hash, status, version, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'PENDING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			plan.ID, activationID, op.AggregateID, setHash[:])
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE recovery_pool_provider_commit_attempts SET
status = CASE WHEN status IN ('RETRYABLE','RECONCILE_REQUIRED') THEN 'PENDING' ELSE status END,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_operation_id = $1 AND status IN ('PENDING','RETRYABLE','RECONCILE_REQUIRED')`, op.AggregateID)
	}
	if err != nil {
		return nil, false, translateRecoveryError("persist provider release attempt", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &recovery.ProviderReleaseTarget{Operation: toRecoveryOperation(op), Plan: plan, PreparedSetHash: setHash}, created, nil
}

func (s *Store) CommitProviderRelease(ctx context.Context,
	input recovery.CommitProviderReleaseInput) (*recovery.StoredOperation, bool, error) {
	if !validRecoveryCommit(input.FinalizationKey, input.FinalizationLeaseOwner, input.FinalizationFencingToken) ||
		!validRecoveryCommit(recovery.OperationKey{ClientID: input.FinalizationKey.ClientID,
			OperationID: input.DerivedOperationID}, input.ChildLeaseOwner, input.ChildFencingToken) ||
		(input.Status != "RELEASED" && input.Status != "RETRYABLE" && input.Status != "RECONCILE_REQUIRED" && input.Status != "FAILED") {
		return nil, false, recovery.ErrInvalidData
	}
	if input.Status == "RELEASED" && (!validJSONObject(input.ResultSnapshot) ||
		!validRecoveryID(input.ProviderAttestationRef) || zeroRecoveryHash(input.ProviderAttestationDigest) ||
		!validRecoveryID(input.ProviderAttestationIssuer) || !validRecoveryID(input.ProviderAttestationKeyID) ||
		input.ProviderAttestationVersion == 0 || len(input.ProviderAttestationSignature) == 0 ||
		!input.AllCredentialsEnabled || !input.AllSubscriptionsEnabled ||
		!input.OldCredentialSetInvalidated || !input.CredentialFingerprintGateEnforced ||
		!input.AuthorizationCacheDurableOutbox || input.AuthCacheMinimumEvents <= 0) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, caseID, err := s.lockProviderPendingCase(ctx, input.FinalizationKey,
		input.FinalizationLeaseOwner, input.FinalizationFencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if input.Status == "RELEASED" && input.AuthCacheMinimumEvents < plan.ExpectedMemberCount {
		return nil, false, recovery.ErrBindingMismatch
	}
	var attemptID, childID string
	err = tx.QueryRowContext(ctx, `SELECT attempt.id, operation.id FROM recovery_pool_provider_commit_attempts attempt
JOIN integration_operations operation ON operation.id = attempt.integration_operation_id
WHERE attempt.plan_id = $1 AND operation.integration_client_id = $2 AND operation.operation_id = $3
 AND operation.fencing_token = $4 AND operation.lease_owner = $5 AND operation.lease_expires_at > CURRENT_TIMESTAMP
 AND attempt.status IN ('PENDING','RETRYABLE','RECONCILE_REQUIRED')
 AND operation.status IN ('RUNNING','RETRYABLE','RECONCILE_REQUIRED') FOR UPDATE OF attempt, operation`,
		plan.ID, input.FinalizationKey.ClientID, input.DerivedOperationID, input.ChildFencingToken,
		input.ChildLeaseOwner).Scan(&attemptID, &childID)
	if err != nil {
		return nil, false, translateRecoveryError("lock provider release attempt", err)
	}
	childStatus := input.Status
	if input.Status == "RELEASED" {
		childStatus = "SUCCEEDED"
	}
	if input.Status == "RELEASED" {
		_, err = tx.ExecContext(ctx, `UPDATE recovery_pool_provider_commit_attempts SET status = 'RELEASED',
provider_attestation_ref=$2, provider_attestation_digest=$3, provider_attestation_issuer=$4,
provider_attestation_key_id=$5, provider_attestation_version=$6, provider_attestation_signature=$7,
all_credentials_enabled=$8, all_subscriptions_enabled=$9, old_credential_set_invalidated=$10,
credential_fingerprint_gate_enforced=$11, authorization_cache_invalidated=$12,
authorization_cache_durable_outbox=$13, auth_cache_minimum_events=$14,
result_snapshot=$15::jsonb, version=version+1, updated_at=CURRENT_TIMESTAMP WHERE id=$1`, attemptID,
			input.ProviderAttestationRef, input.ProviderAttestationDigest[:], input.ProviderAttestationIssuer,
			input.ProviderAttestationKeyID, input.ProviderAttestationVersion, input.ProviderAttestationSignature,
			input.AllCredentialsEnabled, input.AllSubscriptionsEnabled, input.OldCredentialSetInvalidated,
			input.CredentialFingerprintGateEnforced, input.AuthorizationCacheInvalidated,
			input.AuthorizationCacheDurableOutbox, input.AuthCacheMinimumEvents, input.ResultSnapshot)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE recovery_pool_provider_commit_attempts SET status=$2,
version=version+1, updated_at=CURRENT_TIMESTAMP WHERE id=$1`, attemptID, input.Status)
	}
	if err != nil {
		return nil, false, translateRecoveryError("commit provider release proof", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status=$2,
response_snapshot=CASE WHEN $2='SUCCEEDED' THEN $3::jsonb ELSE NULL END,
error_code=NULLIF($4,''), error_detail=NULLIF($5,''), next_attempt_at=$6,
completed_at=CASE WHEN $2 IN ('SUCCEEDED','FAILED') THEN CURRENT_TIMESTAMP ELSE NULL END,
lease_owner=NULL, lease_expires_at=NULL, version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE id=$1 AND fencing_token=$7 AND lease_owner=$8`, childID, childStatus, input.ResultSnapshot,
		input.ErrorCode, input.ErrorDetail, input.NextAttemptAt, input.ChildFencingToken, input.ChildLeaseOwner)
	if err != nil {
		return nil, false, translateRecoveryError("complete provider release operation", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrStaleFence
	}
	if input.Status != "RELEASED" {
		parent, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, input.FinalizationKey.ClientID, input.FinalizationKey.OperationID))
		if err != nil {
			return nil, false, translateRecoveryError("reload provider release parent", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return toRecoveryOperation(parent), false, nil
	}
	if result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status='READY_TO_ISSUE',
version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE id=$1 AND status='PROVIDER_COMMIT_PENDING'`, caseID); err != nil {
		return nil, false, err
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	parent, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2 AND fencing_token=$3 AND lease_owner=$4
 AND lease_expires_at>CURRENT_TIMESTAMP AND status='RUNNING'`,
		input.FinalizationKey.ClientID, input.FinalizationKey.OperationID, input.FinalizationFencingToken,
		input.FinalizationLeaseOwner))
	if err != nil {
		return nil, false, translateRecoveryError("retain provider release parent", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return toRecoveryOperation(parent), true, nil
}

func (s *Store) CommitReplacementClaims(ctx context.Context,
	input recovery.CommitReplacementClaimsInput) (*recovery.StoredOperation, bool, error) {
	claims, err := validateReplacementClaimActivations(input.Claims)
	if err != nil || !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, plan, caseID, parent, err := s.lockReadyToIssueCase(ctx, input.Key, input.LeaseOwner, input.FencingToken)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if len(claims) != plan.ExpectedMemberCount {
		return nil, false, recovery.ErrBindingMismatch
	}
	if err := refreshPendingReplacementClaimsTx(ctx, tx, parent.AggregateID, input.Key.ClientID, claims); err != nil {
		return nil, false, err
	}
	if result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status='FINALIZED',
finalized_at=CURRENT_TIMESTAMP, version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE id=$1 AND status='READY_TO_ISSUE'`, caseID); err != nil {
		return nil, false, err
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	parent, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET status='SUCCEEDED',
completed_at=CURRENT_TIMESTAMP, lease_owner=NULL, lease_expires_at=NULL, version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE id=$1 AND fencing_token=$2 AND lease_owner=$3 AND lease_expires_at>CURRENT_TIMESTAMP
 AND status='RUNNING' RETURNING `+operationColumns, parent.AggregateID, input.FencingToken, input.LeaseOwner))
	if err != nil {
		return nil, false, translateRecoveryError("complete claim issuance parent", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return toRecoveryOperation(parent), true, nil
}

func (s *Store) CommitPermanentReplacement(ctx context.Context, input recovery.CommitPermanentReplacementInput) (*recovery.StoredOperation, bool, error) {
	return s.commitRecoveryFinalization(ctx, input, "REPLACE_PERMANENTLY")
}

func (s *Store) CommitBootstrapFinalization(ctx context.Context, input recovery.CommitBootstrapFinalizationInput) (*recovery.StoredOperation, bool, error) {
	return s.commitRecoveryFinalization(ctx, input, "FINALIZE_RECOVERY_BOOTSTRAP")
}

// commitRecoveryFinalization 是唯一结构切换入口。这里仅创建 ISSUANCE_PENDING 包络；
// provider release 持久成功后，另一个同步事务才写 token hash 并开放领取。
func (s *Store) commitRecoveryFinalization(ctx context.Context, input recovery.CommitPermanentReplacementInput,
	operationKind string) (*recovery.StoredOperation, bool, error) {
	return s.commitRecoveryFinalizationPhase2G(ctx, input, operationKind)
}

func (s *Store) commitRecoveryFinalizationPhase2G(ctx context.Context,
	input recovery.CommitPermanentReplacementInput, operationKind string) (*recovery.StoredOperation, bool, error) {
	claimIntents, claimsErr := validateReplacementClaimIntents(input.ClaimIntents)
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validJSONObject(input.ResultSnapshot) || claimsErr != nil {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, fmt.Errorf("begin Phase2-G finalization: %w", err)
	}
	defer tx.Rollback()
	var poolID, poolExternalID string
	if err := tx.QueryRowContext(ctx, `SELECT pool.id, pool.external_id
FROM integration_operations finalization
JOIN permanent_replacement_cases replacement ON replacement.integration_operation_id = finalization.id
JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id JOIN pools pool ON pool.id = plan.pool_id
WHERE finalization.integration_client_id = $1 AND finalization.operation_id = $2
  AND finalization.operation_type = $3`, input.Key.ClientID, input.Key.OperationID, operationKind).
		Scan(&poolID, &poolExternalID); err != nil {
		return nil, false, translateRecoveryError("locate Phase2-G Pool", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, poolExternalID); err != nil {
		return nil, false, fmt.Errorf("lock Phase2-G Pool advisory key: %w", err)
	}
	var lockedPoolID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM pools WHERE id = $1 FOR UPDATE`, poolID).
		Scan(&lockedPoolID); err != nil {
		return nil, false, translateRecoveryError("lock Phase2-G Pool", err)
	}
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
		input.Key.ClientID, input.Key.OperationID))
	if err != nil {
		return nil, false, translateRecoveryError("lock Phase2-G finalization operation", err)
	}
	if string(op.Kind) != operationKind || op.TargetType != "POOL" || op.TargetExternalID != poolExternalID {
		return nil, false, recovery.ErrBindingMismatch
	}
	if string(op.Status) == "SUCCEEDED" {
		stored, canonicalErr := canonicalJSONObject(op.ResultSnapshot)
		requested, requestErr := canonicalJSONObject(input.ResultSnapshot)
		if canonicalErr != nil || requestErr != nil || !bytes.Equal(stored, requested) {
			return nil, false, recovery.ErrHashDrift
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit Phase2-G replay: %w", err)
		}
		return toRecoveryOperation(op), false, nil
	}
	var leaseValid bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM integration_operations
WHERE id = $1 AND fencing_token = $2 AND lease_owner = $3 AND lease_expires_at > CURRENT_TIMESTAMP
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED'))`, op.AggregateID,
		input.FencingToken, input.LeaseOwner).Scan(&leaseValid); err != nil || !leaseValid {
		return nil, false, recovery.ErrStaleFence
	}
	var alreadyLocal bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM permanent_replacement_cases
WHERE integration_operation_id = $1 AND status IN ('PROVIDER_COMMIT_PENDING', 'READY_TO_ISSUE'))`,
		op.AggregateID).Scan(&alreadyLocal); err != nil {
		return nil, false, err
	}
	if alreadyLocal {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return toRecoveryOperation(op), false, nil
	}
	var caseID, planID, planExternalID, planOperationID string
	var ceremonyType recovery.CeremonyType
	var fromEpoch, toEpoch uint64
	var expectedSeats, expectedAccounts, expectedBatches int
	if err := tx.QueryRowContext(ctx, `SELECT replacement.id, plan.id, plan.external_id,
plan.integration_operation_id, plan.ceremony_type, plan.from_epoch, plan.to_epoch,
plan.expected_seat_count, plan.expected_resource_count, plan.expected_control_batch_count
FROM permanent_replacement_cases replacement JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
WHERE replacement.integration_operation_id = $1 AND replacement.status = 'READY_TO_COMMIT'
  AND plan.status = 'READY' FOR UPDATE OF replacement, plan`, op.AggregateID).
		Scan(&caseID, &planID, &planExternalID, &planOperationID, &ceremonyType, &fromEpoch, &toEpoch,
			&expectedSeats, &expectedAccounts, &expectedBatches); err != nil {
		return nil, false, translateRecoveryError("lock READY_TO_COMMIT aggregate", err)
	}
	if len(claimIntents) != expectedSeats {
		return nil, false, recovery.ErrBindingMismatch
	}
	if err := assertRecoveryInventorySnapshotTx(ctx, tx, planID, "revalidate final recovery inventory"); err != nil {
		return nil, false, err
	}
	var authorizedPlanID string
	if err := tx.QueryRowContext(ctx, `SELECT set_config('trusted_pool.recovery_inventory_plan_id', $1, true)`, planID).
		Scan(&authorizedPlanID); err != nil || authorizedPlanID != planID {
		return nil, false, recovery.ErrInvalidState
	}

	type activatedSeat struct {
		seatID, seatExternalID, targetMemberID, targetExternalID          string
		childAggregateID, childOperationID                                string
		expectedEpoch, expectedAPIKeyVersion, principalID, subscriptionID int64
		apiKeyID, apiKeyVersion                                           int64
		fingerprint, ciphertext, nonce, aadHash, wrappedDEK               []byte
		envelopeAlgorithm, envelopeKeyRef, preparedReference              string
	}
	rows, err := tx.QueryContext(ctx, `SELECT planned.seat_id, seat.external_id, planned.to_member_id,
target.external_id, planned.expected_assignment_epoch, planned.expected_active_api_key_version,
child.id, child.operation_id, progress.principal_user_id, progress.subscription_id, progress.api_key_id,
progress.api_key_version, progress.credential_fingerprint, progress.envelope_algorithm,
progress.envelope_key_ref, progress.envelope_ciphertext, progress.envelope_nonce,
progress.envelope_aad_hash, progress.wrapped_dek_kms, progress.prepared_reference
FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id
JOIN recovery_seat_rotation_progress progress
  ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
JOIN integration_operations child ON child.id = progress.derived_operation_id
WHERE planned.plan_id = $1 AND progress.status = 'ACTIVATED' AND child.status = 'SUCCEEDED'
  AND seat.status = 'FROZEN' AND seat.assignment_epoch = planned.expected_assignment_epoch
  AND seat.active_api_key_version = planned.expected_active_api_key_version
  AND progress.api_key_version = planned.expected_active_api_key_version + 1
ORDER BY seat.seat_no FOR UPDATE OF seat, progress`, planID)
	if err != nil {
		return nil, false, fmt.Errorf("lock sorted ACTIVATED Seats: %w", err)
	}
	activated := make([]activatedSeat, 0, expectedSeats)
	for rows.Next() {
		var item activatedSeat
		if err := rows.Scan(&item.seatID, &item.seatExternalID, &item.targetMemberID, &item.targetExternalID,
			&item.expectedEpoch, &item.expectedAPIKeyVersion, &item.childAggregateID, &item.childOperationID, &item.principalID,
			&item.subscriptionID, &item.apiKeyID, &item.apiKeyVersion, &item.fingerprint,
			&item.envelopeAlgorithm, &item.envelopeKeyRef, &item.ciphertext, &item.nonce,
			&item.aadHash, &item.wrappedDEK, &item.preparedReference); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("scan ACTIVATED Seat: %w", err)
		}
		activated = append(activated, item)
	}
	if err := rows.Close(); err != nil || len(activated) != expectedSeats {
		return nil, false, recovery.ErrInvalidState
	}
	// 锁序固定为 Pool -> sorted Seats -> sorted batches，避免并发终结产生死锁。
	batchRows, err := tx.QueryContext(ctx, `SELECT batch.id FROM recovery_plan_batch_bindings binding
JOIN credential_batches batch ON batch.id = binding.credential_batch_id
JOIN pool_resource_accounts account ON account.id = binding.resource_account_id
WHERE binding.plan_id = $1 ORDER BY account.external_id, binding.epoch_role, binding.batch_type
FOR UPDATE OF batch`, planID)
	if err != nil {
		return nil, false, fmt.Errorf("lock sorted recovery batches: %w", err)
	}
	lockedBatches := 0
	for batchRows.Next() {
		var ignored string
		if err := batchRows.Scan(&ignored); err != nil {
			batchRows.Close()
			return nil, false, err
		}
		lockedBatches++
	}
	if err := batchRows.Close(); err != nil || lockedBatches != expectedBatches*2 {
		return nil, false, recovery.ErrInvalidState
	}
	var activationProofs, verifiedEvidence, pendingSettlements int
	if err := tx.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM recovery_pool_activation_attempts activation
 JOIN integration_operations operation ON operation.id = activation.integration_operation_id
 WHERE activation.plan_id = $1 AND activation.status = 'ACTIVATED' AND operation.status = 'SUCCEEDED'
   AND activation.old_credential_set_invalidated IS TRUE
   AND activation.credential_fingerprint_gate_enforced IS TRUE
   AND activation.authorization_cache_durable_outbox IS TRUE
   AND activation.auth_cache_minimum_events >= 2 * $2),
(SELECT count(*) FROM recovery_pool_activation_seats proof
 JOIN recovery_plan_seats planned ON planned.plan_id = proof.plan_id AND planned.seat_id = proof.seat_id
 JOIN recovery_seat_rotation_progress progress
   ON progress.plan_id = proof.plan_id AND progress.seat_id = proof.seat_id
 WHERE proof.plan_id = $1 AND proof.target_member_id = planned.to_member_id
   AND proof.current_concurrency = 0 AND proof.pending_settlements = 0
   AND proof.prepared_reference = progress.prepared_reference
   AND proof.credential_fingerprint = progress.credential_fingerprint),
(SELECT count(*) FROM settlement_resolution_cases pending JOIN recovery_plan_seats planned
   ON planned.seat_id = pending.seat_id WHERE planned.plan_id = $1 AND pending.status = 'RESOLUTION_PENDING')`,
		planID, expectedSeats).Scan(&activationProofs, &verifiedEvidence, &pendingSettlements); err != nil {
		return nil, false, fmt.Errorf("verify Pool activation and settlement gates: %w", err)
	}
	if activationProofs != 1 || verifiedEvidence != expectedSeats || pendingSettlements != 0 {
		return nil, false, recovery.ErrInvalidState
	}

	if result, err := tx.ExecContext(ctx, `UPDATE credential_batches batch SET status = 'RETIRED',
retired_at = CURRENT_TIMESTAMP, version = version + 1, updated_at = CURRENT_TIMESTAMP
FROM recovery_plan_batch_bindings binding WHERE binding.plan_id = $1 AND binding.epoch_role = 'FROM'
  AND binding.credential_batch_id = batch.id AND batch.membership_epoch = $2
  AND batch.status = 'ACTIVE' AND batch.migration_state = 'CURRENT'`, planID, fromEpoch); err != nil {
		return nil, false, translateRecoveryError("retire source credential batches", err)
	} else if affected, _ := result.RowsAffected(); affected != int64(expectedBatches) {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE credential_batches batch SET status = 'ACTIVE',
activated_at = CURRENT_TIMESTAMP, version = version + 1, updated_at = CURRENT_TIMESTAMP
FROM recovery_plan_batch_bindings binding WHERE binding.plan_id = $1 AND binding.epoch_role = 'TO'
  AND binding.credential_batch_id = batch.id AND batch.recovery_plan_id = $1
  AND batch.membership_epoch = $2 AND batch.status = 'STAGED'`, planID, toEpoch); err != nil {
		return nil, false, translateRecoveryError("activate target credential batches", err)
	} else if affected, _ := result.RowsAffected(); affected != int64(expectedBatches) {
		return nil, false, recovery.ErrInvalidState
	}
	// Bootstrap starts from a LEGACY_UNVERIFIED epoch and therefore has no
	// CURRENT source Manifest to retire. Rotate must preserve the hash-linked
	// CURRENT Manifest retirement in the same structural transaction.
	if ceremonyType == recovery.CeremonyRotate {
		if result, err := tx.ExecContext(ctx, `UPDATE manifests SET status = 'RETIRED'
WHERE epoch_id = (SELECT id FROM membership_epochs WHERE pool_id = $1 AND epoch = $2)
  AND status = 'ACTIVE' AND migration_state = 'CURRENT'`, poolID, fromEpoch); err != nil {
			return nil, false, translateRecoveryError("retire source Manifest", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
	}
	if result, err := tx.ExecContext(ctx, `UPDATE manifests SET status = 'ACTIVE', published_at = CURRENT_TIMESTAMP
WHERE recovery_plan_id = $1 AND status = 'DRAFT' AND migration_state = 'CURRENT'`, planID); err != nil {
		return nil, false, translateRecoveryError("activate target Manifest", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE membership_epochs SET status = 'RETIRED', retired_at = CURRENT_TIMESTAMP
WHERE pool_id = $1 AND epoch = $2 AND status = 'ACTIVE'`, poolID, fromEpoch); err != nil {
		return nil, false, translateRecoveryError("retire source Membership Epoch", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE membership_epochs SET status = 'ACTIVE', activated_at = CURRENT_TIMESTAMP
WHERE recovery_plan_id = $1 AND epoch = $2 AND status = 'PREPARING'
  AND recovery_governance_state = 'CURRENT'`, planID, toEpoch); err != nil {
		return nil, false, translateRecoveryError("activate target Membership Epoch", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}

	for _, item := range activated {
		claim, exists := claimIntents[item.seatExternalID]
		if !exists {
			return nil, false, recovery.ErrBindingMismatch
		}
		if result, err := tx.ExecContext(ctx, `UPDATE seat_assignments SET status = 'ENDED',
ends_at = CURRENT_TIMESTAMP, ended_reason = 'PERMANENT_REPLACEMENT', updated_at = CURRENT_TIMESTAMP
WHERE seat_id = $1 AND status = 'ACTIVE'`, item.seatID); err != nil {
			return nil, false, translateRecoveryError("end prior Seat assignment", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, starts_at, created_at, updated_at
) VALUES ($1, $2, $3, 'PERMANENT', 'ACTIVE', $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			item.seatID, poolID, item.targetMemberID, item.expectedEpoch+1); err != nil {
			return nil, false, translateRecoveryError("insert permanent Seat assignment", err)
		}
		if result, err := tx.ExecContext(ctx, `UPDATE seats SET owner_member_id = $2, status = 'ACTIVE',
assignment_epoch = $3, sub2api_principal_id = $4, sub2api_subscription_id = $5,
sub2api_api_key_id = $6, active_api_key_version = $7, frozen_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND pool_id = $8 AND status = 'FROZEN' AND assignment_epoch = $9
  AND active_api_key_version = $10`, item.seatID, item.targetMemberID, item.expectedEpoch+1,
			item.principalID, item.subscriptionID, item.apiKeyID, item.apiKeyVersion,
			poolID, item.expectedEpoch, item.expectedAPIKeyVersion); err != nil {
			return nil, false, translateRecoveryError("commit permanent Seat owner", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
		intentHash := replacementPendingClaimIntentHash(input.Key.ClientID, planExternalID, item.childOperationID,
			item.seatExternalID, item.targetExternalID, claim.ClaimOperationID, item.fingerprint)
		var claimID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status, claim_token_hash,
credential_fingerprint, claim_intent_hash, envelope_algorithm, envelope_key_ref, envelope_ciphertext,
envelope_nonce, envelope_aad_hash, wrapped_dek_kms, expires_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, 'ISSUANCE_PENDING', NULL, $5, $6, $7, $8, $9, $10, $11, $12, NULL,
CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`, item.childAggregateID, item.seatID, item.targetMemberID,
			claim.ClaimOperationID, item.fingerprint, intentHash[:], item.envelopeAlgorithm,
			item.envelopeKeyRef, item.ciphertext, item.nonce, item.aadHash, item.wrappedDEK).
			Scan(&claimID); err != nil {
			return nil, false, translateRecoveryError("create pending-release credential claim", err)
		}
		if result, err := tx.ExecContext(ctx, `UPDATE recovery_seat_rotation_progress SET status = 'COMMITTED',
credential_claim_id = $2, envelope_algorithm = NULL, envelope_key_ref = NULL,
envelope_ciphertext = NULL, envelope_nonce = NULL, envelope_aad_hash = NULL,
wrapped_dek_kms = NULL, updated_at = CURRENT_TIMESTAMP
WHERE derived_operation_id = $1 AND status = 'ACTIVATED'`, item.childAggregateID, claimID); err != nil {
			return nil, false, translateRecoveryError("clear structurally committed replacement envelope", err)
		} else if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
	}
	if result, err := tx.ExecContext(ctx, `UPDATE recovery_control_evidence SET status = 'COMMITTED',
committed_at = CURRENT_TIMESTAMP WHERE plan_id = $1 AND status = 'VERIFIED'`, planID); err != nil {
		return nil, false, translateRecoveryError("commit recovery control evidence", err)
	} else if affected, _ := result.RowsAffected(); affected != int64(expectedAccounts) {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE pools SET membership_epoch = $2,
credential_epoch_floor = $2, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND membership_epoch = $3 AND credential_epoch_floor = $3`, poolID, toEpoch, fromEpoch); err != nil {
		return nil, false, translateRecoveryError("advance Pool membership Epoch/floor", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases SET status = 'PROVIDER_COMMIT_PENDING',
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'READY_TO_COMMIT'`, caseID); err != nil {
		return nil, false, translateRecoveryError("mark provider commit pending", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	if result, err := tx.ExecContext(ctx, `UPDATE recovery_epoch_plans SET status = 'FINALIZED',
finalized_at = CURRENT_TIMESTAMP, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'READY'`, planID); err != nil {
		return nil, false, translateRecoveryError("finalize recovery epoch plan", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	planResult, _ := json.Marshal(map[string]any{"plan_id": planExternalID, "status": "FINALIZED",
		"membership_epoch": toEpoch, "ceremony_type": ceremonyType})
	if result, err := tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
response_snapshot = $2::jsonb, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL,
lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND operation_type IN ('BOOTSTRAP_RECOVERY_EPOCH', 'ROTATE_RECOVERY_EPOCH')
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')`, planOperationID, planResult); err != nil {
		return nil, false, translateRecoveryError("complete recovery ceremony operation", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	op, err = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET
response_snapshot = $5::jsonb, error_code = NULL, error_detail = NULL, next_attempt_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND operation_type = $6
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED') RETURNING `+operationColumns,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner,
		input.ResultSnapshot, operationKind))
	if err != nil {
		return nil, false, translateRecoveryError("complete Phase2-G finalization", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit Phase2-G finalization: %w", err)
	}
	return toRecoveryOperation(op), true, nil
}

func (s *Store) CommitPermanentReplacementFailure(ctx context.Context, input recovery.CommitPermanentReplacementFailureInput) (*recovery.StoredOperation, error) {
	if !validRecoveryCommit(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validRecoveryID(input.ErrorCode) || strings.TrimSpace(input.ErrorDetail) == "" {
		return nil, recovery.ErrInvalidData
	}
	status := "RECONCILE_REQUIRED"
	if input.NextAttemptAt == nil {
		status = "RECONCILE_REQUIRED"
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `UPDATE integration_operations SET status = $5,
error_code = $6, error_detail = $7, next_attempt_at = $8,
lease_owner = NULL, lease_expires_at = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3 AND lease_owner = $4
  AND lease_expires_at > CURRENT_TIMESTAMP AND operation_type = 'REPLACE_PERMANENTLY'
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.FencingToken,
		input.LeaseOwner, status, input.ErrorCode, input.ErrorDetail, input.NextAttemptAt))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("commit permanent replacement failure: %w", err)
	}
	return toRecoveryOperation(op), nil
}

func (s *Store) AcquireReplacementCredentialClaim(ctx context.Context,
	input recovery.AcquireReplacementCredentialClaimInput) (*recovery.StoredReplacementCredentialClaim, error) {
	if !validRecoveryID(input.Key.ClientID) || !validRecoveryID(input.Key.OperationID) ||
		!validRecoveryID(input.PlanExternalID) || !validRecoveryID(input.SeatExternalID) ||
		!validRecoveryID(input.TargetMemberExternalID) || zeroRecoveryHash(input.TokenHash) ||
		!validRecoveryID(input.LeaseOwner) || input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin recovery claim acquire: %w", err)
	}
	defer tx.Rollback()
	var claimID string
	var storedTokenHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT claim.id, claim.claim_token_hash FROM credential_claims claim
JOIN integration_operations child ON child.id = claim.integration_operation_id
JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id = child.id
JOIN recovery_epoch_plans plan ON plan.id = progress.plan_id
JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
JOIN recovery_pool_provider_commit_attempts release ON release.plan_id = plan.id
JOIN seats seat ON seat.id = claim.seat_id JOIN members target ON target.id = claim.target_member_id
WHERE child.integration_client_id = $1 AND child.operation_id = $2 AND plan.external_id = $3
  AND seat.external_id = $4 AND target.external_id = $5
  AND replacement.status = 'FINALIZED' AND release.status = 'RELEASED'
  AND claim.status = 'READY' AND claim.expires_at > CURRENT_TIMESTAMP
  AND (claim.lease_expires_at IS NULL OR claim.lease_expires_at <= CURRENT_TIMESTAMP OR claim.lease_owner = $6)
FOR UPDATE OF claim`, input.Key.ClientID, input.Key.OperationID, input.PlanExternalID,
		input.SeatExternalID, input.TargetMemberExternalID, input.LeaseOwner).Scan(&claimID, &storedTokenHash); err != nil {
		return nil, translateRecoveryError("lock recovery credential claim", err)
	}
	if subtle.ConstantTimeCompare(storedTokenHash, input.TokenHash[:]) != 1 {
		return nil, recovery.ErrBindingMismatch
	}
	if result, err := tx.ExecContext(ctx, `UPDATE credential_claims SET lease_owner = $2,
lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $3), fencing_token = fencing_token + 1,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'READY'`,
		claimID, input.LeaseOwner, input.LeaseDuration.Seconds()); err != nil {
		return nil, translateRecoveryError("acquire recovery credential claim", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrLeaseHeld
	}
	claim, err := loadReplacementCredentialClaimTx(ctx, tx, claimID)
	if err != nil {
		return nil, err
	}
	expectedAAD := sha256.Sum256(recovery.ReplacementCredentialClaimAAD(claim.Key.ClientID,
		claim.PlanExternalID, claim.Key.OperationID, claim.SeatExternalID, claim.TargetMemberExternalID,
		claim.PrepareRequestHash, claim.CredentialFingerprint))
	if claim.EnvelopeAADHash != expectedAAD {
		return nil, recovery.ErrBindingMismatch
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery claim acquire: %w", err)
	}
	return claim, nil
}

func (s *Store) CommitReplacementCredentialClaim(ctx context.Context,
	input recovery.CommitReplacementCredentialClaimInput) (*recovery.StoredReplacementCredentialClaim, error) {
	if !validRecoveryID(input.Key.ClientID) || !validRecoveryID(input.Key.OperationID) ||
		!validRecoveryID(input.PlanExternalID) || !validRecoveryID(input.SeatExternalID) ||
		!validRecoveryID(input.TargetMemberExternalID) || zeroRecoveryHash(input.TokenHash) ||
		!validRecoveryID(input.LeaseOwner) || input.FencingToken <= 0 {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin recovery claim commit: %w", err)
	}
	defer tx.Rollback()
	var claimID string
	var storedTokenHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT claim.id, claim.claim_token_hash FROM credential_claims claim
JOIN integration_operations child ON child.id = claim.integration_operation_id
JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id = child.id
JOIN recovery_epoch_plans plan ON plan.id = progress.plan_id
JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
JOIN recovery_pool_provider_commit_attempts release ON release.plan_id = plan.id
JOIN seats seat ON seat.id = claim.seat_id JOIN members target ON target.id = claim.target_member_id
WHERE child.integration_client_id = $1 AND child.operation_id = $2 AND plan.external_id = $3
  AND seat.external_id = $4 AND target.external_id = $5
  AND replacement.status = 'FINALIZED' AND release.status = 'RELEASED'
  AND claim.status = 'READY' AND claim.fencing_token = $6 AND claim.lease_owner = $7
  AND claim.lease_expires_at > CURRENT_TIMESTAMP AND claim.expires_at > CURRENT_TIMESTAMP
FOR UPDATE OF claim`, input.Key.ClientID, input.Key.OperationID, input.PlanExternalID,
		input.SeatExternalID, input.TargetMemberExternalID, input.FencingToken,
		input.LeaseOwner).Scan(&claimID, &storedTokenHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, recovery.ErrStaleFence
		}
		return nil, translateRecoveryError("lock recovery claim commit", err)
	}
	if subtle.ConstantTimeCompare(storedTokenHash, input.TokenHash[:]) != 1 {
		return nil, recovery.ErrBindingMismatch
	}
	claim, err := loadReplacementCredentialClaimTx(ctx, tx, claimID)
	if err != nil {
		return nil, err
	}
	if result, err := tx.ExecContext(ctx, `UPDATE credential_claims SET status = 'CLAIMED',
claim_token_hash = NULL, envelope_algorithm = NULL, envelope_key_ref = NULL,
envelope_ciphertext = NULL, envelope_nonce = NULL, envelope_aad_hash = NULL, wrapped_dek_kms = NULL,
claimed_at = CURRENT_TIMESTAMP, terminal_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'READY'`, claimID); err != nil {
		return nil, translateRecoveryError("commit one-time recovery claim", err)
	} else if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrStaleFence
	}
	claim.Status, claim.LeaseOwner, claim.LeaseExpiresAt = "CLAIMED", "", nil
	claim.EnvelopeAlgorithm, claim.EnvelopeKeyRef = "", ""
	claim.EnvelopeCiphertext, claim.EnvelopeNonce, claim.WrappedDEK = nil, nil, nil
	claim.EnvelopeAADHash = [sha256.Size]byte{}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery credential claim: %w", err)
	}
	return claim, nil
}

func loadReplacementCredentialClaimTx(ctx context.Context, tx *sql.Tx,
	claimID string) (*recovery.StoredReplacementCredentialClaim, error) {
	var claim recovery.StoredReplacementCredentialClaim
	var requestHash, fingerprint, aadHash []byte
	var leaseOwner sql.NullString
	var leaseExpires sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT claim.id, child.integration_client_id, child.operation_id,
plan.external_id, child.request_hash, seat.external_id, target.external_id,
claim.credential_fingerprint, claim.envelope_algorithm, claim.envelope_key_ref,
claim.envelope_ciphertext, claim.envelope_nonce, claim.envelope_aad_hash, claim.wrapped_dek_kms,
claim.status, claim.fencing_token, claim.lease_owner, claim.lease_expires_at, claim.expires_at
FROM credential_claims claim JOIN integration_operations child ON child.id = claim.integration_operation_id
JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id = child.id
JOIN recovery_epoch_plans plan ON plan.id = progress.plan_id
JOIN seats seat ON seat.id = claim.seat_id JOIN members target ON target.id = claim.target_member_id
WHERE claim.id = $1`, claimID).Scan(&claim.ID, &claim.Key.ClientID, &claim.Key.OperationID,
		&claim.PlanExternalID, &requestHash, &claim.SeatExternalID, &claim.TargetMemberExternalID,
		&fingerprint, &claim.EnvelopeAlgorithm, &claim.EnvelopeKeyRef, &claim.EnvelopeCiphertext,
		&claim.EnvelopeNonce, &aadHash, &claim.WrappedDEK, &claim.Status, &claim.FencingToken,
		&leaseOwner, &leaseExpires, &claim.ExpiresAt)
	if err != nil {
		return nil, translateRecoveryError("load recovery credential claim", err)
	}
	if len(requestHash) != sha256.Size || len(fingerprint) != sha256.Size || len(aadHash) != sha256.Size {
		return nil, recovery.ErrInvalidState
	}
	copy(claim.PrepareRequestHash[:], requestHash)
	copy(claim.CredentialFingerprint[:], fingerprint)
	copy(claim.EnvelopeAADHash[:], aadHash)
	claim.LeaseOwner = leaseOwner.String
	if leaseExpires.Valid {
		claim.LeaseExpiresAt = &leaseExpires.Time
	}
	return &claim, nil
}

type stagedRootBinding struct {
	ID, Handle, Version, Domain, Algorithm string
	Fingerprint                            [sha256.Size]byte
}

type recoverySeatOwner struct {
	seat, owner               string
	assignment, apiKeyVersion uint64
}

func scanRecoveryPlan(row scanner) (*recovery.StoredEpochPlan, error) {
	var plan recovery.StoredEpochPlan
	var ceremony string
	var previousHash, manifestHash, ceremonyAttestationDigest []byte
	var rootID, manifestID sql.NullString
	var portableFormat, portableTrust, portableSuite, portableProof, portableAlgorithm sql.NullString
	if err := row.Scan(&plan.ID, &plan.ExternalID, &ceremony, &plan.PoolID, &plan.PoolExternalID,
		&plan.FromEpoch, &plan.ToEpoch, &plan.Status, &plan.GovernanceThreshold, &plan.RecoveryThreshold,
		&plan.ExpectedMemberCount, &plan.ExpectedResourceCount, &plan.CommittedShareCount,
		&plan.VerifiedSignatureCount, &plan.AcknowledgedShareCount, &plan.StagedBatchCount,
		&rootID, &manifestID, &manifestHash, &previousHash, &plan.CeremonyAttestationRef,
		&ceremonyAttestationDigest, &plan.CeremonyAttestationIssuer, &plan.CeremonyAttestationKeyID,
		&plan.CeremonyAttestationVersion, &portableFormat, &portableTrust, &portableSuite, &portableProof,
		&portableAlgorithm, &plan.Version, &plan.CreatedAt, &plan.UpdatedAt); err != nil {
		return nil, err
	}
	plan.CeremonyType = recovery.CeremonyType(ceremony)
	plan.RootArtifactID, plan.ManifestID = rootID.String, manifestID.String
	if len(previousHash) != sha256.Size || len(ceremonyAttestationDigest) != sha256.Size ||
		(len(manifestHash) != 0 && len(manifestHash) != sha256.Size) {
		return nil, recovery.ErrInvalidState
	}
	copy(plan.PreviousManifestHash[:], previousHash)
	copy(plan.ManifestHash[:], manifestHash)
	copy(plan.CeremonyAttestationDigest[:], ceremonyAttestationDigest)
	if portableFormat.Valid {
		plan.PortableProfile = &recovery.PortableEvidenceProfile{
			FormatVersion: portableFormat.String, RootTrustProfileID: portableTrust.String,
			CryptoSuiteID: portableSuite.String, ProviderProofProfile: portableProof.String,
			CeremonyAttestationAlgorithm: portableAlgorithm.String,
			PlatformSignatureDomain:      recovery.PlatformManifestSignatureV2,
		}
	}
	return &plan, nil
}

func loadRecoveryPlanTx(ctx context.Context, tx *sql.Tx, externalID string, lock bool) (*recovery.StoredEpochPlan, error) {
	query := `SELECT ` + recoveryPlanColumns + recoveryPlanFrom + `WHERE plan.external_id = $1`
	if lock {
		query += ` FOR UPDATE OF plan`
	}
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, query, externalID))
	if err != nil {
		return nil, translateRecoveryError("load recovery plan", err)
	}
	return plan, nil
}

func (s *Store) lockRecoveryPlan(ctx context.Context, key recovery.OperationKey, leaseOwner string,
	fence int64, expectedStatus string) (*sql.Tx, *recovery.StoredEpochPlan, error) {
	if !validRecoveryCommit(key, leaseOwner, fence) {
		return nil, nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin recovery plan stage: %w", err)
	}
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN integration_operations io ON io.id = plan.integration_operation_id
WHERE io.integration_client_id = $1 AND io.operation_id = $2 AND io.fencing_token = $3
  AND io.lease_owner = $4 AND io.lease_expires_at > CURRENT_TIMESTAMP
  AND io.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND plan.status = $5 FOR UPDATE OF io, plan`, key.ClientID, key.OperationID, fence, leaseOwner, expectedStatus))
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return nil, nil, recovery.ErrStaleFence
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("lock recovery plan stage: %w", err)
	}
	return tx, plan, nil
}

func (s *Store) lockPermanentReplacementCase(ctx context.Context, key recovery.OperationKey,
	leaseOwner string, fence int64) (*sql.Tx, *recovery.StoredEpochPlan, string, error) {
	if !validRecoveryCommit(key, leaseOwner, fence) {
		return nil, nil, "", recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("begin permanent replacement stage: %w", err)
	}
	var caseID string
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
JOIN integration_operations finalization ON finalization.id = replacement.integration_operation_id
WHERE finalization.integration_client_id = $1 AND finalization.operation_id = $2
  AND finalization.fencing_token = $3 AND finalization.lease_owner = $4
  AND finalization.lease_expires_at > CURRENT_TIMESTAMP
  AND finalization.operation_type IN ('REPLACE_PERMANENTLY', 'FINALIZE_RECOVERY_BOOTSTRAP')
  AND finalization.target_type = 'POOL'
  AND finalization.status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND replacement.status IN ('READY', 'ROTATING', 'RECONCILE_REQUIRED', 'OPERATOR_REVIEW_REQUIRED')
  AND plan.status = 'READY' FOR UPDATE OF finalization, replacement, plan`,
		key.ClientID, key.OperationID, fence, leaseOwner))
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return nil, nil, "", recovery.ErrStaleFence
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, "", fmt.Errorf("lock permanent replacement stage: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT replacement.id FROM permanent_replacement_cases replacement
JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
WHERE plan.id = $1 FOR UPDATE OF replacement`, plan.ID).Scan(&caseID); err != nil {
		tx.Rollback()
		return nil, nil, "", translateRecoveryError("lock permanent replacement case", err)
	}
	return tx, plan, caseID, nil
}

func (s *Store) lockProviderPendingCase(ctx context.Context, key recovery.OperationKey,
	leaseOwner string, fence int64) (*sql.Tx, *recovery.StoredEpochPlan, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, "", err
	}
	var caseID string
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
JOIN integration_operations finalization ON finalization.id=replacement.integration_operation_id
WHERE finalization.integration_client_id=$1 AND finalization.operation_id=$2
 AND finalization.fencing_token=$3 AND finalization.lease_owner=$4
 AND finalization.lease_expires_at>CURRENT_TIMESTAMP AND finalization.status='RUNNING'
 AND replacement.status='PROVIDER_COMMIT_PENDING' AND plan.status='FINALIZED'
FOR UPDATE OF finalization,replacement,plan`, key.ClientID, key.OperationID, fence, leaseOwner))
	if err != nil {
		tx.Rollback()
		return nil, nil, "", translateRecoveryError("lock provider pending case", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM permanent_replacement_cases WHERE plan_id=$1`, plan.ID).Scan(&caseID); err != nil {
		tx.Rollback()
		return nil, nil, "", err
	}
	return tx, plan, caseID, nil
}

func (s *Store) lockReadyToIssueCase(ctx context.Context, key recovery.OperationKey, leaseOwner string,
	fence int64) (*sql.Tx, *recovery.StoredEpochPlan, string, *application.StoredOperation, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, nil, "", nil, err
	}
	var caseID string
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2 AND fencing_token=$3 AND lease_owner=$4
 AND lease_expires_at>CURRENT_TIMESTAMP AND status='RUNNING' FOR UPDATE`, key.ClientID, key.OperationID, fence, leaseOwner))
	if err != nil {
		tx.Rollback()
		return nil, nil, "", nil, translateRecoveryError("lock READY_TO_ISSUE parent", err)
	}
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN permanent_replacement_cases replacement ON replacement.plan_id=plan.id
WHERE replacement.integration_operation_id=$1 AND replacement.status='READY_TO_ISSUE'
 AND plan.status='FINALIZED' FOR UPDATE OF replacement,plan`, op.AggregateID))
	if err != nil {
		tx.Rollback()
		return nil, nil, "", nil, translateRecoveryError("lock READY_TO_ISSUE case", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM permanent_replacement_cases WHERE plan_id=$1`, plan.ID).Scan(&caseID); err != nil {
		tx.Rollback()
		return nil, nil, "", nil, err
	}
	return tx, plan, caseID, op, nil
}

func advanceRecoveryPlan(ctx context.Context, tx *sql.Tx, planID, from, to string) error {
	if err := assertRecoveryInventorySnapshotTx(ctx, tx, planID, "revalidate recovery inventory before stage transition"); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE recovery_epoch_plans SET status = $3,
ready_at = CASE WHEN $3 = 'READY' THEN CURRENT_TIMESTAMP ELSE ready_at END,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = $2`, planID, from, to)
	if err != nil {
		return translateRecoveryError("advance recovery plan", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return recovery.ErrInvalidState
	}
	return nil
}

func assertRecoveryInventorySnapshotTx(ctx context.Context, tx *sql.Tx, planID, action string) error {
	if _, err := tx.ExecContext(ctx, `SELECT assert_recovery_plan_authoritative_snapshot($1)`, planID); err != nil {
		// 对调用方只暴露稳定错误；数据库异常细节可能包含内部资源标识。
		return fmt.Errorf("%s: %w", action, recovery.ErrInvalidState)
	}
	return nil
}

func commitAndLoadRecoveryPlan(ctx context.Context, tx *sql.Tx, externalID, action string) (*recovery.StoredEpochPlan, error) {
	plan, err := loadRecoveryPlanTx(ctx, tx, externalID, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	return plan, nil
}

func beginRecoveryLedgerOperation(ctx context.Context, tx *sql.Tx, key recovery.OperationKey, kind,
	poolExternalID string, requestHash [sha256.Size]byte, canonical []byte, lease bool,
	leaseOwner string, leaseDuration time.Duration) (*application.StoredOperation, bool, error) {
	leaseOwnerValue := any(nil)
	leaseSeconds := float64(0)
	if lease {
		leaseOwnerValue, leaseSeconds = leaseOwner, leaseDuration.Seconds()
	}
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner, lease_expires_at,
attempt_count, created_at, updated_at
)
SELECT $1, $2, $3, 'POOL', pool.id, pool.external_id, 'CURRENT', $4, $5::jsonb, 'RUNNING',
CASE WHEN $6::text IS NULL THEN 0 ELSE 1 END, $6,
CASE WHEN $6::text IS NULL THEN NULL ELSE CURRENT_TIMESTAMP + make_interval(secs => $7) END,
CASE WHEN $6::text IS NULL THEN 0 ELSE 1 END, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM pools pool WHERE pool.external_id = $8
ON CONFLICT (integration_client_id, operation_id) DO NOTHING RETURNING `+operationColumns,
		key.ClientID, key.OperationID, kind, requestHash[:], canonical, leaseOwnerValue, leaseSeconds, poolExternalID))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			key.ClientID, key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateRecoveryError("begin recovery operation", scanErr)
	}
	storedCanonical, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || op.Kind != application.OperationKind(kind) || op.TargetType != "POOL" ||
		op.TargetExternalID != poolExternalID || op.RequestHash != requestHash || !bytes.Equal(storedCanonical, canonical) {
		return nil, false, recovery.ErrHashDrift
	}
	if !created && lease && op.Status != application.OperationSucceeded {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET
lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND (lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, key.ClientID, key.OperationID, leaseOwner, leaseDuration.Seconds()))
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, false, recovery.ErrLeaseHeld
		}
		if scanErr != nil {
			return nil, false, fmt.Errorf("acquire recovery operation lease: %w", scanErr)
		}
	}
	return op, created, nil
}

func beginRecoverySeatOperation(ctx context.Context, tx *sql.Tx, key recovery.OperationKey,
	seatExternalID, operationKind string, requestHash [sha256.Size]byte, canonical []byte,
	expectedRequest recovery.PermanentSeatRotationPrepareRequest, leaseOwner string, expectedFence int64,
	leaseDuration time.Duration) (*application.StoredOperation, bool, error) {
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner, lease_expires_at,
attempt_count, created_at, updated_at
)
SELECT $1, $2, $3, 'SEAT', seat.id, seat.external_id, 'CURRENT', $4, $5::jsonb,
'RUNNING', 1, $6, CURRENT_TIMESTAMP + make_interval(secs => $7), 1,
CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM seats seat WHERE seat.external_id = $8 AND $9 = 0
ON CONFLICT (integration_client_id, operation_id) DO NOTHING RETURNING `+operationColumns,
		key.ClientID, key.OperationID, operationKind, requestHash[:], canonical, leaseOwner,
		leaseDuration.Seconds(), seatExternalID, expectedFence))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			key.ClientID, key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateRecoveryError("begin derived Seat rotation operation", scanErr)
	}
	storedCanonical, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || op.Kind != application.OperationKind(operationKind) || op.TargetType != "SEAT" ||
		op.TargetExternalID != seatExternalID || op.RequestHash != requestHash ||
		!seatPrepareSnapshotBindsRequest(storedCanonical, op.RequestHash, expectedRequest) {
		return nil, false, recovery.ErrHashDrift
	}
	if !created {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET
lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
fencing_token = CASE WHEN lease_owner = $3 AND fencing_token = $5 AND lease_expires_at > CURRENT_TIMESTAMP
                     THEN fencing_token ELSE fencing_token + 1 END,
attempt_count = CASE WHEN lease_owner = $3 AND fencing_token = $5 AND lease_expires_at > CURRENT_TIMESTAMP
                     THEN attempt_count ELSE attempt_count + 1 END,
status = 'RUNNING', error_code = NULL, error_detail = NULL, next_attempt_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $5
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND ((lease_owner = $3 AND lease_expires_at > CURRENT_TIMESTAMP) OR
       lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, key.ClientID, key.OperationID, leaseOwner, leaseDuration.Seconds(), expectedFence))
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, false, recovery.ErrLeaseHeld
		}
		if scanErr != nil {
			return nil, false, fmt.Errorf("acquire derived Seat operation lease: %w", scanErr)
		}
	}
	return op, created, nil
}

func beginRecoveryPoolChildOperation(ctx context.Context, tx *sql.Tx, key recovery.OperationKey,
	poolExternalID, operationKind string, requestHash [sha256.Size]byte, canonical []byte,
	leaseOwner string, expectedFence int64, leaseDuration time.Duration) (*application.StoredOperation, bool, error) {
	op, scanErr := scanOperation(tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner, lease_expires_at,
attempt_count, created_at, updated_at
)
SELECT $1, $2, $3, 'POOL', pool.id, pool.external_id, 'CURRENT', $4, $5::jsonb,
'RUNNING', 1, $6, CURRENT_TIMESTAMP + make_interval(secs => $7), 1,
CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM pools pool WHERE pool.external_id = $8 AND $9 = 0
ON CONFLICT (integration_client_id, operation_id) DO NOTHING RETURNING `+operationColumns,
		key.ClientID, key.OperationID, operationKind, requestHash[:], canonical, leaseOwner,
		leaseDuration.Seconds(), poolExternalID, expectedFence))
	created := scanErr == nil
	if errors.Is(scanErr, sql.ErrNoRows) {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR UPDATE`,
			key.ClientID, key.OperationID))
	}
	if scanErr != nil {
		return nil, false, translateRecoveryError("begin derived Pool operation", scanErr)
	}
	storedCanonical, err := canonicalJSONObject(op.RequestSnapshot)
	if err != nil || op.Kind != application.OperationKind(operationKind) || op.TargetType != "POOL" ||
		op.TargetExternalID != poolExternalID || op.RequestHash != requestHash || !bytes.Equal(storedCanonical, canonical) {
		return nil, false, recovery.ErrHashDrift
	}
	if !created {
		op, scanErr = scanOperation(tx.QueryRowContext(ctx, `UPDATE integration_operations SET
lease_owner = $3, lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $4),
fencing_token = CASE WHEN lease_owner = $3 AND fencing_token = $5 AND lease_expires_at > CURRENT_TIMESTAMP
                     THEN fencing_token ELSE fencing_token + 1 END,
attempt_count = CASE WHEN lease_owner = $3 AND fencing_token = $5 AND lease_expires_at > CURRENT_TIMESTAMP
                     THEN attempt_count ELSE attempt_count + 1 END,
status = 'RUNNING', error_code = NULL, error_detail = NULL, next_attempt_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $5
  AND status IN ('RUNNING', 'RETRYABLE', 'RECONCILE_REQUIRED')
  AND ((lease_owner = $3 AND lease_expires_at > CURRENT_TIMESTAMP) OR
       lease_expires_at IS NULL OR lease_expires_at <= CURRENT_TIMESTAMP)
RETURNING `+operationColumns, key.ClientID, key.OperationID, leaseOwner, leaseDuration.Seconds(), expectedFence))
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, false, recovery.ErrLeaseHeld
		}
		if scanErr != nil {
			return nil, false, fmt.Errorf("acquire derived Pool operation lease: %w", scanErr)
		}
	}
	return op, created, nil
}

func loadSeatPrepareRequestsTx(ctx context.Context, tx *sql.Tx,
	plan *recovery.StoredEpochPlan) ([]recovery.PermanentSeatRotationPrepareRequest, error) {
	rows, err := tx.QueryContext(ctx, `SELECT operation.operation_id, operation.request_hash,
seat.external_id, target.external_id, planned.expected_assignment_epoch,
COALESCE(seat.sub2api_principal_id, 0), COALESCE(seat.sub2api_subscription_id, 0),
COALESCE(seat.sub2api_api_key_id, 0), planned.expected_active_api_key_version
FROM recovery_plan_seats planned
JOIN recovery_seat_rotation_progress progress
  ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
JOIN integration_operations operation ON operation.id = progress.derived_operation_id
JOIN seats seat ON seat.id = planned.seat_id JOIN members target ON target.id = planned.to_member_id
WHERE planned.plan_id = $1 AND progress.status IN
  ('PREPARE_PENDING', 'PREPARE_RETRYABLE', 'PREPARE_RECONCILE_REQUIRED', 'PREPARED')
ORDER BY seat.external_id FOR SHARE OF planned, progress, operation, seat, target`, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("load Pool preparation child set: %w", err)
	}
	defer rows.Close()
	requests := make([]recovery.PermanentSeatRotationPrepareRequest, 0, plan.ExpectedMemberCount)
	for rows.Next() {
		var item recovery.PermanentSeatRotationPrepareRequest
		var requestHash []byte
		item.ProtocolVersion = recovery.PermanentSeatRotationProtocolV1
		item.PlanID, item.CeremonyType, item.PoolID = plan.ExternalID, plan.CeremonyType, plan.PoolExternalID
		item.FromEpoch, item.ToEpoch = plan.FromEpoch, plan.ToEpoch
		if err := rows.Scan(&item.OperationID, &requestHash, &item.SeatID, &item.TargetMemberID,
			&item.ExpectedAssignmentEpoch, &item.PrincipalUserID, &item.SubscriptionID, &item.APIKeyID,
			&item.FromAPIKeyVersion); err != nil {
			return nil, fmt.Errorf("scan Pool preparation child set: %w", err)
		}
		item.ToAPIKeyVersion = item.FromAPIKeyVersion + 1
		copy(item.RequestHash[:], requestHash)
		if item.RequestHash != recovery.PermanentSeatRotationPrepareRequestHash(item) {
			return nil, recovery.ErrBindingMismatch
		}
		requests = append(requests, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Pool preparation child set: %w", err)
	}
	if len(requests) != plan.ExpectedMemberCount {
		return nil, recovery.ErrInvalidState
	}
	return requests, nil
}

func loadSeatPrepareRequestTx(ctx context.Context, tx *sql.Tx, plan *recovery.StoredEpochPlan,
	seatExternalID, operationID string) (recovery.PermanentSeatRotationPrepareRequest, error) {
	request := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1, OperationID: operationID,
		PlanID: plan.ExternalID, CeremonyType: plan.CeremonyType, PoolID: plan.PoolExternalID,
		FromEpoch: plan.FromEpoch, ToEpoch: plan.ToEpoch,
	}
	err := tx.QueryRowContext(ctx, `SELECT target.external_id, planned.expected_assignment_epoch,
COALESCE(seat.sub2api_principal_id, 0), COALESCE(seat.sub2api_subscription_id, 0),
COALESCE(seat.sub2api_api_key_id, 0), planned.expected_active_api_key_version
FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id
WHERE planned.plan_id = $1 AND seat.external_id = $2`, plan.ID, seatExternalID).
		Scan(&request.TargetMemberID, &request.ExpectedAssignmentEpoch, &request.PrincipalUserID,
			&request.SubscriptionID, &request.APIKeyID, &request.FromAPIKeyVersion)
	if err != nil {
		return request, translateRecoveryError("load exact Seat prepare intent", err)
	}
	request.SeatID = seatExternalID
	request.ToAPIKeyVersion = request.FromAPIKeyVersion + 1
	return request, nil
}

func canonicalRecoveryProtocolSnapshot(hash [sha256.Size]byte, snapshot []byte) ([]byte, error) {
	if zeroRecoveryHash(hash) {
		return nil, recovery.ErrInvalidData
	}
	canonical, err := canonicalJSONObject(snapshot)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	return canonical, nil
}

func seatPrepareSnapshotBindsRequest(canonical []byte, storedHash [sha256.Size]byte,
	request recovery.PermanentSeatRotationPrepareRequest) bool {
	return seatPrepareSnapshotBindsRequestMode(canonical, storedHash, request, true)
}

func typedSeatPrepareSnapshotBindsRequest(canonical []byte, storedHash [sha256.Size]byte,
	request recovery.PermanentSeatRotationPrepareRequest) bool {
	return seatPrepareSnapshotBindsRequestMode(canonical, storedHash, request, false)
}

func seatPrepareSnapshotBindsRequestMode(canonical []byte, storedHash [sha256.Size]byte,
	request recovery.PermanentSeatRotationPrepareRequest, allowLegacy bool) bool {
	expectedHash := recovery.PermanentSeatRotationPrepareRequestHash(request)
	if storedHash != expectedHash || request.RequestHash != expectedHash {
		return false
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(canonical, &payload) != nil {
		return false
	}
	// Manager persists the canonical JSON encoding of the typed request. Decode
	// that exact representation first so aliases cannot override typed fields.
	typedRaw, err := json.Marshal(request)
	if err != nil {
		return false
	}
	var typedShape map[string]json.RawMessage
	if json.Unmarshal(typedRaw, &typedShape) != nil {
		return false
	}
	var typed recovery.PermanentSeatRotationPrepareRequest
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if sameRecoverySnapshotKeys(payload, typedShape) && decoder.Decode(&typed) == nil &&
		decoder.Decode(&struct{}{}) == io.EOF &&
		reflect.DeepEqual(typed, request) {
		return true
	}
	if !allowLegacy {
		return false
	}
	// The original compatibility shape contained exactly these seven stable
	// identifiers. The separately persisted domain hash above binds every omitted
	// numeric identity and version field. Unknown keys remain fail-closed.
	checks := map[string]string{
		"protocol_version": "trusted-pool/permanent-seat-prepare/v1",
		"plan_id":          request.PlanID, "pool_id": request.PoolID,
		"seat_id": request.SeatID, "target_member_id": request.TargetMemberID,
	}
	if len(payload) != 7 {
		return false
	}
	for key, expected := range checks {
		var value string
		if json.Unmarshal(payload[key], &value) != nil || value != expected {
			return false
		}
	}
	for key, expected := range map[string]uint64{
		"from_epoch": request.FromEpoch, "to_epoch": request.ToEpoch,
	} {
		var value uint64
		if json.Unmarshal(payload[key], &value) != nil || value != expected {
			return false
		}
	}
	return true
}

func sameRecoverySnapshotKeys(left, right map[string]json.RawMessage) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, exists := right[key]; !exists {
			return false
		}
	}
	return true
}

func loadPreparedActivationBindingsTx(ctx context.Context, tx *sql.Tx,
	plan *recovery.StoredEpochPlan) ([]recovery.PermanentSeatActivationBinding, error) {
	return loadActivationBindingsTx(ctx, tx, plan, "PREPARED")
}

func loadCommittedActivationBindingsTx(ctx context.Context, tx *sql.Tx,
	plan *recovery.StoredEpochPlan) ([]recovery.PermanentSeatActivationBinding, error) {
	return loadActivationBindingsTx(ctx, tx, plan, "COMMITTED")
}

func loadActivationBindingsTx(ctx context.Context, tx *sql.Tx, plan *recovery.StoredEpochPlan,
	progressStatus string) ([]recovery.PermanentSeatActivationBinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT seat.external_id, target.external_id,
planned.expected_assignment_epoch, progress.principal_user_id, progress.subscription_id,
progress.api_key_id, progress.api_key_version, operation.operation_id, operation.request_hash,
progress.credential_fingerprint, progress.prepared_reference
FROM recovery_plan_seats planned
JOIN recovery_seat_rotation_progress progress
  ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
JOIN integration_operations operation ON operation.id = progress.derived_operation_id
JOIN seats seat ON seat.id = planned.seat_id JOIN members target ON target.id = planned.to_member_id
WHERE planned.plan_id = $1 AND progress.status = $2 AND operation.status = 'SUCCEEDED'
  AND progress.api_key_version = planned.expected_active_api_key_version + 1
ORDER BY seat.external_id FOR SHARE OF planned, progress, operation, seat, target`, plan.ID, progressStatus)
	if err != nil {
		return nil, fmt.Errorf("load prepared activation set: %w", err)
	}
	defer rows.Close()
	bindings := make([]recovery.PermanentSeatActivationBinding, 0, plan.ExpectedMemberCount)
	for rows.Next() {
		var item recovery.PermanentSeatActivationBinding
		var requestHash, fingerprint []byte
		if err := rows.Scan(&item.SeatID, &item.TargetMemberID, &item.ExpectedAssignmentEpoch,
			&item.PrincipalUserID, &item.SubscriptionID, &item.APIKeyID, &item.ActiveAPIKeyVersion,
			&item.ChildOperationID, &requestHash, &fingerprint, &item.PreparedRotationRef); err != nil {
			return nil, fmt.Errorf("scan prepared activation set: %w", err)
		}
		if len(requestHash) != sha256.Size || len(fingerprint) != sha256.Size {
			return nil, recovery.ErrInvalidState
		}
		copy(item.ChildRequestHash[:], requestHash)
		copy(item.CredentialFingerprint[:], fingerprint)
		bindings = append(bindings, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate prepared activation set: %w", err)
	}
	if len(bindings) != plan.ExpectedMemberCount {
		return nil, recovery.ErrInvalidState
	}
	return bindings, nil
}

func uniquePoolActivatedSeats(values []recovery.PoolActivatedSeat) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || !validRecoveryID(value.TargetMemberExternalID) ||
			!validRecoveryID(value.PreparedReference) || value.PrincipalUserID <= 0 ||
			value.SubscriptionID <= 0 || value.APIKeyID <= 0 || value.APIKeyVersion == 0 ||
			zeroRecoveryHash(value.CredentialFingerprint) || value.CurrentConcurrency != 0 ||
			value.PendingSettlements != 0 {
			return false
		}
		if _, exists := seen[value.SeatExternalID]; exists {
			return false
		}
		seen[value.SeatExternalID] = struct{}{}
	}
	return true
}

func validateReplacementClaimActivations(values []recovery.ReplacementClaimActivation) (map[string]recovery.ReplacementClaimActivation, error) {
	if len(values) == 0 {
		return nil, recovery.ErrInvalidData
	}
	now := time.Now().UTC()
	bySeat := make(map[string]recovery.ReplacementClaimActivation, len(values))
	operations := make(map[string]struct{}, len(values))
	tokens := make(map[[sha256.Size]byte]struct{}, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || !validRecoveryID(value.ClaimOperationID) ||
			zeroRecoveryHash(value.TokenHash) || !value.ExpiresAt.After(now) ||
			value.ExpiresAt.After(now.Add(recovery.MaxReplacementClaimTTL)) {
			return nil, recovery.ErrInvalidData
		}
		if _, exists := bySeat[value.SeatExternalID]; exists {
			return nil, recovery.ErrInvalidData
		}
		if _, exists := operations[value.ClaimOperationID]; exists {
			return nil, recovery.ErrInvalidData
		}
		if _, exists := tokens[value.TokenHash]; exists {
			return nil, recovery.ErrInvalidData
		}
		bySeat[value.SeatExternalID] = value
		operations[value.ClaimOperationID] = struct{}{}
		tokens[value.TokenHash] = struct{}{}
	}
	return bySeat, nil
}

func validateReplacementClaimIntents(values []recovery.ReplacementClaimIntent) (map[string]recovery.ReplacementClaimIntent, error) {
	result := make(map[string]recovery.ReplacementClaimIntent, len(values))
	operations := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || !validRecoveryID(value.ClaimOperationID) {
			return nil, recovery.ErrInvalidData
		}
		if _, ok := result[value.SeatExternalID]; ok {
			return nil, recovery.ErrInvalidData
		}
		if _, ok := operations[value.ClaimOperationID]; ok {
			return nil, recovery.ErrInvalidData
		}
		result[value.SeatExternalID] = value
		operations[value.ClaimOperationID] = struct{}{}
	}
	if len(result) == 0 {
		return nil, recovery.ErrInvalidData
	}
	return result, nil
}

func replacementPendingClaimIntentHash(clientID, planID, childOperationID, seatID, targetMemberID,
	claimOperationID string, fingerprint []byte) [sha256.Size]byte {
	encoded, _ := json.Marshal([]any{"trusted-pool/replacement-claim-pending/v1", clientID, planID,
		childOperationID, seatID, targetMemberID, claimOperationID, fmt.Sprintf("%x", fingerprint)})
	return sha256.Sum256(encoded)
}

func refreshPendingReplacementClaimsTx(ctx context.Context, tx *sql.Tx, finalizationID, clientID string,
	claims map[string]recovery.ReplacementClaimActivation) error {
	rows, err := tx.QueryContext(ctx, `SELECT claim.id, seat.external_id, claim.claim_operation_id,
plan.external_id, child.operation_id, target.external_id, claim.credential_fingerprint
FROM permanent_replacement_cases replacement JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
JOIN recovery_seat_rotation_progress progress ON progress.plan_id = plan.id
JOIN credential_claims claim ON claim.id = progress.credential_claim_id
JOIN integration_operations child ON child.id = claim.integration_operation_id
JOIN seats seat ON seat.id = claim.seat_id JOIN members target ON target.id = claim.target_member_id
WHERE replacement.integration_operation_id = $1 AND replacement.status = 'READY_TO_ISSUE'
  AND claim.status = 'ISSUANCE_PENDING' AND claim.lease_owner IS NULL
ORDER BY seat.external_id FOR UPDATE OF claim`, finalizationID)
	if err != nil {
		return fmt.Errorf("lock pending-release claims: %w", err)
	}
	type pending struct {
		id, seat, claimOp, plan, childOp, target string
		fingerprint                              []byte
	}
	items := make([]pending, 0, len(claims))
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.seat, &item.claimOp, &item.plan, &item.childOp,
			&item.target, &item.fingerprint); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	rows.Close()
	if len(items) != len(claims) {
		return recovery.ErrBindingMismatch
	}
	for _, item := range items {
		claim, ok := claims[item.seat]
		if !ok || claim.ClaimOperationID != item.claimOp {
			return recovery.ErrBindingMismatch
		}
		intent := replacementClaimIntentHash(clientID, item.plan, item.childOp, item.seat, item.target, claim, item.fingerprint)
		result, err := tx.ExecContext(ctx, `UPDATE credential_claims SET status = 'READY', claim_token_hash = $2,
claim_intent_hash = $3, expires_at = $4, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'ISSUANCE_PENDING' AND lease_owner IS NULL`, item.id, claim.TokenHash[:], intent[:], claim.ExpiresAt)
		if err != nil {
			return translateRecoveryError("refresh pending-release claim token", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return recovery.ErrInvalidState
		}
	}
	return nil
}

func replacementClaimIntentHash(clientID, planID, childOperationID, seatID, targetMemberID string,
	claim recovery.ReplacementClaimActivation, fingerprint []byte) [sha256.Size]byte {
	payload := struct {
		Version          int    `json:"version"`
		ClientID         string `json:"client_id"`
		PlanID           string `json:"plan_id"`
		ChildOperationID string `json:"child_operation_id"`
		SeatID           string `json:"seat_id"`
		TargetMemberID   string `json:"target_member_id"`
		ClaimOperationID string `json:"claim_operation_id"`
		TokenHash        string `json:"token_hash"`
		Fingerprint      string `json:"credential_fingerprint"`
		ExpiresAt        string `json:"expires_at"`
	}{1, clientID, planID, childOperationID, seatID, targetMemberID, claim.ClaimOperationID,
		fmt.Sprintf("%x", claim.TokenHash[:]), fmt.Sprintf("%x", fingerprint), claim.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	encoded, _ := json.Marshal(payload)
	return sha256.Sum256(encoded)
}

func rotationSnapshotBindsRequest(canonical []byte, hashField string,
	setHash [sha256.Size]byte, request any) bool {
	var actualShape map[string]json.RawMessage
	if json.Unmarshal(canonical, &actualShape) != nil {
		return false
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return false
	}
	var expectedShape map[string]json.RawMessage
	if json.Unmarshal(raw, &expectedShape) != nil {
		return false
	}
	projection, err := json.Marshal(hex.EncodeToString(setHash[:]))
	if err != nil {
		return false
	}
	expectedShape[hashField] = projection
	if !sameRecoverySnapshotKeys(actualShape, expectedShape) {
		return false
	}
	expectedRaw, err := json.Marshal(expectedShape)
	if err != nil {
		return false
	}
	expectedCanonical, err := canonicalJSONObject(expectedRaw)
	return err == nil && bytes.Equal(canonical, expectedCanonical)
}

func toRecoveryOperation(op *application.StoredOperation) *recovery.StoredOperation {
	if op == nil {
		return nil
	}
	return &recovery.StoredOperation{AggregateID: op.AggregateID,
		Key:  recovery.OperationKey{ClientID: op.Key.ClientID, OperationID: op.Key.OperationID},
		Kind: string(op.Kind), Status: string(op.Status), FencingToken: op.FencingToken,
		LeaseOwner: op.LeaseOwner, LeaseExpiresAt: op.LeaseExpiresAt, RequestHash: op.RequestHash,
		RequestSnapshot:  append([]byte(nil), op.RequestSnapshot...),
		ResponseSnapshot: append([]byte(nil), op.ResultSnapshot...), ErrorCode: op.ErrorCode}
}

func loadSeatRotationProgressTx(ctx context.Context, tx *sql.Tx, operationID string) (*recovery.StoredSeatRotationProgress, error) {
	var result recovery.StoredSeatRotationProgress
	var fingerprint, providerDigest []byte
	err := tx.QueryRowContext(ctx, `SELECT progress.id, plan.external_id, pool.external_id,
plan.from_epoch, plan.to_epoch, seat.external_id, target.external_id,
planned.expected_assignment_epoch, COALESCE(seat.sub2api_principal_id, 0),
COALESCE(seat.sub2api_subscription_id, 0), COALESCE(seat.sub2api_api_key_id, 0),
planned.expected_active_api_key_version,
io.operation_id, progress.status, COALESCE(progress.principal_user_id, 0),
COALESCE(progress.subscription_id, 0), COALESCE(progress.api_key_id, 0),
COALESCE(progress.api_key_version, 0), progress.credential_fingerprint,
COALESCE(progress.prepared_reference, ''), progress.provider_result_digest,
progress.attempt_count, COALESCE(progress.error_code, ''), progress.updated_at
FROM recovery_seat_rotation_progress progress JOIN recovery_epoch_plans plan ON plan.id = progress.plan_id
JOIN pools pool ON pool.id = plan.pool_id
JOIN recovery_plan_seats planned ON planned.plan_id = progress.plan_id AND planned.seat_id = progress.seat_id
JOIN members target ON target.id = planned.to_member_id
JOIN seats seat ON seat.id = progress.seat_id JOIN integration_operations io ON io.id = progress.derived_operation_id
WHERE progress.derived_operation_id = $1`, operationID).Scan(&result.ID, &result.PlanExternalID,
		&result.PoolExternalID, &result.FromEpoch, &result.ToEpoch, &result.SeatExternalID,
		&result.TargetMemberExternalID, &result.ExpectedAssignmentEpoch, &result.ExpectedPrincipalUserID,
		&result.ExpectedSubscriptionID, &result.ExpectedAPIKeyID, &result.ExpectedAPIKeyVersion,
		&result.DerivedOperationID, &result.Status, &result.PrincipalUserID,
		&result.SubscriptionID, &result.APIKeyID, &result.APIKeyVersion, &fingerprint,
		&result.PreparedReference, &providerDigest, &result.AttemptCount, &result.ErrorCode, &result.UpdatedAt)
	if err != nil {
		return nil, translateRecoveryError("load Seat rotation progress", err)
	}
	copy(result.CredentialFingerprint[:], fingerprint)
	copy(result.ProviderResultDigest[:], providerDigest)
	return &result, nil
}

func loadPermanentReplacementTargetTx(ctx context.Context, tx *sql.Tx,
	op *application.StoredOperation) (*recovery.PermanentReplacementTarget, error) {
	var caseExternalID, caseStatus string
	plan, err := scanRecoveryPlan(tx.QueryRowContext(ctx, `SELECT `+recoveryPlanColumns+recoveryPlanFrom+`
JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
WHERE replacement.integration_operation_id = $1`, op.AggregateID))
	if err != nil {
		return nil, translateRecoveryError("load permanent replacement plan", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT external_id, status FROM permanent_replacement_cases
WHERE integration_operation_id = $1`, op.AggregateID).Scan(&caseExternalID, &caseStatus); err != nil {
		return nil, translateRecoveryError("load permanent replacement case", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT COALESCE(progress.id::text, ''), plan.external_id,
pool.external_id, plan.from_epoch, plan.to_epoch, seat.external_id, target.external_id,
planned.expected_assignment_epoch, COALESCE(seat.sub2api_principal_id, 0),
COALESCE(seat.sub2api_subscription_id, 0), COALESCE(seat.sub2api_api_key_id, 0),
planned.expected_active_api_key_version, COALESCE(child.operation_id, ''), COALESCE(progress.status, ''),
COALESCE(progress.principal_user_id, 0), COALESCE(progress.subscription_id, 0),
COALESCE(progress.api_key_id, 0), COALESCE(progress.api_key_version, 0),
progress.credential_fingerprint, COALESCE(progress.prepared_reference, ''), progress.provider_result_digest,
COALESCE(progress.attempt_count, 0), COALESCE(progress.error_code, ''),
COALESCE(progress.updated_at, plan.updated_at)
FROM recovery_plan_seats planned JOIN recovery_epoch_plans plan ON plan.id = planned.plan_id
JOIN pools pool ON pool.id = plan.pool_id JOIN seats seat ON seat.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id
LEFT JOIN recovery_seat_rotation_progress progress
  ON progress.plan_id = planned.plan_id AND progress.seat_id = planned.seat_id
LEFT JOIN integration_operations child ON child.id = progress.derived_operation_id
WHERE planned.plan_id = $1 ORDER BY seat.external_id`, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("load permanent replacement Seat progress: %w", err)
	}
	seatTargets := make([]recovery.SeatRotationTarget, 0, plan.ExpectedMemberCount)
	for rows.Next() {
		var item recovery.StoredSeatRotationProgress
		var fingerprint, providerDigest []byte
		if err := rows.Scan(&item.ID, &item.PlanExternalID, &item.PoolExternalID, &item.FromEpoch,
			&item.ToEpoch, &item.SeatExternalID, &item.TargetMemberExternalID,
			&item.ExpectedAssignmentEpoch, &item.ExpectedPrincipalUserID, &item.ExpectedSubscriptionID,
			&item.ExpectedAPIKeyID, &item.ExpectedAPIKeyVersion, &item.DerivedOperationID, &item.Status,
			&item.PrincipalUserID, &item.SubscriptionID, &item.APIKeyID, &item.APIKeyVersion,
			&fingerprint, &item.PreparedReference, &providerDigest, &item.AttemptCount,
			&item.ErrorCode, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan permanent replacement Seat progress: %w", err)
		}
		copy(item.CredentialFingerprint[:], fingerprint)
		copy(item.ProviderResultDigest[:], providerDigest)
		seatTargets = append(seatTargets, recovery.SeatRotationTarget{Progress: &item})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate permanent replacement Seat progress: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close permanent replacement Seat progress: %w", err)
	}
	for index := range seatTargets {
		if seatTargets[index].Progress.DerivedOperationID == "" {
			continue
		}
		child, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2`,
			op.Key.ClientID, seatTargets[index].Progress.DerivedOperationID))
		if err != nil {
			return nil, translateRecoveryError("load Seat child operation", err)
		}
		seatTargets[index].Operation = toRecoveryOperation(child)
	}
	loadOptionalPoolOperation := func(table string) (*recovery.StoredOperation, error) {
		if table != "recovery_pool_preparation_attempts" && table != "recovery_pool_activation_attempts" &&
			table != "recovery_pool_provider_commit_attempts" {
			return nil, recovery.ErrInvalidData
		}
		var poolOperationID string
		err := tx.QueryRowContext(ctx, `SELECT integration_operation_id FROM `+table+`
WHERE plan_id = $1`, plan.ID).Scan(&poolOperationID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, translateRecoveryError("load Pool child operation", err)
		}
		poolOp, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE id = $1`, poolOperationID))
		if err != nil {
			return nil, translateRecoveryError("load Pool child operation ledger", err)
		}
		return toRecoveryOperation(poolOp), nil
	}
	preparation, err := loadOptionalPoolOperation("recovery_pool_preparation_attempts")
	if err != nil {
		return nil, err
	}
	activation, err := loadOptionalPoolOperation("recovery_pool_activation_attempts")
	if err != nil {
		return nil, err
	}
	providerRelease, err := loadOptionalPoolOperation("recovery_pool_provider_commit_attempts")
	if err != nil {
		return nil, err
	}
	return &recovery.PermanentReplacementTarget{Operation: toRecoveryOperation(op), Plan: plan,
		CaseExternalID: caseExternalID, CaseStatus: caseStatus, SeatTargets: seatTargets,
		Preparation: preparation, Activation: activation, ProviderRelease: providerRelease}, nil
}

func loadCompletedPermanentReplacementReplay(ctx context.Context, tx *sql.Tx, key recovery.OperationKey,
	operationKind string, requestHash [sha256.Size]byte, canonical []byte, caseExternalID,
	planExternalID string) (*recovery.PermanentReplacementTarget, bool, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+`
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2 FOR SHARE`,
		key.ClientID, key.OperationID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, translateRecoveryError("load completed finalization replay", err)
	}
	storedCanonical, canonicalErr := canonicalJSONObject(op.RequestSnapshot)
	if string(op.Kind) != operationKind || op.RequestHash != requestHash || canonicalErr != nil ||
		!bytes.Equal(storedCanonical, canonical) {
		return nil, false, recovery.ErrHashDrift
	}
	if string(op.Status) != "SUCCEEDED" {
		return nil, false, nil
	}
	var storedCaseID, storedPlanID string
	if err := tx.QueryRowContext(ctx, `SELECT replacement.external_id, plan.external_id
FROM permanent_replacement_cases replacement JOIN recovery_epoch_plans plan ON plan.id = replacement.plan_id
WHERE replacement.integration_operation_id = $1`, op.AggregateID).Scan(&storedCaseID, &storedPlanID); err != nil {
		return nil, false, translateRecoveryError("bind completed finalization replay", err)
	}
	if storedCaseID != caseExternalID || storedPlanID != planExternalID {
		return nil, false, recovery.ErrHashDrift
	}
	target, err := loadPermanentReplacementTargetTx(ctx, tx, op)
	return target, err == nil, err
}

func validateRecoveryIntent(key recovery.OperationKey, hash [sha256.Size]byte, snapshot []byte) ([]byte, error) {
	if !validRecoveryID(key.ClientID) || !validRecoveryID(key.OperationID) || zeroRecoveryHash(hash) {
		return nil, recovery.ErrInvalidData
	}
	canonical, err := canonicalJSONObject(snapshot)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	if sha256.Sum256(canonical) != hash {
		return nil, recovery.ErrHashDrift
	}
	return canonical, nil
}

func canonicalPermanentReplacement(input recovery.BeginPermanentReplacementInput) ([]byte, error) {
	return validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
}

func uniqueReplacementIntents(values []recovery.SeatReplacementIntent) bool {
	seats := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || !validRecoveryID(value.TargetMemberExternalID) {
			return false
		}
		if _, exists := seats[value.SeatExternalID]; exists {
			return false
		}
		seats[value.SeatExternalID] = struct{}{}
	}
	return true
}

func uniqueRecoveryIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRecoveryID(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// 控制权证明的幂等快照由持久层按类型化字段生成，调用方不能用无关 JSON 复用同一操作键。
func canonicalControlEvidence(input recovery.IssueControlEvidenceInput) ([]byte, error) {
	type canonicalBatchReference struct {
		EpochRole       string `json:"epoch_role"`
		BatchType       string `json:"batch_type"`
		BatchExternalID string `json:"batch_external_id"`
	}
	type canonicalEvidenceIntent struct {
		EvidenceExternalID                 string                    `json:"evidence_external_id"`
		PlanExternalID                     string                    `json:"plan_external_id"`
		ResourceExternalID                 string                    `json:"resource_external_id"`
		ProviderAttestationRef             string                    `json:"provider_attestation_ref"`
		ProviderAttestationDigest          string                    `json:"provider_attestation_digest"`
		ProviderAttestationIssuer          string                    `json:"provider_attestation_issuer"`
		ProviderAttestationKeyID           string                    `json:"provider_attestation_key_id"`
		ProviderAttestationVersion         uint64                    `json:"provider_attestation_version"`
		ProviderAttestationAlgorithm       string                    `json:"provider_attestation_algorithm"`
		ProviderAttestationSignature       []byte                    `json:"provider_attestation_signature"`
		ProviderAttestationProtocolVersion string                    `json:"provider_attestation_protocol_version"`
		BatchReferences                    []canonicalBatchReference `json:"batch_references"`
	}
	references := make([]canonicalBatchReference, len(input.BatchReferences))
	for index, reference := range input.BatchReferences {
		references[index] = canonicalBatchReference(reference)
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].EpochRole != references[j].EpochRole {
			return references[i].EpochRole < references[j].EpochRole
		}
		if references[i].BatchType != references[j].BatchType {
			return references[i].BatchType < references[j].BatchType
		}
		return references[i].BatchExternalID < references[j].BatchExternalID
	})
	expectedJSON, err := json.Marshal(canonicalEvidenceIntent{
		EvidenceExternalID:                 input.EvidenceExternalID,
		PlanExternalID:                     input.PlanExternalID,
		ResourceExternalID:                 input.ResourceExternalID,
		ProviderAttestationRef:             input.ProviderAttestationRef,
		ProviderAttestationDigest:          fmt.Sprintf("%x", input.ProviderAttestationDigest[:]),
		ProviderAttestationIssuer:          input.ProviderAttestationIssuer,
		ProviderAttestationKeyID:           input.ProviderAttestationKeyID,
		ProviderAttestationVersion:         input.ProviderAttestationVersion,
		ProviderAttestationAlgorithm:       input.ProviderAttestationAlgorithm,
		ProviderAttestationSignature:       input.ProviderAttestationSignature,
		ProviderAttestationProtocolVersion: input.ProviderAttestationProtocolVersion,
		BatchReferences:                    references,
	})
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	expected, err := canonicalJSONObject(expectedJSON)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	actual, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(actual, expected) {
		return nil, recovery.ErrHashDrift
	}
	return expected, nil
}

func validRecoveryID(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) > 0 && len(value) <= 1024 && !strings.ContainsRune(value, '\x00')
}

func zeroRecoveryHash(value [sha256.Size]byte) bool { return value == ([sha256.Size]byte{}) }

func validRecoveryCommit(key recovery.OperationKey, owner string, fence int64) bool {
	return validRecoveryID(key.ClientID) && validRecoveryID(key.OperationID) && validRecoveryID(owner) && fence > 0
}

func sourceGovernanceState(ceremony recovery.CeremonyType) string {
	if ceremony == recovery.CeremonyBootstrap {
		return "LEGACY_UNVERIFIED"
	}
	return "CURRENT"
}

func validateEpochMembers(members []recovery.EpochMember) error {
	seats, memberIDs, indexes := map[string]struct{}{}, map[string]struct{}{}, map[uint16]struct{}{}
	for _, member := range members {
		if !validRecoveryID(member.SeatExternalID) || !validRecoveryID(member.MemberExternalID) ||
			(member.Role != "MEMBER" && member.Role != "OWNER") || member.ShareIndex == 0 ||
			!validRecoveryID(member.SigningAlgorithm) || !validRecoveryID(member.SigningKeyID) ||
			len(member.SigningPublicKey) == 0 || zeroRecoveryHash(member.SigningKeyFingerprint) ||
			!validRecoveryID(member.SigningProofAlgorithm) || len(member.SigningProof) == 0 ||
			!validRecoveryID(member.RecoveryKeyAlgorithm) || !validRecoveryID(member.RecoveryKeyID) ||
			len(member.RecoveryEncryptionPublicKey) == 0 || zeroRecoveryHash(member.RecoveryKeyFingerprint) ||
			!validRecoveryID(member.RecoveryKeyProofAlgorithm) || len(member.RecoveryKeyProof) == 0 ||
			member.SigningKeyID == member.RecoveryKeyID ||
			member.SigningKeyFingerprint == member.RecoveryKeyFingerprint {
			return recovery.ErrInvalidData
		}
		if _, ok := seats[member.SeatExternalID]; ok {
			return recovery.ErrInvalidData
		}
		if _, ok := memberIDs[member.MemberExternalID]; ok {
			return recovery.ErrInvalidData
		}
		if _, ok := indexes[member.ShareIndex]; ok {
			return recovery.ErrInvalidData
		}
		seats[member.SeatExternalID], memberIDs[member.MemberExternalID], indexes[member.ShareIndex] = struct{}{}, struct{}{}, struct{}{}
	}
	return nil
}

func validateEpochFreezes(values []recovery.EpochSeatFreeze) (map[string]recovery.EpochSeatFreeze, error) {
	result := make(map[string]recovery.EpochSeatFreeze, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || value.ExpectedAssignmentEpoch == 0 ||
			!validRecoveryID(value.FreezeOperationID) || zeroRecoveryHash(value.FreezeSnapshotHash) {
			return nil, recovery.ErrInvalidData
		}
		if _, exists := result[value.SeatExternalID]; exists {
			return nil, recovery.ErrInvalidData
		}
		result[value.SeatExternalID] = value
	}
	return result, nil
}

func validateEpochReplacements(values []recovery.EpochSeatReplacement) (map[string]recovery.EpochSeatReplacement, error) {
	result := make(map[string]recovery.EpochSeatReplacement, len(values))
	for _, value := range values {
		if !validRecoveryID(value.SeatExternalID) || !validRecoveryID(value.FromMemberExternalID) ||
			!validRecoveryID(value.ToMemberExternalID) || value.FromMemberExternalID == value.ToMemberExternalID {
			return nil, recovery.ErrInvalidData
		}
		if _, exists := result[value.SeatExternalID]; exists {
			return nil, recovery.ErrInvalidData
		}
		result[value.SeatExternalID] = value
	}
	return result, nil
}

func countChangedOwners(owners []recoverySeatOwner, replacements map[string]recovery.EpochSeatReplacement) int {
	count := 0
	for _, owner := range owners {
		if _, ok := replacements[owner.seat]; ok {
			count++
		}
	}
	return count
}

func validateShareDeliveries(values []recovery.ShareDeliveryInput) error {
	seenMember, seenIndex, seenID := map[string]struct{}{}, map[uint16]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		if !validRecoveryID(value.ExternalID) || !validRecoveryID(value.MemberExternalID) || value.ShareIndex == 0 ||
			!validRecoveryID(value.EncryptionAlgorithm) || !validRecoveryID(value.RecipientKeyID) ||
			zeroRecoveryHash(value.RecipientKeyFingerprint) || len(value.Ciphertext) == 0 ||
			sha256.Sum256(value.Ciphertext) != value.CiphertextHash || len(value.ProviderShareCommitment) == 0 ||
			zeroRecoveryHash(value.ProviderProofDigest) || len(value.ProviderProofSignature) == 0 ||
			!validRecoveryID(value.PortableProofAlgorithm) || !validRecoveryID(value.PortableProofKeyID) ||
			!validRecoveryID(value.PortableProofProtocolVersion) || len(value.PortableProofSignature) == 0 {
			return recovery.ErrInvalidData
		}
		if _, ok := seenMember[value.MemberExternalID]; ok {
			return recovery.ErrInvalidData
		}
		if _, ok := seenIndex[value.ShareIndex]; ok {
			return recovery.ErrInvalidData
		}
		if _, ok := seenID[value.ExternalID]; ok {
			return recovery.ErrInvalidData
		}
		seenMember[value.MemberExternalID], seenIndex[value.ShareIndex], seenID[value.ExternalID] = struct{}{}, struct{}{}, struct{}{}
	}
	return nil
}

func validPortableEvidenceProfile(profile *recovery.PortableEvidenceProfile) bool {
	if profile == nil {
		return true
	}
	return profile.FormatVersion == recovery.PortableBundleFormatV1 &&
		validRecoveryID(profile.RootTrustProfileID) && validRecoveryID(profile.CryptoSuiteID) &&
		profile.ProviderProofProfile == recovery.ProviderProofStatementV1 &&
		profile.CeremonyAttestationAlgorithm == recovery.PortableSignatureAlgorithm &&
		profile.PlatformSignatureDomain == recovery.PlatformManifestSignatureV2
}

func portableProfileField(profile *recovery.PortableEvidenceProfile, field string) any {
	if profile == nil {
		return nil
	}
	switch field {
	case "format":
		return profile.FormatVersion
	case "trust":
		return profile.RootTrustProfileID
	case "suite":
		return profile.CryptoSuiteID
	case "proof":
		return profile.ProviderProofProfile
	case "algorithm":
		return profile.CeremonyAttestationAlgorithm
	default:
		return nil
	}
}

func validateManifestBatchBindings(values []recovery.StagedBatchBinding, accountCount int) error {
	if len(values) != accountCount*8 {
		return recovery.ErrInvalidData
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if (value.EpochRole != "FROM" && value.EpochRole != "TO") ||
			!validRecoveryID(value.ResourceAccountExternalID) || !validRecoveryID(value.BatchExternalID) ||
			!validRecoveryID(value.AccountRef) || !validControlBatchType(value.BatchType) ||
			value.BatchVersion == 0 || zeroRecoveryHash(value.CiphertextHash) ||
			(value.EpochRole == "TO" && zeroRecoveryHash(value.RecoveryWrapHash)) ||
			(value.EpochRole == "FROM" && !zeroRecoveryHash(value.RecoveryWrapHash)) {
			return recovery.ErrInvalidData
		}
		key := value.ResourceAccountExternalID + "\x00" + value.EpochRole + "\x00" + value.BatchType
		if _, ok := seen[key]; ok {
			return recovery.ErrInvalidData
		}
		seen[key] = struct{}{}
	}
	return nil
}

func recoveryBatchSetHash(values []recovery.StagedBatchBinding) ([sha256.Size]byte, error) {
	bindings := append([]recovery.StagedBatchBinding(nil), values...)
	sort.Slice(bindings, func(i, j int) bool {
		return bindingSortKey(bindings[i]) < bindingSortKey(bindings[j])
	})
	raw, err := json.Marshal(bindings)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	canonical, err := canonicalRecoveryJSON(raw)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// canonicalRecoveryJSON accepts arrays as well as objects; batch-set intents are ordered arrays.
func canonicalRecoveryJSON(value []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, recovery.ErrInvalidData
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, recovery.ErrInvalidData
	}
	return json.Marshal(document)
}

func bindingSortKey(value recovery.StagedBatchBinding) string {
	return value.ResourceAccountExternalID + "\x00" + value.EpochRole + "\x00" + value.BatchType
}

// validateManifestProjection 从同一事务的权威快照重建 Manifest 的密码学作用域。
func validateManifestProjection(ctx context.Context, tx *sql.Tx, plan *recovery.StoredEpochPlan,
	payload recovery.ManifestPayload, bindings []recovery.StagedBatchBinding) error {
	previous := fmt.Sprintf("%x", plan.PreviousManifestHash[:])
	if plan.CeremonyType == recovery.CeremonyBootstrap {
		previous = ""
	}
	attestationPurpose := "ROTATION_CONTROL"
	if plan.CeremonyType == recovery.CeremonyBootstrap {
		attestationPurpose = "BOOTSTRAP_GENESIS"
	}
	if payload.ProtocolVersion != recovery.ProtocolVersionV1 || payload.CeremonyType != plan.CeremonyType ||
		payload.OperationID == "" || payload.PoolID != plan.PoolExternalID || payload.FromEpoch != plan.FromEpoch ||
		payload.FromEpochStatus != "ACTIVE" || payload.FromGovernanceState != sourceGovernanceState(plan.CeremonyType) ||
		payload.Epoch != plan.ToEpoch || payload.GovernanceThreshold != plan.GovernanceThreshold ||
		payload.RecoveryThreshold != plan.RecoveryThreshold ||
		int(payload.RequiredShareAcknowledges) != plan.ExpectedMemberCount || payload.PreviousManifestHash != previous {
		return recovery.ErrBindingMismatch
	}
	if payload.CeremonyAttestationDigest != fmt.Sprintf("%x", plan.CeremonyAttestationDigest[:]) ||
		payload.CeremonyAttestationPurpose != attestationPurpose ||
		payload.CeremonyAttestationIssuer != plan.CeremonyAttestationIssuer ||
		payload.CeremonyAttestationKeyID != plan.CeremonyAttestationKeyID ||
		payload.CeremonyAttestationReference != plan.CeremonyAttestationRef ||
		payload.CeremonyAttestationVersion != plan.CeremonyAttestationVersion {
		return recovery.ErrBindingMismatch
	}

	var rootAlgorithm, rootHandle, rootFingerprint, wrapDomain, wrapAlgorithm string
	var provider, keyVersion, privateHash, vssAlgorithm, vssHash, vssProofHash, packageHash string
	var providerAttestationSetHash string
	err := tx.QueryRowContext(ctx, `SELECT epoch_recovery_algorithm, epoch_recovery_key_id,
encode(epoch_recovery_key_fingerprint, 'hex'), wrap_domain, wrap_algorithm, provider, root_key_version,
encode(private_key_commitment_hash, 'hex'), vss_algorithm, encode(vss_commitment_hash, 'hex'),
encode(vss_proof_hash, 'hex'), encode(recovery_package_hash, 'hex'),
(SELECT encode(provider_attestation_set_hash, 'hex') FROM recovery_epoch_plans WHERE id = $1)
FROM recovery_root_artifacts WHERE plan_id = $1 AND migration_state = 'CURRENT'`, plan.ID).
		Scan(&rootAlgorithm, &rootHandle, &rootFingerprint, &wrapDomain, &wrapAlgorithm, &provider,
			&keyVersion, &privateHash, &vssAlgorithm, &vssHash, &vssProofHash, &packageHash,
			&providerAttestationSetHash)
	if err != nil {
		return translateRecoveryError("load Manifest Root projection", err)
	}
	wantRoot := recovery.ManifestRootBinding{PublicAlgorithm: rootAlgorithm, PublicHandle: rootHandle,
		PublicFingerprint: rootFingerprint, WrapDomain: wrapDomain, WrapAlgorithm: wrapAlgorithm,
		ProviderID: provider, KeyVersion: keyVersion, PrivateCommitmentHash: privateHash,
		VSSAlgorithm: vssAlgorithm, VSSCommitmentHash: vssHash, VSSProofHash: vssProofHash, PackageHash: packageHash}
	if !reflect.DeepEqual(payload.RecoveryRoot, wantRoot) {
		return recovery.ErrBindingMismatch
	}
	if payload.ProviderAttestationSetHash != providerAttestationSetHash {
		return recovery.ErrBindingMismatch
	}

	members := make([]recovery.ManifestMember, 0, plan.ExpectedMemberCount)
	rows, err := tx.QueryContext(ctx, `SELECT member.external_id, snapshot.member_role, snapshot.share_index,
snapshot.signing_algorithm, snapshot.signing_key_id, encode(snapshot.signing_key_fingerprint, 'hex'),
snapshot.signing_public_key, snapshot.recovery_key_algorithm, snapshot.recovery_key_id,
encode(snapshot.recovery_key_fingerprint, 'hex'), snapshot.recovery_encryption_public_key
FROM recovery_epoch_plans plan
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = epoch.id AND snapshot.migration_state = 'CURRENT'
JOIN members member ON member.id = snapshot.member_id
WHERE plan.id = $1 ORDER BY member.external_id`, plan.ID)
	if err != nil {
		return fmt.Errorf("load Manifest member projection: %w", err)
	}
	for rows.Next() {
		var member recovery.ManifestMember
		if err := rows.Scan(&member.MemberID, &member.Role, &member.ShareIndex, &member.SigningAlgorithm,
			&member.SigningKeyID, &member.SigningKeyFingerprint, &member.SigningPublicKey,
			&member.RecoveryEncryptionAlgorithm, &member.RecoveryEncryptionKeyID,
			&member.RecoveryEncryptionKeyHash, &member.RecoveryEncryptionPublicKey); err != nil {
			rows.Close()
			return fmt.Errorf("scan Manifest member projection: %w", err)
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Manifest member projection: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Manifest member projection: %w", err)
	}
	if !reflect.DeepEqual(payload.Members, members) {
		return recovery.ErrBindingMismatch
	}

	seats := make([]recovery.SeatPlan, 0, plan.ExpectedMemberCount)
	replacements := make([]recovery.OwnerReplacementPlan, 0)
	rows, err = tx.QueryContext(ctx, `SELECT seat.external_id, target.external_id,
seat.sub2api_principal_id, seat.sub2api_subscription_id, seat.sub2api_api_key_id,
planned.expected_assignment_epoch, planned.freeze_operation_id, encode(planned.freeze_snapshot_hash, 'hex'),
source.external_id, planned.is_replacement
FROM recovery_plan_seats planned JOIN seats seat ON seat.id = planned.seat_id
JOIN members target ON target.id = planned.to_member_id JOIN members source ON source.id = planned.from_member_id
WHERE planned.plan_id = $1 ORDER BY seat.external_id`, plan.ID)
	if err != nil {
		return fmt.Errorf("load Manifest Seat projection: %w", err)
	}
	for rows.Next() {
		var seat recovery.SeatPlan
		var fromMember string
		var replacement bool
		if err := rows.Scan(&seat.SeatID, &seat.MemberID, &seat.PrincipalUserID, &seat.SubscriptionID,
			&seat.APIKeyID, &seat.ExpectedAssignmentEpoch, &seat.FreezeOperationID,
			&seat.FreezeSnapshotHash, &fromMember, &replacement); err != nil {
			rows.Close()
			return fmt.Errorf("scan Manifest Seat projection: %w", err)
		}
		seats = append(seats, seat)
		if replacement {
			replacements = append(replacements, recovery.OwnerReplacementPlan{SeatID: seat.SeatID,
				FromMemberID: fromMember, ToMemberID: seat.MemberID,
				ExpectedAssignmentEpoch: seat.ExpectedAssignmentEpoch, FreezeOperationID: seat.FreezeOperationID,
				FreezeSnapshotHash: seat.FreezeSnapshotHash})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Manifest Seat projection: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Manifest Seat projection: %w", err)
	}
	if !reflect.DeepEqual(payload.Seats, seats) || !reflect.DeepEqual(payload.Replacements, replacements) {
		return recovery.ErrBindingMismatch
	}

	shares := make([]recovery.ManifestEncryptedShare, 0, plan.ExpectedMemberCount)
	rows, err = tx.QueryContext(ctx, `SELECT member.external_id, delivery.share_index,
encode(delivery.share_hash, 'hex'), encode(delivery.provider_proof_digest, 'hex'),
encode(digest(delivery.provider_share_commitment, 'sha256'), 'hex')
FROM recovery_share_deliveries delivery JOIN members member ON member.id = delivery.member_id
WHERE delivery.recovery_plan_id = $1 AND delivery.migration_state = 'CURRENT'
ORDER BY member.external_id`, plan.ID)
	if err != nil {
		return fmt.Errorf("load Manifest Share projection: %w", err)
	}
	for rows.Next() {
		var share recovery.ManifestEncryptedShare
		if err := rows.Scan(&share.MemberID, &share.ShareIndex, &share.CiphertextHash,
			&share.ProviderProofHash, &share.ProviderCommitment); err != nil {
			rows.Close()
			return fmt.Errorf("scan Manifest Share projection: %w", err)
		}
		shares = append(shares, share)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Manifest Share projection: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Manifest Share projection: %w", err)
	}
	if !reflect.DeepEqual(payload.EncryptedShares, shares) {
		return recovery.ErrBindingMismatch
	}

	return validateManifestAccountProjection(ctx, tx, plan, payload.Accounts, bindings)
}

func validateManifestAccountProjection(ctx context.Context, tx *sql.Tx, plan *recovery.StoredEpochPlan,
	accounts []recovery.ResourceAccountPlan, bindings []recovery.StagedBatchBinding) error {
	if len(accounts) != plan.ExpectedResourceCount {
		return recovery.ErrBindingMismatch
	}
	byAccount := make(map[string]recovery.ResourceAccountPlan, len(accounts))
	for _, account := range accounts {
		byAccount[account.AccountID] = account
	}
	rows, err := tx.QueryContext(ctx, `SELECT planned.account_external_id, planned.provider_account_ref,
planned.provider_binding, planned.control_evidence_external_id,
encode(planned.control_attestation_digest, 'hex'), planned.control_attestation_issuer,
planned.control_attestation_key_id, planned.control_attestation_version,
planned.control_attestation_algorithm, planned.control_attestation_signature,
planned.control_attestation_protocol_version,
array_agg(seat.external_id ORDER BY seat.external_id)
FROM recovery_plan_resource_accounts planned
JOIN recovery_plan_account_seats mapping ON mapping.plan_id = planned.plan_id
 AND mapping.resource_account_id = planned.resource_account_id
JOIN seats seat ON seat.id = mapping.seat_id
WHERE planned.plan_id = $1 GROUP BY planned.resource_account_id, planned.account_external_id,
planned.provider_account_ref, planned.provider_binding, planned.control_evidence_external_id,
planned.control_attestation_digest, planned.control_attestation_issuer, planned.control_attestation_key_id,
planned.control_attestation_version, planned.control_attestation_algorithm,
planned.control_attestation_signature, planned.control_attestation_protocol_version
ORDER BY planned.account_external_id`, plan.ID)
	if err != nil {
		return fmt.Errorf("load Manifest account projection: %w", err)
	}
	count := 0
	for rows.Next() {
		var accountID, accountRef, providerBinding, evidenceID, attestationDigest string
		var attestationIssuer, attestationKeyID, attestationAlgorithm, attestationProtocol string
		var attestationSignature []byte
		var attestationVersion uint64
		var seatIDs pq.StringArray
		if err := rows.Scan(&accountID, &accountRef, &providerBinding, &evidenceID, &attestationDigest,
			&attestationIssuer, &attestationKeyID, &attestationVersion, &attestationAlgorithm,
			&attestationSignature, &attestationProtocol, &seatIDs); err != nil {
			rows.Close()
			return fmt.Errorf("scan Manifest account projection: %w", err)
		}
		account, exists := byAccount[accountID]
		if !exists || account.AccountRef != accountRef || account.ProviderBinding != providerBinding ||
			account.ControlEvidenceID != evidenceID || account.ProviderAttestationDigest != attestationDigest ||
			account.ProviderAttestationIssuer != attestationIssuer ||
			account.ProviderAttestationKeyID != attestationKeyID ||
			account.ProviderAttestationVersion != attestationVersion ||
			account.ProviderAttestationAlgorithm != attestationAlgorithm ||
			!bytes.Equal(account.ProviderAttestationSignature, attestationSignature) ||
			account.ProviderAttestationProtocolVersion != attestationProtocol ||
			!reflect.DeepEqual(account.SeatIDs, []string(seatIDs)) {
			rows.Close()
			return recovery.ErrBindingMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Manifest account projection: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Manifest account projection: %w", err)
	}
	if count != len(accounts) {
		return recovery.ErrBindingMismatch
	}
	expectedBindings := make([]recovery.StagedBatchBinding, 0, len(bindings))
	for _, account := range accounts {
		for _, batch := range account.Batches {
			fromHash, err1 := decodeRecoveryHash(batch.FromCiphertextHash)
			toHash, err2 := decodeRecoveryHash(batch.ToCiphertextHash)
			wrapHash, err3 := decodeRecoveryHash(batch.ToRecoveryWrapHash)
			if err1 != nil || err2 != nil || err3 != nil {
				return recovery.ErrInvalidData
			}
			expectedBindings = append(expectedBindings,
				recovery.StagedBatchBinding{EpochRole: "FROM", ResourceAccountExternalID: account.AccountID,
					BatchExternalID: batch.FromBatchID, AccountRef: account.AccountRef,
					BatchType: batch.BatchType, BatchVersion: batch.FromBatchVersion, CiphertextHash: fromHash},
				recovery.StagedBatchBinding{EpochRole: "TO", ResourceAccountExternalID: account.AccountID,
					BatchExternalID: batch.ToBatchID, AccountRef: account.AccountRef,
					BatchType: batch.BatchType, BatchVersion: batch.ToBatchVersion,
					CiphertextHash: toHash, RecoveryWrapHash: wrapHash})
		}
	}
	sort.Slice(expectedBindings, func(i, j int) bool { return bindingSortKey(expectedBindings[i]) < bindingSortKey(expectedBindings[j]) })
	actualBindings := append([]recovery.StagedBatchBinding(nil), bindings...)
	sort.Slice(actualBindings, func(i, j int) bool { return bindingSortKey(actualBindings[i]) < bindingSortKey(actualBindings[j]) })
	if !reflect.DeepEqual(expectedBindings, actualBindings) {
		return recovery.ErrBindingMismatch
	}
	return nil
}

func decodeRecoveryHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return result, recovery.ErrInvalidData
	}
	copy(result[:], decoded)
	return result, nil
}

func nullableRecoveryWrapHash(value recovery.StagedBatchBinding) any {
	if value.EpochRole == "FROM" {
		return nil
	}
	return value.RecoveryWrapHash[:]
}

func validateStagedBatch(operationID string, plan *recovery.StoredEpochPlan, root stagedRootBinding,
	batch recovery.StagedCredentialBatch) error {
	if !validRecoveryID(batch.ExternalID) || !validRecoveryID(batch.ResourceAccountExternalID) ||
		!validRecoveryID(batch.AccountRef) || !validControlBatchType(string(batch.Type)) || batch.BatchVersion == 0 ||
		batch.EncryptionAlgorithm != credentials.BatchEnvelopeAlgorithm || len(batch.Ciphertext) == 0 ||
		len(batch.Nonce) != 12 || zeroRecoveryHash(batch.AADHash) || zeroRecoveryHash(batch.ContentFingerprint) ||
		!validRecoveryID(batch.KMSWrapAlgorithm) || !validRecoveryID(batch.KMSKeyRef) ||
		!validRecoveryID(batch.KMSWrapperDomain) || len(batch.WrappedDEKKMS) == 0 ||
		batch.RecoveryWrapAlgorithm != root.Algorithm || batch.RecoveryWrapDomain != root.Domain ||
		batch.RecoveryKeyHandle != root.Handle || batch.RecoveryKeyVersion != root.Version ||
		batch.RecoveryKeyFingerprint != root.Fingerprint || len(batch.WrappedDEKRecovery) == 0 ||
		batch.KMSWrapperDomain == batch.RecoveryWrapDomain || bytes.Equal(batch.WrappedDEKKMS, batch.WrappedDEKRecovery) ||
		zeroRecoveryHash(batch.ProviderWrapAttestationDigest) || len(batch.ProviderWrapAttestationSignature) == 0 {
		return recovery.ErrInvalidData
	}
	aad, err := credentials.CanonicalBatchAAD(operationID, batch.ExternalID, plan.PoolExternalID,
		batch.AccountRef, batch.Type, batch.BatchVersion, plan.ToEpoch, batch.ContentFingerprint)
	if err != nil || sha256.Sum256(aad) != batch.AADHash ||
		credentials.RecoveryBindingHash(batch.RecoveryWrapDomain, batch.RecoveryWrapAlgorithm,
			batch.RecoveryKeyHandle, batch.AADHash, batch.WrappedDEKRecovery) != batch.RecoveryBindingHash {
		return recovery.ErrBindingMismatch
	}
	return nil
}

func validControlBatchType(value string) bool {
	return value == "LOGIN" || value == "MFA" || value == "RECOVERY" || value == "OWNERSHIP"
}

func errReplacementClaim(claim *recovery.ReplacementCredentialClaim) error {
	if claim == nil || !validRecoveryID(claim.SeatExternalID) || !validRecoveryID(claim.TargetMemberExternalID) ||
		!validRecoveryID(claim.PreparedReference) || zeroRecoveryHash(claim.ProviderResultDigest) ||
		zeroRecoveryHash(claim.CredentialFingerprint) ||
		!validRecoveryID(claim.EnvelopeAlgorithm) || !validRecoveryID(claim.EnvelopeKeyRef) ||
		len(claim.EnvelopeCiphertext) == 0 || len(claim.EnvelopeNonce) == 0 ||
		zeroRecoveryHash(claim.EnvelopeAADHash) || len(claim.WrappedDEK) == 0 {
		return recovery.ErrInvalidData
	}
	return nil
}

func translateRecoveryError(action string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return recovery.ErrNotFound
	}
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "duplicate") || strings.Contains(message, "unique") ||
		strings.Contains(message, "violates") || strings.Contains(message, "invalid") ||
		strings.Contains(message, "inconsistent") || strings.Contains(message, "requires") {
		return fmt.Errorf("%s: %w: %v", action, recovery.ErrInvalidState, err)
	}
	return fmt.Errorf("%s: %w", action, err)
}
