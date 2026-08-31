package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"trusted-pool-platform/backend/internal/recovery"
)

const (
	exportVerificationOperation = "EXPORT_RECOVERY_VERIFICATION"
	authorizeRevealOperation    = "AUTHORIZE_RECOVERY_REVEAL"
	manifestSignatureDomainV2   = "trusted-pool/platform-manifest-signature/v2"
	offlineBundleProtocolV1     = "trusted-pool/offline-evidence-bundle/v1"
	providerProofStatementV1    = "trusted-pool/provider-proof-statement/v1"
	ed25519Algorithm            = "Ed25519"
	exportSignatureDomainV1     = recovery.VerificationExportSignatureDomainV1
	revealAuthorizationDomainV1 = "trusted-pool/reveal-authorization/v1"
)

const verificationExportColumns = `export.id, export.external_id, plan.external_id, manifest.external_id,
pool.external_id, operation.integration_client_id, operation.operation_id,
plan.to_epoch, export.format_version, export.capability, export.status,
export.inventory_digest, export.bundle_digest, export.signer_domain, export.signer_algorithm,
export.signer_key_id, export.signature, export.generated_at, export.version, export.created_at,
export.updated_at, export.missing_evidence_codes`

const revealAuthorizationColumns = `reveal.id, reveal.external_id, plan.external_id, export.external_id,
manifest.external_id, pool.external_id, reveal.membership_epoch, reveal.purpose, reveal.scope_hash,
reveal.challenge_hash, reveal.governance_threshold, reveal.recovery_threshold,
(SELECT count(*) FROM recovery_reveal_approvals approval WHERE approval.reveal_id = reveal.id),
reveal.status, reveal.authorization_digest, reveal.authorization_signer_domain,
reveal.authorization_signer_algorithm, reveal.authorization_signer_key_id,
reveal.authorization_signature, reveal.expires_at, reveal.authorized_at,
reveal.authorization_exported_at, reveal.completed_at, reveal.version, reveal.created_at, reveal.updated_at`

func (s *Store) CommitMemberArtifactReceipt(ctx context.Context, input recovery.CommitMemberArtifactReceiptInput) error {
	receipt := input.Receipt
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validEvidenceID(receipt.PlanExternalID) || !validEvidenceID(receipt.DeliveryExternalID) ||
		!validEvidenceID(receipt.ManifestExternalID) || !validEvidenceID(receipt.MemberExternalID) ||
		!validEvidenceID(receipt.ReceiptID) || zeroRecoveryHash(receipt.ArtifactDigest) ||
		zeroRecoveryHash(receipt.ReceiptDigest) || len(receipt.ProviderProof) == 0 ||
		sha256.Sum256(receipt.ProviderProof) != receipt.ProviderProofDigest || receipt.PublishedAt.IsZero() ||
		!validEvidenceID(receipt.ProviderProofAlgorithm) || !validEvidenceID(receipt.ProviderProofKeyID) ||
		!validEvidenceID(receipt.ProviderProofProtocolVersion) {
		return recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin member artifact receipt transaction: %w", err)
	}
	defer tx.Rollback()
	poolID, poolExternalID, err := locateEvidencePoolByPlan(ctx, tx, receipt.PlanExternalID)
	if err != nil {
		return err
	}
	if err := lockEvidencePool(ctx, tx, poolID, poolExternalID); err != nil {
		return err
	}
	var operationID, planID string
	err = tx.QueryRowContext(ctx, `SELECT operation.id, plan.id
FROM integration_operations operation
JOIN recovery_epoch_plans plan ON plan.integration_operation_id = operation.id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2
  AND operation.lease_owner = $3 AND operation.fencing_token = $4
  AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
  AND plan.external_id = $5 AND plan.status IN ('MANIFEST_DRAFT','MANIFEST_SIGNED')
FOR UPDATE OF operation, plan`, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.FencingToken, receipt.PlanExternalID).Scan(&operationID, &planID)
	if errors.Is(err, sql.ErrNoRows) {
		return recovery.ErrStaleFence
	}
	if err != nil {
		return translateRecoveryError("lock member artifact receipt scope", err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO recovery_member_artifact_receipts (
plan_id, delivery_id, manifest_id, epoch_id, member_id, artifact_digest, receipt_external_id,
receipt_digest, provider_proof, provider_proof_digest, provider_proof_algorithm,
provider_proof_key_id, provider_proof_protocol_version, published_at, created_at)
SELECT plan.id, delivery.id, manifest.id, manifest.epoch_id, member.id, $5, $6, $7, $8, $9,
       $10, $11, $12, $13, CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan
JOIN recovery_share_deliveries delivery ON delivery.recovery_plan_id = plan.id AND delivery.external_id = $2
JOIN manifests manifest ON manifest.recovery_plan_id = plan.id AND manifest.external_id = $3
JOIN members member ON member.id = delivery.member_id AND member.external_id = $4
WHERE plan.id = $1
ON CONFLICT (plan_id, delivery_id) DO NOTHING`, planID, receipt.DeliveryExternalID,
		receipt.ManifestExternalID, receipt.MemberExternalID, receipt.ArtifactDigest[:], receipt.ReceiptID,
		receipt.ReceiptDigest[:], receipt.ProviderProof, receipt.ProviderProofDigest[:],
		receipt.ProviderProofAlgorithm, receipt.ProviderProofKeyID, receipt.ProviderProofProtocolVersion,
		normalizeEvidenceDBTime(receipt.PublishedAt))
	if err != nil {
		return translateRecoveryError("insert member artifact receipt", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var artifactDigest, receiptDigest, proofDigest, proof []byte
		var externalID, algorithm, keyID, protocol string
		var publishedAt time.Time
		err = tx.QueryRowContext(ctx, `SELECT artifact_digest, receipt_external_id, receipt_digest,
provider_proof, provider_proof_digest, provider_proof_algorithm, provider_proof_key_id,
provider_proof_protocol_version, published_at FROM recovery_member_artifact_receipts receipt
JOIN recovery_share_deliveries delivery ON delivery.id = receipt.delivery_id
WHERE receipt.plan_id = $1 AND delivery.external_id = $2`, planID, receipt.DeliveryExternalID).
			Scan(&artifactDigest, &externalID, &receiptDigest, &proof, &proofDigest, &algorithm, &keyID, &protocol, &publishedAt)
		if err != nil || !bytes.Equal(artifactDigest, receipt.ArtifactDigest[:]) || externalID != receipt.ReceiptID ||
			!bytes.Equal(receiptDigest, receipt.ReceiptDigest[:]) || !bytes.Equal(proof, receipt.ProviderProof) ||
			!bytes.Equal(proofDigest, receipt.ProviderProofDigest[:]) || algorithm != receipt.ProviderProofAlgorithm ||
			keyID != receipt.ProviderProofKeyID || protocol != receipt.ProviderProofProtocolVersion ||
			!sameEvidenceDBTime(publishedAt, receipt.PublishedAt) {
			return recovery.ErrHashDrift
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit member artifact receipt: %w", err)
	}
	return nil
}

func (s *Store) BeginVerificationExport(ctx context.Context, input recovery.BeginVerificationExportInput) (*recovery.VerificationExportTarget, bool, error) {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	expectedSnapshot, expectedHash, snapshotErr := recovery.BuildVerificationExportRequestSnapshot(input)
	if err != nil || !validEvidenceID(input.ExportExternalID) || !validEvidenceID(input.PlanExternalID) ||
		!validEvidenceID(input.FormatVersion) || !validEvidenceLease(input.LeaseOwner, input.LeaseDuration) ||
		snapshotErr != nil || input.RequestHash != expectedHash || !bytes.Equal(canonical, expectedSnapshot) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, fmt.Errorf("begin verification export transaction: %w", err)
	}
	defer tx.Rollback()
	poolID, poolExternalID, err := locateEvidencePoolByPlan(ctx, tx, input.PlanExternalID)
	if err != nil {
		return nil, false, err
	}
	if err := lockEvidencePool(ctx, tx, poolID, poolExternalID); err != nil {
		return nil, false, err
	}
	op, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key, exportVerificationOperation,
		poolExternalID, input.RequestHash, canonical, true, input.LeaseOwner, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if !created {
		export, loadErr := loadVerificationExportTx(ctx, tx, input.ExportExternalID, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if export.PlanExternalID != input.PlanExternalID || export.FormatVersion != input.FormatVersion {
			return nil, false, recovery.ErrHashDrift
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit verification export replay: %w", err)
		}
		return &recovery.VerificationExportTarget{Operation: toRecoveryOperation(op), Export: export}, false, nil
	}
	capability, missing, planID, manifestID, err := assessPortableEvidenceTx(ctx, tx, input.PlanExternalID, input.FormatVersion)
	if err != nil {
		return nil, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO recovery_verification_exports (
external_id, integration_operation_id, plan_id, manifest_id, format_version, capability,
missing_evidence_codes, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		input.ExportExternalID, op.AggregateID, planID, manifestID, input.FormatVersion, capability, pq.Array(missing))
	if err != nil {
		return nil, false, translateRecoveryError("insert verification export", err)
	}
	export, err := loadVerificationExportTx(ctx, tx, input.ExportExternalID, false)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin verification export: %w", err)
	}
	return &recovery.VerificationExportTarget{Operation: toRecoveryOperation(op), Export: export}, true, nil
}

func (s *Store) LoadPublicEvidenceSnapshot(ctx context.Context, input recovery.LoadPublicEvidenceSnapshotInput) (*recovery.PublicEvidenceSnapshot, error) {
	if !validPublicEvidenceSnapshotInput(input) {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin public evidence snapshot: %w", err)
	}
	defer tx.Rollback()
	var exportID, planID, manifestID, poolExternalID string
	var planOperationID string
	err = tx.QueryRowContext(ctx, `SELECT export.id, export.plan_id, export.manifest_id, pool.external_id,
ceremony.operation_id
FROM recovery_verification_exports export
JOIN integration_operations operation ON operation.id = export.integration_operation_id
JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
JOIN integration_operations ceremony ON ceremony.id = plan.integration_operation_id
JOIN pools pool ON pool.id = plan.pool_id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2
  AND export.external_id = $5 AND (
    (operation.lease_owner = $3 AND operation.fencing_token = $4
     AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
     AND export.status = 'PENDING') OR
    ($3 = '' AND $4 = 0
     AND operation.status = 'SUCCEEDED' AND export.status = 'AVAILABLE')
  )`, input.Key.ClientID, input.Key.OperationID,
		input.LeaseOwner, input.FencingToken, input.ExportID).
		Scan(&exportID, &planID, &manifestID, &poolExternalID, &planOperationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, translateRecoveryError("load public evidence scope", err)
	}
	export, err := loadVerificationExportTx(ctx, tx, input.ExportID, false)
	if err != nil {
		return nil, err
	}
	snapshot := &recovery.PublicEvidenceSnapshot{Export: export, ProtocolVersion: export.FormatVersion,
		MissingEvidenceCodes: append([]string(nil), export.MissingEvidenceCodes...)}
	var manifestHash []byte
	var platformDomain sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT manifest.canonical_bytes,
manifest.manifest_hash, manifest.platform_signature_domain, manifest.platform_algorithm,
manifest.platform_key_ref, manifest.platform_signature
FROM manifests manifest WHERE manifest.id = $1`, manifestID).Scan(&snapshot.CanonicalManifest,
		&manifestHash, &platformDomain, &snapshot.PlatformSignature.Algorithm,
		&snapshot.PlatformSignature.KeyID, &snapshot.PlatformSignature.Signature)
	if err != nil {
		return nil, translateRecoveryError("load public Manifest evidence", err)
	}
	if err := copyEvidenceHash(&snapshot.ManifestHash, manifestHash); err != nil {
		return nil, err
	}
	snapshot.PlatformSignature.Domain = platformDomain.String

	rows, err := tx.QueryContext(ctx, `SELECT member.external_id, signature.signing_algorithm,
signature.signing_key_id, signature.signature
FROM manifest_signatures signature
JOIN members member ON member.id = signature.member_id
WHERE signature.manifest_id = $1 AND signature.migration_state = 'CURRENT'
ORDER BY member.external_id`, manifestID)
	if err != nil {
		return nil, fmt.Errorf("load public Manifest approvals: %w", err)
	}
	for rows.Next() {
		var approval recovery.PublicMemberApproval
		if err := rows.Scan(&approval.MemberID, &approval.Algorithm, &approval.KeyID, &approval.Signature); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan public Manifest approval: %w", err)
		}
		snapshot.MemberApprovals = append(snapshot.MemberApprovals, approval)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close public Manifest approvals: %w", err)
	}

	rows, err = tx.QueryContext(ctx, `SELECT delivery.external_id, member.external_id,
delivery.share_index, delivery.share_hash, root.root_commitment_hash, root.vss_commitment_hash,
delivery.acknowledgement_algorithm, delivery.acknowledgement_key_id, delivery.acknowledgement_signature
FROM recovery_share_deliveries delivery
JOIN members member ON member.id = delivery.member_id
JOIN recovery_root_artifacts root ON root.id = delivery.root_artifact_id
WHERE delivery.recovery_plan_id = $1 AND delivery.migration_state = 'CURRENT'
  AND delivery.delivery_status = 'ACKNOWLEDGED'
ORDER BY delivery.share_index, member.external_id`, planID)
	if err != nil {
		return nil, fmt.Errorf("load public Share acknowledgements: %w", err)
	}
	for rows.Next() {
		var acknowledgement recovery.PublicShareAcknowledgement
		var ciphertextHash, rootHash, vssHash []byte
		if err := rows.Scan(&acknowledgement.DeliveryID, &acknowledgement.MemberID,
			&acknowledgement.ShareIndex, &ciphertextHash, &rootHash, &vssHash,
			&acknowledgement.Algorithm, &acknowledgement.KeyID, &acknowledgement.Signature); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan public Share acknowledgement: %w", err)
		}
		if copyEvidenceHash(&acknowledgement.CiphertextHash, ciphertextHash) != nil ||
			copyEvidenceHash(&acknowledgement.RootCommitment, rootHash) != nil ||
			copyEvidenceHash(&acknowledgement.VSSCommitment, vssHash) != nil {
			rows.Close()
			return nil, recovery.ErrInvalidData
		}
		acknowledgement.VerifiedCommitment = true
		snapshot.ShareAcknowledgements = append(snapshot.ShareAcknowledgements, acknowledgement)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close public Share acknowledgements: %w", err)
	}

	if err := loadPublicProviderProofsTx(ctx, tx, snapshot, planID, planOperationID, poolExternalID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit public evidence snapshot: %w", err)
	}
	return snapshot, nil
}

// RenewVerificationExportLease is a same-owner heartbeat. It never performs a
// takeover and never changes the fencing token.
func (s *Store) RenewVerificationExportLease(ctx context.Context,
	input recovery.RenewVerificationExportLeaseInput) (*recovery.StoredOperation, error) {
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.ExpectedFencingToken) ||
		!validEvidenceID(input.ExportExternalID) || input.LeaseDuration <= 0 || input.LeaseDuration > 5*time.Minute {
		return nil, recovery.ErrInvalidData
	}
	op, err := scanOperation(s.db.QueryRowContext(ctx, `UPDATE integration_operations operation SET
lease_expires_at = CURRENT_TIMESTAMP + make_interval(secs => $5),
version = operation.version + 1, updated_at = CURRENT_TIMESTAMP
FROM recovery_verification_exports export
WHERE export.integration_operation_id = operation.id
  AND operation.integration_client_id = $1 AND operation.operation_id = $2
  AND operation.lease_owner = $3 AND operation.fencing_token = $4
  AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
  AND operation.operation_type = 'EXPORT_RECOVERY_VERIFICATION'
  AND export.external_id = $6 AND export.status = 'PENDING'
RETURNING `+operationColumns, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.ExpectedFencingToken, input.LeaseDuration.Seconds(), input.ExportExternalID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, fmt.Errorf("renew verification export lease: %w", err)
	}
	return toRecoveryOperation(op), nil
}

func (s *Store) CommitVerificationExport(ctx context.Context, input recovery.CommitVerificationExportInput) (*recovery.StoredVerificationExport, bool, error) {
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validEvidenceID(input.ExportExternalID) || zeroRecoveryHash(input.InventoryDigest) ||
		zeroRecoveryHash(input.BundleDigest) || input.SignerDomain != exportSignatureDomainV1 ||
		!validEvidenceID(input.SignerAlgorithm) || !validEvidenceID(input.SignerKeyID) ||
		len(input.Signature) == 0 || input.GeneratedAt.IsZero() {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, fmt.Errorf("begin commit verification export: %w", err)
	}
	defer tx.Rollback()
	poolID, poolExternalID, err := locateEvidencePoolByExport(ctx, tx, input.ExportExternalID)
	if err != nil {
		return nil, false, err
	}
	if err := lockEvidencePool(ctx, tx, poolID, poolExternalID); err != nil {
		return nil, false, err
	}
	var operationID, status string
	err = tx.QueryRowContext(ctx, `SELECT operation.id, export.status
FROM integration_operations operation
JOIN recovery_verification_exports export ON export.integration_operation_id = operation.id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2
  AND operation.lease_owner = $3 AND operation.fencing_token = $4
  AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
  AND export.external_id = $5
FOR UPDATE OF operation, export`, input.Key.ClientID, input.Key.OperationID, input.LeaseOwner,
		input.FencingToken, input.ExportExternalID).Scan(&operationID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		// 已成功的完全相同重放不要求继续占用 lease。
		existing, loadErr := loadVerificationExportTx(ctx, tx, input.ExportExternalID, true)
		if loadErr == nil && sameVerificationExport(existing, input) {
			_ = tx.Commit()
			return existing, false, nil
		}
		return nil, false, recovery.ErrStaleFence
	}
	if err != nil {
		return nil, false, translateRecoveryError("lock verification export", err)
	}
	if status != recovery.VerificationExportPending {
		existing, loadErr := loadVerificationExportTx(ctx, tx, input.ExportExternalID, false)
		if loadErr != nil || !sameVerificationExport(existing, input) {
			return nil, false, recovery.ErrHashDrift
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit verification export replay: %w", err)
		}
		return existing, false, nil
	}
	resultSnapshot, err := canonicalEvidenceJSON(map[string]any{
		"bundle_digest": fmt.Sprintf("%x", input.BundleDigest[:]), "export_id": input.ExportExternalID,
		"inventory_digest": fmt.Sprintf("%x", input.InventoryDigest[:]), "version": 1,
	})
	if err != nil {
		return nil, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE recovery_verification_exports
SET status = 'AVAILABLE', inventory_digest = $2, bundle_digest = $3, signer_domain = $4,
    signer_algorithm = $5, signer_key_id = $6, signature = $7, generated_at = $8,
    version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE external_id = $1 AND status = 'PENDING' AND $8 <= CURRENT_TIMESTAMP + interval '5 minutes'`,
		input.ExportExternalID, input.InventoryDigest[:], input.BundleDigest[:], input.SignerDomain,
		input.SignerAlgorithm, input.SignerKeyID, input.Signature, normalizeEvidenceDBTime(input.GeneratedAt))
	if err != nil {
		return nil, false, translateRecoveryError("commit verification export metadata", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrInvalidState
	}
	result, err = tx.ExecContext(ctx, `UPDATE integration_operations SET status = 'SUCCEEDED',
response_snapshot = $5::jsonb, completed_at = CURRENT_TIMESTAMP, lease_owner = NULL,
lease_expires_at = NULL, error_code = NULL, error_detail = NULL, version = version + 1,
updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND integration_client_id = $2 AND operation_id = $3 AND fencing_token = $4
  AND status = 'RUNNING'`, operationID, input.Key.ClientID, input.Key.OperationID,
		input.FencingToken, resultSnapshot)
	if err != nil {
		return nil, false, translateRecoveryError("complete verification export operation", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, false, recovery.ErrStaleFence
	}
	export, err := loadVerificationExportTx(ctx, tx, input.ExportExternalID, false)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit verification export transaction: %w", err)
	}
	return export, true, nil
}

func (s *Store) GetVerificationExport(ctx context.Context, externalID string) (*recovery.StoredVerificationExport, error) {
	if !validEvidenceID(externalID) {
		return nil, recovery.ErrInvalidData
	}
	export, err := scanVerificationExport(s.db.QueryRowContext(ctx, `SELECT `+verificationExportColumns+`
FROM recovery_verification_exports export
JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
JOIN manifests manifest ON manifest.id = export.manifest_id
JOIN pools pool ON pool.id = plan.pool_id
JOIN integration_operations operation ON operation.id = export.integration_operation_id
WHERE export.external_id = $1`, externalID))
	if err != nil {
		return nil, translateRecoveryError("get verification export", err)
	}
	return export, nil
}

func (s *Store) BeginRevealAuthorization(context.Context, recovery.BeginRevealAuthorizationInput) (*recovery.RevealAuthorizationTarget, bool, error) {
	return nil, false, recovery.ErrRevealExecutionUnavailable
}

func (s *Store) beginRevealAuthorizationFuture(ctx context.Context, input recovery.BeginRevealAuthorizationInput) (*recovery.RevealAuthorizationTarget, bool, error) {
	canonical, err := validateRecoveryIntent(input.Key, input.RequestHash, input.RequestSnapshot)
	expectedSnapshot, expectedHash, snapshotErr := recovery.BuildRevealAuthorizationRequestSnapshot(input)
	if err != nil || !validEvidenceID(input.RevealExternalID) || !validEvidenceID(input.PlanExternalID) ||
		!validEvidenceID(input.ExportExternalID) || !validEvidenceID(input.Purpose) ||
		zeroRecoveryHash(input.ScopeHash) || zeroRecoveryHash(input.ChallengeHash) ||
		input.ExpiresAt.IsZero() || !validEvidenceLease(input.LeaseOwner, input.LeaseDuration) ||
		!validRevealIntents(input.ApprovalIntents) || snapshotErr != nil || input.RequestHash != expectedHash ||
		!bytes.Equal(canonical, expectedSnapshot) {
		return nil, false, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, fmt.Errorf("begin Reveal authorization transaction: %w", err)
	}
	defer tx.Rollback()
	poolID, poolExternalID, err := locateEvidencePoolByExport(ctx, tx, input.ExportExternalID)
	if err != nil {
		return nil, false, err
	}
	if err := lockEvidencePool(ctx, tx, poolID, poolExternalID); err != nil {
		return nil, false, err
	}
	op, created, err := beginRecoveryLedgerOperation(ctx, tx, input.Key, authorizeRevealOperation,
		poolExternalID, input.RequestHash, canonical, true, input.LeaseOwner, input.LeaseDuration)
	if err != nil {
		return nil, false, err
	}
	if !created {
		reveal, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if reveal.PlanExternalID != input.PlanExternalID || reveal.ExportExternalID != input.ExportExternalID ||
			reveal.Purpose != input.Purpose || reveal.ScopeHash != input.ScopeHash ||
			reveal.ChallengeHash != input.ChallengeHash || !sameEvidenceDBTime(reveal.ExpiresAt, input.ExpiresAt) {
			return nil, false, recovery.ErrHashDrift
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit Reveal authorization replay: %w", err)
		}
		return &recovery.RevealAuthorizationTarget{Operation: toRecoveryOperation(op), Reveal: reveal}, false, nil
	}
	var exportID, planID, manifestID, epochID string
	var membershipEpoch uint64
	var governanceThreshold, recoveryThreshold uint16
	var expectedMembers int
	err = tx.QueryRowContext(ctx, `SELECT export.id, plan.id, manifest.id, epoch.id, plan.to_epoch,
epoch.governance_threshold, epoch.recovery_threshold, plan.expected_member_count
FROM recovery_verification_exports export
JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
JOIN manifests manifest ON manifest.id = export.manifest_id
JOIN membership_epochs epoch ON epoch.id = manifest.epoch_id
JOIN pools pool ON pool.id = plan.pool_id
WHERE export.external_id = $1 AND plan.external_id = $2 AND export.status = 'AVAILABLE'
  AND export.capability = 'REVEAL_CAPABLE' AND manifest.status = 'ACTIVE'
  AND epoch.status = 'ACTIVE' AND pool.membership_epoch = plan.to_epoch
FOR SHARE OF export, plan, manifest, epoch`, input.ExportExternalID, input.PlanExternalID).
		Scan(&exportID, &planID, &manifestID, &epochID, &membershipEpoch, &governanceThreshold,
			&recoveryThreshold, &expectedMembers)
	if err != nil {
		return nil, false, translateRecoveryError("load Reveal authorization scope", err)
	}
	if len(input.ApprovalIntents) != expectedMembers {
		return nil, false, recovery.ErrInvalidData
	}
	var revealID string
	err = tx.QueryRowContext(ctx, `INSERT INTO recovery_reveal_authorizations (
external_id, integration_operation_id, verification_export_id, plan_id, manifest_id, pool_id,
membership_epoch, purpose, scope_hash, challenge_hash, governance_threshold, recovery_threshold,
expires_at, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
        'PENDING_APPROVAL', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id`, input.RevealExternalID, op.AggregateID, exportID, planID, manifestID, poolID,
		membershipEpoch, input.Purpose, input.ScopeHash[:], input.ChallengeHash[:], governanceThreshold,
		recoveryThreshold, normalizeEvidenceDBTime(input.ExpiresAt)).Scan(&revealID)
	if err != nil {
		return nil, false, translateRecoveryError("insert Reveal authorization", err)
	}
	intents := append([]recovery.RevealApprovalIntent(nil), input.ApprovalIntents...)
	sort.Slice(intents, func(i, j int) bool { return intents[i].MemberExternalID < intents[j].MemberExternalID })
	for _, intent := range intents {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO recovery_reveal_approval_intents (
reveal_id, epoch_id, member_id, expected_message_hash, created_at)
SELECT $1, $2, member.id, $4, CURRENT_TIMESTAMP
FROM members member
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = $2 AND snapshot.member_id = member.id
WHERE member.external_id = $3 AND snapshot.migration_state = 'CURRENT'`, revealID, epochID,
			intent.MemberExternalID, intent.ExpectedMessageHash[:])
		if insertErr != nil {
			return nil, false, translateRecoveryError("insert Reveal approval intent", insertErr)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, false, recovery.ErrInvalidState
		}
	}
	if err := appendRevealEventTx(ctx, tx, revealID, "REQUESTED", recovery.RevealPendingApproval, 0, nil); err != nil {
		return nil, false, err
	}
	reveal, err := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit begin Reveal authorization: %w", err)
	}
	return &recovery.RevealAuthorizationTarget{Operation: toRecoveryOperation(op), Reveal: reveal}, true, nil
}

func (s *Store) CommitRevealApprovals(context.Context, recovery.CommitRevealApprovalsInput) (*recovery.StoredRevealAuthorization, error) {
	return nil, recovery.ErrRevealExecutionUnavailable
}

func (s *Store) commitRevealApprovalsFuture(ctx context.Context, input recovery.CommitRevealApprovalsInput) (*recovery.StoredRevealAuthorization, error) {
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validEvidenceID(input.RevealExternalID) || !validRevealApprovals(input.Approvals) {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin Reveal approvals transaction: %w", err)
	}
	defer tx.Rollback()
	revealID, poolID, poolExternalID, epochID, status, threshold, err := lockRevealScopeTx(ctx, tx, input.Key,
		input.LeaseOwner, input.FencingToken, input.RevealExternalID)
	if err != nil {
		return nil, err
	}
	approvals := append([]recovery.RevealApproval(nil), input.Approvals...)
	sort.Slice(approvals, func(i, j int) bool { return approvals[i].MemberExternalID < approvals[j].MemberExternalID })
	_ = poolID
	_ = poolExternalID
	if status != recovery.RevealPendingApproval {
		if !revealApprovalsMatchTx(ctx, tx, revealID, approvals) {
			return nil, recovery.ErrHashDrift
		}
		reveal, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
		if loadErr != nil {
			return nil, loadErr
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit Reveal approval replay: %w", err)
		}
		return reveal, nil
	}
	for _, approval := range approvals {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO recovery_reveal_approvals (
reveal_id, epoch_id, member_id, signing_algorithm, signing_key_id, message_hash,
signature, verified_at, created_at)
SELECT $1, $2, member.id, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP
FROM members member WHERE member.external_id = $3
ON CONFLICT (reveal_id, member_id) DO NOTHING`, revealID, epochID, approval.MemberExternalID,
			approval.Algorithm, approval.KeyID, approval.MessageHash[:], approval.Signature,
			normalizeEvidenceDBTime(approval.VerifiedAt))
		if insertErr != nil {
			return nil, translateRecoveryError("insert Reveal approval", insertErr)
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			var algorithm, keyID string
			var messageHash, signature []byte
			var verifiedAt time.Time
			err = tx.QueryRowContext(ctx, `SELECT approval.signing_algorithm, approval.signing_key_id,
approval.message_hash, approval.signature, approval.verified_at
FROM recovery_reveal_approvals approval JOIN members member ON member.id = approval.member_id
WHERE approval.reveal_id = $1 AND member.external_id = $2`, revealID, approval.MemberExternalID).
				Scan(&algorithm, &keyID, &messageHash, &signature, &verifiedAt)
			if err != nil || algorithm != approval.Algorithm || keyID != approval.KeyID ||
				!bytes.Equal(messageHash, approval.MessageHash[:]) || !bytes.Equal(signature, approval.Signature) ||
				!sameEvidenceDBTime(verifiedAt, approval.VerifiedAt) {
				return nil, recovery.ErrHashDrift
			}
		}
	}
	var approvalCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM recovery_reveal_approvals WHERE reveal_id = $1`, revealID).
		Scan(&approvalCount); err != nil {
		return nil, fmt.Errorf("count Reveal approvals: %w", err)
	}
	eventType := "APPROVALS_COMMITTED"
	if approvalCount >= int(threshold) && status == recovery.RevealPendingApproval {
		result, updateErr := tx.ExecContext(ctx, `UPDATE recovery_reveal_authorizations
SET status = 'AUTHORIZED', authorized_at = CURRENT_TIMESTAMP, version = version + 1,
updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'PENDING_APPROVAL'`, revealID)
		if updateErr != nil {
			return nil, translateRecoveryError("authorize Reveal", updateErr)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, recovery.ErrInvalidState
		}
		eventType, status = "AUTHORIZED", recovery.RevealAuthorized
	} else if status != recovery.RevealPendingApproval {
		eventType = ""
	}
	if eventType != "" {
		if err := appendRevealEventTx(ctx, tx, revealID, eventType, status, approvalCount, nil); err != nil {
			return nil, err
		}
	}
	reveal, err := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Reveal approvals: %w", err)
	}
	return reveal, nil
}

func (s *Store) ExportRevealAuthorization(context.Context, recovery.ExportRevealAuthorizationInput) (*recovery.StoredRevealAuthorization, error) {
	return nil, recovery.ErrRevealExecutionUnavailable
}

func (s *Store) exportRevealAuthorizationFuture(ctx context.Context, input recovery.ExportRevealAuthorizationInput) (*recovery.StoredRevealAuthorization, error) {
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validEvidenceID(input.RevealExternalID) || zeroRecoveryHash(input.AuthorizationDigest) ||
		input.SignerDomain != revealAuthorizationDomainV1 || !validEvidenceID(input.SignerAlgorithm) ||
		!validEvidenceID(input.SignerKeyID) || len(input.Signature) == 0 || input.ExportedAt.IsZero() {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin export Reveal authorization: %w", err)
	}
	defer tx.Rollback()
	revealID, _, _, _, status, _, err := lockRevealScopeTx(ctx, tx, input.Key, input.LeaseOwner,
		input.FencingToken, input.RevealExternalID)
	if err != nil {
		if errors.Is(err, recovery.ErrStaleFence) {
			existing, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, true)
			if loadErr == nil && sameRevealAuthorizationExport(existing, input) {
				_ = tx.Commit()
				return existing, nil
			}
		}
		return nil, err
	}
	if status == recovery.RevealAuthorizationExported {
		existing, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
		if loadErr != nil || !sameRevealAuthorizationExport(existing, input) {
			return nil, recovery.ErrHashDrift
		}
		_ = tx.Commit()
		return existing, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE recovery_reveal_authorizations
SET status = 'AUTHORIZATION_EXPORTED', authorization_digest = $2,
authorization_signer_domain = $3, authorization_signer_algorithm = $4,
authorization_signer_key_id = $5, authorization_signature = $6,
authorization_exported_at = $7, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status = 'AUTHORIZED' AND expires_at > CURRENT_TIMESTAMP
  AND $7 >= authorized_at AND $7 <= CURRENT_TIMESTAMP + interval '5 minutes'`, revealID,
		input.AuthorizationDigest[:], input.SignerDomain, input.SignerAlgorithm, input.SignerKeyID,
		input.Signature, normalizeEvidenceDBTime(input.ExportedAt))
	if err != nil {
		return nil, translateRecoveryError("export Reveal authorization", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrInvalidState
	}
	if err := appendRevealEventTx(ctx, tx, revealID, "AUTHORIZATION_EXPORTED",
		recovery.RevealAuthorizationExported, 0, input.AuthorizationDigest[:]); err != nil {
		return nil, err
	}
	reveal, err := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit export Reveal authorization: %w", err)
	}
	return reveal, nil
}

func (s *Store) CommitRevealExecutorReceipt(context.Context, recovery.CommitRevealExecutorReceiptInput) (*recovery.StoredRevealAuthorization, error) {
	return nil, recovery.ErrRevealExecutionUnavailable
}

func (s *Store) commitRevealExecutorReceiptFuture(ctx context.Context, input recovery.CommitRevealExecutorReceiptInput) (*recovery.StoredRevealAuthorization, error) {
	if !validRecoveryKeyAndFence(input.Key, input.LeaseOwner, input.FencingToken) ||
		!validEvidenceID(input.RevealExternalID) ||
		(input.Disposition != recovery.RevealCompleted && input.Disposition != recovery.RevealAborted) ||
		zeroRecoveryHash(input.ReceiptDigest) || zeroRecoveryHash(input.TranscriptDigest) ||
		zeroRecoveryHash(input.SinkAttestationDigest) || !validEvidenceID(input.ExecutorProfile) ||
		!validEvidenceID(input.ExecutorAlgorithm) || !validEvidenceID(input.ExecutorKeyID) ||
		len(input.ExecutorSignature) == 0 || input.CompletedAt.IsZero() {
		return nil, recovery.ErrInvalidData
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin Reveal executor receipt: %w", err)
	}
	defer tx.Rollback()
	revealID, _, _, _, status, _, err := lockRevealScopeTx(ctx, tx, input.Key, input.LeaseOwner,
		input.FencingToken, input.RevealExternalID)
	if err != nil {
		if errors.Is(err, recovery.ErrStaleFence) {
			existing, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, true)
			if loadErr == nil && sameRevealExecutorReceiptTx(ctx, tx, existing, input) {
				_ = tx.Commit()
				return existing, nil
			}
		}
		return nil, err
	}
	if status == recovery.RevealCompleted || status == recovery.RevealAborted {
		existing, loadErr := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
		if loadErr != nil || !sameRevealExecutorReceiptTx(ctx, tx, existing, input) {
			return nil, recovery.ErrHashDrift
		}
		_ = tx.Commit()
		return existing, nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO recovery_reveal_executor_receipts (
reveal_id, disposition, receipt_digest, transcript_digest, sink_attestation_digest,
executor_profile, executor_algorithm, executor_key_id, executor_signature, completed_at, created_at)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP
WHERE $10 <= CURRENT_TIMESTAMP + interval '5 minutes'`, revealID, input.Disposition,
		input.ReceiptDigest[:], input.TranscriptDigest[:], input.SinkAttestationDigest[:],
		input.ExecutorProfile, input.ExecutorAlgorithm, input.ExecutorKeyID, input.ExecutorSignature,
		normalizeEvidenceDBTime(input.CompletedAt))
	if err != nil {
		return nil, translateRecoveryError("insert Reveal executor receipt", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrInvalidState
	}
	result, err = tx.ExecContext(ctx, `UPDATE recovery_reveal_authorizations
SET status = $2, completed_at = $3, version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND status IN ('AUTHORIZATION_EXPORTED','OPERATOR_REVIEW_REQUIRED')
  AND authorization_exported_at <= $3`, revealID, input.Disposition, normalizeEvidenceDBTime(input.CompletedAt))
	if err != nil {
		return nil, translateRecoveryError("complete Reveal authorization", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrInvalidState
	}
	if err := appendRevealEventTx(ctx, tx, revealID, input.Disposition, input.Disposition, 0,
		input.ReceiptDigest[:]); err != nil {
		return nil, err
	}
	operationStatus := "SUCCEEDED"
	errorCode := ""
	if input.Disposition == recovery.RevealAborted {
		operationStatus, errorCode = "FAILED", "REVEAL_ABORTED"
	}
	response, err := canonicalEvidenceJSON(map[string]any{"disposition": input.Disposition,
		"receipt_digest": fmt.Sprintf("%x", input.ReceiptDigest[:]), "reveal_id": input.RevealExternalID, "version": 1})
	if err != nil {
		return nil, err
	}
	result, err = tx.ExecContext(ctx, `UPDATE integration_operations
SET status = $5, response_snapshot = $6::jsonb, error_code = NULLIF($7, ''),
completed_at = CURRENT_TIMESTAMP, lease_owner = NULL, lease_expires_at = NULL,
version = version + 1, updated_at = CURRENT_TIMESTAMP
WHERE integration_client_id = $1 AND operation_id = $2 AND fencing_token = $3
  AND lease_owner = $4 AND lease_expires_at > CURRENT_TIMESTAMP AND status = 'RUNNING'`,
		input.Key.ClientID, input.Key.OperationID, input.FencingToken, input.LeaseOwner,
		operationStatus, response, errorCode)
	if err != nil {
		return nil, translateRecoveryError("complete Reveal operation", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, recovery.ErrStaleFence
	}
	reveal, err := loadRevealAuthorizationTx(ctx, tx, input.RevealExternalID, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit Reveal executor receipt: %w", err)
	}
	return reveal, nil
}

func (s *Store) GetRevealAuthorization(ctx context.Context, externalID string) (*recovery.StoredRevealAuthorization, error) {
	if !validEvidenceID(externalID) {
		return nil, recovery.ErrInvalidData
	}
	reveal, err := scanRevealAuthorization(s.db.QueryRowContext(ctx, `SELECT `+revealAuthorizationColumns+`
FROM recovery_reveal_authorizations reveal
JOIN recovery_verification_exports export ON export.id = reveal.verification_export_id
JOIN recovery_epoch_plans plan ON plan.id = reveal.plan_id
JOIN manifests manifest ON manifest.id = reveal.manifest_id
JOIN pools pool ON pool.id = reveal.pool_id
WHERE reveal.external_id = $1`, externalID))
	if err != nil {
		return nil, translateRecoveryError("get Reveal authorization", err)
	}
	return reveal, nil
}

func assessPortableEvidenceTx(ctx context.Context, tx *sql.Tx, planExternalID, exportFormat string) (string, []string, string, string, error) {
	var planID, manifestID string
	var portableVersion, trustProfile, suite, proofProfile, ceremonyAlgorithm sql.NullString
	var platformDomain, platformAlgorithm, platformKey sql.NullString
	var platformSignature []byte
	var rootAlgorithm, rootIssuer, rootKeyID, rootProtocol sql.NullString
	var rootPortableSignature []byte
	var expectedMembers, expectedResources, governanceThreshold, approvals, acknowledgements, receipts, shareProofs, accountProofs int
	err := tx.QueryRowContext(ctx, `SELECT plan.id, manifest.id,
plan.portable_format_version, plan.root_trust_profile_id, plan.crypto_suite_id,
plan.provider_proof_profile, plan.ceremony_attestation_algorithm,
manifest.platform_signature_domain, manifest.platform_algorithm, manifest.platform_key_ref, manifest.platform_signature,
root.attestation_algorithm, root.attestation_issuer, root.portable_attestation_key_id,
root.attestation_protocol_version, root.portable_attestation_signature,
plan.expected_member_count, plan.expected_resource_count, plan.governance_threshold,
(SELECT count(*) FROM manifest_signatures signature
 WHERE signature.manifest_id = manifest.id AND signature.migration_state = 'CURRENT'
   AND signature.signing_algorithm = 'Ed25519' AND octet_length(signature.signature) = 64),
(SELECT count(*) FROM recovery_share_deliveries delivery
 WHERE delivery.recovery_plan_id = plan.id AND delivery.migration_state = 'CURRENT'
   AND delivery.delivery_status = 'ACKNOWLEDGED' AND delivery.acknowledgement_algorithm = 'Ed25519'
   AND octet_length(delivery.acknowledgement_signature) = 64),
(SELECT count(*) FROM recovery_member_artifact_receipts receipt WHERE receipt.plan_id = plan.id),
(SELECT count(*) FROM recovery_share_deliveries delivery
 WHERE delivery.recovery_plan_id = plan.id AND delivery.migration_state = 'CURRENT'
   AND delivery.provider_proof_algorithm IS NOT NULL AND delivery.provider_proof_key_id IS NOT NULL
   AND delivery.provider_proof_algorithm = 'Ed25519'
   AND delivery.provider_proof_protocol_version = 'trusted-pool/provider-proof-statement/v1'
   AND delivery.portable_provider_proof_signature IS NOT NULL),
(SELECT count(*) FROM recovery_control_evidence evidence
 WHERE evidence.plan_id = plan.id AND evidence.status = 'COMMITTED'
   AND evidence.provider_attestation_algorithm IS NOT NULL
   AND evidence.provider_attestation_signature IS NOT NULL
   AND evidence.provider_attestation_algorithm = 'Ed25519'
   AND evidence.provider_attestation_protocol_version = 'trusted-pool/provider-proof-statement/v1')
FROM recovery_epoch_plans plan
JOIN manifests manifest ON manifest.recovery_plan_id = plan.id AND manifest.migration_state = 'CURRENT'
JOIN recovery_root_artifacts root ON root.plan_id = plan.id AND root.migration_state = 'CURRENT'
JOIN permanent_replacement_cases replacement ON replacement.plan_id = plan.id
JOIN recovery_pool_provider_commit_attempts provider_commit ON provider_commit.plan_id = plan.id
WHERE plan.external_id = $1 AND plan.status = 'FINALIZED' AND manifest.status = 'ACTIVE'
  AND replacement.status = 'FINALIZED' AND provider_commit.status = 'RELEASED'
FOR SHARE OF plan, manifest, root, replacement, provider_commit`, planExternalID).Scan(&planID, &manifestID,
		&portableVersion, &trustProfile, &suite, &proofProfile, &ceremonyAlgorithm,
		&platformDomain, &platformAlgorithm, &platformKey, &platformSignature,
		&rootAlgorithm, &rootIssuer, &rootKeyID, &rootProtocol,
		&rootPortableSignature,
		&expectedMembers, &expectedResources, &governanceThreshold, &approvals, &acknowledgements,
		&receipts, &shareProofs, &accountProofs)
	if err != nil {
		return "", nil, "", "", translateRecoveryError("assess portable recovery evidence", err)
	}
	missing := make([]string, 0, 8)
	if !portableVersion.Valid || portableVersion.String != offlineBundleProtocolV1 ||
		!trustProfile.Valid || !suite.Valid || !proofProfile.Valid || proofProfile.String != providerProofStatementV1 {
		missing = append(missing, "PORTABLE_PROFILE")
	}
	if portableVersion.String != exportFormat {
		missing = append(missing, "EXPORT_FORMAT_MISMATCH")
	}
	if !ceremonyAlgorithm.Valid || ceremonyAlgorithm.String != ed25519Algorithm {
		missing = append(missing, "CEREMONY_ATTESTATION_PROFILE")
	}
	if platformDomain.String != manifestSignatureDomainV2 || platformAlgorithm.String != ed25519Algorithm ||
		!platformKey.Valid || len(platformSignature) != 64 {
		missing = append(missing, "PLATFORM_SIGNATURE_V2")
	}
	if rootAlgorithm.String != ed25519Algorithm || !rootIssuer.Valid || !rootKeyID.Valid ||
		rootProtocol.String != providerProofStatementV1 || len(rootPortableSignature) != 64 {
		missing = append(missing, "ROOT_PROVIDER_PROOF_PROFILE")
	}
	if shareProofs != expectedMembers {
		missing = append(missing, "SHARE_PROVIDER_PROOF_PROFILE")
	}
	if receipts != expectedMembers {
		missing = append(missing, "MEMBER_ARTIFACT_RECEIPTS")
	}
	if accountProofs != expectedResources {
		missing = append(missing, "ACCOUNT_PROVIDER_PROOF_PROFILE")
	}
	if approvals < governanceThreshold {
		missing = append(missing, "MANIFEST_APPROVALS")
	}
	if acknowledgements != expectedMembers {
		missing = append(missing, "SHARE_ACKNOWLEDGEMENTS")
	}
	capability := recovery.VerificationCapabilityRevealCapable
	if len(missing) != 0 {
		capability = recovery.VerificationCapabilityLegacyExportLimited
	}
	return capability, missing, planID, manifestID, nil
}

func loadPublicProviderProofsTx(ctx context.Context, tx *sql.Tx, snapshot *recovery.PublicEvidenceSnapshot,
	planID, operationID, poolExternalID string) error {
	var protocol sql.NullString
	var epoch uint64
	var ceremonyAlgorithm sql.NullString
	var ceremonyProviderID, ceremonyKeyID, rootProviderID, rootAlgorithm, rootKeyID, rootProtocol sql.NullString
	var ceremonySubject, rootSubject, ceremonySignature, rootSignature []byte
	err := tx.QueryRowContext(ctx, `SELECT plan.provider_proof_profile, plan.to_epoch,
plan.ceremony_attestation_algorithm, plan.bootstrap_attestation_key_id,
plan.bootstrap_attestation_issuer, plan.bootstrap_attestation_digest, plan.bootstrap_attestation_signature,
root.provider,
root.attestation_algorithm, root.portable_attestation_key_id, root.attestation_protocol_version,
root.recovery_package_hash, root.portable_attestation_signature
FROM recovery_epoch_plans plan JOIN recovery_root_artifacts root ON root.plan_id = plan.id
WHERE plan.id = $1`, planID).Scan(&protocol, &epoch, &ceremonyAlgorithm, &ceremonyKeyID,
		&ceremonyProviderID, &ceremonySubject, &ceremonySignature, &rootProviderID,
		&rootAlgorithm, &rootKeyID, &rootProtocol,
		&rootSubject, &rootSignature)
	if err != nil {
		return translateRecoveryError("load public provider proof headers", err)
	}
	ceremonyHash, rootHash := [sha256.Size]byte{}, [sha256.Size]byte{}
	if copyEvidenceHash(&ceremonyHash, ceremonySubject) != nil || copyEvidenceHash(&rootHash, rootSubject) != nil {
		return recovery.ErrInvalidData
	}
	if completePublicProviderProof(protocol, ceremonyAlgorithm, ceremonyProviderID, ceremonyKeyID, ceremonySignature) {
		snapshot.ProviderProofs = append(snapshot.ProviderProofs, recovery.PublicProviderProof{
			Statement: recovery.PublicProviderProofStatement{
				ProtocolVersion: protocol.String, Kind: "CEREMONY_ATTESTATION", ProviderID: ceremonyProviderID.String,
				OperationID: operationID, PoolID: poolExternalID, Epoch: epoch, SubjectHash: ceremonyHash,
			}, Algorithm: ceremonyAlgorithm.String, KeyID: ceremonyKeyID.String, Signature: ceremonySignature})
	}
	if completePublicProviderProof(rootProtocol, rootAlgorithm, rootProviderID, rootKeyID, rootSignature) {
		snapshot.ProviderProofs = append(snapshot.ProviderProofs, recovery.PublicProviderProof{
			Statement: recovery.PublicProviderProofStatement{
				ProtocolVersion: rootProtocol.String, Kind: "RECOVERY_PACKAGE", ProviderID: rootProviderID.String,
				OperationID: operationID, PoolID: poolExternalID, Epoch: epoch, SubjectHash: rootHash,
			}, Algorithm: rootAlgorithm.String, KeyID: rootKeyID.String, Signature: rootSignature})
	}
	rows, err := tx.QueryContext(ctx, `SELECT member.external_id, delivery.share_index,
delivery.provider_proof_protocol_version, delivery.provider_proof_digest,
delivery.provider_proof_algorithm, delivery.provider_proof_key_id, delivery.portable_provider_proof_signature
FROM recovery_share_deliveries delivery JOIN members member ON member.id = delivery.member_id
WHERE delivery.recovery_plan_id = $1 AND delivery.migration_state = 'CURRENT'
ORDER BY delivery.share_index, member.external_id`, planID)
	if err != nil {
		return fmt.Errorf("load public Share provider proofs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var proof recovery.PublicProviderProof
		var proofProtocol, algorithm, keyID sql.NullString
		var subject []byte
		if err := rows.Scan(&proof.Statement.MemberID, &proof.Statement.ShareIndex, &proofProtocol,
			&subject, &algorithm, &keyID, &proof.Signature); err != nil {
			return fmt.Errorf("scan public Share provider proof: %w", err)
		}
		if err := copyEvidenceHash(&proof.Statement.SubjectHash, subject); err != nil {
			return err
		}
		proof.Statement.ProtocolVersion = proofProtocol.String
		proof.Statement.Kind = "SHARE_PROOF"
		proof.Statement.ProviderID = rootProviderID.String
		proof.Statement.OperationID = operationID
		proof.Statement.PoolID = poolExternalID
		proof.Statement.Epoch = epoch
		proof.Algorithm, proof.KeyID = algorithm.String, keyID.String
		if completePublicProviderProof(proofProtocol, algorithm, rootProviderID, keyID, proof.Signature) {
			snapshot.ProviderProofs = append(snapshot.ProviderProofs, proof)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT account.account_external_id,
evidence.provider_attestation_protocol_version, evidence.provider_attestation_issuer,
evidence.provider_attestation_digest,
evidence.provider_attestation_algorithm, evidence.provider_attestation_key_id,
evidence.provider_attestation_signature
FROM recovery_control_evidence evidence
JOIN recovery_plan_resource_accounts account ON account.plan_id = evidence.plan_id
  AND account.resource_account_id = evidence.resource_account_id
WHERE evidence.plan_id = $1 AND evidence.status = 'COMMITTED'
  AND evidence.provider_attestation_algorithm = 'Ed25519'
  AND octet_length(evidence.provider_attestation_signature) = 64
  AND evidence.provider_attestation_protocol_version = 'trusted-pool/provider-proof-statement/v1'
ORDER BY account.account_external_id`, planID)
	if err != nil {
		return fmt.Errorf("load public account provider proofs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var proof recovery.PublicProviderProof
		var subject []byte
		if err := rows.Scan(&proof.Statement.AccountRef, &proof.Statement.ProtocolVersion, &proof.Statement.ProviderID,
			&subject, &proof.Algorithm, &proof.KeyID, &proof.Signature); err != nil {
			return fmt.Errorf("scan public account provider proof: %w", err)
		}
		if err := copyEvidenceHash(&proof.Statement.SubjectHash, subject); err != nil {
			return err
		}
		proof.Statement.Kind = "ACCOUNT_ATTESTATION"
		proof.Statement.OperationID = operationID
		proof.Statement.PoolID = poolExternalID
		proof.Statement.Epoch = epoch
		snapshot.ProviderProofs = append(snapshot.ProviderProofs, proof)
	}
	return rows.Err()
}

func completePublicProviderProof(protocol, algorithm, providerID, keyID sql.NullString, signature []byte) bool {
	return protocol.Valid && algorithm.Valid && providerID.Valid && keyID.Valid && len(signature) != 0 &&
		protocol.String == providerProofStatementV1 && algorithm.String == ed25519Algorithm && len(signature) == 64 &&
		validEvidenceID(protocol.String) && validEvidenceID(algorithm.String) &&
		validEvidenceID(providerID.String) && validEvidenceID(keyID.String)
}

func locateEvidencePoolByPlan(ctx context.Context, tx *sql.Tx, planExternalID string) (string, string, error) {
	var poolID, externalID string
	err := tx.QueryRowContext(ctx, `SELECT pool.id, pool.external_id
FROM recovery_epoch_plans plan JOIN pools pool ON pool.id = plan.pool_id
WHERE plan.external_id = $1`, planExternalID).Scan(&poolID, &externalID)
	if err != nil {
		return "", "", translateRecoveryError("locate evidence Pool by plan", err)
	}
	return poolID, externalID, nil
}

func locateEvidencePoolByExport(ctx context.Context, tx *sql.Tx, exportExternalID string) (string, string, error) {
	var poolID, externalID string
	err := tx.QueryRowContext(ctx, `SELECT pool.id, pool.external_id
FROM recovery_verification_exports export
JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
JOIN pools pool ON pool.id = plan.pool_id
WHERE export.external_id = $1`, exportExternalID).Scan(&poolID, &externalID)
	if err != nil {
		return "", "", translateRecoveryError("locate evidence Pool by export", err)
	}
	return poolID, externalID, nil
}

func lockEvidencePool(ctx context.Context, tx *sql.Tx, poolID, poolExternalID string) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, poolExternalID); err != nil {
		return fmt.Errorf("lock evidence Pool advisory key: %w", err)
	}
	var lockedID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM pools WHERE id = $1 FOR UPDATE`, poolID).Scan(&lockedID); err != nil {
		return translateRecoveryError("lock evidence Pool", err)
	}
	return nil
}

func lockRevealScopeTx(ctx context.Context, tx *sql.Tx, key recovery.OperationKey, leaseOwner string,
	fence int64, revealExternalID string) (string, string, string, string, string, uint16, error) {
	var revealID, poolID, poolExternalID, epochID string
	err := tx.QueryRowContext(ctx, `SELECT reveal.id, pool.id, pool.external_id, epoch.id
FROM recovery_reveal_authorizations reveal
JOIN pools pool ON pool.id = reveal.pool_id
JOIN membership_epochs epoch ON epoch.pool_id = reveal.pool_id AND epoch.epoch = reveal.membership_epoch
WHERE reveal.external_id = $1`, revealExternalID).Scan(&revealID, &poolID, &poolExternalID, &epochID)
	if err != nil {
		return "", "", "", "", "", 0, translateRecoveryError("locate Reveal scope", err)
	}
	if err := lockEvidencePool(ctx, tx, poolID, poolExternalID); err != nil {
		return "", "", "", "", "", 0, err
	}
	var status string
	var threshold uint16
	err = tx.QueryRowContext(ctx, `SELECT reveal.status, reveal.governance_threshold
FROM integration_operations operation
JOIN recovery_reveal_authorizations reveal ON reveal.integration_operation_id = operation.id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2
  AND operation.lease_owner = $3 AND operation.fencing_token = $4
  AND operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'
  AND reveal.id = $5
FOR UPDATE OF operation, reveal`, key.ClientID, key.OperationID, leaseOwner, fence, revealID).
		Scan(&status, &threshold)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", "", 0, recovery.ErrStaleFence
	}
	if err != nil {
		return "", "", "", "", "", 0, translateRecoveryError("lock Reveal scope", err)
	}
	return revealID, poolID, poolExternalID, epochID, status, threshold, nil
}

func appendRevealEventTx(ctx context.Context, tx *sql.Tx, revealID, eventType, status string,
	approvalCount int, evidenceDigest []byte) error {
	var occurredAt time.Time
	var revealExternalID string
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&occurredAt); err != nil {
		return fmt.Errorf("read Reveal database clock: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT external_id FROM recovery_reveal_authorizations WHERE id = $1`, revealID).
		Scan(&revealExternalID); err != nil {
		return translateRecoveryError("load Reveal event public id", err)
	}
	payload := map[string]any{"approval_count": approvalCount, "event_type": eventType,
		"occurred_at": occurredAt.UTC().Format(time.RFC3339Nano), "reveal_id": revealExternalID,
		"status": status, "version": 1}
	if len(evidenceDigest) != 0 {
		payload["evidence_digest"] = fmt.Sprintf("%x", evidenceDigest)
	}
	canonical, err := canonicalEvidenceJSON(payload)
	if err != nil {
		return err
	}
	var sequence int64 = 1
	var previousHash []byte
	err = tx.QueryRowContext(ctx, `SELECT sequence + 1, event_hash FROM recovery_reveal_events
WHERE reveal_id = $1 ORDER BY sequence DESC LIMIT 1`, revealID).Scan(&sequence, &previousHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load Reveal event head: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO recovery_reveal_events (
reveal_id, sequence, event_type, event_payload, canonical_bytes, previous_event_hash,
event_hash, occurred_at, recorded_at)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, recovery_reveal_event_hash($6, $5), $7, CURRENT_TIMESTAMP)`,
		revealID, sequence, eventType, canonical, canonical, previousHash, occurredAt)
	if err != nil {
		return translateRecoveryError("append Reveal event", err)
	}
	return nil
}

func loadVerificationExportTx(ctx context.Context, tx *sql.Tx, externalID string, forUpdate bool) (*recovery.StoredVerificationExport, error) {
	query := `SELECT ` + verificationExportColumns + `
FROM recovery_verification_exports export
JOIN recovery_epoch_plans plan ON plan.id = export.plan_id
JOIN manifests manifest ON manifest.id = export.manifest_id
JOIN pools pool ON pool.id = plan.pool_id
JOIN integration_operations operation ON operation.id = export.integration_operation_id
WHERE export.external_id = $1`
	if forUpdate {
		query += ` FOR UPDATE OF export`
	}
	export, err := scanVerificationExport(tx.QueryRowContext(ctx, query, externalID))
	if err != nil {
		return nil, translateRecoveryError("load verification export", err)
	}
	return export, nil
}

func scanVerificationExport(row scanner) (*recovery.StoredVerificationExport, error) {
	result := &recovery.StoredVerificationExport{}
	var inventoryDigest, bundleDigest []byte
	var signerDomain, signerAlgorithm, signerKeyID sql.NullString
	var signature []byte
	var generatedAt sql.NullTime
	var missing pq.StringArray
	if err := row.Scan(&result.ID, &result.ExternalID, &result.PlanExternalID,
		&result.ManifestExternalID, &result.PoolExternalID, &result.OperationKey.ClientID,
		&result.OperationKey.OperationID, &result.MembershipEpoch,
		&result.FormatVersion, &result.Capability, &result.Status, &inventoryDigest, &bundleDigest,
		&signerDomain, &signerAlgorithm, &signerKeyID, &signature, &generatedAt, &result.Version,
		&result.CreatedAt, &result.UpdatedAt, &missing); err != nil {
		return nil, err
	}
	if len(inventoryDigest) != 0 {
		if err := copyEvidenceHash(&result.InventoryDigest, inventoryDigest); err != nil {
			return nil, err
		}
	}
	if len(bundleDigest) != 0 {
		if err := copyEvidenceHash(&result.BundleDigest, bundleDigest); err != nil {
			return nil, err
		}
	}
	result.SignerDomain, result.SignerAlgorithm, result.SignerKeyID = signerDomain.String,
		signerAlgorithm.String, signerKeyID.String
	result.Signature = append([]byte(nil), signature...)
	if generatedAt.Valid {
		result.GeneratedAt = &generatedAt.Time
	}
	result.MissingEvidenceCodes = append([]string(nil), missing...)
	return result, nil
}

func loadRevealAuthorizationTx(ctx context.Context, tx *sql.Tx, externalID string, forUpdate bool) (*recovery.StoredRevealAuthorization, error) {
	query := `SELECT ` + revealAuthorizationColumns + `
FROM recovery_reveal_authorizations reveal
JOIN recovery_verification_exports export ON export.id = reveal.verification_export_id
JOIN recovery_epoch_plans plan ON plan.id = reveal.plan_id
JOIN manifests manifest ON manifest.id = reveal.manifest_id
JOIN pools pool ON pool.id = reveal.pool_id
WHERE reveal.external_id = $1`
	if forUpdate {
		query += ` FOR UPDATE OF reveal`
	}
	reveal, err := scanRevealAuthorization(tx.QueryRowContext(ctx, query, externalID))
	if err != nil {
		return nil, translateRecoveryError("load Reveal authorization", err)
	}
	return reveal, nil
}

func scanRevealAuthorization(row scanner) (*recovery.StoredRevealAuthorization, error) {
	result := &recovery.StoredRevealAuthorization{}
	var scopeHash, challengeHash, authorizationDigest []byte
	var signerDomain, signerAlgorithm, signerKeyID sql.NullString
	var authorizationSignature []byte
	var authorizedAt, exportedAt, completedAt sql.NullTime
	if err := row.Scan(&result.ID, &result.ExternalID, &result.PlanExternalID, &result.ExportExternalID,
		&result.ManifestExternalID, &result.PoolExternalID, &result.MembershipEpoch, &result.Purpose,
		&scopeHash, &challengeHash, &result.GovernanceThreshold, &result.RecoveryThreshold,
		&result.ApprovalCount, &result.Status, &authorizationDigest, &signerDomain, &signerAlgorithm,
		&signerKeyID, &authorizationSignature, &result.ExpiresAt, &authorizedAt, &exportedAt,
		&completedAt, &result.Version, &result.CreatedAt, &result.UpdatedAt); err != nil {
		return nil, err
	}
	if copyEvidenceHash(&result.ScopeHash, scopeHash) != nil || copyEvidenceHash(&result.ChallengeHash, challengeHash) != nil {
		return nil, recovery.ErrInvalidData
	}
	if len(authorizationDigest) != 0 {
		if err := copyEvidenceHash(&result.AuthorizationDigest, authorizationDigest); err != nil {
			return nil, err
		}
	}
	result.AuthorizationSignerDomain = signerDomain.String
	result.AuthorizationSignerAlgorithm = signerAlgorithm.String
	result.AuthorizationSignerKeyID = signerKeyID.String
	result.AuthorizationSignature = append([]byte(nil), authorizationSignature...)
	if authorizedAt.Valid {
		result.AuthorizedAt = &authorizedAt.Time
	}
	if exportedAt.Valid {
		result.AuthorizationExportedAt = &exportedAt.Time
	}
	if completedAt.Valid {
		result.CompletedAt = &completedAt.Time
	}
	return result, nil
}

func sameVerificationExport(existing *recovery.StoredVerificationExport, input recovery.CommitVerificationExportInput) bool {
	return existing != nil && existing.Status == recovery.VerificationExportAvailable &&
		existing.InventoryDigest == input.InventoryDigest && existing.BundleDigest == input.BundleDigest &&
		existing.SignerDomain == input.SignerDomain && existing.SignerAlgorithm == input.SignerAlgorithm &&
		existing.SignerKeyID == input.SignerKeyID && bytes.Equal(existing.Signature, input.Signature) &&
		existing.GeneratedAt != nil && sameEvidenceDBTime(*existing.GeneratedAt, input.GeneratedAt)
}

func sameRevealAuthorizationExport(existing *recovery.StoredRevealAuthorization, input recovery.ExportRevealAuthorizationInput) bool {
	return existing != nil && existing.Status == recovery.RevealAuthorizationExported &&
		existing.AuthorizationDigest == input.AuthorizationDigest &&
		existing.AuthorizationSignerDomain == input.SignerDomain &&
		existing.AuthorizationSignerAlgorithm == input.SignerAlgorithm &&
		existing.AuthorizationSignerKeyID == input.SignerKeyID &&
		bytes.Equal(existing.AuthorizationSignature, input.Signature) &&
		existing.AuthorizationExportedAt != nil && sameEvidenceDBTime(*existing.AuthorizationExportedAt, input.ExportedAt)
}

func revealApprovalsMatchTx(ctx context.Context, tx *sql.Tx, revealID string, approvals []recovery.RevealApproval) bool {
	var storedCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM recovery_reveal_approvals WHERE reveal_id = $1`,
		revealID).Scan(&storedCount); err != nil || storedCount != len(approvals) {
		return false
	}
	for _, approval := range approvals {
		var algorithm, keyID string
		var messageHash, signature []byte
		var verifiedAt time.Time
		err := tx.QueryRowContext(ctx, `SELECT stored.signing_algorithm, stored.signing_key_id,
stored.message_hash, stored.signature, stored.verified_at
FROM recovery_reveal_approvals stored JOIN members member ON member.id = stored.member_id
WHERE stored.reveal_id = $1 AND member.external_id = $2`, revealID, approval.MemberExternalID).
			Scan(&algorithm, &keyID, &messageHash, &signature, &verifiedAt)
		if err != nil || algorithm != approval.Algorithm || keyID != approval.KeyID ||
			!bytes.Equal(messageHash, approval.MessageHash[:]) || !bytes.Equal(signature, approval.Signature) ||
			!sameEvidenceDBTime(verifiedAt, approval.VerifiedAt) {
			return false
		}
	}
	return true
}

func sameRevealExecutorReceiptTx(ctx context.Context, tx *sql.Tx, existing *recovery.StoredRevealAuthorization,
	input recovery.CommitRevealExecutorReceiptInput) bool {
	if existing == nil || existing.Status != input.Disposition || existing.CompletedAt == nil ||
		!sameEvidenceDBTime(*existing.CompletedAt, input.CompletedAt) {
		return false
	}
	var disposition, profile, algorithm, keyID string
	var receiptDigest, transcriptDigest, sinkDigest, signature []byte
	var completedAt time.Time
	err := tx.QueryRowContext(ctx, `SELECT disposition, receipt_digest, transcript_digest,
sink_attestation_digest, executor_profile, executor_algorithm, executor_key_id,
executor_signature, completed_at FROM recovery_reveal_executor_receipts WHERE reveal_id = $1`, existing.ID).
		Scan(&disposition, &receiptDigest, &transcriptDigest, &sinkDigest, &profile, &algorithm,
			&keyID, &signature, &completedAt)
	return err == nil && disposition == input.Disposition && bytes.Equal(receiptDigest, input.ReceiptDigest[:]) &&
		bytes.Equal(transcriptDigest, input.TranscriptDigest[:]) && bytes.Equal(sinkDigest, input.SinkAttestationDigest[:]) &&
		profile == input.ExecutorProfile && algorithm == input.ExecutorAlgorithm && keyID == input.ExecutorKeyID &&
		bytes.Equal(signature, input.ExecutorSignature) && sameEvidenceDBTime(completedAt, input.CompletedAt)
}

func normalizeEvidenceDBTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func sameEvidenceDBTime(left, right time.Time) bool {
	return normalizeEvidenceDBTime(left).Equal(normalizeEvidenceDBTime(right))
}

func validRecoveryKeyAndFence(key recovery.OperationKey, leaseOwner string, fence int64) bool {
	return validRecoveryID(key.ClientID) && validRecoveryID(key.OperationID) &&
		validEvidenceID(leaseOwner) && fence > 0
}

func validPublicEvidenceSnapshotInput(input recovery.LoadPublicEvidenceSnapshotInput) bool {
	if !validRecoveryID(input.Key.ClientID) || !validRecoveryID(input.Key.OperationID) ||
		!validEvidenceID(input.ExportID) {
		return false
	}
	if input.LeaseOwner == "" && input.FencingToken == 0 {
		return true
	}
	return validEvidenceID(input.LeaseOwner) && input.FencingToken > 0
}

func validEvidenceID(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 512
}

func validEvidenceLease(owner string, duration time.Duration) bool {
	return validEvidenceID(owner) && duration > 0 && duration <= 5*time.Minute
}

func validRevealIntents(intents []recovery.RevealApprovalIntent) bool {
	if len(intents) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		if !validEvidenceID(intent.MemberExternalID) || zeroRecoveryHash(intent.ExpectedMessageHash) {
			return false
		}
		if _, duplicate := seen[intent.MemberExternalID]; duplicate {
			return false
		}
		seen[intent.MemberExternalID] = struct{}{}
	}
	return true
}

func validRevealApprovals(approvals []recovery.RevealApproval) bool {
	if len(approvals) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(approvals))
	for _, approval := range approvals {
		if !validEvidenceID(approval.MemberExternalID) || !validEvidenceID(approval.Algorithm) ||
			!validEvidenceID(approval.KeyID) || zeroRecoveryHash(approval.MessageHash) ||
			len(approval.Signature) == 0 || approval.VerifiedAt.IsZero() {
			return false
		}
		if _, duplicate := seen[approval.MemberExternalID]; duplicate {
			return false
		}
		seen[approval.MemberExternalID] = struct{}{}
	}
	return true
}

func copyEvidenceHash(target *[sha256.Size]byte, source []byte) error {
	if len(source) != sha256.Size {
		return recovery.ErrInvalidData
	}
	copy(target[:], source)
	return nil
}

func canonicalEvidenceJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	canonical, err := canonicalJSONObject(encoded)
	if err != nil {
		return nil, recovery.ErrInvalidData
	}
	return canonical, nil
}

var _ recovery.EvidenceStore = (*Store)(nil)
