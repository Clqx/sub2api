package repository

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *trustedPoolRepository) PreparePermanentRotation(ctx context.Context, input service.PrepareTrustedPoolPermanentRotationInput) (_ *service.TrustedPoolPermanentRotationPrepareResult, err error) {
	if r.permanentCredentialSealer == nil || r.permanentCredentialTTL <= 0 {
		return nil, service.ErrTrustedPoolPermanentCredentialEnvelopeUnavailable
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	if err = requireTrustedPoolClientBinding(ctx, tx, input.ActorClientID, input.ExternalPoolID); err != nil {
		return nil, err
	}
	if existing, found, readErr := r.loadPermanentPrepareResult(ctx, tx, input.ActorClientID, input.OperationID, true); readErr != nil {
		return nil, readErr
	} else if found {
		if !samePermanentPrepareRequest(existing, input) {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return existing, nil
	}

	seats, err := lockTrustedPoolSeats(ctx, tx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	// 等待 Pool 锁后再查一次，覆盖两个相同 prepare 并发首次都未读到父记录的窗口。
	if existing, found, readErr := r.loadPermanentPrepareResult(ctx, tx, input.ActorClientID, input.OperationID, true); readErr != nil {
		return nil, readErr
	} else if found {
		if !samePermanentPrepareRequest(existing, input) {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return existing, nil
	}
	if len(seats) != len(input.Seats) || len(input.Credentials) != len(input.Seats) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	for index := range seats {
		actual, expected := seats[index], input.Seats[index]
		if actual.ExternalSeatID != expected.ExternalSeatID || actual.State != service.TrustedPoolSeatStateFrozen ||
			actual.AssignmentEpoch != expected.ExpectedAssignmentEpoch || actual.PrincipalUserID != expected.PrincipalUserID ||
			(expected.GroupID > 0 && actual.GroupID != expected.GroupID) || actual.SubscriptionID != expected.SubscriptionID || actual.APIKeyID != expected.APIKeyID ||
			strings.TrimSpace(input.Credentials[index]) == "" {
			return nil, service.ErrTrustedPoolSeatConflict
		}
	}
	if err = lockAndVerifyPermanentResources(ctx, tx, seats, false); err != nil {
		return nil, err
	}
	if err = requireNoPermanentPendingSettlements(ctx, tx, seats); err != nil {
		return nil, err
	}

	inserted, err := tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_permanent_rotations(
			client_id, prepare_operation_id, protocol_version, external_pool_id, plan_id, ceremony_type,
			from_epoch, to_epoch, request_hash, child_set_hash, prepared_set_hash, seat_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT DO NOTHING
	`, input.ActorClientID, input.OperationID, input.ProtocolVersion, input.ExternalPoolID, input.PlanID, input.CeremonyType,
		input.FromEpoch, input.ToEpoch, input.RequestHash, input.ChildSetHash, input.PreparedSetHash, len(input.Seats))
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	affected, err := inserted.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	result := &service.TrustedPoolPermanentRotationPrepareResult{
		ProtocolVersion: input.ProtocolVersion, OperationID: input.OperationID, ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID, CeremonyType: input.CeremonyType,
		FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch, RequestHash: input.RequestHash,
		ChildSetHash: input.ChildSetHash, PreparedSetHash: input.PreparedSetHash, Status: "prepared", CredentialsDisclosed: true,
		Seats: make([]service.TrustedPoolPermanentRotationPreparedSeat, len(seats)),
	}
	expiresAt := permanentCredentialExpiry(r.currentTime().Add(r.permanentCredentialTTL))
	for index := range seats {
		binding := input.Seats[index]
		binding.GroupID = seats[index].GroupID
		fingerprint := trustedPoolCredentialFingerprint(input.Credentials[index])
		scope := permanentCredentialScopeFromPrepare(input, binding, seats[index], fingerprint, input.PreparedRotationRefs[index])
		envelope, sealErr := r.permanentCredentialSealer.Seal(ctx, input.Credentials[index], scope, expiresAt)
		if sealErr != nil {
			return nil, service.ErrTrustedPoolPermanentCredentialEnvelopeUnavailable
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO trusted_pool_permanent_rotation_seats(
				client_id, prepare_operation_id, external_seat_id, target_member_id, seat_id, principal_user_id,
				group_id, subscription_id, api_key_id, from_epoch, to_epoch,
				expected_assignment_epoch, target_assignment_epoch, from_api_key_version, to_api_key_version, child_operation_id, child_request_hash,
				credential_fingerprint, prepared_rotation_ref,
				prepared_credential_envelope_version, prepared_credential_key_id,
				prepared_credential_wrap_nonce, prepared_credential_wrapped_dek,
				prepared_credential_nonce, prepared_credential_ciphertext, prepared_credential_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
		`, input.ActorClientID, input.OperationID, binding.ExternalSeatID, binding.TargetMemberID, seats[index].ID, binding.PrincipalUserID,
			seats[index].GroupID, binding.SubscriptionID, binding.APIKeyID, input.FromEpoch, input.ToEpoch,
			binding.ExpectedAssignmentEpoch, binding.ExpectedAssignmentEpoch+1, binding.FromAPIKeyVersion, binding.ToAPIKeyVersion, binding.ChildOperationID, binding.ChildRequestHash,
			fingerprint, input.PreparedRotationRefs[index], envelope.Version, envelope.KeyID, envelope.WrapNonce,
			envelope.WrappedDEK, envelope.DataNonce, envelope.Ciphertext, envelope.ExpiresAt); err != nil {
			return nil, translateTrustedPoolConflict(err)
		}
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_seats
			SET state='rotation_prepared', last_operation_id=$2, updated_at=NOW()
			WHERE id=$1 AND state='frozen' AND assignment_epoch=$3
		`, seats[index].ID, binding.ChildOperationID, binding.ExpectedAssignmentEpoch); err != nil {
			return nil, err
		}
		result.Seats[index] = service.TrustedPoolPermanentRotationPreparedSeat{
			TrustedPoolPermanentRotationSeatBinding: binding,
			Credential:                              input.Credentials[index], CredentialFingerprint: fingerprint,
			ActiveAPIKeyVersion: binding.ToAPIKeyVersion, PreparedRotationRef: input.PreparedRotationRefs[index],
			State: "ROTATION_PREPARED", CredentialEnabled: false, SubscriptionEnabled: false,
			CredentialRotationComplete: true,
		}
	}
	superseded, err := tx.ExecContext(ctx, `
		UPDATE trusted_pool_permanent_rotations
		SET status='superseded', superseded_by_prepare_operation_id=$3, superseded_at=NOW()
		WHERE client_id=$1 AND external_pool_id=$2 AND status='retiring' AND to_epoch=$4
	`, input.ActorClientID, input.ExternalPoolID, input.OperationID, input.FromEpoch)
	if err != nil {
		return nil, err
	}
	if affected, rowsErr := superseded.RowsAffected(); rowsErr != nil {
		return nil, rowsErr
	} else if affected > 1 {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT prepared_at FROM trusted_pool_permanent_rotations WHERE client_id=$1 AND prepare_operation_id=$2`, input.ActorClientID, input.OperationID).Scan(&result.PreparedAt); err != nil {
		return nil, err
	}
	for index := range result.Seats {
		result.Seats[index].CompletedAt = result.PreparedAt
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return result, nil
}

func (r *trustedPoolRepository) ActivatePermanentRotation(ctx context.Context, input service.ActivateTrustedPoolPermanentRotationInput) (_ *service.TrustedPoolPermanentRotationActivationResult, err error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	if err = requireTrustedPoolClientBinding(ctx, tx, input.ActorClientID, input.ExternalPoolID); err != nil {
		return nil, err
	}
	parent, err := lockPermanentRotationParent(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if err != nil {
		return nil, err
	}
	if parent.ProtocolVersion != input.ProtocolVersion || parent.ExternalPoolID != input.ExternalPoolID || parent.PlanID != input.PlanID ||
		parent.CeremonyType != input.CeremonyType || parent.FromEpoch != input.FromEpoch ||
		parent.ToEpoch != input.ToEpoch || parent.PreparedSetHash != input.PreparedSetHash || parent.SeatCount != len(input.Seats) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	if parent.Status == "activated_pending_commit" || parent.Status == "committed" || parent.Status == "retiring" || parent.Status == "superseded" {
		if parent.ActivationOperationID != input.OperationID || parent.ActivationRequestHash != input.RequestHash {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		result, loadErr := loadPermanentActivationResult(ctx, tx, parent)
		if loadErr != nil {
			return nil, loadErr
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return result, nil
	}
	if parent.Status != "prepared" || !input.ConcurrencyVerified {
		return nil, service.ErrTrustedPoolNotDrained
	}
	children, err := lockPermanentRotationChildren(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if err != nil {
		return nil, err
	}
	if len(children) != len(input.Seats) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	for index := range children {
		actual, expected := children[index], input.Seats[index]
		if actual.ExternalSeatID != expected.ExternalSeatID || actual.TargetMemberID != expected.TargetMemberID ||
			actual.ExpectedAssignmentEpoch != expected.ExpectedAssignmentEpoch ||
			actual.PrincipalUserID != expected.PrincipalUserID || actual.SubscriptionID != expected.SubscriptionID ||
			actual.APIKeyID != expected.APIKeyID || actual.ToAPIKeyVersion != expected.ActiveAPIKeyVersion ||
			actual.ChildOperationID != expected.ChildOperationID || actual.PreparedRotationRef != expected.PreparedRotationRef ||
			actual.ChildRequestHash != expected.ChildRequestHash || actual.CredentialFingerprint != expected.CredentialFingerprint {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		credential, openErr := r.openPermanentCredentialForActivation(ctx, parent, &children[index])
		if openErr != nil {
			return nil, openErr
		}
		children[index].DecryptedCredential = credential
	}
	seats, err := lockTrustedPoolSeats(ctx, tx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	if len(seats) != len(children) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	for index := range seats {
		if seats[index].ExternalSeatID != children[index].ExternalSeatID || seats[index].ID != children[index].SeatID ||
			seats[index].State != service.TrustedPoolSeatStateRotationPrepared || seats[index].AssignmentEpoch != children[index].ExpectedAssignmentEpoch {
			return nil, service.ErrTrustedPoolSeatConflict
		}
	}
	if err = lockAndVerifyPermanentResources(ctx, tx, seats, false); err != nil {
		return nil, err
	}
	if err = requireNoPermanentPendingSettlements(ctx, tx, seats); err != nil {
		return nil, err
	}

	for index := range children {
		child, seat := children[index], seats[index]
		if err = execTrustedPoolOne(ctx, tx, `UPDATE api_keys SET key=$2, updated_at=NOW() WHERE id=$1 AND status='disabled' AND deleted_at IS NULL`, child.APIKeyID, child.DecryptedCredential); err != nil {
			return nil, translateTrustedPoolConflict(err)
		}
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_seats
			SET state='rotation_activated_pending_commit', assignment_epoch=$2, last_operation_id=$3, updated_at=NOW()
			WHERE id=$1 AND state='rotation_prepared' AND assignment_epoch=$4
		`, seat.ID, child.ExpectedAssignmentEpoch+1, child.ChildOperationID, child.ExpectedAssignmentEpoch); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_permanent_rotation_seats
			SET prepared_credential_envelope_version=NULL, prepared_credential_key_id=NULL,
			    prepared_credential_wrap_nonce=NULL, prepared_credential_wrapped_dek=NULL,
			    prepared_credential_nonce=NULL, prepared_credential_ciphertext=NULL,
			    prepared_credential_expires_at=NULL, activated_at=NOW()
			WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3
			  AND prepared_credential_envelope_version IS NOT NULL AND activated_at IS NULL
		`, input.ActorClientID, input.PrepareOperationID, child.ExternalSeatID); err != nil {
			return nil, err
		}
	}
	if err = execTrustedPoolOne(ctx, tx, `
		UPDATE trusted_pool_permanent_rotations
		SET status='activated_pending_commit', activation_operation_id=$3, activation_request_hash=$4, activated_at=NOW()
		WHERE client_id=$1 AND prepare_operation_id=$2 AND status='prepared'
	`, input.ActorClientID, input.PrepareOperationID, input.OperationID, input.RequestHash); err != nil {
		return nil, err
	}
	parent.Status = "activated_pending_commit"
	parent.ActivationOperationID = input.OperationID
	parent.ActivationRequestHash = input.RequestHash
	if err = tx.QueryRowContext(ctx, `SELECT activated_at FROM trusted_pool_permanent_rotations WHERE client_id=$1 AND prepare_operation_id=$2`, input.ActorClientID, input.PrepareOperationID).Scan(&parent.ActivatedAt); err != nil {
		return nil, err
	}
	result, err := loadPermanentActivationResult(ctx, tx, parent)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return result, nil
}

func (r *trustedPoolRepository) TryReplayPermanentRotationCommit(ctx context.Context, input service.CommitTrustedPoolPermanentRotationInput) (_ *service.TrustedPoolPermanentRotationCommitResult, found bool, err error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	if err = requireTrustedPoolClientBinding(ctx, tx, input.ActorClientID, input.ExternalPoolID); err != nil {
		return nil, false, err
	}
	parent, err := lockPermanentRotationParent(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if errors.Is(err, service.ErrTrustedPoolSeatNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !samePermanentCommitParent(parent, input) {
		return nil, false, service.ErrTrustedPoolSeatConflict
	}
	result, found, err := tryLoadPermanentCommitReceipt(ctx, tx, parent, input)
	if err != nil || !found {
		return result, found, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	tx = nil
	return result, true, nil
}

func (r *trustedPoolRepository) CommitPermanentRotation(ctx context.Context, input service.CommitTrustedPoolPermanentRotationInput) (_ *service.TrustedPoolPermanentRotationCommitResult, err error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	if err = requireTrustedPoolClientBinding(ctx, tx, input.ActorClientID, input.ExternalPoolID); err != nil {
		return nil, err
	}
	parent, err := lockPermanentRotationParent(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if err != nil {
		return nil, err
	}
	if !samePermanentCommitParent(parent, input) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	if result, found, replayErr := tryLoadPermanentCommitReceipt(ctx, tx, parent, input); replayErr != nil {
		return nil, replayErr
	} else if found {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return result, nil
	}
	if parent.Status != "activated_pending_commit" || !input.ConcurrencyVerified {
		return nil, service.ErrTrustedPoolNotDrained
	}
	children, err := lockPermanentRotationChildren(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if err != nil {
		return nil, err
	}
	if !samePermanentCommitChildren(children, input.Seats) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	seats, err := lockTrustedPoolSeats(ctx, tx, input.ExternalPoolID)
	if err != nil {
		return nil, err
	}
	if len(seats) != len(children) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	for index := range seats {
		if seats[index].ExternalSeatID != children[index].ExternalSeatID || seats[index].ID != children[index].SeatID ||
			seats[index].State != service.TrustedPoolSeatStateRotationPendingCommit ||
			seats[index].AssignmentEpoch != children[index].TargetAssignmentEpoch {
			return nil, service.ErrTrustedPoolSeatConflict
		}
	}
	if err = lockAndVerifyPermanentResources(ctx, tx, seats, false); err != nil {
		return nil, err
	}
	if err = requireNoPermanentPendingSettlements(ctx, tx, seats); err != nil {
		return nil, err
	}
	for index := range children {
		child, seat := children[index], seats[index]
		var currentFingerprint string
		if err = tx.QueryRowContext(ctx, `SELECT encode(sha256(convert_to(key, 'UTF8')), 'hex') FROM api_keys WHERE id=$1 AND deleted_at IS NULL`, child.APIKeyID).Scan(&currentFingerprint); err != nil {
			return nil, err
		}
		if currentFingerprint != child.CredentialFingerprint {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		if err = execTrustedPoolOne(ctx, tx, `UPDATE api_keys SET status='active', updated_at=NOW() WHERE id=$1 AND status='disabled' AND deleted_at IS NULL`, child.APIKeyID); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `UPDATE user_subscriptions SET status='active', updated_at=NOW() WHERE id=$1 AND status='suspended' AND deleted_at IS NULL`, child.SubscriptionID); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_seats SET state='active', last_operation_id=$2, updated_at=NOW()
			WHERE id=$1 AND state='rotation_activated_pending_commit' AND assignment_epoch=$3
		`, seat.ID, child.ChildOperationID, child.TargetAssignmentEpoch); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_permanent_rotation_seats SET committed_at=NOW()
			WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3
			  AND prepared_credential_envelope_version IS NULL AND prepared_credential_key_id IS NULL
			  AND prepared_credential_wrap_nonce IS NULL AND prepared_credential_wrapped_dek IS NULL
			  AND prepared_credential_nonce IS NULL AND prepared_credential_ciphertext IS NULL
			  AND prepared_credential_expires_at IS NULL AND activated_at IS NOT NULL AND committed_at IS NULL
		`, input.ActorClientID, input.PrepareOperationID, child.ExternalSeatID); err != nil {
			return nil, err
		}
	}
	if err = execTrustedPoolOne(ctx, tx, `
		UPDATE trusted_pool_permanent_rotations
		SET status='committed', commit_operation_id=$3, commit_request_hash=$4, committed_at=NOW()
		WHERE client_id=$1 AND prepare_operation_id=$2 AND status='activated_pending_commit'
	`, input.ActorClientID, input.PrepareOperationID, input.OperationID, input.RequestHash); err != nil {
		return nil, err
	}
	parent.Status = "committed"
	parent.CommitOperationID = input.OperationID
	parent.CommitRequestHash = input.RequestHash
	if err = tx.QueryRowContext(ctx, `SELECT committed_at FROM trusted_pool_permanent_rotations WHERE client_id=$1 AND prepare_operation_id=$2`, input.ActorClientID, input.PrepareOperationID).Scan(&parent.CommittedAt); err != nil {
		return nil, err
	}
	result, err := loadPermanentCommitResult(ctx, tx, parent)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return result, nil
}

type permanentRotationParent struct {
	ClientID              string
	PrepareOperationID    string
	ProtocolVersion       string
	ExternalPoolID        string
	PlanID                string
	CeremonyType          string
	FromEpoch             int64
	ToEpoch               int64
	RequestHash           string
	ChildSetHash          string
	PreparedSetHash       string
	SeatCount             int
	Status                string
	ActivationOperationID string
	ActivationRequestHash string
	CommitOperationID     string
	CommitRequestHash     string
	PreparedAt            sql.NullTime
	ActivatedAt           sql.NullTime
	CommittedAt           sql.NullTime
}

type permanentRotationChild struct {
	service.TrustedPoolPermanentRotationSeatBinding
	SeatID                int64
	FromEpoch             int64
	ToEpoch               int64
	TargetAssignmentEpoch int64
	CredentialFingerprint string
	PreparedRotationRef   string
	CredentialEnvelope    permanentCredentialEnvelope
	DecryptedCredential   string
	ActivatedAt           sql.NullTime
	CommittedAt           sql.NullTime
}

func samePermanentCommitParent(parent permanentRotationParent, input service.CommitTrustedPoolPermanentRotationInput) bool {
	return parent.ProtocolVersion == input.ProtocolVersion && parent.ExternalPoolID == input.ExternalPoolID && parent.PlanID == input.PlanID &&
		parent.CeremonyType == input.CeremonyType && parent.FromEpoch == input.FromEpoch && parent.ToEpoch == input.ToEpoch &&
		parent.PreparedSetHash == input.PreparedSetHash && parent.SeatCount == len(input.Seats) &&
		parent.ActivationOperationID == input.ActivationOperationID && parent.ActivationRequestHash == input.ActivationRequestHash
}

func samePermanentCommitChildren(children []permanentRotationChild, expected []service.ActivateTrustedPoolPermanentRotationSeat) bool {
	if len(children) != len(expected) {
		return false
	}
	for index := range children {
		actual, want := children[index], expected[index]
		if actual.ExternalSeatID != want.ExternalSeatID || actual.TargetMemberID != want.TargetMemberID ||
			actual.ExpectedAssignmentEpoch != want.ExpectedAssignmentEpoch || actual.PrincipalUserID != want.PrincipalUserID ||
			actual.SubscriptionID != want.SubscriptionID || actual.APIKeyID != want.APIKeyID ||
			actual.ToAPIKeyVersion != want.ActiveAPIKeyVersion || actual.ChildOperationID != want.ChildOperationID ||
			actual.ChildRequestHash != want.ChildRequestHash || actual.CredentialFingerprint != want.CredentialFingerprint ||
			actual.PreparedRotationRef != want.PreparedRotationRef || !permanentCredentialEnvelopeEmpty(actual.CredentialEnvelope) {
			return false
		}
	}
	return true
}

func tryLoadPermanentCommitReceipt(ctx context.Context, tx *sql.Tx, parent permanentRotationParent, input service.CommitTrustedPoolPermanentRotationInput) (*service.TrustedPoolPermanentRotationCommitResult, bool, error) {
	switch parent.Status {
	case "prepared", "activated_pending_commit":
		return nil, false, nil
	case "committed", "retiring", "superseded":
	default:
		return nil, true, service.ErrTrustedPoolInvalidState
	}
	if parent.CommitOperationID != input.OperationID || parent.CommitRequestHash != input.RequestHash {
		return nil, true, service.ErrTrustedPoolSeatConflict
	}
	if parent.Status == "superseded" {
		return nil, true, service.ErrTrustedPoolPermanentCommitReceiptUnavailable
	}
	if !parent.ActivatedAt.Valid || !parent.CommittedAt.Valid {
		return nil, true, service.ErrTrustedPoolPermanentCommitReceiptUnavailable
	}
	children, err := lockPermanentRotationChildren(ctx, tx, input.ActorClientID, input.PrepareOperationID)
	if err != nil {
		return nil, true, err
	}
	if !samePermanentCommitChildren(children, input.Seats) {
		return nil, true, service.ErrTrustedPoolPermanentCommitReceiptUnavailable
	}
	for index := range children {
		if !children[index].ActivatedAt.Valid || !children[index].CommittedAt.Valid {
			return nil, true, service.ErrTrustedPoolPermanentCommitReceiptUnavailable
		}
	}
	fingerprintsMatch, err := permanentCommitCredentialFingerprintsMatch(ctx, tx, children)
	if err != nil {
		return nil, true, err
	}
	if !fingerprintsMatch {
		return nil, true, service.ErrTrustedPoolPermanentCommitReceiptUnavailable
	}
	result, err := loadPermanentCommitResult(ctx, tx, parent)
	return result, true, err
}

func permanentCommitCredentialFingerprintsMatch(ctx context.Context, tx *sql.Tx, children []permanentRotationChild) (bool, error) {
	for index := range children {
		var currentFingerprint string
		err := tx.QueryRowContext(ctx, `
			SELECT encode(sha256(convert_to(key, 'UTF8')), 'hex')
			FROM api_keys
			WHERE id=$1 AND deleted_at IS NULL
		`, children[index].APIKeyID).Scan(&currentFingerprint)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if currentFingerprint != children[index].CredentialFingerprint {
			return false, nil
		}
	}
	return true, nil
}

func lockPermanentRotationParent(ctx context.Context, tx *sql.Tx, clientID, operationID string) (permanentRotationParent, error) {
	parent := permanentRotationParent{ClientID: clientID, PrepareOperationID: operationID}
	var activationOperationID, activationRequestHash, commitOperationID, commitRequestHash sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT protocol_version, external_pool_id, plan_id, ceremony_type, from_epoch, to_epoch,
		       request_hash, child_set_hash, prepared_set_hash, seat_count, status,
		       activation_operation_id, activation_request_hash, commit_operation_id, commit_request_hash,
		       prepared_at, activated_at, committed_at
		FROM trusted_pool_permanent_rotations
		WHERE client_id=$1 AND prepare_operation_id=$2
		FOR UPDATE
	`, clientID, operationID).Scan(&parent.ProtocolVersion, &parent.ExternalPoolID, &parent.PlanID, &parent.CeremonyType,
		&parent.FromEpoch, &parent.ToEpoch, &parent.RequestHash, &parent.ChildSetHash, &parent.PreparedSetHash,
		&parent.SeatCount, &parent.Status, &activationOperationID, &activationRequestHash, &commitOperationID, &commitRequestHash,
		&parent.PreparedAt, &parent.ActivatedAt, &parent.CommittedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return parent, service.ErrTrustedPoolSeatNotFound
	}
	if activationOperationID.Valid {
		parent.ActivationOperationID = activationOperationID.String
	}
	if activationRequestHash.Valid {
		parent.ActivationRequestHash = activationRequestHash.String
	}
	if commitOperationID.Valid {
		parent.CommitOperationID = commitOperationID.String
	}
	if commitRequestHash.Valid {
		parent.CommitRequestHash = commitRequestHash.String
	}
	return parent, err
}

func lockPermanentRotationChildren(ctx context.Context, tx *sql.Tx, clientID, operationID string) ([]permanentRotationChild, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT external_seat_id, target_member_id, seat_id, principal_user_id, group_id, subscription_id, api_key_id,
		       from_epoch, to_epoch, expected_assignment_epoch, target_assignment_epoch,
		       from_api_key_version, to_api_key_version, child_operation_id,
		       child_request_hash, credential_fingerprint, prepared_rotation_ref,
		       prepared_credential_envelope_version, prepared_credential_key_id,
		       prepared_credential_wrap_nonce, prepared_credential_wrapped_dek,
		       prepared_credential_nonce, prepared_credential_ciphertext, prepared_credential_expires_at,
		       activated_at, committed_at
		FROM trusted_pool_permanent_rotation_seats
		WHERE client_id=$1 AND prepare_operation_id=$2
		ORDER BY external_seat_id
		FOR UPDATE
	`, clientID, operationID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	children := make([]permanentRotationChild, 0)
	for rows.Next() {
		var child permanentRotationChild
		var version sql.NullInt16
		var keyID sql.NullString
		var expiresAt sql.NullTime
		if err := rows.Scan(&child.ExternalSeatID, &child.TargetMemberID, &child.SeatID, &child.PrincipalUserID, &child.GroupID,
			&child.SubscriptionID, &child.APIKeyID, &child.FromEpoch, &child.ToEpoch, &child.ExpectedAssignmentEpoch,
			&child.TargetAssignmentEpoch, &child.FromAPIKeyVersion,
			&child.ToAPIKeyVersion, &child.ChildOperationID, &child.ChildRequestHash, &child.CredentialFingerprint,
			&child.PreparedRotationRef, &version, &keyID, &child.CredentialEnvelope.WrapNonce,
			&child.CredentialEnvelope.WrappedDEK, &child.CredentialEnvelope.DataNonce,
			&child.CredentialEnvelope.Ciphertext, &expiresAt, &child.ActivatedAt, &child.CommittedAt); err != nil {
			return nil, err
		}
		if version.Valid {
			child.CredentialEnvelope.Version = version.Int16
		}
		if keyID.Valid {
			child.CredentialEnvelope.KeyID = keyID.String
		}
		if expiresAt.Valid {
			child.CredentialEnvelope.ExpiresAt = expiresAt.Time
		}
		children = append(children, child)
	}
	return children, rows.Err()
}

func lockTrustedPoolSeats(ctx context.Context, tx *sql.Tx, externalPoolID string) ([]*service.TrustedPoolSeat, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+trustedPoolSeatColumns+`
		FROM trusted_pool_seats WHERE external_pool_id=$1 ORDER BY external_seat_id FOR UPDATE`, externalPoolID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	seats := make([]*service.TrustedPoolSeat, 0)
	for rows.Next() {
		seat, scanErr := scanTrustedPoolSeat(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		seats = append(seats, seat)
	}
	return seats, rows.Err()
}

func lockAndVerifyPermanentResources(ctx context.Context, tx *sql.Tx, seats []*service.TrustedPoolSeat, active bool) error {
	apiKeyIDs := make([]int64, len(seats))
	subscriptionIDs := make([]int64, len(seats))
	for index := range seats {
		apiKeyIDs[index] = seats[index].APIKeyID
		subscriptionIDs[index] = seats[index].SubscriptionID
	}
	sort.Slice(apiKeyIDs, func(i, j int) bool { return apiKeyIDs[i] < apiKeyIDs[j] })
	sort.Slice(subscriptionIDs, func(i, j int) bool { return subscriptionIDs[i] < subscriptionIDs[j] })
	keyStatus, subscriptionStatus := "disabled", "suspended"
	if active {
		keyStatus, subscriptionStatus = "active", "active"
	}
	for _, id := range apiKeyIDs {
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM api_keys WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status != keyStatus {
			return service.ErrTrustedPoolInvalidState
		}
	}
	for _, id := range subscriptionIDs {
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM user_subscriptions WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status != subscriptionStatus {
			return service.ErrTrustedPoolInvalidState
		}
	}
	return nil
}

func requireNoPermanentPendingSettlements(ctx context.Context, tx *sql.Tx, seats []*service.TrustedPoolSeat) error {
	for _, seat := range seats {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_pool_pending_settlements WHERE seat_id=$1`, seat.ID).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return service.ErrTrustedPoolNotDrained
		}
	}
	return nil
}

func (r *trustedPoolRepository) loadPermanentPrepareResult(ctx context.Context, tx *sql.Tx, clientID, operationID string, lock bool) (*service.TrustedPoolPermanentRotationPrepareResult, bool, error) {
	query := `SELECT protocol_version, external_pool_id, plan_id, ceremony_type, from_epoch, to_epoch,
		request_hash, child_set_hash, prepared_set_hash, status, prepared_at
		FROM trusted_pool_permanent_rotations WHERE client_id=$1 AND prepare_operation_id=$2`
	if lock {
		query += " FOR UPDATE"
	}
	result := &service.TrustedPoolPermanentRotationPrepareResult{OperationID: operationID}
	err := tx.QueryRowContext(ctx, query, clientID, operationID).Scan(&result.ProtocolVersion, &result.ExternalPoolID, &result.PlanID,
		&result.CeremonyType, &result.FromEpoch, &result.ToEpoch, &result.RequestHash, &result.ChildSetHash,
		&result.PreparedSetHash, &result.Status, &result.PreparedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	children, err := lockPermanentRotationChildren(ctx, tx, clientID, operationID)
	if err != nil {
		return nil, false, err
	}
	result.CredentialsDisclosed = result.Status == "prepared"
	seatState := "ROTATION_PREPARED"
	credentialEnabled, subscriptionEnabled := false, false
	if result.Status == "activated_pending_commit" {
		seatState = "ROTATION_ACTIVATED_PENDING_COMMIT"
	} else if result.Status == "committed" {
		seatState, credentialEnabled, subscriptionEnabled = "COMMITTED", true, true
	} else if result.Status == "retiring" {
		seatState = "RETIRING"
	} else if result.Status == "superseded" {
		seatState = "SUPERSEDED"
	}
	result.Seats = make([]service.TrustedPoolPermanentRotationPreparedSeat, len(children))
	for index := range children {
		child := children[index]
		result.Seats[index] = service.TrustedPoolPermanentRotationPreparedSeat{
			TrustedPoolPermanentRotationSeatBinding: child.TrustedPoolPermanentRotationSeatBinding,
			CredentialFingerprint:                   child.CredentialFingerprint,
			ActiveAPIKeyVersion:                     child.ToAPIKeyVersion, PreparedRotationRef: child.PreparedRotationRef,
			State: seatState, CredentialEnabled: credentialEnabled, SubscriptionEnabled: subscriptionEnabled,
			CredentialRotationComplete: true, CompletedAt: result.PreparedAt,
		}
		if result.CredentialsDisclosed {
			parent := permanentRotationParent{
				ClientID: clientID, PrepareOperationID: operationID, ProtocolVersion: result.ProtocolVersion,
				ExternalPoolID: result.ExternalPoolID, PlanID: result.PlanID, CeremonyType: result.CeremonyType,
				FromEpoch: result.FromEpoch, ToEpoch: result.ToEpoch, RequestHash: result.RequestHash,
				ChildSetHash: result.ChildSetHash, PreparedSetHash: result.PreparedSetHash,
			}
			credential, openErr := r.openPermanentCredentialForReplay(ctx, parent, &children[index])
			if openErr != nil {
				return nil, false, openErr
			}
			result.Seats[index].Credential = credential
		}
	}
	return result, true, nil
}

func (r *trustedPoolRepository) currentTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func permanentCredentialEnvelopeEmpty(envelope permanentCredentialEnvelope) bool {
	return envelope.Version == 0 && envelope.KeyID == "" && len(envelope.WrapNonce) == 0 &&
		len(envelope.WrappedDEK) == 0 && len(envelope.DataNonce) == 0 && len(envelope.Ciphertext) == 0 &&
		envelope.ExpiresAt.IsZero()
}

func (r *trustedPoolRepository) openPermanentCredentialForReplay(ctx context.Context, parent permanentRotationParent, child *permanentRotationChild) (string, error) {
	if !child.CredentialEnvelope.ExpiresAt.After(permanentCredentialExpiry(r.currentTime())) {
		return "", service.ErrTrustedPoolPermanentCredentialExpired
	}
	return r.openPermanentCredentialForActivation(ctx, parent, child)
}

func (r *trustedPoolRepository) openPermanentCredentialForActivation(ctx context.Context, parent permanentRotationParent, child *permanentRotationChild) (string, error) {
	if r.permanentCredentialSealer == nil {
		return "", service.ErrTrustedPoolPermanentCredentialEnvelopeUnavailable
	}
	credential, err := r.permanentCredentialSealer.Open(ctx, child.CredentialEnvelope, permanentCredentialScopeFromStored(parent, *child))
	if err != nil || strings.TrimSpace(credential) == "" || trustedPoolCredentialFingerprint(credential) != child.CredentialFingerprint {
		return "", service.ErrTrustedPoolPermanentCredentialEnvelopeUnavailable
	}
	return credential, nil
}

func permanentCredentialScopeFromPrepare(
	input service.PrepareTrustedPoolPermanentRotationInput,
	binding service.TrustedPoolPermanentRotationSeatBinding,
	seat *service.TrustedPoolSeat,
	fingerprint string,
	preparedRotationRef string,
) permanentCredentialScope {
	return permanentCredentialScope{
		ClientID: input.ActorClientID, PrepareOperationID: input.OperationID, ProtocolVersion: input.ProtocolVersion,
		ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID, CeremonyType: input.CeremonyType,
		FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch, RequestHash: input.RequestHash,
		ChildSetHash: input.ChildSetHash, PreparedSetHash: input.PreparedSetHash,
		ExternalSeatID: binding.ExternalSeatID, TargetMemberID: binding.TargetMemberID, SeatID: seat.ID,
		PrincipalUserID: binding.PrincipalUserID, GroupID: seat.GroupID, SubscriptionID: binding.SubscriptionID,
		APIKeyID: binding.APIKeyID, ExpectedAssignmentEpoch: binding.ExpectedAssignmentEpoch,
		TargetAssignmentEpoch: binding.ExpectedAssignmentEpoch + 1, FromAPIKeyVersion: binding.FromAPIKeyVersion,
		ToAPIKeyVersion: binding.ToAPIKeyVersion, ChildOperationID: binding.ChildOperationID,
		ChildRequestHash: binding.ChildRequestHash, CredentialFingerprint: fingerprint,
		PreparedRotationRef: preparedRotationRef,
	}
}

func permanentCredentialScopeFromStored(parent permanentRotationParent, child permanentRotationChild) permanentCredentialScope {
	return permanentCredentialScope{
		ClientID: parent.ClientID, PrepareOperationID: parent.PrepareOperationID, ProtocolVersion: parent.ProtocolVersion,
		ExternalPoolID: parent.ExternalPoolID, PlanID: parent.PlanID, CeremonyType: parent.CeremonyType,
		FromEpoch: parent.FromEpoch, ToEpoch: parent.ToEpoch, RequestHash: parent.RequestHash,
		ChildSetHash: parent.ChildSetHash, PreparedSetHash: parent.PreparedSetHash,
		ExternalSeatID: child.ExternalSeatID, TargetMemberID: child.TargetMemberID, SeatID: child.SeatID,
		PrincipalUserID: child.PrincipalUserID, GroupID: child.GroupID, SubscriptionID: child.SubscriptionID,
		APIKeyID: child.APIKeyID, ExpectedAssignmentEpoch: child.ExpectedAssignmentEpoch,
		TargetAssignmentEpoch: child.TargetAssignmentEpoch, FromAPIKeyVersion: child.FromAPIKeyVersion,
		ToAPIKeyVersion: child.ToAPIKeyVersion, ChildOperationID: child.ChildOperationID,
		ChildRequestHash: child.ChildRequestHash, CredentialFingerprint: child.CredentialFingerprint,
		PreparedRotationRef: child.PreparedRotationRef,
	}
}

func samePermanentPrepareRequest(result *service.TrustedPoolPermanentRotationPrepareResult, input service.PrepareTrustedPoolPermanentRotationInput) bool {
	return result != nil && result.ExternalPoolID == input.ExternalPoolID && result.PlanID == input.PlanID &&
		result.ProtocolVersion == input.ProtocolVersion && result.CeremonyType == input.CeremonyType &&
		result.FromEpoch == input.FromEpoch && result.ToEpoch == input.ToEpoch && result.RequestHash == input.RequestHash &&
		result.ChildSetHash == input.ChildSetHash
}

func loadPermanentActivationResult(ctx context.Context, tx *sql.Tx, parent permanentRotationParent) (*service.TrustedPoolPermanentRotationActivationResult, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.external_seat_id, r.target_member_id, r.expected_assignment_epoch, r.target_assignment_epoch,
		       r.principal_user_id, r.group_id, r.subscription_id, r.api_key_id, r.to_api_key_version,
		       r.credential_fingerprint, r.prepared_rotation_ref, r.child_operation_id, r.child_request_hash
		FROM trusted_pool_permanent_rotation_seats AS r
		JOIN trusted_pool_seats AS s ON s.id=r.seat_id
		WHERE r.client_id=$1 AND r.prepare_operation_id=$2
		ORDER BY s.external_seat_id
	`, parent.ClientID, parent.PrepareOperationID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := &service.TrustedPoolPermanentRotationActivationResult{
		ProtocolVersion: parent.ProtocolVersion, OperationID: parent.ActivationOperationID,
		RequestHash: parent.ActivationRequestHash, PrepareOperationID: parent.PrepareOperationID,
		ExternalPoolID: parent.ExternalPoolID, PlanID: parent.PlanID, CeremonyType: parent.CeremonyType,
		FromEpoch: parent.FromEpoch, ToEpoch: parent.ToEpoch,
		PreparedSetHash: parent.PreparedSetHash, Status: "activated_pending_commit",
		AllCredentialsEnabled: false, AllSubscriptionsEnabled: false,
		OldCredentialSetInvalidated: true, AuthorizationCacheInvalidated: false,
		CredentialFingerprintGateEnforced: true,
		Seats:                             make([]service.TrustedPoolPermanentRotationActivatedSeat, 0, parent.SeatCount),
	}
	for rows.Next() {
		var seat service.TrustedPoolPermanentRotationActivatedSeat
		if err := rows.Scan(&seat.ExternalSeatID, &seat.TargetMemberID, &seat.ExpectedAssignmentEpoch,
			&seat.AssignmentEpoch, &seat.PrincipalUserID,
			&seat.GroupID, &seat.SubscriptionID, &seat.APIKeyID, &seat.ActiveAPIKeyVersion,
			&seat.CredentialFingerprint, &seat.PreparedRotationRef, &seat.ChildOperationID, &seat.ChildRequestHash); err != nil {
			return nil, err
		}
		result.Seats = append(result.Seats, seat)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result.Seats) != parent.SeatCount {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	// api_keys 触发器在同一事务内为每个旧/新 key 写 durable outbox；安全放行另有 DB 指纹 gate。
	result.AuthCacheBarrier.DurableOutbox = true
	result.AuthCacheBarrier.MinimumEvents = 2 * parent.SeatCount
	result.ObservedAt = parent.ActivatedAt.Time
	return result, nil
}

func loadPermanentCommitResult(ctx context.Context, tx *sql.Tx, parent permanentRotationParent) (*service.TrustedPoolPermanentRotationCommitResult, error) {
	activation, err := loadPermanentActivationResult(ctx, tx, parent)
	if err != nil {
		return nil, err
	}
	result := &service.TrustedPoolPermanentRotationCommitResult{
		ProtocolVersion: parent.ProtocolVersion, OperationID: parent.CommitOperationID, RequestHash: parent.CommitRequestHash,
		PrepareOperationID: parent.PrepareOperationID, ActivationOperationID: parent.ActivationOperationID,
		ActivationRequestHash: parent.ActivationRequestHash, ExternalPoolID: parent.ExternalPoolID,
		PlanID: parent.PlanID, CeremonyType: parent.CeremonyType, FromEpoch: parent.FromEpoch, ToEpoch: parent.ToEpoch,
		PreparedSetHash: parent.PreparedSetHash, Status: "committed", AllCredentialsEnabled: true,
		AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true, AuthorizationCacheInvalidated: false,
		CredentialFingerprintGateEnforced: true, ObservedAt: parent.CommittedAt.Time, Seats: activation.Seats,
	}
	result.AuthCacheBarrier.DurableOutbox = true
	result.AuthCacheBarrier.MinimumEvents = parent.SeatCount
	return result, nil
}
