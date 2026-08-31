package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type trustedPoolRepository struct {
	db                        *sql.DB
	permanentCredentialSealer *permanentCredentialEnvelopeSealer
	permanentCredentialTTL    time.Duration
	now                       func() time.Time
}

func NewTrustedPoolRepository(db *sql.DB) service.TrustedPoolRepository {
	return &trustedPoolRepository{db: db, now: time.Now}
}

func ProvideTrustedPoolRepository(db *sql.DB, cfg *config.Config) (service.TrustedPoolRepository, error) {
	repo := &trustedPoolRepository{db: db, now: time.Now}
	if cfg == nil || !cfg.TrustedPool.PermanentRotation.StagingEncryption.Enabled {
		return repo, nil
	}
	staging := cfg.TrustedPool.PermanentRotation.StagingEncryption
	key, err := staging.StagingEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("configure trusted-pool permanent rotation credential envelope: %w", err)
	}
	defer clear(key)
	provider, err := newLocalPermanentRotationKEKProvider(strings.TrimSpace(staging.KeyID), key)
	if err != nil {
		return nil, fmt.Errorf("configure trusted-pool permanent rotation credential envelope: %w", err)
	}
	repo.permanentCredentialSealer, err = newPermanentCredentialEnvelopeSealer(provider)
	if err != nil {
		return nil, fmt.Errorf("configure trusted-pool permanent rotation credential envelope: %w", err)
	}
	repo.permanentCredentialTTL = staging.PreparedCredentialTTL
	if repo.permanentCredentialTTL == 0 {
		repo.permanentCredentialTTL = config.TrustedPoolPermanentRotationDefaultPreparedCredentialTTL
	}
	if repo.permanentCredentialTTL < config.TrustedPoolPermanentRotationMinPreparedCredentialTTL ||
		repo.permanentCredentialTTL > config.TrustedPoolPermanentRotationMaxPreparedCredentialTTL {
		return nil, fmt.Errorf("configure trusted-pool permanent rotation credential envelope: prepared credential TTL is out of range")
	}
	return repo, nil
}

func NewTrustedPoolAuthRepository(db *sql.DB) service.TrustedPoolAuthRepository {
	return &trustedPoolRepository{db: db}
}

func (r *trustedPoolRepository) GetIntegrationClient(ctx context.Context, clientID string) (*service.TrustedPoolIntegrationClient, error) {
	client := new(service.TrustedPoolIntegrationClient)
	var scopes string
	err := r.db.QueryRowContext(ctx, `
		SELECT client_id, external_pool_id, secret_hash,
		       COALESCE(hmac_secret_encrypted, ''), array_to_string(scopes, ','), expires_at
		FROM trusted_pool_integration_clients
		WHERE client_id=$1 AND status='active' AND external_pool_id IS NOT NULL
	`, clientID).Scan(&client.ClientID, &client.ExternalPoolID, &client.SecretHash,
		&client.HMACSecretEncrypted, &scopes, &client.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if scopes != "" {
		client.Scopes = strings.Split(scopes, ",")
	}
	return client, nil
}

func (r *trustedPoolRepository) ClaimIntegrationNonce(ctx context.Context, clientID, nonce string, expiresAt time.Time) (bool, error) {
	// 顺手清理过期 nonce，避免长期运行后表无限增长；删除失败不影响本次防重放判断。
	_, _ = r.db.ExecContext(ctx, `DELETE FROM trusted_pool_integration_nonces WHERE expires_at < NOW()`)
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO trusted_pool_integration_nonces(client_id, nonce, expires_at)
		VALUES ($1,$2,$3) ON CONFLICT DO NOTHING
	`, clientID, nonce, expiresAt)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

const trustedPoolSeatColumns = `
	id, external_pool_id, external_seat_id, principal_user_id, group_id,
	subscription_id, api_key_id, state, assignment_epoch, last_operation_id,
	suspended_at, created_at, updated_at`

func scanTrustedPoolSeat(scanner interface{ Scan(...any) error }) (*service.TrustedPoolSeat, error) {
	seat := new(service.TrustedPoolSeat)
	err := scanner.Scan(
		&seat.ID, &seat.ExternalPoolID, &seat.ExternalSeatID, &seat.PrincipalUserID, &seat.GroupID,
		&seat.SubscriptionID, &seat.APIKeyID, &seat.State, &seat.AssignmentEpoch, &seat.LastOperationID,
		&seat.SuspendedAt, &seat.CreatedAt, &seat.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrTrustedPoolSeatNotFound
	}
	return seat, err
}

func scanTrustedPoolProvisionResult(scanner interface{ Scan(...any) error }) (*service.TrustedPoolProvisionResult, error) {
	seat := new(service.TrustedPoolSeat)
	var credential string
	err := scanner.Scan(
		&seat.ID, &seat.ExternalPoolID, &seat.ExternalSeatID, &seat.PrincipalUserID, &seat.GroupID,
		&seat.SubscriptionID, &seat.APIKeyID, &seat.State, &seat.AssignmentEpoch, &seat.LastOperationID,
		&seat.SuspendedAt, &seat.CreatedAt, &seat.UpdatedAt, &credential,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrTrustedPoolSeatNotFound
	}
	if err != nil {
		return nil, err
	}
	return &service.TrustedPoolProvisionResult{Seat: seat, Credential: credential}, nil
}

func trustedPoolCredentialFingerprint(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(digest[:])
}

func (r *trustedPoolRepository) ProvisionSeat(ctx context.Context, input service.ProvisionTrustedPoolSeatInput) (_ *service.TrustedPoolProvisionResult, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
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

	// 幂等记录先占位。相同 client/operation 的并发事务会在唯一约束处等待，
	// 首事务提交后重读原结果，避免生成第二套 Principal 或 Key。
	inserted, err := tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_provision_operations(
			client_id, operation_id, external_pool_id, external_seat_id, request_hash, credential_fingerprint
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (client_id, operation_id) DO NOTHING
	`, input.ActorClientID, input.OperationID, input.ExternalPoolID, input.ExternalSeatID, input.RequestHash, input.CredentialFingerprint)
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	insertedCount, err := inserted.RowsAffected()
	if err != nil {
		return nil, err
	}
	if insertedCount == 0 {
		var existingHash string
		var seatID sql.NullInt64
		var credentialFingerprint string
		if err = tx.QueryRowContext(ctx, `
			SELECT operation.request_hash, operation.seat_id, operation.credential_fingerprint
			FROM trusted_pool_provision_operations operation
			WHERE operation.client_id=$1 AND operation.operation_id=$2
			FOR UPDATE
		`, input.ActorClientID, input.OperationID).Scan(&existingHash, &seatID, &credentialFingerprint); err != nil {
			return nil, err
		}
		if existingHash != input.RequestHash || !seatID.Valid {
			return nil, service.ErrTrustedPoolSeatConflict
		}

		// PostgreSQL READ COMMITTED 在每条 statement 开始时取快照。claim 必须在 operation 行锁
		// 获取完成后用新 statement 重读，否则等待并发 Ack 时可能沿用旧快照并再次返回明文 Key。
		var credentialClaimed bool
		if err = tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM trusted_pool_provision_credential_claims
				WHERE client_id=$1 AND provision_operation_id=$2
			)
		`, input.ActorClientID, input.OperationID).Scan(&credentialClaimed); err != nil {
			return nil, err
		}
		if credentialClaimed {
			return nil, service.ErrTrustedPoolCredentialClaimed
		}
		result, readErr := scanTrustedPoolProvisionResult(tx.QueryRowContext(ctx, `
			SELECT s.id, s.external_pool_id, s.external_seat_id, s.principal_user_id, s.group_id,
			       s.subscription_id, s.api_key_id, s.state, s.assignment_epoch, s.last_operation_id,
			       s.suspended_at, s.created_at, s.updated_at, k.key
			FROM trusted_pool_seats s
			JOIN api_keys k ON k.id=s.api_key_id AND k.deleted_at IS NULL
			WHERE s.id=$1 AND s.last_operation_id=$2
			  AND NOT EXISTS (
				SELECT 1 FROM trusted_pool_operations lifecycle
				JOIN trusted_pool_provision_operations provision
				  ON provision.seat_id=s.id AND provision.client_id=$3 AND provision.operation_id=$2
				WHERE lifecycle.seat_id=s.id AND lifecycle.created_at >= provision.completed_at
			  )
		`, seatID.Int64, input.OperationID, input.ActorClientID))
		if readErr != nil {
			if errors.Is(readErr, service.ErrTrustedPoolSeatNotFound) {
				return nil, service.ErrTrustedPoolSeatConflict
			}
			return nil, readErr
		}
		result.CredentialFingerprint = credentialFingerprint
		if subtle.ConstantTimeCompare([]byte(credentialFingerprint), []byte(trustedPoolCredentialFingerprint(result.Credential))) != 1 {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return result, nil
	}

	var lockedGroupID int64
	if err = tx.QueryRowContext(ctx, `
		SELECT id FROM groups
		WHERE id=$1 AND deleted_at IS NULL AND status='active'
		  AND subscription_type='subscription' AND is_exclusive=TRUE
		FOR UPDATE
	`, input.ExistingGroupID).Scan(&lockedGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		return nil, err
	}

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_groups(external_pool_id, group_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING
	`, input.ExternalPoolID, input.ExistingGroupID); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	var groupBindingValid bool
	if err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM trusted_pool_groups
			WHERE external_pool_id=$1 AND group_id=$2
		)
	`, input.ExternalPoolID, input.ExistingGroupID).Scan(&groupBindingValid); err != nil {
		return nil, err
	}
	if !groupBindingValid {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	var groupIsolated bool
	if err = tx.QueryRowContext(ctx, `
		SELECT
			NOT EXISTS (
				SELECT 1 FROM user_subscriptions us
				WHERE us.group_id=$1 AND us.deleted_at IS NULL
				  AND NOT EXISTS (
					SELECT 1 FROM trusted_pool_seats ts
					JOIN users u ON u.id=us.user_id AND u.principal_type='trusted_pool_seat'
					WHERE ts.subscription_id=us.id AND ts.principal_user_id=u.id
					  AND ts.external_pool_id=$2 AND ts.group_id=$1
				  )
			)
			AND NOT EXISTS (
				SELECT 1 FROM api_keys k
				WHERE k.group_id=$1 AND k.deleted_at IS NULL
				  AND NOT EXISTS (
					SELECT 1 FROM trusted_pool_seats ts
					JOIN users u ON u.id=k.user_id AND u.principal_type='trusted_pool_seat'
					WHERE ts.api_key_id=k.id AND ts.principal_user_id=u.id
					  AND ts.external_pool_id=$2 AND ts.group_id=$1
				  )
			)
	`, input.ExistingGroupID, input.ExternalPoolID).Scan(&groupIsolated); err != nil {
		return nil, err
	}
	if !groupIsolated {
		return nil, service.ErrTrustedPoolSeatConflict
	}

	var seatExists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM trusted_pool_seats WHERE external_seat_id=$1
	)`, input.ExternalSeatID).Scan(&seatExists); err != nil {
		return nil, err
	}
	if seatExists {
		return nil, service.ErrTrustedPoolSeatConflict
	}

	var principalID int64
	if err = tx.QueryRowContext(ctx, `
		INSERT INTO users(
			email, password_hash, role, balance, concurrency, rpm_limit,
			status, signup_source, principal_type, username, notes
		) VALUES ($1,'!trusted-pool-no-login!','user',0,$2,$3,'active','email','trusted_pool_seat','','trusted pool seat principal')
		RETURNING id
	`, input.PrincipalEmail, input.PrincipalConcurrency, input.PrincipalRPMLimit).Scan(&principalID); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}

	now := time.Now()
	var subscriptionID int64
	if err = tx.QueryRowContext(ctx, `
		INSERT INTO user_subscriptions(
			user_id, group_id, starts_at, expires_at, status, assigned_at, notes
		) VALUES ($1,$2,$3,$4,'active',$3,'trusted pool seat provision')
		RETURNING id
	`, principalID, input.ExistingGroupID, now, input.SubscriptionExpiresAt).Scan(&subscriptionID); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}

	var apiKeyID int64
	if err = tx.QueryRowContext(ctx, `
		INSERT INTO api_keys(
			user_id, key, name, group_id, status, quota, quota_used,
			expires_at, rate_limit_5h, rate_limit_1d, rate_limit_7d
		) VALUES ($1,$2,'trusted-pool-seat',$3,'active',$4,0,$5,$6,$7,$8)
		RETURNING id
	`, principalID, input.Credential, input.ExistingGroupID, input.APIKeyQuota, input.SubscriptionExpiresAt,
		input.APIKeyRateLimit5h, input.APIKeyRateLimit1d, input.APIKeyRateLimit7d).Scan(&apiKeyID); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}

	seat, err := scanTrustedPoolSeat(tx.QueryRowContext(ctx, `
		INSERT INTO trusted_pool_seats(
			external_pool_id, external_seat_id, principal_user_id, group_id,
			subscription_id, api_key_id, state, assignment_epoch, last_operation_id
		) VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8)
		RETURNING `+trustedPoolSeatColumns,
		input.ExternalPoolID, input.ExternalSeatID, principalID, input.ExistingGroupID,
		subscriptionID, apiKeyID, input.AssignmentEpoch, input.OperationID))
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	if result, updateErr := tx.ExecContext(ctx, `
		UPDATE trusted_pool_provision_operations
		SET seat_id=$3, completed_at=NOW()
		WHERE client_id=$1 AND operation_id=$2 AND seat_id IS NULL
	`, input.ActorClientID, input.OperationID, seat.ID); updateErr != nil {
		return nil, updateErr
	} else if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		if rowsErr != nil {
			return nil, rowsErr
		}
		return nil, service.ErrTrustedPoolSeatConflict
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return &service.TrustedPoolProvisionResult{
		Seat: seat, Credential: input.Credential, CredentialFingerprint: input.CredentialFingerprint,
	}, nil
}

func scanTrustedPoolProvisionCredentialClaim(scanner interface{ Scan(...any) error }) (*service.TrustedPoolProvisionCredentialClaim, error) {
	claim := new(service.TrustedPoolProvisionCredentialClaim)
	err := scanner.Scan(
		&claim.ExternalSeatID, &claim.ProvisionOperationID, &claim.ClaimOperationID,
		&claim.ClaimedBy, &claim.CredentialFingerprint, &claim.ClaimedAt,
	)
	if err != nil {
		return nil, err
	}
	claim.CredentialClaimed = true
	return claim, nil
}

func (r *trustedPoolRepository) AckProvisionCredential(ctx context.Context, externalSeatID string, input service.AckTrustedPoolProvisionCredentialInput) (_ *service.TrustedPoolProvisionCredentialClaim, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	var seatID int64
	var completedAt time.Time
	var provisionedFingerprint string
	var currentCredential string
	if err = tx.QueryRowContext(ctx, `
		SELECT operation.seat_id, operation.completed_at, operation.credential_fingerprint, api_key.key
		FROM trusted_pool_provision_operations operation
		JOIN trusted_pool_seats seat ON seat.id=operation.seat_id
		JOIN api_keys api_key ON api_key.id=seat.api_key_id AND api_key.deleted_at IS NULL
		WHERE operation.client_id=$1 AND operation.operation_id=$2
		  AND seat.external_seat_id=$3 AND seat.external_pool_id=$4
		FOR UPDATE OF operation, seat, api_key
	`, input.ActorClientID, input.ProvisionOperationID, externalSeatID, input.ExternalPoolID).Scan(&seatID, &completedAt, &provisionedFingerprint, &currentCredential); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, service.ErrTrustedPoolSeatNotFound
		}
		return nil, err
	}
	currentFingerprint := trustedPoolCredentialFingerprint(currentCredential)
	if subtle.ConstantTimeCompare([]byte(provisionedFingerprint), []byte(input.CredentialFingerprint)) != 1 ||
		subtle.ConstantTimeCompare([]byte(provisionedFingerprint), []byte(currentFingerprint)) != 1 {
		return nil, service.ErrTrustedPoolSeatConflict
	}

	// Ack 只确认刚完成的 provision 交付；Seat 一旦暂停、冻结或轮换，旧 Key 的领取状态不可再推进。
	var lifecycleAdvanced bool
	if err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM trusted_pool_operations
			WHERE seat_id=$1 AND created_at >= $2
		)
	`, seatID, completedAt).Scan(&lifecycleAdvanced); err != nil {
		return nil, err
	}
	if lifecycleAdvanced {
		return nil, service.ErrTrustedPoolSeatConflict
	}

	claim, claimErr := scanTrustedPoolProvisionCredentialClaim(tx.QueryRowContext(ctx, `
		SELECT seat.external_seat_id, claim.provision_operation_id, claim.claim_operation_id,
		       claim.claimed_by, claim.credential_fingerprint, claim.claimed_at
		FROM trusted_pool_provision_credential_claims claim
		JOIN trusted_pool_seats seat ON seat.id=claim.seat_id
		WHERE claim.client_id=$1 AND claim.provision_operation_id=$2
		  AND seat.external_pool_id=$3
	`, input.ActorClientID, input.ProvisionOperationID, input.ExternalPoolID))
	if claimErr == nil {
		if claim.ExternalSeatID != externalSeatID || claim.ClaimOperationID != input.ClaimOperationID ||
			claim.ClaimedBy != input.ClaimedBy || claim.CredentialFingerprint != input.CredentialFingerprint {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return claim, nil
	}
	if !errors.Is(claimErr, sql.ErrNoRows) {
		return nil, claimErr
	}

	claim, err = scanTrustedPoolProvisionCredentialClaim(tx.QueryRowContext(ctx, `
		INSERT INTO trusted_pool_provision_credential_claims(
			client_id, provision_operation_id, seat_id, claim_operation_id, claimed_by, credential_fingerprint
		) VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING $7, provision_operation_id, claim_operation_id, claimed_by, credential_fingerprint, claimed_at
	`, input.ActorClientID, input.ProvisionOperationID, seatID, input.ClaimOperationID, input.ClaimedBy,
		input.CredentialFingerprint, externalSeatID))
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return claim, nil
}

func (r *trustedPoolRepository) RegisterSeat(ctx context.Context, input service.RegisterTrustedPoolSeatInput) (_ *service.TrustedPoolSeat, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
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

	// 与 provision 使用相同 Group 行锁，避免导入绑定与普通订阅/API Key 并发穿越隔离检查。
	var lockedGroupID int64
	if err = tx.QueryRowContext(ctx, `
		SELECT id FROM groups
		WHERE id=$1 AND deleted_at IS NULL AND status='active'
		  AND subscription_type='subscription' AND is_exclusive=TRUE
		FOR UPDATE
	`, input.GroupID).Scan(&lockedGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, service.ErrTrustedPoolSeatConflict
		}
		return nil, err
	}

	// 绑定注册只接受已经在 Sub2API 中相互匹配的订阅与 Key，避免集成方越权拼接资源。
	var valid bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_subscriptions s
			JOIN api_keys k ON k.id = $4
			JOIN groups g ON g.id = $2
			JOIN users u ON u.id = $1
			WHERE s.id = $3 AND s.deleted_at IS NULL
			  AND k.deleted_at IS NULL AND g.deleted_at IS NULL AND u.deleted_at IS NULL
			  AND s.user_id = $1 AND s.group_id = $2
			  AND k.user_id = $1 AND k.group_id = $2
			  AND g.subscription_type = 'subscription'
			  AND u.principal_type = 'trusted_pool_seat'
		)
	`, input.PrincipalUserID, input.GroupID, input.SubscriptionID, input.APIKeyID).Scan(&valid)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	// Pool 与 Group 的双向独占关系先在同一事务中登记，再由 Seat 复合外键持续约束。
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_groups (external_pool_id, group_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING
	`, input.ExternalPoolID, input.GroupID); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	var groupBindingValid bool
	if err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM trusted_pool_groups
			WHERE external_pool_id=$1 AND group_id=$2
		)
	`, input.ExternalPoolID, input.GroupID).Scan(&groupBindingValid); err != nil {
		return nil, err
	}
	if !groupBindingValid {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	var groupIsolated bool
	if err = tx.QueryRowContext(ctx, `
		SELECT
			NOT EXISTS (
				SELECT 1 FROM user_subscriptions us
				WHERE us.group_id=$2 AND us.deleted_at IS NULL
				  AND NOT (us.id=$3 AND us.user_id=$1)
				  AND NOT EXISTS (
					SELECT 1 FROM trusted_pool_seats ts
					JOIN users u ON u.id=us.user_id AND u.principal_type='trusted_pool_seat'
					WHERE ts.subscription_id=us.id AND ts.principal_user_id=u.id
					  AND ts.external_pool_id=$5 AND ts.group_id=$2
				  )
			)
			AND NOT EXISTS (
				SELECT 1 FROM api_keys k
				WHERE k.group_id=$2 AND k.deleted_at IS NULL
				  AND NOT (k.id=$4 AND k.user_id=$1)
				  AND NOT EXISTS (
					SELECT 1 FROM trusted_pool_seats ts
					JOIN users u ON u.id=k.user_id AND u.principal_type='trusted_pool_seat'
					WHERE ts.api_key_id=k.id AND ts.principal_user_id=u.id
					  AND ts.external_pool_id=$5 AND ts.group_id=$2
				  )
			)
	`, input.PrincipalUserID, input.GroupID, input.SubscriptionID, input.APIKeyID, input.ExternalPoolID).Scan(&groupIsolated); err != nil {
		return nil, err
	}
	if !groupIsolated {
		return nil, service.ErrTrustedPoolSeatConflict
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_seats (
			external_pool_id, external_seat_id, principal_user_id, group_id,
			subscription_id, api_key_id, state, assignment_epoch, last_operation_id
		) VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8)
		ON CONFLICT (external_seat_id) DO NOTHING
	`, input.ExternalPoolID, input.ExternalSeatID, input.PrincipalUserID, input.GroupID,
		input.SubscriptionID, input.APIKeyID, input.AssignmentEpoch, input.OperationID)
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}

	seat, err := scanTrustedPoolSeat(tx.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE external_seat_id = $1 AND external_pool_id=$2 FOR UPDATE",
		input.ExternalSeatID, input.ExternalPoolID))
	if err != nil {
		return nil, err
	}
	if seat.ExternalPoolID != input.ExternalPoolID || seat.PrincipalUserID != input.PrincipalUserID ||
		seat.GroupID != input.GroupID || seat.SubscriptionID != input.SubscriptionID || seat.APIKeyID != input.APIKeyID ||
		seat.AssignmentEpoch != input.AssignmentEpoch {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return seat, nil
}

func (r *trustedPoolRepository) GetSeat(ctx context.Context, externalPoolID, externalSeatID string) (*service.TrustedPoolSeat, error) {
	return scanTrustedPoolSeat(r.db.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE external_pool_id=$1 AND external_seat_id=$2",
		externalPoolID, externalSeatID))
}

func (r *trustedPoolRepository) GetSeatByAPIKeyID(ctx context.Context, apiKeyID int64) (*service.TrustedPoolSeat, error) {
	return scanTrustedPoolSeat(r.db.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE api_key_id = $1", apiKeyID))
}

func (r *trustedPoolRepository) TrustedPoolCredentialMatches(ctx context.Context, apiKeyID int64, credentialFingerprint string) (bool, error) {
	if strings.TrimSpace(credentialFingerprint) == "" {
		return false, nil
	}
	var matches bool
	err := r.db.QueryRowContext(ctx, `
		SELECT encode(sha256(convert_to(k.key, 'UTF8')), 'hex') = $2
		FROM trusted_pool_seats AS s
		JOIN api_keys AS k ON k.id=s.api_key_id AND k.deleted_at IS NULL
		WHERE s.api_key_id=$1
	`, apiKeyID, credentialFingerprint).Scan(&matches)
	if errors.Is(err, sql.ErrNoRows) {
		return false, service.ErrTrustedPoolSeatNotFound
	}
	return matches, err
}

func (r *trustedPoolRepository) GetUsageSnapshot(ctx context.Context, subscriptionID int64) (*service.TrustedPoolUsageSnapshot, error) {
	return scanTrustedPoolUsageSnapshot(r.db.QueryRowContext(ctx, `
		SELECT hourly_usage_usd, daily_usage_usd, weekly_usage_usd, monthly_usage_usd,
		       hourly_window_start, daily_window_start, weekly_window_start, monthly_window_start,
		       NOW()
		FROM user_subscriptions
		WHERE id=$1 AND deleted_at IS NULL
	`, subscriptionID))
}

// CreatePendingSettlement 用单条 INSERT ... SELECT 再次约束 active/epoch，避免 gate 读取后状态变化仍放行。
func (r *trustedPoolRepository) CreatePendingSettlement(ctx context.Context, seatID int64, settlementID, requestID string, assignmentEpoch int64) error {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO trusted_pool_pending_settlements(seat_id, settlement_id, request_id, assignment_epoch)
		SELECT id, $2, $3, $4
		FROM trusted_pool_seats
		WHERE id=$1 AND state='active' AND assignment_epoch=$4
	`, seatID, settlementID, requestID, assignmentEpoch)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrTrustedPoolSeatSuspended
	}
	return nil
}

// CompletePendingSettlement 仅删除精确匹配的 pending；失败时调用方必须按未结算处理。
func (r *trustedPoolRepository) CompletePendingSettlement(ctx context.Context, seatID int64, settlementID string) error {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM trusted_pool_pending_settlements
		WHERE seat_id=$1 AND settlement_id=$2
	`, seatID, settlementID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		// 找不到 pending 也不能当成成功，否则异常删除会绕过冻结 barrier。
		return fmt.Errorf("trusted pool pending settlement not found: seat=%d settlement=%s", seatID, settlementID)
	}
	return nil
}

func (r *trustedPoolRepository) MarkPendingSettlement(ctx context.Context, seatID int64, settlementID, status, billingID, lastError string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE trusted_pool_pending_settlements
		SET status=$3,
		    billing_id=COALESCE(NULLIF($4, ''), billing_id),
		    last_error=NULLIF($5, ''),
		    attempt_count=attempt_count+1,
		    updated_at=NOW()
		WHERE seat_id=$1 AND settlement_id=$2
	`, seatID, settlementID, status, billingID, lastError)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrTrustedPoolSettlementNotFound
	}
	return nil
}

// CountPendingSettlements 是 drain/freeze 的持久失败关闭屏障。
func (r *trustedPoolRepository) CountPendingSettlements(ctx context.Context, seatID int64) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM trusted_pool_pending_settlements
		WHERE seat_id=$1
	`, seatID).Scan(&count)
	return count, err
}

const trustedPoolPendingSettlementColumns = `
	p.seat_id, s.external_seat_id, p.settlement_id, p.request_id, p.billing_id,
	p.assignment_epoch, p.status, p.last_error, p.attempt_count, p.created_at, p.updated_at`

func scanTrustedPoolPendingSettlement(scanner interface{ Scan(...any) error }) (*service.TrustedPoolPendingSettlement, error) {
	item := new(service.TrustedPoolPendingSettlement)
	var billingID, lastError sql.NullString
	err := scanner.Scan(
		&item.SeatID, &item.ExternalSeatID, &item.SettlementID, &item.RequestID, &billingID,
		&item.AssignmentEpoch, &item.Status, &lastError, &item.AttemptCount, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrTrustedPoolSettlementNotFound
	}
	if err != nil {
		return nil, err
	}
	if billingID.Valid {
		item.BillingID = &billingID.String
	}
	if lastError.Valid {
		item.LastError = &lastError.String
	}
	return item, nil
}

func (r *trustedPoolRepository) ListPendingSettlements(ctx context.Context, externalPoolID, externalSeatID string, limit int) ([]service.TrustedPoolPendingSettlement, error) {
	if limit <= 0 {
		limit = 100
	} else if limit > 200 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+trustedPoolPendingSettlementColumns+`
		FROM trusted_pool_pending_settlements p
		JOIN trusted_pool_seats s ON s.id=p.seat_id
		WHERE s.external_pool_id=$1 AND s.external_seat_id=$2
		ORDER BY p.created_at ASC
		LIMIT $3
	`, externalPoolID, externalSeatID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]service.TrustedPoolPendingSettlement, 0)
	for rows.Next() {
		item, scanErr := scanTrustedPoolPendingSettlement(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

func (r *trustedPoolRepository) GetPendingSettlement(ctx context.Context, externalPoolID, externalSeatID, settlementID string) (*service.TrustedPoolPendingSettlement, error) {
	return scanTrustedPoolPendingSettlement(r.db.QueryRowContext(ctx, `SELECT `+trustedPoolPendingSettlementColumns+`
		FROM trusted_pool_pending_settlements p
		JOIN trusted_pool_seats s ON s.id=p.seat_id
		WHERE s.external_pool_id=$1 AND s.external_seat_id=$2 AND p.settlement_id=$3
	`, externalPoolID, externalSeatID, settlementID))
}

func scanTrustedPoolSettlementResolution(scanner interface{ Scan(...any) error }) (*service.TrustedPoolSettlementResolution, error) {
	item := new(service.TrustedPoolSettlementResolution)
	var assignmentEpoch sql.NullInt64
	var requestID sql.NullString
	err := scanner.Scan(&item.SeatID, &item.ExternalSeatID, &item.SettlementID, &item.OperationID,
		&item.ActorClientID, &assignmentEpoch, &requestID, &item.Reason, &item.Evidence, &item.ResolvedAt)
	if err != nil {
		return nil, err
	}
	// 历史审计没有 pending 绑定，不能作为当前严格请求的成功重放证据。
	if !assignmentEpoch.Valid || assignmentEpoch.Int64 <= 0 || !requestID.Valid || strings.TrimSpace(requestID.String) == "" {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	item.AssignmentEpoch = assignmentEpoch.Int64
	item.RequestID = requestID.String
	return item, err
}

type trustedPoolQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getTrustedPoolResolutionByOperation(ctx context.Context, queryer trustedPoolQueryRower, seatID int64, operationID string) (*service.TrustedPoolSettlementResolution, error) {
	return scanTrustedPoolSettlementResolution(queryer.QueryRowContext(ctx, `
		SELECT r.seat_id, s.external_seat_id, r.settlement_id, r.operation_id,
		       r.actor_client_id, r.expected_assignment_epoch, r.expected_request_id,
		       r.reason, r.evidence, r.resolved_at
		FROM trusted_pool_settlement_resolutions r
		JOIN trusted_pool_seats s ON s.id=r.seat_id
		WHERE r.seat_id=$1 AND r.operation_id=$2
	`, seatID, operationID))
}

func validateTrustedPoolResolutionReplay(existing *service.TrustedPoolSettlementResolution, settlementID string, input service.ResolveTrustedPoolSettlementInput) error {
	if existing == nil || existing.SettlementID != settlementID || existing.ActorClientID != input.ActorClientID ||
		existing.AssignmentEpoch != input.ExpectedAssignmentEpoch || existing.RequestID != input.ExpectedRequestID ||
		existing.Reason != input.Reason || existing.Evidence != input.Evidence {
		return service.ErrTrustedPoolSeatConflict
	}
	return nil
}

func (r *trustedPoolRepository) ResolvePendingSettlement(ctx context.Context, externalSeatID, settlementID string, input service.ResolveTrustedPoolSettlementInput) (_ *service.TrustedPoolSettlementResolution, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var seatID, currentAssignmentEpoch int64
	if err = tx.QueryRowContext(ctx, `
		SELECT id, assignment_epoch FROM trusted_pool_seats WHERE external_pool_id=$1 AND external_seat_id=$2
	`, input.ExternalPoolID, externalSeatID).Scan(&seatID, &currentAssignmentEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, service.ErrTrustedPoolSeatNotFound
		}
		return nil, err
	}
	existing, existingErr := getTrustedPoolResolutionByOperation(ctx, tx, seatID, input.OperationID)
	if existingErr == nil {
		if err = validateTrustedPoolResolutionReplay(existing, settlementID, input); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if !errors.Is(existingErr, sql.ErrNoRows) {
		return nil, existingErr
	}
	if currentAssignmentEpoch != input.ExpectedAssignmentEpoch {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	var lockedSettlementID, lockedRequestID string
	var lockedAssignmentEpoch int64
	if err = tx.QueryRowContext(ctx, `
		SELECT settlement_id, request_id, assignment_epoch FROM trusted_pool_pending_settlements
		WHERE seat_id=$1 AND settlement_id=$2 AND request_id=$3 AND assignment_epoch=$4
		FOR UPDATE
	`, seatID, settlementID, input.ExpectedRequestID, input.ExpectedAssignmentEpoch).
		Scan(&lockedSettlementID, &lockedRequestID, &lockedAssignmentEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 同幂等请求可能刚在等待行锁期间由首事务完成并删除 pending；重新读审计而不是误报 404。
			existing, existingErr = getTrustedPoolResolutionByOperation(ctx, tx, seatID, input.OperationID)
			if existingErr == nil {
				if err = validateTrustedPoolResolutionReplay(existing, settlementID, input); err != nil {
					return nil, err
				}
				if err = tx.Commit(); err != nil {
					return nil, err
				}
				return existing, nil
			}
			if errors.Is(existingErr, sql.ErrNoRows) {
				var mismatched int
				mismatchErr := tx.QueryRowContext(ctx, `
					SELECT 1 FROM trusted_pool_pending_settlements
					WHERE seat_id=$1 AND settlement_id=$2
				`, seatID, settlementID).Scan(&mismatched)
				if mismatchErr == nil {
					return nil, service.ErrTrustedPoolSeatConflict
				}
				if !errors.Is(mismatchErr, sql.ErrNoRows) {
					return nil, mismatchErr
				}
				return nil, service.ErrTrustedPoolSettlementNotFound
			}
			return nil, existingErr
		}
		return nil, err
	}
	resolution, err := scanTrustedPoolSettlementResolution(tx.QueryRowContext(ctx, `
		WITH inserted AS (
			INSERT INTO trusted_pool_settlement_resolutions(
				seat_id, settlement_id, operation_id, actor_client_id,
				expected_assignment_epoch, expected_request_id, reason, evidence
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING seat_id, settlement_id, operation_id, actor_client_id,
			          expected_assignment_epoch, expected_request_id, reason, evidence, resolved_at
		)
		SELECT i.seat_id, $9, i.settlement_id, i.operation_id,
		       i.actor_client_id, i.expected_assignment_epoch, i.expected_request_id,
		       i.reason, i.evidence, i.resolved_at
		FROM inserted i
	`, seatID, settlementID, input.OperationID, input.ActorClientID, input.ExpectedAssignmentEpoch,
		input.ExpectedRequestID, input.Reason, input.Evidence, externalSeatID))
	if err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	if err = execTrustedPoolOne(ctx, tx, `DELETE FROM trusted_pool_pending_settlements
		WHERE seat_id=$1 AND settlement_id=$2 AND request_id=$3 AND assignment_epoch=$4`,
		seatID, settlementID, input.ExpectedRequestID, input.ExpectedAssignmentEpoch); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return resolution, nil
}

func scanTrustedPoolUsageSnapshot(scanner interface{ Scan(...any) error }) (*service.TrustedPoolUsageSnapshot, error) {
	var hourlyStart, dailyStart, weeklyStart, monthlyStart sql.NullTime
	var hourlyUsage, dailyUsage, weeklyUsage, monthlyUsage float64
	snapshot := &service.TrustedPoolUsageSnapshot{
		Usage:        make(map[string]float64, 4),
		WindowStarts: make(map[string]*string, 4),
	}
	err := scanner.Scan(
		&hourlyUsage, &dailyUsage, &weeklyUsage, &monthlyUsage,
		&hourlyStart, &dailyStart, &weeklyStart, &monthlyStart, &snapshot.CapturedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrTrustedPoolSeatConflict
	}
	if err != nil {
		return nil, err
	}
	snapshot.Usage["hourly"] = hourlyUsage
	snapshot.Usage["daily"] = dailyUsage
	snapshot.Usage["weekly"] = weeklyUsage
	snapshot.Usage["monthly"] = monthlyUsage
	for name, value := range map[string]sql.NullTime{
		"hourly": hourlyStart, "daily": dailyStart, "weekly": weeklyStart, "monthly": monthlyStart,
	} {
		if value.Valid {
			formatted := value.Time.UTC().Format(time.RFC3339Nano)
			snapshot.WindowStarts[name] = &formatted
		} else {
			// nil 表示原生额度窗口尚未启动，不能伪造成 captured_at。
			snapshot.WindowStarts[name] = nil
		}
	}
	return snapshot, nil
}

func (r *trustedPoolRepository) SuspendSeat(ctx context.Context, externalPoolID, externalSeatID, operationID string) (_ *service.TrustedPoolSeat, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	seat, err := scanTrustedPoolSeat(tx.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE external_pool_id=$1 AND external_seat_id=$2 FOR UPDATE",
		externalPoolID, externalSeatID))
	if err != nil {
		return nil, err
	}
	historyEpoch, historyFound, err := getTrustedPoolOperationEpoch(ctx, tx, seat.ID, "suspend", operationID)
	if err != nil {
		return nil, err
	}
	if historyFound {
		if historyEpoch != seat.AssignmentEpoch {
			// 旧 epoch 的暂停命令绝不能再次禁用当前 epoch 已轮换的新 Key。
			return nil, service.ErrTrustedPoolEpochConflict
		}
		if seat.State == service.TrustedPoolSeatStateDraining || seat.State == service.TrustedPoolSeatStateFrozen {
			if err = tx.Commit(); err != nil {
				return nil, err
			}
			tx = nil
			return seat, nil
		}
		return nil, service.ErrTrustedPoolInvalidState
	}
	if seat.State == service.TrustedPoolSeatStateRotating {
		return nil, service.ErrTrustedPoolInvalidState
	}

	if seat.State == service.TrustedPoolSeatStateActive {
		if err = execTrustedPoolOne(ctx, tx, `UPDATE user_subscriptions SET status='suspended', updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, seat.SubscriptionID); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `UPDATE api_keys SET status='disabled', updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, seat.APIKeyID); err != nil {
			return nil, err
		}
		if err = execTrustedPoolOne(ctx, tx, `UPDATE trusted_pool_seats SET state='draining', suspended_at=NOW(), last_operation_id=$2, updated_at=NOW() WHERE id=$1`, seat.ID, operationID); err != nil {
			return nil, err
		}
		if err = recordTrustedPoolOperation(ctx, tx, seat.ID, "suspend", operationID, seat.AssignmentEpoch, service.TrustedPoolSeatStateDraining); err != nil {
			return nil, err
		}
	} else if seat.LastOperationID != operationID {
		// 不允许后来的 operation 覆盖首次暂停操作，否则旧请求将无法稳定重放。
		return nil, service.ErrTrustedPoolInvalidState
	}
	seat, err = scanTrustedPoolSeat(tx.QueryRowContext(ctx, "SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE id=$1", seat.ID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return seat, nil
}

func getTrustedPoolOperationEpoch(ctx context.Context, tx *sql.Tx, seatID int64, operationType, operationID string) (int64, bool, error) {
	var epoch int64
	err := tx.QueryRowContext(ctx, `
		SELECT assignment_epoch
		FROM trusted_pool_operations
		WHERE seat_id=$1 AND operation_type=$2 AND operation_id=$3
	`, seatID, operationType, operationID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return epoch, err == nil, err
}

func recordTrustedPoolOperation(ctx context.Context, tx *sql.Tx, seatID int64, operationType, operationID string, epoch int64, resultState string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO trusted_pool_operations(seat_id, operation_type, operation_id, assignment_epoch, result_state)
		VALUES ($1,$2,$3,$4,$5)
	`, seatID, operationType, operationID, epoch, resultState)
	return translateTrustedPoolConflict(err)
}

func (r *trustedPoolRepository) FreezeSeat(ctx context.Context, externalPoolID, externalSeatID, operationID string) (_ *service.TrustedPoolSeat, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	seat, err := scanTrustedPoolSeat(tx.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE external_pool_id=$1 AND external_seat_id=$2 FOR UPDATE",
		externalPoolID, externalSeatID))
	if err != nil {
		return nil, err
	}
	if seat.State == service.TrustedPoolSeatStateFrozen {
		// 冻结是期望状态操作，重复请求直接返回现状。
		if seat.LastOperationID != operationID {
			return nil, service.ErrTrustedPoolInvalidState
		}
	} else if seat.State != service.TrustedPoolSeatStateDraining {
		return nil, service.ErrTrustedPoolInvalidState
	} else {
		if err = execTrustedPoolOne(ctx, tx, `
			UPDATE trusted_pool_seats s SET state='frozen', last_operation_id=$2, updated_at=NOW()
			WHERE s.id=$1
			  AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id=s.api_key_id AND k.status='disabled' AND k.deleted_at IS NULL)
			  AND EXISTS (SELECT 1 FROM user_subscriptions us WHERE us.id=s.subscription_id AND us.status='suspended' AND us.deleted_at IS NULL)
		`, seat.ID, operationID); err != nil {
			return nil, err
		}
	}
	seat, err = scanTrustedPoolSeat(tx.QueryRowContext(ctx, "SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE id=$1", seat.ID))
	if err != nil {
		return nil, err
	}
	seat.UsageSnapshot, err = scanTrustedPoolUsageSnapshot(tx.QueryRowContext(ctx, `
		SELECT hourly_usage_usd, daily_usage_usd, weekly_usage_usd, monthly_usage_usd,
		       hourly_window_start, daily_window_start, weekly_window_start, monthly_window_start,
		       NOW()
		FROM user_subscriptions
		WHERE id=$1 AND deleted_at IS NULL
		FOR SHARE
	`, seat.SubscriptionID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return seat, nil
}

func (r *trustedPoolRepository) RotateSeatCredential(ctx context.Context, externalPoolID, externalSeatID, operationID, credential string, targetEpoch int64) (_ *service.TrustedPoolRotationResult, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	seat, err := scanTrustedPoolSeat(tx.QueryRowContext(ctx,
		"SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE external_pool_id=$1 AND external_seat_id=$2 FOR UPDATE",
		externalPoolID, externalSeatID))
	if err != nil {
		return nil, err
	}

	var currentCredential string
	if err = tx.QueryRowContext(ctx, `SELECT key FROM api_keys WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, seat.APIKeyID).Scan(&currentCredential); err != nil {
		return nil, err
	}
	if seat.AssignmentEpoch == targetEpoch && seat.LastOperationID == operationID {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		tx = nil
		return &service.TrustedPoolRotationResult{Seat: seat, Credential: currentCredential}, nil
	}
	if seat.State != service.TrustedPoolSeatStateFrozen || targetEpoch != seat.AssignmentEpoch+1 || strings.TrimSpace(credential) == "" {
		return nil, service.ErrTrustedPoolEpochConflict
	}
	if err = execTrustedPoolOne(ctx, tx, `UPDATE trusted_pool_seats SET state='rotating', updated_at=NOW() WHERE id=$1`, seat.ID); err != nil {
		return nil, err
	}
	// 只轮换 credential，不改变 api_key_id 及任何 quota/window 字段。
	if err = execTrustedPoolOne(ctx, tx, `UPDATE api_keys SET key=$2, status='active', updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, seat.APIKeyID, credential); err != nil {
		return nil, translateTrustedPoolConflict(err)
	}
	if err = execTrustedPoolOne(ctx, tx, `UPDATE user_subscriptions SET status='active', updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, seat.SubscriptionID); err != nil {
		return nil, err
	}
	if err = execTrustedPoolOne(ctx, tx, `UPDATE trusted_pool_seats SET state='active', assignment_epoch=$2, last_operation_id=$3, updated_at=NOW() WHERE id=$1`, seat.ID, targetEpoch, operationID); err != nil {
		return nil, err
	}
	seat, err = scanTrustedPoolSeat(tx.QueryRowContext(ctx, "SELECT "+trustedPoolSeatColumns+" FROM trusted_pool_seats WHERE id=$1", seat.ID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return &service.TrustedPoolRotationResult{Seat: seat, Credential: credential, OldCredential: currentCredential}, nil
}

func (r *trustedPoolRepository) GetUsageRisk(ctx context.Context, externalPoolID, externalSeatID string, since time.Time) (*service.TrustedPoolUsageRisk, error) {
	risk := &service.TrustedPoolUsageRisk{ExternalSeatID: externalSeatID}
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(l.id),
		       COUNT(DISTINCT NULLIF(l.ip_address, '')),
		       COUNT(DISTINCT encode(sha256(convert_to(COALESCE(l.ip_address,'') || '|' || COALESCE(l.user_agent,''), 'UTF8')), 'hex')) FILTER (WHERE l.id IS NOT NULL),
		       COALESCE(SUM(l.actual_cost), 0)
		FROM trusted_pool_seats s
		LEFT JOIN usage_logs l ON l.api_key_id=s.api_key_id AND l.created_at >= $3
		WHERE s.external_pool_id=$1 AND s.external_seat_id=$2
		HAVING COUNT(s.id) > 0
	`, externalPoolID, externalSeatID, since).Scan(&risk.RequestCount, &risk.DistinctIPCount, &risk.DeviceFingerprintCount, &risk.ActualCostUSD)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrTrustedPoolSeatNotFound
	}
	return risk, err
}

func translateTrustedPoolConflict(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "duplicate key value") || strings.Contains(err.Error(), "unique constraint") {
		return service.ErrTrustedPoolSeatConflict.WithCause(err)
	}
	return fmt.Errorf("trusted pool persistence: %w", err)
}

func requireTrustedPoolClientBinding(ctx context.Context, tx *sql.Tx, clientID, externalPoolID string) error {
	var authorized bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM trusted_pool_integration_clients
			WHERE client_id=$1 AND external_pool_id=$2 AND status='active'
			  AND (expires_at IS NULL OR expires_at > NOW())
		)
	`, clientID, externalPoolID).Scan(&authorized)
	if err != nil {
		return err
	}
	if !authorized {
		return service.ErrTrustedPoolForbidden
	}
	return nil
}

func execTrustedPoolOne(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrTrustedPoolSeatConflict
	}
	return nil
}
