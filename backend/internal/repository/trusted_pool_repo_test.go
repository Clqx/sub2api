//go:build unit

package repository

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func trustedPoolProvisionTestInput(now time.Time) service.ProvisionTrustedPoolSeatInput {
	return service.ProvisionTrustedPoolSeatInput{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", ExistingGroupID: 20,
		AssignmentEpoch: 1, OperationID: "provision-1", ActorClientID: "platform-1",
		RequestHash: strings.Repeat("a", 64), Credential: "sk-tp-secret",
		CredentialFingerprint: trustedPoolCredentialFingerprint("sk-tp-secret"),
		PrincipalEmail:        "tp-seat-1@principal.invalid", PrincipalConcurrency: 2,
		SubscriptionExpiresAt: now.Add(30 * 24 * time.Hour), APIKeyQuota: 10,
	}
}

func trustedPoolSeatTestColumns() []string {
	return []string{
		"id", "external_pool_id", "external_seat_id", "principal_user_id", "group_id",
		"subscription_id", "api_key_id", "state", "assignment_epoch", "last_operation_id",
		"suspended_at", "created_at", "updated_at",
	}
}

func expectTrustedPoolClientBinding(mock sqlmock.Sqlmock, clientID, externalPoolID string, authorized bool) {
	mock.ExpectQuery("(?s)SELECT EXISTS .*trusted_pool_integration_clients").
		WithArgs(clientID, externalPoolID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(authorized))
}

func TestTrustedPoolProvisionCreatesResourcesInOneTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	now := time.Now()
	input := trustedPoolProvisionTestInput(now)

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_provision_operations").
		WithArgs("platform-1", "provision-1", "pool-1", "seat-1", input.RequestHash, input.CredentialFingerprint).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)SELECT id FROM groups.*FOR UPDATE").WithArgs(int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(20))
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_groups").WithArgs("pool-1", int64(20)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_groups").WithArgs("pool-1", int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("(?s)SELECT.*NOT EXISTS .*user_subscriptions.*AND NOT EXISTS .*api_keys").
		WithArgs(int64(20), "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"isolated"}).AddRow(true))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_seats").WithArgs("seat-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("(?s)INSERT INTO users").WithArgs(input.PrincipalEmail, 2, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(10))
	mock.ExpectQuery("(?s)INSERT INTO user_subscriptions").
		WithArgs(int64(10), int64(20), sqlmock.AnyArg(), input.SubscriptionExpiresAt).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(30))
	mock.ExpectQuery("(?s)INSERT INTO api_keys").
		WithArgs(int64(10), "sk-tp-secret", int64(20), float64(10), input.SubscriptionExpiresAt, float64(0), float64(0), float64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(40))
	mock.ExpectQuery("(?s)INSERT INTO trusted_pool_seats").
		WithArgs("pool-1", "seat-1", int64(10), int64(20), int64(30), int64(40), int64(1), "provision-1").
		WillReturnRows(sqlmock.NewRows(trustedPoolSeatTestColumns()).AddRow(
			1, "pool-1", "seat-1", 10, 20, 30, 40, service.TrustedPoolSeatStateActive, 1, "provision-1", nil, now, now,
		))
	mock.ExpectExec("(?s)UPDATE trusted_pool_provision_operations").
		WithArgs("platform-1", "provision-1", int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	result, err := repo.ProvisionSeat(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, int64(10), result.Seat.PrincipalUserID)
	require.Equal(t, "sk-tp-secret", result.Credential)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolProvisionExactReplayReturnsOriginalCredential(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	now := time.Now()
	input := trustedPoolProvisionTestInput(now)

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_provision_operations").
		WithArgs("platform-1", "provision-1", "pool-1", "seat-1", input.RequestHash, input.CredentialFingerprint).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("(?s)SELECT.*request_hash.*seat_id.*FOR UPDATE").WithArgs("platform-1", "provision-1").
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "seat_id", "credential_fingerprint"}).AddRow(input.RequestHash, 1, input.CredentialFingerprint))
	mock.ExpectQuery("(?s)SELECT EXISTS .*trusted_pool_provision_credential_claims").WithArgs("platform-1", "provision-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("(?s)FROM trusted_pool_seats s.*JOIN api_keys.*NOT EXISTS.*trusted_pool_operations").
		WithArgs(int64(1), "provision-1", "platform-1").
		WillReturnRows(sqlmock.NewRows(append(trustedPoolSeatTestColumns(), "key")).AddRow(
			1, "pool-1", "seat-1", 10, 20, 30, 40, service.TrustedPoolSeatStateActive, 1, "provision-1", nil, now, now, "sk-tp-secret",
		))
	mock.ExpectCommit()

	result, err := repo.ProvisionSeat(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, "sk-tp-secret", result.Credential)
	require.Equal(t, input.CredentialFingerprint, result.CredentialFingerprint)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolProvisionRejectsIdempotencyPayloadDrift(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := trustedPoolProvisionTestInput(time.Now())

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_provision_operations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("(?s)SELECT.*request_hash.*seat_id.*FOR UPDATE").WithArgs("platform-1", "provision-1").
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "seat_id", "credential_fingerprint"}).AddRow(strings.Repeat("b", 64), 1, input.CredentialFingerprint))
	mock.ExpectRollback()

	_, err = repo.ProvisionSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolProvisionReplayNeverReturnsClaimedCredential(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := trustedPoolProvisionTestInput(time.Now())

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_provision_operations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("(?s)SELECT.*request_hash.*seat_id.*FOR UPDATE").WithArgs("platform-1", "provision-1").
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "seat_id", "credential_fingerprint"}).AddRow(input.RequestHash, 1, input.CredentialFingerprint))
	mock.ExpectQuery("(?s)SELECT EXISTS .*trusted_pool_provision_credential_claims").WithArgs("platform-1", "provision-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectRollback()

	_, err = repo.ProvisionSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolCredentialClaimed)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolCredentialAckIsAtomicAndIdempotent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	completedAt := time.Now().Add(-time.Minute)
	claimedAt := time.Now()
	input := service.AckTrustedPoolProvisionCredentialInput{
		ProvisionOperationID: "provision-1", ClaimOperationID: "claim-1",
		ClaimedBy: "vault-record-1", CredentialFingerprint: trustedPoolCredentialFingerprint("sk-tp-secret"), ActorClientID: "platform-1", ExternalPoolID: "pool-1",
	}
	claimColumns := []string{"external_seat_id", "provision_operation_id", "claim_operation_id", "claimed_by", "credential_fingerprint", "claimed_at"}

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT operation.seat_id.*FOR UPDATE OF operation, seat, api_key").
		WithArgs("platform-1", "provision-1", "seat-1", "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"seat_id", "completed_at", "credential_fingerprint", "credential"}).AddRow(1, completedAt, input.CredentialFingerprint, "sk-tp-secret"))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_operations").
		WithArgs(int64(1), completedAt).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("(?s)FROM trusted_pool_provision_credential_claims claim").
		WithArgs("platform-1", "provision-1", "pool-1").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("(?s)INSERT INTO trusted_pool_provision_credential_claims").
		WithArgs("platform-1", "provision-1", int64(1), "claim-1", "vault-record-1", input.CredentialFingerprint, "seat-1").
		WillReturnRows(sqlmock.NewRows(claimColumns).AddRow("seat-1", "provision-1", "claim-1", "vault-record-1", input.CredentialFingerprint, claimedAt))
	mock.ExpectCommit()

	claim, err := repo.AckProvisionCredential(context.Background(), "seat-1", input)
	require.NoError(t, err)
	require.True(t, claim.CredentialClaimed)
	require.Equal(t, "claim-1", claim.ClaimOperationID)

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT operation.seat_id.*FOR UPDATE OF operation, seat, api_key").
		WithArgs("platform-1", "provision-1", "seat-1", "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"seat_id", "completed_at", "credential_fingerprint", "credential"}).AddRow(1, completedAt, input.CredentialFingerprint, "sk-tp-secret"))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_operations").
		WithArgs(int64(1), completedAt).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("(?s)FROM trusted_pool_provision_credential_claims claim").
		WithArgs("platform-1", "provision-1", "pool-1").
		WillReturnRows(sqlmock.NewRows(claimColumns).AddRow("seat-1", "provision-1", "claim-1", "vault-record-1", input.CredentialFingerprint, claimedAt))
	mock.ExpectCommit()

	retry, err := repo.AckProvisionCredential(context.Background(), "seat-1", input)
	require.NoError(t, err)
	require.Equal(t, claim, retry)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolCredentialAckFailsClosedAfterLifecycleAdvanced(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	completedAt := time.Now().Add(-time.Minute)
	input := service.AckTrustedPoolProvisionCredentialInput{
		ProvisionOperationID: "provision-1", ClaimOperationID: "claim-1",
		ClaimedBy: "vault-record-1", CredentialFingerprint: trustedPoolCredentialFingerprint("sk-tp-secret"), ActorClientID: "platform-1", ExternalPoolID: "pool-1",
	}

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT operation.seat_id.*FOR UPDATE OF operation, seat, api_key").
		WithArgs("platform-1", "provision-1", "seat-1", "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"seat_id", "completed_at", "credential_fingerprint", "credential"}).AddRow(1, completedAt, input.CredentialFingerprint, "sk-tp-secret"))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_operations").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectRollback()

	_, err = repo.AckProvisionCredential(context.Background(), "seat-1", input)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolProvisionRejectsGroupUsedByNonSeatResources(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := trustedPoolProvisionTestInput(time.Now())

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_provision_operations").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)SELECT id FROM groups.*FOR UPDATE").WithArgs(int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(20))
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_groups").WithArgs("pool-1", int64(20)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_groups").WithArgs("pool-1", int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("(?s)SELECT.*NOT EXISTS .*user_subscriptions.*AND NOT EXISTS .*api_keys").
		WithArgs(int64(20), "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"isolated"}).AddRow(false))
	mock.ExpectRollback()

	_, err = repo.ProvisionSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolRegisterRejectsHumanPrincipal(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := service.RegisterTrustedPoolSeatInput{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", PrincipalUserID: 10,
		GroupID: 20, SubscriptionID: 30, APIKeyID: 40, AssignmentEpoch: 1, OperationID: "register-1", ActorClientID: "platform-1",
	}

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectQuery("(?s)SELECT id FROM groups.*status='active'.*is_exclusive=TRUE.*FOR UPDATE").
		WithArgs(int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(20))
	mock.ExpectQuery("(?s)SELECT EXISTS .*u.principal_type = 'trusted_pool_seat'").
		WithArgs(int64(10), int64(20), int64(30), int64(40)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectRollback()

	_, err = repo.RegisterSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolRegisterRejectsGroupWithOrdinaryResources(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := service.RegisterTrustedPoolSeatInput{
		ExternalPoolID: "pool-1", ExternalSeatID: "seat-1", PrincipalUserID: 10,
		GroupID: 20, SubscriptionID: 30, APIKeyID: 40, AssignmentEpoch: 1, OperationID: "register-1", ActorClientID: "platform-1",
	}

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", true)
	mock.ExpectQuery("(?s)SELECT id FROM groups.*status='active'.*is_exclusive=TRUE.*FOR UPDATE").
		WithArgs(int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(20))
	mock.ExpectQuery("(?s)SELECT EXISTS .*u.principal_type = 'trusted_pool_seat'").
		WithArgs(int64(10), int64(20), int64(30), int64(40)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("(?s)INSERT INTO trusted_pool_groups").
		WithArgs("pool-1", int64(20)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)SELECT EXISTS .* FROM trusted_pool_groups").
		WithArgs("pool-1", int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("(?s)SELECT.*NOT EXISTS .*user_subscriptions.*AND NOT EXISTS .*api_keys").
		WithArgs(int64(10), int64(20), int64(30), int64(40), "pool-1").
		WillReturnRows(sqlmock.NewRows([]string{"isolated"}).AddRow(false))
	mock.ExpectRollback()

	_, err = repo.RegisterSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolSuspendRejectsHistoricalOperationFromOldEpoch(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT .* FROM trusted_pool_seats WHERE external_pool_id=\\$1 AND external_seat_id=\\$2 FOR UPDATE").
		WithArgs("pool-1", "seat-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "external_pool_id", "external_seat_id", "principal_user_id", "group_id",
			"subscription_id", "api_key_id", "state", "assignment_epoch", "last_operation_id",
			"suspended_at", "created_at", "updated_at",
		}).AddRow(1, "pool-1", "seat-1", 10, 20, 30, 40, service.TrustedPoolSeatStateActive, 2, "rotate-2", nil, now, now))
	mock.ExpectQuery("(?s)SELECT assignment_epoch.*FROM trusted_pool_operations").
		WithArgs(int64(1), "suspend", "old-suspend").
		WillReturnRows(sqlmock.NewRows([]string{"assignment_epoch"}).AddRow(1))
	mock.ExpectRollback()

	_, err = repo.SuspendSeat(context.Background(), "pool-1", "seat-1", "old-suspend")
	require.ErrorIs(t, err, service.ErrTrustedPoolEpochConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolUsageRiskReturnsNotFoundForUnknownSeat(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}

	mock.ExpectQuery("SELECT COUNT\\(l.id\\)").
		WithArgs("pool-1", "missing-seat", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	_, err = repo.GetUsageRisk(context.Background(), "pool-1", "missing-seat", time.Now().Add(-time.Hour))
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolGetSeatScopesLookupToAuthorizedPool(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}

	mock.ExpectQuery("(?s)FROM trusted_pool_seats WHERE external_pool_id=\\$1 AND external_seat_id=\\$2").
		WithArgs("pool-1", "seat-from-pool-2").
		WillReturnError(sql.ErrNoRows)
	_, err = repo.GetSeat(context.Background(), "pool-1", "seat-from-pool-2")
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolProvisionRejectsRepositoryClientPoolMismatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := trustedPoolProvisionTestInput(time.Now())

	mock.ExpectBegin()
	expectTrustedPoolClientBinding(mock, "platform-1", "pool-1", false)
	mock.ExpectRollback()
	_, err = repo.ProvisionSeat(context.Background(), input)
	require.ErrorIs(t, err, service.ErrTrustedPoolForbidden)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolPendingSettlementLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}

	mock.ExpectExec("(?s)INSERT INTO trusted_pool_pending_settlements.*state='active'.*assignment_epoch=\\$4").
		WithArgs(int64(1), "settlement-1", "request-1", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, repo.CreatePendingSettlement(context.Background(), 1, "settlement-1", "request-1", 3))

	mock.ExpectQuery("(?s)SELECT COUNT\\(\\*\\).*trusted_pool_pending_settlements").
		WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	count, err := repo.CountPendingSettlements(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	mock.ExpectExec("(?s)DELETE FROM trusted_pool_pending_settlements").
		WithArgs(int64(1), "settlement-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, repo.CompletePendingSettlement(context.Background(), 1, "settlement-1"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolPendingSettlementCreateRejectsChangedGate(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}

	mock.ExpectExec("(?s)INSERT INTO trusted_pool_pending_settlements").
		WithArgs(int64(1), "settlement-1", "request-1", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	err = repo.CreatePendingSettlement(context.Background(), 1, "settlement-1", "request-1", 3)
	require.ErrorIs(t, err, service.ErrTrustedPoolSeatSuspended)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolResolvePendingSettlementIsAuditedAndIdempotent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := service.ResolveTrustedPoolSettlementInput{
		OperationID: "resolve-op-1", ActorClientID: "platform-1", ExternalPoolID: "pool-1", Reason: "verified billing ledger", Evidence: "ticket-123",
	}
	resolvedAt := time.Now()
	resolutionColumns := []string{"seat_id", "external_seat_id", "settlement_id", "operation_id", "actor_client_id", "reason", "evidence", "resolved_at"}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM trusted_pool_seats").WithArgs("pool-1", "seat-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery("(?s)FROM trusted_pool_settlement_resolutions.*operation_id=\\$2").
		WithArgs(int64(1), "resolve-op-1").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("(?s)SELECT settlement_id FROM trusted_pool_pending_settlements.*FOR UPDATE").
		WithArgs(int64(1), "settlement-1").
		WillReturnRows(sqlmock.NewRows([]string{"settlement_id"}).AddRow("settlement-1"))
	mock.ExpectQuery("(?s)INSERT INTO trusted_pool_settlement_resolutions").
		WithArgs(int64(1), "settlement-1", "resolve-op-1", "platform-1", "verified billing ledger", "ticket-123", "seat-1").
		WillReturnRows(sqlmock.NewRows(resolutionColumns).AddRow(1, "seat-1", "settlement-1", "resolve-op-1", "platform-1", "verified billing ledger", "ticket-123", resolvedAt))
	mock.ExpectExec("DELETE FROM trusted_pool_pending_settlements").
		WithArgs(int64(1), "settlement-1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	first, err := repo.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", input)
	require.NoError(t, err)
	require.Equal(t, "resolve-op-1", first.OperationID)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM trusted_pool_seats").WithArgs("pool-1", "seat-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery("(?s)FROM trusted_pool_settlement_resolutions.*operation_id=\\$2").
		WithArgs(int64(1), "resolve-op-1").
		WillReturnRows(sqlmock.NewRows(resolutionColumns).AddRow(1, "seat-1", "settlement-1", "resolve-op-1", "platform-1", "verified billing ledger", "ticket-123", resolvedAt))
	mock.ExpectCommit()

	retry, err := repo.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", input)
	require.NoError(t, err)
	require.Equal(t, first, retry)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTrustedPoolConcurrentResolveRereadsAuditAfterPendingLockWait(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &trustedPoolRepository{db: db}
	input := service.ResolveTrustedPoolSettlementInput{
		OperationID: "resolve-op-1", ActorClientID: "platform-1", ExternalPoolID: "pool-1", Reason: "verified billing ledger", Evidence: "ticket-123",
	}
	resolvedAt := time.Now()
	resolutionColumns := []string{"seat_id", "external_seat_id", "settlement_id", "operation_id", "actor_client_id", "reason", "evidence", "resolved_at"}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM trusted_pool_seats").WithArgs("pool-1", "seat-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	// 第二事务在首轮审计查询时尚未观察到第一事务提交。
	mock.ExpectQuery("(?s)FROM trusted_pool_settlement_resolutions.*operation_id=\\$2").
		WithArgs(int64(1), "resolve-op-1").WillReturnError(sql.ErrNoRows)
	// 等待 pending 行锁后，第一事务已提交并删除 pending。
	mock.ExpectQuery("(?s)SELECT settlement_id FROM trusted_pool_pending_settlements.*FOR UPDATE").
		WithArgs(int64(1), "settlement-1").WillReturnError(sql.ErrNoRows)
	// READ COMMITTED 下新语句必须重读审计并返回原结果，不能返回 404。
	mock.ExpectQuery("(?s)FROM trusted_pool_settlement_resolutions.*operation_id=\\$2").
		WithArgs(int64(1), "resolve-op-1").
		WillReturnRows(sqlmock.NewRows(resolutionColumns).AddRow(1, "seat-1", "settlement-1", "resolve-op-1", "platform-1", "verified billing ledger", "ticket-123", resolvedAt))
	mock.ExpectCommit()

	resolution, err := repo.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", input)
	require.NoError(t, err)
	require.Equal(t, "resolve-op-1", resolution.OperationID)
	require.NoError(t, mock.ExpectationsWereMet())
}
