package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	migrationfiles "github.com/Wei-Shaw/sub2api/migrations"
	"github.com/lib/pq"
)

const (
	permanentRotationMigration                 = "226_trusted_pool_permanent_rotation.sql"
	permanentRotationEncryptedStagingMigration = "227_trusted_pool_permanent_rotation_encrypted_staging.sql"
)

// SUB2API_TEST_POSTGRES_DSN must reference an empty disposable PostgreSQL database.
func TestTrustedPoolPermanentRotationMigrationsOnRealPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("SUB2API_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("SUB2API_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := applyMigrationsFS(ctx, db, migrationFilesBefore(t, permanentRotationMigration)); err != nil {
		t.Fatalf("apply migrations before permanent rotation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO trusted_pool_integration_clients (
client_id, secret_hash, scopes, status, external_pool_id
) VALUES
('permanent-rotate-mixed', repeat('a', 64), ARRAY['seat:permanent-rotate','seat:suspend'], 'active', 'pool-mixed'),
('permanent-rotate-only', repeat('b', 64), ARRAY['seat:permanent-rotate'], 'active', 'pool-only')`); err != nil {
		t.Fatalf("insert pre-226 integration clients: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations through permanent rotation: %v", err)
	}
	assertPermanentRotationEncryptedStagingSchema(t, ctx, db)
	for _, table := range []string{
		"trusted_pool_permanent_rotations",
		"trusted_pool_permanent_rotation_seats",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("permanent rotation table %s unavailable: exists=%v err=%v", table, exists, err)
		}
	}
	for _, migration := range []string{permanentRotationMigration, permanentRotationEncryptedStagingMigration} {
		var applied int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations
WHERE filename = $1`, migration).Scan(&applied); err != nil || applied != 1 {
			t.Fatalf("permanent rotation migration %s ledger count=%d err=%v", migration, applied, err)
		}
	}
	var mixedStatus, isolatedStatus string
	if err := db.QueryRowContext(ctx, `SELECT
max(status) FILTER (WHERE client_id = 'permanent-rotate-mixed'),
max(status) FILTER (WHERE client_id = 'permanent-rotate-only')
FROM trusted_pool_integration_clients`).Scan(&mixedStatus, &isolatedStatus); err != nil {
		t.Fatalf("read upgraded integration clients: %v", err)
	}
	if mixedStatus != "disabled" || isolatedStatus != "active" {
		t.Fatalf("scope isolation upgrade mixed=%s isolated=%s", mixedStatus, isolatedStatus)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO trusted_pool_integration_clients (
client_id, secret_hash, scopes, status, external_pool_id
) VALUES ('permanent-rotate-invalid', repeat('c', 64),
          ARRAY['seat:permanent-rotate','seat:freeze'], 'active', 'pool-invalid')`); err == nil {
		t.Fatal("database accepted a new active mixed permanent-rotation scope")
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("reapply migrations: %v", err)
	}

	fixture := seedPermanentRotationPostgresFixture(t, ctx, db)
	assertPermanentRotationDirectDMLGuards(t, ctx, db, fixture)
	winner := assertPermanentRotationTwoConnectionWinner(t, ctx, db, fixture)
	assertPermanentRotationPreparedEnvelope(t, ctx, db, winner)
	assertPermanentRotationEncryptedStagingReplay(t, ctx, db, winner)
	assertPermanentRotationCommitReceiptRecovery(t, ctx, db, winner)
}

func assertPermanentRotationEncryptedStagingSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	t.Run("EncryptedPreparedCredentialSchema", func(t *testing.T) {
		expectedTypes := map[string][]string{
			"prepared_credential_envelope_version": {"smallint"},
			"prepared_credential_key_id":           {"character varying"},
			"prepared_credential_nonce":            {"bytea"},
			"prepared_credential_ciphertext":       {"bytea"},
			"prepared_credential_wrapped_dek":      {"bytea"},
			"prepared_credential_wrap_nonce":       {"bytea"},
			"prepared_credential_expires_at":       {"timestamp with time zone"},
		}
		rows, err := db.QueryContext(ctx, "SELECT column_name, data_type FROM information_schema.columns "+
			"WHERE table_schema=current_schema() AND table_name='trusted_pool_permanent_rotation_seats' "+
			"AND column_name LIKE 'prepared_credential%' ORDER BY column_name")
		if err != nil {
			t.Fatalf("inspect encrypted staging columns: %v", err)
		}
		defer rows.Close()
		found := make(map[string]string)
		for rows.Next() {
			var name, dataType string
			if err := rows.Scan(&name, &dataType); err != nil {
				t.Fatalf("scan encrypted staging column: %v", err)
			}
			found[name] = dataType
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate encrypted staging columns: %v", err)
		}
		if _, exists := found["prepared_credential"]; exists {
			t.Fatal("legacy plaintext prepared_credential column remains available")
		}
		if len(found) != len(expectedTypes) {
			t.Fatalf("encrypted staging column count=%d want=%d columns=%v", len(found), len(expectedTypes), found)
		}
		for name, allowedTypes := range expectedTypes {
			got, exists := found[name]
			if !exists {
				t.Fatalf("encrypted staging column %s is missing", name)
			}
			allowed := false
			for _, candidate := range allowedTypes {
				allowed = allowed || got == candidate
			}
			if !allowed {
				t.Fatalf("encrypted staging column %s type=%s want one of %v", name, got, allowedTypes)
			}
		}
		var keyIDMaximumLength int
		if err := db.QueryRowContext(ctx, "SELECT character_maximum_length FROM information_schema.columns "+
			"WHERE table_schema=current_schema() AND table_name='trusted_pool_permanent_rotation_seats' "+
			"AND column_name='prepared_credential_key_id'").Scan(&keyIDMaximumLength); err != nil {
			t.Fatalf("inspect prepared credential key ID bound: %v", err)
		}
		if keyIDMaximumLength != 128 {
			t.Fatalf("prepared credential key ID maximum length=%d want=128", keyIDMaximumLength)
		}

		var constraintDefinitions string
		if err := db.QueryRowContext(ctx, "SELECT COALESCE(string_agg(lower(pg_get_constraintdef(c.oid)), ' '), '') "+
			"FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid "+
			"JOIN pg_namespace n ON n.oid=t.relnamespace "+
			"WHERE n.nspname=current_schema() AND t.relname='trusted_pool_permanent_rotation_seats' "+
			"AND c.contype='c'").Scan(&constraintDefinitions); err != nil {
			t.Fatalf("inspect encrypted staging constraints: %v", err)
		}
		constraintDefinitions = strings.Join(strings.Fields(constraintDefinitions), " ")
		for _, required := range []string{
			"prepared_credential_envelope_version = 1",
			"octet_length(prepared_credential_nonce) = 12",
			"octet_length(prepared_credential_wrap_nonce) = 12",
			"octet_length(prepared_credential_ciphertext) >= 16",
			"octet_length(prepared_credential_wrapped_dek) = 48",
		} {
			if !strings.Contains(constraintDefinitions, required) {
				t.Fatalf("encrypted staging constraints lack %q: %s", required, constraintDefinitions)
			}
		}
	})
}

func assertPermanentRotationPreparedEnvelope(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	rotation preparedRotationPostgresFixture,
) {
	t.Helper()
	t.Run("EncryptedPreparedCredentialRow", func(t *testing.T) {
		var version int
		var keyID string
		var nonce, ciphertext, wrappedDEK, wrapNonce []byte
		var expiresInFuture bool
		err := db.QueryRowContext(ctx, "SELECT prepared_credential_envelope_version, prepared_credential_key_id, "+
			"prepared_credential_nonce, prepared_credential_ciphertext, prepared_credential_wrapped_dek, "+
			"prepared_credential_wrap_nonce, prepared_credential_expires_at > NOW() "+
			"FROM trusted_pool_permanent_rotation_seats "+
			"WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3",
			rotation.clientID, rotation.prepareOperationID, rotation.externalSeat).
			Scan(&version, &keyID, &nonce, &ciphertext, &wrappedDEK, &wrapNonce, &expiresInFuture)
		if err != nil {
			t.Fatalf("read encrypted prepared credential row: %v", err)
		}
		if version != 1 || strings.TrimSpace(keyID) == "" || len(nonce) != 12 || len(wrapNonce) != 12 ||
			len(ciphertext) < 16 || len(wrappedDEK) != 48 || !expiresInFuture {
			t.Fatalf("invalid prepared envelope metadata: version=%d key_id=%q nonce=%d ciphertext=%d wrapped_dek=%d wrap_nonce=%d future=%t",
				version, keyID, len(nonce), len(ciphertext), len(wrappedDEK), len(wrapNonce), expiresInFuture)
		}
		plaintext := []byte(rotation.credential)
		if bytes.Contains(ciphertext, plaintext) || bytes.Contains(wrappedDEK, plaintext) {
			t.Fatal("prepared credential plaintext is present in persisted envelope bytes")
		}
		if bytes.Equal(nonce, wrapNonce) {
			t.Fatal("data and DEK wrapping nonces must be generated independently")
		}
	})
}

func assertPermanentRotationPreparedEnvelopeCleared(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	rotation preparedRotationPostgresFixture,
) {
	t.Helper()
	t.Run("EncryptedPreparedCredentialClearedOnActivate", func(t *testing.T) {
		var cleared bool
		err := db.QueryRowContext(ctx, "SELECT "+
			"prepared_credential_envelope_version IS NULL AND prepared_credential_key_id IS NULL AND "+
			"prepared_credential_nonce IS NULL AND prepared_credential_ciphertext IS NULL AND "+
			"prepared_credential_wrapped_dek IS NULL AND prepared_credential_wrap_nonce IS NULL AND "+
			"prepared_credential_expires_at IS NULL "+
			"FROM trusted_pool_permanent_rotation_seats "+
			"WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3",
			rotation.clientID, rotation.prepareOperationID, rotation.externalSeat).Scan(&cleared)
		if err != nil {
			t.Fatalf("inspect activated prepared credential envelope: %v", err)
		}
		if !cleared {
			t.Fatal("activate retained decryptable prepared credential envelope material")
		}
	})
}

func assertPermanentRotationEncryptedStagingReplay(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	rotation preparedRotationPostgresFixture,
) {
	t.Helper()
	t.Run("EncryptedPreparedCredentialReplay", func(t *testing.T) {
		repo := newPermanentRotationPostgresRepository(t, db)
		for _, transactionOutcome := range []struct {
			name   string
			commit bool
		}{
			{name: "Rollback"},
			{name: "Commit", commit: true},
		} {
			t.Run(transactionOutcome.name, func(t *testing.T) {
				tx := beginPermanentRotationPostgresTx(t, ctx, db)
				result, found, err := repo.loadPermanentPrepareResult(
					ctx, tx, rotation.clientID, rotation.prepareOperationID, true,
				)
				if err != nil || !found {
					_ = tx.Rollback()
					t.Fatalf("load encrypted prepared credential replay: found=%v err=%v", found, err)
				}
				if result.OperationID != rotation.prepareOperationID ||
					result.ProtocolVersion != service.TrustedPoolPermanentRotationProtocolV1 ||
					result.ExternalPoolID != rotation.externalPool || result.PlanID != rotation.planID ||
					result.CeremonyType != "ROTATE" || result.FromEpoch != 1 || result.ToEpoch != 2 ||
					result.RequestHash != rotation.requestHash || result.ChildSetHash != rotation.childSetHash ||
					result.PreparedSetHash != rotation.preparedSetHash || result.Status != "prepared" ||
					!result.CredentialsDisclosed || result.PreparedAt.IsZero() {
					_ = tx.Rollback()
					t.Fatalf("encrypted prepared credential replay metadata changed: %+v", result)
				}
				if len(result.Seats) != 1 {
					_ = tx.Rollback()
					t.Fatalf("encrypted prepared credential replay seats=%d want=1", len(result.Seats))
				}
				seat := result.Seats[0]
				if seat.ExternalSeatID != rotation.externalSeat || seat.TargetMemberID != rotation.targetMemberID ||
					seat.ExpectedAssignmentEpoch != 1 || seat.PrincipalUserID != rotation.principalID ||
					seat.GroupID != rotation.groupID || seat.SubscriptionID != rotation.subscriptionID ||
					seat.APIKeyID != rotation.apiKeyID || seat.FromAPIKeyVersion != 1 || seat.ToAPIKeyVersion != 2 ||
					seat.ChildOperationID != rotation.childOperationID || seat.ChildRequestHash != rotation.childRequestHash ||
					seat.Credential != rotation.credential || seat.CredentialFingerprint != rotation.credentialFingerprint ||
					seat.PreparedRotationRef != rotation.preparedRotationRef || seat.State != "ROTATION_PREPARED" ||
					seat.ActiveAPIKeyVersion != 2 || !seat.CredentialRotationComplete ||
					seat.CredentialEnabled || seat.SubscriptionEnabled || !seat.CompletedAt.Equal(result.PreparedAt) {
					_ = tx.Rollback()
					t.Fatalf("encrypted prepared credential replay seat changed: %+v", seat)
				}
				if transactionOutcome.commit {
					if err := tx.Commit(); err != nil {
						t.Fatalf("commit encrypted prepared credential replay read: %v", err)
					}
					return
				}
				if err := tx.Rollback(); err != nil {
					t.Fatalf("rollback encrypted prepared credential replay read: %v", err)
				}
			})
		}
	})
}

type permanentRotationPostgresFixture struct {
	clientID       string
	externalPool   string
	externalSeat   string
	seatID         int64
	principalID    int64
	groupID        int64
	subscriptionID int64
	apiKeyID       int64
}

type preparedRotationPostgresFixture struct {
	permanentRotationPostgresFixture
	prepareOperationID    string
	planID                string
	childOperationID      string
	targetMemberID        string
	preparedRotationRef   string
	credential            string
	credentialFingerprint string
	childRequestHash      string
	childSetHash          string
	preparedSetHash       string
	requestHash           string
	credentialEnvelope    permanentCredentialEnvelope
}

func seedPermanentRotationPostgresFixture(t *testing.T, ctx context.Context, db *sql.DB) permanentRotationPostgresFixture {
	t.Helper()
	fixture := permanentRotationPostgresFixture{
		clientID:     "permanent-rotate-only",
		externalPool: "pool-only",
		externalSeat: "seat-only",
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin permanent rotation fixture: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, `INSERT INTO groups (name) VALUES ('permanent-rotation-pg') RETURNING id`).Scan(&fixture.groupID); err != nil {
		t.Fatalf("insert fixture group: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO users (
email, password_hash, principal_type
) VALUES ('permanent-rotation-pg@example.invalid', 'not-a-real-password', 'trusted_pool_seat') RETURNING id`).Scan(&fixture.principalID); err != nil {
		t.Fatalf("insert fixture principal: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO user_subscriptions (
user_id, group_id, starts_at, expires_at, status
) VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 day', 'suspended') RETURNING id`, fixture.principalID, fixture.groupID).Scan(&fixture.subscriptionID); err != nil {
		t.Fatalf("insert fixture subscription: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO api_keys (
user_id, key, name, group_id, status
) VALUES ($1, 'sk-permanent-rotation-old', 'permanent rotation pg', $2, 'disabled') RETURNING id`, fixture.principalID, fixture.groupID).Scan(&fixture.apiKeyID); err != nil {
		t.Fatalf("insert fixture api key: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO trusted_pool_groups (external_pool_id, group_id) VALUES ($1, $2)`, fixture.externalPool, fixture.groupID); err != nil {
		t.Fatalf("insert fixture pool binding: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO trusted_pool_seats (
external_pool_id, external_seat_id, principal_user_id, group_id, subscription_id, api_key_id,
state, assignment_epoch, last_operation_id
) VALUES ($1, $2, $3, $4, $5, $6, 'frozen', 1, 'fixture-freeze') RETURNING id`, fixture.externalPool, fixture.externalSeat,
		fixture.principalID, fixture.groupID, fixture.subscriptionID, fixture.apiKeyID).Scan(&fixture.seatID); err != nil {
		t.Fatalf("insert fixture seat: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit permanent rotation fixture: %v", err)
	}
	return fixture
}

func assertPermanentRotationDirectDMLGuards(t *testing.T, ctx context.Context, db *sql.DB, fixture permanentRotationPostgresFixture) {
	t.Helper()

	t.Run("incomplete parent is rejected at commit", func(t *testing.T) {
		rotation := newPreparedRotationPostgresFixture(t, fixture, "prepare-incomplete", "plan-incomplete", "child-incomplete")
		tx := beginPermanentRotationPostgresTx(t, ctx, db)
		insertPermanentRotationParent(t, ctx, tx, rotation)
		assertPermanentRotationCommitCode(t, tx, "23514")
		assertPermanentRotationAbsent(t, ctx, db, rotation.prepareOperationID)
	})

	t.Run("forged set hash is rejected at commit", func(t *testing.T) {
		rotation := newPreparedRotationPostgresFixture(t, fixture, "prepare-forged", "plan-forged", "child-forged")
		rotation.childSetHash = strings.Repeat("0", 64)
		rotation.requestHash = permanentRotationPrepareHash(rotation)
		tx := beginPermanentRotationPostgresTx(t, ctx, db)
		insertPermanentRotationParent(t, ctx, tx, rotation)
		insertPermanentRotationChild(t, ctx, tx, rotation)
		setPermanentRotationSeatPrepared(t, ctx, tx, rotation)
		assertPermanentRotationCommitCode(t, tx, "23514")
		assertPermanentRotationAbsent(t, ctx, db, rotation.prepareOperationID)
		assertPermanentRotationSeatState(t, ctx, db, fixture.seatID, "frozen")
	})

	t.Run("prepared credential ciphertext is append only", func(t *testing.T) {
		rotation := newPreparedRotationPostgresFixture(t, fixture, "prepare-ciphertext-tamper", "plan-ciphertext-tamper", "child-ciphertext-tamper")
		tx := beginPermanentRotationPostgresTx(t, ctx, db)
		insertPermanentRotationParent(t, ctx, tx, rotation)
		insertPermanentRotationChild(t, ctx, tx, rotation)
		setPermanentRotationSeatPrepared(t, ctx, tx, rotation)
		_, err := tx.ExecContext(ctx, `UPDATE trusted_pool_permanent_rotation_seats
		SET prepared_credential_ciphertext=prepared_credential_ciphertext || decode('00', 'hex')
		WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3`,
			rotation.clientID, rotation.prepareOperationID, rotation.externalSeat)
		assertPostgresCode(t, err, "55000")
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Fatalf("rollback rejected prepared credential ciphertext tamper: %v", err)
		}
		assertPermanentRotationAbsent(t, ctx, db, rotation.prepareOperationID)
		assertPermanentRotationSeatState(t, ctx, db, fixture.seatID, "frozen")
	})
}

func assertPermanentRotationTwoConnectionWinner(t *testing.T, ctx context.Context, db *sql.DB, fixture permanentRotationPostgresFixture) preparedRotationPostgresFixture {
	t.Helper()
	winner := newPreparedRotationPostgresFixture(t, fixture, "prepare-winner", "plan-winner", "child-winner")
	loser := newPreparedRotationPostgresFixture(t, fixture, "prepare-loser", "plan-loser", "child-loser")

	winnerTx := beginPermanentRotationPostgresTx(t, ctx, db)
	insertPermanentRotationParent(t, ctx, winnerTx, winner)
	insertPermanentRotationChild(t, ctx, winnerTx, winner)
	setPermanentRotationSeatPrepared(t, ctx, winnerTx, winner)

	loserTx := beginPermanentRotationPostgresTx(t, ctx, db)
	defer func() { _ = loserTx.Rollback() }()
	insertPermanentRotationParent(t, ctx, loserTx, loser)
	var loserPID int
	if err := loserTx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&loserPID); err != nil {
		t.Fatalf("read losing connection pid: %v", err)
	}
	loserResult := make(chan error, 1)
	go func() {
		_, err := loserTx.ExecContext(ctx, permanentRotationChildInsertSQL,
			loser.clientID, loser.prepareOperationID, loser.externalSeat, loser.targetMemberID, loser.seatID,
			loser.principalID, loser.groupID, loser.subscriptionID, loser.apiKeyID, loser.childOperationID,
			loser.childRequestHash, loser.credentialFingerprint, loser.preparedRotationRef,
			loser.credentialEnvelope.Version, loser.credentialEnvelope.KeyID, loser.credentialEnvelope.WrapNonce,
			loser.credentialEnvelope.WrappedDEK, loser.credentialEnvelope.DataNonce,
			loser.credentialEnvelope.Ciphertext, loser.credentialEnvelope.ExpiresAt)
		loserResult <- err
	}()
	waitForPermanentRotationLock(t, ctx, db, loserPID)
	if err := winnerTx.Commit(); err != nil {
		t.Fatalf("commit winning permanent rotation: %v", err)
	}
	loserErr := <-loserResult
	assertPostgresCode(t, loserErr, "23505")
	if err := loserTx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("rollback losing permanent rotation: %v", err)
	}

	var winnerCount, loserCount int
	if err := db.QueryRowContext(ctx, `SELECT
		COUNT(*) FILTER (WHERE prepare_operation_id=$2),
		COUNT(*) FILTER (WHERE prepare_operation_id=$3)
		FROM trusted_pool_permanent_rotations WHERE client_id=$1`, fixture.clientID,
		winner.prepareOperationID, loser.prepareOperationID).Scan(&winnerCount, &loserCount); err != nil {
		t.Fatalf("read competing permanent rotations: %v", err)
	}
	if winnerCount != 1 || loserCount != 0 {
		t.Fatalf("expected one permanent rotation winner, winner=%d loser=%d", winnerCount, loserCount)
	}

	t.Run("parent cannot skip activation", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `UPDATE trusted_pool_permanent_rotations SET
		status='committed', activation_operation_id='forged-activation', activation_request_hash=$3, activated_at=NOW(),
		commit_operation_id='forged-commit', commit_request_hash=$3, committed_at=NOW()
		WHERE client_id=$1 AND prepare_operation_id=$2`, fixture.clientID, winner.prepareOperationID, strings.Repeat("a", 64))
		assertPostgresCode(t, err, "55000")
	})

	t.Run("child cannot activate independently", func(t *testing.T) {
		tx := beginPermanentRotationPostgresTx(t, ctx, db)
		if _, err := tx.ExecContext(ctx, `UPDATE trusted_pool_permanent_rotation_seats
		SET prepared_credential_envelope_version=NULL, prepared_credential_key_id=NULL,
		    prepared_credential_wrap_nonce=NULL, prepared_credential_wrapped_dek=NULL,
		    prepared_credential_nonce=NULL, prepared_credential_ciphertext=NULL,
		    prepared_credential_expires_at=NULL, activated_at=NOW()
		WHERE client_id=$1 AND prepare_operation_id=$2 AND external_seat_id=$3`, fixture.clientID, winner.prepareOperationID, fixture.externalSeat); err != nil {
			t.Fatalf("stage child-only activation: %v", err)
		}
		assertPermanentRotationCommitCode(t, tx, "23514")
	})

	t.Run("parent and child evidence are append only", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `DELETE FROM trusted_pool_permanent_rotation_seats
		WHERE client_id=$1 AND prepare_operation_id=$2`, fixture.clientID, winner.prepareOperationID)
		assertPostgresCode(t, err, "55000")
		_, err = db.ExecContext(ctx, `UPDATE trusted_pool_permanent_rotation_seats SET target_member_id='tampered'
		WHERE client_id=$1 AND prepare_operation_id=$2`, fixture.clientID, winner.prepareOperationID)
		assertPostgresCode(t, err, "55000")
		_, err = db.ExecContext(ctx, `DELETE FROM trusted_pool_permanent_rotations
		WHERE client_id=$1 AND prepare_operation_id=$2`, fixture.clientID, winner.prepareOperationID)
		assertPostgresCode(t, err, "55000")
	})

	assertPermanentRotationSeatState(t, ctx, db, fixture.seatID, "rotation_prepared")
	return winner
}

func assertPermanentRotationCommitReceiptRecovery(t *testing.T, ctx context.Context, db *sql.DB, rotation preparedRotationPostgresFixture) {
	t.Helper()
	repo := newPermanentRotationPostgresRepository(t, db)
	seat := service.ActivateTrustedPoolPermanentRotationSeat{
		ExternalSeatID: rotation.externalSeat, TargetMemberID: rotation.targetMemberID,
		ExpectedAssignmentEpoch: 1, PrincipalUserID: rotation.principalID,
		SubscriptionID: rotation.subscriptionID, APIKeyID: rotation.apiKeyID, ActiveAPIKeyVersion: 2,
		ChildOperationID: rotation.childOperationID, ChildRequestHash: rotation.childRequestHash,
		CredentialFingerprint: rotation.credentialFingerprint, PreparedRotationRef: rotation.preparedRotationRef,
	}
	activation := service.ActivateTrustedPoolPermanentRotationInput{
		ProtocolVersion: service.TrustedPoolPermanentRotationProtocolV1,
		OperationID:     "activate-receipt", PrepareOperationID: rotation.prepareOperationID,
		ExternalPoolID: rotation.externalPool, PlanID: rotation.planID, CeremonyType: "ROTATE",
		FromEpoch: 1, ToEpoch: 2, PreparedSetHash: rotation.preparedSetHash,
		Seats: []service.ActivateTrustedPoolPermanentRotationSeat{seat}, ActorClientID: rotation.clientID,
		ConcurrencyVerified: true,
	}
	activation.RequestHash = permanentRotationActivationHash(activation)
	activated, err := repo.ActivatePermanentRotation(ctx, activation)
	if err != nil {
		t.Fatalf("activate permanent rotation for receipt recovery: %v", err)
	}
	if activated.Status != "activated_pending_commit" {
		t.Fatalf("activated status=%s", activated.Status)
	}
	assertPermanentRotationPreparedEnvelopeCleared(t, ctx, db, rotation)

	commit := service.CommitTrustedPoolPermanentRotationInput{
		ProtocolVersion: service.TrustedPoolPermanentRotationProtocolV1,
		OperationID:     "commit-receipt", PrepareOperationID: rotation.prepareOperationID,
		ActivationOperationID: activation.OperationID, ActivationRequestHash: activation.RequestHash,
		ExternalPoolID: rotation.externalPool, PlanID: rotation.planID, CeremonyType: "ROTATE",
		FromEpoch: 1, ToEpoch: 2, PreparedSetHash: rotation.preparedSetHash,
		Seats: []service.ActivateTrustedPoolPermanentRotationSeat{seat}, ActorClientID: rotation.clientID,
		ConcurrencyVerified: true,
	}
	commit.RequestHash = permanentRotationCommitHash(commit)
	committed, err := repo.CommitPermanentRotation(ctx, commit)
	if err != nil {
		t.Fatalf("commit permanent rotation for receipt recovery: %v", err)
	}
	if committed.Status != "committed" || committed.ObservedAt.IsZero() {
		t.Fatalf("invalid initial commit receipt: status=%s observed_at=%s", committed.Status, committed.ObservedAt)
	}

	if _, err := repo.SuspendSeat(ctx, rotation.externalPool, rotation.externalSeat, "suspend-after-lost-commit"); err != nil {
		t.Fatalf("suspend committed permanent rotation seat: %v", err)
	}
	var parentStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM trusted_pool_permanent_rotations
		WHERE client_id=$1 AND prepare_operation_id=$2`, rotation.clientID, rotation.prepareOperationID).Scan(&parentStatus); err != nil {
		t.Fatalf("read retiring parent: %v", err)
	}
	if parentStatus != "retiring" {
		t.Fatalf("parent status=%s want retiring", parentStatus)
	}

	replayed, found, err := repo.TryReplayPermanentRotationCommit(ctx, commit)
	if err != nil || !found {
		t.Fatalf("replay retiring commit receipt: found=%v err=%v", found, err)
	}
	if replayed.OperationID != committed.OperationID || replayed.RequestHash != committed.RequestHash || !replayed.ObservedAt.Equal(committed.ObservedAt) {
		t.Fatalf("replayed receipt changed: got=%+v initial=%+v", replayed, committed)
	}
	commit.ConcurrencyVerified = false
	if _, err := repo.CommitPermanentRotation(ctx, commit); err != nil {
		t.Fatalf("commit race fallback did not replay retiring receipt: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE api_keys SET key='sk-drifted-after-commit', updated_at=NOW() WHERE id=$1`, rotation.apiKeyID); err != nil {
		t.Fatalf("drift committed credential: %v", err)
	}
	_, found, err = repo.TryReplayPermanentRotationCommit(ctx, commit)
	if !found || !errors.Is(err, service.ErrTrustedPoolPermanentCommitReceiptUnavailable) {
		t.Fatalf("credential drift replay: found=%v err=%v", found, err)
	}
}

func newPreparedRotationPostgresFixture(t *testing.T, base permanentRotationPostgresFixture, prepareOperationID, planID, childOperationID string) preparedRotationPostgresFixture {
	t.Helper()
	rotation := preparedRotationPostgresFixture{
		permanentRotationPostgresFixture: base,
		prepareOperationID:               prepareOperationID,
		planID:                           planID,
		childOperationID:                 childOperationID,
		targetMemberID:                   "member-next",
		preparedRotationRef:              "prepared-ref-" + prepareOperationID,
		credential:                       "sk-new-" + prepareOperationID,
	}
	rotation.credentialFingerprint = permanentRotationSHA256([]byte(rotation.credential))
	rotation.childRequestHash = permanentRotationChildRequestHash(rotation)
	rotation.childSetHash = permanentRotationChildSetHash(rotation)
	rotation.preparedSetHash = permanentRotationPreparedSetHash(rotation)
	rotation.requestHash = permanentRotationPrepareHash(rotation)
	sealer := newPermanentRotationPostgresSealer(t)
	envelope, err := sealer.Seal(context.Background(), rotation.credential, permanentRotationPostgresCredentialScope(rotation), time.Now().UTC().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("seal permanent rotation PostgreSQL fixture: %v", err)
	}
	rotation.credentialEnvelope = envelope
	return rotation
}

func beginPermanentRotationPostgresTx(t *testing.T, ctx context.Context, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin permanent rotation transaction: %v", err)
	}
	return tx
}

func insertPermanentRotationParent(t *testing.T, ctx context.Context, tx *sql.Tx, rotation preparedRotationPostgresFixture) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `INSERT INTO trusted_pool_permanent_rotations (
	client_id, prepare_operation_id, protocol_version, external_pool_id, plan_id, ceremony_type,
	from_epoch, to_epoch, request_hash, child_set_hash, prepared_set_hash, seat_count
) VALUES ($1, $2, 'trusted-pool/permanent-seat-rotation/v1', $3, $4, 'ROTATE', 1, 2, $5, $6, $7, 1)`,
		rotation.clientID, rotation.prepareOperationID, rotation.externalPool, rotation.planID,
		rotation.requestHash, rotation.childSetHash, rotation.preparedSetHash); err != nil {
		t.Fatalf("insert permanent rotation parent: %v", err)
	}
}

const permanentRotationChildInsertSQL = `INSERT INTO trusted_pool_permanent_rotation_seats (
	client_id, prepare_operation_id, external_seat_id, target_member_id, seat_id, principal_user_id,
	group_id, subscription_id, api_key_id, from_epoch, to_epoch, expected_assignment_epoch,
	target_assignment_epoch, from_api_key_version, to_api_key_version, child_operation_id,
	child_request_hash, credential_fingerprint, prepared_rotation_ref,
	prepared_credential_envelope_version, prepared_credential_key_id, prepared_credential_wrap_nonce,
	prepared_credential_wrapped_dek, prepared_credential_nonce, prepared_credential_ciphertext,
	prepared_credential_expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 2, 1, 2, 1, 2, $10, $11, $12, $13, $14,
	$15, $16, $17, $18, $19, $20)`

func insertPermanentRotationChild(t *testing.T, ctx context.Context, tx *sql.Tx, rotation preparedRotationPostgresFixture) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, permanentRotationChildInsertSQL,
		rotation.clientID, rotation.prepareOperationID, rotation.externalSeat, rotation.targetMemberID, rotation.seatID,
		rotation.principalID, rotation.groupID, rotation.subscriptionID, rotation.apiKeyID, rotation.childOperationID,
		rotation.childRequestHash, rotation.credentialFingerprint, rotation.preparedRotationRef,
		rotation.credentialEnvelope.Version, rotation.credentialEnvelope.KeyID, rotation.credentialEnvelope.WrapNonce,
		rotation.credentialEnvelope.WrappedDEK, rotation.credentialEnvelope.DataNonce,
		rotation.credentialEnvelope.Ciphertext, rotation.credentialEnvelope.ExpiresAt); err != nil {
		t.Fatalf("insert permanent rotation child: %v", err)
	}
}

func newPermanentRotationPostgresSealer(t *testing.T) *permanentCredentialEnvelopeSealer {
	t.Helper()
	provider, err := newLocalPermanentRotationKEKProvider("postgres-fixture-kek-v1", bytes.Repeat([]byte{0x7c}, 32))
	if err != nil {
		t.Fatalf("create PostgreSQL fixture KEK: %v", err)
	}
	sealer, err := newPermanentCredentialEnvelopeSealer(provider)
	if err != nil {
		t.Fatalf("create PostgreSQL fixture sealer: %v", err)
	}
	return sealer
}

func newPermanentRotationPostgresRepository(t *testing.T, db *sql.DB) *trustedPoolRepository {
	t.Helper()
	return &trustedPoolRepository{
		db: db, permanentCredentialSealer: newPermanentRotationPostgresSealer(t),
		permanentCredentialTTL: 15 * time.Minute, now: time.Now,
	}
}

func permanentRotationPostgresCredentialScope(rotation preparedRotationPostgresFixture) permanentCredentialScope {
	return permanentCredentialScope{
		ClientID: rotation.clientID, PrepareOperationID: rotation.prepareOperationID,
		ProtocolVersion: service.TrustedPoolPermanentRotationProtocolV1, ExternalPoolID: rotation.externalPool,
		PlanID: rotation.planID, CeremonyType: "ROTATE", FromEpoch: 1, ToEpoch: 2,
		RequestHash: rotation.requestHash, ChildSetHash: rotation.childSetHash, PreparedSetHash: rotation.preparedSetHash,
		ExternalSeatID: rotation.externalSeat, TargetMemberID: rotation.targetMemberID, SeatID: rotation.seatID,
		PrincipalUserID: rotation.principalID, GroupID: rotation.groupID, SubscriptionID: rotation.subscriptionID,
		APIKeyID: rotation.apiKeyID, ExpectedAssignmentEpoch: 1, TargetAssignmentEpoch: 2,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2, ChildOperationID: rotation.childOperationID,
		ChildRequestHash: rotation.childRequestHash, CredentialFingerprint: rotation.credentialFingerprint,
		PreparedRotationRef: rotation.preparedRotationRef,
	}
}

func setPermanentRotationSeatPrepared(t *testing.T, ctx context.Context, tx *sql.Tx, rotation preparedRotationPostgresFixture) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `UPDATE trusted_pool_seats SET state='rotation_prepared', last_operation_id=$2
	WHERE id=$1`, rotation.seatID, rotation.childOperationID); err != nil {
		t.Fatalf("set permanent rotation seat prepared: %v", err)
	}
}

func assertPermanentRotationCommitCode(t *testing.T, tx *sql.Tx, wantCode pq.ErrorCode) {
	t.Helper()
	assertPostgresCode(t, tx.Commit(), wantCode)
}

func assertPostgresCode(t *testing.T, err error, wantCode pq.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PostgreSQL error %s", wantCode)
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != wantCode {
		t.Fatalf("expected PostgreSQL error %s, got %v", wantCode, err)
	}
}

func assertPermanentRotationAbsent(t *testing.T, ctx context.Context, db *sql.DB, prepareOperationID string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_pool_permanent_rotations
	WHERE prepare_operation_id=$1`, prepareOperationID).Scan(&count); err != nil {
		t.Fatalf("read rejected permanent rotation: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected permanent rotation %s was persisted", prepareOperationID)
	}
}

func assertPermanentRotationSeatState(t *testing.T, ctx context.Context, db *sql.DB, seatID int64, want string) {
	t.Helper()
	var got string
	if err := db.QueryRowContext(ctx, `SELECT state FROM trusted_pool_seats WHERE id=$1`, seatID).Scan(&got); err != nil {
		t.Fatalf("read permanent rotation seat state: %v", err)
	}
	if got != want {
		t.Fatalf("permanent rotation seat state=%s want=%s", got, want)
	}
}

func waitForPermanentRotationLock(t *testing.T, ctx context.Context, db *sql.DB, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(wait_event_type='Lock', FALSE)
		FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatalf("inspect losing connection lock: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("losing permanent rotation did not wait on the winner's seat lock")
}

func permanentRotationChildRequestHash(rotation preparedRotationPostgresFixture) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-seat-rotation/v1")
		permanentRotationWriteText(encoded, rotation.childOperationID)
		permanentRotationWriteText(encoded, rotation.planID)
		permanentRotationWriteText(encoded, "ROTATE")
		permanentRotationWriteText(encoded, rotation.externalPool)
		permanentRotationWriteUint64(encoded, 1)
		permanentRotationWriteUint64(encoded, 2)
		permanentRotationWriteText(encoded, rotation.externalSeat)
		permanentRotationWriteText(encoded, rotation.targetMemberID)
		permanentRotationWriteUint64(encoded, 1)
		permanentRotationWriteUint64(encoded, uint64(rotation.principalID))
		permanentRotationWriteUint64(encoded, uint64(rotation.subscriptionID))
		permanentRotationWriteUint64(encoded, uint64(rotation.apiKeyID))
		permanentRotationWriteUint64(encoded, 1)
		permanentRotationWriteUint64(encoded, 2)
	})
}

func permanentRotationChildSetHash(rotation preparedRotationPostgresFixture) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-rotation-child-set/v1")
		permanentRotationWriteUint32(encoded, 1)
		permanentRotationWriteText(encoded, rotation.externalSeat)
		permanentRotationWriteText(encoded, rotation.childOperationID)
		permanentRotationWriteHex(encoded, rotation.childRequestHash)
	})
}

func permanentRotationPreparedSetHash(rotation preparedRotationPostgresFixture) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-prepared-seat-set/v1")
		permanentRotationWriteUint32(encoded, 1)
		permanentRotationWriteText(encoded, rotation.externalSeat)
		permanentRotationWriteText(encoded, rotation.targetMemberID)
		permanentRotationWriteUint64(encoded, 1)
		permanentRotationWriteUint64(encoded, uint64(rotation.principalID))
		permanentRotationWriteUint64(encoded, uint64(rotation.subscriptionID))
		permanentRotationWriteUint64(encoded, uint64(rotation.apiKeyID))
		permanentRotationWriteUint64(encoded, 2)
		permanentRotationWriteHex(encoded, rotation.credentialFingerprint)
		permanentRotationWriteText(encoded, rotation.preparedRotationRef)
		permanentRotationWriteText(encoded, rotation.childOperationID)
		permanentRotationWriteHex(encoded, rotation.childRequestHash)
	})
}

func permanentRotationPrepareHash(rotation preparedRotationPostgresFixture) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-pool-rotation-prepare/v1")
		permanentRotationWriteText(encoded, rotation.prepareOperationID)
		permanentRotationWriteText(encoded, rotation.planID)
		permanentRotationWriteText(encoded, "ROTATE")
		permanentRotationWriteText(encoded, rotation.externalPool)
		permanentRotationWriteUint64(encoded, 1)
		permanentRotationWriteUint64(encoded, 2)
		permanentRotationWriteHex(encoded, rotation.childSetHash)
	})
}

func permanentRotationActivationHash(input service.ActivateTrustedPoolPermanentRotationInput) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-pool-rotation-activate/v1")
		permanentRotationWriteText(encoded, input.OperationID)
		permanentRotationWriteText(encoded, input.PrepareOperationID)
		permanentRotationWriteText(encoded, input.PlanID)
		permanentRotationWriteText(encoded, input.CeremonyType)
		permanentRotationWriteText(encoded, input.ExternalPoolID)
		permanentRotationWriteUint64(encoded, uint64(input.FromEpoch))
		permanentRotationWriteUint64(encoded, uint64(input.ToEpoch))
		permanentRotationWriteHex(encoded, input.PreparedSetHash)
	})
}

func permanentRotationCommitHash(input service.CommitTrustedPoolPermanentRotationInput) string {
	return permanentRotationFramedHash(func(encoded *bytes.Buffer) {
		permanentRotationWriteText(encoded, "trusted-pool/permanent-pool-rotation-commit/v1")
		permanentRotationWriteText(encoded, input.OperationID)
		permanentRotationWriteText(encoded, input.PrepareOperationID)
		permanentRotationWriteText(encoded, input.ActivationOperationID)
		permanentRotationWriteHex(encoded, input.ActivationRequestHash)
		permanentRotationWriteText(encoded, input.PlanID)
		permanentRotationWriteText(encoded, input.CeremonyType)
		permanentRotationWriteText(encoded, input.ExternalPoolID)
		permanentRotationWriteUint64(encoded, uint64(input.FromEpoch))
		permanentRotationWriteUint64(encoded, uint64(input.ToEpoch))
		permanentRotationWriteHex(encoded, input.PreparedSetHash)
	})
}

func permanentRotationFramedHash(write func(*bytes.Buffer)) string {
	var encoded bytes.Buffer
	write(&encoded)
	return permanentRotationSHA256(encoded.Bytes())
}

func permanentRotationSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func permanentRotationWriteText(encoded *bytes.Buffer, value string) {
	permanentRotationWriteUint32(encoded, uint32(len([]byte(value))))
	_, _ = encoded.WriteString(value)
}

func permanentRotationWriteUint32(encoded *bytes.Buffer, value uint32) {
	var framed [4]byte
	binary.BigEndian.PutUint32(framed[:], value)
	_, _ = encoded.Write(framed[:])
}

func permanentRotationWriteUint64(encoded *bytes.Buffer, value uint64) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], value)
	_, _ = encoded.Write(framed[:])
}

func permanentRotationWriteHex(encoded *bytes.Buffer, value string) {
	decoded, _ := hex.DecodeString(value)
	_, _ = encoded.Write(decoded)
}

func migrationFilesBefore(t *testing.T, exclusiveName string) fstest.MapFS {
	t.Helper()
	names, err := fs.Glob(migrationfiles.FS, "*.sql")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	result := make(fstest.MapFS)
	for _, name := range names {
		if name >= exclusiveName {
			continue
		}
		data, err := fs.ReadFile(migrationfiles.FS, name)
		if err != nil {
			t.Fatalf("read embedded migration %s: %v", name, err)
		}
		result[name] = &fstest.MapFile{Data: data}
	}
	if len(result) == 0 {
		t.Fatal("no migrations found before permanent rotation")
	}
	return result
}
