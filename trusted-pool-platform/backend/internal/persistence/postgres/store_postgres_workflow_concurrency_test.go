package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"

	_ "github.com/lib/pq"
)

// PHASE2H_TEST_POSTGRES_DSN must reference a disposable database where the
// caller can create and remove schemas.
func TestCredentialClaimFenceOnTwoRealPostgresConnections(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_claim_fence_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create claim fence schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	workerA := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerA.Close()
	if err := Migrate(ctx, workerA, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for credential claim fence test: %v", err)
	}
	workerB := openWorkflowPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerB.Close()
	assertDifferentWorkflowBackends(t, ctx, workerA, workerB)

	insertCredentialClaimFenceFixture(t, ctx, workerA)
	storeA, err := NewStore(workerA)
	if err != nil {
		t.Fatalf("create worker A Store: %v", err)
	}
	storeB, err := NewStore(workerB)
	if err != nil {
		t.Fatalf("create worker B Store: %v", err)
	}
	key := application.ClaimKey{ClientID: "claim-fence-client", OperationID: "claim-fence-operation"}

	first, err := storeA.AcquireCredentialClaimLease(ctx, application.AcquireCredentialClaimLeaseInput{
		Key: key, LeaseOwner: "claim-worker-a", LeaseDuration: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("acquire first credential claim lease: %v", err)
	}
	if _, err := storeB.AcquireCredentialClaimLease(ctx, application.AcquireCredentialClaimLeaseInput{
		Key: key, LeaseOwner: "claim-worker-b", LeaseDuration: time.Second,
	}); !errors.Is(err, application.ErrWorkflowLeaseHeld) {
		t.Fatalf("active credential claim lease was not exclusive: %v", err)
	}
	waitForCredentialClaimLeaseExpiry(t, ctx, workerA, key)

	type claimLeaseResult struct {
		owner string
		store *Store
		lease *application.CredentialClaimLease
		err   error
	}
	start := make(chan struct{})
	results := make(chan claimLeaseResult, 2)
	acquire := func(owner string, store *Store) {
		<-start
		lease, acquireErr := store.AcquireCredentialClaimLease(ctx, application.AcquireCredentialClaimLeaseInput{
			Key: key, LeaseOwner: owner, LeaseDuration: 10 * time.Second,
		})
		results <- claimLeaseResult{owner: owner, store: store, lease: lease, err: acquireErr}
	}
	go acquire("claim-worker-b", storeA)
	go acquire("claim-worker-c", storeB)
	close(start)
	resultOne, resultTwo := <-results, <-results

	var winner claimLeaseResult
	for _, result := range []claimLeaseResult{resultOne, resultTwo} {
		if result.err == nil {
			if winner.lease != nil {
				t.Fatal("both PostgreSQL workers acquired the same expired credential claim lease")
			}
			winner = result
			continue
		}
		if !errors.Is(result.err, application.ErrWorkflowLeaseHeld) {
			t.Fatalf("credential claim contender %s returned %v", result.owner, result.err)
		}
	}
	if winner.lease == nil {
		t.Fatal("neither PostgreSQL worker acquired the expired credential claim lease")
	}
	if winner.lease.FencingToken != first.FencingToken+1 {
		t.Fatalf("credential claim takeover fence=%d, want %d", winner.lease.FencingToken, first.FencingToken+1)
	}

	tokenHash := repeatedWorkflowDigest(0x03)
	if _, err := storeA.ClaimCredential(ctx, application.ClaimCredentialInput{
		Key: key, LeaseOwner: "claim-worker-a", FencingToken: first.FencingToken,
		TargetMemberExternalID: "claim-fence-member", TokenHash: tokenHash,
	}); !errors.Is(err, application.ErrWorkflowStaleFence) {
		t.Fatalf("old credential claim fence was not rejected: %v", err)
	}
	claimed, err := winner.store.ClaimCredential(ctx, application.ClaimCredentialInput{
		Key: key, LeaseOwner: winner.owner, FencingToken: winner.lease.FencingToken,
		TargetMemberExternalID: "claim-fence-member", TokenHash: tokenHash,
	})
	if err != nil {
		t.Fatalf("winning credential claim fence: %v", err)
	}
	if claimed.Status != application.CredentialClaimClaimed || claimed.FencingToken != winner.lease.FencingToken {
		t.Fatalf("unexpected claimed credential: %+v", claimed)
	}

	var status string
	var secretsCleared, leaseCleared, terminalRecorded bool
	if err := workerA.QueryRowContext(ctx, `SELECT status,
claim_token_hash IS NULL AND envelope_algorithm IS NULL AND envelope_key_ref IS NULL AND
envelope_ciphertext IS NULL AND envelope_nonce IS NULL AND envelope_aad_hash IS NULL AND
wrapped_dek_kms IS NULL,
lease_owner IS NULL AND lease_expires_at IS NULL,
claimed_at IS NOT NULL AND terminal_at IS NOT NULL
FROM credential_claims`).Scan(&status, &secretsCleared, &leaseCleared, &terminalRecorded); err != nil {
		t.Fatalf("inspect claimed credential cleanup: %v", err)
	}
	if status != "CLAIMED" || !secretsCleared || !leaseCleared || !terminalRecorded {
		t.Fatalf("claimed credential did not reach a cleared terminal state: status=%s secrets=%t lease=%t terminal=%t",
			status, secretsCleared, leaseCleared, terminalRecorded)
	}
}

func openWorkflowPostgresSchemaConnection(t *testing.T, ctx context.Context, dsn, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL workflow schema connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		_ = db.Close()
		t.Fatalf("select PostgreSQL workflow schema: %v", err)
	}
	return db
}

func assertDifferentWorkflowBackends(t *testing.T, ctx context.Context, workerA, workerB *sql.DB) {
	t.Helper()
	var pidA, pidB int
	if err := workerA.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidA); err != nil {
		t.Fatalf("read workflow worker A backend: %v", err)
	}
	if err := workerB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidB); err != nil {
		t.Fatalf("read workflow worker B backend: %v", err)
	}
	if pidA == pidB {
		t.Fatalf("expected two PostgreSQL connections, both used backend %d", pidA)
	}
}

func insertCredentialClaimFenceFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var memberID, poolID, seatID, operationID string
	if err := db.QueryRowContext(ctx, `INSERT INTO members (
external_id, sub2api_user_id, display_name, status
) VALUES ('claim-fence-member', 100001, 'Claim Fence Member', 'ACTIVE') RETURNING id`).Scan(&memberID); err != nil {
		t.Fatalf("insert credential claim member: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit
) VALUES ('claim-fence-pool', 'Claim Fence Pool', 'ACTIVE', 2) RETURNING id`).Scan(&poolID); err != nil {
		t.Fatalf("insert credential claim pool: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO seats (
external_id, pool_id, seat_no, status, assignment_epoch, active_api_key_version, owner_member_id,
sub2api_principal_id, sub2api_subscription_id, sub2api_api_key_id
) VALUES ('claim-fence-seat', $1, 1, 'ACTIVE', 1, 1, $2, 200001, 200002, 200003)
RETURNING id`, poolID, memberID).Scan(&seatID); err != nil {
		t.Fatalf("insert credential claim seat: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO seat_assignments (
seat_id, pool_id, member_id, assignment_type, status, assignment_epoch, starts_at
) VALUES ($1, $2, $3, 'PERMANENT', 'ACTIVE', 1, CURRENT_TIMESTAMP)`, seatID, poolID, memberID); err != nil {
		t.Fatalf("insert credential claim assignment: %v", err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, response_snapshot, completed_at
) VALUES ('claim-fence-client', 'claim-fence-operation', 'PROVISION', 'SEAT', $1,
          'claim-fence-seat', 'CURRENT', decode(repeat('01', 32), 'hex'),
          '{"test":"credential-claim-fence"}'::jsonb, 'SUCCEEDED', '{"applied":true}'::jsonb,
          CURRENT_TIMESTAMP) RETURNING id`, seatID).Scan(&operationID); err != nil {
		t.Fatalf("insert credential claim operation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO credential_claims (
integration_operation_id, seat_id, target_member_id, claim_operation_id, status,
claim_intent_hash, claim_token_hash, credential_fingerprint,
envelope_algorithm, envelope_key_ref, envelope_ciphertext, envelope_nonce,
envelope_aad_hash, wrapped_dek_kms, ack_response_snapshot, expires_at
) VALUES ($1, $2, $3, 'claim-fence-ack-operation', 'ACK_PENDING',
          decode(repeat('04', 32), 'hex'), decode(repeat('03', 32), 'hex'),
          decode(repeat('02', 32), 'hex'), 'AES-256-GCM', 'kms://claim-fence-test',
          decode('a1', 'hex'), decode('a2', 'hex'), decode(repeat('05', 32), 'hex'),
          decode('a3', 'hex'),
          jsonb_build_object(
            'external_seat_id', 'claim-fence-seat',
            'provision_operation_id', 'claim-fence-operation',
            'claim_operation_id', 'claim-fence-ack-operation',
            'claimed_by', 'claim-fence-member',
            'credential_fingerprint', repeat('02', 32),
            'credential_claimed', true,
            'claimed_at', CURRENT_TIMESTAMP
          ), CURRENT_TIMESTAMP + interval '10 minutes')`, operationID, seatID, memberID); err != nil {
		t.Fatalf("insert credential claim: %v", err)
	}
}

func waitForCredentialClaimLeaseExpiry(t *testing.T, ctx context.Context, db *sql.DB, key application.ClaimKey) {
	t.Helper()
	for {
		var expired bool
		err := db.QueryRowContext(ctx, `SELECT cc.lease_expires_at <= CURRENT_TIMESTAMP
FROM credential_claims cc
JOIN integration_operations operation ON operation.id = cc.integration_operation_id
WHERE operation.integration_client_id = $1 AND operation.operation_id = $2`,
			key.ClientID, key.OperationID).Scan(&expired)
		if err != nil {
			t.Fatalf("inspect credential claim lease expiry: %v", err)
		}
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for credential claim lease expiry: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func repeatedWorkflowDigest(value byte) [sha256.Size]byte {
	var digest [sha256.Size]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}
