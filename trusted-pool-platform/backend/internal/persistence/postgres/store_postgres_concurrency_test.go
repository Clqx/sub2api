package postgres

import (
	"context"
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
func TestOperationLeaseFenceOnTwoRealPostgresConnections(t *testing.T) {
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
	schema := fmt.Sprintf("phase2h_fence_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create fence schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	workerA := openPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerA.Close()
	if err := Migrate(ctx, workerA, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for fence test: %v", err)
	}
	workerB := openPostgresSchemaConnection(t, ctx, dsn, schema)
	defer workerB.Close()
	var pidA, pidB int
	if err := workerA.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidA); err != nil {
		t.Fatalf("read worker A backend: %v", err)
	}
	if err := workerB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidB); err != nil {
		t.Fatalf("read worker B backend: %v", err)
	}
	if pidA == pidB {
		t.Fatalf("expected two PostgreSQL connections, both used backend %d", pidA)
	}

	if _, err := workerA.ExecContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_external_id,
request_hash, request_snapshot, status
) VALUES ('fence-client', 'fence-operation', 'TEST_OPERATION', 'POOL', 'fence-pool',
          decode(repeat('01', 32), 'hex'), '{"test":"two-connection-fence"}'::jsonb, 'RUNNING')`); err != nil {
		t.Fatalf("insert fence operation: %v", err)
	}
	storeA, err := NewStore(workerA)
	if err != nil {
		t.Fatalf("create worker A Store: %v", err)
	}
	storeB, err := NewStore(workerB)
	if err != nil {
		t.Fatalf("create worker B Store: %v", err)
	}
	key := application.OperationKey{ClientID: "fence-client", OperationID: "fence-operation"}
	first, err := storeA.AcquireOperationLease(ctx, application.AcquireOperationLeaseInput{
		Key: key, LeaseOwner: "worker-a", LeaseDuration: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("acquire first lease: %v", err)
	}
	if _, err := storeB.AcquireOperationLease(ctx, application.AcquireOperationLeaseInput{
		Key: key, LeaseOwner: "worker-b", LeaseDuration: time.Second,
	}); !errors.Is(err, application.ErrWorkflowLeaseHeld) {
		t.Fatalf("active lease was not exclusive: %v", err)
	}
	waitForPostgresLeaseExpiry(t, ctx, workerA, key)

	type leaseResult struct {
		owner string
		store *Store
		lease *application.OperationLease
		err   error
	}
	start := make(chan struct{})
	results := make(chan leaseResult, 2)
	acquire := func(owner string, store *Store) {
		<-start
		lease, acquireErr := store.AcquireOperationLease(ctx, application.AcquireOperationLeaseInput{
			Key: key, LeaseOwner: owner, LeaseDuration: 10 * time.Second,
		})
		results <- leaseResult{owner: owner, store: store, lease: lease, err: acquireErr}
	}
	go acquire("worker-b", storeA)
	go acquire("worker-c", storeB)
	close(start)
	resultOne, resultTwo := <-results, <-results

	var winner leaseResult
	for _, result := range []leaseResult{resultOne, resultTwo} {
		if result.err == nil {
			if winner.lease != nil {
				t.Fatal("both PostgreSQL workers acquired the same expired lease")
			}
			winner = result
			continue
		}
		if !errors.Is(result.err, application.ErrWorkflowLeaseHeld) {
			t.Fatalf("lease contender %s returned %v", result.owner, result.err)
		}
	}
	if winner.lease == nil {
		t.Fatal("neither PostgreSQL worker acquired the expired lease")
	}
	if winner.lease.FencingToken != first.FencingToken+1 {
		t.Fatalf("takeover fence=%d, want %d", winner.lease.FencingToken, first.FencingToken+1)
	}

	if _, err := storeA.CommitOperation(ctx, application.CommitOperationInput{
		Key: key, LeaseOwner: "worker-a", FencingToken: first.FencingToken,
		Status: application.OperationFailed, ErrorCode: "STALE_WORKER",
	}); !errors.Is(err, application.ErrWorkflowStaleFence) {
		t.Fatalf("old fence commit was not rejected: %v", err)
	}
	committed, err := winner.store.CommitOperation(ctx, application.CommitOperationInput{
		Key: key, LeaseOwner: winner.owner, FencingToken: winner.lease.FencingToken,
		Status: application.OperationFailed, ErrorCode: "TEST_COMPLETE",
		ResultSnapshot: []byte(`{"winner":true}`),
	})
	if err != nil {
		t.Fatalf("winning fence commit: %v", err)
	}
	if committed.Status != application.OperationFailed || committed.FencingToken != winner.lease.FencingToken {
		t.Fatalf("unexpected committed operation: %+v", committed)
	}
}

func openPostgresSchemaConnection(t *testing.T, ctx context.Context, dsn, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL schema connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		_ = db.Close()
		t.Fatalf("select PostgreSQL schema: %v", err)
	}
	return db
}

func waitForPostgresLeaseExpiry(t *testing.T, ctx context.Context, db *sql.DB, key application.OperationKey) {
	t.Helper()
	for {
		var expired bool
		err := db.QueryRowContext(ctx, `SELECT lease_expires_at <= CURRENT_TIMESTAMP
FROM integration_operations WHERE integration_client_id = $1 AND operation_id = $2`,
			key.ClientID, key.OperationID).Scan(&expired)
		if err != nil {
			t.Fatalf("inspect lease expiry: %v", err)
		}
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL lease expiry: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
