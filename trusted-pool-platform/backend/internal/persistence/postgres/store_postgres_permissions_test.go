package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

// PHASE2H_TEST_POSTGRES_ADMIN_DSN must reference a disposable database through
// a role that can create temporary roles and schemas.
func TestRuntimeRoleUsesStoreWithoutDDLOrDeletePrivileges(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_ADMIN_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_ADMIN_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL admin connection: %v", err)
	}
	defer admin.Close()

	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	migratorRole := "phase2h_migrator_" + suffix
	runtimeRole := "phase2h_runtime_" + suffix
	schema := "phase2h_permissions_" + suffix
	for _, statement := range []string{
		`CREATE ROLE ` + migratorRole + ` NOLOGIN`,
		`CREATE ROLE ` + runtimeRole + ` NOLOGIN`,
		`CREATE SCHEMA ` + schema + ` AUTHORIZATION ` + migratorRole,
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
	} {
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare least-privilege fixture with %q: %v", statement, err)
		}
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_, _ = admin.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+runtimeRole)
		_, _ = admin.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+migratorRole)
	}()

	migrationDB := openPostgresRoleConnection(t, ctx, dsn, migratorRole, schema)
	if err := Migrate(ctx, migrationDB, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		_ = migrationDB.Close()
		t.Fatalf("migrate with migration owner: %v", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatalf("close migration owner connection: %v", err)
	}
	for _, statement := range []string{
		`REVOKE CREATE ON SCHEMA ` + schema + ` FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + runtimeRole,
		`GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + runtimeRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ` + schema + ` TO ` + runtimeRole,
		`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ` + schema + ` TO ` + runtimeRole,
	} {
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatalf("grant runtime privileges with %q: %v", statement, err)
		}
	}

	runtimeDB := openPostgresRoleConnection(t, ctx, dsn, runtimeRole, schema)
	defer runtimeDB.Close()
	var canCreate, canDelete bool
	if err := runtimeDB.QueryRowContext(ctx, `SELECT
has_schema_privilege(current_user, current_schema(), 'CREATE'),
has_table_privilege(current_user, 'integration_operations', 'DELETE')`).Scan(&canCreate, &canDelete); err != nil {
		t.Fatalf("inspect runtime privileges: %v", err)
	}
	if canCreate || canDelete {
		t.Fatalf("runtime role retained unsafe privileges: create=%v delete=%v", canCreate, canDelete)
	}
	store, err := NewStore(runtimeDB)
	if err != nil {
		t.Fatalf("create runtime Store: %v", err)
	}
	requestHash := [32]byte{1}
	key := application.OperationKey{ClientID: "least-privilege-client", OperationID: "least-privilege-operation"}
	if _, created, err := store.BeginOperation(ctx, application.BeginOperationInput{
		Key: key, Kind: application.OperationProvision, TargetType: "SEAT", TargetExternalID: "least-privilege-seat",
		RequestHash: requestHash, RequestSnapshot: []byte(`{"seat_id":"least-privilege-seat"}`),
	}); err != nil || !created {
		t.Fatalf("begin operation as runtime role: created=%v err=%v", created, err)
	}
	lease, err := store.AcquireOperationLease(ctx, application.AcquireOperationLeaseInput{
		Key: key, LeaseOwner: "least-privilege-worker", LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("acquire operation as runtime role: %v", err)
	}
	if _, err := store.CommitOperation(ctx, application.CommitOperationInput{
		Key: key, LeaseOwner: "least-privilege-worker", FencingToken: lease.FencingToken,
		Status: application.OperationFailed, ErrorCode: "PERMISSION_TEST_COMPLETE",
	}); err != nil {
		t.Fatalf("commit operation as runtime role: %v", err)
	}
	if _, err := runtimeDB.ExecContext(ctx, `CREATE TABLE forbidden_runtime_ddl (id integer)`); err == nil {
		t.Fatal("runtime role created a table")
	}
	if _, err := runtimeDB.ExecContext(ctx, `DELETE FROM integration_operations`); err == nil {
		t.Fatal("runtime role deleted operation ledger rows")
	}
}

func openPostgresRoleConnection(t *testing.T, ctx context.Context, dsn, role, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL role connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `SET ROLE `+role); err != nil {
		_ = db.Close()
		t.Fatalf("select PostgreSQL role %s: %v", role, err)
	}
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		_ = db.Close()
		t.Fatalf("select PostgreSQL schema %s: %v", schema, err)
	}
	return db
}
