package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

const migrationAdvisoryLockKey int64 = 0x54504c4d494752 // "TPLMIGR"

var ErrUnmanagedSchema = errors.New("trusted pool database contains an unmanaged schema")

var acceptedLegacyMigrationChecksums = map[string][]string{
	// The original 005 file had an ambiguous PL/pgSQL CASE expression. Existing
	// ledgers retain its checksum while fresh databases record the repaired file.
	"005_phase2c_assignment_persistence.sql": {
		"373ec4cd408840e1b769bdf4307f943be100cc8a1a7a1746149ccfacad5dbd83",
	},
}

type migration struct {
	version  string
	checksum [sha256.Size]byte
	body     string
}

// Migrate 持有 session advisory lock，并将每个迁移与 checksum 记录原子提交。
func Migrate(ctx context.Context, db *sql.DB, migrations fs.FS) error {
	if db == nil || migrations == nil {
		return errors.New("database and migration filesystem are required")
	}
	items, err := loadMigrations(migrations)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("no trusted pool migrations found")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey)
	}()

	if err := ensureMigrationLedger(ctx, conn); err != nil {
		return err
	}
	if err := validateMigrationLedgerPrefix(ctx, conn, items); err != nil {
		return err
	}
	for _, item := range items {
		if err := applyMigration(ctx, conn, item); err != nil {
			return err
		}
	}
	return nil
}

func validateMigrationLedgerPrefix(ctx context.Context, conn *sql.Conn, items []migration) error {
	rows, err := conn.QueryContext(ctx,
		`SELECT version FROM trusted_pool_schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read migration ledger order: %w", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan migration ledger order: %w", err)
		}
		if index >= len(items) || items[index].version != version {
			return fmt.Errorf("migration ledger is not a prefix of configured files at %q", version)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration ledger order: %w", err)
	}
	return nil
}

func ensureMigrationLedger(ctx context.Context, conn *sql.Conn) error {
	var ledgerExists bool
	if err := conn.QueryRowContext(ctx,
		`SELECT to_regclass(format('%I.%I', current_schema(),
'trusted_pool_schema_migrations')) IS NOT NULL`).Scan(&ledgerExists); err != nil {
		return fmt.Errorf("inspect migration ledger: %w", err)
	}
	if ledgerExists {
		return nil
	}
	var domainSchemaExists bool
	if err := conn.QueryRowContext(ctx, `SELECT
to_regclass(format('%I.%I', current_schema(), 'members')) IS NOT NULL OR
to_regclass(format('%I.%I', current_schema(), 'pools')) IS NOT NULL OR
to_regclass(format('%I.%I', current_schema(), 'seats')) IS NOT NULL OR
to_regclass(format('%I.%I', current_schema(), 'integration_operations')) IS NOT NULL OR
to_regclass(format('%I.%I', current_schema(), 'credential_claims')) IS NOT NULL`).
		Scan(&domainSchemaExists); err != nil {
		return fmt.Errorf("inspect unmanaged domain schema: %w", err)
	}
	if domainSchemaExists {
		return ErrUnmanagedSchema
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE trusted_pool_schema_migrations (
version text PRIMARY KEY,
checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, item migration) error {
	var recorded []byte
	err := conn.QueryRowContext(ctx,
		`SELECT checksum FROM trusted_pool_schema_migrations WHERE version = $1`, item.version).Scan(&recorded)
	if err == nil {
		if !migrationChecksumAccepted(item.version, recorded, item.checksum) {
			return fmt.Errorf("migration %s checksum mismatch: expected %s", item.version,
				hex.EncodeToString(item.checksum[:]))
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read migration %s ledger: %w", item.version, err)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", item.version, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, item.body); err != nil {
		return fmt.Errorf("apply migration %s: %w", item.version, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO trusted_pool_schema_migrations (version, checksum) VALUES ($1, $2)`,
		item.version, item.checksum[:]); err != nil {
		return fmt.Errorf("record migration %s: %w", item.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", item.version, err)
	}
	return nil
}

func migrationChecksumAccepted(version string, recorded []byte, current [sha256.Size]byte) bool {
	if len(recorded) != sha256.Size {
		return false
	}
	if equalBytes(recorded, current[:]) {
		return true
	}
	for _, encoded := range acceptedLegacyMigrationChecksums[version] {
		legacy, err := hex.DecodeString(encoded)
		if err == nil && equalBytes(recorded, legacy) {
			return true
		}
	}
	return false
}

func loadMigrations(source fs.FS) ([]migration, error) {
	names, err := fs.Glob(source, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(names)
	items := make([]migration, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		base := filepath.Base(name)
		parts := strings.SplitN(base, "_", 2)
		if len(parts) != 2 || len(parts[0]) != 3 || strings.Trim(parts[0], "0123456789") != "" {
			return nil, fmt.Errorf("invalid migration filename %q", base)
		}
		if _, exists := seen[parts[0]]; exists {
			return nil, fmt.Errorf("duplicate migration version %q", parts[0])
		}
		seen[parts[0]] = struct{}{}
		raw, err := fs.ReadFile(source, name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", base, err)
		}
		body, err := unwrapMigrationTransaction(string(raw))
		if err != nil {
			return nil, fmt.Errorf("parse migration %s: %w", base, err)
		}
		items = append(items, migration{version: base, checksum: sha256.Sum256(raw), body: body})
	}
	return items, nil
}

func unwrapMigrationTransaction(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	const begin = "BEGIN;"
	const commit = "COMMIT;"
	if !strings.HasPrefix(strings.ToUpper(trimmed), begin) ||
		!strings.HasSuffix(strings.ToUpper(trimmed), commit) {
		return "", errors.New("migration must have one explicit BEGIN/COMMIT wrapper")
	}
	body := strings.TrimSpace(trimmed[len(begin) : len(trimmed)-len(commit)])
	if body == "" {
		return "", errors.New("migration body is empty")
	}
	return body, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}
