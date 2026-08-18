package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLoadMigrationsSortsAndUnwraps(t *testing.T) {
	source := fstest.MapFS{
		"002_second.sql": {Data: []byte("BEGIN;\nSELECT 2;\nCOMMIT;")},
		"001_first.sql":  {Data: []byte("BEGIN;\nSELECT 1;\nCOMMIT;")},
	}
	items, err := loadMigrations(source)
	if err != nil {
		t.Fatalf("loadMigrations(): %v", err)
	}
	if len(items) != 2 || items[0].version != "001_first.sql" || items[0].body != "SELECT 1;" {
		t.Fatalf("unexpected migrations: %#v", items)
	}
}

func TestLoadMigrationsRejectsDuplicateVersionAndMissingWrapper(t *testing.T) {
	for name, source := range map[string]fstest.MapFS{
		"duplicate": {
			"001_one.sql": {Data: []byte("BEGIN; SELECT 1; COMMIT;")},
			"001_two.sql": {Data: []byte("BEGIN; SELECT 2; COMMIT;")},
		},
		"wrapper": {"001_one.sql": {Data: []byte("SELECT 1;")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadMigrations(source); err == nil {
				t.Fatal("invalid migration set was accepted")
			}
		})
	}
}

func TestMigrateUsesLockAndAtomicLedger(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw := []byte("BEGIN;\nCREATE TABLE sample(id integer);\nCOMMIT;")
	checksum := sha256.Sum256(raw)
	mock.ExpectExec("SELECT pg_advisory_lock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEmptySchema(mock)
	expectAppliedPrefix(mock)
	mock.ExpectQuery("SELECT checksum FROM trusted_pool_schema_migrations").WithArgs("001_sample.sql").
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectExec("SELECT pg_advisory_unlock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err = Migrate(context.Background(), db, fstest.MapFS{"001_sample.sql": {Data: raw}})
	if err == nil {
		t.Fatal("unexpected ledger read error was ignored")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	db, mock, err = sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("SELECT pg_advisory_lock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectEmptySchema(mock)
	expectAppliedPrefix(mock)
	mock.ExpectQuery("SELECT checksum FROM trusted_pool_schema_migrations").WithArgs("001_sample.sql").
		WillReturnRows(sqlmock.NewRows([]string{"checksum"}))
	mock.ExpectBegin()
	mock.ExpectExec("CREATE TABLE sample").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO trusted_pool_schema_migrations").
		WithArgs("001_sample.sql", checksum[:]).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec("SELECT pg_advisory_unlock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := Migrate(context.Background(), db, fstest.MapFS{"001_sample.sql": {Data: raw}}); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateRejectsChecksumDrift(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw := []byte("BEGIN; SELECT 1; COMMIT;")
	mock.ExpectExec("SELECT pg_advisory_lock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT to_regclass\\('public.trusted_pool_schema_migrations'\\) IS NOT NULL").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectAppliedPrefix(mock, "001_sample.sql")
	mock.ExpectQuery("SELECT checksum FROM trusted_pool_schema_migrations").WithArgs("001_sample.sql").
		WillReturnRows(sqlmock.NewRows([]string{"checksum"}).AddRow(make([]byte, sha256.Size)))
	mock.ExpectExec("SELECT pg_advisory_unlock").WithArgs(migrationAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := Migrate(context.Background(), db, fstest.MapFS{"001_sample.sql": {Data: raw}}); err == nil {
		t.Fatal("checksum drift was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateRollsBackFailedFile(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw := []byte("BEGIN; SELECT broken; COMMIT;")
	mock.ExpectExec("SELECT pg_advisory_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	expectEmptySchema(mock)
	expectAppliedPrefix(mock)
	mock.ExpectQuery("SELECT checksum").WillReturnRows(sqlmock.NewRows([]string{"checksum"}))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT broken").WillReturnError(errors.New("broken migration"))
	mock.ExpectRollback()
	mock.ExpectExec("SELECT pg_advisory_unlock").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := Migrate(context.Background(), db, fstest.MapFS{"001_sample.sql": {Data: raw}}); err == nil {
		t.Fatal("failed migration was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateRejectsUnmanagedDomainSchema(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("SELECT pg_advisory_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT to_regclass\\('public.trusted_pool_schema_migrations'\\) IS NOT NULL").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("to_regclass\\('public.members'\\)").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("SELECT pg_advisory_unlock").WillReturnResult(sqlmock.NewResult(0, 1))
	err = Migrate(context.Background(), db,
		fstest.MapFS{"001_sample.sql": {Data: []byte("BEGIN; SELECT 1; COMMIT;")}})
	if !errors.Is(err, ErrUnmanagedSchema) {
		t.Fatalf("Migrate() error = %v, want ErrUnmanagedSchema", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectEmptySchema(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT to_regclass\\('public.trusted_pool_schema_migrations'\\) IS NOT NULL").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("to_regclass\\('public.members'\\)").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("CREATE TABLE trusted_pool_schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectAppliedPrefix(mock sqlmock.Sqlmock, versions ...string) {
	rows := sqlmock.NewRows([]string{"version"})
	for _, version := range versions {
		rows.AddRow(version)
	}
	mock.ExpectQuery("SELECT version FROM trusted_pool_schema_migrations ORDER BY version").
		WillReturnRows(rows)
}
