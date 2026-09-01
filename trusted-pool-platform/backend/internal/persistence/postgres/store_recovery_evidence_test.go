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

	_ "github.com/lib/pq"

	"trusted-pool-platform/backend/internal/recovery"
)

func TestPhase2HEvidenceMigrationContainsFailClosedBoundaries(t *testing.T) {
	source := readPhase2HSource(t, "../../../../migrations/010_phase2h_offline_verification.sql")
	required := []string{
		"platform_signature_domain",
		"trusted-pool/platform-manifest-signature/v2",
		"recovery_member_artifact_receipts",
		"recovery_verification_exports",
		"trusted-pool/verification-export-signature/v1",
		"LEGACY_EXPORT_LIMITED",
		"recovery_reveal_authorizations",
		"PENDING_APPROVAL",
		"AUTHORIZATION_EXPORTED",
		"recovery_reveal_approval_intents",
		"recovery_reveal_executor_receipts",
		"recovery_reveal_event_hash",
		"DEFERRABLE INITIALLY DEFERRED",
		"assert_phase2h_operation_aggregate",
		"provider_attestation_protocol_version",
		"portable_attestation_signature",
		"portable_provider_proof_signature",
		"online Reveal approval execution is unavailable in Phase2-H",
	}
	for _, fragment := range required {
		if !strings.Contains(source, fragment) {
			t.Fatalf("010 migration lacks %q", fragment)
		}
	}
	for _, table := range []string{"recovery_verification_exports", "recovery_reveal_authorizations"} {
		definition := sqlTableDefinition(t, source, table)
		for _, forbidden := range []string{"encrypted_share", "wrapped_dek", "batch_ciphertext",
			"root_plaintext", "share_plaintext", "credential_payload", "package_blob"} {
			if strings.Contains(strings.ToLower(definition), forbidden) {
				t.Fatalf("%s persists forbidden field %q", table, forbidden)
			}
		}
	}
	approvalGuard := sqlFunctionDefinition(t, source, "enforce_reveal_approval_phase2h")
	for _, guard := range []string{"IF NOT FOUND OR trusted.status IS DISTINCT FROM 'PENDING_APPROVAL'",
		"NEW.signing_algorithm IS DISTINCT FROM trusted.signing_algorithm",
		"NEW.signing_key_id IS DISTINCT FROM trusted.signing_key_id",
		"NEW.message_hash IS DISTINCT FROM trusted.expected_message_hash"} {
		if !strings.Contains(approvalGuard, guard) {
			t.Fatalf("Reveal approval NULL-safe guard lacks %q", guard)
		}
	}
	shareGuard := sqlFunctionDefinition(t, source, "enforce_phase2h_share_evidence_immutable")
	if strings.Contains(shareGuard, "NEW.status") || strings.Contains(shareGuard, "online Reveal") {
		t.Fatal("Share evidence trigger contains a Reveal-only status guard")
	}
	revealGuard := sqlFunctionDefinition(t, source, "enforce_reveal_authorization_phase2h")
	if !strings.Contains(revealGuard, "NEW.status NOT IN ('PENDING_APPROVAL','CANCELLED','EXPIRED')") {
		t.Fatal("Reveal authorization trigger does not fail closed before executable states")
	}
	executorGuard := sqlFunctionDefinition(t, source, "enforce_reveal_executor_receipt_phase2h")
	if !strings.Contains(executorGuard, "online Reveal executor execution is unavailable in Phase2-H") {
		t.Fatal("Reveal executor receipt trigger is not explicitly disabled")
	}
}

func TestPhase2MigrationUpgradeDDLRetainsPostgresFixes(t *testing.T) {
	assignment := readPhase2HSource(t, "../../../../migrations/005_phase2c_assignment_persistence.sql")
	if !strings.Contains(assignment, "pending_assignment_type IS DISTINCT FROM (\n           CASE") {
		t.Fatal("migration 005 lost the parenthesized assignment type CASE expression")
	}
	assignmentRepair := readPhase2HSource(t, "../../../../migrations/012_phase2i_assignment_aggregate_repair.sql")
	if !strings.Contains(assignmentRepair, "CREATE OR REPLACE FUNCTION assert_assignment_aggregate") ||
		!strings.Contains(assignmentRepair, "pending_assignment_type IS DISTINCT FROM (\n           CASE") {
		t.Fatal("migration 012 does not forward-repair the assignment aggregate function")
	}
	governance := readPhase2HSource(t, "../../../../migrations/008_phase2f_recovery_governance.sql")
	for _, fragment := range []string{
		"ceremony_attestation_purpose' IS DISTINCT FROM (\n           CASE",
		"previous_manifest_hash', '') IS DISTINCT FROM (\n           CASE",
	} {
		if !strings.Contains(governance, fragment) {
			t.Fatalf("migration 008 lost parenthesized CASE expression %q", fragment)
		}
	}
	finalization := readPhase2HSource(t, "../../../../migrations/009_phase2g_permanent_finalization.sql")
	for trigger, table := range map[string]string{
		"credential_claims_invariants":                 "credential_claims",
		"pools_credential_epoch_floor_monotonic":       "pools",
		"credential_batches_epoch_floor":               "credential_batches",
		"control_rotation_evidence_invariants":         "control_rotation_evidence",
		"control_rotation_evidence_batches_immutable":  "control_rotation_evidence_batches",
		"credential_batches_issued_evidence_status":    "credential_batches",
		"control_rotation_evidence_complete":           "control_rotation_evidence",
		"control_rotation_evidence_batch_set_complete": "control_rotation_evidence_batches",
	} {
		drop := strings.Index(finalization, "DROP TRIGGER IF EXISTS "+trigger+" ON "+table+";")
		create := strings.Index(finalization, "CREATE TRIGGER "+trigger)
		if create < 0 {
			create = strings.Index(finalization, "CREATE CONSTRAINT TRIGGER "+trigger)
		}
		if drop < 0 || create <= drop {
			t.Fatalf("migration 009 does not replace existing trigger %s on %s", trigger, table)
		}
	}
}

func TestPhase2HOnlineRevealExecutionFailsClosed(t *testing.T) {
	store := &Store{}
	ctx := context.Background()
	if _, _, err := store.BeginRevealAuthorization(ctx, recovery.BeginRevealAuthorizationInput{}); !errors.Is(err, recovery.ErrRevealExecutionUnavailable) {
		t.Fatalf("BeginRevealAuthorization error = %v", err)
	}
	if _, err := store.CommitRevealApprovals(ctx, recovery.CommitRevealApprovalsInput{}); !errors.Is(err, recovery.ErrRevealExecutionUnavailable) {
		t.Fatalf("CommitRevealApprovals error = %v", err)
	}
	if _, err := store.ExportRevealAuthorization(ctx, recovery.ExportRevealAuthorizationInput{}); !errors.Is(err, recovery.ErrRevealExecutionUnavailable) {
		t.Fatalf("ExportRevealAuthorization error = %v", err)
	}
	if _, err := store.CommitRevealExecutorReceipt(ctx, recovery.CommitRevealExecutorReceiptInput{}); !errors.Is(err, recovery.ErrRevealExecutionUnavailable) {
		t.Fatalf("CommitRevealExecutorReceipt error = %v", err)
	}
}

func TestPhase2HEvidenceTimesReplayAtPostgresPrecision(t *testing.T) {
	stored := time.Date(2026, 8, 21, 1, 2, 3, 123456000, time.UTC)
	requested := time.Date(2026, 8, 21, 9, 2, 3, 123456789, time.FixedZone("offset", 8*60*60))
	if !sameEvidenceDBTime(stored, requested) {
		t.Fatal("same PostgreSQL microsecond instant was treated as request drift")
	}
	if sameEvidenceDBTime(stored, requested.Add(time.Microsecond)) {
		t.Fatal("distinct PostgreSQL microsecond instants were treated as equal")
	}
}

func TestPhase2HRequestSnapshotBuildersMatchStoreCanonicalization(t *testing.T) {
	exportInput := recovery.BeginVerificationExportInput{Key: recovery.OperationKey{OperationID: "operation-1"},
		ExportExternalID: "export-1", PlanExternalID: "plan-1", FormatVersion: "phase2h-v1"}
	exportSnapshot, _, err := recovery.BuildVerificationExportRequestSnapshot(exportInput)
	if err != nil {
		t.Fatalf("build export snapshot: %v", err)
	}
	canonical, err := canonicalJSONObject(exportSnapshot)
	if err != nil || string(canonical) != string(exportSnapshot) {
		t.Fatalf("export snapshot is not Store-canonical: err=%v snapshot=%s canonical=%s", err, exportSnapshot, canonical)
	}
	revealInput := recovery.BeginRevealAuthorizationInput{Key: recovery.OperationKey{OperationID: "operation-2"},
		RevealExternalID: "reveal-1", ExportExternalID: "export-1", PlanExternalID: "plan-1",
		Purpose: "incident", ScopeHash: [32]byte{1}, ChallengeHash: [32]byte{2},
		ExpiresAt:       time.Date(2026, 8, 21, 1, 2, 3, 456789123, time.UTC),
		ApprovalIntents: []recovery.RevealApprovalIntent{{MemberExternalID: "member-1", ExpectedMessageHash: [32]byte{3}}}}
	revealSnapshot, _, err := recovery.BuildRevealAuthorizationRequestSnapshot(revealInput)
	if err != nil {
		t.Fatalf("build Reveal snapshot: %v", err)
	}
	canonical, err = canonicalJSONObject(revealSnapshot)
	if err != nil || string(canonical) != string(revealSnapshot) {
		t.Fatalf("Reveal snapshot is not Store-canonical: err=%v snapshot=%s canonical=%s", err, revealSnapshot, canonical)
	}
}

func TestPublicEvidenceSnapshotQueryDoesNotSelectSecretMaterial(t *testing.T) {
	source := readPhase2HSource(t, "store_recovery_evidence.go")
	start := strings.Index(source, "func (s *Store) LoadPublicEvidenceSnapshot")
	end := strings.Index(source, "func (s *Store) CommitVerificationExport")
	if start < 0 || end <= start {
		t.Fatal("cannot isolate public snapshot implementation")
	}
	snapshot := strings.ToLower(source[start:end])
	for _, forbidden := range []string{"encrypted_share", "wrapped_dek", "encrypted_dek",
		"batch.ciphertext", "credential_batches", "root_handle", "provider_key_ref"} {
		if strings.Contains(snapshot, forbidden) {
			t.Fatalf("public evidence snapshot reads forbidden material %q", forbidden)
		}
	}
	for _, required := range []string{"canonical_bytes", "share_hash", "root_commitment_hash",
		"vss_commitment_hash", "acknowledgement_signature", "loadpublicproviderproofstx"} {
		if !strings.Contains(snapshot, required) {
			t.Fatalf("public evidence snapshot lacks %q", required)
		}
	}
	wholeSource := strings.ToLower(source)
	for _, required := range []string{"bootstrap_attestation_issuer", "root.provider", "provider_attestation_issuer"} {
		if !strings.Contains(wholeSource, required) {
			t.Fatalf("public provider projection lacks %q", required)
		}
	}
}

func TestPublicProviderProjectionUsesDetachedPortableSignatures(t *testing.T) {
	source := readPhase2HSource(t, "store_recovery_evidence.go")
	start := strings.Index(source, "func loadPublicProviderProofsTx")
	if start < 0 {
		t.Fatal("cannot isolate public provider proof projection")
	}
	projection := source[start:]
	for _, required := range []string{"root.portable_attestation_signature", "delivery.portable_provider_proof_signature"} {
		if !strings.Contains(projection, required) {
			t.Fatalf("public provider projection lacks detached proof %q", required)
		}
	}
	for _, forbidden := range []string{"root.attestation_signature", "delivery.provider_proof_signature"} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("public provider projection treats opaque proof as detached signature %q", forbidden)
		}
	}
}

func TestIncompletePortableProviderProofIsOmittedInsteadOfRejected(t *testing.T) {
	protocol := sql.NullString{String: providerProofStatementV1, Valid: true}
	algorithm := sql.NullString{String: ed25519Algorithm, Valid: true}
	identity := sql.NullString{String: "provider-key", Valid: true}
	if !completePublicProviderProof(protocol, algorithm, identity, identity, make([]byte, 64)) {
		t.Fatal("complete portable provider proof was rejected")
	}
	missing := sql.NullString{}
	if completePublicProviderProof(protocol, algorithm, identity, missing, make([]byte, 64)) ||
		completePublicProviderProof(protocol, algorithm, identity, identity, []byte("opaque-proof")) {
		t.Fatal("incomplete portable provider proof would be exported as invalid evidence")
	}
}

func TestPublicEvidenceSnapshotAllowsExactTerminalReplayWithoutLiveLease(t *testing.T) {
	source := readPhase2HSource(t, "store_recovery_evidence.go")
	if !strings.Contains(source, "$3 = '' AND $4 = 0") ||
		!strings.Contains(source, "operation.status = 'SUCCEEDED' AND export.status = 'AVAILABLE'") {
		t.Fatal("public evidence snapshot cannot rebuild an exact terminal export after lease expiry")
	}
}

func TestPublicEvidenceSnapshotInputSeparatesActiveAndTerminalModes(t *testing.T) {
	base := recovery.LoadPublicEvidenceSnapshotInput{Key: recovery.OperationKey{
		ClientID: "client-1", OperationID: "operation-1"}, ExportID: "export-1"}
	if !validPublicEvidenceSnapshotInput(base) {
		t.Fatal("terminal snapshot read without a lease was rejected")
	}
	active := base
	active.LeaseOwner = "worker-1"
	active.FencingToken = 7
	if !validPublicEvidenceSnapshotInput(active) {
		t.Fatal("active fenced snapshot read was rejected")
	}
	for _, invalid := range []recovery.LoadPublicEvidenceSnapshotInput{
		{Key: base.Key, ExportID: base.ExportID, LeaseOwner: "worker-1"},
		{Key: base.Key, ExportID: base.ExportID, FencingToken: 7},
		{Key: base.Key, ExportID: base.ExportID, LeaseOwner: "worker-1", FencingToken: -1},
	} {
		if validPublicEvidenceSnapshotInput(invalid) {
			t.Fatalf("mixed snapshot read mode was accepted: %+v", invalid)
		}
	}
}

func TestVerificationExportHeartbeatIsSameOwnerSameFenceOnly(t *testing.T) {
	source := readPhase2HSource(t, "store_recovery_evidence.go")
	start := strings.Index(source, "func (s *Store) RenewVerificationExportLease")
	if start < 0 {
		t.Fatal("cannot isolate verification export heartbeat")
	}
	end := strings.Index(source[start:], "func (s *Store) CommitVerificationExport")
	if end < 0 {
		t.Fatal("cannot find verification export commit after heartbeat")
	}
	heartbeat := source[start : start+end]
	for _, required := range []string{
		"operation.lease_owner = $3 AND operation.fencing_token = $4",
		"operation.lease_expires_at > CURRENT_TIMESTAMP AND operation.status = 'RUNNING'",
		"operation.operation_type = 'EXPORT_RECOVERY_VERIFICATION'",
		"export.external_id = $6 AND export.status = 'PENDING'",
	} {
		if !strings.Contains(heartbeat, required) {
			t.Fatalf("verification export heartbeat lacks %q", required)
		}
	}
	if strings.Contains(heartbeat, "fencing_token = fencing_token + 1") {
		t.Fatal("same-owner verification heartbeat increments the fence")
	}
}

func TestPhase2HEvidenceValidationRejectsDuplicatesAndLongLeases(t *testing.T) {
	hash := [32]byte{1}
	if validEvidenceLease("worker", 5*time.Minute+time.Nanosecond) {
		t.Fatal("evidence lease above the bounded five-minute window was accepted")
	}
	if validRevealIntents([]recovery.RevealApprovalIntent{
		{MemberExternalID: "member-1", ExpectedMessageHash: hash},
		{MemberExternalID: "member-1", ExpectedMessageHash: hash},
	}) {
		t.Fatal("duplicate Reveal approval intents were accepted")
	}
	if validRevealApprovals([]recovery.RevealApproval{
		{MemberExternalID: "member-1", Algorithm: "Ed25519", KeyID: "key-1", MessageHash: hash,
			Signature: []byte{1}, VerifiedAt: time.Now()},
		{MemberExternalID: "member-1", Algorithm: "Ed25519", KeyID: "key-1", MessageHash: hash,
			Signature: []byte{1}, VerifiedAt: time.Now()},
	}) {
		t.Fatal("duplicate Reveal approvals were accepted")
	}
}

func TestPhase2HTypedAccountProofFlowsThroughPlanAndEvidenceSQL(t *testing.T) {
	source := readPhase2HSource(t, "store_recovery.go")
	for _, required := range []string{
		"control_attestation_algorithm, control_attestation_signature",
		"control_attestation_protocol_version, created_at",
		"provider_attestation_algorithm, provider_attestation_signature, provider_attestation_protocol_version",
		"account.control_attestation_algorithm = $8::text",
		"account.control_attestation_signature = $9::bytea",
		"account.control_attestation_protocol_version = $10::text",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("typed account proof persistence lacks %q", required)
		}
	}
}

// PHASE2H_TEST_POSTGRES_DSN 必须指向可创建临时 schema 的一次性测试库。
func TestPhase2HMigrationOnRealPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	schema := fmt.Sprintf("phase2h_%x", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		t.Fatalf("select isolated PostgreSQL schema: %v", err)
	}
	if err := Migrate(ctx, db, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations 001-012 on real PostgreSQL: %v", err)
	}
	for _, table := range []string{"recovery_member_artifact_receipts", "recovery_verification_exports",
		"recovery_reveal_authorizations", "recovery_reveal_events"} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("Phase2-H table %s unavailable after migration: exists=%v err=%v", table, exists, err)
		}
	}
	var secretColumns int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name IN ('recovery_verification_exports','recovery_reveal_authorizations')
  AND column_name IN ('encrypted_share','wrapped_dek','batch_ciphertext','package_blob','credential')`).
		Scan(&secretColumns); err != nil {
		t.Fatalf("inspect Phase2-H secret columns: %v", err)
	}
	if secretColumns != 0 {
		t.Fatalf("Phase2-H public ledgers contain %d forbidden secret columns", secretColumns)
	}
	assertPhase2HTypedAccountStatementsPrepare(t, ctx, db)
	assertPhase2HDetachedProviderProofStatementsPrepare(t, ctx, db)
	assertPhase2HSQLRejected(t, ctx, db, `INSERT INTO recovery_reveal_approvals (
reveal_id, epoch_id, member_id, signing_algorithm, signing_key_id, message_hash, signature, verified_at
) VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'Ed25519', 'member-key',
          decode(repeat('01', 32), 'hex'), decode('01', 'hex'), CURRENT_TIMESTAMP)`,
		"online Reveal approval execution is unavailable in Phase2-H")
	assertPhase2HSQLRejected(t, ctx, db, `INSERT INTO recovery_reveal_executor_receipts (
reveal_id, disposition, receipt_digest, transcript_digest, sink_attestation_digest,
executor_profile, executor_algorithm, executor_key_id, executor_signature, completed_at
) VALUES (gen_random_uuid(), 'COMPLETED', decode(repeat('01', 32), 'hex'),
          decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'),
          'offline-executor/v1', 'Ed25519', 'executor-key', decode('01', 'hex'), CURRENT_TIMESTAMP)`,
		"online Reveal executor execution is unavailable in Phase2-H")
}

func TestPhase2ILegacy005ChecksumAppliesForwardRepair(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	schema := fmt.Sprintf("phase2i_upgrade_%x", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create upgrade schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		t.Fatalf("select upgrade schema: %v", err)
	}
	_, through011 := phase2HProtocolCompatibilityMigrationSets(t)
	if err := Migrate(ctx, db, through011); err != nil {
		t.Fatalf("apply migrations 001-011: %v", err)
	}
	const published005Checksum = "373ec4cd408840e1b769bdf4307f943be100cc8a1a7a1746149ccfacad5dbd83"
	if _, err := db.ExecContext(ctx, `UPDATE trusted_pool_schema_migrations
SET checksum = decode($1, 'hex') WHERE version = '005_phase2c_assignment_persistence.sql'`,
		published005Checksum); err != nil {
		t.Fatalf("install published 005 ledger checksum: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION assert_assignment_aggregate(target_operation_id uuid)
RETURNS void LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'stale assignment aggregate'; END; $$`); err != nil {
		t.Fatalf("install stale assignment aggregate: %v", err)
	}
	if err := Migrate(ctx, db, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("upgrade published 005 ledger through migration 012: %v", err)
	}
	assertMigrationLedgerState(t, ctx, db, 12, "012_phase2i_assignment_aggregate_repair.sql")
	if _, err := db.ExecContext(ctx, `SELECT assert_assignment_aggregate(gen_random_uuid())`); err != nil {
		t.Fatalf("migration 012 did not replace stale assignment aggregate: %v", err)
	}
	var recorded005Checksum string
	if err := db.QueryRowContext(ctx, `SELECT encode(checksum, 'hex')
FROM trusted_pool_schema_migrations WHERE version = '005_phase2c_assignment_persistence.sql'`).
		Scan(&recorded005Checksum); err != nil {
		t.Fatalf("read migration 005 ledger checksum: %v", err)
	}
	if recorded005Checksum != published005Checksum {
		t.Fatalf("migration 005 ledger history was rewritten: %s", recorded005Checksum)
	}
}

func TestPhase2HUpgradeFrom009PreservesLegacyEvidenceFailClosed(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	schema := fmt.Sprintf("phase2h_upgrade_%x", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create upgrade schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve upgrade connection: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		t.Fatalf("select upgrade schema: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE trusted_pool_schema_migrations (
version text PRIMARY KEY, checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create upgrade ledger: %v", err)
	}
	items, err := loadMigrations(os.DirFS(filepath.Clean("../../../../migrations")))
	if err != nil || len(items) < 10 || items[9].version != "010_phase2h_offline_verification.sql" {
		t.Fatalf("load migrations: count=%d err=%v", len(items), err)
	}
	items = items[:10]
	for _, item := range items[:7] {
		if err := applyMigration(ctx, conn, item); err != nil {
			t.Fatalf("apply legacy prefix %s: %v", item.version, err)
		}
	}
	var poolID, epochID string
	if err := conn.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, credential_epoch_floor
) VALUES ('legacy-pool', 'Legacy Pool', 'ACTIVE', 2, 1, 1) RETURNING id`).Scan(&poolID); err != nil {
		t.Fatalf("insert legacy Pool: %v", err)
	}
	if err := conn.QueryRowContext(ctx, `INSERT INTO membership_epochs (
pool_id, epoch, status, governance_threshold, recovery_threshold, activated_at
) VALUES ($1, 1, 'ACTIVE', 1, 1, CURRENT_TIMESTAMP) RETURNING id`, poolID).Scan(&epochID); err != nil {
		t.Fatalf("insert legacy Epoch: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO manifests (
epoch_id, protocol_version, canonical_payload, manifest_hash, platform_signature, status, published_at
) VALUES ($1, 'legacy/v1', '{}'::jsonb, decode(repeat('01',32),'hex'), decode('01','hex'),
          'ACTIVE', CURRENT_TIMESTAMP)`, epochID); err != nil {
		t.Fatalf("insert legacy Manifest: %v", err)
	}
	for _, item := range items[7:] {
		if err := applyMigration(ctx, conn, item); err != nil {
			t.Fatalf("upgrade with %s: %v", item.version, err)
		}
	}
	var governanceState, manifestState string
	var formatVersion, signatureDomain sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT epoch.recovery_governance_state,
manifest.migration_state, plan.portable_format_version, manifest.platform_signature_domain
FROM membership_epochs epoch JOIN manifests manifest ON manifest.epoch_id = epoch.id
LEFT JOIN recovery_epoch_plans plan ON plan.id = manifest.recovery_plan_id
WHERE epoch.id = $1`, epochID).Scan(&governanceState, &manifestState, &formatVersion, &signatureDomain); err != nil {
		t.Fatalf("read upgraded legacy evidence: %v", err)
	}
	if governanceState != "LEGACY_UNVERIFIED" || manifestState != "LEGACY_UNVERIFIED" ||
		formatVersion.Valid || signatureDomain.Valid {
		t.Fatalf("legacy evidence was promoted: governance=%s manifest=%s format=%v domain=%v",
			governanceState, manifestState, formatVersion, signatureDomain)
	}
}

func assertPhase2HDetachedProviderProofStatementsPrepare(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO recovery_epoch_plans (
external_id, integration_operation_id, ceremony_type, pool_id, from_epoch, to_epoch, status,
governance_threshold, recovery_threshold, required_share_ack_count,
expected_member_count, expected_seat_count, expected_resource_count, expected_control_batch_count,
previous_manifest_hash, from_epoch_status, from_governance_state,
bootstrap_attestation_ref, bootstrap_attestation_digest, bootstrap_attestation_issuer,
bootstrap_attestation_key_id, bootstrap_attestation_signature, bootstrap_attestation_version,
provider_attestation_set_hash, portable_format_version, root_trust_profile_id, crypto_suite_id,
provider_proof_profile, ceremony_attestation_algorithm, version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, 'PLANNED', $7, $8, $9, $9, $9, $10, $11, $12,
'ACTIVE', $13, $14, $15::bytea, $16, $17, $18::bytea, $19, $20::bytea,
$21, $22, $23, $24, $25, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
		`INSERT INTO manifests (
external_id, epoch_id, protocol_version, canonical_payload, canonical_bytes, manifest_hash,
platform_signature, status, recovery_plan_id, root_artifact_id, migration_state,
previous_manifest_hash, batch_set_hash, recovery_package_hash, provider_attestation_digest,
platform_algorithm, platform_key_ref, platform_verified_at, platform_signature_domain, created_at
)
SELECT $1, epoch.id, $2, $3::jsonb, $4, $5, $6, 'DRAFT', plan.id, root.id, 'CURRENT',
plan.previous_manifest_hash, $7, $8, $9, $10, $11, $12, NULLIF($13::text, ''), CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN recovery_root_artifacts root ON root.plan_id = plan.id AND root.migration_state = 'CURRENT'
WHERE plan.id = $14 AND root.recovery_package_hash = $8 AND root.attestation_digest = $9
RETURNING id, epoch_id`,
		`INSERT INTO recovery_root_artifacts (
external_id, plan_id, provider, provider_key_ref, root_handle, root_key_version,
epoch_recovery_algorithm, epoch_recovery_key_id, epoch_recovery_key_fingerprint,
wrap_domain, wrap_algorithm, vss_algorithm, vss_commitment, vss_commitment_hash,
vss_proof, vss_proof_hash, private_key_commitment, private_key_commitment_hash,
root_commitment_hash, recovery_package_hash, request_intent_hash,
provider_attestation_ref, attestation_digest, attestation_signature,
attestation_key_id, attestation_algorithm, attestation_issuer, portable_attestation_key_id,
attestation_protocol_version, portable_attestation_signature, migration_state, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
'CURRENT', CURRENT_TIMESTAMP)`,
		`INSERT INTO recovery_share_deliveries (
external_id, recovery_plan_id, root_artifact_id, epoch_id, member_id, encrypted_share, share_hash,
delivery_status, delivered_at, created_at, migration_state, share_index, encryption_algorithm,
recipient_key_id, recipient_key_fingerprint, provider_share_commitment, provider_proof_digest,
provider_proof_signature, provider_proof_algorithm, provider_proof_key_id,
provider_proof_protocol_version, portable_provider_proof_signature
)
SELECT $1, plan.id, root.id, epoch.id, member.id, $2, $3, 'DELIVERED', CURRENT_TIMESTAMP,
CURRENT_TIMESTAMP, 'CURRENT', $4::smallint, $5::text, $6::text, $7::bytea, $8::bytea,
$9::bytea, $10::bytea, $11::text, $12::text, $13::text, $14::bytea
FROM recovery_epoch_plans plan
JOIN recovery_root_artifacts root ON root.plan_id = plan.id AND root.migration_state = 'CURRENT'
JOIN membership_epochs epoch ON epoch.recovery_plan_id = plan.id AND epoch.epoch = plan.to_epoch
JOIN members member ON member.external_id = $15::text
JOIN membership_epoch_members snapshot ON snapshot.epoch_id = epoch.id AND snapshot.member_id = member.id
 AND snapshot.migration_state = 'CURRENT'
WHERE plan.id = $16::uuid AND snapshot.share_index = $4::smallint AND snapshot.recovery_key_id = $6::text
  AND snapshot.recovery_key_fingerprint = $7::bytea`,
	}
	for index, statement := range statements {
		prepared, err := db.PrepareContext(ctx, statement)
		if err != nil {
			t.Fatalf("prepare detached provider proof statement %d: %v", index+1, err)
		}
		if err := prepared.Close(); err != nil {
			t.Fatalf("close detached provider proof statement %d: %v", index+1, err)
		}
	}
}

func assertPhase2HTypedAccountStatementsPrepare(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO recovery_plan_resource_accounts (
plan_id, resource_account_id, pool_id, account_external_id, provider, provider_account_ref,
inventory_version, provider_key_ref, attestation_digest, provider_binding, control_evidence_external_id,
control_attestation_digest, control_attestation_issuer, control_attestation_key_id,
control_attestation_version, control_attestation_algorithm, control_attestation_signature,
control_attestation_protocol_version, created_at)
SELECT $1, account.id, account.pool_id, account.external_id, account.provider, account.provider_account_ref,
account.inventory_version, account.provider_key_ref, account.attestation_digest, $2, $3, $4, $5, $6, $7, $8, $9, $10,
CURRENT_TIMESTAMP FROM pool_resource_accounts account
WHERE account.pool_id = $11 AND account.status = 'ACTIVE' AND account.external_id = $12
  AND account.provider_account_ref = $13`,
		`INSERT INTO recovery_control_evidence (
external_id, integration_operation_id, plan_id, resource_account_id, provider_attestation_ref,
provider_attestation_digest, provider_attestation_issuer, provider_attestation_key_id,
provider_attestation_version, provider_attestation_algorithm, provider_attestation_signature,
provider_attestation_protocol_version, ceremony_type, attestation_purpose, status, verified_at)
SELECT $1::text, $2::uuid, plan.id, account.resource_account_id, $3::text, $4::bytea,
       $5::text, $6::text, $7::bigint, $8::text, $9::bytea, $10::text,
       plan.ceremony_type, $11::text, 'VERIFIED', CURRENT_TIMESTAMP
FROM recovery_epoch_plans plan JOIN recovery_plan_resource_accounts account ON account.plan_id = plan.id
WHERE plan.id = $12::uuid AND plan.status = 'BATCHES_STAGED' AND account.account_external_id = $13::text
  AND account.control_evidence_external_id = $1::text AND account.control_attestation_digest = $4::bytea
  AND account.control_attestation_issuer = $5::text AND account.control_attestation_key_id = $6::text
  AND account.control_attestation_version = $7::bigint AND account.control_attestation_algorithm = $8::text
  AND account.control_attestation_signature = $9::bytea AND account.control_attestation_protocol_version = $10::text
RETURNING id, plan_id, resource_account_id`,
	}
	for index, statement := range statements {
		prepared, err := db.PrepareContext(ctx, statement)
		if err != nil {
			t.Fatalf("prepare typed account statement %d: %v", index+1, err)
		}
		if err := prepared.Close(); err != nil {
			t.Fatalf("close typed account statement %d: %v", index+1, err)
		}
	}
}

func assertPhase2HSQLRejected(t *testing.T, ctx context.Context, db *sql.DB, statement, reason string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, statement); err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("direct SQL was not rejected with %q: %v", reason, err)
	}
}

func readPhase2HSource(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func sqlTableDefinition(t *testing.T, source, table string) string {
	t.Helper()
	start := strings.Index(strings.ToLower(source), "create table "+strings.ToLower(table)+" (")
	if start < 0 {
		t.Fatalf("table %s not found", table)
	}
	remainder := source[start:]
	end := strings.Index(remainder, "\n);")
	if end < 0 {
		t.Fatalf("table %s definition is not closed", table)
	}
	return remainder[:end]
}

func sqlFunctionDefinition(t *testing.T, source, function string) string {
	t.Helper()
	start := strings.Index(strings.ToLower(source), "create or replace function "+strings.ToLower(function)+"()")
	if start < 0 {
		t.Fatalf("function %s not found", function)
	}
	remainder := source[start:]
	end := strings.Index(remainder, "$$;")
	if end < 0 {
		t.Fatalf("function %s definition is not closed", function)
	}
	return remainder[:end]
}
