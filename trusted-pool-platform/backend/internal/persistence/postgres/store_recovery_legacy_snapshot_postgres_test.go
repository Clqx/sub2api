package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

func TestBeginRecoverySeatOperationReplaysLegacySnapshotWithTypedManagerIntent(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_legacy_seat_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create legacy Seat schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer db.Close()
	if err := Migrate(ctx, db, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for legacy Seat replay: %v", err)
	}

	request := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "legacy-seat-child", PlanID: "legacy-seat-plan",
		CeremonyType: recovery.CeremonyBootstrap, PoolID: "legacy-seat-pool",
		FromEpoch: 1, ToEpoch: 2, SeatID: "legacy-seat",
		TargetMemberID: "legacy-seat-target", ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 5101, SubscriptionID: 5201, APIKeyID: 5301,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	request.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(request)
	typedRaw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	typedCanonical, err := canonicalJSONObject(typedRaw)
	if err != nil {
		t.Fatal(err)
	}
	legacyRaw, err := json.Marshal(map[string]any{
		"protocol_version": "trusted-pool/permanent-seat-prepare/v1",
		"plan_id":          request.PlanID,
		"pool_id":          request.PoolID, "seat_id": request.SeatID,
		"target_member_id": request.TargetMemberID,
		"from_epoch":       request.FromEpoch, "to_epoch": request.ToEpoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyCanonical, err := canonicalJSONObject(legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legacyCanonical, typedCanonical) ||
		!seatPrepareSnapshotBindsRequest(typedCanonical, request.RequestHash, request) ||
		!seatPrepareSnapshotBindsRequest(legacyCanonical, request.RequestHash, request) {
		t.Fatal("test fixture does not represent two protocol shapes bound to one request")
	}

	var poolID, seatID string
	if err := db.QueryRowContext(ctx, `INSERT INTO pools (
external_id, name, status, member_limit, membership_epoch, credential_epoch_floor
) VALUES ($1,'Legacy Seat Replay','DRAFT',2,1,1) RETURNING id`,
		request.PoolID).Scan(&poolID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO seats (
external_id, pool_id, seat_no, status, assignment_epoch, active_api_key_version
) VALUES ($1,$2,1,'PROVISIONING',1,1) RETURNING id`,
		request.SeatID, poolID).Scan(&seatID); err != nil {
		t.Fatal(err)
	}
	const clientID = "legacy-seat-client"
	const oldFence = int64(4)
	if _, err := db.ExecContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count
) VALUES ($1,$2,'PREPARE_PERMANENT_REPLACEMENT','SEAT',$3,$4,'CURRENT',$5,$6::jsonb,
'RUNNING',$7,'legacy-worker',CURRENT_TIMESTAMP - interval '1 second',1)`,
		clientID, request.OperationID, seatID, request.SeatID, request.RequestHash[:],
		legacyCanonical, oldFence); err != nil {
		t.Fatalf("insert legacy Seat operation: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	op, created, err := beginRecoverySeatOperation(ctx, tx,
		recovery.OperationKey{ClientID: clientID, OperationID: request.OperationID},
		request.SeatID, "PREPARE_PERMANENT_REPLACEMENT", request.RequestHash,
		typedCanonical, request, "typed-manager", oldFence, 30*time.Second)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("typed Manager could not replay legacy Seat operation: %v", err)
	}
	if created || op.FencingToken != oldFence+1 || op.LeaseOwner != "typed-manager" ||
		op.AttemptCount != 2 {
		_ = tx.Rollback()
		t.Fatalf("unexpected legacy replay result: created=%t operation=%+v", created, op)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit legacy Seat replay: %v", err)
	}

	var storedSnapshot []byte
	var storedFence int64
	var storedOwner string
	var storedAttempts int
	if err := db.QueryRowContext(ctx, `SELECT request_snapshot::text, fencing_token,
lease_owner, attempt_count FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, clientID, request.OperationID).
		Scan(&storedSnapshot, &storedFence, &storedOwner, &storedAttempts); err != nil {
		t.Fatal(err)
	}
	storedCanonical, err := canonicalJSONObject(storedSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedCanonical, legacyCanonical) || bytes.Equal(storedCanonical, typedCanonical) ||
		storedFence != oldFence+1 || storedOwner != "typed-manager" || storedAttempts != 2 {
		t.Fatalf("legacy intent was rewritten or lease state drifted: fence=%d owner=%s attempts=%d snapshot=%s",
			storedFence, storedOwner, storedAttempts, storedCanonical)
	}

	if _, err := db.ExecContext(ctx, `UPDATE integration_operations SET
lease_expires_at=CURRENT_TIMESTAMP - interval '1 second', version=version+1,
updated_at=CURRENT_TIMESTAMP WHERE integration_client_id=$1 AND operation_id=$2`,
		clientID, request.OperationID); err != nil {
		t.Fatalf("expire replay lease: %v", err)
	}
	driftedRequest := request
	driftedRequest.SubscriptionID++
	driftedRequest.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(driftedRequest)
	driftedRaw, err := json.Marshal(driftedRequest)
	if err != nil {
		t.Fatal(err)
	}
	driftedCanonical, err := canonicalJSONObject(driftedRaw)
	if err != nil {
		t.Fatal(err)
	}
	driftTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, created, replayErr := beginRecoverySeatOperation(ctx, driftTx,
		recovery.OperationKey{ClientID: clientID, OperationID: request.OperationID},
		request.SeatID, "PREPARE_PERMANENT_REPLACEMENT", request.RequestHash,
		driftedCanonical, driftedRequest, "drifted-manager", storedFence, 30*time.Second)
	_ = driftTx.Rollback()
	if created || !errors.Is(replayErr, recovery.ErrHashDrift) {
		t.Fatalf("legacy replay accepted full-request drift: created=%t err=%v", created, replayErr)
	}
}

func TestStoreBeginSeatRotationReplaysLegacySnapshotThroughPublicWorkflow(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_public_legacy_seat_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create public legacy Seat schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer db.Close()
	through010, through011 := phase2HProtocolCompatibilityMigrationSets(t)
	if err := Migrate(ctx, db, through010); err != nil {
		t.Fatalf("apply migrations through 010: %v", err)
	}
	assertMigrationLedgerState(t, ctx, db, 10, "010_phase2h_offline_verification.sql")
	insertPublicLegacySeatReadyFixture(t, ctx, db)

	request := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "public-legacy-seat-child", PlanID: "public-legacy-plan",
		CeremonyType: recovery.CeremonyBootstrap, PoolID: "public-legacy-pool",
		FromEpoch: 1, ToEpoch: 2, SeatID: "public-legacy-seat",
		TargetMemberID: "public-legacy-target", ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 6101, SubscriptionID: 6201, APIKeyID: 6301,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	request.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(request)
	typedSnapshot, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	legacySnapshot, err := json.Marshal(map[string]any{
		"protocol_version": "trusted-pool/permanent-seat-prepare/v1",
		"plan_id":          request.PlanID,
		"pool_id":          request.PoolID, "seat_id": request.SeatID,
		"target_member_id": request.TargetMemberID,
		"from_epoch":       request.FromEpoch, "to_epoch": request.ToEpoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	typedCanonical, err := canonicalJSONObject(typedSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	legacyCanonical, err := canonicalJSONObject(legacySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(typedCanonical, legacyCanonical) {
		t.Fatal("public replay fixture does not contain distinct typed and legacy protocol shapes")
	}

	parentKey := recovery.OperationKey{
		ClientID: "public-legacy-client", OperationID: "public-legacy-finalization",
	}
	const legacyOwner = "legacy-seat-worker"
	const legacyFence = int64(1)
	insertPhase2HLegacySeatOperation(t, ctx, db, parentKey.ClientID, request,
		legacyCanonical, legacyOwner, legacyFence)
	beforeUpgrade := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID)
	if err := Migrate(ctx, db, through011); err != nil {
		t.Fatalf("upgrade migration ledger from 010 to 011: %v", err)
	}
	assertMigrationLedgerState(t, ctx, db, 11,
		"011_phase2h_recovery_protocol_compatibility.sql")
	var compatibilityMarker bool
	if err := db.QueryRowContext(ctx, `SELECT legacy_snapshot_compatibility_phase2h
FROM integration_operations
WHERE integration_client_id=$1 AND operation_id=$2`, parentKey.ClientID,
		request.OperationID).Scan(&compatibilityMarker); err != nil {
		t.Fatalf("load pre-011 compatibility marker: %v", err)
	}
	if !compatibilityMarker {
		t.Fatal("011 did not mark the pre-existing legacy operation")
	}
	if _, err := db.ExecContext(ctx, `UPDATE integration_operations
SET legacy_snapshot_compatibility_phase2h=FALSE
WHERE integration_client_id=$1 AND operation_id=$2`, parentKey.ClientID,
		request.OperationID); err == nil ||
		!strings.Contains(err.Error(), "pre-011 operation compatibility marker is immutable") {
		t.Fatalf("011 compatibility marker accepted a post-migration change: %v", err)
	}
	if afterUpgrade := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID); afterUpgrade != beforeUpgrade {
		t.Fatalf("011 rewrote the pre-existing legacy operation: before=%+v after=%+v",
			beforeUpgrade, afterUpgrade)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	input := recovery.BeginSeatRotationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, SeatExternalID: request.SeatID,
		DerivedOperationID: request.OperationID, RequestHash: request.RequestHash,
		RequestSnapshot: typedSnapshot, ChildLeaseOwner: "typed-seat-worker",
		ExpectedChildFencingToken: legacyFence, ChildLeaseDuration: 30 * time.Second,
	}

	result, err := db.ExecContext(ctx, `UPDATE integration_operations SET
lease_expires_at=CURRENT_TIMESTAMP - interval '1 second', version=version+1,
updated_at=CURRENT_TIMESTAMP
WHERE integration_client_id=$1 AND operation_id=$2 AND lease_owner=$3 AND fencing_token=$4`,
		parentKey.ClientID, request.OperationID, legacyOwner, legacyFence)
	if err != nil {
		t.Fatalf("expire public legacy Seat child lease: %v", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		t.Fatalf("expire public legacy Seat child lease affected=%d err=%v", affected, affectedErr)
	}
	before := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID)

	wrongHashInput := input
	wrongHashInput.RequestSnapshot = typedSnapshot
	wrongHashInput.RequestHash[0] ^= 0xff
	wrongHashInput.ChildLeaseOwner = "wrong-hash-worker"
	wrongHashInput.ExpectedChildFencingToken = legacyFence
	if _, created, err := store.BeginSeatRotation(ctx, wrongHashInput); created ||
		!errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("public replay accepted wrong outer hash: created=%t err=%v", created, err)
	}
	if after := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID); after != before {
		t.Fatalf("wrong outer hash changed public aggregate: before=%+v after=%+v", before, after)
	}

	driftedRequest := request
	driftedRequest.SubscriptionID++
	driftedSnapshot, err := json.Marshal(driftedRequest)
	if err != nil {
		t.Fatal(err)
	}
	driftedInput := input
	driftedInput.RequestSnapshot = driftedSnapshot
	driftedInput.ChildLeaseOwner = "field-drift-worker"
	driftedInput.ExpectedChildFencingToken = legacyFence
	if _, created, err := store.BeginSeatRotation(ctx, driftedInput); created ||
		!errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("public replay accepted typed field drift: created=%t err=%v", created, err)
	}
	if after := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID); after != before {
		t.Fatalf("typed field drift changed public aggregate: before=%+v after=%+v", before, after)
	}

	typedInput := input
	target, created, err := store.BeginSeatRotation(ctx, typedInput)
	if err != nil || created || target == nil || target.Operation == nil || target.Progress == nil ||
		target.Operation.FencingToken != 2 || target.Operation.LeaseOwner != typedInput.ChildLeaseOwner ||
		target.Progress.Status != "PREPARE_PENDING" || target.Progress.AttemptCount != 2 {
		t.Fatalf("typed public replay could not take over legacy child: target=%+v created=%t err=%v",
			target, created, err)
	}
	after := loadPublicLegacySeatReplayState(t, ctx, db, parentKey.ClientID, request.OperationID)
	storedCanonical, err := canonicalJSONObject([]byte(after.requestSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedCanonical, legacyCanonical) || bytes.Equal(storedCanonical, typedCanonical) ||
		after.requestHash != fmt.Sprintf("%x", request.RequestHash[:]) ||
		after.operationStatus != "RUNNING" || after.leaseOwner != typedInput.ChildLeaseOwner ||
		after.fencingToken != 2 || after.operationAttempts != 2 || after.operationVersion != 3 ||
		after.progressStatus != "PREPARE_PENDING" || after.progressAttempts != 2 ||
		after.caseStatus != "ROTATING" || after.caseVersion != 2 {
		t.Fatalf("unexpected public legacy replay state: %+v", after)
	}
}

func TestStoreTypedManagerSnapshotReachesPoolActivationThroughPublicWorkflow(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PHASE2H_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PHASE2H_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("phase2h_public_typed_seat_%x", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create public typed Seat schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`)
	}()

	db := openRecoveryFenceConnection(t, ctx, dsn, schema)
	defer db.Close()
	if err := Migrate(ctx, db, os.DirFS(filepath.Clean("../../../../migrations"))); err != nil {
		t.Fatalf("apply migrations for public typed Seat workflow: %v", err)
	}
	insertPublicLegacySeatReadyFixture(t, ctx, db)
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	parentKey := recovery.OperationKey{
		ClientID: "public-legacy-client", OperationID: "public-legacy-finalization",
	}
	seatRequest := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "public-typed-seat-child", PlanID: "public-legacy-plan",
		CeremonyType: recovery.CeremonyBootstrap, PoolID: "public-legacy-pool",
		FromEpoch: 1, ToEpoch: 2, SeatID: "public-legacy-seat",
		TargetMemberID: "public-legacy-target", ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 6101, SubscriptionID: 6201, APIKeyID: 6301,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	seatRequest.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(seatRequest)
	seatSnapshot, err := json.Marshal(seatRequest)
	if err != nil {
		t.Fatal(err)
	}
	legacySeatSnapshot, err := json.Marshal(map[string]any{
		"protocol_version": "trusted-pool/permanent-seat-prepare/v1",
		"plan_id":          seatRequest.PlanID,
		"pool_id":          seatRequest.PoolID,
		"seat_id":          seatRequest.SeatID,
		"target_member_id": seatRequest.TargetMemberID,
		"from_epoch":       seatRequest.FromEpoch,
		"to_epoch":         seatRequest.ToEpoch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.BeginSeatRotation(ctx, recovery.BeginSeatRotationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, SeatExternalID: seatRequest.SeatID,
		DerivedOperationID: seatRequest.OperationID, RequestHash: seatRequest.RequestHash,
		RequestSnapshot: legacySeatSnapshot, ChildLeaseOwner: "legacy-create-worker",
		ExpectedChildFencingToken: 0, ChildLeaseDuration: 30 * time.Second,
	}); created || !errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("post-011 Store accepted a new legacy Seat snapshot: created=%t err=%v", created, err)
	}
	assertPublicRotationOperationAbsent(t, ctx, db, parentKey.ClientID,
		seatRequest.OperationID, "seat")
	assertPost011LegacySeatProgressRejected(t, ctx, db, parentKey.ClientID,
		seatRequest, legacySeatSnapshot)
	assertPublicRotationOperationAbsent(t, ctx, db, parentKey.ClientID,
		seatRequest.OperationID, "seat")
	var replacementStatus string
	if err := db.QueryRowContext(ctx, `SELECT replacement.status
FROM permanent_replacement_cases replacement
JOIN integration_operations operation ON operation.id=replacement.integration_operation_id
WHERE operation.integration_client_id=$1 AND operation.operation_id=$2`,
		parentKey.ClientID, parentKey.OperationID).Scan(&replacementStatus); err != nil {
		t.Fatal(err)
	}
	if replacementStatus != "READY" {
		t.Fatalf("rejected post-011 legacy create changed replacement status to %s", replacementStatus)
	}
	seatTarget, created, err := store.BeginSeatRotation(ctx, recovery.BeginSeatRotationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, SeatExternalID: seatRequest.SeatID,
		DerivedOperationID: seatRequest.OperationID, RequestHash: seatRequest.RequestHash,
		RequestSnapshot: seatSnapshot, ChildLeaseOwner: "typed-seat-worker",
		ExpectedChildFencingToken: 0, ChildLeaseDuration: 30 * time.Second,
	})
	if err != nil || !created || seatTarget == nil || seatTarget.Operation == nil ||
		seatTarget.Progress == nil || seatTarget.Progress.Status != "PREPARE_PENDING" {
		t.Fatalf("typed Manager Seat snapshot did not reach public Store: target=%+v created=%t err=%v",
			seatTarget, created, err)
	}
	var newOperationCompatibilityMarker bool
	if err := db.QueryRowContext(ctx, `SELECT legacy_snapshot_compatibility_phase2h
FROM integration_operations WHERE integration_client_id=$1 AND operation_id=$2`,
		parentKey.ClientID, seatRequest.OperationID).Scan(&newOperationCompatibilityMarker); err != nil {
		t.Fatalf("load post-011 operation compatibility marker: %v", err)
	}
	if newOperationCompatibilityMarker {
		t.Fatal("post-011 typed operation inherited legacy compatibility")
	}

	childSetHash, err := recovery.PermanentRotationChildSetHash(
		[]recovery.PermanentSeatRotationPrepareRequest{seatRequest})
	if err != nil {
		t.Fatal(err)
	}
	poolRequest := recovery.PermanentPoolRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "public-typed-pool-prepare", PlanID: seatRequest.PlanID,
		CeremonyType: seatRequest.CeremonyType, PoolID: seatRequest.PoolID,
		FromEpoch: seatRequest.FromEpoch, ToEpoch: seatRequest.ToEpoch,
		ChildSetHash: childSetHash,
		Seats:        []recovery.PermanentSeatRotationPrepareRequest{seatRequest},
	}
	poolRequest.RequestHash = recovery.PermanentPoolRotationPrepareRequestHash(poolRequest)
	poolSnapshot := publicRotationSnapshot(t, poolRequest, "child_set_hash", childSetHash)
	driftedPoolRequest := poolRequest
	driftedPoolRequest.Seats = append([]recovery.PermanentSeatRotationPrepareRequest(nil), poolRequest.Seats...)
	driftedPoolRequest.Seats[0].SeatID = "public-drift-seat"
	driftedPoolSnapshot := publicRotationSnapshot(t, driftedPoolRequest, "child_set_hash", childSetHash)
	if _, created, err = store.BeginPoolPreparation(ctx, recovery.BeginPoolPreparationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, DerivedOperationID: poolRequest.OperationID,
		RequestHash: poolRequest.RequestHash, RequestSnapshot: driftedPoolSnapshot,
		LeaseOwner: "drifted-pool-worker", ExpectedFencingToken: 0, LeaseDuration: 30 * time.Second,
	}); created || !errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("public Pool preparation accepted nested Seat drift: created=%t err=%v", created, err)
	}
	assertPublicRotationOperationAbsent(t, ctx, db, parentKey.ClientID,
		poolRequest.OperationID, "preparation")
	preparation, created, err := store.BeginPoolPreparation(ctx, recovery.BeginPoolPreparationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, DerivedOperationID: poolRequest.OperationID,
		RequestHash: poolRequest.RequestHash, RequestSnapshot: poolSnapshot,
		LeaseOwner: "typed-pool-worker", ExpectedFencingToken: 0, LeaseDuration: 30 * time.Second,
	})
	if err != nil || !created || preparation == nil || preparation.Operation == nil ||
		preparation.Operation.Status != "RUNNING" || preparation.Operation.FencingToken != 1 ||
		preparation.Operation.LeaseOwner != "typed-pool-worker" ||
		preparation.IntentSetHash != childSetHash {
		t.Fatalf("typed Manager Pool preparation did not reach public Store: target=%+v created=%t err=%v",
			preparation, created, err)
	}
	var attemptStatus string
	if err := db.QueryRowContext(ctx, `SELECT attempt.status
FROM recovery_pool_preparation_attempts attempt
JOIN integration_operations operation ON operation.id=attempt.integration_operation_id
WHERE operation.integration_client_id=$1 AND operation.operation_id=$2`,
		parentKey.ClientID, poolRequest.OperationID).Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "PENDING" {
		t.Fatalf("typed Pool preparation attempt status=%s", attemptStatus)
	}

	credentialFingerprint := sha256.Sum256([]byte("public-typed-credential"))
	providerResultDigest := sha256.Sum256([]byte("public-typed-provider-result"))
	envelopeAADHash := sha256.Sum256(recovery.ReplacementCredentialClaimAAD(
		parentKey.ClientID, seatRequest.PlanID, seatRequest.OperationID, seatRequest.SeatID,
		seatRequest.TargetMemberID, seatRequest.RequestHash, credentialFingerprint))
	preparedReference := "public-typed-prepared-reference"
	progress, err := store.CommitSeatRotationProgress(ctx, recovery.CommitSeatRotationProgressInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, ChildLeaseOwner: "typed-seat-worker",
		ChildFencingToken: seatTarget.Operation.FencingToken,
		PreparationKey: recovery.OperationKey{
			ClientID: parentKey.ClientID, OperationID: poolRequest.OperationID,
		},
		PreparationLeaseOwner:   "typed-pool-worker",
		PreparationFencingToken: preparation.Operation.FencingToken,
		PreparationSetHash:      childSetHash,
		SeatExternalID:          seatRequest.SeatID,
		DerivedOperationID:      seatRequest.OperationID,
		Status:                  "PREPARED",
		PrincipalUserID:         seatRequest.PrincipalUserID,
		SubscriptionID:          seatRequest.SubscriptionID,
		APIKeyID:                seatRequest.APIKeyID,
		APIKeyVersion:           seatRequest.ToAPIKeyVersion,
		Claim: &recovery.ReplacementCredentialClaim{
			SeatExternalID: seatRequest.SeatID, TargetMemberExternalID: seatRequest.TargetMemberID,
			PreparedReference: preparedReference, ProviderResultDigest: providerResultDigest,
			CredentialFingerprint: credentialFingerprint, EnvelopeAlgorithm: "AES-256-GCM",
			EnvelopeKeyRef: "kms/public-typed", EnvelopeCiphertext: []byte{1, 2, 3},
			EnvelopeNonce:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			EnvelopeAADHash: envelopeAADHash, WrappedDEK: []byte{4, 5, 6},
		},
	})
	if err != nil || progress == nil || progress.Status != "PREPARED" ||
		progress.PreparedReference != preparedReference ||
		progress.CredentialFingerprint != credentialFingerprint {
		t.Fatalf("commit typed Seat preparation: progress=%+v err=%v", progress, err)
	}

	binding := recovery.PermanentSeatActivationBinding{
		SeatID: seatRequest.SeatID, TargetMemberID: seatRequest.TargetMemberID,
		ExpectedAssignmentEpoch: seatRequest.ExpectedAssignmentEpoch,
		PrincipalUserID:         seatRequest.PrincipalUserID, SubscriptionID: seatRequest.SubscriptionID,
		APIKeyID: seatRequest.APIKeyID, ActiveAPIKeyVersion: seatRequest.ToAPIKeyVersion,
		ChildOperationID: seatRequest.OperationID, ChildRequestHash: seatRequest.RequestHash,
		CredentialFingerprint: credentialFingerprint, PreparedRotationRef: preparedReference,
	}
	preparedSetHash, err := recovery.PermanentPreparedSeatSetHash(
		[]recovery.PermanentSeatActivationBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	activationRequest := recovery.PermanentPoolRotationActivateRequest{
		ProtocolVersion:    recovery.PermanentSeatRotationProtocolV1,
		OperationID:        "public-typed-pool-activation",
		PrepareOperationID: poolRequest.OperationID, PlanID: seatRequest.PlanID,
		CeremonyType: seatRequest.CeremonyType, PoolID: seatRequest.PoolID,
		FromEpoch: seatRequest.FromEpoch, ToEpoch: seatRequest.ToEpoch,
		PreparedSetHash: preparedSetHash,
		Seats:           []recovery.PermanentSeatActivationBinding{binding},
	}
	activationRequest.RequestHash = recovery.PermanentPoolRotationActivateRequestHash(activationRequest)
	activationSnapshot := publicRotationSnapshot(t, activationRequest,
		"prepared_set_hash", preparedSetHash)
	driftedActivationRequest := activationRequest
	driftedActivationRequest.Seats = append([]recovery.PermanentSeatActivationBinding(nil), activationRequest.Seats...)
	driftedActivationRequest.Seats[0].PreparedRotationRef =
		preparedReference[:len(preparedReference)-1] + "X"
	driftedActivationSnapshot := publicRotationSnapshot(t, driftedActivationRequest,
		"prepared_set_hash", preparedSetHash)
	if _, created, err = store.BeginPoolActivation(ctx, recovery.BeginPoolActivationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, DerivedOperationID: activationRequest.OperationID,
		RequestHash: activationRequest.RequestHash, RequestSnapshot: driftedActivationSnapshot,
		ChildLeaseOwner: "drifted-activation-worker", ExpectedChildFencingToken: 0,
		ChildLeaseDuration: 30 * time.Second,
	}); created || !errors.Is(err, recovery.ErrBindingMismatch) {
		t.Fatalf("public Pool activation accepted nested Seat drift: created=%t err=%v", created, err)
	}
	assertPublicRotationOperationAbsent(t, ctx, db, parentKey.ClientID,
		activationRequest.OperationID, "activation")
	activation, created, err := store.BeginPoolActivation(ctx, recovery.BeginPoolActivationInput{
		FinalizationKey: parentKey, FinalizationLeaseOwner: "public-legacy-finalizer",
		FinalizationFencingToken: 11, DerivedOperationID: activationRequest.OperationID,
		RequestHash: activationRequest.RequestHash, RequestSnapshot: activationSnapshot,
		ChildLeaseOwner: "typed-activation-worker", ExpectedChildFencingToken: 0,
		ChildLeaseDuration: 30 * time.Second,
	})
	if err != nil || !created || activation == nil || activation.Operation == nil ||
		activation.Operation.Status != "RUNNING" || activation.Operation.FencingToken != 1 ||
		activation.Operation.LeaseOwner != "typed-activation-worker" ||
		activation.PreparedSetHash != preparedSetHash {
		t.Fatalf("typed Manager Pool activation did not reach public Store: target=%+v created=%t err=%v",
			activation, created, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT attempt.status
FROM recovery_pool_activation_attempts attempt
JOIN integration_operations operation ON operation.id=attempt.integration_operation_id
WHERE operation.integration_client_id=$1 AND operation.operation_id=$2`,
		parentKey.ClientID, activationRequest.OperationID).Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "PENDING" {
		t.Fatalf("typed Pool activation attempt status=%s", attemptStatus)
	}
}

func phase2HProtocolCompatibilityMigrationSets(t *testing.T) (fstest.MapFS, fstest.MapFS) {
	t.Helper()
	migrationDir := filepath.Clean("../../../../migrations")
	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		t.Fatalf("read Phase 2H migrations: %v", err)
	}
	through010 := fstest.MapFS{}
	through011 := fstest.MapFS{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".sql" || len(name) < 4 || name[3] != '_' {
			continue
		}
		if name[:3] > "011" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(migrationDir, name))
		if readErr != nil {
			t.Fatalf("read migration %s: %v", name, readErr)
		}
		through011[name] = &fstest.MapFile{Data: raw}
		if name[:3] <= "010" {
			through010[name] = &fstest.MapFile{Data: raw}
		}
	}
	if len(through010) != 10 || len(through011) != 11 {
		t.Fatalf("unexpected Phase 2H migration set: through010=%d through011=%d",
			len(through010), len(through011))
	}
	return through010, through011
}

func assertMigrationLedgerState(t *testing.T, ctx context.Context, db *sql.DB,
	wantCount int, wantLatest string) {
	t.Helper()
	var count int
	var latest string
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(version)
FROM trusted_pool_schema_migrations`).Scan(&count, &latest); err != nil {
		t.Fatalf("read migration ledger: %v", err)
	}
	if count != wantCount || latest != wantLatest {
		t.Fatalf("unexpected migration ledger: count=%d latest=%s", count, latest)
	}
}

func insertPhase2HLegacySeatOperation(t *testing.T, ctx context.Context, db *sql.DB,
	clientID string, request recovery.PermanentSeatRotationPrepareRequest, snapshot []byte,
	leaseOwner string, fence int64) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases
SET status='ROTATING', version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE external_id='public-legacy-case' AND status='READY'`)
	if err != nil {
		t.Fatalf("mark pre-011 replacement rotating: %v", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		t.Fatalf("mark pre-011 replacement rotating affected=%d err=%v", affected, affectedErr)
	}
	var operationID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count)
SELECT $1,$2,'PREPARE_PERMANENT_REPLACEMENT','SEAT',seat.id,seat.external_id,
'CURRENT',$3,$4::jsonb,'RUNNING',$5,$6,CURRENT_TIMESTAMP+interval '5 minutes',1
FROM seats seat WHERE seat.external_id=$7 RETURNING id`, clientID, request.OperationID,
		request.RequestHash[:], snapshot, fence, leaseOwner, request.SeatID).Scan(&operationID); err != nil {
		t.Fatalf("insert pre-011 legacy Seat operation: %v", err)
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO recovery_seat_rotation_progress (
plan_id,seat_id,derived_operation_id,status,attempt_count)
SELECT plan.id,seat.id,$1,'PREPARE_PENDING',1
FROM recovery_epoch_plans plan JOIN seats seat ON seat.external_id=$2
WHERE plan.external_id=$3`, operationID, request.SeatID, request.PlanID)
	if err != nil {
		t.Fatalf("insert pre-011 legacy Seat progress: %v", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		t.Fatalf("insert pre-011 legacy Seat progress affected=%d err=%v", affected, affectedErr)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit pre-011 legacy Seat operation: %v", err)
	}
}

func assertPost011LegacySeatProgressRejected(t *testing.T, ctx context.Context, db *sql.DB,
	clientID string, request recovery.PermanentSeatRotationPrepareRequest, snapshot []byte) {
	t.Helper()
	_, err := db.ExecContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count, created_at, legacy_snapshot_compatibility_phase2h)
SELECT $1,$2,'PREPARE_PERMANENT_REPLACEMENT','SEAT',seat.id,seat.external_id,
'CURRENT',$3,$4::jsonb,'RUNNING',1,'forged-legacy-worker',CURRENT_TIMESTAMP+interval '5 minutes',1,
CURRENT_TIMESTAMP-interval '1 year',TRUE
FROM seats seat WHERE seat.external_id=$5`, clientID, request.OperationID,
		request.RequestHash[:], snapshot, request.SeatID)
	if err == nil || !strings.Contains(err.Error(),
		"new integration operation cannot claim pre-011 compatibility") {
		t.Fatalf("post-011 operation forged legacy compatibility: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE permanent_replacement_cases
SET status='ROTATING', version=version+1, updated_at=CURRENT_TIMESTAMP
WHERE external_id='public-legacy-case' AND status='READY'`)
	if err != nil {
		t.Fatalf("mark post-011 replacement rotating: %v", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		t.Fatalf("mark post-011 replacement rotating affected=%d err=%v", affected, affectedErr)
	}
	var operationID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO integration_operations (
integration_client_id, operation_id, operation_type, target_type, target_id, target_external_id,
migration_state, request_hash, request_snapshot, status, fencing_token, lease_owner,
lease_expires_at, attempt_count, created_at)
SELECT $1,$2,'PREPARE_PERMANENT_REPLACEMENT','SEAT',seat.id,seat.external_id,
'CURRENT',$3,$4::jsonb,'RUNNING',1,'post-011-legacy-worker',CURRENT_TIMESTAMP+interval '5 minutes',1,
CURRENT_TIMESTAMP-interval '1 year'
FROM seats seat WHERE seat.external_id=$5 RETURNING id`, clientID, request.OperationID,
		request.RequestHash[:], snapshot, request.SeatID).Scan(&operationID); err != nil {
		t.Fatalf("insert post-011 legacy Seat operation fixture: %v", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO recovery_seat_rotation_progress (
plan_id,seat_id,derived_operation_id,status,attempt_count)
SELECT plan.id,seat.id,$1,'PREPARE_PENDING',1
FROM recovery_epoch_plans plan JOIN seats seat ON seat.external_id=$2
WHERE plan.external_id=$3`, operationID, request.SeatID, request.PlanID)
	if err == nil {
		t.Fatal("011 trigger accepted a newly inserted legacy Seat snapshot")
	}
	if !strings.Contains(err.Error(), "prepare progress lacks exact leased child operation") {
		t.Fatalf("post-011 legacy Seat insert failed for an unexpected reason: %v", err)
	}
}

func publicRotationSnapshot(t *testing.T, request any, hashField string,
	setHash [sha256.Size]byte) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	object[hashField] = fmt.Sprintf("%x", setHash[:])
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertPublicRotationOperationAbsent(t *testing.T, ctx context.Context, db *sql.DB,
	clientID, operationID, attemptKind string) {
	t.Helper()
	var query string
	switch attemptKind {
	case "seat":
		query = `SELECT
  (SELECT count(*) FROM integration_operations
   WHERE integration_client_id=$1 AND operation_id=$2),
  (SELECT count(*) FROM recovery_seat_rotation_progress progress
   JOIN integration_operations operation ON operation.id=progress.derived_operation_id
   WHERE operation.integration_client_id=$1 AND operation.operation_id=$2)`
	case "preparation":
		query = `SELECT
  (SELECT count(*) FROM integration_operations
   WHERE integration_client_id=$1 AND operation_id=$2),
  (SELECT count(*) FROM recovery_pool_preparation_attempts attempt
   JOIN integration_operations operation ON operation.id=attempt.integration_operation_id
   WHERE operation.integration_client_id=$1 AND operation.operation_id=$2)`
	case "activation":
		query = `SELECT
  (SELECT count(*) FROM integration_operations
   WHERE integration_client_id=$1 AND operation_id=$2),
  (SELECT count(*) FROM recovery_pool_activation_attempts attempt
   JOIN integration_operations operation ON operation.id=attempt.integration_operation_id
   WHERE operation.integration_client_id=$1 AND operation.operation_id=$2)`
	default:
		t.Fatalf("unknown public rotation attempt kind %q", attemptKind)
	}
	var operationCount, attemptCount int64
	if err := db.QueryRowContext(ctx, query, clientID, operationID).
		Scan(&operationCount, &attemptCount); err != nil {
		t.Fatalf("load rejected public %s operation: %v", attemptKind, err)
	}
	if operationCount != 0 || attemptCount != 0 {
		t.Fatalf("rejected public %s operation persisted state: operations=%d attempts=%d",
			attemptKind, operationCount, attemptCount)
	}
}

type publicLegacySeatReplayState struct {
	requestHash, requestSnapshot, operationStatus, leaseOwner string
	progressStatus, caseStatus, leaseExpiry                   string
	fencingToken, operationAttempts, operationVersion         int64
	progressAttempts, caseVersion                             int64
}

func loadPublicLegacySeatReplayState(t *testing.T, ctx context.Context, db *sql.DB,
	clientID, operationID string) publicLegacySeatReplayState {
	t.Helper()
	var state publicLegacySeatReplayState
	if err := db.QueryRowContext(ctx, `SELECT encode(child.request_hash,'hex'),
child.request_snapshot::text, child.status, COALESCE(child.lease_owner,''),
COALESCE(child.lease_expires_at::text,''), child.fencing_token, child.attempt_count, child.version,
progress.status, progress.attempt_count, replacement.status, replacement.version
FROM integration_operations child
JOIN recovery_seat_rotation_progress progress ON progress.derived_operation_id=child.id
JOIN permanent_replacement_cases replacement ON replacement.plan_id=progress.plan_id
WHERE child.integration_client_id=$1 AND child.operation_id=$2`, clientID, operationID).
		Scan(&state.requestHash, &state.requestSnapshot, &state.operationStatus, &state.leaseOwner,
			&state.leaseExpiry, &state.fencingToken, &state.operationAttempts, &state.operationVersion,
			&state.progressStatus, &state.progressAttempts, &state.caseStatus, &state.caseVersion); err != nil {
		t.Fatal(err)
	}
	return state
}

func insertPublicLegacySeatReadyFixture(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tables := []string{
		"integration_operations", "members", "pools", "seats", "seat_assignments",
		"suspension_cases", "membership_epochs", "recovery_epoch_plans",
		"recovery_plan_seats", "permanent_replacement_cases",
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
			t.Fatalf("disable %s public legacy fixture triggers: %v", table, err)
		}
	}
	statements := []string{
		`INSERT INTO members (id,external_id,sub2api_user_id,display_name,status) VALUES
('91000000-0000-0000-0000-000000000002','public-legacy-old',6001,'Public Legacy Old','ACTIVE'),
('91000000-0000-0000-0000-000000000003','public-legacy-target',6002,'Public Legacy Target','ACTIVE')`,
		`INSERT INTO pools (id,external_id,name,status,member_limit,membership_epoch,credential_epoch_floor)
VALUES ('91000000-0000-0000-0000-000000000001','public-legacy-pool',
'Public Legacy Pool','ACTIVE',2,1,1)`,
		`INSERT INTO seats (id,external_id,pool_id,seat_no,status,owner_member_id,assignment_epoch,
sub2api_principal_id,sub2api_subscription_id,sub2api_api_key_id,active_api_key_version,frozen_at)
VALUES ('91000000-0000-0000-0000-000000000004','public-legacy-seat',
'91000000-0000-0000-0000-000000000001',1,'FROZEN',
'91000000-0000-0000-0000-000000000002',1,6101,6201,6301,1,CURRENT_TIMESTAMP)`,
		`INSERT INTO seat_assignments (seat_id,pool_id,member_id,assignment_type,status,
assignment_epoch,starts_at) VALUES
('91000000-0000-0000-0000-000000000004','91000000-0000-0000-0000-000000000001',
'91000000-0000-0000-0000-000000000002','PERMANENT','ACTIVE',1,CURRENT_TIMESTAMP)`,
		`INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
response_snapshot,completed_at,fencing_token,attempt_count)
VALUES ('92000000-0000-0000-0000-000000000009','public-legacy-fixture',
'public-legacy-freeze','SUSPEND','SEAT','91000000-0000-0000-0000-000000000004',
'public-legacy-seat','CURRENT',decode(repeat('19',32),'hex'),'{"fixture":"freeze"}',
'SUCCEEDED','{"status":"frozen"}',CURRENT_TIMESTAMP,1,1)`,
		`INSERT INTO suspension_cases (id,seat_id,operation_id,status,reason_code,evidence_refs,
expected_assignment_epoch,blocked_at,frozen_at,freeze_snapshot,integration_operation_id,
migration_state,current_concurrency,pending_settlements,version)
VALUES ('91000000-0000-0000-0000-000000000010',
'91000000-0000-0000-0000-000000000004','public-legacy-freeze','FROZEN','RECOVERY','[]',
1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,
jsonb_build_object('in_flight',0,'pending_settlements',0,'captured_at',CURRENT_TIMESTAMP,
'usage',jsonb_build_object('hourly',0,'daily',0,'weekly',0,'monthly',0),
'window_starts',jsonb_build_object('hourly',NULL,'daily',NULL,'weekly',NULL,'monthly',NULL)),
'92000000-0000-0000-0000-000000000009','CURRENT',0,0,3)`,
		`INSERT INTO membership_epochs (id,pool_id,epoch,status,governance_threshold,recovery_threshold,
activated_at,recovery_governance_state) VALUES
('91000000-0000-0000-0000-000000000006','91000000-0000-0000-0000-000000000001',
1,'ACTIVE',1,1,CURRENT_TIMESTAMP,'LEGACY_UNVERIFIED'),
('91000000-0000-0000-0000-000000000007','91000000-0000-0000-0000-000000000001',
2,'PREPARING',1,1,NULL,'LEGACY_UNVERIFIED')`,
		`INSERT INTO integration_operations (id,integration_client_id,operation_id,operation_type,
target_type,target_id,target_external_id,migration_state,request_hash,request_snapshot,status,
fencing_token,lease_owner,lease_expires_at,attempt_count) VALUES
('92000000-0000-0000-0000-000000000003','public-legacy-client',
'public-legacy-ceremony','BOOTSTRAP_RECOVERY_EPOCH','POOL',
'91000000-0000-0000-0000-000000000001','public-legacy-pool','CURRENT',
decode(repeat('13',32),'hex'),'{"fixture":"ceremony"}','RUNNING',0,NULL,NULL,1),
('92000000-0000-0000-0000-000000000004','public-legacy-client',
'public-legacy-finalization','FINALIZE_RECOVERY_BOOTSTRAP','POOL',
'91000000-0000-0000-0000-000000000001','public-legacy-pool','CURRENT',
decode(repeat('14',32),'hex'),'{"fixture":"finalization"}','RUNNING',11,
'public-legacy-finalizer',CURRENT_TIMESTAMP+interval '5 minutes',1)`,
		`INSERT INTO recovery_epoch_plans (id,external_id,integration_operation_id,ceremony_type,
pool_id,from_epoch,to_epoch,status,governance_threshold,recovery_threshold,
required_share_ack_count,expected_member_count,expected_seat_count,expected_resource_count,
expected_control_batch_count,provider_attestation_set_hash,previous_manifest_hash,
from_epoch_status,from_governance_state,bootstrap_attestation_ref,
bootstrap_attestation_digest,bootstrap_attestation_issuer,bootstrap_attestation_key_id,
bootstrap_attestation_signature,bootstrap_attestation_version,ready_at,version)
VALUES ('91000000-0000-0000-0000-000000000005','public-legacy-plan',
'92000000-0000-0000-0000-000000000003','BOOTSTRAP',
'91000000-0000-0000-0000-000000000001',1,2,'READY',1,1,1,1,1,1,4,
decode(repeat('21',32),'hex'),decode(repeat('00',32),'hex'),'ACTIVE','LEGACY_UNVERIFIED',
'public-legacy-bootstrap',decode(repeat('22',32),'hex'),'public-legacy-issuer',
'public-legacy-key',decode('23','hex'),1,CURRENT_TIMESTAMP,1)`,
		`INSERT INTO recovery_plan_seats (plan_id,pool_id,from_epoch,to_epoch,seat_id,from_member_id,
to_member_id,expected_assignment_epoch,expected_active_api_key_version,is_replacement,
freeze_suspension_case_id,freeze_operation_id,freeze_snapshot_hash) VALUES
('91000000-0000-0000-0000-000000000005','91000000-0000-0000-0000-000000000001',1,2,
'91000000-0000-0000-0000-000000000004','91000000-0000-0000-0000-000000000002',
'91000000-0000-0000-0000-000000000003',1,1,true,
'91000000-0000-0000-0000-000000000010','public-legacy-freeze',decode(repeat('43',32),'hex'))`,
		`INSERT INTO permanent_replacement_cases (id,external_id,integration_operation_id,plan_id,status,version)
VALUES ('91000000-0000-0000-0000-000000000011','public-legacy-case',
'92000000-0000-0000-0000-000000000004','91000000-0000-0000-0000-000000000005','READY',1)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			t.Fatalf("insert public legacy Seat fixture: %v", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		t.Fatalf("flush public legacy Seat fixture constraints: %v", err)
	}
	for index := len(tables) - 1; index >= 0; index-- {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+tables[index]+` ENABLE TRIGGER USER`); err != nil {
			t.Fatalf("enable %s public legacy fixture triggers: %v", tables[index], err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit public legacy Seat fixture: %v", err)
	}
}
