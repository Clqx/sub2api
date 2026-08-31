package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/recovery"
)

func TestAcquireEpochPlanLeaseUsesFenceCASAndDatabaseClock(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{
			"operation.fencing_token = $5", "operation.lease_expires_at > CURRENT_TIMESTAMP",
			"operation.fencing_token + 1", "plan.plan_status NOT IN ('FINALIZED', 'FAILED')",
		}, columns: operationColumnNames(),
		rows: [][]driver.Value{operationRow(hash[:], "RUNNING", 11, "worker-1", now.Add(time.Minute), now)},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	op, err := store.AcquireEpochPlanLease(context.Background(), recovery.AcquireEpochPlanLeaseInput{
		Key:        recovery.OperationKey{ClientID: "client-1", OperationID: "plan-op-1"},
		LeaseOwner: "worker-1", ExpectedFencingToken: 11, LeaseDuration: time.Minute,
	})
	if err != nil || op.FencingToken != 11 {
		t.Fatalf("AcquireEpochPlanLease() op=%+v err=%v", op, err)
	}
	script.assertDone(t)
}

func TestAcquireEpochPlanLeaseRejectsExcessiveDuration(t *testing.T) {
	store := &Store{}
	_, err := store.AcquireEpochPlanLease(context.Background(), recovery.AcquireEpochPlanLeaseInput{
		Key:        recovery.OperationKey{ClientID: "client-1", OperationID: "plan-op-1"},
		LeaseOwner: "worker-1", ExpectedFencingToken: 1, LeaseDuration: 5*time.Minute + time.Second,
	})
	if !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("expected invalid lease duration, got %v", err)
	}
}

func TestRenewPermanentReplacementLeaseRejectsExpiredOrStaleFence(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{
			"WITH eligible AS", "operation.fencing_token = $3", "operation.lease_owner = $5",
			"operation.lease_expires_at > CURRENT_TIMESTAMP", "operation.status = 'RUNNING'",
			"lease_expires_at = CURRENT_TIMESTAMP + make_interval", "FOR UPDATE OF operation",
		}, columns: operationColumnNames()},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, err := store.RenewPermanentReplacementLease(context.Background(),
		recovery.RenewPermanentReplacementLeaseInput{
			Key:        recovery.OperationKey{ClientID: "client-1", OperationID: "finalize-1"},
			LeaseOwner: "worker-1", ExpectedFencingToken: 4, LeaseDuration: time.Minute,
		})
	if !errors.Is(err, recovery.ErrStaleFence) {
		t.Fatalf("expired or stale parent heartbeat must fail closed, got %v", err)
	}
	script.assertDone(t)
}

func TestRenewRecoveryChildOperationLeaseKeepsFence(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	hash := bytes32(7)
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{
			"UPDATE integration_operations child", "child.fencing_token = $6", "child.lease_owner = $8",
			"child.lease_expires_at > CURRENT_TIMESTAMP", "finalization.fencing_token = $3",
			"PREPARE_PERMANENT_REPLACEMENT_SET", "COMMIT_PERMANENT_REPLACEMENT_PROVIDER",
		}, columns: operationColumnNames(),
		rows: [][]driver.Value{operationRow(hash[:], "RUNNING", 9, "worker-1", now.Add(time.Minute), now)},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	op, err := store.RenewRecoveryChildOperationLease(context.Background(),
		recovery.RenewRecoveryChildOperationLeaseInput{
			FinalizationKey:        recovery.OperationKey{ClientID: "client-1", OperationID: "finalize-1"},
			FinalizationLeaseOwner: "worker-1", FinalizationFencingToken: 5,
			DerivedOperationID: "op-1", ChildLeaseOwner: "worker-1",
			ExpectedChildFencingToken: 9, ChildLeaseDuration: time.Minute,
		})
	if err != nil || op.FencingToken != 9 {
		t.Fatalf("child heartbeat must preserve fence: op=%+v err=%v", op, err)
	}
	script.assertDone(t)
}

func TestRecoveryHeartbeatRejectsExcessiveDuration(t *testing.T) {
	store := &Store{}
	_, parentErr := store.RenewPermanentReplacementLease(context.Background(),
		recovery.RenewPermanentReplacementLeaseInput{
			Key:        recovery.OperationKey{ClientID: "client-1", OperationID: "finalize-1"},
			LeaseOwner: "worker-1", ExpectedFencingToken: 1, LeaseDuration: 5*time.Minute + time.Second,
		})
	_, childErr := store.RenewRecoveryChildOperationLease(context.Background(),
		recovery.RenewRecoveryChildOperationLeaseInput{
			FinalizationKey:        recovery.OperationKey{ClientID: "client-1", OperationID: "finalize-1"},
			FinalizationLeaseOwner: "worker-1", FinalizationFencingToken: 1,
			DerivedOperationID: "child-1", ChildLeaseOwner: "worker-1",
			ExpectedChildFencingToken: 1, ChildLeaseDuration: 5*time.Minute + time.Second,
		})
	if !errors.Is(parentErr, recovery.ErrInvalidData) || !errors.Is(childErr, recovery.ErrInvalidData) {
		t.Fatalf("heartbeat duration above five minutes must fail: parent=%v child=%v", parentErr, childErr)
	}
}

func TestRecoveryBatchSetHashBindsRecoveryWrapHash(t *testing.T) {
	fromHash, toHash, wrapHash := bytes32(1), bytes32(2), bytes32(3)
	bindings := []recovery.StagedBatchBinding{
		{EpochRole: "FROM", ResourceAccountExternalID: "account-1", BatchExternalID: "from-1",
			AccountRef: "provider-ref-1", BatchType: "LOGIN", BatchVersion: 1, CiphertextHash: fromHash},
		{EpochRole: "TO", ResourceAccountExternalID: "account-1", BatchExternalID: "to-1",
			AccountRef: "provider-ref-1", BatchType: "LOGIN", BatchVersion: 2,
			CiphertextHash: toHash, RecoveryWrapHash: wrapHash},
	}
	first, err := recoveryBatchSetHash(bindings)
	if err != nil {
		t.Fatal(err)
	}
	bindings[1].RecoveryWrapHash = bytes32(4)
	second, err := recoveryBatchSetHash(bindings)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("RecoveryWrapHash drift must change the durable batch-set hash")
	}
}

func TestManagerSeatPrepareSnapshotBindsStoreProtocol(t *testing.T) {
	request := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "manager-store-seat-prepare", PlanID: "manager-store-plan",
		CeremonyType: recovery.CeremonyBootstrap, PoolID: "manager-store-pool",
		FromEpoch: 1, ToEpoch: 2, SeatID: "manager-store-seat",
		TargetMemberID: "manager-store-target", ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 101, SubscriptionID: 102, APIKeyID: 103,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	request.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(request)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSONObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !seatPrepareSnapshotBindsRequest(canonical, request.RequestHash, request) {
		t.Fatal("Store rejected the canonical typed Seat prepare snapshot emitted by Manager")
	}
	if !typedSeatPrepareSnapshotBindsRequest(canonical, request.RequestHash, request) {
		t.Fatal("Store rejected the canonical typed Seat prepare snapshot for a new operation")
	}
	mutations := []func(*recovery.PermanentSeatRotationPrepareRequest){
		func(value *recovery.PermanentSeatRotationPrepareRequest) { value.ProtocolVersion = "drift-v1" },
		func(value *recovery.PermanentSeatRotationPrepareRequest) { value.RequestHash[0] ^= 0xff },
		func(value *recovery.PermanentSeatRotationPrepareRequest) { value.SeatID = "manager-store-other-seat" },
		func(value *recovery.PermanentSeatRotationPrepareRequest) {
			value.TargetMemberID = "manager-store-other-target"
		},
		func(value *recovery.PermanentSeatRotationPrepareRequest) { value.ToAPIKeyVersion++ },
	}
	for index, mutate := range mutations {
		drifted := request
		mutate(&drifted)
		driftedRaw, err := json.Marshal(drifted)
		if err != nil {
			t.Fatal(err)
		}
		driftedCanonical, err := canonicalJSONObject(driftedRaw)
		if err != nil {
			t.Fatal(err)
		}
		if seatPrepareSnapshotBindsRequest(driftedCanonical, request.RequestHash, request) {
			t.Fatalf("Store accepted typed Seat prepare semantic drift %d", index)
		}
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
	if !seatPrepareSnapshotBindsRequest(legacyCanonical, request.RequestHash, request) {
		t.Fatal("Store rejected the pre-existing snake_case Seat prepare snapshot")
	}
	if typedSeatPrepareSnapshotBindsRequest(legacyCanonical, request.RequestHash, request) {
		t.Fatal("Store accepted a legacy Seat prepare snapshot for a new operation")
	}
	driftedOuterHash := request.RequestHash
	driftedOuterHash[0] ^= 0xff
	if seatPrepareSnapshotBindsRequest(legacyCanonical, driftedOuterHash, request) {
		t.Fatal("Store accepted a legacy Seat prepare snapshot under a different domain hash")
	}
	var mixed map[string]any
	if err := json.Unmarshal(legacyCanonical, &mixed); err != nil {
		t.Fatal(err)
	}
	mixed["SeatID"] = "manager-store-conflicting-seat"
	mixedRaw, err := json.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	mixedCanonical, err := canonicalJSONObject(mixedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if seatPrepareSnapshotBindsRequest(mixedCanonical, request.RequestHash, request) {
		t.Fatal("Store accepted conflicting typed and snake_case Seat prepare fields")
	}
	var aliased map[string]any
	if err := json.Unmarshal(raw, &aliased); err != nil {
		t.Fatal(err)
	}
	aliased["ProtocolVersion"] = "drift-v1"
	aliased["protocolversion"] = request.ProtocolVersion
	aliasedRaw, err := json.Marshal(aliased)
	if err != nil {
		t.Fatal(err)
	}
	aliasedCanonical, err := canonicalJSONObject(aliasedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if seatPrepareSnapshotBindsRequest(aliasedCanonical, request.RequestHash, request) {
		t.Fatal("Store accepted a case-insensitive alias that overrides a typed Seat prepare field")
	}
}

func TestPoolRotationSnapshotsBindEntireTypedSeatSet(t *testing.T) {
	seat := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "snapshot-seat", PlanID: "snapshot-plan",
		CeremonyType: recovery.CeremonyBootstrap, PoolID: "snapshot-pool",
		FromEpoch: 1, ToEpoch: 2, SeatID: "snapshot-seat-id",
		TargetMemberID: "snapshot-member", ExpectedAssignmentEpoch: 1,
		PrincipalUserID: 101, SubscriptionID: 102, APIKeyID: 103,
		FromAPIKeyVersion: 1, ToAPIKeyVersion: 2,
	}
	seat.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(seat)
	childSetHash, err := recovery.PermanentRotationChildSetHash(
		[]recovery.PermanentSeatRotationPrepareRequest{seat})
	if err != nil {
		t.Fatal(err)
	}
	prepare := recovery.PermanentPoolRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "snapshot-prepare", PlanID: seat.PlanID,
		CeremonyType: seat.CeremonyType, PoolID: seat.PoolID,
		FromEpoch: seat.FromEpoch, ToEpoch: seat.ToEpoch,
		ChildSetHash: childSetHash, Seats: []recovery.PermanentSeatRotationPrepareRequest{seat},
	}
	prepare.RequestHash = recovery.PermanentPoolRotationPrepareRequestHash(prepare)
	fingerprint := sha256.Sum256([]byte("snapshot-credential"))
	binding := recovery.PermanentSeatActivationBinding{
		SeatID: seat.SeatID, TargetMemberID: seat.TargetMemberID,
		ExpectedAssignmentEpoch: seat.ExpectedAssignmentEpoch,
		PrincipalUserID:         seat.PrincipalUserID, SubscriptionID: seat.SubscriptionID,
		APIKeyID: seat.APIKeyID, ActiveAPIKeyVersion: seat.ToAPIKeyVersion,
		ChildOperationID: seat.OperationID, ChildRequestHash: seat.RequestHash,
		CredentialFingerprint: fingerprint, PreparedRotationRef: "snapshot-prepared",
	}
	preparedSetHash, err := recovery.PermanentPreparedSeatSetHash(
		[]recovery.PermanentSeatActivationBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	activation := recovery.PermanentPoolRotationActivateRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "snapshot-activation", PrepareOperationID: prepare.OperationID,
		PlanID: seat.PlanID, CeremonyType: seat.CeremonyType, PoolID: seat.PoolID,
		FromEpoch: seat.FromEpoch, ToEpoch: seat.ToEpoch,
		PreparedSetHash: preparedSetHash, Seats: []recovery.PermanentSeatActivationBinding{binding},
	}
	activation.RequestHash = recovery.PermanentPoolRotationActivateRequestHash(activation)
	commit := recovery.PermanentPoolRotationCommitRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID:     "snapshot-commit", PrepareOperationID: prepare.OperationID,
		ActivationOperationID: activation.OperationID, ActivationRequestHash: activation.RequestHash,
		PlanID: seat.PlanID, CeremonyType: seat.CeremonyType, PoolID: seat.PoolID,
		FromEpoch: seat.FromEpoch, ToEpoch: seat.ToEpoch,
		PreparedSetHash: preparedSetHash, Seats: []recovery.PermanentSeatActivationBinding{binding},
	}
	commit.RequestHash = recovery.PermanentPoolRotationCommitRequestHash(commit)

	for _, test := range []struct {
		name, hashField, nestedField string
		setHash                      [sha256.Size]byte
		request                      any
	}{
		{name: "prepare", hashField: "child_set_hash", nestedField: "SeatID",
			setHash: childSetHash, request: prepare},
		{name: "activation", hashField: "prepared_set_hash", nestedField: "PreparedRotationRef",
			setHash: preparedSetHash, request: activation},
		{name: "provider commit", hashField: "prepared_set_hash", nestedField: "PreparedRotationRef",
			setHash: preparedSetHash, request: commit},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := publicRotationSnapshot(t, test.request, test.hashField, test.setHash)
			canonical, err := canonicalJSONObject(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if !rotationSnapshotBindsRequest(canonical, test.hashField, test.setHash, test.request) {
				t.Fatal("Store rejected the exact Manager rotation snapshot")
			}
			var payload map[string]any
			decoder := json.NewDecoder(strings.NewReader(string(canonical)))
			decoder.UseNumber()
			if err := decoder.Decode(&payload); err != nil {
				t.Fatal(err)
			}
			seats, ok := payload["Seats"].([]any)
			if !ok || len(seats) != 1 {
				t.Fatalf("unexpected Seats fixture: %#v", payload["Seats"])
			}
			seatPayload, ok := seats[0].(map[string]any)
			if !ok {
				t.Fatalf("unexpected Seat fixture: %#v", seats[0])
			}
			seatPayload[test.nestedField] = "drifted-value"
			driftedRaw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			driftedCanonical, err := canonicalJSONObject(driftedRaw)
			if err != nil {
				t.Fatal(err)
			}
			if rotationSnapshotBindsRequest(driftedCanonical, test.hashField, test.setHash, test.request) {
				t.Fatal("Store accepted a same-length nested Seat drift")
			}
			payload["unknown"] = true
			unknownRaw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			unknownCanonical, err := canonicalJSONObject(unknownRaw)
			if err != nil {
				t.Fatal(err)
			}
			if rotationSnapshotBindsRequest(unknownCanonical, test.hashField, test.setHash, test.request) {
				t.Fatal("Store accepted an unknown top-level rotation snapshot field")
			}
		})
	}
}

func TestPhase2HRecoveryProtocolCompatibilityMigrationContract(t *testing.T) {
	migrationBytes, err := os.ReadFile("../../../../migrations/011_phase2h_recovery_protocol_compatibility.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(migrationBytes)
	for _, required := range []string{
		"recovery_json_hash_matches_phase2h",
		"recovery_json_hash_value_phase2h",
		"get_byte(expected_hash, item_position::integer - 1)",
		"recovery_seat_prepare_snapshot_matches_phase2h",
		"allow_legacy AND key_count = 7",
		"key_count = 16",
		"trusted-pool/permanent-seat-prepare/v1",
		"'ProtocolVersion', 'OperationID', 'RequestHash'",
		"trusted-pool/permanent-seat-rotation/v1",
		"recovery_pool_prepare_snapshot_matches_phase2h",
		"key_count <> 11",
		"recovery_pool_activation_snapshot_matches_phase2h",
		"key_count <> 12",
		"snapshot -> 'Seats' = expected_seats",
		"ADD COLUMN legacy_snapshot_compatibility_phase2h boolean NOT NULL DEFAULT TRUE",
		"ALTER COLUMN legacy_snapshot_compatibility_phase2h SET DEFAULT FALSE",
		"integration_operations_compatibility_marker_phase2h",
		"new integration operation cannot claim pre-011 compatibility",
		"pre-011 operation compatibility marker is immutable",
		"child.legacy_snapshot_compatibility_phase2h",
		"CREATE OR REPLACE FUNCTION enforce_recovery_rotation_progress_phase2g",
		"CREATE OR REPLACE FUNCTION enforce_pool_preparation_attempt_phase2g",
		"CREATE OR REPLACE FUNCTION enforce_pool_activation_attempt_phase2g",
	} {
		if !strings.Contains(migration, required) {
			t.Fatalf("011 migration protocol compatibility contract missing %q", required)
		}
	}
	storeBytes, err := os.ReadFile("store_recovery.go")
	if err != nil {
		t.Fatal(err)
	}
	store := string(storeBytes)
	begin := strings.Index(store, "func (s *Store) BeginSeatRotation")
	if begin < 0 {
		t.Fatal("could not isolate BeginSeatRotation source")
	}
	end := strings.Index(store[begin:], "func (s *Store) CommitSeatRotationProgress")
	if end < 0 {
		t.Fatal("could not isolate BeginSeatRotation source")
	}
	beginSource := store[begin : begin+end]
	if !strings.Contains(beginSource, "typedSeatPrepareSnapshotBindsRequest") {
		t.Fatal("BeginSeatRotation must reject legacy snapshots for newly created operations")
	}
	markRotating := strings.Index(beginSource, "mark permanent replacement rotating")
	beginChild := strings.Index(beginSource, "beginRecoverySeatOperation")
	if markRotating < 0 || beginChild < 0 || markRotating > beginChild {
		t.Fatal("BeginSeatRotation must mark the case ROTATING before creating child progress")
	}
}

func TestPhase2GPermanentReplacementRejectsDuplicateSets(t *testing.T) {
	if uniqueReplacementIntents([]recovery.SeatReplacementIntent{
		{SeatExternalID: "seat-1", TargetMemberExternalID: "member-1"},
		{SeatExternalID: "seat-1", TargetMemberExternalID: "member-2"},
	}) {
		t.Fatal("duplicate Seat must not satisfy the exact replacement set")
	}
	if uniqueRecoveryIDs([]string{"evidence-1", "evidence-1"}) {
		t.Fatal("duplicate evidence must not satisfy the exact evidence set")
	}
	now := time.Now().UTC()
	token := bytes32(9)
	claims := []recovery.ReplacementClaimActivation{
		{SeatExternalID: "seat-1", ClaimOperationID: "claim-1", TokenHash: token, ExpiresAt: now.Add(time.Minute)},
		{SeatExternalID: "seat-2", ClaimOperationID: "claim-2", TokenHash: token, ExpiresAt: now.Add(time.Minute)},
	}
	if _, err := validateReplacementClaimActivations(claims); !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("duplicate final token hash must fail closed, got %v", err)
	}
	if _, err := validateReplacementClaimIntents([]recovery.ReplacementClaimIntent{
		{SeatExternalID: "seat-1", ClaimOperationID: "claim-1"},
		{SeatExternalID: "seat-1", ClaimOperationID: "claim-2"},
	}); !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("duplicate pending claim Seat must fail closed, got %v", err)
	}
	if _, err := validateReplacementClaimIntents([]recovery.ReplacementClaimIntent{
		{SeatExternalID: "seat-1", ClaimOperationID: "claim-1"},
		{SeatExternalID: "seat-2", ClaimOperationID: "claim-1"},
	}); !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("duplicate pending claim operation must fail closed, got %v", err)
	}
}

func TestPhase2GReplacementClaimTTLIsBounded(t *testing.T) {
	now := time.Now().UTC()
	valid := recovery.ReplacementClaimActivation{SeatExternalID: "seat-1", ClaimOperationID: "claim-1",
		TokenHash: bytes32(1), ExpiresAt: now.Add(recovery.MaxReplacementClaimTTL - time.Minute)}
	if _, err := validateReplacementClaimActivations([]recovery.ReplacementClaimActivation{valid}); err != nil {
		t.Fatalf("claim below maximum TTL should pass: %v", err)
	}
	valid.ExpiresAt = now.Add(recovery.MaxReplacementClaimTTL + time.Minute)
	if _, err := validateReplacementClaimActivations([]recovery.ReplacementClaimActivation{valid}); !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("claim above maximum TTL must fail closed, got %v", err)
	}
}

func TestPhase2GProviderReleaseRejectsIncompleteTypedProof(t *testing.T) {
	digest := bytes32(1)
	input := recovery.CommitProviderReleaseInput{
		FinalizationKey:        recovery.OperationKey{ClientID: "client-1", OperationID: "finalize-1"},
		FinalizationLeaseOwner: "worker-1", FinalizationFencingToken: 1,
		DerivedOperationID: "release-1", ChildLeaseOwner: "worker-1", ChildFencingToken: 1,
		Status: "RELEASED", ProviderAttestationRef: "attestation-1", ProviderAttestationDigest: digest,
		ProviderAttestationIssuer: "issuer-1", ProviderAttestationKeyID: "key-1",
		ProviderAttestationVersion: 1, ProviderAttestationSignature: []byte("signature"),
		AllCredentialsEnabled: true, AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true,
		CredentialFingerprintGateEnforced: true, AuthorizationCacheDurableOutbox: false,
		AuthCacheMinimumEvents: 1, ResultSnapshot: []byte(`{"status":"released"}`),
	}
	if _, _, err := (&Store{}).CommitProviderRelease(context.Background(), input); !errors.Is(err, recovery.ErrInvalidData) {
		t.Fatalf("release without durable cache outbox must fail before persistence, got %v", err)
	}
}

func TestPhase2GPreparedSetHashCrossSystemVector(t *testing.T) {
	first := recovery.PermanentSeatRotationPrepareRequest{
		ProtocolVersion: recovery.PermanentSeatRotationProtocolV1, OperationID: "child-op-a", PlanID: "plan-1",
		CeremonyType: recovery.CeremonyRotate, PoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		SeatID: "seat-a", TargetMemberID: "member-new", ExpectedAssignmentEpoch: 3,
		PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303, FromAPIKeyVersion: 3, ToAPIKeyVersion: 4,
	}
	first.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(first)
	second := first
	second.SeatID, second.OperationID, second.TargetMemberID = "seat-b", "child-op-b", "member-b"
	second.PrincipalUserID, second.SubscriptionID, second.APIKeyID = 102, 203, 304
	second.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(second)
	bindings := []recovery.PermanentSeatActivationBinding{
		{SeatID: first.SeatID, TargetMemberID: first.TargetMemberID,
			ExpectedAssignmentEpoch: first.ExpectedAssignmentEpoch, PrincipalUserID: 101, SubscriptionID: 202,
			APIKeyID: 303, ActiveAPIKeyVersion: 4, CredentialFingerprint: sha256.Sum256([]byte("credential-a")),
			PreparedRotationRef: "prepared-a", ChildOperationID: first.OperationID, ChildRequestHash: first.RequestHash},
		{SeatID: second.SeatID, TargetMemberID: second.TargetMemberID,
			ExpectedAssignmentEpoch: second.ExpectedAssignmentEpoch, PrincipalUserID: 102, SubscriptionID: 203,
			APIKeyID: 304, ActiveAPIKeyVersion: 4, CredentialFingerprint: sha256.Sum256([]byte("credential-b")),
			PreparedRotationRef: "prepared-b", ChildOperationID: second.OperationID, ChildRequestHash: second.RequestHash},
	}
	got, err := recovery.PermanentPreparedSeatSetHash(bindings)
	if err != nil {
		t.Fatal(err)
	}
	if stringHex(got[:]) != "5db639866d27d07d3187627cb4a62f84bcf8c9f86518aeec2aa1ad4a230ceaf7" {
		t.Fatalf("prepared-set canonical vector drifted: %x", got)
	}
}

func TestPhase2GStaticSafetyContracts(t *testing.T) {
	storeBytes, err := os.ReadFile("store_recovery.go")
	if err != nil {
		t.Fatal(err)
	}
	store := string(storeBytes)
	for _, forbidden := range []string{"status = 'ROTATED'", "progress.status = 'ROTATED'",
		"recovery_pool_finalization_barriers", "recovery_seat_finalization_barriers"} {
		if strings.Contains(store, forbidden) {
			t.Fatalf("Phase2-G Store retains obsolete semantic %q", forbidden)
		}
	}
	for _, required := range []string{
		"sql.LevelSerializable", "replacement.status = 'READY_TO_COMMIT'", "progress.status = 'ACTIVATED'",
		"ORDER BY seat.seat_no FOR UPDATE OF seat, progress", "FOR UPDATE OF batch",
		"activation.old_credential_set_invalidated IS TRUE",
		"activation.credential_fingerprint_gate_enforced IS TRUE",
		"if ceremonyType == recovery.CeremonyRotate", "retire source Manifest",
		"'ISSUANCE_PENDING', NULL", "replacement.status = 'READY_TO_ISSUE'",
		"func (s *Store) BeginProviderRelease", "func (s *Store) CommitProviderRelease",
		"func (s *Store) CommitReplacementClaims",
		"func (s *Store) RenewPermanentReplacementLease",
		"func (s *Store) RenewRecoveryChildOperationLease",
		"input.AuthCacheMinimumEvents < plan.ExpectedMemberCount",
		"subtle.ConstantTimeCompare(storedTokenHash, input.TokenHash[:])", "claim_token_hash = NULL", "PlanExternalID",
		"return toRecoveryOperation(op), true, nil",
	} {
		if !strings.Contains(store, required) {
			t.Fatalf("Phase2-G Store safety contract missing %q", required)
		}
	}
	migrationBytes, err := os.ReadFile("../../../../migrations/009_phase2g_permanent_finalization.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(migrationBytes)
	for _, forbidden := range []string{"finalization_barriers", "jsonb_agg", "planned.is_replacement",
		"old_credential_invalidated"} {
		if strings.Contains(migration, forbidden) {
			t.Fatalf("Phase2-G migration retains obsolete semantic %q", forbidden)
		}
	}
	for _, required := range []string{
		"recovery_pool_activation_seats", "old_credential_set_invalidated",
		"ISSUANCE_PENDING", "PROVIDER_COMMIT_PENDING", "READY_TO_ISSUE",
		"recovery_pool_provider_commit_attempts", "credential_claims_lease_shape_phase2g",
		"all_credentials_enabled", "all_subscriptions_enabled",
		"provider_commit.auth_cache_minimum_events >= target.expected_seat_count",
		"recovery_pool_has_open_execution_phase2g", "enforce_resource_account_lifecycle",
		"enforce_resource_account_mapping_lifecycle", "recovery_plan_phase2g_release_barrier",
		"claim_operation_type IS DISTINCT FROM 'PROVISION'",
		"ISSUANCE_PENDING is reserved for Phase2-G replacement claims",
		"claim.status IN ('READY', 'CLAIMED', 'EXPIRED')",
		"operation.operation_type <> 'PROVISION'",
		"credential_fingerprint_gate_enforced", "authorization_cache_durable_outbox",
		"authorization_cache_invalidated", "auth_cache_minimum_events",
		"current_concurrency bigint NOT NULL CHECK (current_concurrency = 0)",
		"pending_settlements bigint NOT NULL CHECK (pending_settlements = 0)",
		"recovery_pool_final_aggregate_phase2g", "recovery_epoch_final_aggregate_phase2g",
		"recovery_manifest_final_aggregate_phase2g", "recovery_batch_final_aggregate_phase2g",
		"recovery_evidence_final_aggregate_phase2g", "recovery_assignment_final_aggregate_phase2g",
		"recovery_seat_final_aggregate_phase2g",
		"CREATE OR REPLACE FUNCTION assert_suspend_aggregate",
		"WHERE freeze_suspension_case_id = case_id AND status <> 'CANCELLED'",
		"planned.freeze_suspension_case_id = case_id", "plan.status = 'FINALIZED'",
	} {
		if !strings.Contains(migration, required) {
			t.Fatalf("Phase2-G migration safety contract missing %q", required)
		}
	}
}

func TestCanonicalControlEvidenceBindsTypedIntent(t *testing.T) {
	digest := sha256.Sum256([]byte("provider-attestation"))
	references := []recovery.ControlEvidenceBatchRef{{
		EpochRole: "TO", BatchType: "LOGIN", BatchExternalID: "batch-to-login",
	}}
	snapshot, err := json.Marshal(map[string]any{
		"evidence_external_id":                  "evidence-1",
		"plan_external_id":                      "plan-1",
		"resource_external_id":                  "account-1",
		"provider_attestation_ref":              "attestation-1",
		"provider_attestation_digest":           strings.Repeat("0", 0) + strings.ToLower(stringHex(digest[:])),
		"provider_attestation_issuer":           "issuer-1",
		"provider_attestation_key_id":           "key-1",
		"provider_attestation_version":          uint64(1),
		"provider_attestation_algorithm":        "Ed25519",
		"provider_attestation_signature":        []byte("account-signature"),
		"provider_attestation_protocol_version": "trusted-pool/provider-statement/v1",
		"batch_references": []map[string]string{{
			"epoch_role": "TO", "batch_type": "LOGIN", "batch_external_id": "batch-to-login",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSONObject(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	input := recovery.IssueControlEvidenceInput{
		Key:                recovery.OperationKey{ClientID: "client-1", OperationID: "evidence-op-1"},
		EvidenceExternalID: "evidence-1", PlanExternalID: "plan-1", ResourceExternalID: "account-1",
		ProviderAttestationRef: "attestation-1", ProviderAttestationDigest: digest,
		ProviderAttestationIssuer: "issuer-1", ProviderAttestationKeyID: "key-1",
		ProviderAttestationVersion: 1, ProviderAttestationAlgorithm: "Ed25519",
		ProviderAttestationSignature:       []byte("account-signature"),
		ProviderAttestationProtocolVersion: "trusted-pool/provider-statement/v1", BatchReferences: references,
		RequestSnapshot: canonical, RequestHash: sha256.Sum256(canonical),
	}
	if _, err := canonicalControlEvidence(input); err != nil {
		t.Fatalf("typed control evidence should validate: %v", err)
	}
	input.ResourceExternalID = "account-2"
	if _, err := canonicalControlEvidence(input); !errors.Is(err, recovery.ErrHashDrift) {
		t.Fatalf("semantic drift should fail with ErrHashDrift, got %v", err)
	}
}

func TestPhase2FRecoveryStaticSafetyContracts(t *testing.T) {
	genericStoreSource, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	genericStore := string(genericStoreSource)
	if strings.Contains(genericStore, `\tAND operation_type`) {
		t.Fatal("generic operation SQL contains a literal escaped tab")
	}
	for _, operationType := range []string{
		"REGISTER_RESOURCE_ACCOUNT", "MAP_RESOURCE_ACCOUNT_SEAT", "VERIFY_RECOVERY_CONTROL",
		"BOOTSTRAP_RECOVERY_EPOCH", "ROTATE_RECOVERY_EPOCH", "FINALIZE_RECOVERY_BOOTSTRAP",
	} {
		if !strings.Contains(genericStore, "'"+operationType+"'") {
			t.Fatalf("generic operation commit does not exclude recovery operation %q", operationType)
		}
	}

	storeSource, err := os.ReadFile("store_recovery.go")
	if err != nil {
		t.Fatal(err)
	}
	store := string(storeSource)
	if strings.Contains(store, "GROUP BY pool.id FOR UPDATE") {
		t.Fatal("PostgreSQL forbids FOR UPDATE on the aggregate inventory query")
	}
	if strings.Count(store, "pq.Array(input.EvidenceExternalIDs)") != 2 {
		t.Fatal("both permanent and bootstrap evidence arrays must use lib/pq array encoding")
	}
	if strings.Count(store, "pg_advisory_xact_lock(hashtextextended($1, 0))") != 2 {
		t.Fatal("begin and finalize must use the same Pool external-id advisory lock key")
	}
	finalize := store[strings.Index(store, "func (s *Store) commitRecoveryFinalization"):]
	poolLock := strings.Index(finalize, "SELECT id FROM pools WHERE id = $1 FOR UPDATE")
	seatLock := strings.Index(finalize, "ORDER BY seat.seat_no FOR UPDATE OF seat, progress")
	if poolLock < 0 || seatLock < 0 || poolLock >= seatLock {
		t.Fatal("finalize must lock Pool before sorted Seats")
	}
	for _, required := range []string{
		"integration_operation_id, plan_id, resource_account_id",
		"ceremony_type, attestation_purpose, status, verified_at",
		"batch.migration_state = 'CURRENT'",
		"old_owner.external_id = $11",
		"new_owner.external_id = $12",
		"seat.external_id = $13",
		"$20::bytea",
		"payload.ProviderAttestationSetHash != providerAttestationSetHash",
		"AND operation.fencing_token = $5",
		"func (s *Store) GetEpochPlanProgress",
		"ReadOnly: true, Isolation: sql.LevelRepeatableRead",
		"operation.operation_type IN ('BOOTSTRAP_RECOVERY_EPOCH', 'ROTATE_RECOVERY_EPOCH')",
		"validateManifestProjection(ctx, tx, plan, manifestPayload, input.BatchBindings)",
		"assertRecoveryInventorySnapshotTx(ctx, tx, planID, \"revalidate recovery inventory before stage transition\")",
		"assertRecoveryInventorySnapshotTx(ctx, tx, planID, \"revalidate final recovery inventory\")",
		"set_config('trusted_pool.recovery_inventory_plan_id', $1, true)",
		"ORDER BY member.external_id",
		"affected != 1",
	} {
		if !strings.Contains(store, required) {
			t.Fatalf("store recovery safety contract missing %q", required)
		}
	}
	if strings.Contains(store, "ORDER BY snapshot.share_index") || strings.Contains(store, "ORDER BY delivery.share_index") {
		t.Fatal("recovery projections must follow canonical member ID order, not independent ShareIndex order")
	}

	migrationSource, err := os.ReadFile("../../../../migrations/008_phase2f_recovery_governance.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(migrationSource)
	for _, required := range []string{
		"seat.status <> 'FROZEN'",
		"AND migration_state = 'CURRENT'",
		"Recovery Root artifact is append-only",
		"CURRENT Epoch member key/PoP snapshot is immutable",
		"recovery_wrap_hash bytea",
		"batch.migration_state IN ('CURRENT', 'LEGACY_UNRECOVERABLE')",
		"expected_active_api_key_version",
		"NEW.acknowledgement_message_hash IS DISTINCT FROM (SELECT expected_message_hash",
		"NEW.signed_message_hash IS DISTINCT FROM (SELECT expected_message_hash",
		"NEW.canonical_payload ->> 'protocol_version' IS DISTINCT FROM 'trusted-pool/recovery-governance/v1'",
		"jsonb_typeof(NEW.canonical_payload -> 'recovery_root') IS DISTINCT FROM 'object'",
		"NEW.canonical_payload #>> '{recovery_root,public_handle}' IS DISTINCT FROM",
		"provider_attestation_set_hash bytea NOT NULL",
		"item ->> 'principal_user_id'",
		"jsonb_array_elements(NEW.canonical_payload -> 'replacements')",
		"recovery_plan_account_seats mapping",
		"plan_row.id IS NULL OR plan_row.status IS DISTINCT FROM 'MANIFEST_DRAFT'",
		"PERFORM assert_recovery_plan_authoritative_snapshot(NEW.id)",
		"CREATE TRIGGER seats_open_recovery_inventory",
		"current_setting('trusted_pool.recovery_inventory_plan_id', true) = open_plan_id::text",
		"CREATE CONSTRAINT TRIGGER seats_recovery_inventory_finalized",
		"AFTER UPDATE ON seats DEFERRABLE INITIALLY DEFERRED",
		"replacement.status = 'FINALIZED' AND progress.status = 'COMMITTED'",
		"finalization.status = 'SUCCEEDED'",
		"仅从事件行和不可变计划快照识别恢复形状",
		"WHERE planned.seat_id = NEW.id AND plan.status <> 'FAILED'",
		"NEW.assignment_epoch = planned.expected_assignment_epoch + 1",
		"NEW.active_api_key_version = planned.expected_active_api_key_version + 1",
		"resource account cannot be added during an open ceremony",
		"resource account Seat mapping cannot be added during an open ceremony",
		"BEFORE INSERT OR UPDATE OR DELETE ON pool_resource_accounts",
		"BEFORE INSERT OR UPDATE OR DELETE ON pool_resource_account_seats",
	} {
		if !strings.Contains(migration, required) {
			t.Fatalf("migration recovery safety contract missing %q", required)
		}
	}
	deferredStart := strings.Index(migration, "CREATE OR REPLACE FUNCTION validate_recovery_seat_inventory_finalized()")
	if deferredStart < 0 {
		t.Fatal("deferred recovery Seat finalization guard is missing")
	}
	deferredEnd := strings.Index(migration[deferredStart:], "CREATE CONSTRAINT TRIGGER seats_recovery_inventory_finalized")
	if deferredEnd < 0 {
		t.Fatal("deferred recovery Seat finalization trigger is missing")
	}
	deferredGuard := migration[deferredStart : deferredStart+deferredEnd]
	if strings.Contains(deferredGuard, "current_setting(") {
		t.Fatal("deferred recovery Seat finalization guard must derive authorization from OLD/NEW and durable state")
	}
}

func stringHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&0x0f]
	}
	return string(result)
}
