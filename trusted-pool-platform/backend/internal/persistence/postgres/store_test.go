package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
)

func TestBeginOperationPersistsSnapshotInOneTransaction(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	hash := bytes32(1)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"INSERT INTO integration_operations", "request_snapshot", "CURRENT_TIMESTAMP"},
			columns: operationColumnNames(), rows: [][]driver.Value{operationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	op, created, err := store.BeginOperation(context.Background(), application.BeginOperationInput{
		Key:  application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		Kind: application.OperationProvision, TargetType: "SEAT", TargetExternalID: "seat-1",
		RequestHash: hash, RequestSnapshot: []byte(`{"external_seat_id":"seat-1"}`),
	})
	if err != nil || !created {
		t.Fatalf("BeginOperation() created=%v err=%v", created, err)
	}
	if op.TargetExternalID != "seat-1" || op.RequestHash != hash {
		t.Fatalf("unexpected operation: %+v", op)
	}
	script.assertDone(t)
}

func TestBeginOperationRejectsRequestHashDrift(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	storedHash, replayHash := bytes32(1), bytes32(2)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"INSERT INTO integration_operations"}, columns: operationColumnNames()},
		{kind: "query", contains: []string{"FROM integration_operations", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{operationRow(storedHash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	_, _, err := store.BeginOperation(context.Background(), application.BeginOperationInput{
		Key:  application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		Kind: application.OperationProvision, TargetType: "SEAT", TargetExternalID: "seat-1",
		RequestHash: replayHash, RequestSnapshot: []byte(`{"external_seat_id":"seat-1"}`),
	})
	if !errors.Is(err, application.ErrWorkflowHashDrift) {
		t.Fatalf("expected hash drift, got %v", err)
	}
	script.assertDone(t)
}

func TestBeginOperationRejectsKindOrTargetDriftWithSameHash(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	hash := bytes32(1)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"INSERT INTO integration_operations"}, columns: operationColumnNames()},
		{kind: "query", contains: []string{"FROM integration_operations", "FOR UPDATE"},
			columns: operationColumnNames(), rows: [][]driver.Value{operationRow(hash[:], "RUNNING", 0, nil, nil, now)}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	_, _, err := store.BeginOperation(context.Background(), application.BeginOperationInput{
		Key:  application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		Kind: application.OperationRestore, TargetType: "POOL", TargetExternalID: "pool-2",
		RequestHash: hash, RequestSnapshot: []byte(`{"external_seat_id":"seat-1"}`),
	})
	if !errors.Is(err, application.ErrWorkflowHashDrift) {
		t.Fatalf("expected immutable intent drift, got %v", err)
	}
	script.assertDone(t)
}

func TestAcquireOperationLeaseUsesDatabaseClock(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	leaseUntil := now.Add(30 * time.Second)
	hash := bytes32(1)
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{
			"lease_expires_at = CURRENT_TIMESTAMP + make_interval", "lease_expires_at <= CURRENT_TIMESTAMP",
			"fencing_token = fencing_token + 1",
		}, columns: operationColumnNames(), rows: [][]driver.Value{
			operationRow(hash[:], "RUNNING", 7, "worker-a", leaseUntil, now),
		},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	lease, err := store.AcquireOperationLease(context.Background(), application.AcquireOperationLeaseInput{
		Key:        application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		LeaseOwner: "worker-a", LeaseDuration: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("AcquireOperationLease(): %v", err)
	}
	if lease.FencingToken != 7 || lease.Operation.LeaseExpiresAt == nil || !lease.Operation.LeaseExpiresAt.Equal(leaseUntil) {
		t.Fatalf("lease did not return database values: %+v", lease)
	}
	script.assertDone(t)
}

func TestValidateProvisionPreflightChecksTrustedBindings(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{
			"p.sub2api_group_id = $3", "p.membership_epoch > 0", "me.pool_id = p.id", "me.epoch = p.membership_epoch",
			"me.status = 'ACTIVE'", "mem.epoch_id = me.id", "owner.id = mem.member_id", "owner.status = 'ACTIVE'",
			"io.migration_state = 'CURRENT'", "other.status = 'SUCCEEDED'",
			"s.assignment_epoch > $7", "io.target_id IS NULL",
		},
		columns: []string{"membership_epoch"}, rows: [][]driver.Value{{int64(2)}},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	err := store.ValidateProvisionPreflight(context.Background(), application.ProvisionPreflightInput{
		Key:            application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		PoolExternalID: "pool-1", SeatExternalID: "seat-1", OwnerExternalID: "owner-1",
		ExistingGroupID: 10, AssignmentEpoch: 1,
	})
	if err != nil {
		t.Fatalf("ValidateProvisionPreflight(): %v", err)
	}
	script.assertDone(t)
}

func TestValidateProvisionPreflightPreservesDatabaseFailure(t *testing.T) {
	dbErr := errors.New("database unavailable")
	script := &fakeScript{steps: []fakeStep{{kind: "query", contains: []string{"SELECT p.membership_epoch"}, err: dbErr}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	err := store.ValidateProvisionPreflight(context.Background(), application.ProvisionPreflightInput{
		Key:            application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		PoolExternalID: "pool-1", SeatExternalID: "seat-1", OwnerExternalID: "owner-1",
		ExistingGroupID: 10, AssignmentEpoch: 1,
	})
	if !errors.Is(err, dbErr) {
		t.Fatalf("database failure was masked: %v", err)
	}
	script.assertDone(t)
}

func TestCommitOperationRejectsStaleFenceAndRequiresOwner(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{
			"fencing_token = $3", "lease_owner = $4", "lease_expires_at > CURRENT_TIMESTAMP",
			"operation_type <> 'RESOLVE_SETTLEMENT'",
		}, columns: operationColumnNames(),
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	_, err := store.CommitOperation(context.Background(), application.CommitOperationInput{
		Key:        application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
		LeaseOwner: "old-worker", FencingToken: 1, Status: application.OperationSucceeded,
		ResultSnapshot: []byte(`{"applied":true}`),
	})
	if !errors.Is(err, application.ErrWorkflowStaleFence) {
		t.Fatalf("expected stale fence, got %v", err)
	}
	script.assertDone(t)
}

func TestAcquireNextOperationLeaseUsesSkipLockedAndRetrySchedule(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	hash := bytes32(1)
	script := &fakeScript{steps: []fakeStep{{
		kind: "query", contains: []string{"next_attempt_at <= CURRENT_TIMESTAMP", "error_code NOT IN ('CALLER_REPLAY_REQUIRED', 'OPERATOR_REVIEW_REQUIRED')", "operation_type IN ('PROVISION', 'SUSPEND', 'ASSIGN_TEMPORARY', 'RESTORE')", "FOR UPDATE SKIP LOCKED", "migration_state = 'CURRENT'"},
		columns: operationColumnNames(), rows: [][]driver.Value{operationRow(hash[:], "RETRYABLE", 8, "recovery-1", now.Add(time.Minute), now)},
	}}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	lease, err := store.AcquireNextOperationLease(context.Background(), application.AcquireNextOperationLeaseInput{
		LeaseOwner: "recovery-1", LeaseDuration: time.Minute,
	})
	if err != nil || lease.FencingToken != 8 {
		t.Fatalf("AcquireNextOperationLease() lease=%+v err=%v", lease, err)
	}
	script.assertDone(t)
}

func TestAcquireNextCredentialClaimLeaseUsesSkipLockedAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"expires_at <= CURRENT_TIMESTAMP", "ACK_PENDING' AND ack_response_snapshot IS NULL", "FOR UPDATE SKIP LOCKED", "RETURNING cc.integration_operation_id"},
			columns: []string{"integration_operation_id"}, rows: [][]driver.Value{{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}},
		{kind: "query", contains: []string{"WHERE cc.integration_operation_id = $1"}, columns: claimColumnNames(), rows: [][]driver.Value{
			claimRow("PROVISION", "ACK_PENDING", tokenHash[:], fingerprint[:], aadHash[:], 9, "recovery-1", now),
		}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	lease, err := store.AcquireNextCredentialClaimLease(context.Background(), application.AcquireNextCredentialClaimLeaseInput{
		LeaseOwner: "recovery-1", LeaseDuration: time.Minute,
	})
	if err != nil || lease.FencingToken != 9 {
		t.Fatalf("AcquireNextCredentialClaimLease() lease=%+v err=%v", lease, err)
	}
	script.assertDone(t)
}

func TestCommitOperationWithCredentialClaimIsAtomic(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	hash, tokenHash, fingerprint, aadHash := bytes32(1), bytes32(3), bytes32(4), bytes32(5)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"UPDATE integration_operations", "target_id = COALESCE", "operation_type IN"},
			columns: operationColumnNames(), rows: [][]driver.Value{operationRow(hash[:], "SUCCEEDED", 4, nil, nil, now)}},
		{kind: "exec", contains: []string{"INSERT INTO credential_claims", "JOIN seat_assignments", "sa.status = 'ACTIVE'", "s.owner_member_id = m.id", "claim_intent_hash"}, affected: 1},
		{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(), rows: [][]driver.Value{
			claimRow("PROVISION", "READY", tokenHash[:], fingerprint[:], aadHash[:], 0, nil, now),
		}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	claimInput := application.CreateCredentialClaimInput{
		Key:            application.ClaimKey{ClientID: "client-1", OperationID: "op-1"},
		SeatExternalID: "seat-1", TargetMemberExternalID: "member-1", ClaimOperationID: "claim-op-1",
		TokenHash: tokenHash, CredentialFingerprint: fingerprint,
		Envelope: application.CredentialEnvelope{Algorithm: "AES-256-GCM", KeyRef: "kms/key/1", Ciphertext: []byte("ciphertext"), Nonce: []byte("nonce"), AADHash: aadHash, WrappedDEK: []byte("wrapped")},
		ClaimTTL: 10 * time.Minute,
	}
	op, claim, err := store.CommitOperationWithCredentialClaim(context.Background(), application.CommitOperationWithCredentialClaimInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-a",
		FencingToken: 4, ResultSnapshot: []byte(`{"applied":true}`), Claim: claimInput,
	})
	if err != nil || op.Status != application.OperationSucceeded || claim.Status != application.CredentialClaimReady {
		t.Fatalf("atomic commit op=%+v claim=%+v err=%v", op, claim, err)
	}
	script.assertDone(t)
}

func TestCommitProvisionRejectsAnotherSuccessfulOperationForSameSeat(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT target_id", "operation_type = 'PROVISION'", "fencing_token = $4", "FOR UPDATE"},
			columns: []string{"target_id"}, rows: [][]driver.Value{{nil}}},
		{kind: "query", contains: []string{"p.sub2api_group_id = $2", "p.membership_epoch > 0", "FOR UPDATE"},
			columns: []string{"pool_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-db-id", int64(1)}}},
		{kind: "query", contains: []string{"me.pool_id = $1", "mem.epoch_id = me.id", "m.id = mem.member_id", "FOR UPDATE OF me, mem, m"},
			columns: []string{"member_id"}, rows: [][]driver.Value{{"member-db-id"}}},
		{kind: "query", contains: []string{"SELECT EXISTS", "target_external_id = $1", "status = 'SUCCEEDED'"},
			columns: []string{"exists"}, rows: [][]driver.Value{{true}}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, _, err := store.CommitProvisionWithCredentialClaim(context.Background(), provisionAggregateInput())
	if !errors.Is(err, application.ErrWorkflowTargetConflict) {
		t.Fatalf("expected target conflict, got %v", err)
	}
	script.assertDone(t)
}

func TestCommitProvisionRequiresStableSub2APIResourceIDs(t *testing.T) {
	store, cleanup := newFakeStore(t, &fakeScript{})
	defer cleanup()
	input := provisionAggregateInput()
	input.APIKeyID = 0
	_, _, _, err := store.CommitProvisionWithCredentialClaim(context.Background(), input)
	if !errors.Is(err, application.ErrWorkflowInvalidData) {
		t.Fatalf("missing stable API Key ID was accepted: %v", err)
	}
}

func TestCommitProvisionRejectsAssignmentEpochRegression(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT target_id", "fencing_token = $4", "lease_owner = $5", "FOR UPDATE"}, columns: []string{"target_id"}, rows: [][]driver.Value{{"seat-db-id"}}},
		{kind: "query", contains: []string{"FROM pools p", "FOR UPDATE"},
			columns: []string{"pool_id", "membership_epoch"}, rows: [][]driver.Value{{"pool-db-id", int64(1)}}},
		{kind: "query", contains: []string{"FROM membership_epochs me", "FOR UPDATE OF me, mem, m"},
			columns: []string{"member_id"}, rows: [][]driver.Value{{"member-db-id"}}},
		{kind: "query", contains: []string{"SELECT EXISTS"}, columns: []string{"exists"}, rows: [][]driver.Value{{false}}},
		{kind: "query", contains: []string{"SELECT id, assignment_epoch, owner_member_id, status", "sub2api_api_key_id", "FOR UPDATE"},
			columns: []string{"id", "assignment_epoch", "owner_member_id", "status", "principal_id", "subscription_id", "api_key_id", "api_key_version"},
			rows:    [][]driver.Value{{"seat-db-id", int64(2), "member-db-id", "PROVISIONING", nil, nil, nil, int64(0)}}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, _, err := store.CommitProvisionWithCredentialClaim(context.Background(), provisionAggregateInput())
	if !errors.Is(err, application.ErrWorkflowInvalidState) {
		t.Fatalf("expected epoch regression rejection, got %v", err)
	}
	script.assertDone(t)
}

func TestCommitProvisionLocksOperationBeforePoolAndSeat(t *testing.T) {
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"SELECT target_id", "operation_type = 'PROVISION'", "lease_expires_at > CURRENT_TIMESTAMP", "FOR UPDATE"},
			columns: []string{"target_id"}, rows: [][]driver.Value{{nil}}},
		{kind: "query", contains: []string{"FROM pools p", "FOR UPDATE"}, err: errors.New("stop after lock-order assertion")},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, _, _, err := store.CommitProvisionWithCredentialClaim(context.Background(), provisionAggregateInput())
	if err == nil || !strings.Contains(err.Error(), "stop after lock-order assertion") {
		t.Fatalf("expected pool query sentinel after operation lock, got %v", err)
	}
	script.assertDone(t)
}

func TestProvisionTargetUniqueViolationMapsToStableConflict(t *testing.T) {
	err := translateOperationWriteError("insert", fakeSQLStateError{
		state: "23505", message: `duplicate key violates constraint "uq_integration_operations_current_provision_seat_target"`,
	})
	if !errors.Is(err, application.ErrWorkflowTargetConflict) {
		t.Fatalf("expected stable target conflict, got %v", err)
	}
}

func TestCommitCredentialAckValidatesTypedEvidenceAndPersistsCanonicalSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	evidence := application.ProvisionCredentialAckResult{
		ExternalSeatID: "seat-1", ProvisionOperationID: "op-1", ClaimOperationID: "claim-op-1",
		ClaimedBy: "member-1", CredentialFingerprint: strings.Repeat("04", 32), CredentialClaimed: true, ClaimedAt: now,
	}
	row := claimRow("PROVISION", "ACK_PENDING", tokenHash[:], fingerprint[:], aadHash[:], 3, nil, now)
	row[20], _ = json.Marshal(evidence)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "exec", contains: []string{"ack_response_snapshot = COALESCE", "cc.ack_response_snapshot = $9::jsonb", "io.operation_type = 'PROVISION'", "s.external_id = $5", "m.external_id = $7", "cc.credential_fingerprint = $8"}, affected: 1},
		{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(), rows: [][]driver.Value{row}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	claim, err := store.CommitCredentialAck(context.Background(), application.CommitCredentialAckInput{
		Key: application.ClaimKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-a", FencingToken: 3, Evidence: evidence,
	})
	if err != nil || len(claim.AckResultSnapshot) == 0 {
		t.Fatalf("CommitCredentialAck() claim=%+v err=%v", claim, err)
	}
	script.assertDone(t)
}

func TestCommitCredentialAckRejectsIncompleteEvidenceBeforeSQL(t *testing.T) {
	store, cleanup := newFakeStore(t, &fakeScript{})
	defer cleanup()
	_, err := store.CommitCredentialAck(context.Background(), application.CommitCredentialAckInput{
		Key: application.ClaimKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-a", FencingToken: 1,
		Evidence: application.ProvisionCredentialAckResult{CredentialClaimed: false},
	})
	if !errors.Is(err, application.ErrWorkflowInvalidData) {
		t.Fatalf("expected invalid typed evidence, got %v", err)
	}
}

func TestBeginCredentialAckPersistsMarkerBeforeUpstreamCall(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "exec", contains: []string{"status = 'ACK_PENDING'", "cc.lease_owner = $4", "cc.status IN ('READY', 'ACK_RECONCILE_REQUIRED')"}, affected: 1},
		{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(), rows: [][]driver.Value{
			claimRow("PROVISION", "ACK_PENDING", tokenHash[:], fingerprint[:], aadHash[:], 3, "worker-a", now),
		}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	claim, err := store.BeginCredentialAck(context.Background(), application.BeginCredentialAckInput{
		Key: application.ClaimKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-a", FencingToken: 3,
	})
	if err != nil || claim.Status != application.CredentialClaimAckPending || claim.LeaseOwner != "worker-a" {
		t.Fatalf("BeginCredentialAck() claim=%+v err=%v", claim, err)
	}
	script.assertDone(t)
}

func TestCommitCredentialAckFailurePersistsRecoveryOrClearsRejectedSecret(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	for _, tc := range []struct {
		name   string
		status application.CredentialClaimStatus
	}{
		{name: "ambiguous", status: application.CredentialClaimReconcileRequired},
		{name: "rejected", status: application.CredentialClaimRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rowToken, rowAAD := tokenHash[:], aadHash[:]
			if tc.status == application.CredentialClaimRejected {
				rowToken, rowAAD = nil, nil
			}
			script := &fakeScript{steps: []fakeStep{
				{kind: "begin"},
				{kind: "exec", contains: []string{"error_code = $6", "claim_token_hash = CASE WHEN $7", "cc.lease_owner = $4", "cc.ack_response_snapshot IS NULL"}, affected: 1},
				{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(), rows: [][]driver.Value{
					claimRow("PROVISION", string(tc.status), rowToken, fingerprint[:], rowAAD, 3, nil, now),
				}},
				{kind: "commit"},
			}}
			store, cleanup := newFakeStore(t, script)
			defer cleanup()
			claim, err := store.CommitCredentialAckFailure(context.Background(), application.CommitCredentialAckFailureInput{
				Key: application.ClaimKey{ClientID: "client-1", OperationID: "op-1"}, LeaseOwner: "worker-a",
				FencingToken: 3, Status: tc.status, ErrorCode: "SUB2API_ACK_TIMEOUT",
			})
			if err != nil || claim.Status != tc.status {
				t.Fatalf("CommitCredentialAckFailure() claim=%+v err=%v", claim, err)
			}
			if tc.status == application.CredentialClaimReconcileRequired && len(claim.TokenHash) == 0 {
				t.Fatal("ambiguous acknowledgement must retain claim secret")
			}
			if tc.status == application.CredentialClaimRejected && (len(claim.TokenHash) != 0 || len(claim.Envelope.Ciphertext) != 0) {
				t.Fatal("rejected acknowledgement must clear claim secret")
			}
			script.assertDone(t)
		})
	}
}

func TestBeginOperationComparesJSONObjectsSemantically(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	hash := bytes32(1)
	row := operationRow(hash[:], "RUNNING", 0, nil, nil, now)
	row[8] = []byte(`{"a":9007199254740993, "b":2}`)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"INSERT INTO integration_operations"}, columns: operationColumnNames()},
		{kind: "query", contains: []string{"FOR UPDATE"}, columns: operationColumnNames(), rows: [][]driver.Value{row}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()
	_, created, err := store.BeginOperation(context.Background(), application.BeginOperationInput{
		Key: application.OperationKey{ClientID: "client-1", OperationID: "op-1"}, Kind: application.OperationProvision,
		TargetType: "SEAT", TargetExternalID: "seat-1", RequestHash: hash, RequestSnapshot: []byte(`{"b":2,"a":9007199254740993}`),
	})
	if err != nil || created {
		t.Fatalf("semantic replay created=%v err=%v", created, err)
	}
	script.assertDone(t)
}

func TestClaimCredentialRejectsOldFenceBeforeSecretMutation(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "query", contains: []string{"FROM credential_claims cc", "FOR UPDATE OF cc"},
			columns: claimColumnNames(), rows: [][]driver.Value{
				claimRow("PROVISION", "ACK_PENDING", tokenHash[:], fingerprint[:], aadHash[:], 2, "worker-new", now),
			}},
		{kind: "rollback"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	_, err := store.ClaimCredential(context.Background(), application.ClaimCredentialInput{
		Key:        application.ClaimKey{ClientID: "client-1", OperationID: "op-1"},
		LeaseOwner: "worker-old", FencingToken: 1, TargetMemberExternalID: "member-1",
		TokenHash: tokenHash,
	})
	if !errors.Is(err, application.ErrWorkflowStaleFence) {
		t.Fatalf("expected stale fence, got %v", err)
	}
	script.assertDone(t)
}

func TestExpireCredentialClaimClearsAllDeliverableSecrets(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	fingerprint := bytes32(4)
	script := &fakeScript{steps: []fakeStep{
		{kind: "begin"},
		{kind: "exec", contains: []string{
			"status = 'EXPIRED'", "claim_token_hash = NULL", "envelope_algorithm = NULL",
			"envelope_ciphertext = NULL", "envelope_nonce = NULL", "envelope_aad_hash = NULL",
			"wrapped_dek_kms = NULL", "lease_owner = $4", "CURRENT_TIMESTAMP",
		}, affected: 1},
		{kind: "query", contains: []string{"FROM credential_claims cc"}, columns: claimColumnNames(), rows: [][]driver.Value{
			claimRow("PROVISION", "EXPIRED", nil, fingerprint[:], nil, 3, nil, now),
		}},
		{kind: "commit"},
	}}
	store, cleanup := newFakeStore(t, script)
	defer cleanup()

	claim, err := store.ExpireCredentialClaim(context.Background(), application.ExpireCredentialClaimInput{
		Key:        application.ClaimKey{ClientID: "client-1", OperationID: "op-1"},
		LeaseOwner: "worker-a", FencingToken: 3,
	})
	if err != nil {
		t.Fatalf("ExpireCredentialClaim(): %v", err)
	}
	if len(claim.TokenHash) != 0 || len(claim.Envelope.Ciphertext) != 0 || len(claim.Envelope.WrappedDEK) != 0 {
		t.Fatalf("terminal claim retained deliverable secret: %+v", claim)
	}
	script.assertDone(t)
}

func TestPhase2AMigrationMatchesStoreContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "migrations", "002_phase2a_persistence.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sqlText := string(content)
	for _, required := range []string{
		"ADD COLUMN request_snapshot jsonb", "ADD COLUMN lease_owner text",
		"ADD COLUMN lease_expires_at timestamptz", "ADD COLUMN fencing_token bigint",
		"CREATE TABLE credential_claims", "claim_token_hash bytea", "envelope_ciphertext bytea",
		"wrapped_dek_kms bytea", "status IN ('CLAIMED', 'EXPIRED', 'REJECTED')",
		"claim_token_hash IS NULL", "envelope_ciphertext IS NULL", "wrapped_dek_kms IS NULL",
		"CREATE TABLE control_rotation_evidence", "CREATE TABLE control_rotation_evidence_batches",
		"provision credential cannot claim directly from READY",
	} {
		if !strings.Contains(sqlText, required) {
			t.Errorf("migration missing Store contract fragment %q", required)
		}
	}
	storeSource, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store source: %v", err)
	}
	for _, required := range []string{
		"CURRENT_TIMESTAMP + make_interval", "lease_expires_at > CURRENT_TIMESTAMP",
		"claim_token_hash = NULL", "envelope_ciphertext = NULL", "wrapped_dek_kms = NULL",
		"request_snapshot", "target_external_id", "io.status = 'SUCCEEDED'",
		"operation_type IN ('PROVISION', 'ASSIGN_TEMPORARY', 'RESTORE', 'REPLACE_PERMANENTLY')",
		"cc.claim_operation_id = $6",
	} {
		if !strings.Contains(string(storeSource), required) {
			t.Errorf("Store SQL missing migration contract fragment %q", required)
		}
	}
	if strings.Contains(string(storeSource), "OR lease_owner = $3") ||
		strings.Contains(string(storeSource), "OR cc.lease_owner = $3") {
		t.Error("Acquire must not steal an unexpired lease from another worker sharing the same owner name")
	}
}

func TestProvisionClaimRequiresDurableAckSnapshot(t *testing.T) {
	claim := &application.StoredCredentialClaim{
		OperationKind: application.OperationProvision,
		Status:        application.CredentialClaimAckPending,
	}
	if claimAllowsDelivery(claim) {
		t.Fatal("provision claim without durable ack snapshot must fail closed")
	}
	claim.AckResultSnapshot = []byte(`{"external_seat_id":"seat-1","provision_operation_id":"op-1","claim_operation_id":"claim-op-1","claimed_by":"member-1","credential_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_claimed":true,"claimed_at":"2026-08-18T01:00:00Z"}`)
	if !claimAllowsDelivery(claim) {
		t.Fatal("provision claim with durable ack snapshot should be deliverable")
	}
}

func bytes32(value byte) [32]byte {
	var result [32]byte
	for i := range result {
		result[i] = value
	}
	return result
}

func provisionAggregateInput() application.CommitProvisionWithCredentialClaimInput {
	tokenHash, fingerprint, aadHash := bytes32(3), bytes32(4), bytes32(5)
	claim := application.CreateCredentialClaimInput{
		Key:            application.ClaimKey{ClientID: "client-1", OperationID: "op-1"},
		SeatExternalID: "seat-1", TargetMemberExternalID: "member-1", ClaimOperationID: "claim-op-1",
		TokenHash: tokenHash, CredentialFingerprint: fingerprint,
		Envelope: application.CredentialEnvelope{Algorithm: "AES-256-GCM", KeyRef: "kms/key/1", Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), AADHash: aadHash, WrappedDEK: []byte("dek")},
		ClaimTTL: 10 * time.Minute,
	}
	return application.CommitProvisionWithCredentialClaimInput{
		Operation: application.CommitOperationWithCredentialClaimInput{
			Key:        application.OperationKey{ClientID: "client-1", OperationID: "op-1"},
			LeaseOwner: "worker-1", FencingToken: 1, ResultSnapshot: []byte(`{"applied":true}`), Claim: claim,
		},
		PoolExternalID: "pool-1", OwnerExternalID: "member-1", ExistingGroupID: 10, AssignmentEpoch: 1,
		PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301,
	}
}

func operationColumnNames() []string {
	return []string{"id", "integration_client_id", "operation_id", "operation_type", "target_type",
		"target_external_id", "migration_state", "request_hash", "request_snapshot", "status", "attempt_count", "response_snapshot",
		"error_code", "error_detail", "fencing_token", "lease_owner", "lease_expires_at", "next_attempt_at", "created_at", "updated_at", "completed_at"}
}

func operationRow(hash []byte, status string, fence int64, owner any, leaseExpiry any, now time.Time) []driver.Value {
	return []driver.Value{
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "client-1", "op-1", "PROVISION", "SEAT", "seat-1", "CURRENT",
		hash, []byte(`{"external_seat_id":"seat-1"}`), status, int64(1), nil, nil, nil, fence,
		owner, leaseExpiry, nil, now, now, nil,
	}
}

func claimColumnNames() []string {
	return []string{"id", "integration_operation_id", "integration_client_id", "operation_id", "operation_type",
		"seat_id", "seat_external_id", "target_member_id", "target_member_external_id", "claim_operation_id", "claim_token_hash", "credential_fingerprint", "claim_intent_hash",
		"envelope_algorithm", "envelope_key_ref", "envelope_ciphertext", "envelope_nonce", "envelope_aad_hash",
		"wrapped_dek_kms", "status", "ack_response_snapshot", "error_code", "fencing_token", "lease_owner",
		"lease_expires_at", "expires_at", "expired", "claimed_at", "terminal_at", "created_at", "updated_at"}
}

func claimRow(kind, status string, tokenHash, fingerprint, aadHash []byte, fence int64, owner any, now time.Time) []driver.Value {
	intentHash := bytes32(9)
	terminal := any(nil)
	claimed := any(nil)
	algorithm, keyRef, ciphertext, nonce, wrapped := any("AES-256-GCM"), any("kms/key/1"), any([]byte("ciphertext")), any([]byte("nonce")), any([]byte("wrapped"))
	if status == "CLAIMED" || status == "EXPIRED" || status == "REJECTED" {
		terminal = now
		algorithm, keyRef, ciphertext, nonce, wrapped = nil, nil, nil, nil, nil
		if status == "CLAIMED" {
			claimed = now
		}
	}
	return []driver.Value{
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "client-1", "op-1", kind,
		"11111111-1111-1111-1111-111111111111", "seat-1", "22222222-2222-2222-2222-222222222222", "member-1", "claim-op-1",
		tokenHash, fingerprint, intentHash[:], algorithm, keyRef, ciphertext, nonce, aadHash, wrapped, status, nil, nil, fence,
		owner, now.Add(time.Minute), now.Add(10 * time.Minute), status == "EXPIRED", claimed, terminal, now, now,
	}
}

type fakeStep struct {
	kind     string
	contains []string
	columns  []string
	rows     [][]driver.Value
	affected int64
	err      error
}

type fakeSQLStateError struct{ state, message string }

func (e fakeSQLStateError) Error() string    { return e.message }
func (e fakeSQLStateError) SQLState() string { return e.state }

type fakeScript struct {
	mu    sync.Mutex
	steps []fakeStep
	next  int
}

func (s *fakeScript) take(kind, query string) (fakeStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.steps) {
		return fakeStep{}, fmt.Errorf("unexpected %s: %s", kind, query)
	}
	step := s.steps[s.next]
	if step.kind != kind {
		return fakeStep{}, fmt.Errorf("step %d: got %s, want %s", s.next, kind, step.kind)
	}
	for _, fragment := range step.contains {
		if !strings.Contains(query, fragment) {
			return fakeStep{}, fmt.Errorf("step %d query missing %q: %s", s.next, fragment, query)
		}
	}
	s.next++
	return step, nil
}

func (s *fakeScript) assertDone(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next != len(s.steps) {
		t.Fatalf("fake SQL consumed %d/%d steps; next=%s", s.next, len(s.steps), s.steps[s.next].kind)
	}
}

var fakeDriverSequence atomic.Uint64

func newFakeStore(t *testing.T, script *fakeScript) (*Store, func()) {
	t.Helper()
	name := fmt.Sprintf("phase2a_fake_%d", fakeDriverSequence.Add(1))
	sql.Register(name, &fakeDriver{script: script})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("open fake database: %v", err)
	}
	db.SetMaxOpenConns(1)
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore(): %v", err)
	}
	return store, func() { _ = db.Close() }
}

type fakeDriver struct{ script *fakeScript }

func (d *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{script: d.script}, nil }

type fakeConn struct{ script *fakeScript }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return c.begin() }
func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.begin()
}
func (c *fakeConn) begin() (driver.Tx, error) {
	if _, err := c.script.take("begin", ""); err != nil {
		return nil, err
	}
	return &fakeTx{script: c.script}, nil
}
func (c *fakeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	step, err := c.script.take("query", query)
	if err != nil {
		return nil, err
	}
	if step.err != nil {
		return nil, step.err
	}
	return &fakeRows{columns: step.columns, rows: step.rows}, nil
}
func (c *fakeConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	step, err := c.script.take("exec", query)
	if err != nil {
		return nil, err
	}
	if step.err != nil {
		return nil, step.err
	}
	return driver.RowsAffected(step.affected), nil
}

type fakeTx struct{ script *fakeScript }

func (tx *fakeTx) Commit() error {
	_, err := tx.script.take("commit", "")
	return err
}
func (tx *fakeTx) Rollback() error {
	_, err := tx.script.take("rollback", "")
	return err
}

type fakeRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *fakeRows) Columns() []string { return r.columns }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}
