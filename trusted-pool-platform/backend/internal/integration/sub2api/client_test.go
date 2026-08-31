package sub2api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/recovery"
)

func TestRecoveryRotationClientUsesDedicatedProtocolAndVerifiesEd25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Integration-Client-ID") != "recovery-rotation-client" ||
			request.Header.Get("Authorization") != "Bearer recovery-rotation-secret" {
			t.Fatal("recovery rotation request did not use its dedicated identity")
		}
		switch request.URL.Path {
		case "/api/v1/integrations/trusted-pools/permanent-rotations/prepare":
			var input permanentRotationPrepareRequest
			if json.NewDecoder(request.Body).Decode(&input) != nil || request.Header.Get("Idempotency-Key") != input.OperationID {
				t.Fatal("prepare request lost exact idempotency binding")
			}
			credential := "credential-seat-1"
			fingerprint := sha256.Sum256([]byte(credential))
			prepared := permanentRotationPreparedSeat{permanentRotationPrepareSeat: input.Seats[0],
				Credential: credential, CredentialFingerprint: hex.EncodeToString(fingerprint[:]),
				ActiveAPIKeyVersion: input.Seats[0].ToAPIKeyVersion, PreparedRotationRef: "prepared-seat-1",
				State: "ROTATION_PREPARED", CredentialRotationComplete: true, CompletedAt: now}
			binding := recovery.PermanentSeatActivationBinding{SeatID: input.Seats[0].ExternalSeatID,
				TargetMemberID:          input.Seats[0].TargetMemberID,
				ExpectedAssignmentEpoch: input.Seats[0].ExpectedAssignmentEpoch,
				PrincipalUserID:         input.Seats[0].PrincipalUserID, SubscriptionID: input.Seats[0].SubscriptionID,
				APIKeyID: input.Seats[0].APIKeyID, ActiveAPIKeyVersion: input.Seats[0].ToAPIKeyVersion,
				ChildOperationID:      input.Seats[0].ChildOperationID,
				ChildRequestHash:      mustDecodeTestHash(t, input.Seats[0].ChildRequestHash),
				CredentialFingerprint: fingerprint, PreparedRotationRef: prepared.PreparedRotationRef}
			preparedSet, hashErr := recovery.PermanentPreparedSeatSetHash([]recovery.PermanentSeatActivationBinding{binding})
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			response := permanentRotationPrepareResponse{OperationID: input.OperationID,
				ProtocolVersion: input.ProtocolVersion, ExternalPoolID: input.ExternalPoolID, PlanID: input.PlanID,
				CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch, ToEpoch: input.ToEpoch,
				RequestHash: input.RequestHash, ChildSetHash: input.ChildSetHash,
				PreparedSetHash: hex.EncodeToString(preparedSet[:]), Status: "PREPARED",
				CredentialsDisclosed: true, Seats: []permanentRotationPreparedSeat{prepared}}
			response.Attestation = signPrepareAttestationForTest(t, response, privateKey)
			writeEnvelope(t, writer, response)
		case "/api/v1/integrations/trusted-pools/permanent-rotations/activate":
			var input permanentRotationActivateRequest
			if json.NewDecoder(request.Body).Decode(&input) != nil || request.Header.Get("Idempotency-Key") != input.OperationID {
				t.Fatal("activation request lost exact idempotency binding")
			}
			response := permanentRotationActivationResponse{ProtocolVersion: input.ProtocolVersion,
				OperationID: input.OperationID, RequestHash: input.RequestHash,
				PrepareOperationID: input.PrepareOperationID, ExternalPoolID: input.ExternalPoolID,
				PlanID: input.PlanID, CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch,
				ToEpoch: input.ToEpoch, PreparedSetHash: input.PreparedSetHash, Status: "ACTIVATED_PENDING_COMMIT",
				AllCredentialsEnabled: false, AllSubscriptionsEnabled: false, OldCredentialSetInvalidated: true,
				CredentialFingerprintGateEnforced: true, ObservedAt: now,
				Seats: []permanentRotationActivatedSeat{{permanentRotationActivateSeat: input.Seats[0],
					AssignmentEpoch: input.Seats[0].ExpectedAssignmentEpoch + 1}}}
			response.AuthCacheBarrier.DurableOutbox = true
			response.AuthCacheBarrier.MinimumEvents = 2
			response.Attestation = signActivationAttestationForTest(t, response, privateKey)
			writeEnvelope(t, writer, response)
		case "/api/v1/integrations/trusted-pools/permanent-rotations/commit":
			var input permanentRotationCommitRequest
			if json.NewDecoder(request.Body).Decode(&input) != nil || request.Header.Get("Idempotency-Key") != input.OperationID {
				t.Fatal("commit request lost exact idempotency binding")
			}
			response := permanentRotationCommitResponse{ProtocolVersion: input.ProtocolVersion,
				OperationID: input.OperationID, RequestHash: input.RequestHash,
				PrepareOperationID: input.PrepareOperationID, ActivationOperationID: input.ActivationOperationID,
				ActivationRequestHash: input.ActivationRequestHash, ExternalPoolID: input.ExternalPoolID,
				PlanID: input.PlanID, CeremonyType: input.CeremonyType, FromEpoch: input.FromEpoch,
				ToEpoch: input.ToEpoch, PreparedSetHash: input.PreparedSetHash, Status: "COMMITTED",
				AllCredentialsEnabled: true, AllSubscriptionsEnabled: true, OldCredentialSetInvalidated: true,
				CredentialFingerprintGateEnforced: true, ObservedAt: now,
				Seats: []permanentRotationActivatedSeat{{permanentRotationActivateSeat: input.Seats[0],
					AssignmentEpoch: input.Seats[0].ExpectedAssignmentEpoch + 1}}}
			response.AuthCacheBarrier.DurableOutbox = true
			response.AuthCacheBarrier.MinimumEvents = 1
			response.Attestation = signCommitAttestationForTest(t, response, privateKey)
			writeEnvelope(t, writer, response)
		default:
			t.Fatalf("unexpected recovery rotation path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewRecoveryRotationClient(server.URL, "recovery-rotation-client",
		"recovery-rotation-secret", "rotation-key-1", publicKey, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	seat := recovery.PermanentSeatRotationPrepareRequest{ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID: "child-op-1", PlanID: "plan-1", CeremonyType: recovery.CeremonyRotate,
		PoolID: "pool-1", FromEpoch: 7, ToEpoch: 8, SeatID: "seat-1", TargetMemberID: "member-new",
		ExpectedAssignmentEpoch: 3, PrincipalUserID: 101, SubscriptionID: 202, APIKeyID: 303,
		FromAPIKeyVersion: 3, ToAPIKeyVersion: 4}
	seat.RequestHash = recovery.PermanentSeatRotationPrepareRequestHash(seat)
	childSet, _ := recovery.PermanentRotationChildSetHash([]recovery.PermanentSeatRotationPrepareRequest{seat})
	prepare := recovery.PermanentPoolRotationPrepareRequest{ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID: "prepare-pool-op", PlanID: "plan-1", CeremonyType: recovery.CeremonyRotate,
		PoolID: "pool-1", FromEpoch: 7, ToEpoch: 8, ChildSetHash: childSet,
		Seats: []recovery.PermanentSeatRotationPrepareRequest{seat}}
	prepare.RequestHash = recovery.PermanentPoolRotationPrepareRequestHash(prepare)
	prepared, err := client.PreparePoolRotation(context.Background(), prepare)
	if err != nil || len(prepared.Seats) != 1 || string(prepared.Seats[0].Credential) != "credential-seat-1" {
		t.Fatalf("PreparePoolRotation() = %+v, %v", prepared, err)
	}
	fingerprint := sha256.Sum256(prepared.Seats[0].Credential)
	binding := recovery.PermanentSeatActivationBinding{SeatID: seat.SeatID, TargetMemberID: seat.TargetMemberID,
		ExpectedAssignmentEpoch: seat.ExpectedAssignmentEpoch, PrincipalUserID: seat.PrincipalUserID,
		SubscriptionID: seat.SubscriptionID, APIKeyID: seat.APIKeyID, ActiveAPIKeyVersion: seat.ToAPIKeyVersion,
		ChildOperationID: seat.OperationID, ChildRequestHash: seat.RequestHash,
		CredentialFingerprint: fingerprint, PreparedRotationRef: prepared.Seats[0].PreparedRotationRef}
	preparedSet, _ := recovery.PermanentPreparedSeatSetHash([]recovery.PermanentSeatActivationBinding{binding})
	activate := recovery.PermanentPoolRotationActivateRequest{ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID: "activate-pool-op", PrepareOperationID: prepare.OperationID, PlanID: "plan-1",
		CeremonyType: recovery.CeremonyRotate, PoolID: "pool-1", FromEpoch: 7, ToEpoch: 8,
		PreparedSetHash: preparedSet, Seats: []recovery.PermanentSeatActivationBinding{binding}}
	activate.RequestHash = recovery.PermanentPoolRotationActivateRequestHash(activate)
	activated, err := client.ActivatePreparedPoolRotation(context.Background(), activate)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.VerifyPermanentPoolRotationActivateResult(context.Background(), client, activate, activated); err != nil {
		t.Fatalf("signed activation was rejected: %v", err)
	}
	commit := recovery.PermanentPoolRotationCommitRequest{ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		OperationID: "commit-pool-op", PrepareOperationID: prepare.OperationID,
		ActivationOperationID: activate.OperationID, ActivationRequestHash: activate.RequestHash,
		PlanID: activate.PlanID, CeremonyType: activate.CeremonyType, PoolID: activate.PoolID,
		FromEpoch: activate.FromEpoch, ToEpoch: activate.ToEpoch, PreparedSetHash: preparedSet,
		Seats: []recovery.PermanentSeatActivationBinding{binding}}
	commit.RequestHash = recovery.PermanentPoolRotationCommitRequestHash(commit)
	committed, err := client.CommitActivatedPoolRotation(context.Background(), commit)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.VerifyPermanentPoolRotationCommitResult(context.Background(), client, commit, committed); err != nil {
		t.Fatalf("signed commit was rejected: %v", err)
	}
	committed.Attestation[0] ^= 0xff
	if err := recovery.VerifyPermanentPoolRotationCommitResult(context.Background(), client, commit, committed); !errors.Is(err, recovery.ErrSignatureInvalid) {
		t.Fatalf("tampered commit signature = %v", err)
	}
	activated.Attestation[0] ^= 0xff
	if err := recovery.VerifyPermanentPoolRotationActivateResult(context.Background(), client, activate, activated); !errors.Is(err, recovery.ErrSignatureInvalid) {
		t.Fatalf("tampered activation signature = %v", err)
	}
}

func signPrepareAttestationForTest(t *testing.T, response permanentRotationPrepareResponse,
	privateKey ed25519.PrivateKey) *permanentRotationAttestation {
	t.Helper()
	digest, err := permanentPrepareAttestationDigest(response)
	if err != nil {
		t.Fatal(err)
	}
	return testRotationAttestation(digest, privateKey)
}

func TestPermanentPrepareAttestationBindsDisclosureAndDisabledState(t *testing.T) {
	response := permanentRotationPrepareResponse{
		OperationID: "prepare-op", ProtocolVersion: recovery.PermanentSeatRotationProtocolV1,
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: string(recovery.CeremonyRotate),
		FromEpoch: 7, ToEpoch: 8, RequestHash: strings.Repeat("1", 64),
		ChildSetHash: strings.Repeat("2", 64), PreparedSetHash: strings.Repeat("3", 64),
		Status: "PREPARED", CredentialsDisclosed: true,
		Seats: []permanentRotationPreparedSeat{{
			permanentRotationPrepareSeat: permanentRotationPrepareSeat{
				ExternalSeatID: "seat-1", TargetMemberID: "member-1", ExpectedAssignmentEpoch: 3,
				PrincipalUserID: 11, SubscriptionID: 12, APIKeyID: 13, ChildOperationID: "child-op",
				ChildRequestHash: strings.Repeat("4", 64),
			},
			ActiveAPIKeyVersion: 4, CredentialFingerprint: strings.Repeat("5", 64),
			PreparedRotationRef: "prepared-1", State: "ROTATION_PREPARED",
			CredentialRotationComplete: true,
		}},
	}
	want, err := permanentPrepareAttestationDigest(response)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*permanentRotationPrepareResponse){
		func(value *permanentRotationPrepareResponse) { value.CredentialsDisclosed = false },
		func(value *permanentRotationPrepareResponse) { value.Seats[0].CredentialEnabled = true },
		func(value *permanentRotationPrepareResponse) { value.Seats[0].SubscriptionEnabled = true },
		func(value *permanentRotationPrepareResponse) { value.Seats[0].CredentialRotationComplete = false },
	}
	for index, mutate := range mutations {
		changed := response
		changed.Seats = append([]permanentRotationPreparedSeat(nil), response.Seats...)
		mutate(&changed)
		got, digestErr := permanentPrepareAttestationDigest(changed)
		if digestErr != nil {
			t.Fatalf("mutation %d: %v", index, digestErr)
		}
		if got == want {
			t.Fatalf("mutation %d was not bound by prepare attestation", index)
		}
	}
}

func signActivationAttestationForTest(t *testing.T, response permanentRotationActivationResponse,
	privateKey ed25519.PrivateKey) *permanentRotationAttestation {
	t.Helper()
	response.Attestation = &permanentRotationAttestation{Version: "trusted-pool/permanent-rotation-attestation/v1",
		Issuer: "sub2api", KeyID: "rotation-key-1", Reference: "temporary", Digest: strings.Repeat("0", 64),
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	mapped, err := mapPermanentRotationActivationResult(response)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := recovery.PermanentPoolRotationActivationAttestationDigest(mapped)
	if err != nil {
		t.Fatal(err)
	}
	return testRotationAttestation(digest, privateKey)
}

func signCommitAttestationForTest(t *testing.T, response permanentRotationCommitResponse,
	privateKey ed25519.PrivateKey) *permanentRotationAttestation {
	t.Helper()
	response.Attestation = &permanentRotationAttestation{Version: "trusted-pool/permanent-rotation-attestation/v1",
		Issuer: "sub2api", KeyID: "rotation-key-1", Reference: "temporary", Digest: strings.Repeat("0", 64),
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	mapped, err := mapPermanentRotationCommitResult(response)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := recovery.PermanentPoolRotationCommitAttestationDigest(mapped)
	if err != nil {
		t.Fatal(err)
	}
	return testRotationAttestation(digest, privateKey)
}

func testRotationAttestation(digest [sha256.Size]byte, privateKey ed25519.PrivateKey) *permanentRotationAttestation {
	encoded := hex.EncodeToString(digest[:])
	return &permanentRotationAttestation{Version: "trusted-pool/permanent-rotation-attestation/v1",
		Issuer: "sub2api", KeyID: "rotation-key-1", Reference: "tpra-" + encoded[:32], Digest: encoded,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))}
}

func mustDecodeTestHash(t *testing.T, value string) [sha256.Size]byte {
	t.Helper()
	decoded, err := decodePermanentRotationHash(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestClientSuspendDrainFreezeContract(t *testing.T) {
	freezeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Integration-Client-ID") != "pool-client" || request.Header.Get("Authorization") != "Bearer integration-secret" {
			t.Fatalf("missing integration authentication: %+v", request.Header)
		}
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			if request.Header.Get("Idempotency-Key") != "op-1" {
				t.Fatal("missing idempotency key")
			}
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 3, "current_concurrency": 1, "pending_settlements": 0})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 3, "current_concurrency": 0, "pending_settlements": 0})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/freeze":
			freezeCalls++
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 3, "current_concurrency": 0, "pending_settlements": 0,
				"usage_snapshot": quotaSnapshot()})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 3})
	if err != nil || !result.Draining {
		t.Fatalf("expected draining: result=%+v err=%v", result, err)
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Applied || status.Freeze == nil || status.Freeze.AssignmentEpoch != 3 ||
		status.Freeze.PendingSettlements != 0 || freezeCalls != 1 {
		t.Fatalf("unexpected freeze reconciliation: result=%+v calls=%d err=%v", status, freezeCalls, err)
	}
}

func TestClientSuspendRejectsUnboundSeatResponse(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]any
	}{
		{name: "different seat", response: map[string]any{"external_seat_id": "seat-2", "state": "draining", "assignment_epoch": 3}},
		{name: "different pool", response: map[string]any{"external_seat_id": "seat-1", "external_pool_id": "pool-2", "state": "draining", "assignment_epoch": 3}},
		{name: "missing seat id", response: map[string]any{"state": "draining", "assignment_epoch": 3}},
		{name: "missing pool id", response: map[string]any{"external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 3}},
		{name: "stale epoch", response: map[string]any{"external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.response["current_concurrency"] = 1
			test.response["pending_settlements"] = 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeEnvelope(t, writer, test.response)
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
			_, err := client.Suspend(context.Background(), application.SuspendCommand{
				OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 3,
			})
			assertAmbiguousSuspendIdentityError(t, err)
		})
	}
}

func TestClientReconcileSuspendRejectsUnboundResponses(t *testing.T) {
	tests := []struct {
		name       string
		drain      map[string]any
		freeze     map[string]any
		wantFreeze bool
	}{
		{name: "active different seat", drain: map[string]any{"external_seat_id": "seat-2", "state": "active", "assignment_epoch": 3}},
		{name: "draining different pool", drain: map[string]any{"external_seat_id": "seat-1", "external_pool_id": "pool-2", "state": "draining", "assignment_epoch": 3}},
		{name: "frozen missing seat id", drain: map[string]any{"state": "frozen", "assignment_epoch": 3}},
		{
			name:       "freeze stale epoch",
			drain:      map[string]any{"external_seat_id": "seat-1", "external_pool_id": "pool-1", "state": "draining", "assignment_epoch": 3},
			freeze:     map[string]any{"external_seat_id": "seat-1", "external_pool_id": "pool-1", "state": "frozen", "assignment_epoch": 2},
			wantFreeze: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.drain["current_concurrency"] = 0
			test.drain["pending_settlements"] = 0
			test.drain["usage_snapshot"] = quotaSnapshot()
			if test.freeze != nil {
				test.freeze["current_concurrency"] = 0
				test.freeze["pending_settlements"] = 0
				test.freeze["usage_snapshot"] = quotaSnapshot()
			}
			freezeCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost {
					freezeCalls++
					writeEnvelope(t, writer, test.freeze)
					return
				}
				writeEnvelope(t, writer, test.drain)
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
			_, err := client.ReconcileSuspend(context.Background(), application.SuspendCommand{
				OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 3,
			})
			assertAmbiguousSuspendIdentityError(t, err)
			if test.wantFreeze != (freezeCalls == 1) {
				t.Fatalf("freeze calls=%d wantFreeze=%v", freezeCalls, test.wantFreeze)
			}
		})
	}
}

func assertAmbiguousSuspendIdentityError(t *testing.T, err error) {
	t.Helper()
	var gatewayErr *application.GatewayError
	if !errors.As(err, &gatewayErr) || !gatewayErr.Retryable || !gatewayErr.Ambiguous {
		t.Fatalf("unbound suspend response was not failed closed: %#v", err)
	}
}

func TestClientReconcileSuspendAfterRestartUsesExplicitCommand(t *testing.T) {
	freezeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 3,
				"current_concurrency": 0, "pending_settlements": 0,
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/freeze":
			freezeCalls++
			if request.Header.Get("Idempotency-Key") != "op-restart" {
				t.Fatalf("freeze lost persisted operation id: %q", request.Header.Get("Idempotency-Key"))
			}
			writeEnvelope(t, writer, map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 3,
				"current_concurrency": 0, "pending_settlements": 0,
				"usage_snapshot": quotaSnapshot(),
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	// 新建 Client 模拟进程重启，未调用 Suspend，因此进程内 operations map 为空。
	restarted, err := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.ReconcileSuspend(context.Background(), application.SuspendCommand{
		OperationID: "op-restart", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 3,
	})
	if err != nil || !result.Applied || result.Freeze == nil || freezeCalls != 1 {
		t.Fatalf("restart reconcile result=%+v freezeCalls=%d err=%v", result, freezeCalls, err)
	}
}

func TestClientProvisionSeatContract(t *testing.T) {
	expiresAt := time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/integrations/trusted-pools/seats/provision" {
			t.Fatalf("unexpected provision request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "provision-1" {
			t.Fatal("provision omitted idempotency key")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["external_pool_id"] != "pool-1" || body["external_seat_id"] != "seat-1" || body["existing_group_id"] != float64(7) ||
			body["principal_concurrency"] != float64(2) || body["api_key_rate_limit_5h"] != float64(25) {
			t.Fatalf("unexpected provision body: %+v", body)
		}
		if _, exists := body["owner_user_id"]; exists {
			t.Fatal("platform owner identity must not be injected into Sub2API principal fields")
		}
		writeEnvelope(t, writer, map[string]any{
			"seat": map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 1,
				"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301, "last_operation_id": "provision-1",
			},
			"credential": "provisioned-key",
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := client.ProvisionSeat(context.Background(), application.ProvisionSeatCommand{
		OperationID: "provision-1", SeatID: "seat-1", PoolID: "pool-1", OwnerUserID: "owner-1",
		ExistingGroupID: 7, AssignmentEpoch: 1, PrincipalConcurrency: 2,
		SubscriptionExpiresAt: expiresAt, APIKeyRateLimit5h: 25,
	})
	if err != nil || result.Credential != "provisioned-key" || result.ExternalSeatID != "seat-1" {
		t.Fatalf("unexpected provision result: result=%+v err=%v", result, err)
	}
}

func TestClientAcknowledgesProvisionCredentialWithoutReturningSecret(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/integrations/trusted-pools/seats/seat-1/provision-credential/ack" {
			t.Fatalf("unexpected ack request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "claim-1" {
			t.Fatal("credential ack omitted idempotency key")
		}
		var body application.ProvisionCredentialAckCommand
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.ProvisionOperationID != "provision-1" || body.ClaimOperationID != "claim-1" ||
			body.ClaimedBy != "owner-1" || body.CredentialFingerprint != strings.Repeat("a", 64) {
			t.Fatalf("unexpected credential ack body: %+v", body)
		}
		writeEnvelope(t, writer, map[string]any{
			"external_seat_id": "seat-1", "provision_operation_id": "provision-1",
			"claim_operation_id": "claim-1", "claimed_by": "owner-1",
			"credential_fingerprint": strings.Repeat("a", 64),
			"credential_claimed":     true, "claimed_at": now,
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := client.AcknowledgeProvisionCredential(context.Background(), application.ProvisionCredentialAckCommand{
		SeatID: "seat-1", ProvisionOperationID: "provision-1", ClaimOperationID: "claim-1",
		ClaimedBy: "owner-1", CredentialFingerprint: strings.Repeat("a", 64),
	})
	if err != nil || !result.CredentialClaimed || result.ClaimOperationID != "claim-1" {
		t.Fatalf("unexpected ack result: result=%+v err=%v", result, err)
	}
}

func TestClientKeepsDrainingWhileConcurrencyIsNonZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1, "current_concurrency": 2, "pending_settlements": 0})
			return
		}
		writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1, "current_concurrency": 2, "pending_settlements": 0})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, _ = client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 1})
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || status.Applied {
		t.Fatalf("unexpected status: %+v err=%v", status, err)
	}
}

func TestClientRejectsDrainingResponseWithoutObservedCounters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, map[string]any{"external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	gatewayErr, ok := err.(*application.GatewayError)
	if !ok || !gatewayErr.Retryable || !gatewayErr.Ambiguous {
		t.Fatalf("missing barrier evidence was accepted: %#v", err)
	}
}

func TestClientKeepsDrainingWhileSettlementIsPending(t *testing.T) {
	freezeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1, "current_concurrency": 0, "pending_settlements": 1})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1,
				"current_concurrency": 0, "pending_settlements": 1,
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/freeze":
			freezeCalls++
			t.Fatal("pending settlement 未清零时不得调用 freeze")
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, _ = client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 1})
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || status.Applied || freezeCalls != 0 {
		t.Fatalf("unexpected settlement barrier status: status=%+v freeze_calls=%d err=%v", status, freezeCalls, err)
	}
}

func TestClientPendingSettlementManagementContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/settlements":
			if request.Header.Get("X-Integration-Client-ID") != "settlement-read" || request.Header.Get("Authorization") != "Bearer settlement-read-secret" {
				t.Fatal("settlement read did not use independent read credentials")
			}
			if request.URL.Query().Get("limit") != "25" {
				t.Fatalf("unexpected pending limit %q", request.URL.RawQuery)
			}
			writeEnvelope(t, writer, []map[string]any{{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "request_id": "request-1",
				"assignment_epoch": 2, "status": "failed", "attempt_count": 1, "created_at": now, "updated_at": now,
			}})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/settlements/settlement-1":
			if request.Header.Get("X-Integration-Client-ID") != "settlement-read" || request.Header.Get("Authorization") != "Bearer settlement-read-secret" {
				t.Fatal("settlement detail did not use independent read credentials")
			}
			writeEnvelope(t, writer, map[string]any{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "request_id": "request-1",
				"assignment_epoch": 2, "status": "failed", "attempt_count": 1, "created_at": now, "updated_at": now,
				"credential": "must-not-cross-platform-contract",
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/settlements/settlement-1/resolve":
			if request.Header.Get("X-Integration-Client-ID") != "settlement-resolve" || request.Header.Get("Authorization") != "Bearer settlement-resolve-secret" {
				t.Fatal("settlement resolve did not use independent resolve credentials")
			}
			if request.Header.Get("Idempotency-Key") != "resolve-1" {
				t.Fatal("resolve omitted operation idempotency key")
			}
			var command application.ResolvePendingSettlementCommand
			if err := json.NewDecoder(request.Body).Decode(&command); err != nil {
				t.Fatal(err)
			}
			if command.OperationID != "resolve-1" || command.ExpectedAssignmentEpoch != 2 || command.ExpectedRequestID != "request-1" ||
				command.Reason != "usage verified" || command.Evidence != "ticket-123" {
				t.Fatalf("unexpected resolve command: %+v", command)
			}
			writeEnvelope(t, writer, map[string]any{
				"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1", "operation_id": "resolve-1",
				"actor_client_id": "settlement-resolve", "assignment_epoch": 2, "request_id": "request-1",
				"reason": "usage verified", "evidence": "ticket-123", "resolved_at": now,
				"credential": "must-not-cross-platform-contract",
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	readClient, _ := NewSettlementReadClient(server.URL, "settlement-read", "settlement-read-secret", server.Client())
	resolveClient, _ := NewSettlementResolveClient(server.URL, "settlement-resolve", "settlement-resolve-secret", server.Client())
	items, err := readClient.ListPendingSettlements(context.Background(), "seat-1", 25)
	if err != nil || len(items) != 1 || items[0].SettlementID != "settlement-1" {
		t.Fatalf("unexpected pending list: items=%+v err=%v", items, err)
	}
	detail, err := readClient.GetPendingSettlement(context.Background(), "seat-1", "settlement-1")
	if err != nil || detail.RequestID != "request-1" {
		t.Fatalf("unexpected pending detail: item=%+v err=%v", detail, err)
	}
	resolution, err := resolveClient.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", application.ResolvePendingSettlementCommand{
		OperationID: "resolve-1", ExpectedAssignmentEpoch: 2, ExpectedRequestID: "request-1",
		Reason: "usage verified", Evidence: "ticket-123",
	})
	if err != nil || resolution.OperationID != "resolve-1" {
		t.Fatalf("unexpected resolution: resolution=%+v err=%v", resolution, err)
	}
	encoded, _ := json.Marshal(struct {
		Detail     *application.PendingSettlement    `json:"detail"`
		Resolution *application.SettlementResolution `json:"resolution"`
	}{Detail: detail, Resolution: resolution})
	if strings.Contains(string(encoded), "credential") || strings.Contains(string(encoded), "must-not-cross-platform-contract") {
		t.Fatalf("pending DTO leaked upstream credential field: %s", encoded)
	}
}

func TestSettlementClientsRejectMismatchedBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	readCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong seat", func(value map[string]any) { value["external_seat_id"] = "seat-2" }},
		{"missing epoch", func(value map[string]any) { delete(value, "assignment_epoch") }},
		{"missing request", func(value map[string]any) { delete(value, "request_id") }},
	}
	for _, test := range readCases {
		t.Run("read "+test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				value := map[string]any{"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1",
					"request_id": "request-1", "assignment_epoch": 2, "status": "failed", "attempt_count": 1,
					"created_at": now, "updated_at": now}
				test.mutate(value)
				writeEnvelope(t, writer, []map[string]any{value})
			}))
			defer server.Close()
			client, _ := NewSettlementReadClient(server.URL, "settlement-read", "settlement-read-secret", server.Client())
			if _, err := client.ListPendingSettlements(context.Background(), "seat-1", 10); err == nil {
				t.Fatal("mismatched pending settlement was accepted")
			}
		})
	}

	resolveCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong actor", func(value map[string]any) { value["actor_client_id"] = "control-client" }},
		{"wrong operation", func(value map[string]any) { value["operation_id"] = "resolve-2" }},
		{"wrong epoch", func(value map[string]any) { value["assignment_epoch"] = 1 }},
		{"wrong request", func(value map[string]any) { value["request_id"] = "request-2" }},
	}
	for _, test := range resolveCases {
		t.Run("resolve "+test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				value := map[string]any{"seat_id": 7, "external_seat_id": "seat-1", "settlement_id": "settlement-1",
					"operation_id": "resolve-1", "actor_client_id": "settlement-resolve", "assignment_epoch": 2,
					"request_id": "request-1", "reason": "verified", "evidence": "ticket-1", "resolved_at": now}
				test.mutate(value)
				writeEnvelope(t, writer, value)
			}))
			defer server.Close()
			client, _ := NewSettlementResolveClient(server.URL, "settlement-resolve", "settlement-resolve-secret", server.Client())
			_, err := client.ResolvePendingSettlement(context.Background(), "seat-1", "settlement-1", application.ResolvePendingSettlementCommand{
				OperationID: "resolve-1", ExpectedAssignmentEpoch: 2, ExpectedRequestID: "request-1",
				Reason: "verified", Evidence: "ticket-1",
			})
			if err == nil {
				t.Fatal("mismatched settlement resolution was accepted")
			}
		})
	}
}

func TestClientMapsAssignmentToRotateContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/integrations/trusted-pools/seats/seat-1/rotate" {
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		var body struct {
			TargetEpoch uint64 `json:"target_epoch"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.TargetEpoch != 4 {
			t.Fatalf("unexpected target epoch %d", body.TargetEpoch)
		}
		writeEnvelope(t, writer, map[string]any{"seat": map[string]any{
			"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 4,
			"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301, "last_operation_id": "op-rotate",
		},
			"credential": "must-not-be-retained", "access_credential_rotated": true})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	command := assignmentCommand("op-rotate", 3)
	result, err := client.Assign(context.Background(), command)
	if err != nil || !result.AccessCredentialRotationComplete || result.Credential != "must-not-be-retained" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
}

func TestClientReplaysAmbiguousAssignmentFromOriginalFrozenEpoch(t *testing.T) {
	rotateCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/rotate":
			rotateCalls++
			if rotateCalls == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 503, "reason": "TEMPORARY"})
				return
			}
			writeEnvelope(t, writer, map[string]any{
				"seat": map[string]any{
					"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 2,
					"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301, "last_operation_id": "op-1",
				},
				"credential": "replayed-key", "access_credential_rotated": true,
			})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 1,
				"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301,
				"current_concurrency": 0, "pending_settlements": 0, "usage_snapshot": quotaSnapshot(),
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	command := assignmentCommand("op-1", 1)
	_, err := client.Assign(context.Background(), command)
	if err == nil {
		t.Fatal("expected ambiguous first assignment result")
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Applied || status.Credential != "replayed-key" || rotateCalls != 2 {
		t.Fatalf("ambiguous assignment was not safely replayed: status=%+v calls=%d err=%v", status, rotateCalls, err)
	}
}

func TestClientReconcileAssignmentAfterRestartUsesExplicitCommand(t *testing.T) {
	rotateCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{
				"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 1,
				"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301,
			})
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/rotate":
			rotateCalls++
			if request.Header.Get("Idempotency-Key") != "assign-restart" {
				t.Fatalf("lost persisted operation id: %q", request.Header.Get("Idempotency-Key"))
			}
			writeEnvelope(t, writer, map[string]any{
				"seat": map[string]any{
					"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 2,
					"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301, "last_operation_id": "assign-restart",
				},
				"credential": "restart-key", "access_credential_rotated": true,
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	restarted, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	result, err := restarted.ReconcileAssignment(context.Background(), assignmentCommand("assign-restart", 1))
	if err != nil || result.Credential != "restart-key" || result.ActiveAPIKeyVersion != 2 || rotateCalls != 1 {
		t.Fatalf("restart assignment result=%+v calls=%d err=%v", result, rotateCalls, err)
	}
}

func TestClientAssignmentFailsClosedOnStableBindingDrift(t *testing.T) {
	tests := []struct {
		name        string
		drainAPIKey int
		lastOp      string
	}{
		{name: "drain status wrong api key", drainAPIKey: 999, lastOp: "assign-1"},
		{name: "rotate wrong last operation", drainAPIKey: 301, lastOp: "other-operation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodGet {
					writeEnvelope(t, writer, map[string]any{
						"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 1,
						"principal_user_id": 101, "subscription_id": 201, "api_key_id": test.drainAPIKey,
					})
					return
				}
				writeEnvelope(t, writer, map[string]any{
					"seat": map[string]any{
						"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 2,
						"principal_user_id": 101, "subscription_id": 201, "api_key_id": 301, "last_operation_id": test.lastOp,
					},
					"credential": "unsafe-key", "access_credential_rotated": true,
				})
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
			_, err := client.ReconcileAssignment(context.Background(), assignmentCommand("assign-1", 1))
			var gatewayErr *application.GatewayError
			if !errors.As(err, &gatewayErr) || !gatewayErr.Retryable || !gatewayErr.Ambiguous {
				t.Fatalf("binding drift did not fail closed: %#v", err)
			}
		})
	}
}

func TestClientReplaysAmbiguousSuspendStillAtActiveEpoch(t *testing.T) {
	suspendCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "POST /api/v1/integrations/trusted-pools/seats/seat-1/suspend":
			suspendCalls++
			if suspendCalls == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 503, "reason": "TEMPORARY"})
				return
			}
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "draining", "assignment_epoch": 1, "current_concurrency": 1, "pending_settlements": 0})
		case "GET /api/v1/integrations/trusted-pools/seats/seat-1/drain-status":
			writeEnvelope(t, writer, map[string]any{"external_pool_id": "pool-1", "external_seat_id": "seat-1", "state": "active", "assignment_epoch": 1, "current_concurrency": 0, "usage_snapshot": quotaSnapshot()})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", PoolID: "pool-1", AssignmentEpoch: 1})
	if err == nil {
		t.Fatal("expected ambiguous first suspend result")
	}
	status, err := client.OperationStatus(context.Background(), "op-1")
	if err != nil || !status.Draining || status.CurrentConcurrency != 1 || status.PendingSettlements != 0 || suspendCalls != 2 {
		t.Fatalf("ambiguous suspend was not safely replayed: status=%+v calls=%d err=%v", status, suspendCalls, err)
	}
}

func TestClientRejectsFrozenResponseWithoutQuotaEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, map[string]any{"external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 1, "current_concurrency": 0})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	if _, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1}); err == nil {
		t.Fatal("accepted frozen response without quota freeze snapshot")
	}
}

func TestClientRejectsFrozenResponseWithPendingSettlement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeEnvelope(t, writer, map[string]any{
			"external_seat_id": "seat-1", "state": "frozen", "assignment_epoch": 1,
			"current_concurrency": 0, "pending_settlements": 1,
			"usage_snapshot": quotaSnapshot(),
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1", AssignmentEpoch: 1})
	if err == nil {
		t.Fatal("expected frozen response with pending settlement to be rejected")
	}
}

func TestClientClassifiesExplicitAndAmbiguousFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		reason    string
		ambiguous bool
		retryable bool
	}{
		{name: "validation", status: 400, reason: "INVALID_REQUEST"},
		{name: "rate limited", status: 429, reason: "RATE_LIMITED", retryable: true},
		{name: "server failure", status: 503, reason: "UPSTREAM_FAILED", retryable: true, ambiguous: true},
		{name: "idempotency in progress", status: 409, reason: "IDEMPOTENCY_IN_PROGRESS", retryable: true, ambiguous: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": test.status, "reason": test.reason})
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
			_, err := client.Suspend(context.Background(), application.SuspendCommand{OperationID: "op-1", SeatID: "seat-1"})
			gatewayErr, ok := err.(*application.GatewayError)
			if !ok || gatewayErr.Ambiguous != test.ambiguous || gatewayErr.Retryable != test.retryable || gatewayErr.StatusCode != test.status {
				t.Fatalf("unexpected error: %#v", err)
			}
		})
	}
}

func TestClientTreatsMalformedSuccessfulProvisionAsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, nil)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "pool-client", "integration-secret", server.Client())
	_, err := client.ProvisionSeat(context.Background(), application.ProvisionSeatCommand{OperationID: "provision-1"})
	gatewayErr, ok := err.(*application.GatewayError)
	if !ok || !gatewayErr.Retryable || !gatewayErr.Ambiguous || gatewayErr.StatusCode != http.StatusOK {
		t.Fatalf("malformed committed response was not ambiguous: %#v", err)
	}
}

func TestClientRejectsUnsafeBaseURL(t *testing.T) {
	if _, err := NewClient("https://user:pass@example.com?token=secret", "client", "secret", nil); err == nil {
		t.Fatal("accepted unsafe base URL")
	}
}

func TestClientRefusesRedirectsWithoutForwardingCredentials(t *testing.T) {
	var redirectedAuthorization string
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		redirectedAuthorization = request.Header.Get("Authorization")
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client, err := NewClient(origin.URL, "pool-client", "integration-secret", origin.Client())
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	err = client.do(context.Background(), http.MethodGet, "/redirect", "", nil, nil)
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirectedAuthorization != "" {
		t.Fatal("authorization header was forwarded to redirect destination")
	}
}

func writeEnvelope(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": data}); err != nil {
		t.Fatal(err)
	}
}

func quotaSnapshot() map[string]any {
	return map[string]any{
		"captured_at":   time.Now().UTC(),
		"usage":         map[string]float64{"hourly": 0, "daily": 3.5, "weekly": 3.5, "monthly": 3.5},
		"window_starts": map[string]any{"hourly": nil, "daily": time.Now().UTC().Add(-time.Hour), "weekly": nil, "monthly": nil},
	}
}

func assignmentCommand(operationID string, epoch uint64) application.AssignmentCommand {
	return application.AssignmentCommand{
		OperationID: operationID, SeatID: "seat-1", PoolID: "pool-1", TargetUser: "member-2",
		AssignmentEpoch: epoch, MembershipEpoch: 1, FreezeOperationID: "suspend-1",
		PrincipalUserID: 101, SubscriptionID: 201, APIKeyID: 301, ActiveAPIKeyVersion: epoch,
		Mode: application.OperationAssignTemp,
	}
}

var _ application.PendingSettlementReadGateway = (*SettlementReadClient)(nil)
var _ application.PendingSettlementResolveGateway = (*SettlementResolveClient)(nil)
