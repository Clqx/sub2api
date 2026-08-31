//go:build unit

package repository

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestPermanentCredentialEnvelopeRoundTripAndAADBinding(t *testing.T) {
	provider, err := newLocalPermanentRotationKEKProvider("staging-kek-v1", bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	sealer, err := newPermanentCredentialEnvelopeSealer(provider)
	if err != nil {
		t.Fatalf("create sealer: %v", err)
	}
	scope := permanentCredentialTestScope()
	expiresAt := time.Date(2026, 8, 31, 3, 4, 5, 987654321, time.FixedZone("test", 8*60*60))
	envelope, err := sealer.Seal(context.Background(), "prepared-secret-value", scope, expiresAt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !envelope.ExpiresAt.Equal(expiresAt.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("expires_at=%s is not PostgreSQL-safe microsecond UTC value", envelope.ExpiresAt)
	}
	if len(envelope.DataNonce) != 12 || len(envelope.WrapNonce) != 12 || len(envelope.WrappedDEK) != 48 {
		t.Fatalf("unexpected envelope sizes: data_nonce=%d wrap_nonce=%d wrapped_dek=%d", len(envelope.DataNonce), len(envelope.WrapNonce), len(envelope.WrappedDEK))
	}
	if bytes.Contains(envelope.Ciphertext, []byte("prepared-secret-value")) || bytes.Contains(envelope.WrappedDEK, []byte("prepared-secret-value")) {
		t.Fatal("persisted envelope contains plaintext credential")
	}
	credential, err := sealer.Open(context.Background(), envelope, scope)
	if err != nil || credential != "prepared-secret-value" {
		t.Fatalf("open credential=%q err=%v", credential, err)
	}

	tampered := scope
	tampered.RequestHash = "different-request-hash"
	if _, err := sealer.Open(context.Background(), envelope, tampered); !errors.Is(err, errPermanentCredentialEnvelope) {
		t.Fatalf("request-hash AAD drift error=%v", err)
	}

	tamperedEnvelope := envelope
	tamperedEnvelope.KeyID = "staging-kek-v2"
	if _, err := sealer.Open(context.Background(), tamperedEnvelope, scope); !errors.Is(err, errPermanentCredentialEnvelope) {
		t.Fatalf("key-id drift error=%v", err)
	}
}

func TestPermanentCredentialEnvelopeUsesIndependentPerRecordDEKs(t *testing.T) {
	provider, err := newLocalPermanentRotationKEKProvider("staging-kek-v1", bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	sealer, err := newPermanentCredentialEnvelopeSealer(provider)
	if err != nil {
		t.Fatalf("create sealer: %v", err)
	}
	scope := permanentCredentialTestScope()
	expiresAt := time.Now().UTC().Add(15 * time.Minute)
	first, err := sealer.Seal(context.Background(), "same-secret", scope, expiresAt)
	if err != nil {
		t.Fatalf("seal first: %v", err)
	}
	second, err := sealer.Seal(context.Background(), "same-secret", scope, expiresAt)
	if err != nil {
		t.Fatalf("seal second: %v", err)
	}
	if bytes.Equal(first.DataNonce, second.DataNonce) || bytes.Equal(first.WrapNonce, second.WrapNonce) ||
		bytes.Equal(first.WrappedDEK, second.WrappedDEK) || bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("two records reused envelope cryptographic material")
	}
}

func TestOpenPermanentCredentialExpiryBlocksRedisclosureButAllowsFailForwardActivation(t *testing.T) {
	provider, err := newLocalPermanentRotationKEKProvider("staging-kek-v1", bytes.Repeat([]byte{0x63}, 32))
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	sealer, err := newPermanentCredentialEnvelopeSealer(provider)
	if err != nil {
		t.Fatalf("create sealer: %v", err)
	}
	now := time.Date(2026, 8, 31, 1, 2, 3, 456789999, time.UTC)
	parent, child := permanentCredentialTestStoredBinding()
	envelope, err := sealer.Seal(context.Background(), "prepared-secret-value", permanentCredentialScopeFromStored(parent, child), now)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	child.CredentialEnvelope = envelope
	repo := &trustedPoolRepository{permanentCredentialSealer: sealer, now: func() time.Time { return now }}
	if _, err := repo.openPermanentCredentialForReplay(context.Background(), parent, &child); !errors.Is(err, service.ErrTrustedPoolPermanentCredentialExpired) {
		t.Fatalf("expired redisclosure error=%v", err)
	}
	credential, err := repo.openPermanentCredentialForActivation(context.Background(), parent, &child)
	if err != nil || credential != "prepared-secret-value" {
		t.Fatalf("fail-forward activation credential=%q err=%v", credential, err)
	}
}

func permanentCredentialTestScope() permanentCredentialScope {
	parent, child := permanentCredentialTestStoredBinding()
	return permanentCredentialScopeFromStored(parent, child)
}

func permanentCredentialTestStoredBinding() (permanentRotationParent, permanentRotationChild) {
	parent := permanentRotationParent{
		ClientID: "client-1", PrepareOperationID: "prepare-1", ProtocolVersion: "protocol-v1",
		ExternalPoolID: "pool-1", PlanID: "plan-1", CeremonyType: "permanent",
		FromEpoch: 9, ToEpoch: 10, RequestHash: "request-hash", ChildSetHash: "child-set-hash",
		PreparedSetHash: "prepared-set-hash",
	}
	child := permanentRotationChild{
		TrustedPoolPermanentRotationSeatBinding: service.TrustedPoolPermanentRotationSeatBinding{
			ExternalSeatID: "seat-ext-1", TargetMemberID: "member-1", ExpectedAssignmentEpoch: 9,
			PrincipalUserID: 11, GroupID: 12, SubscriptionID: 13, APIKeyID: 14,
			FromAPIKeyVersion: 9, ToAPIKeyVersion: 10, ChildOperationID: "child-op-1",
			ChildRequestHash: "child-request-hash",
		},
		SeatID: 15, FromEpoch: 9, ToEpoch: 10, TargetAssignmentEpoch: 10,
		CredentialFingerprint: trustedPoolCredentialFingerprint("prepared-secret-value"),
		PreparedRotationRef:   "prepared-ref-1",
	}
	return parent, child
}
