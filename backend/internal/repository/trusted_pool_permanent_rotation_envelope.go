package repository

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	permanentCredentialEnvelopeVersion int16 = 1
	permanentCredentialDEKSize               = 32
)

var errPermanentCredentialEnvelope = errors.New("permanent rotation credential envelope is invalid")

// TrustedPoolPermanentRotationKEKProvider is the narrow boundary for a future
// KMS adapter. Implementations wrap one random DEK per prepared credential.
type TrustedPoolPermanentRotationKEKProvider interface {
	KeyID() string
	WrapDEK(ctx context.Context, plaintextDEK, aad []byte) (nonce, wrappedDEK []byte, err error)
	UnwrapDEK(ctx context.Context, keyID string, nonce, wrappedDEK, aad []byte) ([]byte, error)
}

type localPermanentRotationKEKProvider struct {
	keyID string
	aead  cipher.AEAD
}

func newLocalPermanentRotationKEKProvider(keyID string, key []byte) (TrustedPoolPermanentRotationKEKProvider, error) {
	if keyID == "" || len(key) != permanentCredentialDEKSize {
		return nil, fmt.Errorf("%w: invalid local KEK configuration", errPermanentCredentialEnvelope)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize local KEK", errPermanentCredentialEnvelope)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize local KEK AEAD", errPermanentCredentialEnvelope)
	}
	return &localPermanentRotationKEKProvider{keyID: keyID, aead: aead}, nil
}

func (p *localPermanentRotationKEKProvider) KeyID() string { return p.keyID }

func (p *localPermanentRotationKEKProvider) WrapDEK(_ context.Context, plaintextDEK, aad []byte) ([]byte, []byte, error) {
	if len(plaintextDEK) != permanentCredentialDEKSize {
		return nil, nil, errPermanentCredentialEnvelope
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate KEK nonce: %w", err)
	}
	return nonce, p.aead.Seal(nil, nonce, plaintextDEK, aad), nil
}

func (p *localPermanentRotationKEKProvider) UnwrapDEK(_ context.Context, keyID string, nonce, wrappedDEK, aad []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare([]byte(keyID), []byte(p.keyID)) != 1 || len(nonce) != p.aead.NonceSize() {
		return nil, errPermanentCredentialEnvelope
	}
	dek, err := p.aead.Open(nil, nonce, wrappedDEK, aad)
	if err != nil || len(dek) != permanentCredentialDEKSize {
		clear(dek)
		return nil, errPermanentCredentialEnvelope
	}
	return dek, nil
}

type permanentCredentialEnvelope struct {
	Version    int16
	KeyID      string
	WrapNonce  []byte
	WrappedDEK []byte
	DataNonce  []byte
	Ciphertext []byte
	ExpiresAt  time.Time
}

type permanentCredentialScope struct {
	ClientID                string
	PrepareOperationID      string
	ProtocolVersion         string
	ExternalPoolID          string
	PlanID                  string
	CeremonyType            string
	FromEpoch               int64
	ToEpoch                 int64
	RequestHash             string
	ChildSetHash            string
	PreparedSetHash         string
	ExternalSeatID          string
	TargetMemberID          string
	SeatID                  int64
	PrincipalUserID         int64
	GroupID                 int64
	SubscriptionID          int64
	APIKeyID                int64
	ExpectedAssignmentEpoch int64
	TargetAssignmentEpoch   int64
	FromAPIKeyVersion       int64
	ToAPIKeyVersion         int64
	ChildOperationID        string
	ChildRequestHash        string
	CredentialFingerprint   string
	PreparedRotationRef     string
}

type permanentCredentialEnvelopeSealer struct {
	provider TrustedPoolPermanentRotationKEKProvider
	random   io.Reader
}

func newPermanentCredentialEnvelopeSealer(provider TrustedPoolPermanentRotationKEKProvider) (*permanentCredentialEnvelopeSealer, error) {
	if provider == nil || provider.KeyID() == "" {
		return nil, errPermanentCredentialEnvelope
	}
	return &permanentCredentialEnvelopeSealer{provider: provider, random: rand.Reader}, nil
}

func (s *permanentCredentialEnvelopeSealer) Seal(ctx context.Context, credential string, scope permanentCredentialScope, expiresAt time.Time) (permanentCredentialEnvelope, error) {
	expiresAt = permanentCredentialExpiry(expiresAt)
	envelope := permanentCredentialEnvelope{Version: permanentCredentialEnvelopeVersion, KeyID: s.provider.KeyID(), ExpiresAt: expiresAt}
	dek := make([]byte, permanentCredentialDEKSize)
	if _, err := io.ReadFull(s.random, dek); err != nil {
		return permanentCredentialEnvelope{}, fmt.Errorf("generate credential DEK: %w", err)
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return permanentCredentialEnvelope{}, fmt.Errorf("initialize credential DEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return permanentCredentialEnvelope{}, fmt.Errorf("initialize credential AEAD: %w", err)
	}
	envelope.DataNonce = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(s.random, envelope.DataNonce); err != nil {
		return permanentCredentialEnvelope{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	plaintext := []byte(credential)
	envelope.Ciphertext = aead.Seal(nil, envelope.DataNonce, plaintext, permanentCredentialPayloadAAD(scope, envelope))
	clear(plaintext)
	wrapAAD := permanentCredentialWrapAAD(scope, envelope)
	envelope.WrapNonce, envelope.WrappedDEK, err = s.provider.WrapDEK(ctx, dek, wrapAAD)
	if err != nil {
		clear(envelope.DataNonce)
		clear(envelope.Ciphertext)
		clear(envelope.WrapNonce)
		clear(envelope.WrappedDEK)
		return permanentCredentialEnvelope{}, fmt.Errorf("wrap credential DEK: %w", err)
	}
	return envelope, nil
}

func (s *permanentCredentialEnvelopeSealer) Open(ctx context.Context, envelope permanentCredentialEnvelope, scope permanentCredentialScope) (string, error) {
	if envelope.Version != permanentCredentialEnvelopeVersion || envelope.KeyID == "" ||
		len(envelope.DataNonce) != 12 || len(envelope.WrapNonce) != 12 ||
		len(envelope.WrappedDEK) != permanentCredentialDEKSize+16 || len(envelope.Ciphertext) < 16 ||
		envelope.ExpiresAt.IsZero() {
		return "", errPermanentCredentialEnvelope
	}
	envelope.ExpiresAt = permanentCredentialExpiry(envelope.ExpiresAt)
	dek, err := s.provider.UnwrapDEK(ctx, envelope.KeyID, envelope.WrapNonce, envelope.WrappedDEK, permanentCredentialWrapAAD(scope, envelope))
	if err != nil {
		return "", errPermanentCredentialEnvelope
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", errPermanentCredentialEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(envelope.DataNonce) != aead.NonceSize() {
		return "", errPermanentCredentialEnvelope
	}
	plaintext, err := aead.Open(nil, envelope.DataNonce, envelope.Ciphertext, permanentCredentialPayloadAAD(scope, envelope))
	if err != nil {
		return "", errPermanentCredentialEnvelope
	}
	credential := string(plaintext)
	clear(plaintext)
	return credential, nil
}

func permanentCredentialExpiry(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func permanentCredentialPayloadAAD(scope permanentCredentialScope, envelope permanentCredentialEnvelope) []byte {
	return permanentCredentialAAD("trusted-pool/permanent-credential-payload/v1", scope, envelope, nil)
}

func permanentCredentialWrapAAD(scope permanentCredentialScope, envelope permanentCredentialEnvelope) []byte {
	digest := sha256.Sum256(envelope.Ciphertext)
	extra := append(append([]byte(nil), envelope.DataNonce...), digest[:]...)
	return permanentCredentialAAD("trusted-pool/permanent-credential-dek-wrap/v1", scope, envelope, extra)
}

func permanentCredentialAAD(domain string, scope permanentCredentialScope, envelope permanentCredentialEnvelope, extra []byte) []byte {
	var framed bytes.Buffer
	writePermanentCredentialAADString(&framed, domain)
	for _, value := range []string{
		scope.ClientID, scope.PrepareOperationID, scope.ProtocolVersion, scope.ExternalPoolID, scope.PlanID,
		scope.CeremonyType, scope.RequestHash, scope.ChildSetHash, scope.PreparedSetHash,
		scope.ExternalSeatID, scope.TargetMemberID,
		scope.ChildOperationID, scope.ChildRequestHash, scope.CredentialFingerprint, scope.PreparedRotationRef,
		envelope.KeyID,
	} {
		writePermanentCredentialAADString(&framed, value)
	}
	for _, value := range []int64{
		scope.FromEpoch, scope.ToEpoch, scope.SeatID, scope.PrincipalUserID, scope.GroupID,
		scope.SubscriptionID, scope.APIKeyID, scope.ExpectedAssignmentEpoch, scope.TargetAssignmentEpoch,
		scope.FromAPIKeyVersion, scope.ToAPIKeyVersion, envelope.ExpiresAt.UnixMicro(),
	} {
		_ = binary.Write(&framed, binary.BigEndian, value)
	}
	_ = binary.Write(&framed, binary.BigEndian, envelope.Version)
	writePermanentCredentialAADBytes(&framed, extra)
	return framed.Bytes()
}

func writePermanentCredentialAADString(target *bytes.Buffer, value string) {
	writePermanentCredentialAADBytes(target, []byte(value))
}

func writePermanentCredentialAADBytes(target *bytes.Buffer, value []byte) {
	_ = binary.Write(target, binary.BigEndian, uint32(len(value)))
	_, _ = target.Write(value)
}
