package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
)

type adapterCipher struct {
	sealed []byte
	aad    []byte
}

func (c *adapterCipher) Ready(context.Context) error { return nil }
func (c *adapterCipher) Seal(_ context.Context, plaintext, aad []byte) (credentials.Envelope, error) {
	c.sealed = append([]byte(nil), plaintext...)
	c.aad = append([]byte(nil), aad...)
	return credentials.Envelope{
		Algorithm: credentials.EnvelopeAlgorithm, KeyRef: "kms/key/claims",
		Ciphertext: []byte("ciphertext"), Nonce: []byte("nonce"),
		AADHash: sha256.Sum256(aad), WrappedDEK: []byte("wrapped"),
	}, nil
}
func (c *adapterCipher) Open(_ context.Context, envelope credentials.Envelope, aad []byte) ([]byte, error) {
	if envelope.Algorithm != credentials.EnvelopeAlgorithm || envelope.KeyRef != "kms/key/claims" ||
		!bytes.Equal(envelope.Ciphertext, []byte("ciphertext")) || !bytes.Equal(aad, c.aad) {
		return nil, errors.New("envelope mapping mismatch")
	}
	return []byte("credential"), nil
}

func TestApplicationEnvelopeCipherMapsWithoutBypass(t *testing.T) {
	base := &adapterCipher{}
	adapter, err := NewApplicationEnvelopeCipher(base)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := adapter.Seal(context.Background(), "credential", []byte("bound-aad"))
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if string(base.sealed) != "credential" || envelope.KeyRef != "kms/key/claims" ||
		!bytes.Equal(envelope.WrappedDEK, []byte("wrapped")) {
		t.Fatalf("unexpected application envelope: %#v", envelope)
	}
	plaintext, err := adapter.Open(context.Background(), envelope, []byte("bound-aad"))
	if err != nil || plaintext != "credential" {
		t.Fatalf("Open() = %q, %v", plaintext, err)
	}
}

type recoveryScannerStub struct {
	mu             sync.Mutex
	operationCalls int
	claimCalls     int
	operationWork  bool
	operationErr   error
	claimErr       error
	firstRound     chan struct{}
}

func (s *recoveryScannerStub) RecoverNextOperation(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operationCalls++
	return s.operationWork, s.operationErr
}

func (s *recoveryScannerStub) RecoverNextCredentialClaim(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimCalls++
	if s.firstRound != nil && s.claimCalls == 1 {
		close(s.firstRound)
	}
	return false, s.claimErr
}

func TestPersistentRecoveryLoopScansBothAndStopsDuringIdle(t *testing.T) {
	stub := &recoveryScannerStub{firstRound: make(chan struct{})}
	loop, err := NewPersistentRecoveryLoop(stub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	<-stub.firstRound
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery loop did not stop after cancellation")
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.operationCalls != 1 || stub.claimCalls != 1 {
		t.Fatalf("scan calls = operation %d, claim %d", stub.operationCalls, stub.claimCalls)
	}
}

func TestPersistentRecoveryLoopPropagatesScannerFailure(t *testing.T) {
	stub := &recoveryScannerStub{operationWork: true, claimErr: errors.New("database unavailable")}
	loop, err := NewPersistentRecoveryLoop(stub, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = loop.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "credential claim") {
		t.Fatalf("Run() error = %v", err)
	}
}

var _ application.CredentialEnvelopeCipher = (*ApplicationEnvelopeCipher)(nil)
var _ Worker = (*PersistentRecoveryLoop)(nil)
