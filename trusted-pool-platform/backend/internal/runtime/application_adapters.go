package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"trusted-pool-platform/backend/internal/application"
	"trusted-pool-platform/backend/internal/credentials"
)

// ApplicationEnvelopeCipher 将应用包络契约显式映射到 KMS cipher，不提供明文旁路。
type ApplicationEnvelopeCipher struct {
	cipher credentials.EnvelopeCipher
}

func NewApplicationEnvelopeCipher(cipher credentials.EnvelopeCipher) (*ApplicationEnvelopeCipher, error) {
	if cipher == nil {
		return nil, errors.New("KMS envelope cipher is required")
	}
	return &ApplicationEnvelopeCipher{cipher: cipher}, nil
}

func (a *ApplicationEnvelopeCipher) Seal(ctx context.Context, plaintext string, aad []byte) (application.CredentialEnvelope, error) {
	secret := []byte(plaintext)
	defer clear(secret)
	envelope, err := a.cipher.Seal(ctx, secret, aad)
	if err != nil {
		return application.CredentialEnvelope{}, err
	}
	return application.CredentialEnvelope{
		Algorithm: envelope.Algorithm, KeyRef: envelope.KeyRef,
		Ciphertext: cloneBytes(envelope.Ciphertext), Nonce: cloneBytes(envelope.Nonce),
		AADHash: envelope.AADHash, WrappedDEK: cloneBytes(envelope.WrappedDEK),
	}, nil
}

func (a *ApplicationEnvelopeCipher) Open(ctx context.Context, envelope application.CredentialEnvelope, aad []byte) (string, error) {
	plaintext, err := a.cipher.Open(ctx, credentials.Envelope{
		Algorithm: envelope.Algorithm, KeyRef: envelope.KeyRef,
		Ciphertext: cloneBytes(envelope.Ciphertext), Nonce: cloneBytes(envelope.Nonce),
		AADHash: envelope.AADHash, WrappedDEK: cloneBytes(envelope.WrappedDEK),
	}, aad)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	return string(plaintext), nil
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

type PersistentRecoveryScanner interface {
	RecoverNextOperation(context.Context) (bool, error)
	RecoverNextCredentialClaim(context.Context) (bool, error)
}

type PersistentRecoveryLoop struct {
	scanner     PersistentRecoveryScanner
	idleBackoff time.Duration
}

func NewPersistentRecoveryLoop(scanner PersistentRecoveryScanner, idleBackoff time.Duration) (*PersistentRecoveryLoop, error) {
	if scanner == nil || idleBackoff <= 0 {
		return nil, errors.New("persistent recovery scanner and positive idle backoff are required")
	}
	return &PersistentRecoveryLoop{scanner: scanner, idleBackoff: idleBackoff}, nil
}

// Run 每轮公平扫描 operation 与 claim；空闲时退避，持久层错误则交给进程生命周期处理。
func (w *PersistentRecoveryLoop) Run(ctx context.Context) error {
	for {
		operationWorked, err := w.scanner.RecoverNextOperation(ctx)
		if err != nil {
			return fmt.Errorf("recover persistent operation: %w", err)
		}
		claimWorked, err := w.scanner.RecoverNextCredentialClaim(ctx)
		if err != nil {
			return fmt.Errorf("recover persistent credential claim: %w", err)
		}
		if operationWorked || claimWorked {
			continue
		}
		timer := time.NewTimer(w.idleBackoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
