package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const EnvelopeAlgorithm = "AES-256-GCM+KMS"

// Envelope 是待交付秘密的在线 KMS 单包装结果，不表示 Recovery Root 双包装。
type Envelope struct {
	Algorithm  string
	KeyRef     string
	Ciphertext []byte
	Nonce      []byte
	AADHash    [sha256.Size]byte
	WrappedDEK []byte
}

// EnvelopeCipher 隔离明文处理与持久层。实现必须验证 AAD 并在返回前清除原始 DEK。
type EnvelopeCipher interface {
	Seal(context.Context, []byte, []byte) (Envelope, error)
	Open(context.Context, Envelope, []byte) ([]byte, error)
	Ready(context.Context) error
}

// KMSKeyWrapper 是生产 KMS/HSM 适配器边界；平台不在生产模式持有根 KEK。
type KMSKeyWrapper interface {
	KeyWrapper
	Ready(context.Context) error
}

type KMSEnvelopeCipher struct {
	wrapper KMSKeyWrapper
	keyRef  string
	random  io.Reader
}

func NewKMSEnvelopeCipher(wrapper KMSKeyWrapper, keyRef string, random io.Reader) (*KMSEnvelopeCipher, error) {
	if wrapper == nil {
		return nil, errors.New("KMS key wrapper is required")
	}
	if keyRef == "" {
		return nil, errors.New("KMS key reference is required")
	}
	if random == nil {
		random = rand.Reader
	}
	return &KMSEnvelopeCipher{wrapper: wrapper, keyRef: keyRef, random: random}, nil
}

func (c *KMSEnvelopeCipher) Ready(ctx context.Context) error {
	if c == nil || c.wrapper == nil {
		return errors.New("envelope cipher is not configured")
	}
	return c.wrapper.Ready(ctx)
}

func (c *KMSEnvelopeCipher) Seal(ctx context.Context, plaintext, aad []byte) (Envelope, error) {
	if len(plaintext) == 0 || len(aad) == 0 {
		return Envelope{}, errors.New("credential plaintext and AAD are required")
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(c.random, dek); err != nil {
		return Envelope{}, fmt.Errorf("generate envelope DEK: %w", err)
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return Envelope{}, errors.New("initialize envelope cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, errors.New("initialize envelope AEAD")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate envelope nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	wrapped, err := c.wrapper.Wrap(ctx, c.keyRef, dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("wrap envelope DEK: %w", err)
	}
	return Envelope{
		Algorithm: EnvelopeAlgorithm, KeyRef: c.keyRef, Ciphertext: ciphertext,
		Nonce: nonce, AADHash: sha256.Sum256(aad), WrappedDEK: wrapped,
	}, nil
}

func (c *KMSEnvelopeCipher) Open(ctx context.Context, envelope Envelope, aad []byte) ([]byte, error) {
	if envelope.Algorithm != EnvelopeAlgorithm || envelope.KeyRef != c.keyRef || len(aad) == 0 ||
		len(envelope.Ciphertext) == 0 || len(envelope.Nonce) == 0 || len(envelope.WrappedDEK) == 0 ||
		envelope.AADHash != sha256.Sum256(aad) {
		return nil, errors.New("credential envelope metadata mismatch")
	}
	dek, err := c.wrapper.Unwrap(ctx, envelope.KeyRef, envelope.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap envelope DEK: %w", err)
	}
	defer wipe(dek)
	if len(dek) != 32 {
		return nil, errors.New("KMS returned an invalid envelope DEK")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.New("initialize envelope cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize envelope AEAD")
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, errors.New("credential envelope nonce size mismatch")
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("credential envelope authentication failed")
	}
	return plaintext, nil
}
