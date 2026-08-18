package credentials

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type testKMSWrapper struct {
	readyErr error
}

func (w testKMSWrapper) Ready(context.Context) error { return w.readyErr }
func (w testKMSWrapper) Wrap(_ context.Context, keyRef string, plaintext []byte) ([]byte, error) {
	return append([]byte(keyRef+":"), plaintext...), nil
}
func (w testKMSWrapper) Unwrap(_ context.Context, keyRef string, wrapped []byte) ([]byte, error) {
	prefix := []byte(keyRef + ":")
	if !bytes.HasPrefix(wrapped, prefix) {
		return nil, errors.New("wrong key")
	}
	return append([]byte(nil), wrapped[len(prefix):]...), nil
}

func TestKMSEnvelopeCipherRoundTripAndAADBinding(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	cipher, err := NewKMSEnvelopeCipher(testKMSWrapper{}, "kms/key/claims", random)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cipher.Seal(context.Background(), []byte("credential"), []byte("seat-1/member-1"))
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	plaintext, err := cipher.Open(context.Background(), envelope, []byte("seat-1/member-1"))
	if err != nil || string(plaintext) != "credential" {
		t.Fatalf("Open() = %q, %v", plaintext, err)
	}
	if _, err := cipher.Open(context.Background(), envelope, []byte("seat-2/member-1")); err == nil {
		t.Fatal("AAD substitution was accepted")
	}
	wrongKeyRef := envelope
	wrongKeyRef.KeyRef = "kms/key/other"
	if _, err := cipher.Open(context.Background(), wrongKeyRef, []byte("seat-1/member-1")); err == nil {
		t.Fatal("KMS key reference substitution was accepted")
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := cipher.Open(context.Background(), envelope, []byte("seat-1/member-1")); err == nil {
		t.Fatal("ciphertext tampering was accepted")
	}
}

func TestKMSEnvelopeCipherReadinessFailsClosed(t *testing.T) {
	expected := errors.New("kms unavailable")
	cipher, err := NewKMSEnvelopeCipher(testKMSWrapper{readyErr: expected}, "kms/key/claims", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cipher.Ready(context.Background()), expected) {
		t.Fatal("KMS readiness error was hidden")
	}
}
