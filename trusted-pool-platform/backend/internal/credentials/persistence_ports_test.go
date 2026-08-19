package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCanonicalBatchAADBindsSealOperation(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("keyed payload fingerprint"))
	first, err := CanonicalBatchAAD("seal-op-1", "batch-1", "pool-1", "account-1",
		BatchLogin, 2, 7, fingerprint)
	if err != nil {
		t.Fatalf("CanonicalBatchAAD(): %v", err)
	}
	second, err := CanonicalBatchAAD("seal-op-2", "batch-1", "pool-1", "account-1",
		BatchLogin, 2, 7, fingerprint)
	if err != nil {
		t.Fatalf("CanonicalBatchAAD(second): %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("seal operation id was not bound into canonical AAD")
	}
	if want := hex.EncodeToString(fingerprint[:]); !containsBytes(first, []byte(want)) {
		t.Fatalf("AAD does not contain canonical fingerprint %q: %s", want, first)
	}
}

func TestRecoveryBindingHashSeparatesWrapperMetadataAndBlob(t *testing.T) {
	aad := sha256.Sum256([]byte("aad"))
	base := RecoveryBindingHash("recovery-domain", "RSA-OAEP-256", "recovery-key-1", aad, []byte("wrapped-dek"))
	tests := []struct {
		name string
		hash [sha256.Size]byte
	}{
		{"domain", RecoveryBindingHash("other-domain", "RSA-OAEP-256", "recovery-key-1", aad, []byte("wrapped-dek"))},
		{"algorithm", RecoveryBindingHash("recovery-domain", "AES-KWP", "recovery-key-1", aad, []byte("wrapped-dek"))},
		{"key ref", RecoveryBindingHash("recovery-domain", "RSA-OAEP-256", "recovery-key-2", aad, []byte("wrapped-dek"))},
		{"wrapped blob", RecoveryBindingHash("recovery-domain", "RSA-OAEP-256", "recovery-key-1", aad, []byte("other-wrapped-dek"))},
	}
	for _, test := range tests {
		if test.hash == base {
			t.Fatalf("%s was not bound into recovery hash", test.name)
		}
	}
}

func containsBytes(value, part []byte) bool {
outer:
	for start := 0; start+len(part) <= len(value); start++ {
		for index := range part {
			if value[start+index] != part[index] {
				continue outer
			}
		}
		return true
	}
	return false
}
