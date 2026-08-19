package runtime

import (
	"context"
	"testing"
)

func TestLoadConfigRequiresDatabaseAndProductionKMS(t *testing.T) {
	lookup := envLookup(map[string]string{})
	if _, err := loadConfig(lookup); err == nil {
		t.Fatal("missing database and KMS configuration was accepted")
	}

	production := map[string]string{
		"TRUSTED_POOL_DATABASE_URL": "postgres://db/platform",
		"TRUSTED_POOL_KMS_KEY_REF":  "kms/key/claims",
		"TRUSTED_POOL_KMS_PROVIDER": "example-kms",
		"TRUSTED_POOL_WORKER_ID":    "worker-1",
	}
	addBatchConfig(production, false)
	config, err := loadConfig(envLookup(production))
	if err != nil {
		t.Fatalf("production config rejected: %v", err)
	}
	if _, err := BuildCrypto(config, nil); err == nil {
		t.Fatal("production configuration fell back without a KMS adapter")
	}
	production["TRUSTED_POOL_KEK_HEX"] = testKEKHex
	if _, err := loadConfig(envLookup(production)); err == nil {
		t.Fatal("production environment KEK was accepted")
	}
}

func TestDevelopmentLocalKEKRequiresAllExplicitGates(t *testing.T) {
	base := map[string]string{
		"TRUSTED_POOL_RUNTIME_MODE":  "development",
		"TRUSTED_POOL_DATABASE_URL":  "postgres://db/platform",
		"TRUSTED_POOL_ENVELOPE_MODE": "local",
		"TRUSTED_POOL_KMS_KEY_REF":   "development/key",
		"TRUSTED_POOL_KEK_HEX":       testKEKHex,
		"TRUSTED_POOL_WORKER_ID":     "worker-1",
	}
	addBatchConfig(base, true)
	if _, err := loadConfig(envLookup(base)); err == nil {
		t.Fatal("development local KEK was accepted without allow flag")
	}
	base["TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK"] = "true"
	config, err := loadConfig(envLookup(base))
	if err != nil {
		t.Fatalf("explicit development config rejected: %v", err)
	}
	crypto, err := BuildCrypto(config, nil)
	if err != nil {
		t.Fatalf("BuildCrypto(): %v", err)
	}
	if err := crypto.Cipher.Ready(context.Background()); err != nil {
		t.Fatalf("development cipher not ready: %v", err)
	}
}

func TestWorkflowConfigRejectsMissingOwnerAndUnsafeDurations(t *testing.T) {
	base := map[string]string{
		"TRUSTED_POOL_RUNTIME_MODE":             "development",
		"TRUSTED_POOL_DATABASE_URL":             "postgres://db/platform",
		"TRUSTED_POOL_ENVELOPE_MODE":            "local",
		"TRUSTED_POOL_KMS_KEY_REF":              "development/key",
		"TRUSTED_POOL_KEK_HEX":                  testKEKHex,
		"TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK": "true",
		"TRUSTED_POOL_WORKFLOW_LEASE_DURATION":  "30s",
		"TRUSTED_POOL_RECOVERY_BACKOFF":         "1m",
		"TRUSTED_POOL_RECOVERY_IDLE_BACKOFF":    "1s",
	}
	addBatchConfig(base, true)
	if _, err := loadConfig(envLookup(base)); err == nil {
		t.Fatal("configuration without a persistent worker owner was accepted")
	}
	base["TRUSTED_POOL_WORKER_ID"] = "worker-1"
	base["TRUSTED_POOL_CLAIM_TTL"] = "25h"
	if _, err := loadConfig(envLookup(base)); err == nil {
		t.Fatal("claim TTL above the 24h safety limit was accepted")
	}
	base["TRUSTED_POOL_CLAIM_TTL"] = "10m"
	base["TRUSTED_POOL_WORKFLOW_LEASE_DURATION"] = "0s"
	if _, err := loadConfig(envLookup(base)); err == nil {
		t.Fatal("non-positive workflow lease was accepted")
	}
}

func addBatchConfig(values map[string]string, development bool) {
	values["TRUSTED_POOL_BATCH_CLIENT_ID"] = "batch-client"
	values["TRUSTED_POOL_BATCH_KMS_WRAP_ALGORITHM"] = "KMS-CONTEXT-WRAP-V1"
	values["TRUSTED_POOL_BATCH_KMS_DOMAIN"] = "online-domain"
	values["TRUSTED_POOL_BATCH_KMS_KEY_REF"] = "kms/key/batches"
	values["TRUSTED_POOL_BATCH_RECOVERY_WRAP_ALGORITHM"] = "RECOVERY-CONTEXT-WRAP-V1"
	values["TRUSTED_POOL_BATCH_RECOVERY_DOMAIN"] = "recovery-domain"
	values["TRUSTED_POOL_BATCH_RECOVERY_KEY_REF"] = "recovery/key/batches"
	values["TRUSTED_POOL_BATCH_FINGERPRINT_KEY_REF"] = "fingerprint/key/v1"
	values["TRUSTED_POOL_BATCH_FINGERPRINT_HMAC_KEY_HEX"] = testBatchFingerprintHex
	if development {
		values["TRUSTED_POOL_RECOVERY_KEK_HEX"] = testRecoveryKEKHex
	}
}

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

const testKEKHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const testRecoveryKEKHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
const testBatchFingerprintHex = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
