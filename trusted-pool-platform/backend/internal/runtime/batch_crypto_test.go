package runtime

import (
	"context"
	"testing"

	"trusted-pool-platform/backend/internal/credentials"
)

func TestBuildBatchSealerDevelopmentUsesIndependentRecoveryKey(t *testing.T) {
	values := map[string]string{
		"TRUSTED_POOL_RUNTIME_MODE":             "development",
		"TRUSTED_POOL_DATABASE_URL":             "postgres://db/platform",
		"TRUSTED_POOL_ENVELOPE_MODE":            "local",
		"TRUSTED_POOL_KMS_KEY_REF":              "development/claim-key",
		"TRUSTED_POOL_KEK_HEX":                  testKEKHex,
		"TRUSTED_POOL_ALLOW_INSECURE_LOCAL_KEK": "true",
		"TRUSTED_POOL_WORKER_ID":                "worker-1",
	}
	addBatchConfig(values, true)
	config, err := loadConfig(envLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	online, err := credentials.NewDevelopmentLocalKMS(config.LocalKEK, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := BuildBatchSealer(config, online, nil, nil)
	if err != nil {
		t.Fatalf("BuildBatchSealer(): %v", err)
	}
	if err := sealer.Ready(context.Background()); err != nil {
		t.Fatalf("development dual wrapper not ready: %v", err)
	}
}

func TestBuildBatchSealerProductionRequiresNativeContextAwareWrappers(t *testing.T) {
	values := map[string]string{
		"TRUSTED_POOL_DATABASE_URL": "postgres://db/platform",
		"TRUSTED_POOL_KMS_KEY_REF":  "kms/key/claims",
		"TRUSTED_POOL_KMS_PROVIDER": "example-kms",
		"TRUSTED_POOL_WORKER_ID":    "worker-1",
	}
	addBatchConfig(values, false)
	config, err := loadConfig(envLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildBatchSealer(config, nil, nil, nil); err == nil {
		t.Fatal("production batch sealer accepted missing context-aware wrappers")
	}
}
