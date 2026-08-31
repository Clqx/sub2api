//go:build unit

package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func clearTrustedPoolPermanentRotationEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVER_MODE", "debug")
	for _, name := range []string{
		"TRUSTED_POOL_PERMANENT_ROTATION_ENABLED",
		"TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED",
		"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID",
		"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64",
		"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_FILE",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_FILE",
		"TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_PREPARED_CREDENTIAL_TTL",
	} {
		t.Setenv(name, "")
	}
}

func generatedEd25519PrivateKeyBase64(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(privateKey)
}

func generatedStagingEncryptionKeyBase64(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(privateKey[:32])
}

func configureValidPermanentRotationSigning(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-signing-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString(privateKey))
	return privateKey
}

func TestTrustedPoolPermanentRotationDisabledByDefaultAndIgnoresUnusedKeyMaterial(t *testing.T) {
	resetViperWithJWTSecret(t)
	clearTrustedPoolPermanentRotationEnv(t)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "unused-key")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", "not-base64")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "unused-staging-key")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", "not-base64")

	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.TrustedPool.PermanentRotation.Enabled)
	require.False(t, cfg.TrustedPool.PermanentRotation.Required)
	require.False(t, cfg.TrustedPool.PermanentRotation.StagingEncryption.Enabled)
}

func TestTrustedPoolPermanentRotationStartupGate(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "enabled without key fails",
			env: map[string]string{
				"TRUSTED_POOL_PERMANENT_ROTATION_ENABLED": "true",
			},
			wantErr: "signing_key_id is required",
		},
		{
			name: "required capability cannot be disabled",
			env: map[string]string{
				"TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED": "true",
			},
			wantErr: "enabled must be true when required is true",
		},
		{
			name: "malformed key fails",
			env: map[string]string{
				"TRUSTED_POOL_PERMANENT_ROTATION_ENABLED":                    "true",
				"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID":             "rotation-key-v1",
				"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64": "not-base64",
			},
			wantErr: "64-byte Ed25519 private key",
		},
		{
			name: "inconsistent public suffix fails",
			env: map[string]string{
				"TRUSTED_POOL_PERMANENT_ROTATION_ENABLED":                    "true",
				"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID":             "rotation-key-v1",
				"TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64": base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
			},
			wantErr: "inconsistent Ed25519 public-key suffix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViperWithJWTSecret(t)
			clearTrustedPoolPermanentRotationEnv(t)
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			_, err := Load()
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestTrustedPoolPermanentRotationLoadsValidEnvironmentKey(t *testing.T) {
	resetViperWithJWTSecret(t)
	clearTrustedPoolPermanentRotationEnv(t)
	encoded := generatedEd25519PrivateKeyBase64(t)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", " rotation-key-v1 ")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", encoded)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))

	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.TrustedPool.PermanentRotation.Enabled)
	require.True(t, cfg.TrustedPool.PermanentRotation.Required)
	require.Equal(t, "rotation-key-v1", cfg.TrustedPool.PermanentRotation.SigningKeyID)
	privateKey, err := cfg.TrustedPool.PermanentRotation.SigningPrivateKey()
	require.NoError(t, err)
	require.Equal(t, encoded, base64.StdEncoding.EncodeToString(privateKey))
}

func TestTrustedPoolPermanentRotationStagingEncryptionStartupGate(t *testing.T) {
	t.Run("enabled rotation requires staging in every mode", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)

		_, err := Load()
		require.ErrorContains(t, err, "staging_encryption.enabled must be true when permanent rotation is enabled")
	})

	t.Run("required staging cannot be disabled", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED", "true")

		_, err := Load()
		require.ErrorContains(t, err, "staging_encryption")
		require.ErrorContains(t, err, "enabled must be true when required is true")
	})

	t.Run("enabled staging requires key", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")

		_, err := Load()
		require.ErrorContains(t, err, "staging_encryption")
		require.ErrorContains(t, err, "key_id is required")
	})

	t.Run("release mode requires staging to be required", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)
		t.Setenv("SERVER_MODE", "release")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))

		_, err := Load()
		require.ErrorContains(t, err, "staging_encryption.required must be true in release mode")
	})

	t.Run("staging key ID cannot reuse signing key ID", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-signing-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))

		_, err := Load()
		require.ErrorContains(t, err, "key_id must differ from signing_key_id")
	})

	t.Run("staging key cannot reuse signing seed", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		signingKey := configureValidPermanentRotationSigning(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", base64.StdEncoding.EncodeToString(signingKey.Seed()))

		_, err := Load()
		require.ErrorContains(t, err, "must not reuse Ed25519 signing key material")
	})

	t.Run("valid independent release key", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		configureValidPermanentRotationSigning(t)
		t.Setenv("SERVER_MODE", "release")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))

		cfg, err := Load()
		require.NoError(t, err)
		require.True(t, cfg.TrustedPool.PermanentRotation.StagingEncryption.Enabled)
		require.True(t, cfg.TrustedPool.PermanentRotation.StagingEncryption.Required)
		require.Equal(t, TrustedPoolPermanentRotationDefaultPreparedCredentialTTL,
			cfg.TrustedPool.PermanentRotation.StagingEncryption.PreparedCredentialTTL)
	})

	t.Run("prepare replay credential disclosure TTL is bounded", func(t *testing.T) {
		for _, invalidTTL := range []string{"30s", "25h"} {
			t.Run(invalidTTL, func(t *testing.T) {
				resetViperWithJWTSecret(t)
				clearTrustedPoolPermanentRotationEnv(t)
				configureValidPermanentRotationSigning(t)
				t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
				t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
				t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))
				t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_PREPARED_CREDENTIAL_TTL", invalidTTL)

				_, err := Load()
				require.ErrorContains(t, err, "prepared_credential_ttl")
			})
		}
	})
}

func TestTrustedPoolPermanentRotationEmptyEnvironmentDoesNotOverrideConfigFile(t *testing.T) {
	resetViperWithJWTSecret(t)
	clearTrustedPoolPermanentRotationEnv(t)
	encoded := generatedEd25519PrivateKeyBase64(t)
	stagingEncoded := generatedStagingEncryptionKeyBase64(t)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	contents := "trusted_pool:\n" +
		"  permanent_rotation:\n" +
		"    enabled: true\n" +
		"    required: true\n" +
		"    signing_key_id: rotation-key-from-file\n" +
		"    signing_private_key_base64: " + encoded + "\n" +
		"    staging_encryption:\n" +
		"      enabled: true\n" +
		"      required: true\n" +
		"      key_id: rotation-staging-from-file\n" +
		"      key_base64: " + stagingEncoded + "\n" +
		"      prepared_credential_ttl: 20m\n"
	require.NoError(t, os.WriteFile(configFile, []byte(contents), 0o600))
	t.Setenv("CONFIG_FILE", configFile)

	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.TrustedPool.PermanentRotation.Enabled)
	require.True(t, cfg.TrustedPool.PermanentRotation.Required)
	require.Equal(t, "rotation-key-from-file", cfg.TrustedPool.PermanentRotation.SigningKeyID)
	require.True(t, cfg.TrustedPool.PermanentRotation.StagingEncryption.Enabled)
	require.Equal(t, "rotation-staging-from-file", cfg.TrustedPool.PermanentRotation.StagingEncryption.KeyID)
	require.Equal(t, 20*time.Minute, cfg.TrustedPool.PermanentRotation.StagingEncryption.PreparedCredentialTTL)
}

func TestTrustedPoolPermanentRotationStagingEncryptionLoadsFileAndRejectsAmbiguousSources(t *testing.T) {
	encoded := generatedStagingEncryptionKeyBase64(t)
	keyFile := filepath.Join(t.TempDir(), "staging-key.base64")
	require.NoError(t, os.WriteFile(keyFile, []byte(encoded+"\n"), 0o600))

	cfg := TrustedPoolPermanentRotationStagingEncryptionConfig{Enabled: true, Required: true, KeyID: "staging-v1", KeyFile: keyFile}
	key, err := cfg.StagingEncryptionKey()
	require.NoError(t, err)
	require.Equal(t, encoded, base64.StdEncoding.EncodeToString(key))
	clear(key)

	cfg.KeyBase64 = encoded
	_, err = cfg.StagingEncryptionKey()
	require.ErrorContains(t, err, "cannot both be set")
}

func TestTrustedPoolPermanentRotationLoadsFileBackedKeyAndRejectsAmbiguousSources(t *testing.T) {
	encoded := generatedEd25519PrivateKeyBase64(t)
	keyFile := filepath.Join(t.TempDir(), "rotation-key.base64")
	require.NoError(t, os.WriteFile(keyFile, []byte(encoded+"\n"), 0o600))

	t.Run("file backed key", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_FILE", keyFile)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", generatedStagingEncryptionKeyBase64(t))

		cfg, err := Load()
		require.NoError(t, err)
		privateKey, err := cfg.TrustedPool.PermanentRotation.SigningPrivateKey()
		require.NoError(t, err)
		require.Equal(t, encoded, base64.StdEncoding.EncodeToString(privateKey))
	})

	t.Run("both sources fail", func(t *testing.T) {
		resetViperWithJWTSecret(t)
		clearTrustedPoolPermanentRotationEnv(t)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", encoded)
		t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_FILE", keyFile)

		_, err := Load()
		require.ErrorContains(t, err, "cannot both be set")
	})
}
