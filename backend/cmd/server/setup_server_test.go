//go:build unit

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func resetSetupServerConfig(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("JWT_SECRET", "")
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

func TestNewSetupServerAllowsDisabledPermanentRotation(t *testing.T) {
	resetSetupServerConfig(t)

	server, err := newSetupServer()
	require.NoError(t, err)
	require.NotNil(t, server)
}

func TestNewSetupServerRejectsInvalidEnabledPermanentRotationBeforeListen(t *testing.T) {
	resetSetupServerConfig(t)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", "not-base64")

	server, err := newSetupServer()
	require.Nil(t, server)
	require.ErrorContains(t, err, "trusted_pool.permanent_rotation")
	require.ErrorContains(t, err, "64-byte Ed25519 private key")
}

func TestNewSetupServerAcceptsValidRequiredPermanentRotation(t *testing.T) {
	resetSetupServerConfig(t)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, stagingKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_REQUIRED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv("SERVER_MODE", "release")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_REQUIRED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", base64.StdEncoding.EncodeToString(stagingKey.Seed()))

	server, err := newSetupServer()
	require.NoError(t, err)
	require.NotNil(t, server)
}

func TestNewSetupServerRejectsEnabledPermanentRotationWithoutStagingEncryptionBeforeListen(t *testing.T) {
	resetSetupServerConfig(t)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString(privateKey))

	server, err := newSetupServer()
	require.Nil(t, server)
	require.ErrorContains(t, err, "staging_encryption.enabled must be true when permanent rotation is enabled")
}

func TestNewSetupServerRejectsReleasePermanentRotationWithoutRequiredStagingBeforeListen(t *testing.T) {
	resetSetupServerConfig(t)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, stagingKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	t.Setenv("SERVER_MODE", "release")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_KEY_ID", "rotation-key-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_SIGNING_PRIVATE_KEY_BASE64", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_ENABLED", "true")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_ID", "rotation-staging-v1")
	t.Setenv("TRUSTED_POOL_PERMANENT_ROTATION_STAGING_ENCRYPTION_KEY_BASE64", base64.StdEncoding.EncodeToString(stagingKey.Seed()))

	server, err := newSetupServer()
	require.Nil(t, server)
	require.ErrorContains(t, err, "staging_encryption.required must be true in release mode")
}
