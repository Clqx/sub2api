//go:build unit

package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestProvideTrustedPoolIntegrationServiceLeavesPermanentRotationExplicitlyDisabled(t *testing.T) {
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: false, SigningKeyID: "unused", SigningPrivateKeyBase64: "not-base64",
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.Nil(t, svc.permanentRotationSigner)
}

func TestProvideTrustedPoolIntegrationServiceInstallsValidatedSigner(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, independentKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, SigningKeyID: "rotation-key-v1",
			SigningPrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
			StagingEncryption: config.TrustedPoolPermanentRotationStagingEncryptionConfig{
				Enabled: true, KeyID: "rotation-staging-v1",
				KeyBase64: base64.StdEncoding.EncodeToString(independentKey.Seed()),
			},
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.NoError(t, err)
	require.NotNil(t, svc.permanentRotationSigner)
	require.Equal(t, "rotation-key-v1", svc.permanentRotationSigner.keyID)
	require.Equal(t, privateKey, svc.permanentRotationSigner.privateKey)
}

func TestProvideTrustedPoolIntegrationServiceRejectsInvalidEnabledSigner(t *testing.T) {
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, SigningKeyID: "rotation-key-v1", SigningPrivateKeyBase64: "not-base64",
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.ErrorContains(t, err, "configure trusted-pool permanent rotation signer")
	require.Nil(t, svc)
}

func TestProvideTrustedPoolIntegrationServiceRejectsRequiredButDisabled(t *testing.T) {
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{Required: true},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.ErrorContains(t, err, "enabled must be true when required is true")
	require.Nil(t, svc)
}

func TestProvideTrustedPoolIntegrationServiceRejectsEnabledRotationWithoutStagingEncryption(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, SigningKeyID: "rotation-signing-v1",
			SigningPrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.ErrorContains(t, err, "enabled must be true when permanent rotation is enabled")
	require.Nil(t, svc)
}

func TestProvideTrustedPoolIntegrationServiceRejectsReleaseWithoutRequiredStagingEncryption(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, independentKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := &config.Config{Server: config.ServerConfig{Mode: "release"}, TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, SigningKeyID: "rotation-signing-v1",
			SigningPrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
			StagingEncryption: config.TrustedPoolPermanentRotationStagingEncryptionConfig{
				Enabled: true, KeyID: "rotation-staging-v1",
				KeyBase64: base64.StdEncoding.EncodeToString(independentKey.Seed()),
			},
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.ErrorContains(t, err, "required must be true in release mode")
	require.Nil(t, svc)
}

func TestProvideTrustedPoolIntegrationServiceAcceptsIndependentReleaseStagingKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, independentKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := &config.Config{Server: config.ServerConfig{Mode: "release"}, TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, Required: true, SigningKeyID: "rotation-signing-v1",
			SigningPrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
			StagingEncryption: config.TrustedPoolPermanentRotationStagingEncryptionConfig{
				Enabled: true, Required: true, KeyID: "rotation-staging-v1",
				KeyBase64:             base64.StdEncoding.EncodeToString(independentKey.Seed()),
				PreparedCredentialTTL: 15 * time.Minute,
			},
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestProvideTrustedPoolIntegrationServiceRejectsInvalidPrepareReplayDisclosureTTL(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, independentKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cfg := &config.Config{TrustedPool: config.TrustedPoolConfig{
		PermanentRotation: config.TrustedPoolPermanentRotationConfig{
			Enabled: true, SigningKeyID: "rotation-signing-v1",
			SigningPrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
			StagingEncryption: config.TrustedPoolPermanentRotationStagingEncryptionConfig{
				Enabled: true, KeyID: "rotation-staging-v1",
				KeyBase64:             base64.StdEncoding.EncodeToString(independentKey.Seed()),
				PreparedCredentialTTL: 30 * time.Second,
			},
		},
	}}

	svc, err := ProvideTrustedPoolIntegrationService(nil, nil, nil, nil, cfg)
	require.ErrorContains(t, err, "prepared credential TTL")
	require.Nil(t, svc)
}
