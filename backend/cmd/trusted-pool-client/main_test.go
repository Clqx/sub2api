package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

type capturedString struct{ value string }

func (capture *capturedString) Match(value driver.Value) bool {
	text, ok := value.(string)
	if ok {
		capture.value = text
	}
	return ok && text != ""
}

func TestProvisionTrustedPoolClientStoresVerifierAndEncryptedSigningMaterial(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	key := bytes.Repeat([]byte{0x42}, 32)
	randomMaterial := append(bytes.Repeat([]byte{0x24}, 32), bytes.Repeat([]byte{0x35}, 32)...)
	randomMaterial = append(randomMaterial, bytes.Repeat([]byte{0x46}, 32)...)
	random := bytes.NewReader(randomMaterial)
	verifier, encrypted := new(capturedString), new(capturedString)

	mock.ExpectQuery("(?s)INSERT INTO trusted_pool_integration_clients.*ON CONFLICT.*DO NOTHING.*RETURNING client_id").
		WithArgs("platform-1", "pool-1", verifier, encrypted, sqlmock.AnyArg(), nil).
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}).AddRow("platform-1"))
	credentials, err := provisionTrustedPoolClient(context.Background(), db, key, random, clientProvisionOptions{
		ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read", "seat:write"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, credentials.BearerSecret)
	require.NotEmpty(t, credentials.HMACSecret)
	require.NotEqual(t, credentials.BearerSecret, credentials.HMACSecret)
	require.Contains(t, credentials.BearerSecret, "tpb_")
	require.Contains(t, credentials.HMACSecret, "tph_")
	digest := sha256.Sum256([]byte(credentials.BearerSecret))
	require.Equal(t, hex.EncodeToString(digest[:]), verifier.value)
	hmacDigest := sha256.Sum256([]byte(credentials.HMACSecret))
	require.NotEqual(t, hex.EncodeToString(hmacDigest[:]), verifier.value)
	require.NotEqual(t, verifier.value, encrypted.value)
	require.Equal(t, credentials.HMACSecret, decryptTestHMACSecret(t, key, encrypted.value))
	require.NotEqual(t, credentials.BearerSecret, decryptTestHMACSecret(t, key, encrypted.value))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisionTrustedPoolClientRequiresExplicitRotation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectQuery("(?s)INSERT INTO trusted_pool_integration_clients.*ON CONFLICT.*DO NOTHING.*RETURNING client_id").
		WillReturnError(sql.ErrNoRows)
	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-2", Scopes: []string{"seat:read"},
		})
	require.ErrorContains(t, err, "use -rotate")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisionTrustedPoolClientRotatesExistingClientExplicitly(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	verifier, encrypted := new(capturedString), new(capturedString)

	mock.ExpectQuery("(?s)UPDATE trusted_pool_integration_clients.*expires_at=CASE WHEN \\$6 THEN \\$7::timestamptz ELSE expires_at END.*external_pool_id IS NULL OR external_pool_id=\\$2.*RETURNING client_id").
		WithArgs("platform-1", "pool-1", verifier, encrypted, sqlmock.AnyArg(), false, nil).
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}).AddRow("platform-1"))
	credentials, err := provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"}, Rotate: true,
		})
	require.NoError(t, err)
	require.NotEmpty(t, credentials.BearerSecret)
	require.NotEmpty(t, credentials.HMACSecret)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisionTrustedPoolClientRotatesWithExplicitExpiry(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	mock.ExpectQuery("(?s)UPDATE trusted_pool_integration_clients.*expires_at=CASE WHEN \\$6 THEN \\$7::timestamptz ELSE expires_at END.*RETURNING client_id").
		WithArgs("platform-1", "pool-1", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, expiresAt).
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}).AddRow("platform-1"))
	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"},
			ExpiresAt: &expiresAt, Rotate: true,
		})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisionTrustedPoolClientClearsExpiryOnlyWhenExplicit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectQuery("(?s)UPDATE trusted_pool_integration_clients.*expires_at=CASE WHEN \\$6 THEN \\$7::timestamptz ELSE expires_at END.*RETURNING client_id").
		WithArgs("platform-1", "pool-1", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, nil).
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}).AddRow("platform-1"))
	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"},
			ClearExpiry: true, Rotate: true,
		})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisionTrustedPoolClientRejectsAmbiguousExpiryOptions(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"},
			ExpiresAt: &expiresAt, ClearExpiry: true, Rotate: true,
		})
	require.ErrorContains(t, err, "mutually exclusive")

	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"}, ClearExpiry: true,
		})
	require.ErrorContains(t, err, "requires rotation")
}

func TestProvisionTrustedPoolClientRejectsMissingOrCrossPoolRotationTarget(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectQuery("(?s)UPDATE trusted_pool_integration_clients.*external_pool_id IS NULL OR external_pool_id=\\$2.*RETURNING client_id").
		WillReturnError(sql.ErrNoRows)
	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-2", Scopes: []string{"seat:read"}, Rotate: true,
		})
	require.ErrorContains(t, err, "does not exist or is already bound to another external pool")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestParseScopesRejectsUnknownPrivileges(t *testing.T) {
	_, err := parseScopes("seat:read,admin:all")
	require.ErrorContains(t, err, "unsupported trusted-pool scope")
	_, err = parseScopes("*")
	require.ErrorContains(t, err, "unsupported trusted-pool scope")
	_, err = parseScopes("seat:read,settlement:resolve")
	require.ErrorContains(t, err, "must be the client's only scope")
	resolveScopes, err := parseScopes("settlement:resolve")
	require.NoError(t, err)
	require.Equal(t, []string{"settlement:resolve"}, resolveScopes)
	scopes, err := parseScopes("seat:write, seat:read,seat:read")
	require.NoError(t, err)
	require.Equal(t, []string{"seat:read", "seat:write"}, scopes)
}

func TestParseScopesRequiresPermanentRotationSingleton(t *testing.T) {
	scopes, err := parseScopes("seat:permanent-rotate")
	require.NoError(t, err)
	require.Equal(t, []string{"seat:permanent-rotate"}, scopes)

	for _, value := range []string{
		"seat:permanent-rotate,seat:read",
		"seat:write,seat:permanent-rotate",
		"settlement:resolve,seat:permanent-rotate",
	} {
		_, err = parseScopes(value)
		require.ErrorContains(t, err, "must be the client's only scope", value)
	}
}

func TestProvisionTrustedPoolClientRejectsExpiredCredential(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	expired := time.Now().Add(-time.Minute)

	_, err = provisionTrustedPoolClient(context.Background(), db, bytes.Repeat([]byte{0x42}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 96)), clientProvisionOptions{
			ClientID: "platform-1", ExternalPoolID: "pool-1", Scopes: []string{"seat:read"}, ExpiresAt: &expired,
		})
	require.ErrorContains(t, err, "expires-at must be in the future")
}

func decryptTestHMACSecret(t *testing.T, key []byte, encoded string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data), gcm.NonceSize())
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	require.NoError(t, err)
	return string(plain)
}
