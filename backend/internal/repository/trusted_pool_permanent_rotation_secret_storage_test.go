//go:build unit

package repository

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestTrustedPoolPermanentRotationEncryptedStagingStaticContract(t *testing.T) {
	matches, err := fs.Glob(migrations.FS, "227_*.sql")
	require.NoError(t, err)
	require.Len(t, matches, 1, "encrypted staging must be delivered by exactly one forward migration 227")

	content, err := migrations.FS.ReadFile(matches[0])
	require.NoError(t, err)
	migrationSQL := normalizePermanentRotationSecretStorageSource(string(content))

	envelopeColumns := []string{
		"prepared_credential_envelope_version",
		"prepared_credential_key_id",
		"prepared_credential_nonce",
		"prepared_credential_ciphertext",
		"prepared_credential_wrapped_dek",
		"prepared_credential_wrap_nonce",
		"prepared_credential_expires_at",
	}
	for _, column := range envelopeColumns {
		require.Contains(t, migrationSQL, column, "migration 227 must define %s", column)
		require.Contains(t, migrationSQL, column+" is not null",
			"PREPARED rows must require %s", column)
		require.Contains(t, migrationSQL, column+" is null",
			"post-activation rows must clear %s", column)
	}
	for _, required := range []string{
		"prepared_credential is not null",
		"raise exception",
		"prepared_credential_envelope_version smallint",
		"prepared_credential_key_id varchar(128)",
		"prepared_credential_wrap_nonce bytea",
		"prepared_credential_wrapped_dek bytea",
		"prepared_credential_nonce bytea",
		"prepared_credential_ciphertext bytea",
		"prepared_credential_expires_at timestamptz",
		"prepared_credential_envelope_version = 1",
		"octet_length(prepared_credential_nonce) = 12",
		"octet_length(prepared_credential_wrap_nonce) = 12",
		"octet_length(prepared_credential_ciphertext) >= 16",
		"octet_length(prepared_credential_wrapped_dek) = 48",
	} {
		require.Contains(t, migrationSQL, required)
	}
	require.True(t,
		strings.Contains(migrationSQL, "drop column prepared_credential") ||
			strings.Contains(migrationSQL, "drop column if exists prepared_credential"),
		"migration 227 must remove the legacy plaintext prepared_credential column")

	implementation := readPermanentRotationImplementation(t)
	barePlaintextColumn := regexp.MustCompile("(?i)\\bprepared_credential\\b")
	require.NotRegexp(t, barePlaintextColumn, implementation,
		"repository implementation must not retain the legacy plaintext column or fallback")
	compactImplementation := removePermanentRotationSecretStorageWhitespace(implementation)
	for _, column := range envelopeColumns {
		require.Contains(t, strings.ToLower(implementation), column,
			"repository implementation must use %s", column)
		require.Contains(t, compactImplementation, column+"=null",
			"activate must clear %s in the protected transaction", column)
	}
}

func readPermanentRotationImplementation(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob("trusted_pool_permanent_rotation*.go")
	require.NoError(t, err)
	var source strings.Builder
	for _, name := range matches {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, readErr := os.ReadFile(name)
		require.NoError(t, readErr)
		source.Write(content)
		source.WriteByte(' ')
	}
	require.NotZero(t, source.Len(), "permanent rotation repository implementation is missing")
	return source.String()
}

func normalizePermanentRotationSecretStorageSource(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

func removePermanentRotationSecretStorageWhitespace(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), "")
}
