package migrations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration222EnforcesTrustedPoolSeatPrincipalPolicy(t *testing.T) {
	content, err := FS.ReadFile("222_user_principal_type.sql")
	require.NoError(t, err)

	sql := string(content)
	require.Contains(t, sql, "principal_type VARCHAR(32) NOT NULL DEFAULT 'human'")
	require.Contains(t, sql, "CHECK (principal_type IN ('human', 'trusted_pool_seat'))")
	require.Contains(t, sql, "CREATE OR REPLACE FUNCTION enforce_interactive_auth_identity_principal()")
	require.Contains(t, sql, "BEFORE INSERT OR UPDATE ON auth_identities")
	require.Contains(t, sql, "principal_type = 'human'")
}
