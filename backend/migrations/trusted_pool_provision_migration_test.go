package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrustedPoolProvisionMigrationSerializesOrdinaryGroupResources(t *testing.T) {
	content, err := FS.ReadFile("223_trusted_pool_provision.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	groupLock := "PERFORM 1 FROM groups WHERE id=NEW.group_id FOR SHARE"
	bindingRead := "SELECT 1 FROM trusted_pool_groups WHERE group_id=NEW.group_id"
	require.Contains(t, sql, groupLock)
	// 软删除资源恢复时也必须重新经过 Principal 隔离检查。
	require.Contains(t, sql, "BEFORE INSERT OR UPDATE OF user_id, group_id, deleted_at ON user_subscriptions")
	require.Contains(t, sql, "BEFORE INSERT OR UPDATE OF user_id, group_id, deleted_at ON api_keys")
	require.Contains(t, sql, bindingRead)
	require.Less(t, strings.Index(sql, groupLock), strings.Index(sql, bindingRead))
}

func TestTrustedPoolProvisionMigrationKeepsOperationHistoryImmutable(t *testing.T) {
	content, err := FS.ReadFile("223_trusted_pool_provision.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "PRIMARY KEY (client_id, operation_id)")
	require.Contains(t, sql, "BEFORE UPDATE OR DELETE ON trusted_pool_provision_operations")
	require.Contains(t, sql, "OLD.seat_id IS NOT NULL")
	require.Contains(t, sql, "credential_fingerprint CHAR(64) NOT NULL CHECK (credential_fingerprint ~ '^[0-9a-f]{64}$')")
	require.Contains(t, sql, "NEW.credential_fingerprint <> OLD.credential_fingerprint")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS trusted_pool_provision_credential_claims")
	require.Contains(t, sql, "UNIQUE (client_id, claim_operation_id)")
	require.Contains(t, sql, "BEFORE UPDATE OR DELETE ON trusted_pool_provision_credential_claims")
	require.Contains(t, sql, "REFERENCES trusted_pool_provision_operations(client_id, operation_id, seat_id)")
	require.Equal(t, 2, strings.Count(sql, "credential_fingerprint CHAR(64) NOT NULL CHECK (credential_fingerprint ~ '^[0-9a-f]{64}$')"))
}

func TestTrustedPoolClientSecurityMigrationFailsClosed(t *testing.T) {
	content, err := FS.ReadFile("224_trusted_pool_client_security.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS external_pool_id VARCHAR(128)")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS hmac_secret_encrypted TEXT")
	require.NotContains(t, sql, "client_pool_candidates")
	require.NotContains(t, sql, "trusted_pool_settlement_resolutions resolution")
	require.Contains(t, sql, "SET status='disabled'")
	require.Contains(t, sql, "external_pool_id IS NULL OR BTRIM(external_pool_id)=''")
	require.Contains(t, sql, "status <> 'active' OR (external_pool_id IS NOT NULL")
	require.Contains(t, sql, "FOREIGN KEY (client_id, external_pool_id)")
	require.Contains(t, sql, "NOT VALID")
	require.Contains(t, sql, "never valid HMAC signing material")
}

func TestTrustedPoolSettlementResolutionBindingMigrationFailsClosed(t *testing.T) {
	content, err := FS.ReadFile("225_trusted_pool_settlement_resolution_binding.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS expected_assignment_epoch BIGINT")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS expected_request_id VARCHAR(128)")
	require.Contains(t, sql, "expected_assignment_epoch > 0")
	require.Contains(t, sql, "CREATE TRIGGER trg_trusted_pool_resolution_require_binding")
	require.Contains(t, sql, "BEFORE INSERT ON trusted_pool_settlement_resolutions")
	require.Contains(t, sql, "trusted pool settlement resolution requires expected epoch and request id")
	require.Contains(t, sql, "ck_trusted_pool_resolve_scope_isolation")
	require.Contains(t, sql, "cardinality(scopes) = 1 AND scopes[1] = 'settlement:resolve'")
	require.Contains(t, sql, "SET status = 'disabled'")
}
