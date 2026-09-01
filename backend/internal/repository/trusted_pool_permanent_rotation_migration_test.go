//go:build unit

package repository

import (
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestTrustedPoolPermanentRotationMigrationClosesDirectSQLBypass(t *testing.T) {
	content, err := migrations.FS.ReadFile("226_trusted_pool_permanent_rotation.sql")
	require.NoError(t, err)
	sqlText := string(content)
	for _, required := range []string{
		"seat:permanent-rotate", "cardinality(scopes) = 1", "rotation_prepared",
		"ALTER COLUMN state TYPE VARCHAR(64)",
		"DEFERRABLE INITIALLY DEFERRED", "enforce_trusted_pool_permanent_rotation_aggregate",
		"trusted_pool_permanent_child_set_hash_phase2g", "trusted_pool_permanent_prepared_set_hash_phase2g",
		"prepared_credential IS NULL", "encode(sha256(convert_to(k.key, 'UTF8')), 'hex')",
		"activated_pending_commit", "rotation_activated_pending_commit", "trusted_pool_permanent_commit_hash_phase2g",
		"status='retiring'", "retire_trusted_pool_permanent_rotation_on_seat_exit",
		"OLD.state='active' AND NEW.state <> 'active'", "OLD.status='committed' AND NEW.status='retiring'",
		"OLD.status='retiring' AND NEW.status='superseded'",
		"successor.from_epoch=p.to_epoch", "successor.prepare_operation_id=p.superseded_by_prepare_operation_id",
		"FROM trusted_pool_seats live_seat", "live_seat.external_pool_id=p.external_pool_id",
		"child.seat_id=live_seat.id",
	} {
		require.Contains(t, sqlText, required)
	}
	require.NotContains(t, strings.ToLower(sqlText), "authorization_cache_invalidated = true")
	// 连续轮换必须先由 Seat 退出 active 触发 retiring，再由相邻完整 successor supersede；
	// 禁止调用方直接伪造 activated -> superseded 跳转。
	require.NotContains(t, sqlText, "OLD.status='committed' AND NEW.status='superseded'")
	require.Contains(t, sqlText, "successor.seat_count=p.seat_count")
	require.Contains(t, sqlText, "new_child.seat_id=old_child.seat_id")
	require.Contains(t, sqlText, "p.status='activated_pending_commit'")
	require.Contains(t, sqlText, "k.status <> 'disabled' OR u.status <> 'suspended'")
	require.Contains(t, sqlText, "OLD.status='activated_pending_commit' AND NEW.status='committed'")
	require.Contains(t, sqlText, "WHERE committed_at IS NULL")
}
