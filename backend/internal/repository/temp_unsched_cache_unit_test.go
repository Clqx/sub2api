//go:build unit

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestTempUnschedCacheGenerationPreventsStaleDelete(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	ctx := context.Background()
	cache := NewTempUnschedCache(client)
	conditional := cache.(service.ConditionalTempUnschedCache)
	accountID := int64(901)

	firstUntil := time.Now().Add(5 * time.Minute).Unix()
	require.NoError(t, cache.SetTempUnsched(ctx, accountID, &service.TempUnschedState{UntilUnix: firstUntil, ErrorMessage: "first"}))
	first, err := cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.NotEmpty(t, first.Generation)

	secondUntil := firstUntil + 300
	require.NoError(t, cache.SetTempUnsched(ctx, accountID, &service.TempUnschedState{UntilUnix: secondUntil, ErrorMessage: "second"}))
	second, err := cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.NotEmpty(t, second.Generation)
	require.NotEqual(t, first.Generation, second.Generation)

	deleted, err := conditional.DeleteTempUnschedIfObserved(ctx, accountID, first.Generation)
	require.NoError(t, err)
	require.False(t, deleted)
	current, err := cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, second.Generation, current.Generation)

	require.NoError(t, cache.SetTempUnsched(ctx, accountID, &service.TempUnschedState{
		UntilUnix:    firstUntil,
		ErrorMessage: "shorter concurrent fault",
	}))
	third, err := cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, secondUntil, third.UntilUnix, "a shorter observation must not shorten the block")
	require.Equal(t, "second", third.ErrorMessage, "a shorter observation must preserve the stronger state")
	require.NotEqual(t, second.Generation, third.Generation, "even same/shorter observations are new generations")

	deleted, err = conditional.DeleteTempUnschedIfObserved(ctx, accountID, second.Generation)
	require.NoError(t, err)
	require.False(t, deleted)
	deleted, err = conditional.DeleteTempUnschedIfObserved(ctx, accountID, third.Generation)
	require.NoError(t, err)
	require.True(t, deleted)
	current, err = cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.Nil(t, current)
}

func TestTempUnschedCacheSetUpgradesLegacyValueWithoutShorteningIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	ctx := context.Background()
	cache := NewTempUnschedCache(client)
	accountID := int64(902)
	key := fmt.Sprintf("%s%d", tempUnschedPrefix, accountID)
	legacyUntil := time.Now().Add(20 * time.Minute).Unix()
	legacyTTL := 15 * time.Minute

	require.NoError(t, client.Set(ctx, key, fmt.Sprintf(`{"until_unix":%d,"error_message":"legacy"}`, legacyUntil), legacyTTL).Err())
	ttlBefore, err := client.TTL(ctx, key).Result()
	require.NoError(t, err)
	require.NoError(t, cache.SetTempUnsched(ctx, accountID, &service.TempUnschedState{
		UntilUnix:    time.Now().Add(5 * time.Minute).Unix(),
		ErrorMessage: "shorter replacement",
	}))

	upgraded, err := cache.GetTempUnsched(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, legacyUntil, upgraded.UntilUnix)
	require.Equal(t, "legacy", upgraded.ErrorMessage)
	require.NotEmpty(t, upgraded.Generation)
	ttlAfter, err := client.TTL(ctx, key).Result()
	require.NoError(t, err)
	require.Equal(t, ttlBefore, ttlAfter)

	conditional := cache.(service.ConditionalTempUnschedCache)
	deleted, err := conditional.DeleteTempUnschedIfObserved(ctx, accountID, upgraded.Generation)
	require.NoError(t, err)
	require.True(t, deleted)
}
