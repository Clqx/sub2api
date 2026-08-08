package service

import (
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/stretchr/testify/require"
)

func TestRenewedSubscriptionTermAlignsUsageWindowsWithTheirBoundaries(t *testing.T) {
	startsAt := time.Date(2026, 8, 2, 9, 37, 0, 0, time.UTC)
	renewed := renewedSubscriptionTerm(
		&UserSubscription{},
		"",
		startsAt,
		startsAt.Add(24*time.Hour),
	)

	require.Equal(t, startsAt, *renewed.HourlyWindowStart)
	require.Equal(t, timezone.StartOfDay(startsAt), *renewed.DailyWindowStart)
	require.Equal(t, startsAt, *renewed.WeeklyWindowStart)
	require.Equal(t, startsAt, *renewed.MonthlyWindowStart)
}

func TestHourlyWindowCatchUpUsesSubscriptionAlignedBoundary(t *testing.T) {
	startsAt := time.Date(2026, 8, 2, 9, 37, 0, 0, time.UTC)
	sub := &UserSubscription{
		StartsAt:          startsAt,
		ExpiresAt:         startsAt.Add(4 * time.Hour),
		HourlyWindowStart: &startsAt,
	}

	windowStart, ok := sub.automaticWindowStartAt(
		sub.HourlyWindowStart,
		time.Hour,
		startsAt.Add(2*time.Hour+15*time.Minute),
	)
	require.True(t, ok)
	require.Equal(t, startsAt.Add(2*time.Hour), windowStart)
}
