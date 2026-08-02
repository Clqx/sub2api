package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateAndCheckLimits_HourlyQuota(t *testing.T) {
	hourlyLimit := 5.0
	group := &Group{HourlyLimitUSD: &hourlyLimit}
	svc := &SubscriptionService{}

	freshStart := time.Now().Add(-30 * time.Minute)
	fresh := &UserSubscription{
		Status:            SubscriptionStatusActive,
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		HourlyWindowStart: &freshStart,
		HourlyUsageUSD:    5.1,
	}
	needsMaintenance, err := svc.ValidateAndCheckLimits(fresh, group)
	require.False(t, needsMaintenance)
	require.ErrorIs(t, err, ErrHourlyLimitExceeded)

	expiredStart := time.Now().Add(-61 * time.Minute)
	expired := &UserSubscription{
		Status:            SubscriptionStatusActive,
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		HourlyWindowStart: &expiredStart,
		HourlyUsageUSD:    5.1,
	}
	needsMaintenance, err = svc.ValidateAndCheckLimits(expired, group)
	require.NoError(t, err)
	require.True(t, needsMaintenance)
	require.Zero(t, expired.HourlyUsageUSD)
}

func TestValidateAndCheckLimits_MissingHourlyWindowNeedsMaintenance(t *testing.T) {
	hourlyLimit := 5.0
	svc := &SubscriptionService{}
	dailyStart := time.Now()
	sub := &UserSubscription{
		Status:           SubscriptionStatusActive,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		DailyWindowStart: &dailyStart,
	}

	needsMaintenance, err := svc.ValidateAndCheckLimits(sub, &Group{HourlyLimitUSD: &hourlyLimit})
	require.NoError(t, err)
	require.True(t, needsMaintenance)
}

func TestCheckUsageLimits_HourlyCheckedFirst(t *testing.T) {
	hourlyLimit := 1.0
	dailyLimit := 100.0
	sub := &UserSubscription{HourlyUsageUSD: 1.1, DailyUsageUSD: 101}
	err := (&SubscriptionService{}).CheckUsageLimits(context.Background(), sub, &Group{
		HourlyLimitUSD: &hourlyLimit,
		DailyLimitUSD:  &dailyLimit,
	}, 0)
	require.ErrorIs(t, err, ErrHourlyLimitExceeded)
}

func TestCalculateProgress_Hourly(t *testing.T) {
	limit := 10.0
	windowStart := time.Now().Add(-15 * time.Minute)
	sub := &UserSubscription{
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		HourlyWindowStart: &windowStart,
		HourlyUsageUSD:    2.5,
	}

	progress := (&SubscriptionService{}).calculateProgress(sub, &Group{Name: "hourly", HourlyLimitUSD: &limit})
	require.NotNil(t, progress.Hourly)
	require.InDelta(t, 2.5, progress.Hourly.UsedUSD, 1e-9)
	require.InDelta(t, 7.5, progress.Hourly.RemainingUSD, 1e-9)
	require.InDelta(t, 25, progress.Hourly.Percentage, 1e-9)
	require.Equal(t, windowStart.Add(time.Hour), progress.Hourly.ResetsAt)
}
