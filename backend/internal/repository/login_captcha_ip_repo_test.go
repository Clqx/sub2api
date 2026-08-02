package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestLoginCaptchaIPRepositoryListClearsExpiredFailureWindow(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	windowStartedAt := now.Add(-11 * time.Minute)
	lastFailedAt := now.Add(-10 * time.Minute)
	blockedUntil := now.Add(-time.Minute)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM login_captcha_ip_records").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT id, client_ip, failure_count").
		WithArgs(20, 0).
		WillReturnRows(loginCaptchaIPRows().AddRow(
			int64(7), "203.0.113.7", 5, int64(8), 1,
			windowStartedAt, now.Add(-time.Hour), lastFailedAt, nil, blockedUntil,
			"scanner", nil, nil, "", now.Add(-time.Hour), lastFailedAt,
		))

	repo := &loginCaptchaIPRepository{db: db}
	result, err := repo.List(context.Background(), &service.LoginCaptchaIPFilter{}, now, 10*time.Minute)
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	require.Equal(t, "cleared", result.Records[0].Status)
	require.Zero(t, result.Records[0].FailureCount)
	require.NoError(t, mock.ExpectationsWereMet())
}

func loginCaptchaIPRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "client_ip", "failure_count", "total_failures", "block_count",
		"window_started_at", "first_failed_at", "last_failed_at", "last_success_at", "blocked_until",
		"last_user_agent", "resolved_at", "resolved_by_user_id", "resolution_note", "created_at", "updated_at",
	})
}
