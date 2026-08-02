package service

import (
	"context"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var ErrLoginCaptchaIPRecordNotFound = infraerrors.NotFound("LOGIN_CAPTCHA_IP_RECORD_NOT_FOUND", "login captcha IP record not found")

type LoginCaptchaIPRecord struct {
	ID               int64      `json:"id"`
	ClientIP         string     `json:"client_ip"`
	FailureCount     int        `json:"failure_count"`
	TotalFailures    int64      `json:"total_failures"`
	BlockCount       int        `json:"block_count"`
	WindowStartedAt  time.Time  `json:"window_started_at"`
	FirstFailedAt    time.Time  `json:"first_failed_at"`
	LastFailedAt     time.Time  `json:"last_failed_at"`
	LastSuccessAt    *time.Time `json:"last_success_at,omitempty"`
	BlockedUntil     *time.Time `json:"blocked_until,omitempty"`
	LastUserAgent    string     `json:"last_user_agent"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	ResolvedByUserID *int64     `json:"resolved_by_user_id,omitempty"`
	ResolutionNote   string     `json:"resolution_note"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Status           string     `json:"status"`
}

type LoginCaptchaIPFilter struct {
	Page     int
	PageSize int
	Query    string
	Status   string
}

type LoginCaptchaIPList struct {
	Records  []*LoginCaptchaIPRecord
	Total    int
	Page     int
	PageSize int
}

type LoginCaptchaIPRepository interface {
	GetBlocked(ctx context.Context, clientIP string, now time.Time) (*LoginCaptchaIPRecord, error)
	RecordFailure(ctx context.Context, clientIP, userAgent string, now time.Time, threshold int, window, block time.Duration) (*LoginCaptchaIPRecord, error)
	RecordSuccess(ctx context.Context, clientIP string, now time.Time) error
	List(ctx context.Context, filter *LoginCaptchaIPFilter, now time.Time, failureWindow time.Duration) (*LoginCaptchaIPList, error)
	Unblock(ctx context.Context, id, actorUserID int64, note string, now time.Time) (*LoginCaptchaIPRecord, error)
}
