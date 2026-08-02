package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type loginCaptchaIPRepository struct {
	db *sql.DB
}

func NewLoginCaptchaIPRepository(db *sql.DB) service.LoginCaptchaIPRepository {
	return &loginCaptchaIPRepository{db: db}
}

const loginCaptchaIPColumns = `id, client_ip, failure_count, total_failures, block_count,
window_started_at, first_failed_at, last_failed_at, last_success_at, blocked_until,
last_user_agent, resolved_at, resolved_by_user_id, resolution_note, created_at, updated_at`

type loginCaptchaIPScanner interface {
	Scan(dest ...any) error
}

func scanLoginCaptchaIP(scanner loginCaptchaIPScanner, now time.Time) (*service.LoginCaptchaIPRecord, error) {
	record := &service.LoginCaptchaIPRecord{}
	var lastSuccessAt, blockedUntil, resolvedAt sql.NullTime
	var resolvedBy sql.NullInt64
	if err := scanner.Scan(
		&record.ID, &record.ClientIP, &record.FailureCount, &record.TotalFailures, &record.BlockCount,
		&record.WindowStartedAt, &record.FirstFailedAt, &record.LastFailedAt, &lastSuccessAt, &blockedUntil,
		&record.LastUserAgent, &resolvedAt, &resolvedBy, &record.ResolutionNote, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if lastSuccessAt.Valid {
		record.LastSuccessAt = &lastSuccessAt.Time
	}
	if blockedUntil.Valid {
		record.BlockedUntil = &blockedUntil.Time
	}
	if resolvedAt.Valid {
		record.ResolvedAt = &resolvedAt.Time
	}
	if resolvedBy.Valid {
		record.ResolvedByUserID = &resolvedBy.Int64
	}
	record.Status = loginCaptchaIPStatus(record, now)
	return record, nil
}

func loginCaptchaIPStatus(record *service.LoginCaptchaIPRecord, now time.Time) string {
	if record != nil && record.BlockedUntil != nil && record.BlockedUntil.After(now) {
		return "blocked"
	}
	if record != nil && record.FailureCount > 0 {
		return "monitoring"
	}
	return "cleared"
}

func (r *loginCaptchaIPRepository) GetBlocked(ctx context.Context, clientIP string, now time.Time) (*service.LoginCaptchaIPRecord, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil login captcha IP repository")
	}
	query := `SELECT ` + loginCaptchaIPColumns + ` FROM login_captcha_ip_records
WHERE client_ip=$1 AND blocked_until>$2`
	record, err := scanLoginCaptchaIP(r.db.QueryRowContext(ctx, query, clientIP, now.UTC()), now)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return record, err
}

func (r *loginCaptchaIPRepository) RecordFailure(ctx context.Context, clientIP, userAgent string, now time.Time, threshold int, window, block time.Duration) (*service.LoginCaptchaIPRecord, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil login captcha IP repository")
	}
	now = now.UTC()
	query := `INSERT INTO login_captcha_ip_records (
client_ip, failure_count, total_failures, block_count, window_started_at,
first_failed_at, last_failed_at, blocked_until, last_user_agent, created_at, updated_at
) VALUES ($1,1,1,CASE WHEN $3<=1 THEN 1 ELSE 0 END,$2,$2,$2,
CASE WHEN $3<=1 THEN $2+($5 * INTERVAL '1 second') ELSE NULL END,$6,$2,$2)
ON CONFLICT (client_ip) DO UPDATE SET
failure_count = CASE
  WHEN login_captcha_ip_records.blocked_until>$2 THEN login_captcha_ip_records.failure_count
  WHEN login_captcha_ip_records.window_started_at>$2-($4 * INTERVAL '1 second') THEN login_captcha_ip_records.failure_count+1
  ELSE 1
END,
total_failures = login_captcha_ip_records.total_failures+1,
block_count = login_captcha_ip_records.block_count + CASE WHEN
  NOT COALESCE(login_captcha_ip_records.blocked_until>$2,FALSE) AND
  (CASE WHEN login_captcha_ip_records.window_started_at>$2-($4 * INTERVAL '1 second')
    THEN login_captcha_ip_records.failure_count+1 ELSE 1 END) >= $3
  THEN 1 ELSE 0 END,
window_started_at = CASE
  WHEN login_captcha_ip_records.blocked_until>$2 THEN login_captcha_ip_records.window_started_at
  WHEN login_captcha_ip_records.window_started_at>$2-($4 * INTERVAL '1 second') THEN login_captcha_ip_records.window_started_at
  ELSE $2
END,
last_failed_at=$2,
blocked_until = CASE
  WHEN login_captcha_ip_records.blocked_until>$2 THEN login_captcha_ip_records.blocked_until
  WHEN (CASE WHEN login_captcha_ip_records.window_started_at>$2-($4 * INTERVAL '1 second')
    THEN login_captcha_ip_records.failure_count+1 ELSE 1 END) >= $3
    THEN $2+($5 * INTERVAL '1 second')
  ELSE NULL
END,
last_user_agent=$6,
resolved_at=NULL,
resolved_by_user_id=NULL,
resolution_note='',
updated_at=$2
RETURNING ` + loginCaptchaIPColumns
	record, err := scanLoginCaptchaIP(r.db.QueryRowContext(ctx, query,
		clientIP, now, threshold, int64(window/time.Second), int64(block/time.Second), truncateString(userAgent, 512)), now)
	return record, err
}

func (r *loginCaptchaIPRepository) RecordSuccess(ctx context.Context, clientIP string, now time.Time) error {
	if r == nil || r.db == nil || strings.TrimSpace(clientIP) == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE login_captcha_ip_records SET
failure_count=0, window_started_at=$2, last_success_at=$2,
blocked_until=CASE WHEN blocked_until<=$2 THEN NULL ELSE blocked_until END,
updated_at=$2 WHERE client_ip=$1`, clientIP, now.UTC())
	return err
}

func (r *loginCaptchaIPRepository) List(ctx context.Context, filter *service.LoginCaptchaIPFilter, now time.Time, failureWindow time.Duration) (*service.LoginCaptchaIPList, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil login captcha IP repository")
	}
	if filter == nil {
		filter = &service.LoginCaptchaIPFilter{}
	}
	page, pageSize := filter.Page, filter.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	where := make([]string, 0, 2)
	args := make([]any, 0, 4)
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+query+"%")
		where = append(where, fmt.Sprintf("(client_ip ILIKE $%d OR last_user_agent ILIKE $%d)", len(args), len(args)))
	}
	switch filter.Status {
	case "blocked":
		args = append(args, now.UTC())
		where = append(where, fmt.Sprintf("blocked_until>$%d", len(args)))
	case "monitoring":
		args = append(args, now.UTC(), int64(failureWindow/time.Second))
		nowArg, windowArg := len(args)-1, len(args)
		where = append(where, fmt.Sprintf("(blocked_until IS NULL OR blocked_until<=$%d) AND failure_count>0 AND window_started_at>$%d-($%d * INTERVAL '1 second')", nowArg, nowArg, windowArg))
	case "cleared":
		args = append(args, now.UTC(), int64(failureWindow/time.Second))
		nowArg, windowArg := len(args)-1, len(args)
		where = append(where, fmt.Sprintf("(blocked_until IS NULL OR blocked_until<=$%d) AND (failure_count=0 OR window_started_at<=$%d-($%d * INTERVAL '1 second'))", nowArg, nowArg, windowArg))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM login_captcha_ip_records"+whereSQL, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+loginCaptchaIPColumns+` FROM login_captcha_ip_records`+whereSQL+
		fmt.Sprintf(" ORDER BY last_failed_at DESC,id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	records := make([]*service.LoginCaptchaIPRecord, 0, pageSize)
	for rows.Next() {
		record, scanErr := scanLoginCaptchaIP(rows, now)
		if scanErr != nil {
			return nil, scanErr
		}
		if record.Status == "monitoring" && !record.WindowStartedAt.After(now.Add(-failureWindow)) {
			record.FailureCount = 0
			record.Status = "cleared"
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &service.LoginCaptchaIPList{Records: records, Total: total, Page: page, PageSize: pageSize}, nil
}

func (r *loginCaptchaIPRepository) Unblock(ctx context.Context, id, actorUserID int64, note string, now time.Time) (*service.LoginCaptchaIPRecord, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil login captcha IP repository")
	}
	now = now.UTC()
	query := `UPDATE login_captcha_ip_records SET failure_count=0, blocked_until=NULL,
resolved_at=$2, resolved_by_user_id=$3, resolution_note=$4, updated_at=$2
WHERE id=$1 RETURNING ` + loginCaptchaIPColumns
	record, err := scanLoginCaptchaIP(r.db.QueryRowContext(ctx, query, id, now, actorUserID, truncateString(note, 255)), now)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrLoginCaptchaIPRecordNotFound
	}
	return record, err
}
