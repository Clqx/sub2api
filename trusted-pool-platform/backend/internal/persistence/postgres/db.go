package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

const (
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 5
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 5 * time.Minute
)

// DBConfig 定义平台独立 PostgreSQL 连接池参数，不得指向 Sub2API 数据库。
type DBConfig struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

func (c DBConfig) validate() error {
	if c.URL == "" {
		return errors.New("trusted pool database URL is required")
	}
	if c.MaxOpenConns < 0 || c.MaxIdleConns < 0 || c.MaxIdleConns > c.MaxOpenConns {
		return errors.New("invalid trusted pool database pool limits")
	}
	if c.ConnMaxLifetime < 0 || c.ConnMaxIdleTime < 0 {
		return errors.New("invalid trusted pool database connection lifetime")
	}
	return nil
}

func (c DBConfig) withDefaults() DBConfig {
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = defaultMaxOpenConns
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = defaultMaxIdleConns
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = defaultConnMaxLifetime
	}
	if c.ConnMaxIdleTime == 0 {
		c.ConnMaxIdleTime = defaultConnMaxIdleTime
	}
	return c
}

// OpenDB 只有在数据库可连接时才返回；调用方不得降级到内存 Store。
func OpenDB(ctx context.Context, config DBConfig) (*sql.DB, error) {
	config = config.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", config.URL)
	if err != nil {
		return nil, fmt.Errorf("open trusted pool database: %w", err)
	}
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping trusted pool database: %w", err)
	}
	return db, nil
}

// DBProbe 用于 readiness；错误只返回给组合根，HTTP 响应不得泄露连接信息。
type DBProbe struct {
	DB *sql.DB
}

func (p DBProbe) Check(ctx context.Context) error {
	if p.DB == nil {
		return errors.New("trusted pool database is not configured")
	}
	return p.DB.PingContext(ctx)
}
