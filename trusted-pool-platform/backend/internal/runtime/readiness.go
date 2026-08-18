package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trusted-pool-platform/backend/internal/credentials"
)

type Probe interface {
	Check(context.Context) error
}

type EnvelopeProbe struct {
	Cipher credentials.EnvelopeCipher
}

func (p EnvelopeProbe) Check(ctx context.Context) error {
	if p.Cipher == nil {
		return errors.New("envelope cipher is not configured")
	}
	return p.Cipher.Ready(ctx)
}

type Readiness struct {
	probes  []Probe
	timeout time.Duration
}

func NewReadiness(timeout time.Duration, probes ...Probe) (*Readiness, error) {
	if timeout <= 0 || len(probes) == 0 {
		return nil, errors.New("positive readiness timeout and probes are required")
	}
	for _, probe := range probes {
		if probe == nil {
			return nil, errors.New("readiness probe is nil")
		}
	}
	return &Readiness{probes: probes, timeout: timeout}, nil
}

func (r *Readiness) Check(ctx context.Context) error {
	if r == nil {
		return errors.New("readiness is not configured")
	}
	checkContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	for _, probe := range r.probes {
		if err := probe.Check(checkContext); err != nil {
			return err
		}
	}
	return nil
}

// WithReadiness 只暴露就绪布尔结果，不把数据库或 KMS 错误写入响应。
func WithReadiness(next http.Handler, readiness *Readiness) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ready" {
			next.ServeHTTP(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := readiness.Check(request.Context()); err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			if request.Method == http.MethodGet {
				_ = json.NewEncoder(writer).Encode(map[string]string{"status": "not_ready"})
			}
			return
		}
		writer.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_ = json.NewEncoder(writer).Encode(map[string]string{"status": "ready"})
		}
	})
}
