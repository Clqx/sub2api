package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type probeFunc func(context.Context) error

func (f probeFunc) Check(ctx context.Context) error { return f(ctx) }

func TestReadinessHandlerDoesNotLeakProbeError(t *testing.T) {
	readiness, err := NewReadiness(time.Second, probeFunc(func(context.Context) error {
		return errors.New("postgres://user:secret@db/internal")
	}))
	if err != nil {
		t.Fatal(err)
	}
	handler := WithReadiness(http.NotFoundHandler(), readiness)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("unsafe readiness response: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestReadinessHandlerPassesAndDelegates(t *testing.T) {
	readiness, err := NewReadiness(time.Second, probeFunc(func(context.Context) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	handler := WithReadiness(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}), readiness)
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready status = %d", ready.Code)
	}
	delegated := httptest.NewRecorder()
	handler.ServeHTTP(delegated, httptest.NewRequest(http.MethodGet, "/health", nil))
	if delegated.Code != http.StatusNoContent {
		t.Fatalf("delegated status = %d", delegated.Code)
	}
}
