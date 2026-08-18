package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

type workerFunc func(context.Context) error

func (f workerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestWorkerGroupStopsByCancellation(t *testing.T) {
	started := make(chan struct{})
	group, err := NewWorkerGroup(workerFunc(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := group.Stop(ctx); err != nil {
		t.Fatalf("Stop(): %v", err)
	}
}

func TestWorkerGroupReportsFailure(t *testing.T) {
	expected := errors.New("recovery failed")
	group, err := NewWorkerGroup(workerFunc(func(context.Context) error { return expected }))
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-group.Errors():
		if !errors.Is(actual, expected) {
			t.Fatalf("worker error = %v", actual)
		}
	case <-time.After(time.Second):
		t.Fatal("worker error was not reported")
	}
}
