package runtime

import (
	"context"
	"errors"
	"sync"
)

// Worker 是恢复扫描器的稳定生命周期边界；具体扫描 API 由 application 层实现后注入。
type Worker interface {
	Run(context.Context) error
}

type WorkerGroup struct {
	workers []Worker

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	errors  chan error
	started bool
}

func NewWorkerGroup(workers ...Worker) (*WorkerGroup, error) {
	for _, worker := range workers {
		if worker == nil {
			return nil, errors.New("runtime worker is nil")
		}
	}
	return &WorkerGroup{workers: workers, errors: make(chan error, max(1, len(workers)))}, nil
}

func (g *WorkerGroup) Start(parent context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started {
		return errors.New("runtime workers already started")
	}
	workerContext, cancel := context.WithCancel(parent)
	g.cancel = cancel
	g.done = make(chan struct{})
	g.started = true
	var wait sync.WaitGroup
	wait.Add(len(g.workers))
	for _, worker := range g.workers {
		go func(worker Worker) {
			defer wait.Done()
			if err := worker.Run(workerContext); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case g.errors <- err:
				default:
				}
			}
		}(worker)
	}
	go func() {
		wait.Wait()
		close(g.done)
	}()
	return nil
}

func (g *WorkerGroup) Errors() <-chan error {
	return g.errors
}

func (g *WorkerGroup) Stop(ctx context.Context) error {
	g.mu.Lock()
	if !g.started {
		g.mu.Unlock()
		return nil
	}
	g.cancel()
	done := g.done
	g.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
