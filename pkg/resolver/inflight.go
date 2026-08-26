package resolver

import (
	"context"
	"sync"
	"time"
)

// inflightGroup coalesces concurrent identical lookups so one outbound
// resolve is shared by all waiters (request stampede).
type inflightGroup struct {
	mu sync.Mutex
	m  map[string]*inflightCall
}

type inflightCall struct {
	done chan struct{}
	val  *CachedEntityStatement
	err  error
}

func (c *inflightCall) wait(ctx context.Context) (*CachedEntityStatement, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return c.val, c.err
	}
}

func detachResolveContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return context.WithTimeout(base, timeout)
}

func (g *inflightGroup) len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.m)
}

func (g *inflightGroup) Do(ctx context.Context, key string, timeout time.Duration, fn func(context.Context) (*CachedEntityStatement, error)) (*CachedEntityStatement, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*inflightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		return c.wait(ctx)
	}
	c := &inflightCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	workCtx, cancel := detachResolveContext(ctx, timeout)
	go func() {
		defer cancel()
		c.val, c.err = fn(workCtx)
		close(c.done)
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
	}()

	return c.wait(ctx)
}
