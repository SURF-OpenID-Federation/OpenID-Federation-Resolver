package resolver

import "sync"

// inflightGroup coalesces concurrent identical lookups so one outbound
// resolve is shared by all waiters (request stampede).
type inflightGroup struct {
	mu sync.Mutex
	m  map[string]*inflightCall
}

type inflightCall struct {
	wg  sync.WaitGroup
	val *CachedEntityStatement
	err error
}

func (g *inflightGroup) Do(key string, fn func() (*CachedEntityStatement, error)) (*CachedEntityStatement, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*inflightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &inflightCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.val, c.err
}
