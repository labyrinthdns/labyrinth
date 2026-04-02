package resolver

import (
	"fmt"
	"sync"
)

// inflight provides request coalescing: if multiple goroutines request the same
// query simultaneously, only one upstream resolution runs and all waiters share the result.
type inflight struct {
	mu    sync.Mutex
	calls map[string]*call
}

type call struct {
	wg     sync.WaitGroup
	result *ResolveResult
	err    error
}

func newInflight() *inflight {
	return &inflight{calls: make(map[string]*call)}
}

// do executes fn for the given key, deduplicating concurrent calls with the same key.
func (inf *inflight) do(key string, fn func() (*ResolveResult, error)) (*ResolveResult, error) {
	inf.mu.Lock()
	if c, ok := inf.calls[key]; ok {
		inf.mu.Unlock()
		c.wg.Wait()
		return c.result, c.err
	}

	c := &call{}
	c.wg.Add(1)
	inf.calls[key] = c
	inf.mu.Unlock()

	func() {
		defer func() {
			if r := recover(); r != nil {
				c.err = fmt.Errorf("panic in resolver: %v", r)
			}
		}()
		c.result, c.err = fn()
	}()

	c.wg.Done()

	inf.mu.Lock()
	delete(inf.calls, key)
	inf.mu.Unlock()

	return c.result, c.err
}
