package resolver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinth-dns/labyrinth/dns"
)

func TestInflightCoalescing(t *testing.T) {
	inf := newInflight()

	var callCount atomic.Int32
	started := make(chan struct{})

	fn := func() (*ResolveResult, error) {
		callCount.Add(1)
		close(started) // signal that fn is running
		time.Sleep(50 * time.Millisecond)
		return &ResolveResult{RCODE: dns.RCodeNoError}, nil
	}

	var wg sync.WaitGroup
	results := make([]*ResolveResult, 10)

	// Launch first goroutine to start the inflight call
	wg.Add(1)
	go func() {
		defer wg.Done()
		r, _ := inf.do("same-key", fn)
		results[0] = r
	}()

	// Wait for fn to start, then launch 9 more goroutines that will coalesce
	<-started
	for i := 1; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, _ := inf.do("same-key", fn)
			results[idx] = r
		}(i)
	}
	wg.Wait()

	// fn should have been called exactly once
	if count := callCount.Load(); count != 1 {
		t.Errorf("expected fn called 1 time, got %d", count)
	}

	// All results should have valid RCODE
	for i, r := range results {
		if r == nil {
			t.Errorf("result[%d] is nil", i)
		} else if r.RCODE != dns.RCodeNoError {
			t.Errorf("result[%d].RCODE = %d", i, r.RCODE)
		}
	}
}

func TestInflightDifferentKeys(t *testing.T) {
	inf := newInflight()

	var callCount atomic.Int32

	fn := func() (*ResolveResult, error) {
		callCount.Add(1)
		return &ResolveResult{RCODE: dns.RCodeNoError}, nil
	}

	// Different keys should not be coalesced
	inf.do("key-a", fn)
	inf.do("key-b", fn)

	if count := callCount.Load(); count != 2 {
		t.Errorf("expected 2 calls for different keys, got %d", count)
	}
}

func TestInflightPanicRecovery(t *testing.T) {
	inf := newInflight()

	result, err := inf.do("panic-key", func() (*ResolveResult, error) {
		panic("test panic")
	})

	if err == nil {
		t.Fatal("expected error from panic recovery")
	}
	if result != nil {
		t.Error("result should be nil after panic")
	}
}
