package cache

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestLaunchPrefetch_DropsWhenSaturated(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(100, 1, 3600, 60, m)
	// Shrink the semaphore to 1 for a deterministic test.
	c.prefetchSem = make(chan struct{}, 1)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var runs atomic.Int64
	c.SetPrefetchEnabled(true)
	c.SetPrefetchFunc(func(name string, qtype, qclass uint16) {
		runs.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	})

	if !c.launchPrefetch("a.example.", dns.TypeA, dns.ClassIN, nil) {
		t.Fatal("first prefetch should admit")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch never started")
	}

	if c.launchPrefetch("b.example.", dns.TypeA, dns.ClassIN, nil) {
		t.Fatal("second prefetch should drop under cap")
	}
	if got := m.PrefetchDrops(); got != 1 {
		t.Fatalf("prefetchDrops = %d, want 1", got)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runs.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
}
