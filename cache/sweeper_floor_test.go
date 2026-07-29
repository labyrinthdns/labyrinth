package cache

import (
	"context"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestStartSweeper_ZeroIntervalDoesNotPanic pins the v0.8.10 gate:
// time.NewTicker(0) panics with "non-positive interval for NewTicker".
// A YAML cache.sweep_interval: 0 (or a /api/config/raw PUT that
// planted a zero value) would crash the resolver at boot before any
// query is served. StartSweeper now floors the interval at
// MinSweepInterval; this test fires the panic-prone path with
// interval=0 and asserts the goroutine starts cleanly.
func TestStartSweeper_ZeroIntervalDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartSweeper panicked with zero interval: %v — MinSweepInterval floor not applied", r)
		}
	}()

	m := metrics.NewMetrics()
	c := NewCache(100, 5, 86400, 3600, m)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start with interval=0 — the original panic path.
	go c.StartSweeper(ctx, 0)

	// Give the goroutine a moment to either panic or settle.
	time.Sleep(50 * time.Millisecond)
}

// TestStartSweeper_NegativeIntervalDoesNotPanic covers the symmetric
// branch — time.NewTicker treats negative intervals the same as zero.
func TestStartSweeper_NegativeIntervalDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StartSweeper panicked with negative interval: %v", r)
		}
	}()

	m := metrics.NewMetrics()
	c := NewCache(100, 5, 86400, 3600, m)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go c.StartSweeper(ctx, -10*time.Second)
	time.Sleep(50 * time.Millisecond)
}

// TestMinSweepInterval_StableConstant pins the floor. A regression
// that lifted it to a tiny value (1 ns, 1 µs) would re-open a CPU-
// burner thrash path; lifting it past several seconds would lengthen
// the eviction latency well past acceptable bounds.
func TestMinSweepInterval_StableConstant(t *testing.T) {
	if MinSweepInterval <= 0 {
		t.Fatalf("MinSweepInterval = %v is non-positive — would re-introduce the panic", MinSweepInterval)
	}
	if MinSweepInterval > 10*time.Second {
		t.Fatalf("MinSweepInterval = %v is too high — eviction latency penalty", MinSweepInterval)
	}
}
