package cache

import (
	"context"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestSweepEvictsExpired(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "sweep.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("sweep.com", dns.TypeA, dns.ClassIN, answers, nil)

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Fatalf("expected 1 entry, got %d", stats.Entries)
	}

	time.Sleep(2 * time.Second)

	c.sweep()

	stats = c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expected 0 entries after sweep, got %d", stats.Entries)
	}
}

func TestSweepKeepsFresh(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "fresh.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 3600, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("fresh.com", dns.TypeA, dns.ClassIN, answers, nil)

	c.sweep()

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("expected 1 entry (not expired), got %d", stats.Entries)
	}
}

func TestStartSweeperStopsOnCancel(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.StartSweeper(ctx, 100*time.Millisecond)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("sweeper did not stop after context cancel")
	}
}

func TestSweepWithNilMetrics(t *testing.T) {
	// Cover the sweep() path where c.metrics == nil
	c := NewCache(1000, 1, 86400, 3600, nil)

	answers := []dns.ResourceRecord{{
		Name: "sweepnil.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("sweepnil.com", dns.TypeA, dns.ClassIN, answers, nil)

	time.Sleep(2 * time.Second)

	// sweep should not panic with nil metrics
	c.sweep()

	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expected 0 entries after sweep, got %d", stats.Entries)
	}
}

func TestSweepNoEvictions(t *testing.T) {
	// Cover sweep() path where evicted == 0, so the metrics branch is not entered
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "fresh.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 3600, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("fresh.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Sweep with no expired entries
	c.sweep()

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("expected 1 entry (not expired), got %d", stats.Entries)
	}
}

func TestFlush(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	for i := 0; i < 50; i++ {
		answers := []dns.ResourceRecord{{
			Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store("domain"+string(rune('A'+i))+".com", dns.TypeA, dns.ClassIN, answers, nil)
	}

	c.Flush()

	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("expected 0 after flush, got %d", stats.Entries)
	}
}
