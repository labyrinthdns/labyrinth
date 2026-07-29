package metrics

import (
	"testing"
	"time"
)

func TestSnapshot(t *testing.T) {
	m := NewMetrics()

	m.IncQueries("A")
	m.IncQueries("A")
	m.IncQueries("AAAA")
	m.IncResponses("NOERROR")
	m.IncResponses("NXDOMAIN")
	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheHits()
	m.IncCacheMisses()
	m.IncUpstreamQueries()
	m.IncUpstreamErrors()
	m.IncRateLimited()
	m.IncCacheEvictions("expired")
	m.ObserveQueryDuration(10 * time.Millisecond)

	snap := m.Snapshot()

	if snap.QueriesByType["A"] != 2 {
		t.Errorf("A queries: expected 2, got %d", snap.QueriesByType["A"])
	}
	if snap.QueriesByType["AAAA"] != 1 {
		t.Errorf("AAAA queries: expected 1, got %d", snap.QueriesByType["AAAA"])
	}
	if snap.ResponsesByRCode["NOERROR"] != 1 {
		t.Errorf("NOERROR responses: expected 1, got %d", snap.ResponsesByRCode["NOERROR"])
	}
	if snap.ResponsesByRCode["NXDOMAIN"] != 1 {
		t.Errorf("NXDOMAIN responses: expected 1, got %d", snap.ResponsesByRCode["NXDOMAIN"])
	}
	if snap.CacheHits != 3 {
		t.Errorf("cache hits: expected 3, got %d", snap.CacheHits)
	}
	if snap.CacheMisses != 1 {
		t.Errorf("cache misses: expected 1, got %d", snap.CacheMisses)
	}
	if snap.CacheEvictions != 1 {
		t.Errorf("cache evictions: expected 1, got %d", snap.CacheEvictions)
	}
	if snap.UpstreamQueries != 1 {
		t.Errorf("upstream queries: expected 1, got %d", snap.UpstreamQueries)
	}
	if snap.UpstreamErrors != 1 {
		t.Errorf("upstream errors: expected 1, got %d", snap.UpstreamErrors)
	}
	if snap.RateLimited != 1 {
		t.Errorf("rate limited: expected 1, got %d", snap.RateLimited)
	}
	if snap.UptimeSeconds < 0 {
		t.Error("uptime should be >= 0")
	}
	if snap.Goroutines <= 0 {
		t.Error("goroutines should be > 0")
	}
	if snap.QueryDurationCount != 1 {
		t.Errorf("query duration count: expected 1, got %d", snap.QueryDurationCount)
	}
}

func TestSnapshotEmpty(t *testing.T) {
	m := NewMetrics()
	snap := m.Snapshot()

	if len(snap.QueriesByType) != 0 {
		t.Errorf("empty metrics should have no query types")
	}
	if snap.CacheHits != 0 {
		t.Errorf("cache hits should be 0")
	}
}

func TestSnapshotIsolation(t *testing.T) {
	m := NewMetrics()
	m.IncQueries("A")

	snap := m.Snapshot()
	m.IncQueries("A") // modify after snapshot

	if snap.QueriesByType["A"] != 1 {
		t.Error("snapshot should not be affected by subsequent changes")
	}
}

func TestSnapshotFallbackMetrics(t *testing.T) {
	m := NewMetrics()

	m.IncFallbackQueries()
	m.IncFallbackQueries()
	m.IncFallbackQueries()
	m.IncFallbackRecoveries()
	m.IncFallbackRecoveries()

	snap := m.Snapshot()

	if snap.FallbackQueries != 3 {
		t.Errorf("fallback queries: expected 3, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 2 {
		t.Errorf("fallback recoveries: expected 2, got %d", snap.FallbackRecoveries)
	}
}

func TestSnapshotEmptyFallbackMetrics(t *testing.T) {
	m := NewMetrics()
	snap := m.Snapshot()

	if snap.FallbackQueries != 0 {
		t.Errorf("fallback queries: expected 0, got %d", snap.FallbackQueries)
	}
	if snap.FallbackRecoveries != 0 {
		t.Errorf("fallback recoveries: expected 0, got %d", snap.FallbackRecoveries)
	}
}
