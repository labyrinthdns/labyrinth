package resolver

import (
	"context"
	"sort"
	"sync"
	"time"
)

// NSInfo holds performance data for a single nameserver IP.
type NSInfo struct {
	RTT       time.Duration // EWMA of round-trip times
	FailCount int
	LameZones map[string]struct{}
	LastUsed  time.Time
}

// InfraCache tracks nameserver performance (RTT, failures, lameness)
// to enable intelligent NS selection.
type InfraCache struct {
	mu      sync.RWMutex
	entries map[string]*NSInfo
}

// NewInfraCache creates a new infrastructure cache.
func NewInfraCache() *InfraCache {
	return &InfraCache{
		entries: make(map[string]*NSInfo),
	}
}

func (ic *InfraCache) getOrCreate(nsIP string) *NSInfo {
	info, ok := ic.entries[nsIP]
	if !ok {
		info = &NSInfo{
			LameZones: make(map[string]struct{}),
			LastUsed:  time.Now(),
		}
		ic.entries[nsIP] = info
	}
	return info
}

// RecordRTT records a successful query RTT using EWMA (0.7*old + 0.3*sample).
func (ic *InfraCache) RecordRTT(nsIP string, rtt time.Duration) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	info := ic.getOrCreate(nsIP)
	info.LastUsed = time.Now()
	if info.RTT == 0 {
		info.RTT = rtt
	} else {
		// EWMA: new = 0.7*old + 0.3*sample
		info.RTT = time.Duration(float64(info.RTT)*0.7 + float64(rtt)*0.3)
	}
}

// RecordFailure increments the fail count for a nameserver.
func (ic *InfraCache) RecordFailure(nsIP string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	info := ic.getOrCreate(nsIP)
	info.LastUsed = time.Now()
	info.FailCount++
}

// RecordLame marks a nameserver as lame for a specific zone.
func (ic *InfraCache) RecordLame(nsIP string, zone string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	info := ic.getOrCreate(nsIP)
	info.LastUsed = time.Now()
	info.LameZones[zone] = struct{}{}
}

// IsLame returns true if the nameserver is known to be lame for the given zone.
func (ic *InfraCache) IsLame(nsIP string, zone string) bool {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	info, ok := ic.entries[nsIP]
	if !ok {
		return false
	}
	_, lame := info.LameZones[zone]
	return lame
}

// effectiveRTT returns the RTT with a penalty for failures.
// Each failure adds 500ms of penalty to discourage use of failing servers.
func (ic *InfraCache) effectiveRTT(nsIP string) time.Duration {
	info, ok := ic.entries[nsIP]
	if !ok {
		// Unknown servers get a default 100ms (moderate priority)
		return 100 * time.Millisecond
	}
	rtt := info.RTT
	if rtt == 0 {
		rtt = 100 * time.Millisecond
	}
	rtt += time.Duration(info.FailCount) * 500 * time.Millisecond
	return rtt
}

// SortByRTT sorts nameserver entries by their effective RTT (fastest first).
// Entries with failures are penalised. Unknown servers get moderate priority.
func (ic *InfraCache) SortByRTT(entries []nsEntry) []nsEntry {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	sorted := make([]nsEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		ipI := sorted[i].ipv4
		if ipI == "" {
			ipI = sorted[i].ipv6
		}
		ipJ := sorted[j].ipv4
		if ipJ == "" {
			ipJ = sorted[j].ipv6
		}
		return ic.effectiveRTT(ipI) < ic.effectiveRTT(ipJ)
	})
	return sorted
}

// CleanStale removes entries that have not been used for more than maxIdle.
func (ic *InfraCache) CleanStale(maxIdle time.Duration) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	cutoff := time.Now().Add(-maxIdle)
	for ip, info := range ic.entries {
		if info.LastUsed.Before(cutoff) {
			delete(ic.entries, ip)
		}
	}
}

// StartCleanup runs periodic cleanup of stale infra cache entries.
func (ic *InfraCache) StartCleanup(ctx context.Context, interval, maxIdle time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ic.CleanStale(maxIdle)
		}
	}
}

// Len returns the number of entries in the infra cache (for testing).
func (ic *InfraCache) Len() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return len(ic.entries)
}

// GetRTT returns the recorded RTT for a nameserver (for testing).
func (ic *InfraCache) GetRTT(nsIP string) time.Duration {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	if info, ok := ic.entries[nsIP]; ok {
		return info.RTT
	}
	return 0
}
