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

// MaxInfraCacheEntries caps the number of distinct nameserver IPs the
// InfraCache will track at once. An attacker who controls an
// authoritative server (or a chain of glue records pointing into
// their controlled zone) can drive the resolver to contact thousands
// of distinct upstream NS addresses by serving each query with a
// fresh, unique IPv4/IPv6 NS set. Each contact lazily creates an
// NSInfo via getOrCreate, and CleanStale only runs on the operator-
// configured interval — between ticks the map can grow without
// bound. 100k IP-tracked nameservers is multiple orders of magnitude
// above any legitimate population (the global root + TLD + popular
// auth NS footprint sits below 50k IPs) and small enough that the
// worst-case footprint stays bounded to a handful of MB. When the
// cap is reached, getOrCreate evicts the OLDEST (least recently
// used) entry to make room — the cache exists to remember "good
// recent servers", so evicting the stalest is the right loss.
const MaxInfraCacheEntries = 100_000

// MaxLameZonesPerNS caps the number of zones a single NSInfo will
// remember as lame. Without this an attacker who controls one
// nameserver IP can flag it lame for millions of distinct sub-zones
// via crafted referral chains, inflating the per-NSInfo LameZones
// map without bound. 10k lame zones per NS is enormous — a single
// authoritative misbehaving for 10k zones is a sysadmin emergency,
// not a steady state — and stops a single IP from amplifying memory
// pressure linearly in qname diversity. When the cap is reached,
// RecordLame is a no-op (the cache is degraded but functional; the
// NSInfo still serves its primary role of tracking RTT/FailCount).
const MaxLameZonesPerNS = 10_000

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
		// Bounded eviction. If the cache is full, drop the entry with
		// the oldest LastUsed timestamp before inserting the new one.
		// This is O(n) over the map but only runs on a cache miss
		// after the cap is reached, and the cap (100k) means at most
		// one linear scan per insert under sustained pressure. We
		// prefer this to a fixed-cap random eviction because the LRU
		// signal is exactly what makes a stale entry worth losing.
		if len(ic.entries) >= MaxInfraCacheEntries {
			ic.evictOldestLocked()
		}
		info = &NSInfo{
			LameZones: make(map[string]struct{}),
			LastUsed:  time.Now(),
		}
		ic.entries[nsIP] = info
	}
	return info
}

// evictOldestLocked drops the entry with the oldest LastUsed timestamp
// to make room for a new insert. Caller holds ic.mu in write mode.
func (ic *InfraCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range ic.entries {
		if first || v.LastUsed.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastUsed
			first = false
		}
	}
	if oldestKey != "" {
		delete(ic.entries, oldestKey)
	}
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

// RecordLame marks a nameserver as lame for a specific zone. When the
// per-NSInfo LameZones map has reached MaxLameZonesPerNS, additional
// distinct lame zones are dropped silently — see the cap's docstring
// for the threat model. RTT / FailCount continue to track as normal.
func (ic *InfraCache) RecordLame(nsIP string, zone string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	info := ic.getOrCreate(nsIP)
	info.LastUsed = time.Now()
	if _, exists := info.LameZones[zone]; !exists && len(info.LameZones) >= MaxLameZonesPerNS {
		return
	}
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
