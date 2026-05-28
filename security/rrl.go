package security

import (
	"net"
	"strings"
	"sync"
	"time"
)

// RRLAction represents the action to take for a rate-limited response.
type RRLAction int

const (
	RRLAllow RRLAction = iota
	RRLDrop
	RRLSlip // send TC=1 truncated response
)

// RRL implements Response Rate Limiting to prevent DNS amplification attacks.
type RRL struct {
	mu                 sync.Mutex
	entries            map[rrlKey]*rrlEntry
	responsesPerSecond float64
	slipRatio          int
	ipv4Prefix         int
	ipv6Prefix         int
	cleanupInterval    time.Duration
}

const defaultRRLCleanupInterval = 5 * time.Minute

// MaxRRLEntries caps the per-(prefix, qname, response_type) entries
// map. RRL is a remote-attacker-reachable surface: each entry is keyed
// on the requester's source-IP /prefix, the query name (up to 255
// bytes), and a response-type tag. A UDP-source-spoofing attacker
// sending queries for distinct names from distinct spoofed sources
// can grow this map without bound — between the 5-minute cleanup
// ticks, the entries map can reach gigabytes of resident memory
// before any eviction happens. 1 M is the same ceiling used on
// RateLimiter.clients (v0.7.65) and AdminServer.clientQueryNum
// (v0.7.66) — well above any legitimate workload and bounded under
// the OOM threshold. When the cap fires the oldest entry by
// `lastTime` is evicted to make room. RRL semantics survive
// eviction: the spoofed attacker already gets a fresh per-key budget
// on every distinct (prefix, qname, responseType) tuple by design,
// so eviction-then-recreate preserves the rate-limit contract.
const MaxRRLEntries = 1_000_000

const (
	maxRRLPrefixLen       = 64
	maxRRLQNameLen        = 255
	maxRRLResponseTypeLen = 32
)

type rrlKey struct {
	prefix       string
	qname        string
	responseType string
}

type rrlEntry struct {
	tokens    float64
	lastTime  time.Time
	slipCount int
}

// NewRRL creates a new Response Rate Limiter.
func NewRRL(responsesPerSecond float64, slipRatio, ipv4Prefix, ipv6Prefix int) *RRL {
	return &RRL{
		entries:            make(map[rrlKey]*rrlEntry),
		responsesPerSecond: responsesPerSecond,
		slipRatio:          slipRatio,
		ipv4Prefix:         ipv4Prefix,
		ipv6Prefix:         ipv6Prefix,
		cleanupInterval:    defaultRRLCleanupInterval,
	}
}

// AllowResponse checks if a response should be allowed, dropped, or slipped.
func (r *RRL) AllowResponse(sourceIP string, qname string, responseType string) RRLAction {
	r.mu.Lock()
	defer r.mu.Unlock()

	prefix := normalizeRRLKeyPart(r.sourcePrefix(sourceIP), maxRRLPrefixLen, false)
	key := rrlKey{
		prefix:       prefix,
		qname:        normalizeRRLKeyPart(qname, maxRRLQNameLen, true),
		responseType: strings.ToUpper(normalizeRRLKeyPart(responseType, maxRRLResponseTypeLen, false)),
	}
	now := time.Now()

	entry, ok := r.entries[key]
	if !ok {
		if len(r.entries) >= MaxRRLEntries {
			r.evictOldestLocked()
		}
		r.entries[key] = &rrlEntry{
			tokens:   r.responsesPerSecond - 1,
			lastTime: now,
		}
		return RRLAllow
	}

	elapsed := now.Sub(entry.lastTime).Seconds()
	entry.tokens += elapsed * r.responsesPerSecond
	if entry.tokens > r.responsesPerSecond {
		entry.tokens = r.responsesPerSecond
	}
	entry.lastTime = now

	if entry.tokens >= 1 {
		entry.tokens--
		return RRLAllow
	}

	// Rate limited
	entry.slipCount++
	if r.slipRatio > 0 && entry.slipCount%r.slipRatio == 0 {
		return RRLSlip
	}
	return RRLDrop
}

func (r *RRL) sourcePrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}

	if ip4 := ip.To4(); ip4 != nil {
		mask := net.CIDRMask(r.ipv4Prefix, 32)
		return ip4.Mask(mask).String()
	}

	mask := net.CIDRMask(r.ipv6Prefix, 128)
	return ip.Mask(mask).String()
}

func normalizeRRLKeyPart(value string, maxLen int, lower bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if len(value) > maxLen {
		value = value[:maxLen]
	}
	if lower {
		return strings.ToLower(value)
	}
	return value
}

// evictOldestLocked drops the entry with the oldest `lastTime` to free
// a slot when the cap is hit. Caller holds r.mu. Single-pass O(n) scan
// — cap fires rarely in practice (cleanup ticker prunes idle entries
// every 5 minutes), so this is acceptable.
func (r *RRL) evictOldestLocked() {
	var oldestKey rrlKey
	var oldestTime time.Time
	first := true
	for k, e := range r.entries {
		if first || e.lastTime.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.lastTime
			first = false
		}
	}
	if !first {
		delete(r.entries, oldestKey)
	}
}

// StartCleanup removes stale RRL entries periodically.
func (r *RRL) StartCleanup(ctx interface{ Done() <-chan struct{} }) {
	interval := r.cleanupInterval
	if interval <= 0 {
		interval = defaultRRLCleanupInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			cutoff := time.Now().Add(-interval)
			for key, entry := range r.entries {
				if entry.lastTime.Before(cutoff) {
					delete(r.entries, key)
				}
			}
			r.mu.Unlock()
		}
	}
}
