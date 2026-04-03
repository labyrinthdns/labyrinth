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
