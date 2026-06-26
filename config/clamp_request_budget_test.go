package config

import (
	"testing"
	"time"
)

// TestClampConfigBounds_MaxQueriesPerRequestFloor pins the v0.8.29 floor:
// resolver.max_queries_per_request <= 0 makes the resolver charge the very
// first outbound query of every request against a zero budget, so every cache
// miss SERVFAILs while cache hits still answer — the same half-alive black-hole
// shape as the max_cname_depth floor. A YAML typo (`max_queries_per_request: 0`
// read as "no limit", which is the opposite of what 0 does) triggers it.
func TestClampConfigBounds_MaxQueriesPerRequestFloor(t *testing.T) {
	for _, sentinel := range []int{0, -1, -100} {
		cfg := &Config{}
		cfg.Resolver.MaxQueriesPerRequest = sentinel
		clampConfigBounds(cfg)
		if cfg.Resolver.MaxQueriesPerRequest != defaultMaxQueriesPerRequest {
			t.Errorf("sentinel=%d: MaxQueriesPerRequest = %d, want default %d",
				sentinel, cfg.Resolver.MaxQueriesPerRequest, defaultMaxQueriesPerRequest)
		}
	}
}

// TestClampConfigBounds_MaxQueriesPerRequestUntouchedWhenPositive pins that an
// operator forcing a small-but-positive budget (e.g. a tightly-bounded edge
// resolver) is not rewritten, and that a huge value is capped at the ceiling.
func TestClampConfigBounds_MaxQueriesPerRequestBounds(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.MaxQueriesPerRequest = 50
	clampConfigBounds(cfg)
	if cfg.Resolver.MaxQueriesPerRequest != 50 {
		t.Errorf("positive MaxQueriesPerRequest=50 rewritten to %d", cfg.Resolver.MaxQueriesPerRequest)
	}

	cfg = &Config{}
	cfg.Resolver.MaxQueriesPerRequest = clampMaxQueriesPerRequest * 10
	clampConfigBounds(cfg)
	if cfg.Resolver.MaxQueriesPerRequest != clampMaxQueriesPerRequest {
		t.Errorf("oversized MaxQueriesPerRequest = %d, want ceiling %d",
			cfg.Resolver.MaxQueriesPerRequest, clampMaxQueriesPerRequest)
	}
}

// TestClampConfigBounds_RequestTimeoutFloor pins the v0.8.29 floor:
// resolver.request_timeout <= 0 makes the per-request deadline "now" (0) or in
// the past (<0), so every request times out before its first upstream query —
// total outage with cache still serving (same inverted-zero footgun as
// upstream_timeout).
func TestClampConfigBounds_RequestTimeoutFloor(t *testing.T) {
	for _, sentinel := range []time.Duration{0, -time.Millisecond, -time.Hour} {
		cfg := &Config{}
		cfg.Resolver.RequestTimeout = sentinel
		clampConfigBounds(cfg)
		if cfg.Resolver.RequestTimeout != defaultRequestTimeout {
			t.Errorf("sentinel=%v: RequestTimeout = %v, want default %v",
				sentinel, cfg.Resolver.RequestTimeout, defaultRequestTimeout)
		}
	}
}

// TestClampConfigBounds_RequestTimeoutBounds pins that a legitimate value is
// kept and an over-large one is capped.
func TestClampConfigBounds_RequestTimeoutBounds(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.RequestTimeout = 10 * time.Second
	clampConfigBounds(cfg)
	if cfg.Resolver.RequestTimeout != 10*time.Second {
		t.Errorf("positive RequestTimeout=10s rewritten to %v", cfg.Resolver.RequestTimeout)
	}

	cfg = &Config{}
	cfg.Resolver.RequestTimeout = clampMaxRequestTimeout * 10
	clampConfigBounds(cfg)
	if cfg.Resolver.RequestTimeout != clampMaxRequestTimeout {
		t.Errorf("oversized RequestTimeout = %v, want ceiling %v",
			cfg.Resolver.RequestTimeout, clampMaxRequestTimeout)
	}
}
