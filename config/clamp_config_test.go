package config

import (
	"testing"
	"time"
)

// TestClampConfigBounds_OverCapValuesGetClamped pins the v0.7.70 gate:
// values above the safe ceilings must be clamped to the ceiling
// rather than passing through unchanged. An operator who edits
// labyrinth.yaml directly (bypassing the setup-wizard validator)
// or who plants pathological values via /api/config/raw PUT would
// otherwise OOM or stall the resolver:
//
//   - resolver.max_depth = 1e9 → a single recursion-failing query
//     iterates the resolver loop 1e9 times.
//   - cache.max_entries = 1e10 → LRU eviction lets cache grow ~10 GB.
//
// The pin sets every clamped field to 10× its cap and asserts each
// is clamped to the ceiling exactly.
func TestClampConfigBounds_OverCapValuesGetClamped(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.MaxDepth = clampMaxResolverDepth * 10
	cfg.Cache.MaxEntries = clampMaxCacheEntries * 10
	cfg.Security.RateLimit.Rate = clampMaxRateLimitRate * 10
	cfg.Security.RateLimit.Burst = clampMaxRateLimitBurst * 10
	cfg.Web.QueryLogBuffer = clampMaxQueryLogBuffer * 10
	cfg.Web.TopClientsLimit = clampMaxTopClientsLimit * 10
	cfg.Web.TopDomainsLimit = clampMaxTopDomainsLimit * 10
	cfg.Server.MaxUDPWorkers = clampMaxUDPWorkers * 10
	cfg.Server.MaxTCPConns = clampMaxTCPConns * 10
	cfg.Resolver.UpstreamRetries = clampMaxUpstreamRetries * 10
	cfg.Resolver.MaxCNAMEDepth = clampMaxCNAMEDepth * 10
	cfg.Server.TCPPipelineMax = clampMaxTCPPipelineMax * 10
	cfg.Resolver.UpstreamTimeout = clampMaxUpstreamTimeout * 10
	cfg.Server.TCPIdleTimeout = clampMaxTCPIdleTimeout * 10
	cfg.Server.TCPTimeout = clampMaxTCPTimeout * 10

	clampConfigBounds(cfg)

	if got := cfg.Resolver.MaxDepth; got != clampMaxResolverDepth {
		t.Errorf("Resolver.MaxDepth = %d, want %d", got, clampMaxResolverDepth)
	}
	if got := cfg.Cache.MaxEntries; got != clampMaxCacheEntries {
		t.Errorf("Cache.MaxEntries = %d, want %d", got, clampMaxCacheEntries)
	}
	if got := cfg.Security.RateLimit.Rate; got != clampMaxRateLimitRate {
		t.Errorf("Security.RateLimit.Rate = %g, want %g", got, clampMaxRateLimitRate)
	}
	if got := cfg.Security.RateLimit.Burst; got != clampMaxRateLimitBurst {
		t.Errorf("Security.RateLimit.Burst = %d, want %d", got, clampMaxRateLimitBurst)
	}
	if got := cfg.Web.QueryLogBuffer; got != clampMaxQueryLogBuffer {
		t.Errorf("Web.QueryLogBuffer = %d, want %d", got, clampMaxQueryLogBuffer)
	}
	if got := cfg.Web.TopClientsLimit; got != clampMaxTopClientsLimit {
		t.Errorf("Web.TopClientsLimit = %d, want %d", got, clampMaxTopClientsLimit)
	}
	if got := cfg.Web.TopDomainsLimit; got != clampMaxTopDomainsLimit {
		t.Errorf("Web.TopDomainsLimit = %d, want %d", got, clampMaxTopDomainsLimit)
	}
	if got := cfg.Server.MaxUDPWorkers; got != clampMaxUDPWorkers {
		t.Errorf("Server.MaxUDPWorkers = %d, want %d", got, clampMaxUDPWorkers)
	}
	if got := cfg.Server.MaxTCPConns; got != clampMaxTCPConns {
		t.Errorf("Server.MaxTCPConns = %d, want %d", got, clampMaxTCPConns)
	}
	if got := cfg.Resolver.UpstreamRetries; got != clampMaxUpstreamRetries {
		t.Errorf("Resolver.UpstreamRetries = %d, want %d", got, clampMaxUpstreamRetries)
	}
	if got := cfg.Resolver.MaxCNAMEDepth; got != clampMaxCNAMEDepth {
		t.Errorf("Resolver.MaxCNAMEDepth = %d, want %d", got, clampMaxCNAMEDepth)
	}
	if got := cfg.Server.TCPPipelineMax; got != clampMaxTCPPipelineMax {
		t.Errorf("Server.TCPPipelineMax = %d, want %d", got, clampMaxTCPPipelineMax)
	}
	if got := cfg.Resolver.UpstreamTimeout; got != clampMaxUpstreamTimeout {
		t.Errorf("Resolver.UpstreamTimeout = %v, want %v", got, clampMaxUpstreamTimeout)
	}
	if got := cfg.Server.TCPIdleTimeout; got != clampMaxTCPIdleTimeout {
		t.Errorf("Server.TCPIdleTimeout = %v, want %v", got, clampMaxTCPIdleTimeout)
	}
	if got := cfg.Server.TCPTimeout; got != clampMaxTCPTimeout {
		t.Errorf("Server.TCPTimeout = %v, want %v", got, clampMaxTCPTimeout)
	}
}

// TestClampConfigBounds_UnderCapValuesPassThrough pins that legitimate
// operator values (well under the clamps) are not modified. The clamp
// must only fire at the very top end; mid-range workloads must boot
// with the operator's chosen settings unchanged.
func TestClampConfigBounds_UnderCapValuesPassThrough(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.MaxDepth = 30
	cfg.Cache.MaxEntries = 100_000
	cfg.Security.RateLimit.Rate = 100.0
	cfg.Security.RateLimit.Burst = 50
	cfg.Web.QueryLogBuffer = 5000
	cfg.Web.TopClientsLimit = 5000
	cfg.Web.TopDomainsLimit = 5000
	cfg.Server.MaxUDPWorkers = 1024
	cfg.Server.MaxTCPConns = 256
	cfg.Resolver.UpstreamRetries = 3
	cfg.Resolver.MaxCNAMEDepth = 16
	cfg.Server.TCPPipelineMax = 100
	cfg.Resolver.UpstreamTimeout = 5 * time.Second
	cfg.Server.TCPIdleTimeout = 5 * time.Minute
	cfg.Server.TCPTimeout = 10 * time.Second

	clampConfigBounds(cfg)

	if cfg.Resolver.MaxDepth != 30 {
		t.Errorf("Resolver.MaxDepth got clamped from 30 to %d", cfg.Resolver.MaxDepth)
	}
	if cfg.Cache.MaxEntries != 100_000 {
		t.Errorf("Cache.MaxEntries got clamped from 100_000 to %d", cfg.Cache.MaxEntries)
	}
	if cfg.Web.QueryLogBuffer != 5000 {
		t.Errorf("Web.QueryLogBuffer got clamped from 5000 to %d", cfg.Web.QueryLogBuffer)
	}
	if cfg.Server.MaxUDPWorkers != 1024 {
		t.Errorf("Server.MaxUDPWorkers got clamped from 1024 to %d", cfg.Server.MaxUDPWorkers)
	}
	if cfg.Server.MaxTCPConns != 256 {
		t.Errorf("Server.MaxTCPConns got clamped from 256 to %d", cfg.Server.MaxTCPConns)
	}
	if cfg.Resolver.UpstreamRetries != 3 {
		t.Errorf("Resolver.UpstreamRetries got clamped from 3 to %d", cfg.Resolver.UpstreamRetries)
	}
	if cfg.Resolver.MaxCNAMEDepth != 16 {
		t.Errorf("Resolver.MaxCNAMEDepth got clamped from 16 to %d", cfg.Resolver.MaxCNAMEDepth)
	}
	if cfg.Server.TCPPipelineMax != 100 {
		t.Errorf("Server.TCPPipelineMax got clamped from 100 to %d", cfg.Server.TCPPipelineMax)
	}
	if cfg.Resolver.UpstreamTimeout != 5*time.Second {
		t.Errorf("Resolver.UpstreamTimeout got clamped from 5s to %v", cfg.Resolver.UpstreamTimeout)
	}
	if cfg.Server.TCPIdleTimeout != 5*time.Minute {
		t.Errorf("Server.TCPIdleTimeout got clamped from 5m to %v", cfg.Server.TCPIdleTimeout)
	}
	if cfg.Server.TCPTimeout != 10*time.Second {
		t.Errorf("Server.TCPTimeout got clamped from 10s to %v", cfg.Server.TCPTimeout)
	}
}

// TestClampConfigBounds_LowerBoundsRescueZeroAndNegative pins the v0.8.18
// gate: the three integer fields that feed `make(chan struct{}, N)` calls
// in the UDP/TCP/DoT server constructors must be rescued to a working
// default when the operator-supplied value is <= 0. Without the rescue,
// `max_udp_workers: -1` panics the resolver at boot, `max_udp_workers: 0`
// creates an unbuffered semaphore that blocks every spawn forever, and
// the operator gets a crash log or a hung process with no helpful
// pointer to "your config value is wrong".
func TestClampConfigBounds_LowerBoundsRescueZeroAndNegative(t *testing.T) {
	for _, sentinel := range []int{0, -1, -100} {
		cfg := &Config{}
		cfg.Server.MaxUDPWorkers = sentinel
		cfg.Server.MaxTCPConns = sentinel
		cfg.Server.TCPPipelineMax = sentinel

		clampConfigBounds(cfg)

		if cfg.Server.MaxUDPWorkers != defaultMaxUDPWorkers {
			t.Errorf("sentinel=%d: MaxUDPWorkers = %d, want default %d",
				sentinel, cfg.Server.MaxUDPWorkers, defaultMaxUDPWorkers)
		}
		if cfg.Server.MaxTCPConns != defaultMaxTCPConns {
			t.Errorf("sentinel=%d: MaxTCPConns = %d, want default %d",
				sentinel, cfg.Server.MaxTCPConns, defaultMaxTCPConns)
		}
		if cfg.Server.TCPPipelineMax != defaultTCPPipelineMax {
			t.Errorf("sentinel=%d: TCPPipelineMax = %d, want default %d",
				sentinel, cfg.Server.TCPPipelineMax, defaultTCPPipelineMax)
		}
	}
}

// TestClampConfigBounds_RateLimitBurstRescuedWhenEnabled pins the
// v0.8.19 floor: when the rate limiter is enabled and Burst <= 0, the
// clamp must rescue it to the default. NewRateLimiter accepts any
// burst, but burst <= 0 makes the token bucket start at -1 tokens and
// the `tb.tokens >= 1` gate never holds — every queried client is
// permanently denied, effectively black-holing the resolver while
// logs say nothing useful.
func TestClampConfigBounds_RateLimitBurstRescuedWhenEnabled(t *testing.T) {
	for _, sentinel := range []int{0, -1, -100} {
		cfg := &Config{}
		cfg.Security.RateLimit.Enabled = true
		cfg.Security.RateLimit.Rate = 100
		cfg.Security.RateLimit.Burst = sentinel

		clampConfigBounds(cfg)

		if cfg.Security.RateLimit.Burst != defaultRateLimitBurst {
			t.Errorf("sentinel=%d: Burst = %d, want default %d",
				sentinel, cfg.Security.RateLimit.Burst, defaultRateLimitBurst)
		}
	}
}

// TestClampConfigBounds_RateLimitBurstUntouchedWhenDisabled pins that
// the rescue only fires when the rate limiter is actually enabled.
// Disabled limiters don't read burst, so an operator using burst=0
// as a "record but don't enforce" marker shouldn't be rewritten.
func TestClampConfigBounds_RateLimitBurstUntouchedWhenDisabled(t *testing.T) {
	cfg := &Config{}
	cfg.Security.RateLimit.Enabled = false
	cfg.Security.RateLimit.Burst = 0

	clampConfigBounds(cfg)

	if cfg.Security.RateLimit.Burst != 0 {
		t.Errorf("disabled rate limiter: Burst = %d, want 0 (unchanged)", cfg.Security.RateLimit.Burst)
	}
}

// TestClampConfigBounds_MaxCNAMEDepthFloor pins the v0.8.20 floor:
// resolver.max_cname_depth <= 0 silently black-holes every CNAME-
// fronted query. The resolver's CNAME loop checks
// `if cnameDepth > r.config.MaxCNAMEDepth` — with the cap at 0 (or
// negative), the very first CNAME chase errors with "CNAME chain
// too long", but apex A/AAAA queries still succeed, so the operator
// sees a half-working resolver with no log line pointing at config.
// Most modern web traffic is CDN-fronted (www.* → CNAME → CDN apex),
// so this is a wholesale outage for a misconfig that looks harmless.
func TestClampConfigBounds_MaxCNAMEDepthFloor(t *testing.T) {
	for _, sentinel := range []int{0, -1, -100} {
		cfg := &Config{}
		cfg.Resolver.MaxCNAMEDepth = sentinel

		clampConfigBounds(cfg)

		if cfg.Resolver.MaxCNAMEDepth != defaultMaxCNAMEDepth {
			t.Errorf("sentinel=%d: MaxCNAMEDepth = %d, want default %d",
				sentinel, cfg.Resolver.MaxCNAMEDepth, defaultMaxCNAMEDepth)
		}
	}
}

// TestClampConfigBounds_MaxCNAMEDepthUntouchedWhenPositive pins that
// the floor does NOT rewrite a legitimately small but positive value
// (e.g. an operator forcing max_cname_depth: 3 to defend against
// CNAME-loop CPU exhaustion in a hostile-zone environment). Only
// the <=0 sentinel triggers the rescue.
func TestClampConfigBounds_MaxCNAMEDepthUntouchedWhenPositive(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.MaxCNAMEDepth = 3

	clampConfigBounds(cfg)

	if cfg.Resolver.MaxCNAMEDepth != 3 {
		t.Errorf("positive MaxCNAMEDepth=3 got rewritten to %d", cfg.Resolver.MaxCNAMEDepth)
	}
}

// TestClampConfigBounds_RunsViaValidate pins that the validate
// entry-point invokes the clamp. A regression that moved validate
// callers off the clamp (or replaced validate with a custom flow
// that skipped clampConfigBounds) would re-open the OOM hole.
func TestClampConfigBounds_RunsViaValidate(t *testing.T) {
	cfg := &Config{}
	cfg.Resolver.MaxDepth = clampMaxResolverDepth * 10
	cfg.Cache.MaxEntries = clampMaxCacheEntries * 10
	cfg.Web.AlertErrorThreshold = 1
	cfg.Web.AlertLatencyMs = 1

	if err := validate(cfg); err != nil {
		t.Fatalf("validate returned unexpected error: %v", err)
	}
	if cfg.Resolver.MaxDepth != clampMaxResolverDepth {
		t.Errorf("validate did not clamp Resolver.MaxDepth: got %d", cfg.Resolver.MaxDepth)
	}
	if cfg.Cache.MaxEntries != clampMaxCacheEntries {
		t.Errorf("validate did not clamp Cache.MaxEntries: got %d", cfg.Cache.MaxEntries)
	}
}
