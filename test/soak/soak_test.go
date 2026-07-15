// Package soak provides a long-running integration test that exercises the
// full resolver stack (UDP listener → cache → upstream resolution → DNSSEC
// validation) under sustained load. It monitors goroutine count, memory
// usage, and response latency over time, failing if any metric degrades
// beyond the configured threshold.
//
// Usage:
//
//	go test ./test/soak/ -run TestSoak -timeout 24h -v
//
// Duration defaults to 5 minutes and can be overridden via the
// LABYRINTH_SOAK_DURATION environment variable (e.g. "72h", "30m").
// Requires outbound network access to root DNS servers.
package soak

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/security"
	dnsServer "github.com/labyrinthdns/labyrinth/server"

	"log/slog"
)

// builtinDomains is a subset of popular domains used as query targets.
// Mirrors the list in cmd/labyrinth-bench/domains.go.
var builtinDomains = []string{
	"google.com", "facebook.com", "youtube.com", "amazon.com",
	"github.com", "stackoverflow.com", "wikipedia.org", "golang.org",
	"cloudflare.com", "microsoft.com", "apple.com", "netflix.com",
	"twitter.com", "reddit.com", "linkedin.com", "zoom.us",
	"dropbox.com", "spotify.com", "gitlab.com", "docker.com",
}

// queryTypes cycles through these DNS types to vary cache behaviour.
var queryTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS, dns.TypeTXT}

type soakSnapshot struct {
	elapsed    time.Duration
	goroutines int
	allocMB    float64
	sysMB      float64
	totalOps   int64
	latencyP50 time.Duration
	latencyP95 time.Duration
	latencyP99 time.Duration
	failures   int
}

func TestSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	duration := soakDuration(t)
	t.Logf("soak duration: %s (set LABYRINTH_SOAK_DURATION to override)", duration)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	// ── setup ──────────────────────────────────────────────────────────
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := metrics.NewMetrics()
	c := cache.NewCache(100000, 5, 86400, 3600, m)

	rl := security.NewRateLimiter(100000, 200000)

	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        30,
		MaxCNAMEDepth:   10,
		UpstreamTimeout: 5 * time.Second,
		UpstreamRetries: 2,
		QMinEnabled:     true,
		PreferIPv4:      true,
	}, m, logger)

	// Prime root hints so the resolver can resolve real domains.
	if err := res.PrimeRootHints(); err != nil {
		t.Skipf("skipping: root hint priming failed (no network?): %v", err)
	}

	// Pick a random ephemeral port, release it, then start the server.
	// The brief release creates a tiny race window but it's acceptable
	// for a test harness — the kernel rarely recycles ports instantly.
	tempConn, tempErr := net.ListenPacket("udp", "127.0.0.1:0")
	if tempErr != nil {
		t.Fatalf("failed to pick test port: %v", tempErr)
	}
	addr := tempConn.LocalAddr().String()
	tempConn.Close()

	handler := &testHandler{resolver: res, cache: c, limiter: rl, logger: logger}
	srv, err := dnsServer.NewUDPServer(addr, handler, 100, logger)
	if err != nil {
		t.Fatalf("failed to start UDP server: %v", err)
	}

	go func() {
		if err := srv.Serve(ctx); err != nil {
			t.Logf("server exited: %v", err)
		}
	}()

	t.Logf("soak server listening on %s", addr)

	// ── warmup ─────────────────────────────────────────────────────────
	t.Log("warming up resolver (60s)...")
	warmupCtx, warmupCancel := context.WithTimeout(ctx, 60*time.Second)
	sendQueries(t, warmupCtx, addr, 50, 100*time.Millisecond)
	warmupCancel()
	t.Log("warmup complete")

	// ── main loop ──────────────────────────────────────────────────────
	snapInterval := 30 * time.Second
	if duration < 5*time.Minute {
		snapInterval = 10 * time.Second
	}

	ticker := time.NewTicker(snapInterval)
	defer ticker.Stop()

	var (
		snapshots  []soakSnapshot
		mu         sync.Mutex
		totalOps   int64
		totalFails int64
		latencies  []time.Duration
		latMu      sync.Mutex
	)

	// Worker: send queries at a steady rate
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			start := time.Now()
			err := sendOneQuery(addr, randomDomain(), randomType())
			elapsed := time.Since(start)

			latMu.Lock()
			latencies = append(latencies, elapsed)
			if len(latencies) > 10000 {
				latencies = latencies[len(latencies)-5000:]
			}
			latMu.Unlock()

			mu.Lock()
			totalOps++
			if err != nil {
				totalFails++
			}
			mu.Unlock()

			// Brief sleep to stay under rate limits
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Sampling loop
	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
		}

		var mstats runtime.MemStats
		runtime.ReadMemStats(&mstats)

		mu.Lock()
		ops := totalOps
		fails := totalFails
		mu.Unlock()

		latMu.Lock()
		p50, p95, p99 := latencyPercentiles(latencies)
		latMu.Unlock()

		deadline, _ := ctx.Deadline()
		snap := soakSnapshot{
			elapsed:    duration - time.Until(deadline),
			goroutines: runtime.NumGoroutine(),
			allocMB:    float64(mstats.Alloc) / 1024 / 1024,
			sysMB:      float64(mstats.Sys) / 1024 / 1024,
			totalOps:   ops,
			latencyP50: p50,
			latencyP95: p95,
			latencyP99: p99,
			failures:   int(fails),
		}

		mu.Lock()
		snapshots = append(snapshots, snap)
		mu.Unlock()

		t.Logf("[%s] goroutines=%d alloc=%.1fMB sys=%.1fMB ops=%d p50=%v p95=%v p99=%v fails=%d",
			snap.elapsed.Round(time.Second), snap.goroutines, snap.allocMB, snap.sysMB,
			snap.totalOps, snap.latencyP50, snap.latencyP95, snap.latencyP99, snap.failures)
	}

done:
	t.Log("soak complete, analysing results...")
	analyzeSoak(t, snapshots)
}

// ── helpers ──────────────────────────────────────────────────────────

func soakDuration(t *testing.T) time.Duration {
	if d := os.Getenv("LABYRINTH_SOAK_DURATION"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err == nil {
			return parsed
		}
		t.Logf("invalid LABYRINTH_SOAK_DURATION %q: %v; using default", d, err)
	}
	return 5 * time.Minute
}

func randomDomain() string {
	return builtinDomains[rand.IntN(len(builtinDomains))]
}

func randomType() uint16 {
	return queryTypes[rand.IntN(len(queryTypes))]
}

// sendOneQuery sends a single DNS query over UDP and waits for a response.
func sendOneQuery(addr, name string, qtype uint16) error {
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	msg := &dns.Message{
		Header: dns.Header{
			ID:      uint16(rand.Uint32()),
			Flags:   dns.NewFlagBuilder().SetRD(true).Build(),
			QDCount: 1,
		},
		Questions: []dns.Question{{
			Name:  name + ".",
			Type:  qtype,
			Class: dns.ClassIN,
		}},
	}

	buf := make([]byte, 512)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write(packed); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	if _, err := dns.Unpack(respBuf[:n]); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	return nil
}

// sendQueries sends count queries in rapid succession.
func sendQueries(t *testing.T, ctx context.Context, addr string, count int, delay time.Duration) {
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := sendOneQuery(addr, randomDomain(), randomType()); err != nil {
			t.Logf("warmup query %d failed: %v", i, err)
		}
		time.Sleep(delay)
	}
}

func latencyPercentiles(latencies []time.Duration) (p50, p95, p99 time.Duration) {
	if len(latencies) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	// Simple selection-sort for small slices; production tools use
	// t-digest, but here the slice is bounded to 5000 entries and
	// sorting once per 30s tick is negligible.
	for i := 0; i < len(sorted); i++ {
		best := i
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[best] {
				best = j
			}
		}
		sorted[i], sorted[best] = sorted[best], sorted[i]
	}

	n := len(sorted)
	p50 = sorted[int(math.Ceil(float64(n)*0.50))-1]
	p95 = sorted[int(math.Ceil(float64(n)*0.95))-1]
	p99 = sorted[int(math.Ceil(float64(n)*0.99))-1]
	return
}

func analyzeSoak(t *testing.T, snapshots []soakSnapshot) {
	if len(snapshots) < 2 {
		t.Log("too few snapshots to analyse (soak may have been too short)")
		return
	}

	first := snapshots[0]
	last := snapshots[len(snapshots)-1]

	t.Logf("=== Soak Results ===")
	t.Logf("  Duration:     %s", last.elapsed.Round(time.Second))
	t.Logf("  Total ops:    %d", last.totalOps-first.totalOps)
	t.Logf("  Failures:     %d", last.failures-first.failures)
	t.Logf("  Goroutines:   %d → %d (%.1f%%)", first.goroutines, last.goroutines,
		pctChange(first.goroutines, last.goroutines))
	t.Logf("  Alloc memory: %.1fMB → %.1fMB (%.1f%%)", first.allocMB, last.allocMB,
		pctChangeI(first.allocMB, last.allocMB))
	t.Logf("  Sys memory:   %.1fMB → %.1fMB (%.1f%%)", first.sysMB, last.sysMB,
		pctChangeI(first.sysMB, last.sysMB))
	t.Logf("  Latency p50:  %v → %v", first.latencyP50, last.latencyP50)
	t.Logf("  Latency p95:  %v → %v", first.latencyP95, last.latencyP95)
	t.Logf("  Latency p99:  %v → %v", first.latencyP99, last.latencyP99)

	// Mid-point comparison: compare the first half to the second half.
	// This catches gradual degradation that start-to-end might hide
	// (e.g. memory that grows then plateaus).
	secondHalf := snapshots[len(snapshots)/2:]
	firstHalf := snapshots[:len(snapshots)/2]

	avgGoroutines := func(ss []soakSnapshot) float64 {
		var sum float64
		for _, s := range ss {
			sum += float64(s.goroutines)
		}
		return sum / float64(len(ss))
	}
	avgAlloc := func(ss []soakSnapshot) float64 {
		var sum float64
		for _, s := range ss {
			sum += s.allocMB
		}
		return sum / float64(len(ss))
	}
	avgLatency := func(ss []soakSnapshot) float64 {
		var sum float64
		for _, s := range ss {
			sum += float64(s.latencyP95)
		}
		return sum / float64(len(ss))
	}

	firstAvgG := avgGoroutines(firstHalf)
	secondAvgG := avgGoroutines(secondHalf)
	firstAvgM := avgAlloc(firstHalf)
	secondAvgM := avgAlloc(secondHalf)
	firstAvgL := avgLatency(firstHalf)
	secondAvgL := avgLatency(secondHalf)

	t.Logf("  Avg goroutines: %.0f (first half) → %.0f (second half) (%.1f%%)",
		firstAvgG, secondAvgG, pctChangeI(firstAvgG, secondAvgG))
	t.Logf("  Avg alloc MB:   %.1f (first half) → %.1f (second half) (%.1f%%)",
		firstAvgM, secondAvgM, pctChangeI(firstAvgM, secondAvgM))
	t.Logf("  Avg p95 latency: %.0fms (first half) → %.0fms (second half) (%.1f%%)",
		firstAvgL, secondAvgL, pctChangeI(firstAvgL, secondAvgL))

	// ── Threshold checks ──
	failures := 0

	// Goroutine leak: >10% growth between halves.
	if secondAvgG > firstAvgG*1.10 && firstAvgG > 10 {
		t.Errorf("GOROUTINE LEAK: goroutines grew %.1f%% (%.0f → %.0f)",
			pctChangeI(firstAvgG, secondAvgG), firstAvgG, secondAvgG)
		failures++
	}

	// Memory leak: >10% growth between halves.
	if secondAvgM > firstAvgM*1.10 && firstAvgM > 1 {
		t.Errorf("MEMORY LEAK: alloc grew %.1f%% (%.1fMB → %.1fMB)",
			pctChangeI(firstAvgM, secondAvgM), firstAvgM, secondAvgM)
		failures++
	}

	// Latency degradation: >3x increase in p95 between halves.
	if secondAvgL > firstAvgL*3 && firstAvgL > 10 {
		t.Errorf("LATENCY DEGRADATION: p95 grew %.1f%% (%.0fms → %.0fms)",
			pctChangeI(firstAvgL, secondAvgL), firstAvgL, secondAvgL)
		failures++
	}

	// High failure rate: >5% of total queries.
	totalOps := last.totalOps - first.totalOps
	totalFails := last.failures - first.failures
	if totalOps > 100 && float64(totalFails)/float64(totalOps) > 0.05 {
		t.Errorf("HIGH FAILURE RATE: %.1f%% (%d/%d)",
			float64(totalFails)/float64(totalOps)*100, totalFails, totalOps)
		failures++
	}

	if failures == 0 {
		t.Log("✅ All soak thresholds passed")
	}

	// Run GC and force a final memory snapshot for the record.
	runtime.GC()
	debug.FreeOSMemory()
	var finalMS runtime.MemStats
	runtime.ReadMemStats(&finalMS)
	t.Logf("  Final alloc (after GC): %.1fMB", float64(finalMS.Alloc)/1024/1024)
}

func pctChange(oldVal, newVal int) float64 {
	if oldVal == 0 {
		return 0
	}
	return float64(newVal-oldVal) / float64(oldVal) * 100
}

func pctChangeI(oldVal, newVal float64) float64 {
	if oldVal == 0 {
		return 0
	}
	return (newVal - oldVal) / oldVal * 100
}

// testHandler is a minimal server.Handler that resolves queries through the
// full resolver stack without rate limiting or ACL checks.
type testHandler struct {
	resolver *resolver.Resolver
	cache    *cache.Cache
	limiter  *security.RateLimiter
	logger   *slog.Logger
}

func (h *testHandler) Handle(query []byte, clientAddr net.Addr) ([]byte, error) {
	msg, err := dns.Unpack(query)
	if err != nil {
		return nil, err
	}

	if len(msg.Questions) == 0 {
		return nil, fmt.Errorf("no questions")
	}

	q := msg.Questions[0]
	result, resErr := h.resolver.Resolve(q.Name, q.Type, q.Class)
	if resErr != nil {
		return nil, resErr
	}
	if result.Error != nil {
		return nil, result.Error
	}

	// Build a response message
	resp := &dns.Message{
		Header: dns.Header{
			ID:      msg.Header.ID,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetRD(true).SetRA(true).SetRCODE(result.RCODE).Build(),
			QDCount: 1,
		},
		Questions:  []dns.Question{q},
		Answers:    result.Answers,
		Authority:  result.Authority,
		Additional: result.Additional,
	}

	buf := make([]byte, 4096)
	packed, err := dns.Pack(resp, buf)
	if err != nil {
		return nil, err
	}

	return packed, nil
}
