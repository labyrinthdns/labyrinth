package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RunConfig holds the benchmark configuration.
type RunConfig struct {
	Target    string
	QPS       int
	Duration  time.Duration
	Workers   int
	Domains   []string
	Types     []uint16
	Name      string
	ReportURL string
}

// HistBucket represents a single bucket in a latency histogram.
type HistBucket struct {
	Label string  `json:"label"`
	Count int64   `json:"count"`
	MinMs float64 `json:"min_ms"`
	MaxMs float64 `json:"max_ms"`
}

// RunResult holds the aggregated results of a benchmark run.
type RunResult struct {
	TotalQueries  int64        `json:"total_queries"`
	SuccessCount  int64        `json:"success_count"`
	ErrorCount    int64        `json:"error_count"`
	TimeoutCount  int64        `json:"timeout_count"`
	NXDomainCount int64        `json:"nxdomain_count"`
	ServFailCount int64        `json:"servfail_count"`
	RefusedCount  int64        `json:"refused_count"`
	Duration      float64      `json:"duration_sec"`
	QPS           float64      `json:"qps"`
	AvgLatencyMs  float64      `json:"avg_latency_ms"`
	P50LatencyMs  float64      `json:"p50_latency_ms"`
	P95LatencyMs  float64      `json:"p95_latency_ms"`
	P99LatencyMs  float64      `json:"p99_latency_ms"`
	MinLatencyMs  float64      `json:"min_latency_ms"`
	MaxLatencyMs  float64      `json:"max_latency_ms"`
	LatencyHist   []HistBucket `json:"latency_hist"`
	RunnerName    string       `json:"runner_name"`
	Timestamp     int64        `json:"timestamp"`
}

// liveStats holds atomic counters for real-time progress tracking.
type liveStats struct {
	totalQueries  atomic.Int64
	successCount  atomic.Int64
	errorCount    atomic.Int64
	timeoutCount  atomic.Int64
	nxdomainCount atomic.Int64
	servfailCount atomic.Int64
	refusedCount  atomic.Int64
}

// queryLatency records a single query result.
type queryLatency struct {
	durationNs int64
	success    bool
	timeout    bool
	rcode      uint8
}

// RunBenchmark executes the DNS benchmark according to the given config.
// It returns the final RunResult. If onSnapshot is non-nil, it is called
// approximately once per second with an intermediate result snapshot.
func RunBenchmark(cfg RunConfig, onSnapshot func(RunResult)) RunResult {
	var stats liveStats
	latencyCh := make(chan queryLatency, cfg.Workers*100)

	// Collect all latencies for percentile computation.
	var allLatencies []int64
	var latMu sync.Mutex
	collectorDone := make(chan struct{})

	go func() {
		defer close(collectorDone)
		for l := range latencyCh {
			latMu.Lock()
			allLatencies = append(allLatencies, l.durationNs)
			latMu.Unlock()
		}
	}()

	// Token bucket rate limiter: we distribute tokens across time.
	// interval between tokens
	interval := time.Second / time.Duration(cfg.QPS)

	start := time.Now()
	deadline := start.Add(cfg.Duration)

	// Ticker for sending tokens to workers.
	tokens := make(chan struct{}, cfg.Workers*2)

	// done is closed when the test duration elapses, signaling the snapshot
	// reporter to stop.
	done := make(chan struct{})

	// Token producer goroutine. It closes the tokens channel when the
	// deadline is reached, which causes workers to drain and exit.
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if time.Now().After(deadline) {
					close(tokens)
					return
				}
				select {
				case tokens <- struct{}{}:
				default:
					// Drop token if workers are busy.
				}
			}
		}
	}()

	// Snapshot reporter goroutine.
	var snapshotDone chan struct{}
	if onSnapshot != nil || cfg.ReportURL != "" {
		snapshotDone = make(chan struct{})
		go func() {
			defer close(snapshotDone)
			snapTicker := time.NewTicker(time.Second)
			defer snapTicker.Stop()
			for {
				select {
				case <-snapTicker.C:
					snap := buildSnapshot(&stats, &latMu, allLatencies, cfg.Name, start)
					if onSnapshot != nil {
						onSnapshot(snap)
					}
					if cfg.ReportURL != "" {
						reportToCoordinator(cfg.ReportURL, snap)
					}
				case <-done:
					return
				}
			}
		}()
	}

	// Worker goroutines.
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			worker(workerID, cfg, deadline, tokens, &stats, latencyCh)
		}(i)
	}

	// Wait for all workers to finish (they exit when tokens channel is closed
	// and drained, or when the deadline passes).
	wg.Wait()
	close(done)
	close(latencyCh)
	<-collectorDone

	if snapshotDone != nil {
		<-snapshotDone
	}

	// Build final result.
	elapsed := time.Since(start)
	result := buildFinalResult(&stats, allLatencies, cfg.Name, elapsed)

	// Send final report.
	if cfg.ReportURL != "" {
		reportToCoordinator(cfg.ReportURL, result)
	}

	return result
}

func worker(id int, cfg RunConfig, deadline time.Time, tokens <-chan struct{}, stats *liveStats, latencyCh chan<- queryLatency) {
	// Each worker gets its own UDP connection.
	conn, err := net.DialTimeout("udp", cfg.Target, 2*time.Second)
	if err != nil {
		// Record all remaining as errors.
		for range tokens {
			if time.Now().After(deadline) {
				return
			}
			stats.totalQueries.Add(1)
			stats.errorCount.Add(1)
		}
		return
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
	recvBuf := make([]byte, 4096)
	sendBuf := make([]byte, 512)

	for range tokens {
		if time.Now().After(deadline) {
			return
		}

		domain := cfg.Domains[rng.Intn(len(cfg.Domains))]
		qtype := cfg.Types[rng.Intn(len(cfg.Types))]

		// Build DNS query using our dns package.
		msg := &dns.Message{
			Header: dns.Header{
				ID:    uint16(rng.Intn(65536)),
				Flags: dns.NewFlagBuilder().SetRD(true).Build(),
			},
			Questions: []dns.Question{
				{Name: domain, Type: qtype, Class: dns.ClassIN},
			},
		}

		packed, packErr := dns.Pack(msg, sendBuf)
		if packErr != nil {
			stats.totalQueries.Add(1)
			stats.errorCount.Add(1)
			continue
		}

		// Set write/read deadline.
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		queryStart := time.Now()
		_, writeErr := conn.Write(packed)
		if writeErr != nil {
			stats.totalQueries.Add(1)
			stats.errorCount.Add(1)
			continue
		}

		n, readErr := conn.Read(recvBuf)
		elapsed := time.Since(queryStart)

		stats.totalQueries.Add(1)

		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				stats.timeoutCount.Add(1)
				stats.errorCount.Add(1)
				latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), timeout: true}
			} else {
				stats.errorCount.Add(1)
				latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds()}
			}
			continue
		}

		// Parse response to get RCODE.
		resp, parseErr := dns.Unpack(recvBuf[:n])
		if parseErr != nil {
			stats.errorCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds()}
			continue
		}

		rcode := resp.Header.RCODE()
		switch rcode {
		case dns.RCodeNoError:
			stats.successCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), success: true, rcode: rcode}
		case dns.RCodeNXDomain:
			// NXDOMAIN is a valid response (domain doesn't exist), count as success
			stats.successCount.Add(1)
			stats.nxdomainCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), success: true, rcode: rcode}
		case dns.RCodeServFail:
			stats.servfailCount.Add(1)
			stats.errorCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), rcode: rcode}
		case dns.RCodeRefused:
			stats.refusedCount.Add(1)
			stats.errorCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), rcode: rcode}
		default:
			stats.errorCount.Add(1)
			latencyCh <- queryLatency{durationNs: elapsed.Nanoseconds(), rcode: rcode}
		}
	}
}

func buildSnapshot(stats *liveStats, latMu *sync.Mutex, latencies []int64, name string, start time.Time) RunResult {
	total := stats.totalQueries.Load()
	elapsed := time.Since(start)

	latMu.Lock()
	latCopy := make([]int64, len(latencies))
	copy(latCopy, latencies)
	latMu.Unlock()

	result := RunResult{
		TotalQueries:  total,
		SuccessCount:  stats.successCount.Load(),
		ErrorCount:    stats.errorCount.Load(),
		TimeoutCount:  stats.timeoutCount.Load(),
		NXDomainCount: stats.nxdomainCount.Load(),
		ServFailCount: stats.servfailCount.Load(),
		RefusedCount:  stats.refusedCount.Load(),
		Duration:      elapsed.Seconds(),
		RunnerName:    name,
		Timestamp:     time.Now().Unix(),
	}

	if elapsed.Seconds() > 0 {
		result.QPS = float64(total) / elapsed.Seconds()
	}

	computeLatencyStats(&result, latCopy)
	return result
}

func buildFinalResult(stats *liveStats, latencies []int64, name string, elapsed time.Duration) RunResult {
	total := stats.totalQueries.Load()

	result := RunResult{
		TotalQueries:  total,
		SuccessCount:  stats.successCount.Load(),
		ErrorCount:    stats.errorCount.Load(),
		TimeoutCount:  stats.timeoutCount.Load(),
		NXDomainCount: stats.nxdomainCount.Load(),
		ServFailCount: stats.servfailCount.Load(),
		RefusedCount:  stats.refusedCount.Load(),
		Duration:      elapsed.Seconds(),
		RunnerName:    name,
		Timestamp:     time.Now().Unix(),
	}

	if elapsed.Seconds() > 0 {
		result.QPS = float64(total) / elapsed.Seconds()
	}

	computeLatencyStats(&result, latencies)
	return result
}

func computeLatencyStats(result *RunResult, latencies []int64) {
	if len(latencies) == 0 {
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	var sum int64
	for _, l := range latencies {
		sum += l
	}

	nsToMs := func(ns int64) float64 {
		return float64(ns) / 1e6
	}

	result.AvgLatencyMs = nsToMs(sum / int64(len(latencies)))
	result.MinLatencyMs = nsToMs(latencies[0])
	result.MaxLatencyMs = nsToMs(latencies[len(latencies)-1])
	result.P50LatencyMs = nsToMs(percentile(latencies, 50))
	result.P95LatencyMs = nsToMs(percentile(latencies, 95))
	result.P99LatencyMs = nsToMs(percentile(latencies, 99))

	result.LatencyHist = buildHistogram(latencies)
}

func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(p)/100.0*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func buildHistogram(latencies []int64) []HistBucket {
	// Define histogram buckets in milliseconds.
	boundaries := []float64{0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000}
	buckets := make([]HistBucket, len(boundaries)+1)

	for i, b := range boundaries {
		if i == 0 {
			buckets[i] = HistBucket{Label: fmt.Sprintf("<%.0fms", b), MinMs: 0, MaxMs: b}
		} else {
			buckets[i] = HistBucket{Label: fmt.Sprintf("%.0f-%.0fms", boundaries[i-1], b), MinMs: boundaries[i-1], MaxMs: b}
		}
	}
	lastBound := boundaries[len(boundaries)-1]
	buckets[len(boundaries)] = HistBucket{Label: fmt.Sprintf(">%.0fms", lastBound), MinMs: lastBound, MaxMs: math.MaxFloat64}

	for _, ns := range latencies {
		ms := float64(ns) / 1e6
		placed := false
		for i := range buckets {
			if ms < buckets[i].MaxMs || (i == len(buckets)-1) {
				buckets[i].Count++
				placed = true
				break
			}
		}
		if !placed {
			buckets[len(buckets)-1].Count++
		}
	}

	return buckets
}

func reportToCoordinator(url string, result RunResult) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url+"/api/report", "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	resp.Body.Close()
}

// PrintQuickResult formats and prints benchmark results to stdout.
func PrintQuickResult(result RunResult) {
	successRate := float64(0)
	errorRate := float64(0)
	if result.TotalQueries > 0 {
		successRate = float64(result.SuccessCount) / float64(result.TotalQueries) * 100
		errorRate = float64(result.ErrorCount) / float64(result.TotalQueries) * 100
	}

	fmt.Println()
	fmt.Println("Labyrinth DNS Benchmark Results")
	fmt.Println("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
	fmt.Printf("Duration:   %.1fs\n", result.Duration)
	fmt.Printf("Runner:     %s\n", result.RunnerName)
	fmt.Println()
	fmt.Println("Results:")
	fmt.Printf("  Total Queries:  %s\n", formatInt(result.TotalQueries))
	fmt.Printf("  Successful:     %s (%.1f%%)\n", formatInt(result.SuccessCount), successRate)
	fmt.Printf("  Errors:         %s (%.1f%%)\n", formatInt(result.ErrorCount), errorRate)
	fmt.Printf("    Timeout:      %s\n", formatInt(result.TimeoutCount))
	fmt.Printf("    SERVFAIL:     %s\n", formatInt(result.ServFailCount))
	fmt.Printf("    REFUSED:      %s\n", formatInt(result.RefusedCount))
	fmt.Printf("    NXDOMAIN:     %s\n", formatInt(result.NXDomainCount))
	fmt.Println()
	fmt.Println("Latency:")
	fmt.Printf("  Avg:    %.1fms\n", result.AvgLatencyMs)
	fmt.Printf("  P50:    %.1fms\n", result.P50LatencyMs)
	fmt.Printf("  P95:    %.1fms\n", result.P95LatencyMs)
	fmt.Printf("  P99:    %.1fms\n", result.P99LatencyMs)
	fmt.Printf("  Min:    %.1fms\n", result.MinLatencyMs)
	fmt.Printf("  Max:    %.1fms\n", result.MaxLatencyMs)
	fmt.Println()
	fmt.Println("Throughput:")
	fmt.Printf("  Achieved QPS: %.1f\n", result.QPS)
	fmt.Println()
}

func formatInt(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	// Insert commas.
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
