package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func withArgs(args []string, fn func() int) int {
	old := os.Args
	os.Args = args
	defer func() { os.Args = old }()
	return fn()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	_ = w.Close()
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CMD_MAIN_HELPER") != "1" {
		t.Skip("helper process")
	}

	switch os.Getenv("CMD_MAIN_MODE") {
	case "ok":
		os.Args = []string{"labyrinth-bench", "help"}
	case "fail":
		os.Args = []string{"labyrinth-bench", "unknown"}
	default:
		os.Args = []string{"labyrinth-bench"}
	}
	main()
}

func TestMain_ExitCodes(t *testing.T) {
	runMain := func(mode string) error {
		cmd := exec.Command(os.Args[0], "-test.run=TestMainHelperProcess")
		cmd.Env = append(os.Environ(), "GO_WANT_CMD_MAIN_HELPER=1", "CMD_MAIN_MODE="+mode)
		return cmd.Run()
	}

	if err := runMain("ok"); err != nil {
		t.Fatalf("expected main helper success, got error: %v", err)
	}
	if err := runMain("fail"); err == nil {
		t.Fatalf("expected main helper to exit non-zero")
	}
}

func TestRun_CommandDispatch(t *testing.T) {
	if got := withArgs([]string{"labyrinth-bench"}, run); got != 1 {
		t.Fatalf("run() no args = %d, want 1", got)
	}
	if got := withArgs([]string{"labyrinth-bench", "help"}, run); got != 0 {
		t.Fatalf("run() help = %d, want 0", got)
	}
	if got := withArgs([]string{
		"labyrinth-bench", "quick",
		"-target", "127.0.0.1",
		"-qps", "1",
		"-duration", "10ms",
		"-workers", "1",
		"-domains", "builtin",
		"-types", "A",
	}, run); got != 0 {
		t.Fatalf("run() quick = %d, want 0", got)
	}
	if got := withArgs([]string{
		"labyrinth-bench", "run",
		"-target", "127.0.0.1",
		"-qps", "1",
		"-duration", "10ms",
		"-workers", "1",
		"-domains", "builtin",
		"-types", "A",
	}, run); got != 0 {
		t.Fatalf("run() run = %d, want 0", got)
	}
	if got := withArgs([]string{"labyrinth-bench", "serve", "-addr", "127.0.0.1:bad"}, run); got != 1 {
		t.Fatalf("run() serve invalid addr = %d, want 1", got)
	}
	if got := withArgs([]string{"labyrinth-bench", "unknown"}, run); got != 1 {
		t.Fatalf("run() unknown = %d, want 1", got)
	}
}

func TestLoadDomainsAndParseTypes(t *testing.T) {
	domains, err := loadDomains("builtin")
	if err != nil {
		t.Fatalf("loadDomains builtin: %v", err)
	}
	if len(domains) == 0 {
		t.Fatalf("expected builtin domains")
	}

	file := filepath.Join(t.TempDir(), "domains.txt")
	err = os.WriteFile(file, []byte("\n# comment\nexample.com\n\nwww.example.org\n"), 0o644)
	if err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	domains, err = loadDomains(file)
	if err != nil {
		t.Fatalf("loadDomains file: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# only comments"), 0o644); err != nil {
		t.Fatalf("os.WriteFile empty: %v", err)
	}
	if _, err := loadDomains(empty); err == nil {
		t.Fatalf("expected error for empty domain file")
	}

	types, err := parseTypes("A, aaaa ,mx")
	if err != nil {
		t.Fatalf("parseTypes: %v", err)
	}
	if len(types) != 3 {
		t.Fatalf("expected 3 parsed types, got %d", len(types))
	}
	if _, err := parseTypes("BOGUS"); err == nil {
		t.Fatalf("expected error for unknown type")
	}
	if _, err := parseTypes(",,"); err == nil {
		t.Fatalf("expected error for empty types")
	}
}

func TestBuildRunConfig(t *testing.T) {
	cfg, err := buildRunConfig("127.0.0.1:53", 10, "100ms", 1, "builtin", "A", "", "")
	if err != nil {
		t.Fatalf("buildRunConfig: %v", err)
	}
	if cfg.Name == "" {
		t.Fatalf("expected generated runner name")
	}
	if len(cfg.Domains) == 0 || len(cfg.Types) == 0 {
		t.Fatalf("expected domains/types to be populated")
	}
	if _, err := buildRunConfig("127.0.0.1:53", 10, "not-duration", 1, "builtin", "A", "", "n"); err == nil {
		t.Fatalf("expected invalid duration error")
	}
	if _, err := buildRunConfig("127.0.0.1:53", 10, "1s", 1, "missing-file", "A", "", "n"); err == nil {
		t.Fatalf("expected domain source error")
	}
}

func TestCmdRunQuickServe(t *testing.T) {
	// Invalid listen address should fail fast and cover cmdServe error path.
	if err := cmdServe([]string{"-addr", "127.0.0.1:bad"}); err == nil {
		t.Fatalf("expected cmdServe error for invalid addr")
	}

	quickOut := captureStdout(t, func() {
		err := cmdQuick([]string{
			"-target", "127.0.0.1",
			"-qps", "20",
			"-duration", "50ms",
			"-workers", "1",
			"-domains", "builtin",
			"-types", "A",
			"-name", "quick-runner",
		})
		if err != nil {
			t.Fatalf("cmdQuick: %v", err)
		}
	})
	if !strings.Contains(quickOut, "Quick Mode") {
		t.Fatalf("expected quick mode output, got: %q", quickOut)
	}

	recv := make(chan RunResult, 16)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/report" {
			http.NotFound(w, r)
			return
		}
		var rr RunResult
		_ = json.NewDecoder(r.Body).Decode(&rr)
		select {
		case recv <- rr:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := cmdRun([]string{
		"-target", "127.0.0.1",
		"-qps", "20",
		"-duration", "60ms",
		"-workers", "1",
		"-domains", "builtin",
		"-types", "A",
		"-name", "reporting-runner",
		"-report", ts.URL,
	}); err != nil {
		t.Fatalf("cmdRun: %v", err)
	}

	select {
	case <-recv:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected at least one report to coordinator")
	}
}

func TestCoordinatorHandlersAndAggregation(t *testing.T) {
	c := NewCoordinator()
	if c == nil || c.runners == nil {
		t.Fatalf("NewCoordinator should initialize runners map")
	}
	if got := resolveAddr(":8080"); got != "localhost:8080" {
		t.Fatalf("resolveAddr unexpected: %q", got)
	}
	if got := resolveAddr("127.0.0.1:8080"); got != "127.0.0.1:8080" {
		t.Fatalf("resolveAddr pass-through unexpected: %q", got)
	}

	// Method not allowed.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	c.handleReport(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}

	// Invalid JSON.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/report", strings.NewReader("not-json"))
	c.handleReport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Valid report.
	report := RunResult{
		RunnerName:   "runner-1",
		TotalQueries: 10,
		SuccessCount: 9,
		QPS:          15,
		AvgLatencyMs: 5,
		P50LatencyMs: 4,
		P95LatencyMs: 6,
		P99LatencyMs: 7,
	}
	body, _ := json.Marshal(report)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/report", bytes.NewReader(body))
	c.handleReport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(c.history) == 0 {
		t.Fatalf("expected aggregated history entry")
	}

	// Status endpoint.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	c.handleStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}

	// Timeseries endpoint.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/timeseries", nil)
	c.handleTimeseries(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("timeseries: expected 200, got %d", w.Code)
	}

	// Dashboard endpoint.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	c.handleDashboard(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard: expected 200, got %d", w.Code)
	}

	// Aggregation branch where all runners are stale.
	c.mu.Lock()
	c.runners["stale"] = &RunnerState{
		Name:     "stale",
		LastSeen: time.Now().Add(-11 * time.Second),
		LastResult: RunResult{
			TotalQueries: 100,
			SuccessCount: 100,
			QPS:          100,
		},
	}
	snap := c.buildAggregatedSnapshotLocked()
	c.mu.Unlock()
	if snap.RunnerCount != 1 {
		// runner-1 is active, stale runner is ignored
		t.Fatalf("unexpected active runner count: %d", snap.RunnerCount)
	}
}

func TestRunBenchmarkAndHelpers(t *testing.T) {
	cfg := RunConfig{
		Target:   "127.0.0.1",
		QPS:      100,
		Duration: 40 * time.Millisecond,
		Workers:  1,
		Domains:  []string{"example.com"},
		Types:    []uint16{dns.TypeA},
		Name:     "bench",
	}
	result := RunBenchmark(cfg, nil)
	if result.Duration <= 0 {
		t.Fatalf("expected positive duration")
	}

	var stats liveStats
	stats.totalQueries.Store(10)
	stats.successCount.Store(8)
	stats.errorCount.Store(2)
	stats.timeoutCount.Store(1)
	stats.nxdomainCount.Store(1)
	stats.servfailCount.Store(1)
	stats.refusedCount.Store(0)

	lat := []int64{1_000_000, 2_000_000, 3_000_000}
	var mu sync.Mutex
	snap := buildSnapshot(&stats, &mu, lat, "runner", time.Now().Add(-time.Second))
	if snap.TotalQueries != 10 {
		t.Fatalf("unexpected snapshot total: %d", snap.TotalQueries)
	}
	final := buildFinalResult(&stats, lat, "runner", time.Second)
	if final.P95LatencyMs == 0 {
		t.Fatalf("expected computed latency percentiles")
	}

	if got := percentile([]int64{1, 2, 3}, 95); got != 3 {
		t.Fatalf("unexpected percentile result: %d", got)
	}
	hist := buildHistogram([]int64{100_000, 900_000, 2_100_000})
	if len(hist) == 0 {
		t.Fatalf("expected histogram buckets")
	}
	if got := formatInt(1234567); got != "1,234,567" {
		t.Fatalf("unexpected formatInt output: %q", got)
	}

	out := captureStdout(t, func() { PrintQuickResult(final) })
	if !strings.Contains(out, "Benchmark Results") {
		t.Fatalf("expected quick result output")
	}

	// reportToCoordinator should tolerate valid endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	reportToCoordinator(ts.URL, final)
	reportToCoordinator("://bad-url", final)
}

func TestWorker_DialFailureCountsErrors(t *testing.T) {
	cfg := RunConfig{
		Target:  "127.0.0.1",
		Domains: []string{"example.com"},
		Types:   []uint16{dns.TypeA},
	}
	tokens := make(chan struct{}, 2)
	tokens <- struct{}{}
	tokens <- struct{}{}
	close(tokens)

	var stats liveStats
	latCh := make(chan queryLatency, 10)
	worker(0, cfg, time.Now().Add(time.Second), tokens, &stats, latCh)

	if stats.totalQueries.Load() == 0 || stats.errorCount.Load() == 0 {
		t.Fatalf("expected failed dials to increment counters")
	}
}

func startUDPResponder(t *testing.T, handler func(*dns.Message) []byte) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	quit := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-quit:
						return
					default:
					}
					continue
				}
				return
			}
			msg, err := dns.Unpack(buf[:n])
			if err != nil {
				continue
			}
			resp := handler(msg)
			if len(resp) == 0 {
				continue
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	stop := func() {
		close(quit)
		_ = pc.Close()
	}
	return pc.LocalAddr().String(), stop
}

func buildDNSResponse(t *testing.T, req *dns.Message, rcode uint8) []byte {
	t.Helper()
	resp := &dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   dns.NewFlagBuilder().SetQR(true).SetRA(true).SetRD(req.Header.RD()).SetRCODE(rcode).Build(),
			QDCount: uint16(len(req.Questions)),
		},
		Questions: req.Questions,
	}
	buf := make([]byte, 512)
	out, err := dns.Pack(resp, buf)
	if err != nil {
		t.Fatalf("dns.Pack response: %v", err)
	}
	return out
}

func runWorkerOnce(target string) *liveStats {
	cfg := RunConfig{
		Target:  target,
		Domains: []string{"example.com"},
		Types:   []uint16{dns.TypeA},
	}
	tokens := make(chan struct{}, 1)
	tokens <- struct{}{}
	close(tokens)
	stats := &liveStats{}
	latCh := make(chan queryLatency, 4)
	worker(0, cfg, time.Now().Add(time.Second), tokens, stats, latCh)
	return stats
}

func TestWorker_ResponseRCodes(t *testing.T) {
	tests := []struct {
		name          string
		rcode         uint8
		wantSuccess   int64
		wantError     int64
		wantNXDomain  int64
		wantServFail  int64
		wantRefused   int64
		malformedResp bool
	}{
		{name: "noerror", rcode: dns.RCodeNoError, wantSuccess: 1},
		{name: "nxdomain", rcode: dns.RCodeNXDomain, wantSuccess: 1, wantNXDomain: 1},
		{name: "servfail", rcode: dns.RCodeServFail, wantError: 1, wantServFail: 1},
		{name: "refused", rcode: dns.RCodeRefused, wantError: 1, wantRefused: 1},
		{name: "malformed", malformedResp: true, wantError: 1},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			addr, stop := startUDPResponder(t, func(req *dns.Message) []byte {
				if tc.malformedResp {
					return []byte{0x01, 0x02, 0x03}
				}
				return buildDNSResponse(t, req, tc.rcode)
			})
			defer stop()

			stats := runWorkerOnce(addr)
			if got := stats.totalQueries.Load(); got != 1 {
				t.Fatalf("totalQueries=%d want 1", got)
			}
			if got := stats.successCount.Load(); got != tc.wantSuccess {
				t.Fatalf("successCount=%d want %d", got, tc.wantSuccess)
			}
			if got := stats.errorCount.Load(); got != tc.wantError {
				t.Fatalf("errorCount=%d want %d", got, tc.wantError)
			}
			if got := stats.nxdomainCount.Load(); got != tc.wantNXDomain {
				t.Fatalf("nxdomainCount=%d want %d", got, tc.wantNXDomain)
			}
			if got := stats.servfailCount.Load(); got != tc.wantServFail {
				t.Fatalf("servfailCount=%d want %d", got, tc.wantServFail)
			}
			if got := stats.refusedCount.Load(); got != tc.wantRefused {
				t.Fatalf("refusedCount=%d want %d", got, tc.wantRefused)
			}
		})
	}
}

func TestWorker_TimeoutBranch(t *testing.T) {
	addr, stop := startUDPResponder(t, func(req *dns.Message) []byte {
		_ = req
		// No reply -> worker should hit read timeout path.
		return nil
	})
	defer stop()

	stats := runWorkerOnce(addr)
	if got := stats.totalQueries.Load(); got != 1 {
		t.Fatalf("totalQueries=%d want 1", got)
	}
	if got := stats.timeoutCount.Load(); got != 1 {
		t.Fatalf("timeoutCount=%d want 1", got)
	}
	if got := stats.errorCount.Load(); got != 1 {
		t.Fatalf("errorCount=%d want 1", got)
	}
}

func TestPercentile_EdgeCases(t *testing.T) {
	if got := percentile(nil, 95); got != 0 {
		t.Fatalf("percentile(nil)= %d, want 0", got)
	}

	sorted := []int64{10, 20, 30}
	if got := percentile(sorted, 0); got != 10 {
		t.Fatalf("percentile p=0 = %d, want 10", got)
	}
	if got := percentile(sorted, 101); got != 30 {
		t.Fatalf("percentile p=101 = %d, want 30", got)
	}
}
