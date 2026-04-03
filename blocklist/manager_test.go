package blocklist

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestLogger returns a silent logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(
		&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1},
	))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// --- NewManager tests ---

func TestNewManager_Defaults(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, nil)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.blockingMode != "nxdomain" {
		t.Errorf("default blockingMode = %q, want %q", mgr.blockingMode, "nxdomain")
	}
	if mgr.refreshInterval != 24*time.Hour {
		t.Errorf("default refreshInterval = %v, want %v", mgr.refreshInterval, 24*time.Hour)
	}
	if mgr.logger == nil {
		t.Error("logger should not be nil when nil is passed")
	}
}

func TestNewManager_CustomConfig(t *testing.T) {
	cfg := ManagerConfig{
		Lists: []ListEntry{
			{URL: "http://example.com/hosts", Format: "hosts"},
			{URL: "http://example.com/domains", Format: "domains"},
		},
		Whitelist:       []string{"safe.example.com", "GOOD.ORG."},
		BlockingMode:    "custom_ip",
		CustomIP:        "192.168.1.1",
		RefreshInterval: 1 * time.Hour,
	}
	logger := newTestLogger()
	mgr := NewManager(cfg, logger)

	if mgr.blockingMode != "custom_ip" {
		t.Errorf("blockingMode = %q, want %q", mgr.blockingMode, "custom_ip")
	}
	if mgr.customIP != "192.168.1.1" {
		t.Errorf("customIP = %q, want %q", mgr.customIP, "192.168.1.1")
	}
	if mgr.refreshInterval != 1*time.Hour {
		t.Errorf("refreshInterval = %v, want %v", mgr.refreshInterval, 1*time.Hour)
	}
	if len(mgr.sources) != 2 {
		t.Errorf("sources count = %d, want 2", len(mgr.sources))
	}
	for _, s := range mgr.sources {
		if !s.Enabled {
			t.Errorf("source %q should be enabled", s.URL)
		}
	}
	// Whitelist entries should be normalized (lowered, trailing dot stripped).
	if _, ok := mgr.customAllows["safe.example.com"]; !ok {
		t.Error("expected safe.example.com in customAllows")
	}
	if _, ok := mgr.customAllows["good.org"]; !ok {
		t.Error("expected good.org (normalized) in customAllows")
	}
}

func TestNewManager_NegativeRefreshInterval(t *testing.T) {
	cfg := ManagerConfig{RefreshInterval: -5 * time.Minute}
	mgr := NewManager(cfg, newTestLogger())
	if mgr.refreshInterval != 24*time.Hour {
		t.Errorf("negative refreshInterval should default to 24h, got %v", mgr.refreshInterval)
	}
}

// --- downloadAndParse tests ---

func TestDownloadAndParse_Hosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "0.0.0.0 ads.example.com")
		fmt.Fprintln(w, "0.0.0.0 tracker.net")
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newTestLogger())
	domains, err := mgr.downloadAndParse(srv.URL, "hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
}

func TestDownloadAndParse_Domains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ads.example.com")
		fmt.Fprintln(w, "tracker.net")
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newTestLogger())
	domains, err := mgr.downloadAndParse(srv.URL, "domains")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
}

func TestDownloadAndParse_ABP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "||ads.example.com^")
		fmt.Fprintln(w, "||tracker.net^")
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newTestLogger())
	domains, err := mgr.downloadAndParse(srv.URL, "ABP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
}

func TestDownloadAndParse_UnknownFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "some content")
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newTestLogger())
	_, err := mgr.downloadAndParse(srv.URL, "xml")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown list format") {
		t.Errorf("error = %q, want it to contain 'unknown list format'", err.Error())
	}
}

func TestDownloadAndParse_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newTestLogger())
	_, err := mgr.downloadAndParse(srv.URL, "hosts")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("error = %q, want it to contain 'unexpected status 500'", err.Error())
	}
}

func TestDownloadAndParse_NetworkError(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	_, err := mgr.downloadAndParse("http://127.0.0.1:1", "hosts")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "HTTP GET") {
		t.Errorf("error = %q, want it to contain 'HTTP GET'", err.Error())
	}
}

// --- RefreshAll tests ---

func TestRefreshAll_LoadsListsAndAppliesCustomRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ads.example.com")
		fmt.Fprintln(w, "tracker.net")
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists:     []ListEntry{{URL: srv.URL, Format: "domains"}},
		Whitelist: []string{"tracker.net"},
	}
	mgr := NewManager(cfg, newTestLogger())

	// Add a custom block before refreshing.
	mgr.mu.Lock()
	mgr.customBlocks["custom-block.com"] = struct{}{}
	mgr.mu.Unlock()

	mgr.RefreshAll()

	// ads.example.com should be blocked (from list).
	if !mgr.matcher.Match("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	// tracker.net should NOT be blocked (whitelisted).
	if mgr.matcher.Match("tracker.net") {
		t.Error("tracker.net should be whitelisted and not blocked")
	}
	// custom-block.com should be blocked.
	if !mgr.matcher.Match("custom-block.com") {
		t.Error("custom-block.com should be blocked via custom block")
	}

	// Verify the source metadata was updated.
	mgr.mu.RLock()
	src := mgr.sources[0]
	if src.RuleCount != 2 {
		t.Errorf("source RuleCount = %d, want 2", src.RuleCount)
	}
	if src.Error != "" {
		t.Errorf("source Error = %q, want empty", src.Error)
	}
	if src.LastUpdate.IsZero() {
		t.Error("source LastUpdate should be set")
	}
	mgr.mu.RUnlock()
}

func TestRefreshAll_DisabledListSkipped(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		fmt.Fprintln(w, "ads.example.com")
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists: []ListEntry{{URL: srv.URL, Format: "domains"}},
	}
	mgr := NewManager(cfg, newTestLogger())

	// Disable the source.
	mgr.mu.Lock()
	mgr.sources[0].Enabled = false
	mgr.mu.Unlock()

	mgr.RefreshAll()

	if callCount != 0 {
		t.Errorf("disabled list was fetched %d times, want 0", callCount)
	}
}

func TestRefreshAll_DownloadErrorRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists: []ListEntry{{URL: srv.URL, Format: "hosts"}},
	}
	mgr := NewManager(cfg, newTestLogger())
	mgr.RefreshAll()

	mgr.mu.RLock()
	errMsg := mgr.sources[0].Error
	mgr.mu.RUnlock()

	if errMsg == "" {
		t.Error("source Error should be set after download failure")
	}
}

// --- Start tests ---

func TestStart_ImmediateRefreshAndCancellation(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		fmt.Fprintln(w, "ads.example.com")
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists:           []ListEntry{{URL: srv.URL, Format: "domains"}},
		RefreshInterval: 50 * time.Millisecond,
	}
	mgr := NewManager(cfg, newTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mgr.Start(ctx)
		close(done)
	}()

	// Wait long enough for the initial refresh plus at least one tick.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good, Start returned
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	if callCount < 2 {
		t.Errorf("expected at least 2 refresh calls (initial + tick), got %d", callCount)
	}
}

// --- IsBlocked tests ---

func TestIsBlocked(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	mgr.matcher.AddExact("ads.example.com")

	if !mgr.IsBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	if mgr.IsBlocked("safe.example.com") {
		t.Error("safe.example.com should not be blocked")
	}

	// Verify counter incremented.
	count := mgr.blockedTotal.Load()
	if count != 1 {
		t.Errorf("blockedTotal = %d, want 1", count)
	}
}

// --- BlockingMode tests ---

func TestBlockingMode(t *testing.T) {
	mgr := NewManager(ManagerConfig{BlockingMode: "null_ip"}, newTestLogger())
	if got := mgr.BlockingMode(); got != "null_ip" {
		t.Errorf("BlockingMode() = %q, want %q", got, "null_ip")
	}

	mgr2 := NewManager(ManagerConfig{}, newTestLogger())
	if got := mgr2.BlockingMode(); got != "nxdomain" {
		t.Errorf("BlockingMode() = %q, want %q (default)", got, "nxdomain")
	}
}

// --- CustomIP tests ---

func TestCustomIP(t *testing.T) {
	mgr := NewManager(ManagerConfig{CustomIP: "10.0.0.1"}, newTestLogger())
	if got := mgr.CustomIP(); got != "10.0.0.1" {
		t.Errorf("CustomIP() = %q, want %q", got, "10.0.0.1")
	}

	mgr2 := NewManager(ManagerConfig{}, newTestLogger())
	if got := mgr2.CustomIP(); got != "" {
		t.Errorf("CustomIP() = %q, want empty", got)
	}
}

// --- AddList tests ---

func TestAddList_New(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())

	mgr.AddList("http://example.com/list", "hosts")

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.sources) != 1 {
		t.Fatalf("sources count = %d, want 1", len(mgr.sources))
	}
	s := mgr.sources[0]
	if s.URL != "http://example.com/list" {
		t.Errorf("URL = %q", s.URL)
	}
	if s.Format != "hosts" {
		t.Errorf("Format = %q", s.Format)
	}
	if !s.Enabled {
		t.Error("new source should be enabled")
	}
}

func TestAddList_DuplicateUpdates(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())

	mgr.AddList("http://example.com/list", "hosts")
	mgr.AddList("http://example.com/list", "domains") // same URL, different format

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.sources) != 1 {
		t.Fatalf("sources count = %d, want 1 (no duplicate)", len(mgr.sources))
	}
	if mgr.sources[0].Format != "domains" {
		t.Errorf("format should be updated to 'domains', got %q", mgr.sources[0].Format)
	}
	if !mgr.sources[0].Enabled {
		t.Error("re-added source should be enabled")
	}
}

// --- RemoveList tests ---

func TestRemoveList_Existing(t *testing.T) {
	cfg := ManagerConfig{
		Lists: []ListEntry{
			{URL: "http://a.com", Format: "hosts"},
			{URL: "http://b.com", Format: "domains"},
		},
	}
	mgr := NewManager(cfg, newTestLogger())

	mgr.RemoveList("http://a.com")

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.sources) != 1 {
		t.Fatalf("sources count = %d, want 1 after removal", len(mgr.sources))
	}
	if mgr.sources[0].URL != "http://b.com" {
		t.Errorf("remaining source URL = %q, want http://b.com", mgr.sources[0].URL)
	}
}

func TestRemoveList_NonExisting(t *testing.T) {
	cfg := ManagerConfig{
		Lists: []ListEntry{{URL: "http://a.com", Format: "hosts"}},
	}
	mgr := NewManager(cfg, newTestLogger())

	mgr.RemoveList("http://nonexistent.com") // should not panic

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.sources) != 1 {
		t.Errorf("sources count = %d, want 1 (no change)", len(mgr.sources))
	}
}

// --- BlockDomain tests ---

func TestBlockDomain(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())

	mgr.BlockDomain("evil.com")
	if !mgr.matcher.Match("evil.com") {
		t.Error("evil.com should be blocked after BlockDomain")
	}

	mgr.mu.RLock()
	_, ok := mgr.customBlocks["evil.com"]
	mgr.mu.RUnlock()
	if !ok {
		t.Error("evil.com should be in customBlocks")
	}
}

func TestBlockDomain_Empty(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	mgr.BlockDomain("") // should not panic or add anything

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.customBlocks) != 0 {
		t.Error("empty domain should not be added to customBlocks")
	}
}

// --- UnblockDomain tests ---

func TestUnblockDomain(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())

	// First block, then unblock.
	mgr.BlockDomain("evil.com")
	if !mgr.matcher.Match("evil.com") {
		t.Fatal("evil.com should be blocked first")
	}

	mgr.UnblockDomain("evil.com")

	if mgr.matcher.Match("evil.com") {
		t.Error("evil.com should not be blocked after UnblockDomain")
	}

	mgr.mu.RLock()
	_, inBlocks := mgr.customBlocks["evil.com"]
	_, inAllows := mgr.customAllows["evil.com"]
	mgr.mu.RUnlock()

	if inBlocks {
		t.Error("evil.com should be removed from customBlocks")
	}
	if !inAllows {
		t.Error("evil.com should be in customAllows")
	}
}

func TestUnblockDomain_Empty(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	mgr.UnblockDomain("") // should not panic or add anything

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.customAllows) != 0 {
		t.Error("empty domain should not be added to customAllows")
	}
}

// --- CheckDomain tests ---

func TestCheckDomain(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	mgr.matcher.AddExact("ads.example.com")

	if !mgr.CheckDomain("ads.example.com") {
		t.Error("CheckDomain should return true for blocked domain")
	}
	if mgr.CheckDomain("safe.example.com") {
		t.Error("CheckDomain should return false for non-blocked domain")
	}

	// Verify CheckDomain does NOT increment blockedTotal.
	if mgr.blockedTotal.Load() != 0 {
		t.Errorf("blockedTotal = %d, want 0 (CheckDomain should not increment)", mgr.blockedTotal.Load())
	}
}

// --- Stats tests ---

func TestStats_Empty(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	st := mgr.Stats()

	if st.Enabled {
		t.Error("Enabled should be false with no sources and no custom blocks")
	}
	if st.TotalRules != 0 {
		t.Errorf("TotalRules = %d, want 0", st.TotalRules)
	}
	if st.ListCount != 0 {
		t.Errorf("ListCount = %d, want 0", st.ListCount)
	}
	if st.BlockedTotal != 0 {
		t.Errorf("BlockedTotal = %d, want 0", st.BlockedTotal)
	}
	if st.BlockingMode != "nxdomain" {
		t.Errorf("BlockingMode = %q, want %q", st.BlockingMode, "nxdomain")
	}
}

func TestStats_WithData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ads.example.com")
		fmt.Fprintln(w, "tracker.net")
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists:        []ListEntry{{URL: srv.URL, Format: "domains"}},
		BlockingMode: "null_ip",
	}
	mgr := NewManager(cfg, newTestLogger())
	mgr.RefreshAll()

	// Add a custom block and trigger IsBlocked to increment counter.
	mgr.BlockDomain("custom.bad.com")
	mgr.IsBlocked("ads.example.com")
	mgr.IsBlocked("nonexistent.com") // won't increment

	st := mgr.Stats()

	if !st.Enabled {
		t.Error("Enabled should be true with sources")
	}
	if st.TotalRules < 2 {
		t.Errorf("TotalRules = %d, want >= 2", st.TotalRules)
	}
	if st.ListCount != 1 {
		t.Errorf("ListCount = %d, want 1", st.ListCount)
	}
	if st.BlockedTotal != 1 {
		t.Errorf("BlockedTotal = %d, want 1", st.BlockedTotal)
	}
	if st.CustomBlocks != 1 {
		t.Errorf("CustomBlocks = %d, want 1", st.CustomBlocks)
	}
	if st.BlockingMode != "null_ip" {
		t.Errorf("BlockingMode = %q, want %q", st.BlockingMode, "null_ip")
	}
}

func TestStats_EnabledWithCustomBlocksOnly(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	mgr.BlockDomain("evil.com")

	st := mgr.Stats()
	if !st.Enabled {
		t.Error("Enabled should be true when custom blocks exist, even with no list sources")
	}
	if st.CustomBlocks != 1 {
		t.Errorf("CustomBlocks = %d, want 1", st.CustomBlocks)
	}
}

func TestStats_DisabledListNotCounted(t *testing.T) {
	cfg := ManagerConfig{
		Lists: []ListEntry{
			{URL: "http://a.com", Format: "hosts"},
			{URL: "http://b.com", Format: "hosts"},
		},
	}
	mgr := NewManager(cfg, newTestLogger())

	// Disable one source.
	mgr.mu.Lock()
	mgr.sources[0].Enabled = false
	mgr.mu.Unlock()

	st := mgr.Stats()
	if st.ListCount != 1 {
		t.Errorf("ListCount = %d, want 1 (only enabled lists)", st.ListCount)
	}
}

// --- Sources tests ---

func TestSources_ReturnsSnapshot(t *testing.T) {
	cfg := ManagerConfig{
		Lists: []ListEntry{
			{URL: "http://a.com", Format: "hosts"},
			{URL: "http://b.com", Format: "domains"},
		},
	}
	mgr := NewManager(cfg, newTestLogger())

	sources := mgr.Sources()
	if len(sources) != 2 {
		t.Fatalf("Sources() returned %d items, want 2", len(sources))
	}

	// Verify it's a copy, not a reference to the internal slice.
	sources[0].URL = "modified"
	mgr.mu.RLock()
	if mgr.sources[0].URL == "modified" {
		t.Error("Sources() should return a copy, not the internal slice")
	}
	mgr.mu.RUnlock()
}

func TestSources_EmptyManager(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newTestLogger())
	sources := mgr.Sources()
	if len(sources) != 0 {
		t.Errorf("Sources() returned %d items, want 0", len(sources))
	}
}

// --- Parser edge cases for remaining coverage ---

func TestParseHostsFile_InlineCommentBecomesEmpty(t *testing.T) {
	// After stripping the inline comment, the remainder is "0.0.0.0 " which
	// trims to "0.0.0.0" with < 2 fields, so it should be skipped.
	// Also test a line that is entirely a comment after the # strip.
	input := "0.0.0.0 #just a comment\n0.0.0.0 real.com\n"
	domains := ParseHostsFile(strings.NewReader(input))
	if len(domains) != 1 || domains[0] != "real.com" {
		t.Errorf("got %v, want [real.com]", domains)
	}
}

func TestParseDomainList_InlineCommentBecomesEmpty(t *testing.T) {
	// A line that is just "#comment" after trimming the start should be
	// caught by the line[0]=='#' check. But a line like "  #foo" also
	// hits that. The uncovered branch is: content before # is whitespace only.
	input := " #just-comment\nreal.com\n"
	domains := ParseDomainList(strings.NewReader(input))
	if len(domains) != 1 || domains[0] != "real.com" {
		t.Errorf("got %v, want [real.com]", domains)
	}
}

// --- Integration / end-to-end test ---

func TestManager_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hosts":
			fmt.Fprintln(w, "0.0.0.0 ads.example.com")
			fmt.Fprintln(w, "0.0.0.0 tracker.net")
		case "/domains":
			fmt.Fprintln(w, "malware.org")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists: []ListEntry{
			{URL: srv.URL + "/hosts", Format: "hosts"},
			{URL: srv.URL + "/domains", Format: "domains"},
		},
		Whitelist:       []string{"tracker.net"},
		BlockingMode:    "custom_ip",
		CustomIP:        "0.0.0.0",
		RefreshInterval: 1 * time.Hour,
	}
	mgr := NewManager(cfg, newTestLogger())

	// RefreshAll loads lists.
	mgr.RefreshAll()

	// Verify blocking.
	if !mgr.IsBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	if mgr.IsBlocked("tracker.net") {
		t.Error("tracker.net should be whitelisted")
	}
	if !mgr.IsBlocked("malware.org") {
		t.Error("malware.org should be blocked")
	}
	if mgr.IsBlocked("safe.com") {
		t.Error("safe.com should not be blocked")
	}

	// Add a runtime list.
	mgr.AddList(srv.URL+"/domains", "domains")
	// Remove a list.
	mgr.RemoveList(srv.URL + "/hosts")

	// Custom block/unblock.
	mgr.BlockDomain("evil.com")
	if !mgr.CheckDomain("evil.com") {
		t.Error("evil.com should be blocked via custom rule")
	}
	mgr.UnblockDomain("evil.com")
	if mgr.CheckDomain("evil.com") {
		t.Error("evil.com should be unblocked via custom whitelist")
	}

	// Check stats.
	st := mgr.Stats()
	if st.BlockingMode != "custom_ip" {
		t.Errorf("BlockingMode = %q", st.BlockingMode)
	}
	if mgr.CustomIP() != "0.0.0.0" {
		t.Errorf("CustomIP = %q", mgr.CustomIP())
	}

	// Check sources snapshot.
	sources := mgr.Sources()
	if len(sources) < 1 {
		t.Error("expected at least 1 source after add/remove")
	}
}

func TestStats_CustomAllowsCounted(t *testing.T) {
	cfg := ManagerConfig{
		Whitelist: []string{"a.com", "b.com"},
	}
	mgr := NewManager(cfg, newTestLogger())

	st := mgr.Stats()
	if st.CustomAllows != 2 {
		t.Errorf("CustomAllows = %d, want 2", st.CustomAllows)
	}
}
