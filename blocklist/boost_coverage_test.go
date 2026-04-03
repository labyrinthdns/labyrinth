package blocklist

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newSilentLogger returns a logger that suppresses all output.
func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(
		&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1},
	))
}

// ---------------------------------------------------------------------------
// RPZAction: covers manager.go:154-156 (RPZAction method, 0% coverage)
// ---------------------------------------------------------------------------

func TestRPZAction_Blocked(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	mgr.rpzMatcher.AddRule(RPZRule{
		Name:       "malware.com",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	action := mgr.RPZAction("malware.com")
	if action == nil {
		t.Fatal("expected RPZ action for malware.com")
	}
	if action.Type != RPZActionNXDomain {
		t.Errorf("action type = %d, want NXDOMAIN(%d)", action.Type, RPZActionNXDomain)
	}
}

func TestRPZAction_NoMatch(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newSilentLogger())

	action := mgr.RPZAction("safe.com")
	if action != nil {
		t.Errorf("expected nil for unmatched domain, got %v", action)
	}
}

// ---------------------------------------------------------------------------
// IsBlocked: covers manager.go:142-145 (RPZ match path, 71.4% -> 100%)
// ---------------------------------------------------------------------------

func TestIsBlocked_ViaRPZMatcher(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	mgr.rpzMatcher.AddRule(RPZRule{
		Name:       "rpz-blocked.com",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionDrop},
	})

	if !mgr.IsBlocked("rpz-blocked.com") {
		t.Error("rpz-blocked.com should be blocked via RPZ matcher")
	}

	count := mgr.blockedTotal.Load()
	if count != 1 {
		t.Errorf("blockedTotal = %d, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// downloadAndParseRPZ: covers manager.go:310-324 (0% coverage)
// ---------------------------------------------------------------------------

func TestDownloadAndParseRPZ_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "malware.example.com CNAME .")
		fmt.Fprintln(w, "*.ads.example.com CNAME .")
		fmt.Fprintln(w, "safe.example.com CNAME rpz-passthru.")
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	rules, err := mgr.downloadAndParseRPZ(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
}

func TestDownloadAndParseRPZ_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	_, err := mgr.downloadAndParseRPZ(srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("error = %q, want it to contain 'unexpected status 500'", err.Error())
	}
}

func TestDownloadAndParseRPZ_NetworkError(t *testing.T) {
	mgr := NewManager(ManagerConfig{}, newSilentLogger())
	_, err := mgr.downloadAndParseRPZ("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "HTTP GET") {
		t.Errorf("error = %q, want it to contain 'HTTP GET'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// RefreshAll: covers RPZ download path (manager.go:194-221, 71.4% -> 100%)
// ---------------------------------------------------------------------------

func TestRefreshAll_RPZList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "malware.com CNAME .")
		fmt.Fprintln(w, "*.tracking.com CNAME .")
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists: []ListEntry{{URL: srv.URL, Format: "rpz"}},
	}
	mgr := NewManager(cfg, newSilentLogger())
	mgr.RefreshAll()

	// Verify RPZ rules are loaded
	action := mgr.rpzMatcher.Match("malware.com")
	if action == nil {
		t.Error("malware.com should be blocked via RPZ")
	}
	action = mgr.rpzMatcher.Match("sub.tracking.com")
	if action == nil {
		t.Error("sub.tracking.com should be blocked via RPZ wildcard")
	}

	// Verify source metadata updated
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

func TestRefreshAll_RPZDownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := ManagerConfig{
		Lists: []ListEntry{{URL: srv.URL, Format: "rpz"}},
	}
	mgr := NewManager(cfg, newSilentLogger())
	mgr.RefreshAll()

	mgr.mu.RLock()
	errMsg := mgr.sources[0].Error
	mgr.mu.RUnlock()

	if errMsg == "" {
		t.Error("source Error should be set after RPZ download failure")
	}
}

// ---------------------------------------------------------------------------
// ParseRPZ: cover remaining uncovered lines
// ---------------------------------------------------------------------------

func TestParseRPZ_ShortLine(t *testing.T) {
	// Lines with fewer than 3 fields should be skipped (line 73-74)
	input := "malware.com CNAME\n" // only 2 fields
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for short line, got %d", len(rules))
	}
}

func TestParseRPZ_EmptyOwnerAfterTrim(t *testing.T) {
	// Owner that becomes empty after stripping trailing dot (line 78-79)
	input := ". CNAME .\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	// "." becomes "" after TrimSuffix(".") -> empty -> skip
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty owner, got %d", len(rules))
	}
}

func TestParseRPZ_NotEnoughFieldsForTypeRData(t *testing.T) {
	// After skipping TTL and class, not enough fields remain (line 101-102)
	input := "example.com 300 IN\n" // TTL and CLASS present but no RRTYPE
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRPZ_UnknownCNAMETarget(t *testing.T) {
	// Unknown CNAME target (line 127-129)
	input := "example.com CNAME some-other-domain.com.\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for unknown CNAME target, got %d", len(rules))
	}
}

func TestParseRPZ_EmptyARData(t *testing.T) {
	// A record with TTL but no RDATA: 3 fields, TTL consumed, rrtype="A", rdata="" (line 132-133)
	input := "example.com 300 A\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for A without IP, got %d", len(rules))
	}
}

func TestParseRPZ_AInvalidIP(t *testing.T) {
	// A record with completely invalid IP (line 140-141, ParseIP returns nil)
	input := "example.com A not_an_ip\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for invalid A IP, got %d", len(rules))
	}
}

func TestParseRPZ_AWithIPv6Address(t *testing.T) {
	// A record with an IPv6 address (To4() returns nil) (line 145-146)
	input := "example.com A ::1\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for A with IPv6 address, got %d", len(rules))
	}
}

func TestParseRPZ_EmptyAAAARData(t *testing.T) {
	// AAAA record with TTL but no RDATA: 3 fields, TTL consumed, rrtype="AAAA", rdata="" (line 145-146)
	input := "example.com 300 AAAA\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for AAAA without IP, got %d", len(rules))
	}
}

func TestParseRPZ_AAAAInvalidIP(t *testing.T) {
	// AAAA with invalid IP (line 153-155)
	input := "example.com AAAA not_an_ip\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for invalid AAAA IP, got %d", len(rules))
	}
}

func TestParseRPZ_UnsupportedRRType(t *testing.T) {
	// Unsupported RR type like TXT (default case)
	input := "example.com TXT \"hello\"\n"
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for unsupported RR type, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// AddRule: cover empty name branch (rpz.go:214-216)
// ---------------------------------------------------------------------------

func TestAddRule_EmptyName(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{
		Name:       "",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	exact, wildcards, passthru := m.Stats()
	if exact != 0 || wildcards != 0 || passthru != 0 {
		t.Errorf("empty name should not be added: exact=%d, wildcards=%d, passthru=%d", exact, wildcards, passthru)
	}
}

func TestAddRule_EmptyNameWithTrailingDot(t *testing.T) {
	m := NewRPZMatcher()
	// normalize(".") returns "", which should be rejected
	m.AddRule(RPZRule{
		Name:       ".",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	exact, wildcards, passthru := m.Stats()
	if exact != 0 || wildcards != 0 || passthru != 0 {
		t.Errorf("dot-only name should not be added: exact=%d, wildcards=%d, passthru=%d", exact, wildcards, passthru)
	}
}

// ---------------------------------------------------------------------------
// ParseHostsFile: cover inline comment that leaves only IP (line 41-42)
// ---------------------------------------------------------------------------

func TestParseHostsFile_InlineCommentLeavesOnlyIP(t *testing.T) {
	// After stripping inline comment "0.0.0.0 #comment" -> "0.0.0.0" -> <2 fields -> skip
	input := "0.0.0.0 #inline-comment\n0.0.0.0 real.com\n"
	domains := ParseHostsFile(strings.NewReader(input))
	if len(domains) != 1 || domains[0] != "real.com" {
		t.Errorf("got %v, want [real.com]", domains)
	}
}

// ---------------------------------------------------------------------------
// ParseDomainList: cover inline comment that leaves empty line (line 80-81)
// ---------------------------------------------------------------------------

func TestParseDomainList_InlineCommentLeavesEmpty(t *testing.T) {
	// "domain.com #stuff" -> after strip: "domain.com" (ok)
	// "#pure-comment" -> starts with '#' (already covered)
	// "  value#note" -> strip -> "  value" -> ok
	// But the line "stuff #all" -> "stuff" (ok, covered).
	// The uncovered line is when after stripping inline comment, the result is empty.
	// e.g., "#comment-only-after-hash" -> idx=0 -> line[:0]="" -> trim -> "" -> continue
	input := "#comment\n"
	domains := ParseDomainList(strings.NewReader(input))
	if len(domains) != 0 {
		t.Errorf("got %v, want []", domains)
	}

	// Test the specific uncovered case: line that contains text before # but
	// after stripping is empty whitespace
	input2 := "   #just-a-comment\nreal.com\n"
	domains2 := ParseDomainList(strings.NewReader(input2))
	if len(domains2) != 1 || domains2[0] != "real.com" {
		t.Errorf("got %v, want [real.com]", domains2)
	}
}
