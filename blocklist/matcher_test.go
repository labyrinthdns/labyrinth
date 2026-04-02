package blocklist

import (
	"fmt"
	"sync"
	"testing"
)

func TestNewMatcher(t *testing.T) {
	m := NewMatcher()
	if m == nil {
		t.Fatal("NewMatcher returned nil")
	}

	// An empty matcher should match nothing.
	domains := []string{"example.com", "ads.tracker.io", "localhost", "", "a.b.c.d.e"}
	for _, d := range domains {
		if m.Match(d) {
			t.Errorf("empty matcher should not match %q", d)
		}
	}
}

func TestMatchExact(t *testing.T) {
	m := NewMatcher()
	m.AddExact("ads.example.com")
	m.AddExact("tracker.net")

	tests := []struct {
		domain string
		want   bool
	}{
		{"ads.example.com", true},
		{"tracker.net", true},
		{"example.com", false},
		{"sub.ads.example.com", false}, // exact match only, not subdomains
		{"other.com", false},
		{"", false},
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestMatchWildcard(t *testing.T) {
	m := NewMatcher()
	m.AddWildcard("example.com")

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},           // the domain itself matches
		{"sub.example.com", true},       // one level subdomain
		{"deep.sub.example.com", true},  // multi-level subdomain
		{"a.b.c.d.example.com", true},   // very deep subdomain
		{"other.com", false},            // unrelated domain
		{"notexample.com", false},       // different domain with shared suffix
		{"example.com.evil.net", false}, // example.com is not a parent here
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestWhitelistOverride(t *testing.T) {
	m := NewMatcher()
	m.AddExact("ads.example.com")
	m.AddWhitelist("ads.example.com")

	if m.Match("ads.example.com") {
		t.Error("whitelisted domain should not be blocked")
	}

	// A domain that is only blocked (not whitelisted) should still match.
	m.AddExact("tracker.net")
	if !m.Match("tracker.net") {
		t.Error("non-whitelisted domain should still be blocked")
	}
}

func TestWildcardWhitelist(t *testing.T) {
	m := NewMatcher()

	// Block all of example.com via wildcard.
	m.AddWildcard("example.com")

	// Whitelist all of safe.example.com via wildcard whitelist.
	m.AddWildcardWhitelist("safe.example.com")

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},                // blocked by wildcard
		{"ads.example.com", true},            // blocked by wildcard
		{"safe.example.com", false},          // whitelisted by wildcard whitelist
		{"sub.safe.example.com", false},      // whitelisted (subdomain of whitelisted wildcard)
		{"deep.sub.safe.example.com", false}, // whitelisted (deep subdomain)
		{"other.com", false},                 // not blocked at all
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestCaseInsensitive(t *testing.T) {
	m := NewMatcher()
	m.AddExact("ADS.Example.COM")
	m.AddWildcard("Tracker.NET")

	tests := []struct {
		domain string
		want   bool
	}{
		{"ads.example.com", true},
		{"ADS.EXAMPLE.COM", true},
		{"Ads.Example.Com", true},
		{"tracker.net", true},
		{"TRACKER.NET", true},
		{"sub.tracker.net", true},
		{"SUB.TRACKER.NET", true},
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestTrailingDot(t *testing.T) {
	m := NewMatcher()
	m.AddExact("example.com")
	m.AddWildcard("tracker.net.")

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com.", true},      // trailing dot query matches exact entry
		{"example.com", true},       // no trailing dot also matches
		{"tracker.net", true},       // entry was added with dot, matches without
		{"tracker.net.", true},      // both have dots
		{"sub.tracker.net.", true},  // wildcard + trailing dot
		{"sub.tracker.net", true},   // wildcard without trailing dot
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestRemove(t *testing.T) {
	m := NewMatcher()
	m.AddExact("ads.example.com")
	m.AddWildcard("tracker.net")

	// Verify both match before removal.
	if !m.Match("ads.example.com") {
		t.Fatal("expected ads.example.com to be blocked before removal")
	}
	if !m.Match("sub.tracker.net") {
		t.Fatal("expected sub.tracker.net to be blocked before removal")
	}

	// Remove exact entry.
	m.Remove("ads.example.com")
	if m.Match("ads.example.com") {
		t.Error("ads.example.com should not be blocked after removal")
	}

	// Remove wildcard entry.
	m.Remove("tracker.net")
	if m.Match("tracker.net") {
		t.Error("tracker.net should not be blocked after wildcard removal")
	}
	if m.Match("sub.tracker.net") {
		t.Error("sub.tracker.net should not be blocked after wildcard removal")
	}

	// Remove non-existent domain should not panic.
	m.Remove("nonexistent.com")

	// Remove empty string should be a no-op.
	m.Remove("")
}

func TestReset(t *testing.T) {
	m := NewMatcher()
	m.AddExact("ads.example.com")
	m.AddWildcard("tracker.net")
	m.AddWhitelist("safe.example.com")
	m.AddWildcardWhitelist("trusted.org")

	// Verify state before reset.
	exact, wildcards, wl := m.Stats()
	if exact == 0 || wildcards == 0 || wl == 0 {
		t.Fatal("expected non-zero stats before reset")
	}

	m.Reset()

	// Everything should be cleared.
	exact, wildcards, wl = m.Stats()
	if exact != 0 || wildcards != 0 || wl != 0 {
		t.Errorf("after Reset, Stats() = (%d, %d, %d), want (0, 0, 0)", exact, wildcards, wl)
	}

	// Previously blocked domains should no longer match.
	if m.Match("ads.example.com") {
		t.Error("ads.example.com should not match after reset")
	}
	if m.Match("sub.tracker.net") {
		t.Error("sub.tracker.net should not match after reset")
	}
}

func TestStats(t *testing.T) {
	m := NewMatcher()

	exact, wildcards, wl := m.Stats()
	if exact != 0 || wildcards != 0 || wl != 0 {
		t.Errorf("empty matcher Stats() = (%d, %d, %d), want (0, 0, 0)", exact, wildcards, wl)
	}

	m.AddExact("a.com")
	m.AddExact("b.com")
	m.AddExact("c.com")
	m.AddWildcard("d.com")
	m.AddWildcard("e.com")
	m.AddWhitelist("f.com")
	m.AddWildcardWhitelist("g.com")
	m.AddWildcardWhitelist("h.com")

	exact, wildcards, wl = m.Stats()
	if exact != 3 {
		t.Errorf("exact = %d, want 3", exact)
	}
	if wildcards != 2 {
		t.Errorf("wildcards = %d, want 2", wildcards)
	}
	// whitelist count = len(whitelist) + len(wildcardWhitelist) = 1 + 2 = 3
	if wl != 3 {
		t.Errorf("whitelist = %d, want 3", wl)
	}

	// Adding the same domain again should not increase counts.
	m.AddExact("a.com")
	exact, _, _ = m.Stats()
	if exact != 3 {
		t.Errorf("duplicate AddExact changed count: exact = %d, want 3", exact)
	}
}

func TestMatchEmptyDomain(t *testing.T) {
	m := NewMatcher()
	m.AddExact("")
	m.AddWildcard("")

	if m.Match("") {
		t.Error("Match on empty string should return false")
	}
}

func TestAddEmptyDomain(t *testing.T) {
	m := NewMatcher()
	m.AddExact("")
	m.AddWildcard("")
	m.AddWhitelist("")
	m.AddWildcardWhitelist("")

	exact, wildcards, wl := m.Stats()
	if exact != 0 || wildcards != 0 || wl != 0 {
		t.Errorf("adding empty strings should not change stats, got (%d, %d, %d)", exact, wildcards, wl)
	}
}

func TestConcurrency(t *testing.T) {
	m := NewMatcher()
	const goroutines = 50
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				domain := fmt.Sprintf("domain-%d-%d.example.com", id, j)
				m.AddExact(domain)
				m.Match(domain)
				m.AddWildcard(fmt.Sprintf("wild-%d.com", id))
				m.Match(fmt.Sprintf("sub.wild-%d.com", id))
				m.AddWhitelist(fmt.Sprintf("white-%d-%d.com", id, j))
				m.Remove(domain)
			}
		}(i)
	}

	wg.Wait()

	// If we got here without a race condition panic, the test passes.
	// Run with -race flag for full verification.
}

func TestExactDoesNotMatchSubdomains(t *testing.T) {
	m := NewMatcher()
	m.AddExact("example.com")

	if m.Match("sub.example.com") {
		t.Error("exact rule for example.com should not match sub.example.com")
	}
	if !m.Match("example.com") {
		t.Error("exact rule for example.com should match example.com")
	}
}

func TestMultipleWildcards(t *testing.T) {
	m := NewMatcher()
	m.AddWildcard("ads.com")
	m.AddWildcard("tracking.io")

	tests := []struct {
		domain string
		want   bool
	}{
		{"ads.com", true},
		{"sub.ads.com", true},
		{"tracking.io", true},
		{"pixel.tracking.io", true},
		{"safe.org", false},
	}
	for _, tc := range tests {
		got := m.Match(tc.domain)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestWhitelistExactOverridesWildcardBlock(t *testing.T) {
	m := NewMatcher()
	m.AddWildcard("example.com")
	m.AddWhitelist("safe.example.com")

	if m.Match("safe.example.com") {
		t.Error("exact whitelist should override wildcard block")
	}
	if !m.Match("other.example.com") {
		t.Error("non-whitelisted subdomain should still be blocked")
	}
}
