package blocklist

import (
	"net"
	"strings"
	"testing"
)

func TestParseRPZ(t *testing.T) {
	input := `
; RPZ zone file
$TTL 300

; NXDOMAIN for exact domain
malware.example.com CNAME .

; NXDOMAIN for all subdomains
*.ads.example.com CNAME .

; NODATA
nodata.example.com CNAME *.

; Passthru (whitelist)
safe.example.com CNAME rpz-passthru.

; Drop
drop.example.com CNAME rpz-drop.

; Redirect to custom IPv4
redirect.example.com A 10.0.0.1

; Redirect to custom IPv6
redirect6.example.com AAAA ::1

; With TTL and class
ttl.example.com 300 IN CNAME .

# Comment with hash
; blank lines are skipped

bad-rdata.example.com A not-an-ip
`

	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}

	// Expected rules (skip "bad-rdata" since IP parse fails):
	// 1. malware.example.com NXDOMAIN (exact)
	// 2. ads.example.com NXDOMAIN (wildcard)
	// 3. nodata.example.com NODATA (exact)
	// 4. safe.example.com PASSTHRU (exact)
	// 5. drop.example.com DROP (exact)
	// 6. redirect.example.com LOCAL_A (exact)
	// 7. redirect6.example.com LOCAL_AAAA (exact)
	// 8. ttl.example.com NXDOMAIN (exact)
	if len(rules) != 8 {
		t.Fatalf("expected 8 rules, got %d", len(rules))
	}

	tests := []struct {
		idx        int
		name       string
		isWildcard bool
		actionType RPZActionType
		ip         string
	}{
		{0, "malware.example.com", false, RPZActionNXDomain, ""},
		{1, "ads.example.com", true, RPZActionNXDomain, ""},
		{2, "nodata.example.com", false, RPZActionNODATA, ""},
		{3, "safe.example.com", false, RPZActionPassthru, ""},
		{4, "drop.example.com", false, RPZActionDrop, ""},
		{5, "redirect.example.com", false, RPZActionLocalA, "10.0.0.1"},
		{6, "redirect6.example.com", false, RPZActionLocalAAAA, "::1"},
		{7, "ttl.example.com", false, RPZActionNXDomain, ""},
	}

	for _, tc := range tests {
		r := rules[tc.idx]
		if r.Name != tc.name {
			t.Errorf("rule[%d] name = %q, want %q", tc.idx, r.Name, tc.name)
		}
		if r.IsWildcard != tc.isWildcard {
			t.Errorf("rule[%d] isWildcard = %v, want %v", tc.idx, r.IsWildcard, tc.isWildcard)
		}
		if r.Action.Type != tc.actionType {
			t.Errorf("rule[%d] action type = %d, want %d", tc.idx, r.Action.Type, tc.actionType)
		}
		if tc.ip != "" {
			expected := net.ParseIP(tc.ip)
			if !r.Action.IP.Equal(expected) {
				t.Errorf("rule[%d] IP = %v, want %v", tc.idx, r.Action.IP, expected)
			}
		}
	}
}

func TestParseRPZEmptyInput(t *testing.T) {
	rules, err := ParseRPZ(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRPZCommentsOnly(t *testing.T) {
	input := `
; comment
# another comment
$ORIGIN example.com.
`
	rules, err := ParseRPZ(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRPZ error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestRPZMatcherExact(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{
		Name:       "malware.com",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	action := m.Match("malware.com")
	if action == nil {
		t.Fatal("expected match for malware.com")
	}
	if action.Type != RPZActionNXDomain {
		t.Errorf("action type = %d, want NXDOMAIN(%d)", action.Type, RPZActionNXDomain)
	}

	// Should not match subdomains.
	if m.Match("sub.malware.com") != nil {
		t.Error("exact rule should not match subdomain")
	}

	// Should not match unrelated domains.
	if m.Match("other.com") != nil {
		t.Error("should not match unrelated domain")
	}
}

func TestRPZMatcherWildcard(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{
		Name:       "ads.example.com",
		IsWildcard: true,
		Action:     RPZAction{Type: RPZActionDrop},
	})

	tests := []struct {
		domain string
		match  bool
	}{
		{"ads.example.com", true},
		{"sub.ads.example.com", true},
		{"deep.sub.ads.example.com", true},
		{"example.com", false},
		{"other.com", false},
	}

	for _, tc := range tests {
		action := m.Match(tc.domain)
		if tc.match && action == nil {
			t.Errorf("Match(%q) = nil, expected match", tc.domain)
		} else if !tc.match && action != nil {
			t.Errorf("Match(%q) = %v, expected nil", tc.domain, action)
		}
		if tc.match && action != nil && action.Type != RPZActionDrop {
			t.Errorf("Match(%q) type = %d, want DROP(%d)", tc.domain, action.Type, RPZActionDrop)
		}
	}
}

func TestRPZMatcherPassthru(t *testing.T) {
	m := NewRPZMatcher()

	// Block all of example.com via wildcard.
	m.AddRule(RPZRule{
		Name:       "example.com",
		IsWildcard: true,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	// Passthru (whitelist) safe.example.com.
	m.AddRule(RPZRule{
		Name:       "safe.example.com",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionPassthru},
	})

	// Blocked domains should match.
	action := m.Match("ads.example.com")
	if action == nil || action.Type != RPZActionNXDomain {
		t.Error("ads.example.com should be NXDOMAIN")
	}

	// Whitelisted domain should not match.
	if m.Match("safe.example.com") != nil {
		t.Error("safe.example.com should be passthru (nil)")
	}
}

func TestRPZMatcherWildcardPassthru(t *testing.T) {
	m := NewRPZMatcher()

	// Block all of example.com.
	m.AddRule(RPZRule{
		Name:       "example.com",
		IsWildcard: true,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	// Wildcard passthru for safe.example.com and all subdomains.
	m.AddRule(RPZRule{
		Name:       "safe.example.com",
		IsWildcard: true,
		Action:     RPZAction{Type: RPZActionPassthru},
	})

	// Blocked domains should match.
	action := m.Match("ads.example.com")
	if action == nil {
		t.Fatal("ads.example.com should match")
	}

	// safe.example.com and its subdomains should pass through.
	if m.Match("safe.example.com") != nil {
		t.Error("safe.example.com should be passthru")
	}
	if m.Match("sub.safe.example.com") != nil {
		t.Error("sub.safe.example.com should be passthru")
	}
}

func TestRPZMatcherLocalRedirect(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{
		Name:       "redirect.example.com",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionLocalA, IP: net.ParseIP("10.0.0.1").To4()},
	})

	action := m.Match("redirect.example.com")
	if action == nil {
		t.Fatal("expected match for redirect.example.com")
	}
	if action.Type != RPZActionLocalA {
		t.Errorf("action type = %d, want LOCAL_A(%d)", action.Type, RPZActionLocalA)
	}
	expected := net.ParseIP("10.0.0.1").To4()
	if !action.IP.Equal(expected) {
		t.Errorf("action IP = %v, want %v", action.IP, expected)
	}
}

func TestRPZMatcherEmpty(t *testing.T) {
	m := NewRPZMatcher()
	if m.Match("anything.com") != nil {
		t.Error("empty matcher should not match anything")
	}
	if m.Match("") != nil {
		t.Error("empty matcher should not match empty string")
	}
}

func TestRPZMatcherStats(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{Name: "a.com", IsWildcard: false, Action: RPZAction{Type: RPZActionNXDomain}})
	m.AddRule(RPZRule{Name: "b.com", IsWildcard: true, Action: RPZAction{Type: RPZActionDrop}})
	m.AddRule(RPZRule{Name: "c.com", IsWildcard: false, Action: RPZAction{Type: RPZActionPassthru}})
	m.AddRule(RPZRule{Name: "d.com", IsWildcard: true, Action: RPZAction{Type: RPZActionPassthru}})

	exact, wildcards, passthru := m.Stats()
	if exact != 1 {
		t.Errorf("exact = %d, want 1", exact)
	}
	if wildcards != 1 {
		t.Errorf("wildcards = %d, want 1", wildcards)
	}
	if passthru != 2 {
		t.Errorf("passthru = %d, want 2", passthru)
	}
}

func TestRPZMatcherCaseInsensitive(t *testing.T) {
	m := NewRPZMatcher()
	m.AddRule(RPZRule{
		Name:       "Malware.COM",
		IsWildcard: false,
		Action:     RPZAction{Type: RPZActionNXDomain},
	})

	// AddRule normalizes names, so "Malware.COM" is stored as "malware.com".
	// Match also normalizes the query, so case-insensitive matching works.
	action := m.Match("MALWARE.COM")
	if action == nil {
		t.Fatal("Match should be case-insensitive")
	}
	if action.Type != RPZActionNXDomain {
		t.Errorf("action type = %d, want NXDOMAIN(%d)", action.Type, RPZActionNXDomain)
	}

	// Also test with lowercase query.
	action = m.Match("malware.com")
	if action == nil {
		t.Fatal("Match should find lowercase query")
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"", false},
		{"0", true},
		{"300", true},
		{"abc", false},
		{"12a", false},
	}
	for _, tc := range tests {
		if got := isNumeric(tc.s); got != tc.want {
			t.Errorf("isNumeric(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestIsClass(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"IN", true},
		{"in", true},
		{"CH", true},
		{"HS", true},
		{"ANY", true},
		{"XX", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isClass(tc.s); got != tc.want {
			t.Errorf("isClass(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
