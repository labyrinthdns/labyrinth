package blocklist

import (
	"strings"
	"testing"
)

func TestParseHostsFile(t *testing.T) {
	input := `# This is a hosts file blocklist
# Last updated: 2024-01-01

0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
0.0.0.0 malware.bad.org
127.0.0.1 spyware.evil.net

# Local entries that should be skipped
0.0.0.0 localhost
127.0.0.1 localhost.localdomain
0.0.0.0 broadcasthost
0.0.0.0 ip6-localhost
0.0.0.0 ip6-loopback
0.0.0.0 ip6-localnet
0.0.0.0 ip6-mcastprefix
0.0.0.0 ip6-allnodes
0.0.0.0 ip6-allrouters
0.0.0.0 ip6-allhosts
0.0.0.0 local
`

	domains := ParseHostsFile(strings.NewReader(input))

	expected := map[string]bool{
		"ads.example.com":     false,
		"tracker.example.com": false,
		"malware.bad.org":     false,
		"spyware.evil.net":    false,
	}

	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}

	for _, d := range domains {
		if _, ok := expected[d]; !ok {
			t.Errorf("unexpected domain %q in result", d)
		} else {
			expected[d] = true
		}
	}

	for d, found := range expected {
		if !found {
			t.Errorf("expected domain %q not found in result", d)
		}
	}
}

func TestParseHostsFileEdgeCases(t *testing.T) {
	// Tabs, multiple spaces, inline comments, Windows-style line endings (\r\n)
	input := "# Comment line\r\n" +
		"\r\n" +
		"0.0.0.0\t\tads.example.com\t# inline comment\r\n" +
		"127.0.0.1    tracker.net   # another comment\r\n" +
		"  0.0.0.0   spaced.com  \r\n" +
		"! ABP-style comment\r\n" +
		"192.168.1.1 internal.local\r\n" + // non-blocking IP, should be skipped
		"0.0.0.0\r\n" +                    // no domain field, should be skipped
		"just-a-domain.com\r\n" +          // no IP prefix, should be skipped
		"0.0.0.0 UPPERCASE.COM\r\n"        // should be lowercased

	domains := ParseHostsFile(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net", "spaced.com", "uppercase.com"}

	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}

	expectedMap := make(map[string]bool, len(expected))
	for _, d := range expected {
		expectedMap[d] = false
	}
	for _, d := range domains {
		if _, ok := expectedMap[d]; !ok {
			t.Errorf("unexpected domain %q", d)
		} else {
			expectedMap[d] = true
		}
	}
	for d, found := range expectedMap {
		if !found {
			t.Errorf("missing expected domain %q", d)
		}
	}
}

func TestParseHostsFileSkipsLocalEntries(t *testing.T) {
	locals := []string{
		"localhost", "localhost.localdomain", "local", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-localnet",
		"ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
	}

	var sb strings.Builder
	for _, local := range locals {
		sb.WriteString("0.0.0.0 " + local + "\n")
	}
	// Add one real domain to verify parsing still works.
	sb.WriteString("0.0.0.0 real.domain.com\n")

	domains := ParseHostsFile(strings.NewReader(sb.String()))
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d: %v", len(domains), domains)
	}
	if domains[0] != "real.domain.com" {
		t.Errorf("expected real.domain.com, got %q", domains[0])
	}
}

func TestParseDomainList(t *testing.T) {
	input := `# Domain blocklist
# Source: example.org

ads.example.com
tracker.net
malware.bad.org

# Another section
spyware.evil.net
`

	domains := ParseDomainList(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net", "malware.bad.org", "spyware.evil.net"}

	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}

	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseDomainListWithInlineComments(t *testing.T) {
	input := `ads.example.com # ad server
tracker.net#tracking pixel
  UPPERCASE.COM  # should be lowercased
! exclamation comment
`
	domains := ParseDomainList(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net", "uppercase.com"}
	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}
	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseABP(t *testing.T) {
	input := `[Adblock Plus 2.0]
! Title: Test Filter List
! Last modified: 2024-01-01

||ads.example.com^
||tracker.net^
||malware.bad.org^

! Element hiding rules (should be skipped)
##.ad-banner
example.com##.sidebar-ad

! Exception rules (should be skipped)
@@||safe.example.com^

! URL patterns with paths (should be skipped)
||example.com/ads^
||example.com/tracking/*^

! Rules without proper format (should be skipped)
example.com
|example.com^
||example.com
`

	domains := ParseABP(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net", "malware.bad.org"}

	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}

	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseABPSkipsPathsAndWildcards(t *testing.T) {
	input := `||ads.example.com^
||tracker.net/path^
||wild*.example.com^
||clean.org^
`

	domains := ParseABP(strings.NewReader(input))

	expected := []string{"ads.example.com", "clean.org"}
	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}
	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseABPCaseInsensitive(t *testing.T) {
	input := `||ADS.EXAMPLE.COM^
||Tracker.Net^
`

	domains := ParseABP(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net"}
	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}
	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseABPEmptyDomain(t *testing.T) {
	// "||^" has an empty domain between || and ^ -- should be skipped.
	input := "||^\n||valid.com^\n"
	domains := ParseABP(strings.NewReader(input))

	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1; domains = %v", len(domains), domains)
	}
	if domains[0] != "valid.com" {
		t.Errorf("domain = %q, want %q", domains[0], "valid.com")
	}
}

func TestParseABPBracketLines(t *testing.T) {
	input := `[Adblock Plus 2.0]
[some other header]
||real.domain.com^
`

	domains := ParseABP(strings.NewReader(input))
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1; domains = %v", len(domains), domains)
	}
	if domains[0] != "real.domain.com" {
		t.Errorf("got %q, want %q", domains[0], "real.domain.com")
	}
}

func TestParseEmptyInput(t *testing.T) {
	t.Run("hosts", func(t *testing.T) {
		domains := ParseHostsFile(strings.NewReader(""))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("domains", func(t *testing.T) {
		domains := ParseDomainList(strings.NewReader(""))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("abp", func(t *testing.T) {
		domains := ParseABP(strings.NewReader(""))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})
}

func TestParseOnlyComments(t *testing.T) {
	input := `# comment 1
# comment 2
! another comment
`

	t.Run("hosts", func(t *testing.T) {
		domains := ParseHostsFile(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("domains", func(t *testing.T) {
		domains := ParseDomainList(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("abp", func(t *testing.T) {
		domains := ParseABP(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})
}

func TestParseOnlyBlankLines(t *testing.T) {
	input := "\n\n\n\n"

	t.Run("hosts", func(t *testing.T) {
		domains := ParseHostsFile(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("domains", func(t *testing.T) {
		domains := ParseDomainList(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})

	t.Run("abp", func(t *testing.T) {
		domains := ParseABP(strings.NewReader(input))
		if len(domains) != 0 {
			t.Errorf("expected empty slice, got %v", domains)
		}
	})
}

func TestParseDomainListWindowsLineEndings(t *testing.T) {
	input := "ads.example.com\r\ntracker.net\r\n# comment\r\nmalware.org\r\n"
	domains := ParseDomainList(strings.NewReader(input))

	expected := []string{"ads.example.com", "tracker.net", "malware.org"}
	if len(domains) != len(expected) {
		t.Fatalf("got %d domains, want %d; domains = %v", len(domains), len(expected), domains)
	}
	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestParseHostsFileOnlyCommentsAndBlanks(t *testing.T) {
	input := `# just comments
# and blank lines

# nothing else
`
	domains := ParseHostsFile(strings.NewReader(input))
	if len(domains) != 0 {
		t.Errorf("expected empty slice, got %v", domains)
	}
}
