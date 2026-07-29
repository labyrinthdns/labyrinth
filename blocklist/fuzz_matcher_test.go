package blocklist

import (
	"strings"
	"testing"
)

// FuzzRPZParser feeds arbitrary bytes to the RPZ zone parser.
// RPZ zone files contain owner, TTL, class, type, and RDATA fields
// separated by whitespace. The parser must handle pathological inputs
// (binary data, extra-long lines, severe abuse of RPZ directives) without
// panicking.
func FuzzRPZParser(f *testing.F) {
	// Seed with realistic RPZ zone content
	f.Add([]byte("example.com CNAME .\n*.example.com CNAME .\n"))
	f.Add([]byte("example.com CNAME rpz-passthru.\n"))
	f.Add([]byte("example.com A 10.0.0.1\n"))
	f.Add([]byte("example.com AAAA ::1\n"))
	f.Add([]byte("example.com CNAME rpz-drop.\n"))
	f.Add([]byte("example.com CNAME *.\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := strings.NewReader(string(data))
		rules, err := ParseRPZ(r)
		if err != nil {
			// Parse errors are expected for malformed input.
			return
		}
		// Build an RPZMatcher from the successfully parsed rules
		// to verify that every parseable rule can be loaded and
		// matched without panicking.
		m := NewRPZMatcher()
		for _, rule := range rules {
			m.AddRule(rule)
		}
		// Try matching a few query names against the populated matcher
		_ = m.Match("example.com")
		_ = m.Match("sub.example.com")
		_ = m.Match("evil.example.org")
	})
}

// FuzzDomainMatcher exercises the plain domain Matcher (non-RPZ) with
// arbitrary AddExact/AddWildcard/Match calls. The input is interpreted
// as alternating null-terminated domains for rule insertion and querying.
func FuzzDomainMatcher(f *testing.F) {
	f.Add([]byte("example.com\x00evil.com\x00test.example.com"))
	f.Add([]byte("\x00\x00"))
	f.Add([]byte(strings.Repeat("a", 300)))

	f.Fuzz(func(t *testing.T, data []byte) {
		m := NewMatcher()

		// Interpret the input as domains separated by null bytes.
		// Even-numbered domains are added as rules; odd-numbered
		// ones are queried. This exercises the matcher with
		// arbitrary strings including empty, very long, or binary.
		domains := strings.Split(string(data), "\x00")
		for i, domain := range domains {
			if domain == "" {
				continue
			}
			if i%2 == 0 {
				m.AddExact(domain)
				m.AddWildcard(domain)
			} else {
				// Match must not panic regardless of input.
				_ = m.Match(domain)
			}
		}

		// Always query with a few edge cases.
		_ = m.Match("")
		_ = m.Match(strings.Repeat("x", 500))
		_ = m.Match(".")
	})
}
