package dnssec

import (
	"testing"
)

// TestCanonicalCompareName_RFC4034_Section6_1 pins the RFC 4034 §6.1
// canonical DNS name ordering — the foundation of every NSEC denial
// proof, every RRset canonical-form RRSIG, and every signed-zone hash
// in the resolver. A regression in this comparator silently breaks
// DNSSEC validation across the entire signed-name space:
//
//   - NSEC denial proofs depend on "qname falls within (owner, next)"
//     using exactly this ordering. Flip the comparator and every
//     NXDOMAIN proof either accepts forgeries (open gap inversion) or
//     rejects valid proofs (no-gap-found).
//   - Aggressive NSEC caching (RFC 8198) walks intervals using this
//     ordering. A regression makes the cache either miss legitimate
//     hits or — worse — synthesise NXDOMAIN for names that DO exist.
//
// RFC 4034 §6.1 ordering rules:
//   1. Compare labels right-to-left (TLD first).
//   2. Each label compared as a byte string (lowercased, RFC 4343).
//   3. Shorter prefix label sorts first when one is a prefix of the other.
//   4. A name with fewer labels sorts before a name with more labels
//      sharing the same suffix.
//
// We pin a five-case matrix exercising each rule plus the equality
// case and the cross-TLD case (rightmost label wins).
func TestCanonicalCompareName_RFC4034_Section6_1(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
		why  string
	}{
		{
			name: "identical names",
			a:    "example.com", b: "example.com",
			want: 0,
			why:  "reflexivity — required for the cache to dedupe NSEC owners",
		},
		{
			name: "different TLD: org < com? bytewise 'c'<'o' so com < org",
			a:    "example.com", b: "example.org",
			want: -1,
			why:  "rightmost label compared first; 'com' < 'org' bytewise",
		},
		{
			name: "shorter-suffix sorts first (a.com vs. www.a.com)",
			a:    "a.com", b: "www.a.com",
			want: -1,
			why:  "name with fewer labels sorts first when sharing a suffix — RFC 4034 §6.1 'shorter name sorts first'",
		},
		{
			name: "case-insensitive: WWW.example.com == www.example.com",
			a:    "WWW.example.com", b: "www.example.com",
			want: 0,
			why:  "RFC 4343 case-folding before byte compare",
		},
		{
			name: "same TLD, second label differs (alpha.com vs. beta.com)",
			a:    "alpha.com", b: "beta.com",
			want: -1,
			why:  "TLD ties, next label decides; 'a'<'b' bytewise",
		},
		{
			name: "byte ordering for digits-vs-letters in a label (alpha vs. 9names)",
			a:    "9names.com", b: "alpha.com",
			want: -1,
			why:  "ASCII '9' (0x39) < 'a' (0x61) — RFC 4034 §6.1 'each octet of each label is treated as an unsigned 8-bit value'",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := canonicalCompareName(c.a, c.b)
			if !sameSign(got, c.want) {
				t.Errorf("compare(%q, %q) = %d, want %d\nrationale: %s", c.a, c.b, got, c.want, c.why)
			}
			// Antisymmetry pin: compare(b, a) must be the negation.
			if sym := canonicalCompareName(c.b, c.a); !sameSign(sym, -c.want) {
				t.Errorf("antisymmetry violated: compare(%q,%q)=%d but compare(%q,%q)=%d", c.a, c.b, got, c.b, c.a, sym)
			}
		})
	}
}

// sameSign reports whether x and y have the same sign (counting 0 as
// matching only 0). The comparator may return any negative or positive
// int — we care about direction, not magnitude.
func sameSign(x, y int) bool {
	switch {
	case x < 0:
		return y < 0
	case x > 0:
		return y > 0
	default:
		return y == 0
	}
}
