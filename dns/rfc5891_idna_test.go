package dns

import "testing"

// IDNA2008 (RFC 5890–5894) at the human-facing boundary.
//
// The resolver never needed this: the DNS protocol has no Unicode, and a
// conforming stub converts before sending. The gap was the dashboard, where
// an operator pasting "müller.example" into the lookup box got a query for
// the literal UTF-8 octets — a name that exists nowhere, failing for a reason
// invisible in the string they typed.

// TestRFC5891_ToASCII pins the conversion, including the case that makes it
// worth having: the input looks like a domain name and is not one.
func TestRFC5891_ToASCII(t *testing.T) {
	cases := []struct{ in, want string }{
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"münchen.de.", "xn--mnchen-3ya.de."}, // trailing dot preserved
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},
		{"example.com", "example.com"}, // pure ASCII unchanged
		{"EXAMPLE.COM", "EXAMPLE.COM"}, // ASCII case left to the caller
		{"", ""},
	}
	for _, tc := range cases {
		if got := ToASCII(tc.in); got != tc.want {
			t.Errorf("ToASCII(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRFC5891_NonTransitional pins the profile choice. IDNA2008 has two
// dispositions for ß, ς and the zero-width joiners, inherited from the
// IDNA2003 transition. Transitional processing maps ß to "ss", making
// "faß.example" and "fass.example" the same name — so a dashboard using the
// transitional profile would silently look up a different domain than the one
// typed. Non-transitional is what IDNA2008 specifies and what browsers use.
func TestRFC5891_NonTransitional(t *testing.T) {
	got := ToASCII("faß.example")
	if got == "fass.example" {
		t.Fatal("ß was mapped to 'ss' — that is IDNA2003 transitional processing, " +
			"and it silently resolves a different domain than the operator typed")
	}
	const want = "xn--fa-hia.example"
	if got != want {
		t.Errorf("ToASCII(\"faß.example\") = %q, want %q", got, want)
	}
}

// TestRFC5891_ToUnicode pins the display direction.
func TestRFC5891_ToUnicode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"xn--mnchen-3ya.de", "münchen.de"},
		{"xn--mnchen-3ya.de.", "münchen.de."},
		{"example.com", "example.com"}, // no A-label, untouched
		{"", ""},
	}
	for _, tc := range cases {
		if got := ToUnicode(tc.in); got != tc.want {
			t.Errorf("ToUnicode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRFC5891_RoundTrip pins that a name survives both directions.
func TestRFC5891_RoundTrip(t *testing.T) {
	for _, name := range []string{"münchen.de", "例え.テスト", "example.com"} {
		if got := ToUnicode(ToASCII(name)); got != name {
			t.Errorf("round trip of %q produced %q", name, got)
		}
	}
}

// TestRFC5891_UnconvertibleInputPassesThrough pins the failure policy. A name
// that cannot be converted is returned unchanged rather than replaced with an
// error: the caller is about to look it up, and letting the resolver reject it
// and say why is more useful than substituting a message that hides what was
// actually asked for.
func TestRFC5891_UnconvertibleInputPassesThrough(t *testing.T) {
	// A lone combining mark cannot begin a label under IDNA2008 §4.2.3.2.
	const bad = "́bad.example"
	if got := ToASCII(bad); got != bad {
		t.Errorf("ToASCII(%q) = %q, want the input unchanged", bad, got)
	}
}

// TestRFC5891_ASCIIFastPath pins that pure-ASCII names skip conversion
// entirely. This is the overwhelming majority of lookups, and it runs on every
// dashboard query.
func TestRFC5891_ASCIIFastPath(t *testing.T) {
	// An ASCII string that IDNA's own validation would reject (underscore is
	// disallowed by the lookup profile) must still pass through: underscore
	// labels are ubiquitous in the real DNS (_dmarc, _acme-challenge,
	// _dns.resolver.arpa) and rejecting them would break the dashboard for
	// the names operators most often need to inspect.
	const underscored = "_acme-challenge.example.com"
	if got := ToASCII(underscored); got != underscored {
		t.Errorf("ToASCII(%q) = %q — underscore labels must pass through", underscored, got)
	}
}
