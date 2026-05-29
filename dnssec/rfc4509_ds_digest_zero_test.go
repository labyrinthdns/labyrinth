package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestIsWeakDSDigest_DigestZeroAlwaysRejected pins Y37: RFC 4509 §2.4
// / RFC 8624 §3.3 require digest type 0 (IANA-reserved) to be treated
// as unusable for DNSKEY authentication. Unlike SHA-1, the reject is
// UNCONDITIONAL — even an operator that opted into allowSHA1=true
// must not see digest 0 honoured (it's a reserved value, not a
// deprecated-but-functional one).
func TestIsWeakDSDigest_DigestZeroAlwaysRejected(t *testing.T) {
	v := &Validator{}
	if !v.isWeakDSDigest(dns.DigestReserved) {
		t.Error("digest type 0 must be weak by default")
	}

	// Opt into SHA-1: SHA-1 becomes acceptable, but digest 0 is STILL
	// weak — the §3.3 constraint is hard, not subject to the toggle.
	v.allowSHA1.Store(true)
	if !v.isWeakDSDigest(dns.DigestReserved) {
		t.Error("digest type 0 must remain weak even with allowSHA1=true (RFC 8624 §3.3 hard constraint)")
	}
	if v.isWeakDSDigest(dns.DigestSHA1) {
		t.Error("regression: digest SHA-1 should be acceptable when allowSHA1=true")
	}
}

// TestIsWeakDSDigest_NonZeroAcceptable: SHA-256 / SHA-384 are the
// RFC 8624 §3.3 "MUST"/"RECOMMENDED" digest types and must remain
// acceptable in both default and allowSHA1 modes.
func TestIsWeakDSDigest_NonZeroAcceptable(t *testing.T) {
	v := &Validator{}
	if v.isWeakDSDigest(dns.DigestSHA256) {
		t.Error("DigestSHA256 must be acceptable")
	}
	if v.isWeakDSDigest(dns.DigestSHA384) {
		t.Error("DigestSHA384 must be acceptable")
	}
}

// TestDigestReservedConstantValue regression-locks the IANA assignment:
// digest type 0 is reserved, so the constant must be 0. If someone
// renumbers it the §3.3 check breaks silently.
func TestDigestReservedConstantValue(t *testing.T) {
	if dns.DigestReserved != 0 {
		t.Errorf("DigestReserved = %d, want 0 (IANA reserved)", dns.DigestReserved)
	}
}
