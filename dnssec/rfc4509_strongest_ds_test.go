package dnssec

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestStrongestDSDigestForKey_SHA256BeatsSHA1 pins the Y12 fix to RFC 4509
// §3 / RFC 6840 §5.2: when the parent zone publishes multiple DS RRs for
// the same key tag + algorithm with different digest types, the validator
// MUST use the strongest supported digest and ignore weaker siblings. The
// digest-type numbering was assigned in ascending strength (1=SHA-1,
// 2=SHA-256, 4=SHA-384), so the helper returns the max over the supported
// subset. A SHA-1 collision against the same key MUST NOT validate when a
// SHA-256 DS is also present — that's the whole point of the rule.
func TestStrongestDSDigestForKey_SHA256BeatsSHA1(t *testing.T) {
	v := &Validator{allowSHA1: true} // accept SHA1 by policy
	dsList := []*dns.DSRecord{
		{KeyTag: 1234, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA1, Digest: []byte{0x01}},
		{KeyTag: 1234, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA256, Digest: []byte{0x02}},
	}
	got := strongestDSDigestForKey(dsList, 1234, dns.AlgECDSAP256, v)
	if got != dns.DigestSHA256 {
		t.Errorf("with both SHA1 and SHA256 DS present, want strongest=SHA256(%d), got %d",
			dns.DigestSHA256, got)
	}
}

// TestStrongestDSDigestForKey_SHA384BeatsSHA256 confirms the ordering
// continues to favour the higher digest-type number (SHA-384=4 > SHA-256=2).
func TestStrongestDSDigestForKey_SHA384BeatsSHA256(t *testing.T) {
	v := &Validator{}
	dsList := []*dns.DSRecord{
		{KeyTag: 9, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA256, Digest: []byte{0x02}},
		{KeyTag: 9, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA384, Digest: []byte{0x04}},
	}
	got := strongestDSDigestForKey(dsList, 9, dns.AlgECDSAP256, v)
	if got != dns.DigestSHA384 {
		t.Errorf("with both SHA256 and SHA384 DS present, want strongest=SHA384(%d), got %d",
			dns.DigestSHA384, got)
	}
}

// TestStrongestDSDigestForKey_OnlyWeakReturnsZeroWhenWeakRejected: when
// the policy refuses SHA-1 and SHA-1 is the only digest present for the
// key, the function returns 0 — caller's verify loop falls through and
// the key is treated as having no DS chain (Indeterminate).
func TestStrongestDSDigestForKey_OnlyWeakReturnsZeroWhenWeakRejected(t *testing.T) {
	v := &Validator{allowSHA1: false}
	dsList := []*dns.DSRecord{
		{KeyTag: 7, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA1, Digest: []byte{0x01}},
	}
	got := strongestDSDigestForKey(dsList, 7, dns.AlgRSASHA256, v)
	if got != 0 {
		t.Errorf("only SHA-1 DS with allowSHA1=false should return 0, got %d", got)
	}
}

// TestStrongestDSDigestForKey_IgnoresUnrelatedKeys: a DS record for a
// DIFFERENT key tag or algorithm must not influence the selection for
// the key we're asking about. Otherwise an attacker can mix
// (keytag=A, SHA256) with (keytag=B, SHA1) and trick the validator into
// thinking B's SHA-1 was the strongest for A.
func TestStrongestDSDigestForKey_IgnoresUnrelatedKeys(t *testing.T) {
	v := &Validator{allowSHA1: true}
	dsList := []*dns.DSRecord{
		{KeyTag: 100, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA256, Digest: []byte{0x02}},
		{KeyTag: 200, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA1, Digest: []byte{0x01}},
	}
	// Asking about key 200: only its own DS counts → SHA1.
	got := strongestDSDigestForKey(dsList, 200, dns.AlgECDSAP256, v)
	if got != dns.DigestSHA1 {
		t.Errorf("for key 200 with only a SHA1 DS, want %d, got %d", dns.DigestSHA1, got)
	}
	// Asking about key 100: only its own DS counts → SHA256.
	got = strongestDSDigestForKey(dsList, 100, dns.AlgECDSAP256, v)
	if got != dns.DigestSHA256 {
		t.Errorf("for key 100 with only a SHA256 DS, want %d, got %d", dns.DigestSHA256, got)
	}
}
