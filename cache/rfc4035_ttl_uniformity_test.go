package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// TestWithDecayedTTL_RRsetAndRRSIGShareDecayedTTL pins RFC 4035 §3.1.3
// + RFC 2181 §5.2: every RR in an RRset MUST have the same TTL, AND
// the RRSIG that signs the RRset MUST have the same TTL as the RRset
// it covers. A downstream validating stub that sees an A record at
// TTL=240 alongside its RRSIG at TTL=300 (because cache decay was
// non-uniform) treats this as a TTL violation and may either:
//   - reject the response (paranoid validator), OR
//   - propagate the inconsistent TTLs to its own cache, where they
//     resync to whichever value came first — silent data inconsistency.
//
// The cache decays an entry uniformly via WithDecayedTTL: every record
// in `entry.Records` and `entry.Authority` is rewritten to the same
// `remaining` value. A regression that decayed Records but left
// Authority alone (or decayed by-type rather than uniformly) would
// produce the mixed-TTL pathology above.
//
// We pin: an entry with an A record (TTL=300), a covering RRSIG
// (TTL=300), and an NSEC in Authority (TTL=300) — after WithDecayedTTL(42)
// every TTL is exactly 42.
func TestWithDecayedTTL_RRsetAndRRSIGShareDecayedTTL(t *testing.T) {
	entry := &Entry{
		Records: []dns.ResourceRecord{
			{Name: "y89.example.com", Type: dns.TypeA, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1}},
			{Name: "y89.example.com", Type: dns.TypeRRSIG, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
		Authority: []dns.ResourceRecord{
			{Name: "example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
				TTL: 300, RDLength: 4, RData: []byte{0x00, 0x00, 0x00, 0x00}},
		},
		OrigTTL: 300,
	}

	const remaining = uint32(42)
	decayed := entry.WithDecayedTTL(remaining)

	for i, rr := range decayed.Records {
		if rr.TTL != remaining {
			t.Errorf("Records[%d] (type=%d) TTL = %d, want %d — RFC 4035 §3.1.3: RRSIG and covered RRset MUST share TTL after decay",
				i, rr.Type, rr.TTL, remaining)
		}
	}
	for i, rr := range decayed.Authority {
		if rr.TTL != remaining {
			t.Errorf("Authority[%d] (type=%d) TTL = %d, want %d — authority records (NSEC/SOA/NS) must decay alongside answer section",
				i, rr.Type, rr.TTL, remaining)
		}
	}

	// Mutating the decayed copy must NOT touch the original entry.
	decayed.Records[0].TTL = 999
	if entry.Records[0].TTL == 999 {
		t.Errorf("WithDecayedTTL aliased Records slice — mutation leaked back to the cached entry; concurrent callers would see corrupted TTLs")
	}
}
