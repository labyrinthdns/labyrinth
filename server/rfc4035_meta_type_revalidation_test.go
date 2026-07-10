package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestHandler_UnstatusedMetaTypeCacheHitRevalidates pins the fix for the
// AD-bit-loss class affecting DNSKEY / DS / NS meta-type queries.
//
// The shared answer cache can hold entries for these types that were seeded by
// resolver-internal machinery rather than a validated client answer, and those
// entries carry an empty DNSSEC status:
//
//   - NS: cacheDelegation stores the parent-side delegation NS from a referral.
//   - DS / DNSKEY: QueryDNSSEC stores RRsets fetched for a trust-chain walk
//     with validation skipped.
//
// Serving such an entry to a direct client query drops the AD bit (and, for NS,
// the RRSIG) versus what a validating resolver should return. The handler now
// treats a DNSKEY/DS/NS cache hit with no DNSSEC status as a miss when a
// validator is active, forcing a validating resolution.
//
// The fixture uses a fail-fast resolver (unreachable upstream → SERVFAIL) so
// the two paths are distinguishable: an unstatused entry that is (wrongly)
// served yields NOERROR with the seeded record, whereas revalidation fail-fasts
// to SERVFAIL. The companion sub-test proves the bypass is tightly scoped: an
// entry WITH a "secure" status is still served straight from cache (NOERROR),
// so normal cached answers are untouched.
func TestHandler_UnstatusedMetaTypeCacheHitRevalidates(t *testing.T) {
	// Valid, packable RDATA per type so buildCacheResponse succeeds on the
	// served path (otherwise a pack failure would itself fall through to
	// resolution and mask what we are testing).
	dsRData := append([]byte{0x12, 0x34, 0x0D, 0x02}, make([]byte, 32)...) // keytag, alg13, SHA-256, 32B digest
	dnskeyRData := append([]byte{0x01, 0x00, 0x03, 0x0D}, make([]byte, 32)...)
	metaTypes := []struct {
		name  string
		typ   uint16
		rdata []byte
	}{
		{"NS", dns.TypeNS, []byte{0x01, 'n', 0x00}}, // wire name "n."
		{"DS", dns.TypeDS, dsRData},
		{"DNSKEY", dns.TypeDNSKEY, dnskeyRData},
	}

	newRR := func(typ uint16, rdata []byte) dns.ResourceRecord {
		return dns.ResourceRecord{
			Name: "zone.example.com", Type: typ, Class: dns.ClassIN,
			TTL: 300, RDLength: uint16(len(rdata)), RData: rdata,
		}
	}

	for _, mt := range metaTypes {
		t.Run(mt.name+"/unstatused-is-revalidated", func(t *testing.T) {
			m := metrics.NewMetrics()
			c := cache.NewCache(1000, 5, 86400, 3600, m)
			// Empty DNSSEC status, as cacheDelegation / QueryDNSSEC leave it.
			c.Store("zone.example.com", mt.typ, dns.ClassIN, []dns.ResourceRecord{newRR(mt.typ, mt.rdata)}, nil)

			res := newFailFastResolver(c, m)
			res.EnableDNSSEC(discardLogger())
			h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

			query := buildTestQueryWithEDNS("zone.example.com", mt.typ, 4096)
			resp, err := h.Handle(query, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			msg, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if msg.Header.RCODE() != dns.RCodeServFail {
				t.Errorf("%s: an unstatused cache entry was served (rcode=%d) instead of "+
					"being revalidated — a validator is active, so the stale entry must be a miss",
					mt.name, msg.Header.RCODE())
			}
		})

		t.Run(mt.name+"/secure-status-still-served-from-cache", func(t *testing.T) {
			m := metrics.NewMetrics()
			c := cache.NewCache(1000, 5, 86400, 3600, m)
			// A properly validated entry (status "secure") must NOT be bypassed.
			c.StoreWithStatus("zone.example.com", mt.typ, dns.ClassIN, []dns.ResourceRecord{newRR(mt.typ, mt.rdata)}, nil, "secure")

			res := newFailFastResolver(c, m)
			res.EnableDNSSEC(discardLogger())
			h := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

			query := buildTestQueryWithEDNS("zone.example.com", mt.typ, 4096)
			resp, err := h.Handle(query, nil)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			msg, err := dns.Unpack(resp)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			// Served from cache (fail-fast resolver would SERVFAIL); NOERROR
			// with AD proves the secure entry was NOT bypassed.
			if msg.Header.RCODE() != dns.RCodeNoError {
				t.Errorf("%s: a secure cache entry was wrongly bypassed (rcode=%d), want NOERROR served from cache",
					mt.name, msg.Header.RCODE())
			}
			if !msg.Header.AD() {
				t.Errorf("%s: secure cache entry served without AD bit", mt.name)
			}
		})
	}
}
