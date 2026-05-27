package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestExtractNegativeTTL_TakesMinimumOfRRTTLAndSOAMinimum pins Y47:
// RFC 2308 §5 says the TTL of a cached negative answer "MUST be the
// MINIMUM of the SOA.MINIMUM field and the TTL of the SOA RR itself."
// A bug in either direction is silent and dangerous:
//   - taking the MAX would let an authoritative server with a small
//     MINIMUM field accidentally extend the negative-cache horizon
//     beyond its intended one (re-asking would be late after a fix)
//   - taking only the RR TTL would ignore the operator-curated MINIMUM
//     and over-cache negatives that the zone owner wants short
//   - taking only MINIMUM would ignore the RR TTL the operator may
//     have set tighter in a specific response
//
// Cache constructed with minTTL=1 and a generous negMaxTTL so the
// clamp does not interfere with the §5 minimum-of-two semantics.
func TestExtractNegativeTTL_TakesMinimumOfRRTTLAndSOAMinimum(t *testing.T) {
	for _, c := range []struct {
		name      string
		rrTTL     uint32
		soaMin    uint32
		wantTTL   uint32
	}{
		{"SOA.Minimum < RR TTL — Minimum wins", 3600, 600, 600},
		{"RR TTL < SOA.Minimum — RR TTL wins", 100, 1800, 100},
		{"equal values — that value", 500, 500, 500},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := metrics.NewMetrics()
			// minTTL=1 + negMaxTTL=86400 ensures clampNegativeTTL is a no-op
			// for the values we test — the truth being pinned is §5, not
			// the operator clamps.
			ca := NewCache(1000, 1, 86400, 86400, m)

			soaRR := dns.ResourceRecord{
				Name:     "zone.example.",
				Type:     dns.TypeSOA,
				Class:    dns.ClassIN,
				TTL:      c.rrTTL,
				RDLength: 0, // filled below
				RData:    buildSOAWithMinimum(t, c.soaMin),
			}
			soaRR.RDLength = uint16(len(soaRR.RData))

			ca.StoreNegative("missing.zone.example.", dns.TypeA, dns.ClassIN,
				NegNXDomain, dns.RCodeNXDomain, []dns.ResourceRecord{soaRR})

			entry, ok := ca.Lookup("missing.zone.example.", 0, dns.ClassIN)
			if !ok {
				t.Fatalf("negative entry was not stored")
			}
			if entry.OrigTTL != c.wantTTL {
				t.Errorf("cached negative TTL = %d, want %d (RFC 2308 §5 minimum-of-two)",
					entry.OrigTTL, c.wantTTL)
			}
		})
	}
}

// TestExtractNegativeTTL_NoSOA_FallsBackToConstant pins the secondary
// invariant: a negative response that arrives WITHOUT an SOA (some
// upstreams misbehave) still gets a sane cached TTL via a fallback
// constant — not zero (which would mean "do not cache" per §4) and not
// infinity (which would lock in a bad answer). Without this pin a
// refactor of extractNegativeTTL could quietly return 0 on the no-SOA
// path and silently disable negative caching for every misbehaving
// upstream.
func TestExtractNegativeTTL_NoSOA_FallsBackToConstant(t *testing.T) {
	m := metrics.NewMetrics()
	ca := NewCache(1000, 1, 86400, 86400, m)

	// No SOA in authority — just a stray NS record (representative of a
	// misformatted upstream).
	ca.StoreNegative("nosoa.example.", dns.TypeA, dns.ClassIN, NegNXDomain,
		dns.RCodeNXDomain, []dns.ResourceRecord{{
			Name:  "example.",
			Type:  dns.TypeNS,
			Class: dns.ClassIN,
			TTL:   3600,
		}})

	entry, ok := ca.Lookup("nosoa.example.", 0, dns.ClassIN)
	if !ok {
		t.Fatalf("negative entry was not stored — fallback TTL must keep this cacheable")
	}
	if entry.OrigTTL == 0 {
		t.Errorf("fallback negative TTL = 0 (disables caching on every misbehaving upstream)")
	}
	if entry.OrigTTL > 3600 {
		t.Errorf("fallback negative TTL = %d, too generous (RFC 2308 §5 — unknown means short)", entry.OrigTTL)
	}
}
