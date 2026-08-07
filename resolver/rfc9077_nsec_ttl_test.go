package resolver

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 9077 "NSEC and NSEC3: TTLs and Aggressive Use" closes a hole opened by
// RFC 8198. Aggressive use lets a resolver answer NXDOMAIN for names it never
// asked about, purely because a cached NSEC/NSEC3 record proves the gap they
// fall in is empty. RFC 8198 §5.1 originally bounded that synthesis by the
// RFC 2308 negative TTL — min(SOA RR TTL, SOA.MINIMUM) — and said nothing
// about the TTL of the NSEC record itself.
//
// That is the bug. The SOA-derived TTL and the NSEC record's own TTL are two
// independent numbers on the wire. A signer that publishes NSEC records with
// a *shorter* TTL than the SOA implies is telling every resolver "this proof
// goes stale sooner than the zone's negative TTL". A resolver that ignores
// the shorter number keeps synthesising NXDOMAIN from a proof the zone owner
// already retired — so a name created right after the NSEC expired stays
// invisible for the remainder of the longer SOA window. RFC 9077 §4 rewrites
// RFC 8198 §5.1 to forbid exactly that.
//
// These tests pin the clamp at `aggressiveNegTTL`, the single point where the
// resolver decides how long an interval may live in the aggressive-use index.

// soaRDataWithMinimum builds SOA RDATA whose MINIMUM field is `minimum`.
// The other timers are fixed; only MINIMUM participates in negative TTL.
func soaRDataWithMinimum(minimum uint32) []byte {
	mname := dns.BuildPlainName("ns.example.com")
	rname := dns.BuildPlainName("admin.example.com")
	timers := make([]byte, 20)
	binary.BigEndian.PutUint32(timers[0:], 2026010101) // serial
	binary.BigEndian.PutUint32(timers[4:], 3600)       // refresh
	binary.BigEndian.PutUint32(timers[8:], 900)        // retry
	binary.BigEndian.PutUint32(timers[12:], 604800)    // expire
	binary.BigEndian.PutUint32(timers[16:], minimum)   // minimum

	rdata := append([]byte{}, mname...)
	rdata = append(rdata, rname...)
	return append(rdata, timers...)
}

func soaRR(ttl, minimum uint32) dns.ResourceRecord {
	return dns.ResourceRecord{
		Name:  "example.com",
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: soaRDataWithMinimum(minimum),
	}
}

func denialRR(rrtype uint16, ttl uint32) dns.ResourceRecord {
	return dns.ResourceRecord{
		Name:  "a.example.com",
		Type:  rrtype,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: []byte{0x00},
	}
}

// TestRFC9077_NSECTTLClampsAggressiveSynthesis pins RFC 9077 §4: when the
// NSEC record's TTL is shorter than the RFC 2308 negative TTL, the shorter
// value wins. Before this clamp the resolver registered the interval for the
// full SOA-derived 3600s while the proof itself expired at 300s.
func TestRFC9077_NSECTTLClampsAggressiveSynthesis(t *testing.T) {
	authority := []dns.ResourceRecord{
		soaRR(3600, 3600),           // RFC 2308 negative TTL = 3600
		denialRR(dns.TypeNSEC, 300), // but the proof is only good for 300
	}

	got := aggressiveNegTTL(authority, dns.TypeNSEC)
	if got != 300 {
		t.Fatalf("aggressiveNegTTL = %d, want 300 (clamped by NSEC TTL per RFC 9077 §4)", got)
	}

	// The RFC 2308 base is unchanged — the clamp is additive, not a
	// replacement. If this drifts, the negative *cache* would start
	// disagreeing with the aggressive index for the same response.
	if base := minNegativeTTL(authority); base != 3600 {
		t.Fatalf("minNegativeTTL = %d, want 3600 (RFC 2308 §5 base must be untouched)", base)
	}
}

// TestRFC9077_NSEC3TTLClampedIndependently pins that the clamp is computed
// per denial type. NSEC and NSEC3 feed two separate indices registered with
// two separate TTLs; sharing one number would let an NSEC3 record's TTL
// tighten an NSEC interval it has nothing to do with (or vice versa).
func TestRFC9077_NSEC3TTLClampedIndependently(t *testing.T) {
	authority := []dns.ResourceRecord{
		soaRR(3600, 3600),
		denialRR(dns.TypeNSEC3, 120),
	}

	if got := aggressiveNegTTL(authority, dns.TypeNSEC3); got != 120 {
		t.Fatalf("NSEC3 aggressiveNegTTL = %d, want 120", got)
	}

	// No NSEC records present: the NSEC index must fall back to the RFC 2308
	// base rather than borrowing the NSEC3 record's 120s.
	if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 3600 {
		t.Fatalf("NSEC aggressiveNegTTL = %d, want 3600 (no NSEC records to clamp against)", got)
	}
}

// TestRFC9077_ShortestDenialRecordWins pins that a multi-record proof is only
// as fresh as its weakest link. An NXDOMAIN proof carries up to three NSEC
// records (closest encloser, next closer, wildcard); synthesis must stop when
// the first of them expires, not the last.
func TestRFC9077_ShortestDenialRecordWins(t *testing.T) {
	authority := []dns.ResourceRecord{
		soaRR(3600, 3600),
		denialRR(dns.TypeNSEC, 900),
		denialRR(dns.TypeNSEC, 60), // shortest — bounds the whole proof
		denialRR(dns.TypeNSEC, 600),
	}

	if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 60 {
		t.Fatalf("aggressiveNegTTL = %d, want 60 (shortest NSEC in the proof)", got)
	}
}

// TestRFC9077_ConformingZoneUnaffected pins that the clamp is a no-op for a
// zone that follows RFC 9077 §3, which requires signers to publish NSEC TTLs
// equal to min(SOA TTL, SOA.MINIMUM). Almost every signed zone on the
// Internet is in this shape, so a regression here would be a silent global
// cache-hit-rate loss rather than a visible failure.
func TestRFC9077_ConformingZoneUnaffected(t *testing.T) {
	authority := []dns.ResourceRecord{
		soaRR(3600, 300),            // RFC 2308 negative TTL = 300
		denialRR(dns.TypeNSEC, 300), // signer did the right thing
	}

	if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 300 {
		t.Fatalf("aggressiveNegTTL = %d, want 300 (conforming zone must not be tightened)", got)
	}
}

// TestRFC9077_LongerNSECTTLDoesNotExtend pins the direction of the clamp. An
// NSEC TTL *longer* than the SOA-derived negative TTL must not raise the
// ceiling — RFC 2308 §5 still caps the answer. Getting the comparison
// backwards would turn a hardening fix into a cache-poisoning amplifier.
func TestRFC9077_LongerNSECTTLDoesNotExtend(t *testing.T) {
	authority := []dns.ResourceRecord{
		soaRR(300, 300),               // RFC 2308 negative TTL = 300
		denialRR(dns.TypeNSEC, 86400), // signer over-published
	}

	if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 300 {
		t.Fatalf("aggressiveNegTTL = %d, want 300 (NSEC TTL must never extend the RFC 2308 cap)", got)
	}
}

// TestRFC9077_HostileTTLsSanitized pins the RFC 2181 §8 guard on both TTL
// sources now feeding this path. TTLs with the top bit set MUST be treated
// as zero; the negative *cache* has always done this (sanitizeWireTTL) but
// the aggressive-use path did not, so a hostile authoritative could pin a
// synthesised denial for ~68 years while the ordinary negative cache
// correctly refused the same value.
func TestRFC9077_HostileTTLsSanitized(t *testing.T) {
	t.Run("SOA RR TTL", func(t *testing.T) {
		authority := []dns.ResourceRecord{soaRR(0x80000001, 3600)}
		if got := minNegativeTTL(authority); got != 0 {
			t.Fatalf("minNegativeTTL = %d, want 0 for MSB-set SOA TTL (RFC 2181 §8)", got)
		}
	})

	t.Run("SOA MINIMUM", func(t *testing.T) {
		authority := []dns.ResourceRecord{soaRR(3600, 0x80000001)}
		if got := minNegativeTTL(authority); got != 0 {
			t.Fatalf("minNegativeTTL = %d, want 0 for MSB-set SOA.MINIMUM (RFC 2181 §8)", got)
		}
	})

	t.Run("NSEC RR TTL", func(t *testing.T) {
		authority := []dns.ResourceRecord{
			soaRR(3600, 3600),
			denialRR(dns.TypeNSEC, 0x80000001),
		}
		if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 0 {
			t.Fatalf("aggressiveNegTTL = %d, want 0 for MSB-set NSEC TTL (RFC 2181 §8)", got)
		}
	})
}

// TestRFC9077_NoSOAMeansNoRegistration pins the "do not register" contract.
// aggressiveNegTTL returning 0 is what stops resolver.go from calling
// RegisterNSECInterval at all; a non-zero fallback here would register an
// interval with no authenticated negative TTL behind it.
func TestRFC9077_NoSOAMeansNoRegistration(t *testing.T) {
	authority := []dns.ResourceRecord{denialRR(dns.TypeNSEC, 300)}

	if got := aggressiveNegTTL(authority, dns.TypeNSEC); got != 0 {
		t.Fatalf("aggressiveNegTTL = %d, want 0 when no SOA is present", got)
	}
}
