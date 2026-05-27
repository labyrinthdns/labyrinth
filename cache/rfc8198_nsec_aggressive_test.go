package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// buildNSECRData encodes a minimal NSEC RDATA whose next-domain field is
// `next` and whose type bitmap is empty. The bitmap content does not
// matter for interval-coverage tests — the lookup is purely on
// (owner, next) range.
func buildNSECRData(t *testing.T, next string) []byte {
	t.Helper()
	encoded, err := dns.EncodeNameToBytes(next)
	if err != nil {
		t.Fatalf("EncodeNameToBytes(%q): %v", next, err)
	}
	return encoded
}

func soaForZone(zone string, ttl uint32, minimum uint32) dns.ResourceRecord {
	// 20 + 2*len("ns.zone") for primary+admin names — but for these unit
	// tests we don't actually parse the SOA contents (zone is taken from
	// rr.Name); only the TTL and Minimum fields end up driving expiry.
	// Build a minimal-but-valid RDATA: zero-length names + 5 uint32s.
	rdata := []byte{0x00, 0x00} // empty primary + admin names
	rdata = append(rdata,
		// SERIAL
		0, 0, 0, 1,
		// REFRESH, RETRY, EXPIRE — placeholder
		0, 0, 0, 60,
		0, 0, 0, 60,
		0, 0, 1, 0,
	)
	// MINIMUM
	rdata = append(rdata,
		byte(minimum>>24), byte(minimum>>16), byte(minimum>>8), byte(minimum),
	)
	return dns.ResourceRecord{
		Name: zone, Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: ttl, RDLength: uint16(len(rdata)), RData: rdata,
	}
}

// TestLookupNSECCovers_SynthesizesNXDOMAINInGap pins the Y17 fix to
// RFC 8198 §5.4: a Secure NSEC range previously cached as part of a
// signed NXDOMAIN proof MUST be reusable to synthesise NXDOMAIN for any
// OTHER name strictly between the NSEC's owner and next-domain fields.
// Big win for popular signed zones (.com, .org, ccTLDs) hit by garbage-
// subdomain traffic: the same gap interval covers many unrelated dead
// names, so cache hit rate climbs sharply and the auth load drops.
func TestLookupNSECCovers_SynthesizesNXDOMAINInGap(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	// Cache an NSEC interval for example.com proving the gap (foo, hop)
	// — names like "g.example.com" or "h.example.com" fall in this gap.
	nsec := dns.ResourceRecord{
		Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RData: buildNSECRData(t, "hop.example.com"),
	}
	nsec.RDLength = uint16(len(nsec.RData))
	auth := []dns.ResourceRecord{soaForZone("example.com", 600, 300), nsec}

	c.RegisterNSECInterval("example.com", 300, auth)

	// Probe a name that falls in (foo, hop): "h.example.com" canonical
	// order is alphabetically between foo and hop.
	got, ok := c.LookupNSECCovers("h.example.com", dns.ClassIN)
	if !ok {
		t.Fatal("LookupNSECCovers should synthesise NXDOMAIN for name in (foo, hop) gap")
	}
	if got.RCODE != dns.RCodeNXDomain {
		t.Errorf("synth RCODE: want NXDOMAIN, got %d", got.RCODE)
	}
	if !got.Negative || got.NegType != NegNXDomain {
		t.Errorf("synth must be marked negative+NXDOMAIN; got Negative=%v NegType=%d",
			got.Negative, got.NegType)
	}
	if got.DNSSECStatus != "secure" {
		t.Errorf("synthesised entry must carry DNSSECStatus=secure so server sets AD; got %q",
			got.DNSSECStatus)
	}
	if len(got.Authority) == 0 {
		t.Error("synthesised entry must carry authority RRs (SOA+NSEC+RRSIG) for downstream validators")
	}
}

// TestLookupNSECCovers_DoesNotSynthesizeForExistingOwner is the negative
// counterpart: a name that equals the NSEC owner itself does NOT fall in
// the open interval (owner, next) — it sorts equal to the owner. Same
// for the next-domain field. Synthesizing for those names would be a
// false NXDOMAIN.
func TestLookupNSECCovers_DoesNotSynthesizeForExistingOwner(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	nsec := dns.ResourceRecord{
		Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RData: buildNSECRData(t, "hop.example.com"),
	}
	nsec.RDLength = uint16(len(nsec.RData))
	auth := []dns.ResourceRecord{soaForZone("example.com", 600, 300), nsec}
	c.RegisterNSECInterval("example.com", 300, auth)

	if _, ok := c.LookupNSECCovers("foo.example.com", dns.ClassIN); ok {
		t.Error("must not synthesise NXDOMAIN for NSEC owner itself — that name DOES exist")
	}
	if _, ok := c.LookupNSECCovers("hop.example.com", dns.ClassIN); ok {
		t.Error("must not synthesise NXDOMAIN for NSEC next-domain — that name exists too")
	}
}

// TestLookupNSECCovers_DoesNotCrossZoneBoundary checks that a cached
// interval in zone X does NOT synthesise NXDOMAIN for names outside X.
// Otherwise an interval in (e.g.) com → org could "prove" arbitrary
// nonexistence across zones.
func TestLookupNSECCovers_DoesNotCrossZoneBoundary(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	nsec := dns.ResourceRecord{
		Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RData: buildNSECRData(t, "hop.example.com"),
	}
	nsec.RDLength = uint16(len(nsec.RData))
	auth := []dns.ResourceRecord{soaForZone("example.com", 600, 300), nsec}
	c.RegisterNSECInterval("example.com", 300, auth)

	// "h.different.org" is not under example.com → must not synth.
	if _, ok := c.LookupNSECCovers("h.different.org", dns.ClassIN); ok {
		t.Error("must not synthesise NXDOMAIN for name outside the registered zone")
	}
}

// TestLookupNSECCovers_RespectsExpiry: once the cached interval's TTL
// has elapsed, no synthesis should happen.
func TestLookupNSECCovers_RespectsExpiry(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	nsec := dns.ResourceRecord{
		Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RData: buildNSECRData(t, "hop.example.com"),
	}
	nsec.RDLength = uint16(len(nsec.RData))
	auth := []dns.ResourceRecord{soaForZone("example.com", 1, 1), nsec}

	// negTTL=1 second → expires almost immediately.
	c.RegisterNSECInterval("example.com", 1, auth)

	// Wait beyond the TTL.
	time.Sleep(1100 * time.Millisecond)

	if _, ok := c.LookupNSECCovers("h.example.com", dns.ClassIN); ok {
		t.Error("expired NSEC interval must not be used for synthesis")
	}
}

// TestStaleMaxAge_RejectsOldStaleEntry pins the Y18 fix to RFC 8767 §3.3:
// an entry that expired more than `staleMaxAge` seconds ago must NOT be
// served stale even when the physical record still occupies the cache.
// Otherwise a long-tail name accessed once and then six months later
// would be served with month-old data — exactly the failure mode the
// RFC's 1-3 day recommendation guards against.
func TestStaleMaxAge_RejectsOldStaleEntry(t *testing.T) {
	m := metrics.NewMetrics()
	// staleTTL=30s served-record TTL; staleMaxAge=60s past-expiry cap.
	c := NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)
	c.SetStaleMaxAge(60)

	c.Store("x.example.com", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{{
			Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 5, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}}, nil)

	// Forcibly age the entry: roll back InsertedAt so it is "expired 120s
	// ago" (way past staleMaxAge=60).
	c.shards[c.shardIndex("x.example.com")].mu.Lock()
	for _, e := range c.shards[c.shardIndex("x.example.com")].entries {
		e.InsertedAt = time.Now().Add(-125 * time.Second) // OrigTTL=5 → expired 120s ago
	}
	c.shards[c.shardIndex("x.example.com")].mu.Unlock()

	if _, ok := c.GetStale("x.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("stale entry expired >staleMaxAge ago must NOT be served (RFC 8767 §3.3)")
	}
}

// TestStaleMaxAge_AllowsRecentlyExpiredEntry is the positive control: an
// entry just past expiry but within staleMaxAge must still serve.
func TestStaleMaxAge_AllowsRecentlyExpiredEntry(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)
	c.SetStaleMaxAge(86400)

	c.Store("y.example.com", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{{
			Name: "y.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 5, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}}, nil)

	// Expired 10s ago — well within 1-day cap.
	c.shards[c.shardIndex("y.example.com")].mu.Lock()
	for _, e := range c.shards[c.shardIndex("y.example.com")].entries {
		e.InsertedAt = time.Now().Add(-15 * time.Second) // OrigTTL=5 → expired 10s ago
	}
	c.shards[c.shardIndex("y.example.com")].mu.Unlock()

	if _, ok := c.GetStale("y.example.com", dns.TypeA, dns.ClassIN); !ok {
		t.Error("recently expired stale entry within cap MUST still serve")
	}
}

// TestStaleMaxAge_ZeroDisablesCap: setting staleMaxAge=0 restores the
// pre-RFC-8767-cap behaviour (unbounded). Documented for operators who
// explicitly want it.
func TestStaleMaxAge_ZeroDisablesCap(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)
	c.SetStaleMaxAge(0)

	c.Store("z.example.com", dns.TypeA, dns.ClassIN,
		[]dns.ResourceRecord{{
			Name: "z.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 5, RDLength: 4, RData: []byte{1, 2, 3, 4},
		}}, nil)

	c.shards[c.shardIndex("z.example.com")].mu.Lock()
	for _, e := range c.shards[c.shardIndex("z.example.com")].entries {
		e.InsertedAt = time.Now().Add(-10 * 365 * 24 * time.Hour) // ~10 years stale
	}
	c.shards[c.shardIndex("z.example.com")].mu.Unlock()

	if _, ok := c.GetStale("z.example.com", dns.TypeA, dns.ClassIN); !ok {
		t.Error("with staleMaxAge=0, ancient stale entries should still serve (cap disabled)")
	}
}
