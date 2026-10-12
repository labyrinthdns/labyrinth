package server

import (
	"encoding/binary"
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// nsecRDataFor builds NSEC RDATA: next-domain name + a type bitmap that
// lists only RRSIG(46) and NSEC(47). A is deliberately absent so the typed
// lookup can synthesise a denial for an A query.
func nsecRDataFor(t *testing.T, next string) []byte {
	t.Helper()
	rdata := dns.BuildPlainName(next)
	// Window 0, bitmap length 6 (covers type numbers 0..47).
	bitmap := []byte{0x00, 0x06, 0, 0, 0, 0, 0, 0xC0}
	return append(rdata, bitmap...)
}

func soaRDataFor(zone string, minimum uint32) []byte {
	rdata := dns.BuildPlainName("ns." + zone)
	rdata = append(rdata, dns.BuildPlainName("hostmaster."+zone)...)
	rdata = append(rdata,
		0, 0, 0, 1, // SERIAL
		0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 1, 0, // REFRESH RETRY EXPIRE
		byte(minimum>>24), byte(minimum>>16), byte(minimum>>8), byte(minimum),
	)
	return rdata
}

func simpleQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := &dns.Message{
		Header: dns.Header{
			ID:    0x4321,
			Flags: dns.NewFlagBuilder().SetRD(true).Build(),
		},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
	}
	buf := make([]byte, 512)
	packed, err := dns.Pack(msg, buf)
	if err != nil {
		t.Fatalf("pack %s: %v", name, err)
	}
	out := make([]byte, len(packed))
	copy(out, packed)
	return out
}

// TestHandle_AggressiveCacheHit_CountedOnce pins the contract that a
// query served from the cache increments the cache-hit counter exactly once,
// on every cache-serve path.
//
// Contract, established by the normal cache-hit path in Handle itself: the
// shared `if ok { h.metrics.IncCacheHits() ... }` block is the only place a
// cache-served query is counted. The RFC 8198 aggressive NSEC and NSEC3
// branches additionally call IncCacheHits() inside their own branch and then
// fall through to that same shared block, so an aggressive-NSEC-synthesised
// answer is counted twice.
//
// cacheHits feeds the operator-visible hit rate (/api/stats hit_rate, the
// dashboard, Zabbix labyrinth.cache.hit_ratio and the Prometheus cache_hits
// series), so double-counting overstates cache efficiency.
func TestHandle_AggressiveCacheHit_CountedOnce(t *testing.T) {
	m := metrics.NewMetrics()
	c := cache.NewCache(1000, 1, 86400, 3600, m)

	// A Secure NSEC interval proving the gap (foo, hop) for example.com,
	// so "h.example.com" must be synthesised NXDOMAIN from cache.
	nsecRD := nsecRDataFor(t, "hop.example.com.")
	nsec := dns.ResourceRecord{
		Name: "foo.example.com", Type: dns.TypeNSEC, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(nsecRD)), RData: nsecRD,
	}
	soaRD := soaRDataFor("example.com", 300)
	soa := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 300, RDLength: uint16(len(soaRD)), RData: soaRD,
	}
	c.RegisterNSECInterval("example.com", 300, []dns.ResourceRecord{soa, nsec})

	res := newFailFastResolver(c, m)
	handler := NewMainHandler(res, c, nil, nil, nil, m, discardLogger())

	client := &mockAddr{network: "udp", addr: "198.51.100.7:5353"}

	// CONTROL: an ordinary positive cache entry costs exactly one hit.
	c.Store("direct.example.com", dns.TypeA, dns.ClassIN, []dns.ResourceRecord{{
		Name: "direct.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{93, 184, 216, 34},
	}}, nil)

	before := m.Snapshot().CacheHits
	if _, err := handler.Handle(simpleQuery(t, "direct.example.com", dns.TypeA), client); err != nil {
		t.Fatalf("control query: %v", err)
	}
	controlDelta := m.Snapshot().CacheHits - before
	t.Logf("control: normal cache hit incremented CacheHits by %d", controlDelta)
	if controlDelta != 1 {
		t.Fatalf("control FAILED: normal cache hit counted %d times, want 1; harness is wrong", controlDelta)
	}

	// FAILING CASE: the aggressive NSEC-synthesised answer.
	before = m.Snapshot().CacheHits
	resp, err := handler.Handle(simpleQuery(t, "h.example.com", dns.TypeA), client)
	if err != nil {
		t.Fatalf("aggressive query: %v", err)
	}
	aggressiveDelta := m.Snapshot().CacheHits - before
	rcode := uint8(binary.BigEndian.Uint16(resp[2:4]) & 0xF)
	t.Logf("failing: aggressive NSEC answer rcode=%d incremented CacheHits by %d", rcode, aggressiveDelta)

	if aggressiveDelta != 1 {
		t.Errorf("cache-hit double count: one cache-served query incremented CacheHits by %d, want 1", aggressiveDelta)
	}
}
