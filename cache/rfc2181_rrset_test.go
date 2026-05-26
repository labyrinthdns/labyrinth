package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestStore_NormalizesMixedRRsetTTLs pins the Y6 fix: RFC 2181 §5.2 says
// "If any of the records in the [RR]set have different TTLs, then a
// receiver must … treat them as if they all had the same TTL — the
// lowest of those TTLs." The cache now picks the lowest TTL in the
// rrset and applies it uniformly at store time. Without this, a hostile
// or buggy authoritative could publish an rrset with one short-TTL
// record and several long-TTL ones; serve-stale would honour the
// longest, pinning the rrset into cache far past its intended life.
//
// Note: we can only assert via Cache.Get, which decays all returned
// TTLs to a single remaining value. The strong assertion is that the
// query-key rrset's expiry derives from the minimum (60s), so a Get
// shortly after Store sees TTLs ≤ 60 — not 600 or 300.
func TestStore_NormalizesMixedRRsetTTLs(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{
		{Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		{Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 600, RDLength: 4, RData: []byte{5, 6, 7, 8}},
		{Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 60, RDLength: 4, RData: []byte{9, 10, 11, 12}},
	}
	c.Store("x.example.com", dns.TypeA, dns.ClassIN, answers, nil)

	entry, ok := c.Get("x.example.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("rrset not cached")
	}
	if len(entry.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(entry.Records))
	}
	// All returned TTLs must be ≤ 60 — anything higher means the
	// rrset's expiry was anchored on a larger TTL than the minimum.
	for i, rr := range entry.Records {
		if rr.TTL > 60 {
			t.Errorf("record[%d] TTL: want ≤60 (RFC 2181 §5.2 min), got %d",
				i, rr.TTL)
		}
	}
}
