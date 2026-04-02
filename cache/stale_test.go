package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestServeStaleDisabled(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, false, 30, m)

	answers := []dns.ResourceRecord{{
		Name: "stale.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("stale.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	_, ok := c.GetStale("stale.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("GetStale should return false when serve-stale is disabled")
	}
}

func TestServeStaleEnabled(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 1, 86400, 3600, true, 30, m)

	answers := []dns.ResourceRecord{{
		Name: "stale.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("stale.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Regular Get should miss
	_, ok := c.Get("stale.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Get should miss for expired entry")
	}

	// GetStale should hit
	entry, ok := c.GetStale("stale.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("GetStale should return expired entry when serve-stale is enabled")
	}
	if len(entry.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(entry.Records))
	}
	if entry.Records[0].TTL != 30 {
		t.Errorf("stale TTL should be 30, got %d", entry.Records[0].TTL)
	}
}

func TestServeStaleNotExpired(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCacheWithStale(1000, 5, 86400, 3600, true, 30, m)

	answers := []dns.ResourceRecord{{
		Name: "fresh.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("fresh.com", dns.TypeA, dns.ClassIN, answers, nil)

	// GetStale should NOT return non-expired entries
	_, ok := c.GetStale("fresh.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("GetStale should not return non-expired entries")
	}
}

func TestExtractNegativeTTLWithSOAMinimum(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Build a SOA RDATA with Minimum=300
	// MNAME: "ns1.example.com" + RNAME: "admin.example.com" + 5*uint32
	soaRData := buildSOARData("ns1.example.com", "admin.example.com", 2024010101, 3600, 900, 604800, 300)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}

	ttl := c.extractNegativeTTL(authority)

	// Should be min(SOA.TTL=600, SOA.Minimum=300) = 300
	if ttl != 300 {
		t.Errorf("expected TTL=300 (SOA.Minimum), got %d", ttl)
	}
}

func TestExtractNegativeTTLSOATTLSmaller(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOARData("ns1.example.com", "admin.example.com", 2024010101, 3600, 900, 604800, 7200)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 60, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}

	ttl := c.extractNegativeTTL(authority)

	// Should be min(SOA.TTL=60, SOA.Minimum=7200) = 60
	if ttl != 60 {
		t.Errorf("expected TTL=60 (SOA.TTL), got %d", ttl)
	}
}

// buildSOARData constructs uncompressed SOA RDATA bytes.
func buildSOARData(mname, rname string, serial, refresh, retry, expire, minimum uint32) []byte {
	var buf []byte

	// Encode MNAME
	buf = append(buf, encodeName(mname)...)
	// Encode RNAME
	buf = append(buf, encodeName(rname)...)

	// 5 × uint32
	for _, v := range []uint32{serial, refresh, retry, expire, minimum} {
		buf = append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return buf
}

func encodeName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	var buf []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
			start = i + 1
		}
	}
	buf = append(buf, 0)
	return buf
}
