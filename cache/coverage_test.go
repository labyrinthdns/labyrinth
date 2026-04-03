package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestLookupExpired covers the remaining==0 branch in Lookup (line 294-296).
func TestLookupExpired(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "expire-lookup.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 1, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}
	c.Store("expire-lookup.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Verify it's there first
	_, ok := c.Lookup("expire-lookup.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("Lookup should find fresh entry")
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Lookup should return false for expired entry (without deleting it)
	_, ok = c.Lookup("expire-lookup.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Lookup should return false for expired entry")
	}

	// Unlike Get, Lookup should NOT delete the entry
	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("Lookup should not delete expired entries, expected 1 entry, got %d", stats.Entries)
	}
}

// TestNegativeEntriesBasic covers NegativeEntries with NXDOMAIN entries having SOA authority.
func TestNegativeEntriesBasic(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOARData("ns1.example.com", "admin.example.com", 2024010101, 3600, 900, 604800, 300)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}

	c.StoreNegative("nxtest.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, authority)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 negative entry, got %d", len(entries))
	}

	e := entries[0]
	if e.Name != "nxtest.example.com" {
		t.Errorf("expected name 'nxtest.example.com', got '%s'", e.Name)
	}
	if e.QType != "*" {
		t.Errorf("expected qtype '*' (NXDOMAIN covers all types), got '%s'", e.QType)
	}
	if e.NegType != "NXDOMAIN" {
		t.Errorf("expected neg_type 'NXDOMAIN', got '%s'", e.NegType)
	}
	if e.RCODE != "NXDOMAIN" {
		t.Errorf("expected rcode 'NXDOMAIN', got '%s'", e.RCODE)
	}
	if e.RemainingTTL == 0 {
		t.Error("remaining TTL should be > 0")
	}
	if len(e.Authority) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(e.Authority))
	}
	if e.Authority[0].Type != "SOA" {
		t.Errorf("expected authority type 'SOA', got '%s'", e.Authority[0].Type)
	}
	// formatAuthorityRData for SOA should return "ns1.example.com admin.example.com"
	if e.Authority[0].RData != "ns1.example.com admin.example.com" {
		t.Errorf("expected SOA rdata 'ns1.example.com admin.example.com', got '%s'", e.Authority[0].RData)
	}
}

// TestNegativeEntriesNODATA covers the NegNoData branch in NegativeEntries.
func TestNegativeEntriesNODATA(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOARData("ns1.example.com", "admin.example.com", 2024010101, 3600, 900, 604800, 300)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: uint16(len(soaRData)), RData: soaRData,
	}}

	c.StoreNegative("nodata.example.com", dns.TypeAAAA, dns.ClassIN, NegNoData, dns.RCodeNoError, authority)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 negative entry, got %d", len(entries))
	}

	e := entries[0]
	if e.NegType != "NODATA" {
		t.Errorf("expected neg_type 'NODATA', got '%s'", e.NegType)
	}
	if e.RCODE != "NOERROR" {
		t.Errorf("expected rcode 'NOERROR', got '%s'", e.RCODE)
	}
	if e.QType != "AAAA" {
		t.Errorf("expected qtype 'AAAA', got '%s'", e.QType)
	}
}

// TestNegativeEntriesWithNSAuthority covers formatAuthorityRData for TypeNS records.
func TestNegativeEntriesWithNSAuthority(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	nsRData := encodeName("ns1.example.com")

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 600, RDLength: uint16(len(nsRData)), RData: nsRData,
	}}

	c.StoreNegative("nstest.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, authority)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 negative entry, got %d", len(entries))
	}

	// Check that NS authority record is formatted correctly
	if len(entries[0].Authority) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(entries[0].Authority))
	}
	if entries[0].Authority[0].RData != "ns1.example.com" {
		t.Errorf("expected NS rdata 'ns1.example.com', got '%s'", entries[0].Authority[0].RData)
	}
}

// TestNegativeEntriesLimit covers the limit early-return branch in NegativeEntries (line 394-397).
func TestNegativeEntriesLimit(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Store multiple negative entries
	for i := 0; i < 10; i++ {
		name := "neg" + string(rune('a'+i)) + ".example.com"
		c.StoreNegative(name, dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)
	}

	// Request with limit=3
	entries := c.NegativeEntries(3)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries with limit=3, got %d", len(entries))
	}
}

// TestNegativeEntriesSkipsPositive covers the !entry.Negative continue branch.
func TestNegativeEntriesSkipsPositive(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Store a positive entry
	answers := []dns.ResourceRecord{{
		Name: "positive.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("positive.com", dns.TypeA, dns.ClassIN, answers, nil)

	// Store a negative entry
	c.StoreNegative("negative.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)

	entries := c.NegativeEntries(0)
	if len(entries) != 1 {
		t.Errorf("expected 1 negative entry (skipping positive), got %d", len(entries))
	}
	if entries[0].Name != "negative.com" {
		t.Errorf("expected name 'negative.com', got '%s'", entries[0].Name)
	}
}

// TestNegativeEntriesSkipsExpired covers the remaining==0 continue branch.
func TestNegativeEntriesSkipsExpired(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 1, 86400, 3600, m)

	// Store a negative entry, then directly manipulate it to be expired
	c.StoreNegative("expired-neg.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)

	// Directly set InsertedAt far in the past to force expiry.
	// NXDOMAIN is stored with sentinel qtype=0 (RFC 2308).
	name := "expired-neg.com"
	key := cacheKey{name: name, qtype: 0, class: dns.ClassIN}
	idx := c.shardIndex(name)
	s := &c.shards[idx]
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		entry.InsertedAt = time.Now().Add(-1 * time.Hour)
		entry.OrigTTL = 1 // set a very short TTL so it's definitely expired
	}
	s.mu.Unlock()

	entries := c.NegativeEntries(10)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (all expired), got %d", len(entries))
	}
}

// TestNegativeEntriesUnknownNegType covers the default "UNKNOWN" case for NegType.
func TestNegativeEntriesUnknownNegType(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Use NegNone (0) which doesn't match NegNXDomain or NegNoData
	c.StoreNegative("unknown-neg.com", dns.TypeA, dns.ClassIN, NegNone, dns.RCodeNoError, nil)

	// Manually set the Negative flag since StoreNegative sets it
	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].NegType != "UNKNOWN" {
		t.Errorf("expected neg_type 'UNKNOWN', got '%s'", entries[0].NegType)
	}
}

// TestNegativeEntriesUnknownRCode covers the "UNKNOWN" rcode branch.
func TestNegativeEntriesUnknownRCode(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Use an RCODE that's not in RCodeToString (e.g., 15)
	c.StoreNegative("unknown-rcode.com", dns.TypeA, dns.ClassIN, NegNXDomain, 15, nil)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].RCODE != "UNKNOWN" {
		t.Errorf("expected rcode 'UNKNOWN', got '%s'", entries[0].RCODE)
	}
}

// TestNegativeEntriesUnknownQType covers the "UNKNOWN" qtype branch.
func TestNegativeEntriesUnknownQType(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Use NODATA (type-specific) with a qtype not in TypeToString (e.g., 999)
	c.StoreNegative("unknown-qtype.com", 999, dns.ClassIN, NegNoData, dns.RCodeNoError, nil)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].QType != "UNKNOWN" {
		t.Errorf("expected qtype 'UNKNOWN', got '%s'", entries[0].QType)
	}
}

// TestNegativeEntriesUnknownAuthorityType covers the "UNKNOWN" type branch for authority records.
func TestNegativeEntriesUnknownAuthorityType(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	authority := []dns.ResourceRecord{{
		Name: "example.com", Type: 999, Class: dns.ClassIN,
		TTL: 600, RDLength: 0, RData: nil,
	}}

	c.StoreNegative("unknown-authtype.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, authority)

	entries := c.NegativeEntries(10)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Authority) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(entries[0].Authority))
	}
	if entries[0].Authority[0].Type != "UNKNOWN" {
		t.Errorf("expected authority type 'UNKNOWN', got '%s'", entries[0].Authority[0].Type)
	}
}

// TestFormatAuthorityRDataSOAError covers formatAuthorityRData with invalid SOA RDATA.
func TestFormatAuthorityRDataSOAError(t *testing.T) {
	rr := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
		TTL: 600, RDLength: 3, RData: []byte{0xFF, 0xFF, 0xFF},
	}
	result := formatAuthorityRData(rr)
	if result != "" {
		t.Errorf("expected empty string for invalid SOA, got '%s'", result)
	}
}

// TestFormatAuthorityRDataNSError covers formatAuthorityRData with invalid NS RDATA.
func TestFormatAuthorityRDataNSError(t *testing.T) {
	rr := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeNS, Class: dns.ClassIN,
		TTL: 600, RDLength: 1, RData: []byte{0xFF}, // invalid label length
	}
	result := formatAuthorityRData(rr)
	if result != "" {
		t.Errorf("expected empty string for invalid NS, got '%s'", result)
	}
}

// TestFormatAuthorityRDataUnknownType covers formatAuthorityRData with an unknown type.
func TestFormatAuthorityRDataUnknownType(t *testing.T) {
	rr := dns.ResourceRecord{
		Name: "example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 600, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}
	result := formatAuthorityRData(rr)
	if result != "" {
		t.Errorf("expected empty string for non-SOA/NS type, got '%s'", result)
	}
}

// TestEnforceMaxEntriesNilMetrics covers the eviction path in enforceMaxEntriesLocked
// with nil metrics (line 268-270 where c.metrics != nil check fails).
func TestEnforceMaxEntriesNilMetrics(t *testing.T) {
	// maxEntries=2 means each shard allows maxEntries/shardCount+1 = 2/256+1 = 1 entry
	c := NewCacheWithStale(2, 5, 86400, 3600, false, 30, nil)

	// Insert many entries; some will land in the same shard and trigger eviction
	for i := 0; i < 100; i++ {
		name := "evict-nil-" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + ".com"
		answers := []dns.ResourceRecord{{
			Name: name, Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	// Verify eviction happened (no panic with nil metrics)
	stats := c.Stats()
	if stats.Entries >= 100 {
		t.Errorf("eviction should have removed entries, got %d", stats.Entries)
	}
}

// TestNegativeEntriesEmpty covers NegativeEntries on an empty cache.
func TestNegativeEntriesEmpty(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	entries := c.NegativeEntries(10)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries on empty cache, got %d", len(entries))
	}
}

// TestNegativeEntriesZeroLimit covers NegativeEntries with limit=0 (no limit).
func TestNegativeEntriesZeroLimit(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	for i := 0; i < 5; i++ {
		name := "zerolimit" + string(rune('a'+i)) + ".com"
		c.StoreNegative(name, dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)
	}

	// limit=0 means no limit, should return all
	entries := c.NegativeEntries(0)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries with limit=0, got %d", len(entries))
	}
}
