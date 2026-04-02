package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

func TestLookup(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "lookup.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{10, 0, 0, 1},
	}}
	c.Store("lookup.com", dns.TypeA, dns.ClassIN, answers, nil)

	entry, ok := c.Lookup("lookup.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Fatal("Lookup should find entry")
	}
	if len(entry.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(entry.Records))
	}
}

func TestLookupNotFound(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	_, ok := c.Lookup("nonexistent.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Lookup should not find nonexistent entry")
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "CASE.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("CASE.com", dns.TypeA, dns.ClassIN, answers, nil)

	_, ok := c.Lookup("case.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Error("Lookup should be case-insensitive")
	}
}

func TestDelete(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "del.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("del.com", dns.TypeA, dns.ClassIN, answers, nil)

	ok := c.Delete("del.com", dns.TypeA, dns.ClassIN)
	if !ok {
		t.Error("Delete should return true for existing entry")
	}

	_, found := c.Get("del.com", dns.TypeA, dns.ClassIN)
	if found {
		t.Error("entry should be deleted")
	}
}

func TestDeleteNotFound(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	ok := c.Delete("nonexistent.com", dns.TypeA, dns.ClassIN)
	if ok {
		t.Error("Delete should return false for nonexistent entry")
	}
}

func TestDetailedStats(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	// Add positive entries
	for i := 0; i < 3; i++ {
		answers := []dns.ResourceRecord{{
			Name: "pos.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 4, RData: []byte{byte(i), 2, 3, 4},
		}}
		name := "pos" + string(rune('a'+i)) + ".com"
		c.Store(name, dns.TypeA, dns.ClassIN, answers, nil)
	}

	// Add negative entries
	for i := 0; i < 2; i++ {
		name := "neg" + string(rune('a'+i)) + ".com"
		c.StoreNegative(name, dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain, nil)
	}

	stats := c.DetailedStats()
	if stats.Entries != 5 {
		t.Errorf("total: expected 5, got %d", stats.Entries)
	}
	if stats.PositiveEntries != 3 {
		t.Errorf("positive: expected 3, got %d", stats.PositiveEntries)
	}
	if stats.NegativeEntries != 2 {
		t.Errorf("negative: expected 2, got %d", stats.NegativeEntries)
	}
}

func TestDetailedStatsEmpty(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	stats := c.DetailedStats()
	if stats.Entries != 0 || stats.PositiveEntries != 0 || stats.NegativeEntries != 0 {
		t.Errorf("empty cache should have all zeros: %+v", stats)
	}
}
