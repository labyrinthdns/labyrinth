package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func glueA(ip byte) []dns.ResourceRecord {
	return []dns.ResourceRecord{{
		Name: "ns1.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: []byte{192, 0, 2, ip},
	}}
}

// TestStoreGlue_Ranking pins RFC 2181 §5.4.1 trust ranking between referral
// glue and authoritative answers sharing one cache key.
func TestStoreGlue_Ranking(t *testing.T) {
	t.Run("flagged", func(t *testing.T) {
		c := NewCache(100, 5, 86400, 3600, nil)
		c.StoreGlue("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(1))
		e, ok := c.Get("ns1.example.com", dns.TypeA, dns.ClassIN)
		if !ok || !e.Glue {
			t.Fatalf("glue entry missing or unflagged: ok=%v", ok)
		}
	})

	t.Run("does_not_replace_authoritative", func(t *testing.T) {
		c := NewCache(100, 5, 86400, 3600, nil)
		c.StoreWithStatus("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(1), nil, "secure")
		c.StoreGlue("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(2))
		e, _ := c.Get("ns1.example.com", dns.TypeA, dns.ClassIN)
		if e.Glue || e.DNSSECStatus != "secure" || e.Records[0].RData[3] != 1 {
			t.Fatalf("glue overwrote authoritative entry: glue=%v status=%q", e.Glue, e.DNSSECStatus)
		}
	})

	t.Run("authoritative_replaces_glue", func(t *testing.T) {
		c := NewCache(100, 5, 86400, 3600, nil)
		c.StoreGlue("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(1))
		c.StoreWithStatus("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(2), nil, "secure")
		e, _ := c.Get("ns1.example.com", dns.TypeA, dns.ClassIN)
		if e.Glue || e.DNSSECStatus != "secure" {
			t.Fatalf("authoritative answer did not replace glue: glue=%v status=%q", e.Glue, e.DNSSECStatus)
		}
	})

	t.Run("replaces_expired_authoritative", func(t *testing.T) {
		c := NewCacheWithStale(100, 5, 86400, 3600, true, 30, nil)
		c.StoreWithStatus("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(1), nil, "secure")
		key := cacheKey{name: "ns1.example.com", qtype: dns.TypeA, class: dns.ClassIN}
		s := &c.shards[c.shardIndex("ns1.example.com")]
		s.entries[key].InsertedAt = time.Now().Add(-time.Hour)
		c.StoreGlue("ns1.example.com", dns.TypeA, dns.ClassIN, glueA(2))
		e, ok := c.Get("ns1.example.com", dns.TypeA, dns.ClassIN)
		if !ok || !e.Glue {
			t.Fatalf("fresh glue should replace expired authoritative entry: ok=%v", ok)
		}
	})
}
