package cache

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestStoreNegativeWithStatus_PreservesDNSSECVerdict pins the fix for cached
// negative responses silently losing their AD bit. StoreNegative historically
// recorded no DNSSEC verdict, so a validated (Secure) NXDOMAIN/NODATA came back
// from cache with DNSSECStatus="" and the handler cleared the AD bit on the
// second and later hits — a discrepancy from every mainstream validating
// resolver (verified live: the first query for a signed NODATA/NXDOMAIN set AD,
// the cached re-serve dropped it).
//
// StoreNegativeWithStatus records the verdict so buildCacheResponse can re-set
// AD (it gates on entry.DNSSECStatus == "secure"). The plain StoreNegative
// remains as the ""-status shorthand.
func TestStoreNegativeWithStatus_PreservesDNSSECVerdict(t *testing.T) {
	soaRR := func() dns.ResourceRecord {
		rr := dns.ResourceRecord{
			Name: "zone.example.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300,
			RData: buildSOAWithMinimum(t, 300),
		}
		rr.RDLength = uint16(len(rr.RData))
		return rr
	}

	t.Run("NXDOMAIN secure verdict preserved", func(t *testing.T) {
		c := NewCache(1000, 1, 86400, 86400, metrics.NewMetrics())
		c.StoreNegativeWithStatus("nx.zone.example.", dns.TypeA, dns.ClassIN,
			NegNXDomain, dns.RCodeNXDomain, []dns.ResourceRecord{soaRR()}, "secure")

		entry, ok := c.Lookup("nx.zone.example.", 0, dns.ClassIN) // NXDOMAIN sentinel qtype=0
		if !ok {
			t.Fatal("negative entry not stored")
		}
		if entry.DNSSECStatus != "secure" {
			t.Errorf("cached NXDOMAIN DNSSECStatus = %q, want %q — a validated denial must keep its verdict so AD survives re-serve",
				entry.DNSSECStatus, "secure")
		}
	})

	t.Run("NODATA secure verdict preserved", func(t *testing.T) {
		c := NewCache(1000, 1, 86400, 86400, metrics.NewMetrics())
		c.StoreNegativeWithStatus("nd.zone.example.", dns.TypeMX, dns.ClassIN,
			NegNoData, dns.RCodeNoError, []dns.ResourceRecord{soaRR()}, "secure")

		entry, ok := c.Lookup("nd.zone.example.", dns.TypeMX, dns.ClassIN)
		if !ok {
			t.Fatal("negative NODATA entry not stored")
		}
		if entry.DNSSECStatus != "secure" {
			t.Errorf("cached NODATA DNSSECStatus = %q, want %q", entry.DNSSECStatus, "secure")
		}
	})

	t.Run("insecure verdict not upgraded", func(t *testing.T) {
		c := NewCache(1000, 1, 86400, 86400, metrics.NewMetrics())
		// Plain StoreNegative records no verdict ("") — an unsigned-zone denial
		// must NOT come back marked secure.
		c.StoreNegative("plain.zone.example.", dns.TypeA, dns.ClassIN,
			NegNXDomain, dns.RCodeNXDomain, []dns.ResourceRecord{soaRR()})

		entry, ok := c.Lookup("plain.zone.example.", 0, dns.ClassIN)
		if !ok {
			t.Fatal("negative entry not stored")
		}
		if entry.DNSSECStatus == "secure" {
			t.Errorf("plain StoreNegative must not mark an entry secure (got %q)", entry.DNSSECStatus)
		}
	})
}
