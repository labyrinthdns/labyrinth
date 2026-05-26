package cache

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestSanitizeWireTTL_RFC2181_MSBSet pins the RFC 2181 §8 rule that any
// on-wire TTL with the most-significant bit set MUST be treated as zero.
// Without this clamp a hostile authoritative could ship a TTL of
// 2^31 (~68 years), turning a single poisoned answer into an effectively
// permanent cache entry.
func TestSanitizeWireTTL_RFC2181_MSBSet(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want uint32
	}{
		{"zero stays zero", 0, 0},
		{"normal value passes", 300, 300},
		{"max positive int31", 0x7FFFFFFF, 0x7FFFFFFF},
		{"MSB set → clamp to 0", 0x80000000, 0},
		{"max uint32 → clamp to 0", 0xFFFFFFFF, 0},
		{"high bit + low bits → 0", 0x80000001, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeWireTTL(c.in); got != c.want {
				t.Errorf("sanitizeWireTTL(%#x) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestStore_TTLZero_NotCached pins RFC 2181 §8: "Zero TTL values are
// interpreted to mean that the RR can only be used for the transaction in
// progress, and should not be cached." A previous bug promoted TTL=0 up
// to minTTL, silently caching answers the authoritative explicitly marked
// non-cacheable.
func TestStore_TTLZero_NotCached(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "dynamic.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("dynamic.example.com", dns.TypeA, dns.ClassIN, answers, nil)

	if _, ok := c.Get("dynamic.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("TTL=0 record was cached (RFC 2181 §8 violation)")
	}
}

// TestStore_TTLHighBit_ClampedToZero verifies that the §8 sanitize feeds
// the don't-cache rule above — an answer carrying a TTL with bit 31 set
// must NOT be cached.
func TestStore_TTLHighBit_ClampedToZero(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{{
		Name: "evil.example.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 0xFFFFFFFF, RDLength: 4, RData: []byte{1, 2, 3, 4},
	}}
	c.Store("evil.example.com", dns.TypeA, dns.ClassIN, answers, nil)

	if _, ok := c.Get("evil.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("0xFFFFFFFF TTL was cached (RFC 2181 §8 §6.1 hostile-TTL attack)")
	}
}

// TestStoreNegative_TTLZero_NotCached pins the same RFC 2181 §8 rule for
// negative caching: an authoritative shipping NXDOMAIN with SOA.Minimum=0
// is asking us not to cache the denial.
func TestStoreNegative_TTLZero_NotCached(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOAWithMinimum(t, 0)
	c.StoreNegative("gone.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain,
		[]dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
			TTL: 0, RDLength: uint16(len(soaRData)), RData: soaRData,
		}})

	if _, ok := c.Get("gone.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("negative TTL=0 NXDOMAIN was cached (RFC 2181 §8 / RFC 2308 §5)")
	}
}

// TestStoreNegative_TTLHighBit pins the §8 sanitize for negatives: high-bit
// SOA Minimum (~68 years) must NOT make the negative entry effectively
// permanent.
func TestStoreNegative_TTLHighBit(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	soaRData := buildSOAWithMinimum(t, 0x80000000)
	c.StoreNegative("evil.example.com", dns.TypeA, dns.ClassIN, NegNXDomain, dns.RCodeNXDomain,
		[]dns.ResourceRecord{{
			Name: "example.com", Type: dns.TypeSOA, Class: dns.ClassIN,
			TTL: 0xFFFFFFFF, RDLength: uint16(len(soaRData)), RData: soaRData,
		}})

	if _, ok := c.Get("evil.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("0xFFFFFFFF negative SOA.Minimum was cached (RFC 2181 §8 hostile-TTL)")
	}
}

// buildSOAWithMinimum constructs a minimally-correct SOA RDATA blob with
// MNAME="m.", RNAME="r.", serial=1, refresh=1, retry=1, expire=1,
// minimum=<arg>. Enough for ParseSOA to extract the Minimum field.
func buildSOAWithMinimum(t *testing.T, minimum uint32) []byte {
	t.Helper()
	// m. → label "m" + 0 terminator → [1 'm' 0]
	// r. → [1 'r' 0]
	rdata := []byte{
		1, 'm', 0,
		1, 'r', 0,
		0, 0, 0, 1, // serial
		0, 0, 0, 1, // refresh
		0, 0, 0, 1, // retry
		0, 0, 0, 1, // expire
		byte(minimum >> 24), byte(minimum >> 16), byte(minimum >> 8), byte(minimum),
	}
	return rdata
}

// TestStore_TTLZero_OneOfMany verifies that when the minimum TTL across an
// RRset is 0, the whole entry is not cached (per RFC 2181 §5.2 the RRset
// shares a single TTL — taking the minimum is the safe interpretation, and
// §8 then says that minimum=0 means don't cache).
func TestStore_TTLZero_OneOfMany(t *testing.T) {
	m := metrics.NewMetrics()
	c := NewCache(1000, 5, 86400, 3600, m)

	answers := []dns.ResourceRecord{
		{Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RDLength: 4, RData: []byte{1, 2, 3, 4}},
		{Name: "x.example.com", Type: dns.TypeA, Class: dns.ClassIN, TTL: 0, RDLength: 4, RData: []byte{5, 6, 7, 8}}, // poison
	}
	c.Store("x.example.com", dns.TypeA, dns.ClassIN, answers, nil)

	if _, ok := c.Get("x.example.com", dns.TypeA, dns.ClassIN); ok {
		t.Error("RRset with min TTL=0 was cached (RFC 2181 §5.2 + §8)")
	}
}

// Silence unused-import warning when test file is the only consumer.
var _ = time.Now
