package dns

import (
	"net"
	"testing"
)

func TestECS_CacheKeyFamilyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		family uint16
		prefix uint8
		addr   string
		want   string
	}{
		{1, 24, "192.0.2.1", "192.0.2.0/24"},
		{1, 32, "192.0.2.1", "192.0.2.1/32"},
		{2, 64, "2001:db8:1234:5678::1", "2001:db8:1234:5678::/64"},
		{2, 64, "::ffff:192.0.2.1", "::/64"},
		{2, 96, "::ffff:192.0.2.1", "0.0.0.0/96"},
		{2, 96, "::ffff:198.51.100.7", "0.0.0.0/96"},
		{2, 97, "::ffff:192.0.2.1", "128.0.0.0/97"},
		{2, 127, "::ffff:192.0.2.1", "192.0.2.0/127"},
		{2, 128, "::ffff:192.0.2.1", "192.0.2.1/128"},
		{2, 0, "::ffff:192.0.2.1", ""},
	} {
		ecs := &ECSOption{Family: tc.family, SourcePrefixLen: tc.prefix, Address: net.ParseIP(tc.addr)}
		before := append(net.IP(nil), ecs.Address...)
		if got := ecs.CacheKey(); got != tc.want {
			t.Errorf("family=%d prefix=%d addr=%s: key=%q, want %q", tc.family, tc.prefix, tc.addr, got, tc.want)
		}
		parsed, err := ParseECS(BuildECS(ecs).Data)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.CacheKey(); got != tc.want {
			t.Errorf("wire round trip: key=%q, want %q", got, tc.want)
		}
		// net.IP.Equal, not bytes.Equal: the same address can be held as a
		// 4-byte or a 16-byte slice, so a byte comparison reports a false
		// difference for equal addresses. The ECS fixtures here parse
		// IPv4-mapped inputs like "::ffff:192.0.2.1", which is exactly where
		// the two representations diverge.
		if !before.Equal(ecs.Address) {
			t.Error("cache key or encoding changed the input address")
		}
	}
	var none *ECSOption
	if none.CacheKey() != "" {
		t.Fatal("nil ECS must denote global scope")
	}
}
