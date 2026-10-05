package resolver

import (
	"net"
	"testing"
)

func TestParseDNS64Prefix_UsableNetwork(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want string
	}{
		{"64:ff9b::/96", "64:ff9b::c000:201"},
		{"2001:db8::1234/96", "2001:db8::c000:201"},
	} {
		prefix, err := ParseDNS64Prefix(tc.cidr)
		if err != nil {
			t.Fatalf("ParseDNS64Prefix(%q): %v", tc.cidr, err)
		}
		got := SynthesizeAAAA(net.ParseIP("192.0.2.1"), prefix)
		if !got.Equal(net.ParseIP(tc.want)) {
			t.Errorf("synthesis with %q = %v, want %s", tc.cidr, got, tc.want)
		}
	}
	for _, cidr := range []string{"2001:db8::/64", "2001:db8::/95", "2001:db8::/97", "192.0.2.0/24", "not-a-cidr"} {
		if prefix, err := ParseDNS64Prefix(cidr); err == nil {
			t.Errorf("ParseDNS64Prefix(%q) = %v, want an error", cidr, prefix)
		}
	}
}
