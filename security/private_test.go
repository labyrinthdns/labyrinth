package security

import (
	"net"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

func makeA(ip net.IP) dns.ResourceRecord {
	ipv4 := ip.To4()
	return dns.ResourceRecord{
		Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
		TTL: 300, RDLength: 4, RData: ipv4,
	}
}

func makeAAAA(ip net.IP) dns.ResourceRecord {
	ipv6 := ip.To16()
	return dns.ResourceRecord{
		Name: "test.com", Type: dns.TypeAAAA, Class: dns.ClassIN,
		TTL: 300, RDLength: 16, RData: ipv6,
	}
}

func TestFilterPrivateAddresses_RFC1918(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeA(net.ParseIP("10.0.0.1")),
		makeA(net.ParseIP("172.16.5.1")),
		makeA(net.ParseIP("192.168.1.1")),
		makeA(net.ParseIP("93.184.216.34")), // public
	}

	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 public record, got %d", len(filtered))
	}
	if !net.IP(filtered[0].RData).Equal(net.ParseIP("93.184.216.34")) {
		t.Error("expected the public IP to survive filtering")
	}
}

func TestFilterPrivateAddresses_Loopback(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeA(net.ParseIP("127.0.0.1")),
		makeA(net.ParseIP("8.8.8.8")),
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 record, got %d", len(filtered))
	}
}

func TestFilterPrivateAddresses_LinkLocal(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeA(net.ParseIP("169.254.1.1")),
		makeA(net.ParseIP("1.1.1.1")),
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 record, got %d", len(filtered))
	}
}

func TestFilterPrivateAddresses_IPv6(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeAAAA(net.ParseIP("::1")),         // loopback
		makeAAAA(net.ParseIP("fe80::1")),     // link-local
		makeAAAA(net.ParseIP("fc00::1")),     // ULA
		makeAAAA(net.ParseIP("fd00::1")),     // ULA
		makeAAAA(net.ParseIP("2001:db8::1")), // RFC 3849 documentation -- must be filtered
		makeAAAA(net.ParseIP("2606:4700:4700::1111")), // public (Cloudflare)
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 public AAAA record, got %d", len(filtered))
	}
	if !net.IP(filtered[0].RData).Equal(net.ParseIP("2606:4700:4700::1111")) {
		t.Errorf("expected the public IP to survive, got %s", net.IP(filtered[0].RData))
	}
}

func TestFilterPrivateAddresses_PreservesOtherTypes(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeA(net.ParseIP("10.0.0.1")),
		{
			Name: "test.com", Type: dns.TypeCNAME, Class: dns.ClassIN,
			TTL: 300, RDLength: 0, RData: nil,
		},
		{
			Name: "test.com", Type: dns.TypeMX, Class: dns.ClassIN,
			TTL: 300, RDLength: 0, RData: nil,
		},
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 records (CNAME + MX), got %d", len(filtered))
	}
}

func TestFilterPrivateAddresses_EmptyInput(t *testing.T) {
	filtered := FilterPrivateAddresses(nil)
	if len(filtered) != 0 {
		t.Fatalf("expected 0 records, got %d", len(filtered))
	}
}

func TestFilterPrivateAddresses_AllPublic(t *testing.T) {
	answers := []dns.ResourceRecord{
		makeA(net.ParseIP("93.184.216.34")),
		makeA(net.ParseIP("8.8.8.8")),
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 records, got %d", len(filtered))
	}
}

func TestFilterPrivateAddresses_BadRData(t *testing.T) {
	// A record with wrong length RDATA should not be filtered
	answers := []dns.ResourceRecord{
		{
			Name: "test.com", Type: dns.TypeA, Class: dns.ClassIN,
			TTL: 300, RDLength: 2, RData: []byte{1, 2},
		},
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 record (bad RDATA should pass through), got %d", len(filtered))
	}
}

// TestFilterPrivateAddresses_ExpandedV4 covers the additional reserved IPv4
// ranges added for proper DNS-rebinding protection: CGNAT, TEST-NETs,
// benchmarking, multicast, broadcast, "this network", and reserved/Class E.
func TestFilterPrivateAddresses_ExpandedV4(t *testing.T) {
	cases := []struct {
		ip   string
		desc string
	}{
		{"100.64.0.1", "CGNAT (RFC 6598)"},
		{"100.127.255.254", "CGNAT high"},
		{"0.0.0.1", "this-network (RFC 1122)"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"198.18.0.1", "benchmarking (RFC 2544)"},
		{"198.19.255.254", "benchmarking high"},
		{"224.0.0.1", "multicast (RFC 5771)"},
		{"239.255.255.255", "multicast high"},
		{"240.0.0.1", "reserved/Class E"},
		{"255.255.255.255", "broadcast"},
		{"192.0.0.1", "IETF protocol assignments"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			filtered := FilterPrivateAddresses([]dns.ResourceRecord{makeA(ip)})
			if len(filtered) != 0 {
				t.Errorf("%s (%s) should have been filtered, got %d records",
					tc.desc, tc.ip, len(filtered))
			}
		})
	}
}

// TestFilterPrivateAddresses_ExpandedV6 covers extra IPv6 reserved ranges:
// 6to4, NAT64, IETF protocol assignments (incl. Teredo), multicast, ULA,
// link-local, IPv4-mapped IPv6 (which must be unwrapped to the v4 form
// and re-evaluated -- attacker cannot bypass the v4 list this way).
func TestFilterPrivateAddresses_ExpandedV6(t *testing.T) {
	cases := []struct {
		ip   string
		desc string
	}{
		{"2002::1", "6to4 (RFC 3056)"},
		{"64:ff9b::1", "well-known NAT64 (RFC 6052)"},
		{"64:ff9b:1::1", "local-use NAT64 (RFC 8215)"},
		{"2001::1", "Teredo / IETF assignments (RFC 2928)"},
		{"ff02::1", "link-local multicast"},
		{"ff05::1", "site-local multicast"},
		{"ff0e::1", "global multicast"},
		{"100::1", "discard-only (RFC 6666)"},
		{"::ffff:192.168.1.1", "IPv4-mapped IPv6 wrapping RFC 1918"},
		{"::ffff:127.0.0.1", "IPv4-mapped IPv6 wrapping loopback"},
		{"::ffff:100.64.0.1", "IPv4-mapped IPv6 wrapping CGNAT"},
		{"::", "unspecified"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			filtered := FilterPrivateAddresses([]dns.ResourceRecord{makeAAAA(ip)})
			if len(filtered) != 0 {
				t.Errorf("%s (%s) should have been filtered, got %d records",
					tc.desc, tc.ip, len(filtered))
			}
		})
	}
}

// TestIsReservedIP_PublicAddresses ensures common public addresses are
// never wrongly flagged as reserved.
func TestIsReservedIP_PublicAddresses(t *testing.T) {
	pub := []string{
		"1.1.1.1", "8.8.8.8", "9.9.9.9",
		"93.184.216.34", "208.67.222.222",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	}
	for _, s := range pub {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if IsReservedIP(ip) {
			t.Errorf("public IP %s wrongly flagged as reserved", s)
		}
	}
}

// TestIsReservedIP_NilIP ensures nil input is handled gracefully.
func TestIsReservedIP_NilIP(t *testing.T) {
	if IsReservedIP(nil) {
		t.Error("nil IP should not be reserved")
	}
}
