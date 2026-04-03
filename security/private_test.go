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
		makeAAAA(net.ParseIP("::1")),
		makeAAAA(net.ParseIP("fe80::1")),
		makeAAAA(net.ParseIP("fc00::1")),
		makeAAAA(net.ParseIP("fd00::1")),
		makeAAAA(net.ParseIP("2001:db8::1")), // public (documentation, but not private/loopback/link-local)
	}
	filtered := FilterPrivateAddresses(answers)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 public AAAA record, got %d", len(filtered))
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
