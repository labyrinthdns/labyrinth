package server

import (
	"net"
	"testing"
)

type mockAddr struct {
	network string
	addr    string
}

func (a *mockAddr) Network() string { return a.network }
func (a *mockAddr) String() string  { return a.addr }

func TestExtractIPWithPort(t *testing.T) {
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:12345"}
	ip := extractIP(addr)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

func TestExtractIPNil(t *testing.T) {
	ip := extractIP(nil)
	if ip != "" {
		t.Errorf("expected empty, got %q", ip)
	}
}

func TestExtractIPNoPort(t *testing.T) {
	addr := &mockAddr{network: "udp", addr: "192.168.1.1:"}
	ip := extractIP(addr)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

func TestExtractIPIPv6(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53}
	ip := extractIP(addr)
	if ip != "::1" {
		t.Errorf("expected '::1', got %q", ip)
	}
}
