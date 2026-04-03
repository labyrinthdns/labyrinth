package resolver

import (
	"net"
	"testing"
)

func TestSynthesizeAAAA(t *testing.T) {
	prefix := DefaultDNS64Prefix

	tests := []struct {
		name   string
		ipv4   string
		want   string
	}{
		{
			name: "basic",
			ipv4: "192.0.2.1",
			want: "64:ff9b::c000:201",
		},
		{
			name: "all zeros",
			ipv4: "0.0.0.0",
			want: "64:ff9b::",
		},
		{
			name: "all ones",
			ipv4: "255.255.255.255",
			want: "64:ff9b::ffff:ffff",
		},
		{
			name: "loopback",
			ipv4: "127.0.0.1",
			want: "64:ff9b::7f00:1",
		},
		{
			name: "private",
			ipv4: "10.0.0.1",
			want: "64:ff9b::a00:1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipv4 := net.ParseIP(tc.ipv4)
			got := SynthesizeAAAA(ipv4, prefix)
			if got == nil {
				t.Fatal("SynthesizeAAAA returned nil")
			}
			want := net.ParseIP(tc.want)
			if !got.Equal(want) {
				t.Errorf("SynthesizeAAAA(%s) = %s, want %s", tc.ipv4, got, want)
			}
		})
	}
}

func TestSynthesizeAAAANilIPv4(t *testing.T) {
	prefix := DefaultDNS64Prefix
	got := SynthesizeAAAA(nil, prefix)
	if got != nil {
		t.Errorf("expected nil for nil input, got %s", got)
	}
}

func TestSynthesizeAAAAIPv6Input(t *testing.T) {
	prefix := DefaultDNS64Prefix
	// IPv6 address should return nil (not IPv4)
	ipv6 := net.ParseIP("2001:db8::1")
	got := SynthesizeAAAA(ipv6, prefix)
	if got != nil {
		t.Errorf("expected nil for IPv6 input, got %s", got)
	}
}

func TestSynthesizeAAAABadPrefix(t *testing.T) {
	// /64 prefix is not supported (must be /96)
	_, ipNet, _ := net.ParseCIDR("64:ff9b::/64")
	got := SynthesizeAAAA(net.ParseIP("10.0.0.1"), *ipNet)
	if got != nil {
		t.Errorf("expected nil for non-/96 prefix, got %s", got)
	}
}

func TestSynthesizeAAAACustomPrefix(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8::/96")
	ipv4 := net.ParseIP("192.168.1.1")
	got := SynthesizeAAAA(ipv4, *ipNet)
	if got == nil {
		t.Fatal("SynthesizeAAAA returned nil")
	}
	want := net.ParseIP("2001:db8::c0a8:101")
	if !got.Equal(want) {
		t.Errorf("SynthesizeAAAA = %s, want %s", got, want)
	}
}

func TestParseDNS64Prefix(t *testing.T) {
	tests := []struct {
		cidr    string
		wantErr bool
	}{
		{"64:ff9b::/96", false},
		{"2001:db8::/96", false},
		{"not-a-cidr", true},
	}

	for _, tc := range tests {
		_, err := ParseDNS64Prefix(tc.cidr)
		if tc.wantErr && err == nil {
			t.Errorf("ParseDNS64Prefix(%q) expected error", tc.cidr)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ParseDNS64Prefix(%q) unexpected error: %v", tc.cidr, err)
		}
	}
}
