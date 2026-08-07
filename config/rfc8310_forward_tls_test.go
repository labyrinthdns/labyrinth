package config

import (
	"strings"
	"testing"
)

// Forward-zone DoT configuration (RFC 7858 transport, RFC 8310 authentication).
//
// The config layer carries a security decision, not just parsing: a forward
// zone with TLS enabled but no way to authenticate the upstream is rejected
// outright rather than downgraded. RFC 8310's Opportunistic profile would
// permit connecting anyway, and Labyrinth deliberately does not offer it —
// see resolver/dot_upstream.go for why. These tests pin that the refusal is
// real and that the parser actually reads the keys it promises.

func TestRFC8310_ForwardZoneTLSRequiresAuthentication(t *testing.T) {
	t.Run("tls with no auth is rejected", func(t *testing.T) {
		z := ForwardZoneConfig{Name: "internal.example", Addrs: []string{"10.0.0.53"}, TLS: true}
		err := z.Validate()
		if err == nil {
			t.Fatal("a TLS forward zone with neither an auth name nor pins was accepted — " +
				"an on-path attacker could then be the trusted upstream while the " +
				"config still reports the zone as encrypted")
		}
		if !strings.Contains(err.Error(), "internal.example") {
			t.Errorf("error does not name the offending zone: %v", err)
		}
	})

	t.Run("auth name is sufficient", func(t *testing.T) {
		z := ForwardZoneConfig{
			Name: "corp.example", Addrs: []string{"1.1.1.1"},
			TLS: true, TLSAuthName: "cloudflare-dns.com",
		}
		if err := z.Validate(); err != nil {
			t.Fatalf("auth-name-only policy rejected: %v", err)
		}
	})

	t.Run("pins alone are sufficient", func(t *testing.T) {
		z := ForwardZoneConfig{
			Name: "lab.example", Addrs: []string{"10.0.0.53"},
			TLS: true, TLSPins: []string{"1nOOfx0X6kBqZs2Q0T6qUUvhVE1p4c0PZ7bJcXKvGQY="},
		}
		if err := z.Validate(); err != nil {
			t.Fatalf("pin-only policy rejected: %v", err)
		}
	})

	t.Run("plaintext zone needs no authentication", func(t *testing.T) {
		z := ForwardZoneConfig{Name: "plain.example", Addrs: []string{"192.0.2.1"}}
		if err := z.Validate(); err != nil {
			t.Fatalf("plaintext forward zone rejected: %v", err)
		}
	})
}

// TestRFC8310_ForwardZoneTLSKeysParsed pins that the parser reads all four
// keys. Silently ignoring tls_auth_name would be the worst outcome available:
// Validate() would then reject a correctly-written config, or — if a pin were
// also present — the zone would connect without the name check the operator
// asked for.
func TestRFC8310_ForwardZoneTLSKeysParsed(t *testing.T) {
	values := map[string]string{
		"forward_zones.corp.example.addrs":         "1.1.1.1, 1.0.0.1",
		"forward_zones.corp.example.tls":           "true",
		"forward_zones.corp.example.tls_auth_name": "cloudflare-dns.com",
		"forward_zones.corp.example.tls_pins":      "pinA=, pinB=",
	}

	zones := parseForwardZones(values)
	if len(zones) != 1 {
		t.Fatalf("parsed %d zones, want 1", len(zones))
	}
	z := zones[0]

	if len(z.Addrs) != 2 || z.Addrs[0] != "1.1.1.1" || z.Addrs[1] != "1.0.0.1" {
		t.Errorf("addrs = %v, want [1.1.1.1 1.0.0.1]", z.Addrs)
	}
	if !z.TLS {
		t.Error("tls key not parsed")
	}
	if z.TLSAuthName != "cloudflare-dns.com" {
		t.Errorf("tls_auth_name = %q, want %q", z.TLSAuthName, "cloudflare-dns.com")
	}
	if len(z.TLSPins) != 2 || z.TLSPins[0] != "pinA=" || z.TLSPins[1] != "pinB=" {
		t.Errorf("tls_pins = %v, want [pinA= pinB=]", z.TLSPins)
	}
	if err := z.Validate(); err != nil {
		t.Errorf("fully-specified zone rejected: %v", err)
	}
}

// TestRFC8310_ForwardZoneDefaultsToPlaintext pins that adding the TLS keys did
// not change the behaviour of an existing config. A zone that says nothing
// about TLS must keep working exactly as before.
func TestRFC8310_ForwardZoneDefaultsToPlaintext(t *testing.T) {
	values := map[string]string{
		"forward_zones.legacy.example.addrs": "192.0.2.1",
	}
	zones := parseForwardZones(values)
	if len(zones) != 1 {
		t.Fatalf("parsed %d zones, want 1", len(zones))
	}
	if zones[0].TLS {
		t.Error("a zone that never mentioned tls came out with TLS enabled")
	}
	if err := zones[0].Validate(); err != nil {
		t.Errorf("plaintext zone rejected: %v", err)
	}
}

// TestStubZonesIgnoreTLSKeys pins that stub zones do not grow a TLS surface.
// A stub drives iterative resolution against whatever authoritative servers
// the delegation names; there is no single operator-chosen endpoint to
// authenticate, so offering the keys there would promise something the
// transport cannot deliver.
func TestStubZonesIgnoreTLSKeys(t *testing.T) {
	values := map[string]string{
		"stub_zones.internal.example.addrs": "10.0.0.53",
		"stub_zones.internal.example.tls":   "true",
	}
	zones := parseStubZones(values)
	if len(zones) != 1 {
		t.Fatalf("parsed %d stub zones, want 1", len(zones))
	}
	if zones[0].Name != "internal.example" || len(zones[0].Addrs) != 1 {
		t.Errorf("stub zone mis-parsed: %+v", zones[0])
	}
	// StubZoneConfig has no TLS field at all; this test exists so that a
	// future refactor re-introducing one has to justify itself.
}
