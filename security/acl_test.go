package security

import "testing"

func TestCheckWithZoneNoZones(t *testing.T) {
	// Without any zone ACLs, CheckWithZone falls back to global rules.
	acl, err := NewACL([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if !acl.CheckWithZone("10.0.0.1", "example.com") {
		t.Error("10.0.0.1 should be allowed by global rule")
	}
	if acl.CheckWithZone("192.168.1.1", "example.com") {
		t.Error("192.168.1.1 should be denied by global rule")
	}
}

func TestCheckWithZoneSpecificZone(t *testing.T) {
	acl, err := NewACL([]string{"0.0.0.0/0"}, nil) // global: allow all
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	// Zone: internal.corp — only allow 10.0.0.0/8 (no deny list means
	// only IPs in allow are permitted; all others are implicitly denied).
	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "internal.corp",
		Allow: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// Query to internal.corp from 10.0.0.1 → allowed by zone allow list
	if !acl.CheckWithZone("10.0.0.1", "server.internal.corp") {
		t.Error("10.0.0.1 should be allowed for internal.corp")
	}

	// Query to internal.corp from 192.168.1.1 → denied (not in zone allow list)
	if acl.CheckWithZone("192.168.1.1", "server.internal.corp") {
		t.Error("192.168.1.1 should be denied for internal.corp")
	}

	// Query to public.com from 192.168.1.1 → allowed by global rules
	if !acl.CheckWithZone("192.168.1.1", "www.public.com") {
		t.Error("192.168.1.1 should be allowed for public.com via global rules")
	}
}

func TestCheckWithZoneExactMatch(t *testing.T) {
	acl, err := NewACL([]string{"0.0.0.0/0"}, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "secret.corp",
		Allow: []string{"172.16.0.0/12"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// Exact zone match
	if !acl.CheckWithZone("172.16.1.1", "secret.corp") {
		t.Error("172.16.1.1 should be allowed for exact zone match")
	}

	if acl.CheckWithZone("10.0.0.1", "secret.corp") {
		t.Error("10.0.0.1 should be denied for secret.corp zone")
	}
}

func TestCheckWithZoneMostSpecific(t *testing.T) {
	acl, err := NewACL([]string{"0.0.0.0/0"}, nil) // global: allow all
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	// Broad zone
	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "corp",
		Allow: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// More specific zone
	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "public.corp",
		Allow: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// Query to public.corp from external IP → allowed (more specific zone)
	if !acl.CheckWithZone("192.168.1.1", "www.public.corp") {
		t.Error("192.168.1.1 should be allowed for public.corp (more specific zone)")
	}

	// Query to private.corp from external IP → denied by corp zone rules
	if acl.CheckWithZone("192.168.1.1", "www.private.corp") {
		t.Error("192.168.1.1 should be denied for private.corp")
	}

	// Query to private.corp from internal IP → allowed by corp zone rules
	if !acl.CheckWithZone("10.1.2.3", "www.private.corp") {
		t.Error("10.1.2.3 should be allowed for private.corp")
	}
}

func TestCheckWithZoneDenyOverridesAllow(t *testing.T) {
	acl, err := NewACL(nil, nil) // global: allow all (empty allow)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "restricted.zone",
		Allow: []string{"10.0.0.0/8"},
		Deny:  []string{"10.1.0.0/16"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// 10.2.0.1 is in allow but not in deny → allowed
	if !acl.CheckWithZone("10.2.0.1", "host.restricted.zone") {
		t.Error("10.2.0.1 should be allowed")
	}

	// 10.1.0.1 is in both allow and deny → denied (deny takes priority)
	if acl.CheckWithZone("10.1.0.1", "host.restricted.zone") {
		t.Error("10.1.0.1 should be denied (deny overrides allow)")
	}
}

func TestCheckWithZoneInvalidIP(t *testing.T) {
	acl, err := NewACL(nil, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	if acl.CheckWithZone("not-an-ip", "example.com") {
		t.Error("invalid IP should return false")
	}
}

func TestCheckWithZoneTrailingDot(t *testing.T) {
	acl, err := NewACL([]string{"0.0.0.0/0"}, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "internal.corp.",
		Allow: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	// Query with trailing dot in qname — should still match
	if !acl.CheckWithZone("10.0.0.1", "server.internal.corp.") {
		t.Error("10.0.0.1 should be allowed for zone with trailing dot")
	}

	// External IP should be denied by zone rule (no 0.0.0.0/0 in zone allow)
	if acl.CheckWithZone("192.168.1.1", "server.internal.corp") {
		t.Error("192.168.1.1 should be denied for internal.corp zone")
	}
}

func TestAddZoneACLInvalidCIDR(t *testing.T) {
	acl, err := NewACL(nil, nil)
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "test.zone",
		Allow: []string{"bad-cidr"},
	})
	if err == nil {
		t.Error("expected error for invalid allow CIDR in zone ACL")
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone: "test.zone",
		Deny: []string{"also-bad"},
	})
	if err == nil {
		t.Error("expected error for invalid deny CIDR in zone ACL")
	}
}

func TestInZoneOrEqual(t *testing.T) {
	tests := []struct {
		qname, zone string
		want        bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", "example.com", true},
		{"deep.sub.example.com", "example.com", true},
		{"other.com", "example.com", false},
		{"notexample.com", "example.com", false},
		{"com", "example.com", false},
		{"", "", true},
	}

	for _, tc := range tests {
		got := inZoneOrEqual(tc.qname, tc.zone)
		if got != tc.want {
			t.Errorf("inZoneOrEqual(%q, %q) = %v, want %v", tc.qname, tc.zone, got, tc.want)
		}
	}
}

func TestCheckWithZoneIPv6(t *testing.T) {
	acl, err := NewACL([]string{"::/0"}, nil) // global: allow all IPv6
	if err != nil {
		t.Fatalf("NewACL error: %v", err)
	}

	err = acl.AddZoneACL(ZoneACLConfig{
		Zone:  "v6only.zone",
		Allow: []string{"fd00::/8"},
	})
	if err != nil {
		t.Fatalf("AddZoneACL error: %v", err)
	}

	if !acl.CheckWithZone("fd00::1", "host.v6only.zone") {
		t.Error("fd00::1 should be allowed for v6only.zone")
	}
	if acl.CheckWithZone("2001:db8::1", "host.v6only.zone") {
		t.Error("2001:db8::1 should be denied for v6only.zone")
	}
	// Global fallback
	if !acl.CheckWithZone("2001:db8::1", "other.zone") {
		t.Error("2001:db8::1 should be allowed by global rule for other.zone")
	}
}
