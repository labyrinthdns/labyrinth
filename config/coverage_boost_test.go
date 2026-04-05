package config

import (
	"testing"
	"time"
)

// =============================================================================
// Coverage boost tests for config/config.go
// Targets: parseACLZones, parseLocalZones, parseStubZones, parseZoneAddrs,
//          and uncovered branches in applyYAML.
// =============================================================================

// --- applyYAML: uncovered branches ---

func TestApplyYAMLServerFields(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"server.max_udp_size":       "1232",
		"server.tcp_timeout":        "5s",
		"server.max_tcp_connections": "512",
		"server.graceful_shutdown":  "10s",
		"server.tcp_pipeline_max":   "200",
		"server.tcp_idle_timeout":   "30s",
		"server.dot_enabled":        "true",
		"server.dot_listen_addr":    ":8853",
		"server.tls_cert_file":      "/etc/tls/cert.pem",
		"server.tls_key_file":       "/etc/tls/key.pem",
	}
	applyYAML(cfg, values)

	if cfg.Server.MaxUDPSize != 1232 {
		t.Errorf("MaxUDPSize: got %d", cfg.Server.MaxUDPSize)
	}
	if cfg.Server.TCPTimeout != 5*time.Second {
		t.Errorf("TCPTimeout: got %v", cfg.Server.TCPTimeout)
	}
	if cfg.Server.MaxTCPConns != 512 {
		t.Errorf("MaxTCPConns: got %d", cfg.Server.MaxTCPConns)
	}
	if cfg.Server.GracefulPeriod != 10*time.Second {
		t.Errorf("GracefulPeriod: got %v", cfg.Server.GracefulPeriod)
	}
	if cfg.Server.TCPPipelineMax != 200 {
		t.Errorf("TCPPipelineMax: got %d", cfg.Server.TCPPipelineMax)
	}
	if cfg.Server.TCPIdleTimeout != 30*time.Second {
		t.Errorf("TCPIdleTimeout: got %v", cfg.Server.TCPIdleTimeout)
	}
	if !cfg.Server.DoTEnabled {
		t.Error("DoTEnabled should be true")
	}
	if cfg.Server.DoTListenAddr != ":8853" {
		t.Errorf("DoTListenAddr: got %q", cfg.Server.DoTListenAddr)
	}
	if cfg.Server.TLSCertFile != "/etc/tls/cert.pem" {
		t.Errorf("TLSCertFile: got %q", cfg.Server.TLSCertFile)
	}
	if cfg.Server.TLSKeyFile != "/etc/tls/key.pem" {
		t.Errorf("TLSKeyFile: got %q", cfg.Server.TLSKeyFile)
	}
}

func TestApplyYAMLResolverFields(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"resolver.max_cname_depth":       "5",
		"resolver.upstream_timeout":      "3s",
		"resolver.upstream_retries":      "5",
		"resolver.prefer_ipv4":           "false",
		"resolver.dnssec_enabled":        "false",
		"resolver.harden_below_nxdomain": "false",
		"resolver.root_hints_refresh":    "6h",
		"resolver.ecs_enabled":           "true",
		"resolver.ecs_max_prefix":        "20",
		"resolver.dns64_enabled":         "true",
		"resolver.dns64_prefix":          "2001:db8::/96",
	}
	applyYAML(cfg, values)

	if cfg.Resolver.MaxCNAMEDepth != 5 {
		t.Errorf("MaxCNAMEDepth: got %d", cfg.Resolver.MaxCNAMEDepth)
	}
	if cfg.Resolver.UpstreamTimeout != 3*time.Second {
		t.Errorf("UpstreamTimeout: got %v", cfg.Resolver.UpstreamTimeout)
	}
	if cfg.Resolver.UpstreamRetries != 5 {
		t.Errorf("UpstreamRetries: got %d", cfg.Resolver.UpstreamRetries)
	}
	if cfg.Resolver.PreferIPv4 {
		t.Error("PreferIPv4 should be false")
	}
	if cfg.Resolver.DNSSECEnabled {
		t.Error("DNSSECEnabled should be false")
	}
	if cfg.Resolver.HardenBelowNXDomain {
		t.Error("HardenBelowNXDomain should be false")
	}
	if cfg.Resolver.RootHintsRefresh != 6*time.Hour {
		t.Errorf("RootHintsRefresh: got %v", cfg.Resolver.RootHintsRefresh)
	}
	if !cfg.Resolver.ECSEnabled {
		t.Error("ECSEnabled should be true")
	}
	if cfg.Resolver.ECSMaxPrefix != 20 {
		t.Errorf("ECSMaxPrefix: got %d", cfg.Resolver.ECSMaxPrefix)
	}
	if !cfg.Resolver.DNS64Enabled {
		t.Error("DNS64Enabled should be true")
	}
	if cfg.Resolver.DNS64Prefix != "2001:db8::/96" {
		t.Errorf("DNS64Prefix: got %q", cfg.Resolver.DNS64Prefix)
	}
}

func TestApplyYAMLFallbackResolvers(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"resolver.fallback_resolvers": "8.8.8.8, 1.1.1.1, 9.9.9.9",
	}
	applyYAML(cfg, values)

	if len(cfg.Resolver.FallbackResolvers) != 3 {
		t.Fatalf("expected 3 fallback resolvers, got %d", len(cfg.Resolver.FallbackResolvers))
	}
	expected := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	for i, want := range expected {
		if cfg.Resolver.FallbackResolvers[i] != want {
			t.Errorf("fallback_resolvers[%d]: expected %q, got %q", i, want, cfg.Resolver.FallbackResolvers[i])
		}
	}
}

func TestApplyYAMLFallbackResolversEmpty(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{}
	applyYAML(cfg, values)

	if len(cfg.Resolver.FallbackResolvers) != 0 {
		t.Errorf("expected 0 fallback resolvers by default, got %d", len(cfg.Resolver.FallbackResolvers))
	}
}

func TestApplyYAMLFallbackResolversSingle(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"resolver.fallback_resolvers": "8.8.8.8",
	}
	applyYAML(cfg, values)

	if len(cfg.Resolver.FallbackResolvers) != 1 {
		t.Fatalf("expected 1 fallback resolver, got %d", len(cfg.Resolver.FallbackResolvers))
	}
	if cfg.Resolver.FallbackResolvers[0] != "8.8.8.8" {
		t.Errorf("got %q", cfg.Resolver.FallbackResolvers[0])
	}
}

func TestApplyYAMLCacheNegMaxTTL(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"cache.negative_max_ttl": "1800",
		"cache.prefetch":         "false",
	}
	applyYAML(cfg, values)

	if cfg.Cache.NegMaxTTL != 1800 {
		t.Errorf("NegMaxTTL: got %d", cfg.Cache.NegMaxTTL)
	}
	if cfg.Cache.Prefetch {
		t.Error("Prefetch should be false")
	}
}

func TestApplyYAMLSecurityFields(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"security.private_address_filter": "false",
		"security.dns_cookies":            "true",
		"security.rrl.enabled":            "true",
		"security.rrl.responses_per_second": "10",
		"security.rrl.slip_ratio":         "3",
	}
	applyYAML(cfg, values)

	if cfg.Security.PrivateAddressFilter {
		t.Error("PrivateAddressFilter should be false")
	}
	if !cfg.Security.DNSCookies {
		t.Error("DNSCookies should be true")
	}
	if !cfg.Security.RRL.Enabled {
		t.Error("RRL.Enabled should be true")
	}
	if cfg.Security.RRL.ResponsesPerSecond != 10 {
		t.Errorf("RRL.ResponsesPerSecond: got %f", cfg.Security.RRL.ResponsesPerSecond)
	}
	if cfg.Security.RRL.SlipRatio != 3 {
		t.Errorf("RRL.SlipRatio: got %d", cfg.Security.RRL.SlipRatio)
	}
}

func TestApplyYAMLWebExtraFields(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"web.top_clients_limit":     "50",
		"web.top_domains_limit":     "100",
		"web.alert_error_threshold_pct": "3.5",
		"web.alert_latency_threshold_ms": "180",
		"web.auto_update":           "false",
		"web.update_check_interval": "12h",
		"web.doh_enabled":           "true",
		"web.tls_enabled":           "true",
		"web.tls_cert_file":         "/path/cert.pem",
		"web.tls_key_file":          "/path/key.pem",
	}
	applyYAML(cfg, values)

	if cfg.Web.TopClientsLimit != 50 {
		t.Errorf("TopClientsLimit: got %d", cfg.Web.TopClientsLimit)
	}
	if cfg.Web.TopDomainsLimit != 100 {
		t.Errorf("TopDomainsLimit: got %d", cfg.Web.TopDomainsLimit)
	}
	if cfg.Web.AlertErrorThreshold != 3.5 {
		t.Errorf("AlertErrorThreshold: got %f", cfg.Web.AlertErrorThreshold)
	}
	if cfg.Web.AlertLatencyMs != 180 {
		t.Errorf("AlertLatencyMs: got %d", cfg.Web.AlertLatencyMs)
	}
	if cfg.Web.AutoUpdate {
		t.Error("AutoUpdate should be false")
	}
	if cfg.Web.UpdateCheckInterval != 12*time.Hour {
		t.Errorf("UpdateCheckInterval: got %v", cfg.Web.UpdateCheckInterval)
	}
	if !cfg.Web.DoHEnabled {
		t.Error("DoHEnabled should be true")
	}
	if !cfg.Web.TLSEnabled {
		t.Error("TLSEnabled should be true")
	}
	if cfg.Web.TLSCertFile != "/path/cert.pem" {
		t.Errorf("TLSCertFile: got %q", cfg.Web.TLSCertFile)
	}
	if cfg.Web.TLSKeyFile != "/path/key.pem" {
		t.Errorf("TLSKeyFile: got %q", cfg.Web.TLSKeyFile)
	}
}

// --- parseACLZones ---

func TestParseACLZonesBasic(t *testing.T) {
	values := map[string]string{
		"access_control.zones.example.com.allow": "10.0.0.0/8, 172.16.0.0/12",
		"access_control.zones.example.com.deny":  "10.1.0.0/16",
	}
	zones := parseACLZones(values)

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Zone != "example.com" {
		t.Errorf("zone: got %q", zones[0].Zone)
	}
	if len(zones[0].Allow) != 2 {
		t.Fatalf("allow: expected 2, got %d", len(zones[0].Allow))
	}
	if zones[0].Allow[0] != "10.0.0.0/8" {
		t.Errorf("allow[0]: got %q", zones[0].Allow[0])
	}
	if len(zones[0].Deny) != 1 || zones[0].Deny[0] != "10.1.0.0/16" {
		t.Errorf("deny: got %v", zones[0].Deny)
	}
}

func TestParseACLZonesMultipleZones(t *testing.T) {
	values := map[string]string{
		"access_control.zones.zone1.com.allow": "10.0.0.0/8",
		"access_control.zones.zone2.org.deny":  "192.168.0.0/16",
	}
	zones := parseACLZones(values)

	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
}

func TestParseACLZonesEmptyValues(t *testing.T) {
	values := map[string]string{
		"access_control.zones.example.com.allow": "",
		"access_control.zones.example.com.deny":  "",
	}
	zones := parseACLZones(values)

	// Empty allow/deny means no ACL entries are created
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for empty allow/deny, got %d", len(zones))
	}
}

func TestParseACLZonesUnknownField(t *testing.T) {
	values := map[string]string{
		"access_control.zones.example.com.unknown": "value",
	}
	zones := parseACLZones(values)

	// Unknown field means no allow/deny set, so zone should not appear
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for unknown field, got %d", len(zones))
	}
}

func TestParseACLZonesNoDot(t *testing.T) {
	// Keys with no dot in the rest portion (no field separator) are skipped
	values := map[string]string{
		"access_control.zones.nodotsuffix": "value",
	}
	zones := parseACLZones(values)
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for key with no field, got %d", len(zones))
	}
}

func TestParseACLZonesNonPrefixKeysIgnored(t *testing.T) {
	values := map[string]string{
		"server.listen_addr":                      ":53",
		"access_control.zones.example.com.allow":  "10.0.0.0/8",
	}
	zones := parseACLZones(values)
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
}

// --- parseLocalZones ---

func TestParseLocalZonesBasic(t *testing.T) {
	values := map[string]string{
		"local_zones.localhost.type": "static",
		"local_zones.localhost.data": "localhost. A 127.0.0.1, localhost. AAAA ::1",
	}
	zones := parseLocalZones(values)

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Name != "localhost" {
		t.Errorf("name: got %q", zones[0].Name)
	}
	if zones[0].Type != "static" {
		t.Errorf("type: got %q", zones[0].Type)
	}
	if len(zones[0].Data) != 2 {
		t.Fatalf("data: expected 2 entries, got %d", len(zones[0].Data))
	}
	if zones[0].Data[0] != "localhost. A 127.0.0.1" {
		t.Errorf("data[0]: got %q", zones[0].Data[0])
	}
	if zones[0].Data[1] != "localhost. AAAA ::1" {
		t.Errorf("data[1]: got %q", zones[0].Data[1])
	}
}

func TestParseLocalZonesMultipleZones(t *testing.T) {
	values := map[string]string{
		"local_zones.zone1.local.type": "static",
		"local_zones.zone1.local.data": "host. A 10.0.0.1",
		"local_zones.zone2.local.type": "deny",
	}
	zones := parseLocalZones(values)

	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
}

func TestParseLocalZonesEmptyData(t *testing.T) {
	values := map[string]string{
		"local_zones.example.local.type": "refuse",
		"local_zones.example.local.data": "",
	}
	zones := parseLocalZones(values)

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if len(zones[0].Data) != 0 {
		t.Errorf("expected empty data, got %v", zones[0].Data)
	}
}

func TestParseLocalZonesNoType(t *testing.T) {
	// Zone without type should be skipped
	values := map[string]string{
		"local_zones.orphan.local.data": "host. A 10.0.0.1",
	}
	zones := parseLocalZones(values)

	if len(zones) != 0 {
		t.Fatalf("expected 0 zones (no type), got %d", len(zones))
	}
}

func TestParseLocalZonesNoDot(t *testing.T) {
	values := map[string]string{
		"local_zones.nodotsuffix": "value",
	}
	zones := parseLocalZones(values)
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for key with no field, got %d", len(zones))
	}
}

func TestParseLocalZonesNonPrefixKeysIgnored(t *testing.T) {
	values := map[string]string{
		"server.listen_addr":                ":53",
		"local_zones.example.local.type":    "transparent",
		"local_zones.example.local.data":    "host. A 1.2.3.4",
	}
	zones := parseLocalZones(values)
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
}

func TestParseLocalZonesUnknownField(t *testing.T) {
	values := map[string]string{
		"local_zones.example.local.type":   "static",
		"local_zones.example.local.bogus":  "something",
	}
	zones := parseLocalZones(values)

	// Should still create the zone (type is set), but ignore "bogus" field
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Type != "static" {
		t.Errorf("type: got %q", zones[0].Type)
	}
}

// --- parseStubZones ---

func TestParseStubZonesBasic(t *testing.T) {
	values := map[string]string{
		"stub_zones.internal.corp.addrs": "10.0.0.53, 10.0.0.54",
	}
	zones := parseStubZones(values)

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Name != "internal.corp" {
		t.Errorf("name: got %q", zones[0].Name)
	}
	if len(zones[0].Addrs) != 2 {
		t.Fatalf("addrs: expected 2, got %d", len(zones[0].Addrs))
	}
	if zones[0].Addrs[0] != "10.0.0.53" {
		t.Errorf("addrs[0]: got %q", zones[0].Addrs[0])
	}
	if zones[0].Addrs[1] != "10.0.0.54" {
		t.Errorf("addrs[1]: got %q", zones[0].Addrs[1])
	}
}

func TestParseStubZonesEmpty(t *testing.T) {
	values := map[string]string{}
	zones := parseStubZones(values)
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones, got %d", len(zones))
	}
}

func TestParseStubZonesEmptyAddrs(t *testing.T) {
	values := map[string]string{
		"stub_zones.internal.corp.addrs": "",
	}
	zones := parseStubZones(values)

	// Empty addrs means no zone
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for empty addrs, got %d", len(zones))
	}
}

// --- parseZoneAddrs (tested via parseForwardZones) ---

func TestParseForwardZonesBasic(t *testing.T) {
	values := map[string]string{
		"forward_zones.example.com.addrs": "1.1.1.1, 8.8.8.8",
	}
	zones := parseForwardZones(values)

	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Name != "example.com" {
		t.Errorf("name: got %q", zones[0].Name)
	}
	if len(zones[0].Addrs) != 2 {
		t.Fatalf("addrs: expected 2, got %d", len(zones[0].Addrs))
	}
}

func TestParseForwardZonesMultiple(t *testing.T) {
	values := map[string]string{
		"forward_zones.zone1.com.addrs": "1.1.1.1",
		"forward_zones.zone2.org.addrs": "8.8.8.8, 8.8.4.4",
	}
	zones := parseForwardZones(values)
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
}

func TestParseForwardZonesNonAddrsField(t *testing.T) {
	values := map[string]string{
		"forward_zones.example.com.name":  "example.com",
		"forward_zones.example.com.addrs": "1.1.1.1",
	}
	zones := parseForwardZones(values)

	// "name" field should be ignored; only "addrs" is processed
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
}

func TestParseForwardZonesNoDot(t *testing.T) {
	values := map[string]string{
		"forward_zones.nodotsuffix": "1.1.1.1",
	}
	zones := parseForwardZones(values)
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for key with no field, got %d", len(zones))
	}
}

func TestParseForwardZonesNonPrefixIgnored(t *testing.T) {
	values := map[string]string{
		"server.listen_addr":                  ":53",
		"forward_zones.example.com.addrs":     "1.1.1.1",
	}
	zones := parseForwardZones(values)
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
}

func TestParseForwardZonesEmptyAddrs(t *testing.T) {
	values := map[string]string{
		"forward_zones.example.com.addrs": "",
	}
	zones := parseForwardZones(values)
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones for empty addrs, got %d", len(zones))
	}
}

// --- Integration: applyYAML with forward/stub/local zones ---

func TestApplyYAMLForwardZones(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"forward_zones.corp.local.addrs": "10.0.0.53, 10.0.0.54",
	}
	applyYAML(cfg, values)

	if len(cfg.ForwardZones) != 1 {
		t.Fatalf("expected 1 forward zone, got %d", len(cfg.ForwardZones))
	}
	if cfg.ForwardZones[0].Name != "corp.local" {
		t.Errorf("name: got %q", cfg.ForwardZones[0].Name)
	}
}

func TestApplyYAMLStubZones(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"stub_zones.internal.corp.addrs": "10.0.0.53",
	}
	applyYAML(cfg, values)

	if len(cfg.StubZones) != 1 {
		t.Fatalf("expected 1 stub zone, got %d", len(cfg.StubZones))
	}
	if cfg.StubZones[0].Name != "internal.corp" {
		t.Errorf("name: got %q", cfg.StubZones[0].Name)
	}
}

func TestApplyYAMLLocalZones(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"local_zones.blocked.local.type": "deny",
	}
	applyYAML(cfg, values)

	if len(cfg.LocalZones) != 1 {
		t.Fatalf("expected 1 local zone, got %d", len(cfg.LocalZones))
	}
	if cfg.LocalZones[0].Name != "blocked.local" {
		t.Errorf("name: got %q", cfg.LocalZones[0].Name)
	}
	if cfg.LocalZones[0].Type != "deny" {
		t.Errorf("type: got %q", cfg.LocalZones[0].Type)
	}
}

func TestApplyYAMLACLZones(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"access_control.zones.secret.local.allow": "192.168.0.0/16",
		"access_control.zones.secret.local.deny":  "192.168.1.0/24",
	}
	applyYAML(cfg, values)

	if len(cfg.ACL.Zones) != 1 {
		t.Fatalf("expected 1 ACL zone, got %d", len(cfg.ACL.Zones))
	}
	if cfg.ACL.Zones[0].Zone != "secret.local" {
		t.Errorf("zone: got %q", cfg.ACL.Zones[0].Zone)
	}
}

func TestApplyYAMLDenyACLZoneOnly(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"access_control.deny":                        "0.0.0.0/0",
		"access_control.zones.internal.corp.deny":    "192.168.0.0/16",
	}
	applyYAML(cfg, values)

	if len(cfg.ACL.Deny) != 1 || cfg.ACL.Deny[0] != "0.0.0.0/0" {
		t.Errorf("deny: got %v", cfg.ACL.Deny)
	}
	if len(cfg.ACL.Zones) != 1 {
		t.Fatalf("expected 1 ACL zone, got %d", len(cfg.ACL.Zones))
	}
}
