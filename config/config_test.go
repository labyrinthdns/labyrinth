package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.Server.ListenAddr != ":53" {
		t.Errorf("listen: expected ':53', got %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.MetricsAddr != "127.0.0.1:9153" {
		t.Errorf("metrics: expected '127.0.0.1:9153', got %q", cfg.Server.MetricsAddr)
	}
	if cfg.Cache.MaxEntries != 100000 {
		t.Errorf("cache max: expected 100000, got %d", cfg.Cache.MaxEntries)
	}
	if cfg.Cache.MinTTL != 5 {
		t.Errorf("min ttl: expected 5, got %d", cfg.Cache.MinTTL)
	}
	if cfg.Cache.MaxTTL != 86400 {
		t.Errorf("max ttl: expected 86400, got %d", cfg.Cache.MaxTTL)
	}
	if cfg.Resolver.MaxDepth != 30 {
		t.Errorf("max depth: expected 30, got %d", cfg.Resolver.MaxDepth)
	}
	if !cfg.Resolver.QMinEnabled {
		t.Error("qmin should be enabled by default")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("log level: expected 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Cache.ServeStale {
		t.Error("serve-stale should be disabled by default")
	}
	if cfg.Cache.StaleTTL != 30 {
		t.Errorf("stale ttl: expected 30, got %d", cfg.Cache.StaleTTL)
	}
	if cfg.Web.DoH3Enabled {
		t.Error("web.doh3_enabled should be disabled by default")
	}
}

func TestParseYAML(t *testing.T) {
	yaml := `
server:
  listen_addr: "0.0.0.0:5353"
  metrics_addr: "0.0.0.0:9153"

resolver:
  max_depth: 20
  qname_minimization: false

cache:
  max_entries: 50000
  min_ttl: 10
  serve_stale: true
  serve_stale_ttl: 60

logging:
  level: debug
  format: text
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}

	tests := map[string]string{
		"server.listen_addr":          "0.0.0.0:5353",
		"server.metrics_addr":         "0.0.0.0:9153",
		"resolver.max_depth":          "20",
		"resolver.qname_minimization": "false",
		"cache.max_entries":           "50000",
		"cache.min_ttl":               "10",
		"cache.serve_stale":           "true",
		"cache.serve_stale_ttl":       "60",
		"logging.level":               "debug",
		"logging.format":              "text",
	}

	for key, expected := range tests {
		if got, ok := values[key]; !ok {
			t.Errorf("key %q not found", key)
		} else if got != expected {
			t.Errorf("key %q: expected %q, got %q", key, expected, got)
		}
	}
}

func TestParseYAMLComments(t *testing.T) {
	yaml := `
server:
  listen_addr: ":53"  # inline comment
  # full line comment
  metrics_addr: "127.0.0.1:9153"
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}

	if v := values["server.listen_addr"]; v != ":53" {
		t.Errorf("expected ':53', got %q (comment not stripped)", v)
	}
	if v := values["server.metrics_addr"]; v != "127.0.0.1:9153" {
		t.Errorf("expected '127.0.0.1:9153', got %q", v)
	}
}

func TestParseYAMLQuotedValues(t *testing.T) {
	yaml := `
logging:
  level: "info"
  format: 'json'
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}

	if v := values["logging.level"]; v != "info" {
		t.Errorf("double quotes not stripped: got %q", v)
	}
	if v := values["logging.format"]; v != "json" {
		t.Errorf("single quotes not stripped: got %q", v)
	}
}

func TestParseYAMLUTF8BOM(t *testing.T) {
	yaml := "\ufeffserver:\n  listen_addr: \"127.0.0.1:5353\"\n"
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}
	if v := values["server.listen_addr"]; v != "127.0.0.1:5353" {
		t.Errorf("expected BOM-prefixed YAML to parse listen_addr, got %q", v)
	}
}

func TestApplyYAML(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"server.listen_addr":          "0.0.0.0:5353",
		"server.max_tcp_conns":        "123",
		"server.max_udp_workers":      "4096",
		"server.graceful_period":      "9s",
		"resolver.max_depth":          "15",
		"resolver.qname_minimization": "false",
		"cache.max_entries":           "200000",
		"cache.min_ttl":               "10",
		"cache.max_ttl":               "43200",
		"cache.sweep_interval":        "30s",
		"cache.serve_stale":           "true",
		"cache.stale_ttl":             "45",
		"security.rate_limit.enabled": "false",
		"security.rate_limit.rate":    "100",
		"security.rate_limit.burst":   "200",
		"security.rrl.ipv4_prefix":    "16",
		"security.rrl.ipv6_prefix":    "48",
		"logging.level":               "debug",
		"access_control.allow":        "10.0.0.0/8, 192.168.0.0/16",
		"web.doh3_enabled":            "true",
	}

	applyYAML(cfg, values)

	if cfg.Server.ListenAddr != "0.0.0.0:5353" {
		t.Errorf("listen addr: got %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.MaxTCPConns != 123 {
		t.Errorf("max tcp conns: got %d", cfg.Server.MaxTCPConns)
	}
	if cfg.Server.MaxUDPWorkers != 4096 {
		t.Errorf("max udp workers: got %d", cfg.Server.MaxUDPWorkers)
	}
	if cfg.Server.GracefulPeriod != 9*time.Second {
		t.Errorf("graceful period: got %v", cfg.Server.GracefulPeriod)
	}
	if cfg.Resolver.MaxDepth != 15 {
		t.Errorf("max depth: got %d", cfg.Resolver.MaxDepth)
	}
	if cfg.Resolver.QMinEnabled {
		t.Error("qmin should be disabled")
	}
	if cfg.Cache.MaxEntries != 200000 {
		t.Errorf("cache max: got %d", cfg.Cache.MaxEntries)
	}
	if cfg.Cache.MinTTL != 10 {
		t.Errorf("min ttl: got %d", cfg.Cache.MinTTL)
	}
	if cfg.Cache.MaxTTL != 43200 {
		t.Errorf("max ttl: got %d", cfg.Cache.MaxTTL)
	}
	if cfg.Cache.SweepInterval != 30*time.Second {
		t.Errorf("sweep interval: got %v", cfg.Cache.SweepInterval)
	}
	if !cfg.Cache.ServeStale {
		t.Error("serve stale should be true")
	}
	if cfg.Cache.StaleTTL != 45 {
		t.Errorf("stale ttl: got %d", cfg.Cache.StaleTTL)
	}
	if cfg.Security.RateLimit.Enabled {
		t.Error("rate limit should be disabled")
	}
	if cfg.Security.RateLimit.Rate != 100 {
		t.Errorf("rate: got %f", cfg.Security.RateLimit.Rate)
	}
	if cfg.Security.RateLimit.Burst != 200 {
		t.Errorf("burst: got %d", cfg.Security.RateLimit.Burst)
	}
	if cfg.Security.RRL.IPv4Prefix != 16 {
		t.Errorf("ipv4 prefix: got %d", cfg.Security.RRL.IPv4Prefix)
	}
	if cfg.Security.RRL.IPv6Prefix != 48 {
		t.Errorf("ipv6 prefix: got %d", cfg.Security.RRL.IPv6Prefix)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("log level: got %q", cfg.Logging.Level)
	}
	if !cfg.Web.DoH3Enabled {
		t.Error("web.doh3_enabled should be true")
	}
	if len(cfg.ACL.Allow) != 2 {
		t.Fatalf("acl allow: expected 2, got %d", len(cfg.ACL.Allow))
	}
	if cfg.ACL.Allow[0] != "10.0.0.0/8" || cfg.ACL.Allow[1] != "192.168.0.0/16" {
		t.Errorf("acl allow: got %v", cfg.ACL.Allow)
	}
}

func TestApplyEnv(t *testing.T) {
	cfg := defaultConfig()

	os.Setenv("LABYRINTH_SERVER_LISTEN_ADDR", ":5454")
	os.Setenv("LABYRINTH_LOGGING_LEVEL", "warn")
	defer os.Unsetenv("LABYRINTH_SERVER_LISTEN_ADDR")
	defer os.Unsetenv("LABYRINTH_LOGGING_LEVEL")

	applyEnv(cfg)

	if cfg.Server.ListenAddr != ":5454" {
		t.Errorf("listen addr: got %q", cfg.Server.ListenAddr)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("log level: got %q", cfg.Logging.Level)
	}
}

func TestValidateValid(t *testing.T) {
	cfg := defaultConfig()
	if err := validate(cfg); err != nil {
		t.Fatalf("valid config should not error: %v", err)
	}
}

func TestValidateInvalid(t *testing.T) {
	cfg := defaultConfig()
	cfg.Resolver.MaxDepth = 0
	if err := validate(cfg); err == nil {
		t.Error("max_depth=0 should fail validation")
	}

	cfg = defaultConfig()
	cfg.Cache.MinTTL = 1000
	cfg.Cache.MaxTTL = 100
	if err := validate(cfg); err == nil {
		t.Error("min_ttl > max_ttl should fail validation")
	}

	cfg = defaultConfig()
	cfg.Security.RateLimit.Enabled = true
	cfg.Security.RateLimit.Rate = 0
	if err := validate(cfg); err == nil {
		t.Error("rate=0 with enabled=true should fail validation")
	}

	cfg = defaultConfig()
	cfg.Server.DoTEnabled = true
	cfg.Server.TLSCertFile = ""
	cfg.Server.TLSKeyFile = ""
	if err := validate(cfg); err == nil {
		t.Error("dot_enabled=true without cert/key should fail validation")
	}

	cfg = defaultConfig()
	cfg.Web.TLSEnabled = true
	cfg.Web.TLSCertFile = ""
	cfg.Web.TLSKeyFile = ""
	if err := validate(cfg); err == nil {
		t.Error("web.tls_enabled=true without cert/key should fail validation")
	}

	cfg = defaultConfig()
	cfg.Web.DoH3Enabled = true
	cfg.Web.TLSEnabled = false
	if err := validate(cfg); err == nil {
		t.Error("web.doh3_enabled=true without web.tls_enabled should fail validation")
	}

	cfg = defaultConfig()
	cfg.Web.Enabled = false
	cfg.Web.DoH3Enabled = true
	cfg.Web.TLSEnabled = true
	cfg.Web.TLSCertFile = "cert.pem"
	cfg.Web.TLSKeyFile = "key.pem"
	if err := validate(cfg); err == nil {
		t.Error("web.doh3_enabled=true with web.enabled=false should fail validation")
	}

	cfg = defaultConfig()
	cfg.Web.DoH3Enabled = true
	cfg.Web.TLSEnabled = true
	cfg.Web.TLSCertFile = ""
	cfg.Web.TLSKeyFile = ""
	if err := validate(cfg); err == nil {
		t.Error("web.doh3_enabled=true without cert/key should fail validation")
	}
}

func TestParse(t *testing.T) {
	cfg, err := Parse([]byte("resolver:\n  max_depth: 25\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Resolver.MaxDepth != 25 {
		t.Fatalf("resolver.max_depth mismatch: got %d", cfg.Resolver.MaxDepth)
	}
}

func TestParseValidationError(t *testing.T) {
	_, err := Parse([]byte("resolver:\n  max_depth: 0\n"))
	if err == nil {
		t.Fatal("expected validation error for max_depth=0")
	}
	if !strings.Contains(err.Error(), "resolver.max_depth") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/labyrinth.yaml")
	if err != nil {
		t.Fatalf("missing config file should not error: %v", err)
	}
	if cfg.Server.ListenAddr != ":53" {
		t.Errorf("should use defaults, got listen=%q", cfg.Server.ListenAddr)
	}
}

func TestLoadWithFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "labyrinth-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	yaml := `
server:
  listen_addr: ":5353"
resolver:
  max_depth: 25
`
	tmpFile.Write([]byte(yaml))
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if cfg.Server.ListenAddr != ":5353" {
		t.Errorf("listen: got %q", cfg.Server.ListenAddr)
	}
	if cfg.Resolver.MaxDepth != 25 {
		t.Errorf("max depth: got %d", cfg.Resolver.MaxDepth)
	}
}

func TestLoadEnvOverridesFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "labyrinth-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	yaml := `
server:
  listen_addr: ":5353"
`
	tmpFile.Write([]byte(yaml))
	tmpFile.Close()

	os.Setenv("LABYRINTH_SERVER_LISTEN_ADDR", ":9999")
	defer os.Unsetenv("LABYRINTH_SERVER_LISTEN_ADDR")

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if cfg.Server.ListenAddr != ":9999" {
		t.Errorf("env should override file, got %q", cfg.Server.ListenAddr)
	}
}

func TestParseCSVList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"10.0.0.0/8, 192.168.0.0/16", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"single", []string{"single"}},
		{" spaced , values ", []string{"spaced", "values"}},
		{"", nil},
	}

	for _, tt := range tests {
		got := parseCSVList(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("parseCSVList(%q): expected %d items, got %d", tt.input, len(tt.expected), len(got))
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("parseCSVList(%q)[%d]: expected %q, got %q", tt.input, i, tt.expected[i], got[i])
			}
		}
	}
}

func TestParseYAMLThreeLevelNesting(t *testing.T) {
	yaml := `
security:
  rate_limit:
    enabled: true
    rate: 50
    burst: 100
  rrl:
    enabled: false
    responses_per_second: 10
    ipv4_prefix: 24
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}

	tests := map[string]string{
		"security.rate_limit.enabled":       "true",
		"security.rate_limit.rate":          "50",
		"security.rate_limit.burst":         "100",
		"security.rrl.enabled":              "false",
		"security.rrl.responses_per_second": "10",
		"security.rrl.ipv4_prefix":          "24",
	}

	for key, expected := range tests {
		got, ok := values[key]
		if !ok {
			t.Errorf("key %q not found in parsed values", key)
		} else if got != expected {
			t.Errorf("key %q: expected %q, got %q", key, expected, got)
		}
	}
}

func TestParseYAMLFullConfig(t *testing.T) {
	yaml := `
server:
  listen_addr: "0.0.0.0:53"
  metrics_addr: "127.0.0.1:9153"

resolver:
  max_depth: 30
  qname_minimization: true

cache:
  max_entries: 100000
  serve_stale: false

security:
  rate_limit:
    enabled: true
    rate: 50
  rrl:
    enabled: true
    slip_ratio: 2

logging:
  level: info
  format: json

access_control:
  allow:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
  deny:
    - "10.1.0.0/16"
`
	cfg := defaultConfig()
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}
	applyYAML(cfg, values)

	if cfg.Server.ListenAddr != "0.0.0.0:53" {
		t.Errorf("listen: got %q", cfg.Server.ListenAddr)
	}
	if !cfg.Security.RateLimit.Enabled {
		t.Error("rate_limit should be enabled")
	}
	if cfg.Security.RateLimit.Rate != 50 {
		t.Errorf("rate: got %f", cfg.Security.RateLimit.Rate)
	}
	if !cfg.Security.RRL.Enabled {
		t.Error("rrl should be enabled")
	}
	if cfg.Security.RRL.SlipRatio != 2 {
		t.Errorf("slip_ratio: got %d", cfg.Security.RRL.SlipRatio)
	}
	if len(cfg.ACL.Allow) != 2 {
		t.Errorf("allow: expected 2, got %d", len(cfg.ACL.Allow))
	}
	if len(cfg.ACL.Deny) != 1 {
		t.Errorf("deny: expected 1, got %d", len(cfg.ACL.Deny))
	}
}

func TestParseYAMLArrays(t *testing.T) {
	yaml := `
access_control:
  allow:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  deny:
    - "10.1.0.0/16"
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}

	allow := values["access_control.allow"]
	if allow != "127.0.0.0/8,10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("allow: expected comma-separated CIDRs, got %q", allow)
	}

	deny := values["access_control.deny"]
	if deny != "10.1.0.0/16" {
		t.Errorf("deny: expected '10.1.0.0/16', got %q", deny)
	}
}

func TestParseYAMLArrayApplied(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"access_control.allow": "127.0.0.0/8,10.0.0.0/8",
		"access_control.deny":  "10.1.0.0/16",
	}
	applyYAML(cfg, values)

	if len(cfg.ACL.Allow) != 2 {
		t.Fatalf("allow: expected 2, got %d", len(cfg.ACL.Allow))
	}
	if cfg.ACL.Allow[0] != "127.0.0.0/8" {
		t.Errorf("allow[0]: got %q", cfg.ACL.Allow[0])
	}
	if len(cfg.ACL.Deny) != 1 || cfg.ACL.Deny[0] != "10.1.0.0/16" {
		t.Errorf("deny: got %v", cfg.ACL.Deny)
	}
}

func TestShippedLabyrinthYAML(t *testing.T) {
	data, err := os.ReadFile("../labyrinth.yaml")
	if err != nil {
		t.Skip("labyrinth.yaml not found (running from different directory)")
	}

	values, err := parseYAML(data)
	if err != nil {
		t.Fatalf("parseYAML error on shipped config: %v", err)
	}

	// Verify key fields are parsed
	if v, ok := values["server.listen_addr"]; !ok || v == "" {
		t.Error("server.listen_addr not parsed from shipped config")
	}
	if v, ok := values["cache.max_entries"]; !ok || v == "" {
		t.Error("cache.max_entries not parsed from shipped config")
	}
	if _, ok := values["security.rate_limit.enabled"]; !ok {
		t.Error("security.rate_limit.enabled not parsed (3-level nesting)")
	}

	// Verify it loads into a valid config
	cfg := defaultConfig()
	applyYAML(cfg, values)
	if err := validate(cfg); err != nil {
		t.Fatalf("shipped config validation failed: %v", err)
	}
}

func TestParseBool(t *testing.T) {
	truths := []string{"true", "True", "TRUE", "yes", "YES", "1"}
	for _, v := range truths {
		if !parseBool(v) {
			t.Errorf("parseBool(%q) should be true", v)
		}
	}

	falses := []string{"false", "False", "no", "0", "", "anything"}
	for _, v := range falses {
		if parseBool(v) {
			t.Errorf("parseBool(%q) should be false", v)
		}
	}
}

func TestApplyYAMLCluster(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"cluster.enabled":                    "true",
		"cluster.role":                       "master",
		"cluster.node_id":                    "dns-1",
		"cluster.shared_fields":              "access_control, blocklist",
		"cluster.actions.fanout_cache_flush": "true",
		"cluster.sync.mode":                  "manual_push",
		"cluster.sync.push_on_save":          "true",
		"cluster.sync.pull_interval":         "45s",
		"cluster.peers.dns-2.enabled":        "true",
		"cluster.peers.dns-2.api_base":       "http://10.0.0.2:9153",
		"cluster.peers.dns-2.api_token":      "abc123",
		"cluster.peers.dns-2.sync_fields":    "access_control,blocklist",
	}

	applyYAML(cfg, values)

	if !cfg.Cluster.Enabled {
		t.Fatal("cluster should be enabled")
	}
	if cfg.Cluster.Role != "master" {
		t.Fatalf("role mismatch: %q", cfg.Cluster.Role)
	}
	if cfg.Cluster.NodeID != "dns-1" {
		t.Fatalf("node id mismatch: %q", cfg.Cluster.NodeID)
	}
	if !cfg.Cluster.Actions.FanoutCacheFlush {
		t.Fatal("fanout_cache_flush should be enabled")
	}
	if cfg.Cluster.Sync.Mode != "manual_push" {
		t.Fatalf("sync mode mismatch: %q", cfg.Cluster.Sync.Mode)
	}
	if !cfg.Cluster.Sync.PushOnSave {
		t.Fatal("sync.push_on_save should be true")
	}
	if cfg.Cluster.Sync.PullInterval != 45*time.Second {
		t.Fatalf("sync.pull_interval mismatch: %v", cfg.Cluster.Sync.PullInterval)
	}
	if len(cfg.Cluster.Peers) != 1 {
		t.Fatalf("expected 1 cluster peer, got %d", len(cfg.Cluster.Peers))
	}
	peer := cfg.Cluster.Peers[0]
	if peer.Name != "dns-2" || peer.APIBase != "http://10.0.0.2:9153" || peer.APIToken != "abc123" {
		t.Fatalf("peer mismatch: %+v", peer)
	}
}

func TestValidateClusterRole(t *testing.T) {
	cfg := defaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.Role = "invalid"
	if err := validate(cfg); err == nil {
		t.Fatal("expected cluster.role validation error")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	// Cover the error path when YAML parsing fails
	tmpFile, err := os.CreateTemp("", "labyrinth-bad-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write content that will trigger a parse error:
	// a line with a colon in value but structured to confuse the parser
	// Actually, our simple parseYAML never returns errors. Let's check.
	// Looking at parseYAML, it always returns (result, nil).
	// The error path in Load is: parseYAML returns err != nil.
	// Since our parseYAML never errors, we need a different approach.
	// The error from Load comes from validate() failing after parse.
	// Let's create a config that fails validation instead.
	yaml := `
resolver:
  max_depth: 0
`
	tmpFile.Write([]byte(yaml))
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	if err == nil {
		t.Error("expected validation error for max_depth=0")
	}
}

func TestApplyEnvResolverMaxDepth(t *testing.T) {
	// Cover LABYRINTH_RESOLVER_MAX_DEPTH env var branch
	cfg := defaultConfig()

	os.Setenv("LABYRINTH_RESOLVER_MAX_DEPTH", "50")
	defer os.Unsetenv("LABYRINTH_RESOLVER_MAX_DEPTH")

	applyEnv(cfg)

	if cfg.Resolver.MaxDepth != 50 {
		t.Errorf("expected MaxDepth=50, got %d", cfg.Resolver.MaxDepth)
	}
}

func TestApplyEnvCacheMaxEntries(t *testing.T) {
	// Cover LABYRINTH_CACHE_MAX_ENTRIES env var branch
	cfg := defaultConfig()

	os.Setenv("LABYRINTH_CACHE_MAX_ENTRIES", "500000")
	defer os.Unsetenv("LABYRINTH_CACHE_MAX_ENTRIES")

	applyEnv(cfg)

	if cfg.Cache.MaxEntries != 500000 {
		t.Errorf("expected MaxEntries=500000, got %d", cfg.Cache.MaxEntries)
	}
}

func TestApplyEnvLoggingFormat(t *testing.T) {
	// Cover LABYRINTH_LOGGING_FORMAT env var branch
	cfg := defaultConfig()

	os.Setenv("LABYRINTH_LOGGING_FORMAT", "text")
	defer os.Unsetenv("LABYRINTH_LOGGING_FORMAT")

	applyEnv(cfg)

	if cfg.Logging.Format != "text" {
		t.Errorf("expected Format='text', got %q", cfg.Logging.Format)
	}
}

func TestApplyEnvMetricsAddr(t *testing.T) {
	// Cover LABYRINTH_SERVER_METRICS_ADDR env var branch
	cfg := defaultConfig()

	os.Setenv("LABYRINTH_SERVER_METRICS_ADDR", "0.0.0.0:9999")
	defer os.Unsetenv("LABYRINTH_SERVER_METRICS_ADDR")

	applyEnv(cfg)

	if cfg.Server.MetricsAddr != "0.0.0.0:9999" {
		t.Errorf("expected MetricsAddr='0.0.0.0:9999', got %q", cfg.Server.MetricsAddr)
	}
}

func TestParseBlocklistEntries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []BlocklistEntry
	}{
		{
			name:     "single entry",
			input:    "https://example.com/list.txt|hosts",
			expected: []BlocklistEntry{{URL: "https://example.com/list.txt", Format: "hosts"}},
		},
		{
			name:  "multiple entries",
			input: "https://a.com/l1|hosts,https://b.com/l2|domains",
			expected: []BlocklistEntry{
				{URL: "https://a.com/l1", Format: "hosts"},
				{URL: "https://b.com/l2", Format: "domains"},
			},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "empty items with commas",
			input:    " , , ",
			expected: nil,
		},
		{
			name:     "entry without pipe separator is skipped",
			input:    "https://example.com/list.txt",
			expected: nil,
		},
		{
			name:  "mixed valid and no-pipe entries",
			input: "https://a.com/l1|hosts,nopipe,https://b.com/l2|domains",
			expected: []BlocklistEntry{
				{URL: "https://a.com/l1", Format: "hosts"},
				{URL: "https://b.com/l2", Format: "domains"},
			},
		},
		{
			name:     "whitespace trimming",
			input:    " https://a.com/list | hosts ",
			expected: []BlocklistEntry{{URL: "https://a.com/list", Format: "hosts"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBlocklistEntries(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d entries, got %d: %v", len(tt.expected), len(got), got)
			}
			for i := range got {
				if got[i].URL != tt.expected[i].URL {
					t.Errorf("[%d] URL: expected %q, got %q", i, tt.expected[i].URL, got[i].URL)
				}
				if got[i].Format != tt.expected[i].Format {
					t.Errorf("[%d] Format: expected %q, got %q", i, tt.expected[i].Format, got[i].Format)
				}
			}
		})
	}
}

func TestApplyYAMLBlocklistFields(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"blocklist.enabled":          "true",
		"blocklist.lists":            "https://example.com/hosts.txt|hosts,https://example.com/domains.txt|domains",
		"blocklist.refresh_interval": "12h",
		"blocklist.blocking_mode":    "custom_ip",
		"blocklist.custom_ip":        "0.0.0.0",
		"blocklist.whitelist":        "example.com, example.org",
	}

	applyYAML(cfg, values)

	if !cfg.Blocklist.Enabled {
		t.Error("blocklist should be enabled")
	}
	if len(cfg.Blocklist.Lists) != 2 {
		t.Fatalf("expected 2 blocklist entries, got %d", len(cfg.Blocklist.Lists))
	}
	if cfg.Blocklist.Lists[0].URL != "https://example.com/hosts.txt" {
		t.Errorf("lists[0].URL: got %q", cfg.Blocklist.Lists[0].URL)
	}
	if cfg.Blocklist.Lists[0].Format != "hosts" {
		t.Errorf("lists[0].Format: got %q", cfg.Blocklist.Lists[0].Format)
	}
	if cfg.Blocklist.Lists[1].URL != "https://example.com/domains.txt" {
		t.Errorf("lists[1].URL: got %q", cfg.Blocklist.Lists[1].URL)
	}
	if cfg.Blocklist.RefreshInterval != 12*time.Hour {
		t.Errorf("refresh_interval: got %v", cfg.Blocklist.RefreshInterval)
	}
	if cfg.Blocklist.BlockingMode != "custom_ip" {
		t.Errorf("blocking_mode: got %q", cfg.Blocklist.BlockingMode)
	}
	if cfg.Blocklist.CustomIP != "0.0.0.0" {
		t.Errorf("custom_ip: got %q", cfg.Blocklist.CustomIP)
	}
	if len(cfg.Blocklist.Whitelist) != 2 {
		t.Fatalf("expected 2 whitelist entries, got %d", len(cfg.Blocklist.Whitelist))
	}
	if cfg.Blocklist.Whitelist[0] != "example.com" || cfg.Blocklist.Whitelist[1] != "example.org" {
		t.Errorf("whitelist: got %v", cfg.Blocklist.Whitelist)
	}
}

func TestLoadWithInvalidYAMLSyntax(t *testing.T) {
	// Our simple YAML parser never returns an error, so the parseYAML error
	// branch in Load is unreachable dead code. We verify that even
	// badly-formed YAML still loads (falling back to defaults + env).
	tmpFile, err := os.CreateTemp("", "labyrinth-malformed-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	badYAML := `
:::: not valid yaml at all {{{{
	tabs mixed: with: colons: everywhere
`
	tmpFile.Write([]byte(badYAML))
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("load should succeed (simple parser ignores syntax errors): %v", err)
	}
	if cfg.Server.ListenAddr != ":53" {
		t.Errorf("expected default listen addr, got %q", cfg.Server.ListenAddr)
	}
}

func TestApplyYAMLNoCacheClients(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"cache.no_cache_clients": "192.168.1.1, 10.0.0.1, 172.16.0.0/12",
	}

	applyYAML(cfg, values)

	if len(cfg.Cache.NoCacheClients) != 3 {
		t.Fatalf("expected 3 no_cache_clients, got %d", len(cfg.Cache.NoCacheClients))
	}
	if cfg.Cache.NoCacheClients[0] != "192.168.1.1" {
		t.Errorf("no_cache_clients[0]: got %q", cfg.Cache.NoCacheClients[0])
	}
	if cfg.Cache.NoCacheClients[1] != "10.0.0.1" {
		t.Errorf("no_cache_clients[1]: got %q", cfg.Cache.NoCacheClients[1])
	}
	if cfg.Cache.NoCacheClients[2] != "172.16.0.0/12" {
		t.Errorf("no_cache_clients[2]: got %q", cfg.Cache.NoCacheClients[2])
	}
}

func TestLoadYAMLParseError(t *testing.T) {
	// Cover the parseYAML error return path in Load (lines 146-148).
	// Temporarily replace yamlParser with one that always returns an error.
	orig := yamlParser
	yamlParser = func(data []byte) (map[string]string, error) {
		return nil, fmt.Errorf("forced parse error")
	}
	defer func() { yamlParser = orig }()

	tmpFile, err := os.CreateTemp("", "labyrinth-parseerr-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.Write([]byte("server:\n  listen_addr: ':53'\n"))
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	if err == nil {
		t.Fatal("expected error from Load when yamlParser fails")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("expected 'parse config' in error, got: %v", err)
	}
}
