package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// yamlParser is the function used to parse YAML data.
// It defaults to parseYAML and can be overridden in tests.
var yamlParser = parseYAML

// Config holds the complete application configuration.
type Config struct {
	Server     ServerConfig
	Resolver   ResolverConfig
	Cache      CacheConfig
	Security   SecurityConfig
	Logging    LoggingConfig
	ACL        ACLConfig
	Web        WebConfig
	Daemon     DaemonConfig
	Zabbix     ZabbixConfig
	Blocklist  BlocklistConfig
	LocalZones   []LocalZoneConfig
	ForwardZones []ForwardZoneConfig
	StubZones    []StubZoneConfig
}

// ForwardZoneConfig holds a single forward zone: queries matching the zone
// name are forwarded (RD=1) to the configured upstream addresses.
type ForwardZoneConfig struct {
	Name  string
	Addrs []string
}

// StubZoneConfig holds a single stub zone: the resolver starts iterative
// resolution (RD=0) from the configured nameserver addresses instead of roots.
type StubZoneConfig struct {
	Name  string
	Addrs []string
}

// LocalZoneConfig holds a local zone's definition from the config file.
type LocalZoneConfig struct {
	Name string
	Type string
	Data []string
}

// BlocklistConfig holds blocklist filtering settings.
type BlocklistConfig struct {
	Enabled         bool
	Lists           []BlocklistEntry
	RefreshInterval time.Duration
	BlockingMode    string
	CustomIP        string
	Whitelist       []string
}

// BlocklistEntry holds a single blocklist source URL and its format.
type BlocklistEntry struct {
	URL    string
	Format string
}

// WebConfig holds web dashboard settings.
type WebConfig struct {
	Enabled             bool
	Addr                string
	QueryLogBuffer      int
	TopClientsLimit     int
	TopDomainsLimit     int
	AutoUpdate          bool
	UpdateCheckInterval time.Duration
	Auth                WebAuthConfig
	DoHEnabled          bool
	TLSEnabled          bool
	TLSCertFile         string
	TLSKeyFile          string
}

// WebAuthConfig holds web dashboard authentication settings.
type WebAuthConfig struct {
	Username     string
	PasswordHash string
}

// DaemonConfig holds daemon mode settings.
type DaemonConfig struct {
	Enabled bool
	PIDFile string
}

// ZabbixConfig holds Zabbix integration settings.
type ZabbixConfig struct {
	Enabled bool
	Addr    string
}

// ServerConfig holds server-related settings.
type ServerConfig struct {
	ListenAddr     string
	MetricsAddr    string
	MaxUDPSize     int
	TCPTimeout     time.Duration
	MaxTCPConns    int
	MaxUDPWorkers  int
	GracefulPeriod time.Duration
	TCPPipelineMax int
	TCPIdleTimeout time.Duration
	DoTEnabled     bool
	DoTListenAddr  string
	TLSCertFile    string
	TLSKeyFile     string
}

// ResolverConfig holds resolver settings.
type ResolverConfig struct {
	MaxDepth            int
	MaxCNAMEDepth       int
	UpstreamTimeout     time.Duration
	UpstreamRetries     int
	QMinEnabled         bool
	PreferIPv4          bool
	DNSSECEnabled       bool
	HardenBelowNXDomain bool
	RootHintsRefresh    time.Duration
}

// CacheConfig holds cache settings.
type CacheConfig struct {
	MaxEntries     int
	MinTTL         uint32
	MaxTTL         uint32
	NegMaxTTL      uint32
	SweepInterval  time.Duration
	ServeStale     bool
	StaleTTL       uint32
	NoCacheClients []string
	Prefetch       bool
}

// SecurityConfig holds security settings.
type SecurityConfig struct {
	RateLimit            RateLimitConfig
	RRL                  RRLConfig
	PrivateAddressFilter bool
}

// RateLimitConfig holds rate limiter settings.
type RateLimitConfig struct {
	Enabled bool
	Rate    float64
	Burst   int
}

// RRLConfig holds response rate limiting settings.
type RRLConfig struct {
	Enabled            bool
	ResponsesPerSecond float64
	SlipRatio          int
	IPv4Prefix         int
	IPv6Prefix         int
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string
	Format string
}

// ACLConfig holds access control list settings.
type ACLConfig struct {
	Allow []string
	Deny  []string
}

// Load loads configuration from file, environment, and defaults.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	// 1. Try config file
	if data, err := os.ReadFile(path); err == nil {
		values, err := yamlParser(data)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		applyYAML(cfg, values)
	}

	// 2. Override with environment variables
	applyEnv(cfg)

	// 3. Validate
	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyYAML(cfg *Config, values map[string]string) {
	if v, ok := values["server.listen_addr"]; ok {
		cfg.Server.ListenAddr = v
	}
	if v, ok := values["server.metrics_addr"]; ok {
		cfg.Server.MetricsAddr = v
	}
	if v, ok := values["server.max_udp_size"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.MaxUDPSize = n
		}
	}
	if v, ok := values["server.tcp_timeout"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.TCPTimeout = d
		}
	}
	if v, ok := values["server.max_tcp_connections"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.MaxTCPConns = n
		}
	}
	if v, ok := values["server.graceful_shutdown"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.GracefulPeriod = d
		}
	}
	if v, ok := values["server.tcp_pipeline_max"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.TCPPipelineMax = n
		}
	}
	if v, ok := values["server.tcp_idle_timeout"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.TCPIdleTimeout = d
		}
	}
	if v, ok := values["server.dot_enabled"]; ok {
		cfg.Server.DoTEnabled = parseBool(v)
	}
	if v, ok := values["server.dot_listen_addr"]; ok {
		cfg.Server.DoTListenAddr = v
	}
	if v, ok := values["server.tls_cert_file"]; ok {
		cfg.Server.TLSCertFile = v
	}
	if v, ok := values["server.tls_key_file"]; ok {
		cfg.Server.TLSKeyFile = v
	}

	// Resolver
	if v, ok := values["resolver.max_depth"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Resolver.MaxDepth = n
		}
	}
	if v, ok := values["resolver.max_cname_depth"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Resolver.MaxCNAMEDepth = n
		}
	}
	if v, ok := values["resolver.upstream_timeout"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Resolver.UpstreamTimeout = d
		}
	}
	if v, ok := values["resolver.upstream_retries"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Resolver.UpstreamRetries = n
		}
	}
	if v, ok := values["resolver.qname_minimization"]; ok {
		cfg.Resolver.QMinEnabled = parseBool(v)
	}
	if v, ok := values["resolver.prefer_ipv4"]; ok {
		cfg.Resolver.PreferIPv4 = parseBool(v)
	}
	if v, ok := values["resolver.dnssec_enabled"]; ok {
		cfg.Resolver.DNSSECEnabled = parseBool(v)
	}
	if v, ok := values["resolver.harden_below_nxdomain"]; ok {
		cfg.Resolver.HardenBelowNXDomain = parseBool(v)
	}
	if v, ok := values["resolver.root_hints_refresh"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Resolver.RootHintsRefresh = d
		}
	}

	// Cache
	if v, ok := values["cache.max_entries"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Cache.MaxEntries = n
		}
	}
	if v, ok := values["cache.min_ttl"]; ok {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.Cache.MinTTL = uint32(n)
		}
	}
	if v, ok := values["cache.max_ttl"]; ok {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.Cache.MaxTTL = uint32(n)
		}
	}
	if v, ok := values["cache.negative_max_ttl"]; ok {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.Cache.NegMaxTTL = uint32(n)
		}
	}
	if v, ok := values["cache.sweep_interval"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Cache.SweepInterval = d
		}
	}
	if v, ok := values["cache.serve_stale"]; ok {
		cfg.Cache.ServeStale = parseBool(v)
	}
	if v, ok := values["cache.serve_stale_ttl"]; ok {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.Cache.StaleTTL = uint32(n)
		}
	}
	if v, ok := values["cache.no_cache_clients"]; ok && v != "" {
		cfg.Cache.NoCacheClients = parseCSVList(v)
	}
	if v, ok := values["cache.prefetch"]; ok {
		cfg.Cache.Prefetch = parseBool(v)
	}

	// Security
	if v, ok := values["security.private_address_filter"]; ok {
		cfg.Security.PrivateAddressFilter = parseBool(v)
	}
	if v, ok := values["security.rate_limit.enabled"]; ok {
		cfg.Security.RateLimit.Enabled = parseBool(v)
	}
	if v, ok := values["security.rate_limit.rate"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Security.RateLimit.Rate = f
		}
	}
	if v, ok := values["security.rate_limit.burst"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Security.RateLimit.Burst = n
		}
	}
	if v, ok := values["security.rrl.enabled"]; ok {
		cfg.Security.RRL.Enabled = parseBool(v)
	}
	if v, ok := values["security.rrl.responses_per_second"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Security.RRL.ResponsesPerSecond = f
		}
	}
	if v, ok := values["security.rrl.slip_ratio"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Security.RRL.SlipRatio = n
		}
	}
	if v, ok := values["security.rrl.ipv4_prefix"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Security.RRL.IPv4Prefix = n
		}
	}
	if v, ok := values["security.rrl.ipv6_prefix"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Security.RRL.IPv6Prefix = n
		}
	}

	// ACL — parse comma-separated or individual entries
	if v, ok := values["access_control.allow"]; ok && v != "" {
		cfg.ACL.Allow = parseCSVList(v)
	}
	if v, ok := values["access_control.deny"]; ok && v != "" {
		cfg.ACL.Deny = parseCSVList(v)
	}

	// Logging
	if v, ok := values["logging.level"]; ok {
		cfg.Logging.Level = v
	}
	if v, ok := values["logging.format"]; ok {
		cfg.Logging.Format = v
	}

	// Web
	if v, ok := values["web.enabled"]; ok {
		cfg.Web.Enabled = parseBool(v)
	}
	if v, ok := values["web.addr"]; ok {
		cfg.Web.Addr = v
	}
	if v, ok := values["web.query_log_buffer"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Web.QueryLogBuffer = n
		}
	}
	if v, ok := values["web.top_clients_limit"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Web.TopClientsLimit = n
		}
	}
	if v, ok := values["web.top_domains_limit"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Web.TopDomainsLimit = n
		}
	}
	if v, ok := values["web.auto_update"]; ok {
		cfg.Web.AutoUpdate = parseBool(v)
	}
	if v, ok := values["web.update_check_interval"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Web.UpdateCheckInterval = d
		}
	}
	if v, ok := values["web.doh_enabled"]; ok {
		cfg.Web.DoHEnabled = parseBool(v)
	}
	if v, ok := values["web.tls_enabled"]; ok {
		cfg.Web.TLSEnabled = parseBool(v)
	}
	if v, ok := values["web.tls_cert_file"]; ok {
		cfg.Web.TLSCertFile = v
	}
	if v, ok := values["web.tls_key_file"]; ok {
		cfg.Web.TLSKeyFile = v
	}
	if v, ok := values["web.auth.username"]; ok {
		cfg.Web.Auth.Username = v
	}
	if v, ok := values["web.auth.password_hash"]; ok {
		cfg.Web.Auth.PasswordHash = v
	}

	// Daemon
	if v, ok := values["daemon.enabled"]; ok {
		cfg.Daemon.Enabled = parseBool(v)
	}
	if v, ok := values["daemon.pid_file"]; ok {
		cfg.Daemon.PIDFile = v
	}

	// Zabbix
	if v, ok := values["zabbix.enabled"]; ok {
		cfg.Zabbix.Enabled = parseBool(v)
	}
	if v, ok := values["zabbix.addr"]; ok {
		cfg.Zabbix.Addr = v
	}

	// Blocklist
	if v, ok := values["blocklist.enabled"]; ok {
		cfg.Blocklist.Enabled = parseBool(v)
	}
	if v, ok := values["blocklist.lists"]; ok && v != "" {
		cfg.Blocklist.Lists = parseBlocklistEntries(v)
	}
	if v, ok := values["blocklist.refresh_interval"]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Blocklist.RefreshInterval = d
		}
	}
	if v, ok := values["blocklist.blocking_mode"]; ok {
		cfg.Blocklist.BlockingMode = v
	}
	if v, ok := values["blocklist.custom_ip"]; ok {
		cfg.Blocklist.CustomIP = v
	}
	if v, ok := values["blocklist.whitelist"]; ok && v != "" {
		cfg.Blocklist.Whitelist = parseCSVList(v)
	}

	// Local zones: parsed from "local_zones.<name>.type" and "local_zones.<name>.data"
	cfg.LocalZones = parseLocalZones(values)

	// Forward zones: parsed from "forward_zones.<name>.addrs"
	cfg.ForwardZones = parseForwardZones(values)

	// Stub zones: parsed from "stub_zones.<name>.addrs"
	cfg.StubZones = parseStubZones(values)
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("LABYRINTH_SERVER_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("LABYRINTH_SERVER_METRICS_ADDR"); v != "" {
		cfg.Server.MetricsAddr = v
	}
	if v := os.Getenv("LABYRINTH_RESOLVER_MAX_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Resolver.MaxDepth = n
		}
	}
	if v := os.Getenv("LABYRINTH_CACHE_MAX_ENTRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Cache.MaxEntries = n
		}
	}
	if v := os.Getenv("LABYRINTH_LOGGING_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("LABYRINTH_LOGGING_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
}

func validate(cfg *Config) error {
	if cfg.Resolver.MaxDepth <= 0 {
		return fmt.Errorf("resolver.max_depth must be > 0")
	}
	if cfg.Cache.MinTTL > cfg.Cache.MaxTTL {
		return fmt.Errorf("cache.min_ttl (%d) must be <= cache.max_ttl (%d)", cfg.Cache.MinTTL, cfg.Cache.MaxTTL)
	}
	if cfg.Security.RateLimit.Enabled && cfg.Security.RateLimit.Rate <= 0 {
		return fmt.Errorf("security.rate_limit.rate must be > 0")
	}
	return nil
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "yes" || s == "1"
}

func parseCSVList(s string) []string {
	var result []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// parseBlocklistEntries parses a pipe-separated list of "url|format" pairs
// separated by commas: "url1|format1,url2|format2".
func parseBlocklistEntries(s string) []BlocklistEntry {
	var result []BlocklistEntry
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "|", 2)
		if len(parts) == 2 {
			result = append(result, BlocklistEntry{
				URL:    strings.TrimSpace(parts[0]),
				Format: strings.TrimSpace(parts[1]),
			})
		}
	}
	return result
}

// parseLocalZones extracts local zone configs from the flat YAML key map.
// Expected keys: "local_zones.<zonename>.type" and "local_zones.<zonename>.data"
// The data value is a comma-separated list of record strings.
func parseLocalZones(values map[string]string) []LocalZoneConfig {
	// Collect zone names from keys like "local_zones.localhost.type"
	zones := make(map[string]*LocalZoneConfig)
	const prefix = "local_zones."
	for key, val := range values {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key[len(prefix):]
		// rest = "<zonename>.type" or "<zonename>.data"
		dotIdx := strings.LastIndex(rest, ".")
		if dotIdx < 0 {
			continue
		}
		zoneName := rest[:dotIdx]
		field := rest[dotIdx+1:]

		zc, ok := zones[zoneName]
		if !ok {
			zc = &LocalZoneConfig{Name: zoneName}
			zones[zoneName] = zc
		}
		switch field {
		case "type":
			zc.Type = val
		case "data":
			if val != "" {
				for _, item := range strings.Split(val, ",") {
					item = strings.TrimSpace(item)
					if item != "" {
						zc.Data = append(zc.Data, item)
					}
				}
			}
		}
	}

	var result []LocalZoneConfig
	for _, zc := range zones {
		if zc.Type != "" {
			result = append(result, *zc)
		}
	}
	return result
}

// parseForwardZones extracts forward zone configs from the flat YAML key map.
// Expected keys: "forward_zones.<zonename>.addrs" (comma-separated IPs).
func parseForwardZones(values map[string]string) []ForwardZoneConfig {
	return parseZoneAddrs(values, "forward_zones.")
}

// parseStubZones extracts stub zone configs from the flat YAML key map.
// Expected keys: "stub_zones.<zonename>.addrs" (comma-separated IPs).
func parseStubZones(values map[string]string) []StubZoneConfig {
	zones := parseZoneAddrs(values, "stub_zones.")
	result := make([]StubZoneConfig, len(zones))
	for i, z := range zones {
		result[i] = StubZoneConfig{Name: z.Name, Addrs: z.Addrs}
	}
	return result
}

// parseZoneAddrs is a helper that extracts zone name + addrs from keys with
// the given prefix (e.g. "forward_zones." or "stub_zones.").
func parseZoneAddrs(values map[string]string, prefix string) []ForwardZoneConfig {
	zones := make(map[string]*ForwardZoneConfig)
	for key, val := range values {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key[len(prefix):]
		// rest = "<zonename>.addrs" or just "<zonename>"
		dotIdx := strings.LastIndex(rest, ".")
		if dotIdx < 0 {
			continue
		}
		zoneName := rest[:dotIdx]
		field := rest[dotIdx+1:]

		if field != "addrs" {
			continue
		}

		zc, ok := zones[zoneName]
		if !ok {
			zc = &ForwardZoneConfig{Name: zoneName}
			zones[zoneName] = zc
		}
		if val != "" {
			for _, item := range strings.Split(val, ",") {
				item = strings.TrimSpace(item)
				if item != "" {
					zc.Addrs = append(zc.Addrs, item)
				}
			}
		}
	}

	var result []ForwardZoneConfig
	for _, zc := range zones {
		if len(zc.Addrs) > 0 {
			result = append(result, *zc)
		}
	}
	return result
}
