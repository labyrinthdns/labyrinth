package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// yamlParser is the function used to parse YAML data.
// It defaults to parseYAML and can be overridden in tests.
var yamlParser = parseYAML

// Config holds the complete application configuration.
type Config struct {
	Server       ServerConfig
	Resolver     ResolverConfig
	Cache        CacheConfig
	Security     SecurityConfig
	Logging      LoggingConfig
	ACL          ACLConfig
	Web          WebConfig
	Daemon       DaemonConfig
	Zabbix       ZabbixConfig
	Blocklist    BlocklistConfig
	Cluster      ClusterConfig
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
	DoH3Enabled         bool
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
	ECSEnabled          bool
	ECSMaxPrefix        int
	DNS64Enabled        bool
	DNS64Prefix         string
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
	DNSCookies           bool
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
	Zones []ACLZoneConfig
}

// ACLZoneConfig holds per-zone ACL settings.
type ACLZoneConfig struct {
	Zone  string
	Allow []string
	Deny  []string
}

// ClusterConfig holds optional multi-node cluster settings.
type ClusterConfig struct {
	Enabled      bool
	Role         string
	NodeID       string
	SharedFields []string
	Peers        []ClusterPeerConfig
	Actions      ClusterActionConfig
	Sync         ClusterSyncConfig
}

// ClusterPeerConfig defines a peer node accessible via admin API.
type ClusterPeerConfig struct {
	Name       string
	Enabled    bool
	APIBase    string
	APIToken   string
	SyncFields []string
}

// ClusterActionConfig controls cluster fanout behavior for admin actions.
type ClusterActionConfig struct {
	FanoutCacheFlush       bool
	FanoutBlocklistRefresh bool
}

// ClusterSyncConfig controls configuration synchronization behavior.
type ClusterSyncConfig struct {
	Mode         string
	PushOnSave   bool
	PullInterval time.Duration
}

// Parse builds a config from YAML bytes using defaults and validation.
// Environment variables are not applied in this helper.
func Parse(data []byte) (*Config, error) {
	cfg := defaultConfig()
	values, err := yamlParser(data)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyYAML(cfg, values)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load loads configuration from file, environment, and defaults.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	// 1. Try config file
	if data, err := os.ReadFile(path); err == nil {
		fileCfg, err := Parse(data)
		if err != nil {
			return nil, err
		}
		cfg = fileCfg
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
	setString := func(dst *string, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			*dst = v
		}
	}
	setBool := func(dst *bool, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			*dst = parseBool(v)
		}
	}
	setInt := func(dst *int, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	setUint32 := func(dst *uint32, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				*dst = uint32(n)
			}
		}
	}
	setFloat64 := func(dst *float64, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				*dst = n
			}
		}
	}
	setDuration := func(dst *time.Duration, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	setCSV := func(dst *[]string, keys ...string) {
		if v, ok := firstConfigValue(values, keys...); ok && strings.TrimSpace(v) != "" {
			*dst = parseCSVList(v)
		}
	}

	// Server
	setString(&cfg.Server.ListenAddr, "server.listen_addr")
	setString(&cfg.Server.MetricsAddr, "server.metrics_addr")
	setInt(&cfg.Server.MaxUDPSize, "server.max_udp_size")
	setDuration(&cfg.Server.TCPTimeout, "server.tcp_timeout")
	setInt(&cfg.Server.MaxTCPConns, "server.max_tcp_connections", "server.max_tcp_conns")
	setInt(&cfg.Server.MaxUDPWorkers, "server.max_udp_workers")
	setDuration(&cfg.Server.GracefulPeriod, "server.graceful_shutdown", "server.graceful_period")
	setInt(&cfg.Server.TCPPipelineMax, "server.tcp_pipeline_max")
	setDuration(&cfg.Server.TCPIdleTimeout, "server.tcp_idle_timeout")
	setBool(&cfg.Server.DoTEnabled, "server.dot_enabled")
	setString(&cfg.Server.DoTListenAddr, "server.dot_listen_addr")
	setString(&cfg.Server.TLSCertFile, "server.tls_cert_file")
	setString(&cfg.Server.TLSKeyFile, "server.tls_key_file")

	// Resolver
	setInt(&cfg.Resolver.MaxDepth, "resolver.max_depth")
	setInt(&cfg.Resolver.MaxCNAMEDepth, "resolver.max_cname_depth")
	setDuration(&cfg.Resolver.UpstreamTimeout, "resolver.upstream_timeout")
	setInt(&cfg.Resolver.UpstreamRetries, "resolver.upstream_retries")
	setBool(&cfg.Resolver.QMinEnabled, "resolver.qname_minimization")
	setBool(&cfg.Resolver.PreferIPv4, "resolver.prefer_ipv4")
	setBool(&cfg.Resolver.DNSSECEnabled, "resolver.dnssec_enabled")
	setBool(&cfg.Resolver.HardenBelowNXDomain, "resolver.harden_below_nxdomain")
	setDuration(&cfg.Resolver.RootHintsRefresh, "resolver.root_hints_refresh")
	setBool(&cfg.Resolver.ECSEnabled, "resolver.ecs_enabled")
	setInt(&cfg.Resolver.ECSMaxPrefix, "resolver.ecs_max_prefix")
	setBool(&cfg.Resolver.DNS64Enabled, "resolver.dns64_enabled")
	setString(&cfg.Resolver.DNS64Prefix, "resolver.dns64_prefix")

	// Cache
	setInt(&cfg.Cache.MaxEntries, "cache.max_entries")
	setUint32(&cfg.Cache.MinTTL, "cache.min_ttl")
	setUint32(&cfg.Cache.MaxTTL, "cache.max_ttl")
	setUint32(&cfg.Cache.NegMaxTTL, "cache.negative_max_ttl")
	setDuration(&cfg.Cache.SweepInterval, "cache.sweep_interval")
	setBool(&cfg.Cache.ServeStale, "cache.serve_stale")
	setUint32(&cfg.Cache.StaleTTL, "cache.serve_stale_ttl", "cache.stale_ttl")
	setCSV(&cfg.Cache.NoCacheClients, "cache.no_cache_clients")
	setBool(&cfg.Cache.Prefetch, "cache.prefetch")

	// Security
	setBool(&cfg.Security.PrivateAddressFilter, "security.private_address_filter")
	setBool(&cfg.Security.DNSCookies, "security.dns_cookies")
	setBool(&cfg.Security.RateLimit.Enabled, "security.rate_limit.enabled")
	setFloat64(&cfg.Security.RateLimit.Rate, "security.rate_limit.rate")
	setInt(&cfg.Security.RateLimit.Burst, "security.rate_limit.burst")
	setBool(&cfg.Security.RRL.Enabled, "security.rrl.enabled")
	setFloat64(&cfg.Security.RRL.ResponsesPerSecond, "security.rrl.responses_per_second")
	setInt(&cfg.Security.RRL.SlipRatio, "security.rrl.slip_ratio")
	setInt(&cfg.Security.RRL.IPv4Prefix, "security.rrl.ipv4_prefix")
	setInt(&cfg.Security.RRL.IPv6Prefix, "security.rrl.ipv6_prefix")

	// ACL: parse comma-separated or individual entries
	setCSV(&cfg.ACL.Allow, "access_control.allow")
	setCSV(&cfg.ACL.Deny, "access_control.deny")
	cfg.ACL.Zones = parseACLZones(values)

	// Logging
	setString(&cfg.Logging.Level, "logging.level")
	setString(&cfg.Logging.Format, "logging.format")

	// Web
	setBool(&cfg.Web.Enabled, "web.enabled")
	setString(&cfg.Web.Addr, "web.addr")
	setInt(&cfg.Web.QueryLogBuffer, "web.query_log_buffer")
	setInt(&cfg.Web.TopClientsLimit, "web.top_clients_limit")
	setInt(&cfg.Web.TopDomainsLimit, "web.top_domains_limit")
	setBool(&cfg.Web.AutoUpdate, "web.auto_update")
	setDuration(&cfg.Web.UpdateCheckInterval, "web.update_check_interval")
	setBool(&cfg.Web.DoHEnabled, "web.doh_enabled")
	setBool(&cfg.Web.DoH3Enabled, "web.doh3_enabled")
	setBool(&cfg.Web.TLSEnabled, "web.tls_enabled")
	setString(&cfg.Web.TLSCertFile, "web.tls_cert_file")
	setString(&cfg.Web.TLSKeyFile, "web.tls_key_file")
	setString(&cfg.Web.Auth.Username, "web.auth.username")
	setString(&cfg.Web.Auth.PasswordHash, "web.auth.password_hash")

	// Daemon
	setBool(&cfg.Daemon.Enabled, "daemon.enabled")
	setString(&cfg.Daemon.PIDFile, "daemon.pid_file")

	// Zabbix
	setBool(&cfg.Zabbix.Enabled, "zabbix.enabled")
	setString(&cfg.Zabbix.Addr, "zabbix.addr")

	// Blocklist
	setBool(&cfg.Blocklist.Enabled, "blocklist.enabled")
	if v, ok := firstConfigValue(values, "blocklist.lists"); ok && strings.TrimSpace(v) != "" {
		cfg.Blocklist.Lists = parseBlocklistEntries(v)
	}
	setDuration(&cfg.Blocklist.RefreshInterval, "blocklist.refresh_interval")
	setString(&cfg.Blocklist.BlockingMode, "blocklist.blocking_mode")
	setString(&cfg.Blocklist.CustomIP, "blocklist.custom_ip")
	setCSV(&cfg.Blocklist.Whitelist, "blocklist.whitelist")

	// Cluster
	setBool(&cfg.Cluster.Enabled, "cluster.enabled")
	setString(&cfg.Cluster.Role, "cluster.role")
	setString(&cfg.Cluster.NodeID, "cluster.node_id")
	setCSV(&cfg.Cluster.SharedFields, "cluster.shared_fields")
	setBool(&cfg.Cluster.Actions.FanoutCacheFlush, "cluster.actions.fanout_cache_flush")
	setBool(&cfg.Cluster.Actions.FanoutBlocklistRefresh, "cluster.actions.fanout_blocklist_refresh")
	setString(&cfg.Cluster.Sync.Mode, "cluster.sync.mode")
	setBool(&cfg.Cluster.Sync.PushOnSave, "cluster.sync.push_on_save")
	setDuration(&cfg.Cluster.Sync.PullInterval, "cluster.sync.pull_interval")
	cfg.Cluster.Peers = parseClusterPeers(values)

	// Local zones: parsed from "local_zones.<name>.type" and "local_zones.<name>.data"
	cfg.LocalZones = parseLocalZones(values)

	// Forward zones: parsed from "forward_zones.<name>.addrs"
	cfg.ForwardZones = parseForwardZones(values)

	// Stub zones: parsed from "stub_zones.<name>.addrs"
	cfg.StubZones = parseStubZones(values)
}

func firstConfigValue(values map[string]string, keys ...string) (string, bool) {
	for _, key := range keys {
		if v, ok := values[key]; ok {
			return v, true
		}
	}
	return "", false
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
	if cfg.Server.DoTEnabled {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			return fmt.Errorf("server.dot_enabled=true requires server.tls_cert_file and server.tls_key_file")
		}
	}
	if cfg.Web.TLSEnabled {
		if cfg.Web.TLSCertFile == "" || cfg.Web.TLSKeyFile == "" {
			return fmt.Errorf("web.tls_enabled=true requires web.tls_cert_file and web.tls_key_file")
		}
	}
	if cfg.Web.DoH3Enabled {
		if !cfg.Web.Enabled {
			return fmt.Errorf("web.doh3_enabled=true requires web.enabled=true")
		}
		if !cfg.Web.TLSEnabled {
			return fmt.Errorf("web.doh3_enabled=true requires web.tls_enabled=true")
		}
		if cfg.Web.TLSCertFile == "" || cfg.Web.TLSKeyFile == "" {
			return fmt.Errorf("web.doh3_enabled=true requires web.tls_cert_file and web.tls_key_file")
		}
	}
	if cfg.Cluster.Enabled {
		switch cfg.Cluster.Role {
		case "", "standalone", "master", "secondary":
		default:
			return fmt.Errorf("cluster.role must be one of standalone|master|secondary")
		}
		switch cfg.Cluster.Sync.Mode {
		case "", "off", "manual_push", "auto_push":
		default:
			return fmt.Errorf("cluster.sync.mode must be one of off|manual_push|auto_push")
		}
		for _, p := range cfg.Cluster.Peers {
			if p.Enabled && strings.TrimSpace(p.APIBase) == "" {
				return fmt.Errorf("cluster.peers.%s.api_base must be set when peer is enabled", p.Name)
			}
		}
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

// parseACLZones extracts per-zone ACL configs from the flat YAML key map.
// Expected keys: "access_control.zones.<zone>.allow" and "access_control.zones.<zone>.deny"
func parseACLZones(values map[string]string) []ACLZoneConfig {
	zones := make(map[string]*ACLZoneConfig)
	const prefix = "access_control.zones."
	for key, val := range values {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key[len(prefix):]
		// rest = "<zone>.allow" or "<zone>.deny"
		dotIdx := strings.LastIndex(rest, ".")
		if dotIdx < 0 {
			continue
		}
		zoneName := rest[:dotIdx]
		field := rest[dotIdx+1:]

		zc, ok := zones[zoneName]
		if !ok {
			zc = &ACLZoneConfig{Zone: zoneName}
			zones[zoneName] = zc
		}
		switch field {
		case "allow":
			if val != "" {
				zc.Allow = parseCSVList(val)
			}
		case "deny":
			if val != "" {
				zc.Deny = parseCSVList(val)
			}
		}
	}

	var result []ACLZoneConfig
	for _, zc := range zones {
		if len(zc.Allow) > 0 || len(zc.Deny) > 0 {
			result = append(result, *zc)
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

// parseClusterPeers extracts peer configs from keys:
// "cluster.peers.<name>.api_base", ".api_token", ".enabled", ".sync_fields".
func parseClusterPeers(values map[string]string) []ClusterPeerConfig {
	const prefix = "cluster.peers."

	type peerBuild struct {
		cfg ClusterPeerConfig
	}
	peers := make(map[string]*peerBuild)

	for key, val := range values {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key[len(prefix):]
		dotIdx := strings.LastIndex(rest, ".")
		if dotIdx < 0 {
			continue
		}
		name := rest[:dotIdx]
		field := rest[dotIdx+1:]
		if name == "" {
			continue
		}

		p, ok := peers[name]
		if !ok {
			p = &peerBuild{
				cfg: ClusterPeerConfig{
					Name:    name,
					Enabled: true,
				},
			}
			peers[name] = p
		}

		switch field {
		case "enabled":
			p.cfg.Enabled = parseBool(val)
		case "api_base":
			p.cfg.APIBase = strings.TrimSpace(val)
		case "api_token":
			p.cfg.APIToken = val
		case "sync_fields":
			if val != "" {
				p.cfg.SyncFields = parseCSVList(val)
			}
		}
	}

	names := make([]string, 0, len(peers))
	for name := range peers {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]ClusterPeerConfig, 0, len(names))
	for _, name := range names {
		p := peers[name].cfg
		if p.APIBase == "" && p.APIToken == "" && len(p.SyncFields) == 0 {
			continue
		}
		result = append(result, p)
	}
	return result
}
