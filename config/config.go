package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the complete application configuration.
type Config struct {
	Server   ServerConfig
	Resolver ResolverConfig
	Cache    CacheConfig
	Security SecurityConfig
	Logging  LoggingConfig
	ACL      ACLConfig
	Web      WebConfig
	Daemon   DaemonConfig
	Zabbix   ZabbixConfig
}

// WebConfig holds web dashboard settings.
type WebConfig struct {
	Enabled         bool
	Addr            string
	QueryLogBuffer  int
	TopClientsLimit int
	TopDomainsLimit int
	Auth            WebAuthConfig
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
}

// ResolverConfig holds resolver settings.
type ResolverConfig struct {
	MaxDepth        int
	MaxCNAMEDepth   int
	UpstreamTimeout time.Duration
	UpstreamRetries int
	QMinEnabled     bool
	PreferIPv4      bool
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
}

// SecurityConfig holds security settings.
type SecurityConfig struct {
	RateLimit RateLimitConfig
	RRL       RRLConfig
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
		values, err := parseYAML(data)
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

	// Security
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
