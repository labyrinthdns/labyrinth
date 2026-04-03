package config

import "time"

func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:     ":53",
			MetricsAddr:    "127.0.0.1:9153",
			MaxUDPSize:     4096,
			TCPTimeout:     10 * time.Second,
			MaxTCPConns:    256,
			MaxUDPWorkers:  10000,
			GracefulPeriod: 5 * time.Second,
			TCPPipelineMax: 100,
			TCPIdleTimeout: 5 * time.Second,
		},
		Resolver: ResolverConfig{
			MaxDepth:        30,
			MaxCNAMEDepth:   10,
			UpstreamTimeout: 2 * time.Second,
			UpstreamRetries: 3,
			QMinEnabled:     true,
			PreferIPv4:      true,
			DNSSECEnabled:   true,
		},
		Cache: CacheConfig{
			MaxEntries:    100000,
			MinTTL:        5,
			MaxTTL:        86400,
			NegMaxTTL:     3600,
			SweepInterval: 60 * time.Second,
			ServeStale:    false,
			StaleTTL:      30,
		},
		Security: SecurityConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rate:    50,
				Burst:   100,
			},
			RRL: RRLConfig{
				Enabled:            true,
				ResponsesPerSecond: 5,
				SlipRatio:          2,
				IPv4Prefix:         24,
				IPv6Prefix:         56,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		ACL: ACLConfig{},
		Web: WebConfig{
			Enabled:             true,
			Addr:                "127.0.0.1:9153",
			QueryLogBuffer:      1000,
			TopClientsLimit:     20,
			TopDomainsLimit:     20,
			AutoUpdate:          true,
			UpdateCheckInterval: 24 * time.Hour,
		},
		Daemon: DaemonConfig{
			Enabled: false,
			PIDFile: "/var/run/labyrinth.pid",
		},
		Zabbix: ZabbixConfig{
			Enabled: false,
		},
		Blocklist: BlocklistConfig{
			Enabled:         false,
			RefreshInterval: 24 * time.Hour,
			BlockingMode:    "nxdomain",
		},
	}
}
