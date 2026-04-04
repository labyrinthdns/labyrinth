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
			DoTEnabled:     false,
			DoTListenAddr:  ":853",
		},
		Resolver: ResolverConfig{
			MaxDepth:            30,
			MaxCNAMEDepth:       10,
			UpstreamTimeout:     2 * time.Second,
			UpstreamRetries:     3,
			QMinEnabled:         true,
			PreferIPv4:          true,
			DNSSECEnabled:       true,
			HardenBelowNXDomain: true,
			RootHintsRefresh:    12 * time.Hour,
			ECSEnabled:          false,
			ECSMaxPrefix:        24,
			DNS64Enabled:        false,
			DNS64Prefix:         "64:ff9b::/96",
		},
		Cache: CacheConfig{
			MaxEntries:    100000,
			MinTTL:        5,
			MaxTTL:        86400,
			NegMaxTTL:     3600,
			SweepInterval: 60 * time.Second,
			ServeStale:    false,
			StaleTTL:      30,
			Prefetch:      true,
		},
		Security: SecurityConfig{
			PrivateAddressFilter: true,
			DNSCookies:           false,
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
			TopClientsLimit:     2000,
			TopDomainsLimit:     2000,
			AlertErrorThreshold: 5,
			AlertLatencyMs:      250,
			AutoUpdate:          true,
			UpdateCheckInterval: 24 * time.Hour,
			DoH3Enabled:         false,
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
		Cluster: ClusterConfig{
			Enabled:      false,
			Role:         "standalone",
			NodeID:       "node-1",
			SharedFields: nil,
			Actions: ClusterActionConfig{
				FanoutCacheFlush:       false,
				FanoutBlocklistRefresh: false,
			},
			Sync: ClusterSyncConfig{
				Mode:         "off",
				PushOnSave:   false,
				PullInterval: 30 * time.Second,
			},
		},
	}
}
