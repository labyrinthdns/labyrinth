package web

import (
	"net/http"
)

// handleGetConfig handles GET /api/config — returns config as JSON with password_hash redacted.
func (s *AdminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Build a sanitized config representation
	cfg := s.config

	authPassword := ""
	if cfg.Web.Auth.PasswordHash != "" {
		authPassword = "***REDACTED***"
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server": map[string]interface{}{
			"listen_addr":      cfg.Server.ListenAddr,
			"metrics_addr":     cfg.Server.MetricsAddr,
			"max_udp_size":     cfg.Server.MaxUDPSize,
			"tcp_timeout":      cfg.Server.TCPTimeout.String(),
			"max_tcp_conns":    cfg.Server.MaxTCPConns,
			"max_udp_workers":  cfg.Server.MaxUDPWorkers,
			"graceful_period":  cfg.Server.GracefulPeriod.String(),
		},
		"resolver": map[string]interface{}{
			"max_depth":            cfg.Resolver.MaxDepth,
			"max_cname_depth":      cfg.Resolver.MaxCNAMEDepth,
			"upstream_timeout":     cfg.Resolver.UpstreamTimeout.String(),
			"upstream_retries":     cfg.Resolver.UpstreamRetries,
			"qname_minimization":   cfg.Resolver.QMinEnabled,
			"prefer_ipv4":          cfg.Resolver.PreferIPv4,
		},
		"cache": map[string]interface{}{
			"max_entries":    cfg.Cache.MaxEntries,
			"min_ttl":        cfg.Cache.MinTTL,
			"max_ttl":        cfg.Cache.MaxTTL,
			"negative_max_ttl": cfg.Cache.NegMaxTTL,
			"sweep_interval": cfg.Cache.SweepInterval.String(),
			"serve_stale":    cfg.Cache.ServeStale,
			"stale_ttl":      cfg.Cache.StaleTTL,
		},
		"security": map[string]interface{}{
			"rate_limit": map[string]interface{}{
				"enabled": cfg.Security.RateLimit.Enabled,
				"rate":    cfg.Security.RateLimit.Rate,
				"burst":   cfg.Security.RateLimit.Burst,
			},
			"rrl": map[string]interface{}{
				"enabled":              cfg.Security.RRL.Enabled,
				"responses_per_second": cfg.Security.RRL.ResponsesPerSecond,
				"slip_ratio":           cfg.Security.RRL.SlipRatio,
				"ipv4_prefix":          cfg.Security.RRL.IPv4Prefix,
				"ipv6_prefix":          cfg.Security.RRL.IPv6Prefix,
			},
		},
		"logging": map[string]interface{}{
			"level":  cfg.Logging.Level,
			"format": cfg.Logging.Format,
		},
		"web": map[string]interface{}{
			"enabled":          cfg.Web.Enabled,
			"addr":             cfg.Web.Addr,
			"query_log_buffer": cfg.Web.QueryLogBuffer,
			"auth": map[string]interface{}{
				"username":      cfg.Web.Auth.Username,
				"password_hash": authPassword,
			},
		},
		"acl": map[string]interface{}{
			"allow": cfg.ACL.Allow,
			"deny":  cfg.ACL.Deny,
		},
	})
}
