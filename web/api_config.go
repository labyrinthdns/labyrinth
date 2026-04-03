package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labyrinthdns/labyrinth/config"
)

// handleGetConfig handles GET /api/config and returns a sanitized config JSON.
func (s *AdminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

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
			"tcp_pipeline_max": cfg.Server.TCPPipelineMax,
			"tcp_idle_timeout": cfg.Server.TCPIdleTimeout.String(),
			"dot_enabled":      cfg.Server.DoTEnabled,
			"dot_listen_addr":  cfg.Server.DoTListenAddr,
			"tls_cert_file":    cfg.Server.TLSCertFile,
			"tls_key_file":     cfg.Server.TLSKeyFile,
		},
		"resolver": map[string]interface{}{
			"max_depth":             cfg.Resolver.MaxDepth,
			"max_cname_depth":       cfg.Resolver.MaxCNAMEDepth,
			"upstream_timeout":      cfg.Resolver.UpstreamTimeout.String(),
			"upstream_retries":      cfg.Resolver.UpstreamRetries,
			"qname_minimization":    cfg.Resolver.QMinEnabled,
			"prefer_ipv4":           cfg.Resolver.PreferIPv4,
			"dnssec_enabled":        cfg.Resolver.DNSSECEnabled,
			"harden_below_nxdomain": cfg.Resolver.HardenBelowNXDomain,
			"root_hints_refresh":    cfg.Resolver.RootHintsRefresh.String(),
			"ecs_enabled":           cfg.Resolver.ECSEnabled,
			"ecs_max_prefix":        cfg.Resolver.ECSMaxPrefix,
			"dns64_enabled":         cfg.Resolver.DNS64Enabled,
			"dns64_prefix":          cfg.Resolver.DNS64Prefix,
		},
		"cache": map[string]interface{}{
			"max_entries":      cfg.Cache.MaxEntries,
			"min_ttl":          cfg.Cache.MinTTL,
			"max_ttl":          cfg.Cache.MaxTTL,
			"negative_max_ttl": cfg.Cache.NegMaxTTL,
			"sweep_interval":   cfg.Cache.SweepInterval.String(),
			"serve_stale":      cfg.Cache.ServeStale,
			"stale_ttl":        cfg.Cache.StaleTTL,
			"no_cache_clients": cfg.Cache.NoCacheClients,
			"prefetch":         cfg.Cache.Prefetch,
		},
		"security": map[string]interface{}{
			"private_address_filter": cfg.Security.PrivateAddressFilter,
			"dns_cookies":            cfg.Security.DNSCookies,
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
			"enabled":               cfg.Web.Enabled,
			"addr":                  cfg.Web.Addr,
			"query_log_buffer":      cfg.Web.QueryLogBuffer,
			"top_clients_limit":     cfg.Web.TopClientsLimit,
			"top_domains_limit":     cfg.Web.TopDomainsLimit,
			"auto_update":           cfg.Web.AutoUpdate,
			"update_check_interval": cfg.Web.UpdateCheckInterval.String(),
			"doh_enabled":           cfg.Web.DoHEnabled,
			"doh3_enabled":          cfg.Web.DoH3Enabled,
			"tls_enabled":           cfg.Web.TLSEnabled,
			"tls_cert_file":         cfg.Web.TLSCertFile,
			"tls_key_file":          cfg.Web.TLSKeyFile,
			"auth": map[string]interface{}{
				"username":      cfg.Web.Auth.Username,
				"password_hash": authPassword,
			},
		},
		"zabbix": map[string]interface{}{
			"enabled": cfg.Zabbix.Enabled,
			"addr":    cfg.Zabbix.Addr,
		},
		"daemon": map[string]interface{}{
			"enabled":  cfg.Daemon.Enabled,
			"pid_file": cfg.Daemon.PIDFile,
		},
		"acl": map[string]interface{}{
			"allow": cfg.ACL.Allow,
			"deny":  cfg.ACL.Deny,
			"zones": func() []map[string]interface{} {
				out := make([]map[string]interface{}, 0, len(cfg.ACL.Zones))
				for _, z := range cfg.ACL.Zones {
					out = append(out, map[string]interface{}{
						"zone":  z.Zone,
						"allow": z.Allow,
						"deny":  z.Deny,
					})
				}
				return out
			}(),
		},
		"blocklist": map[string]interface{}{
			"enabled":          cfg.Blocklist.Enabled,
			"refresh_interval": cfg.Blocklist.RefreshInterval.String(),
			"blocking_mode":    cfg.Blocklist.BlockingMode,
			"custom_ip":        cfg.Blocklist.CustomIP,
			"whitelist":        cfg.Blocklist.Whitelist,
			"list_count":       len(cfg.Blocklist.Lists),
			"lists": func() []map[string]string {
				out := make([]map[string]string, 0, len(cfg.Blocklist.Lists))
				for _, e := range cfg.Blocklist.Lists {
					out = append(out, map[string]string{
						"url":    e.URL,
						"format": e.Format,
					})
				}
				return out
			}(),
		},
		"cluster": map[string]interface{}{
			"enabled":       cfg.Cluster.Enabled,
			"role":          cfg.Cluster.Role,
			"node_id":       cfg.Cluster.NodeID,
			"shared_fields": cfg.Cluster.SharedFields,
			"actions": map[string]interface{}{
				"fanout_cache_flush":       cfg.Cluster.Actions.FanoutCacheFlush,
				"fanout_blocklist_refresh": cfg.Cluster.Actions.FanoutBlocklistRefresh,
			},
			"sync": map[string]interface{}{
				"mode":          cfg.Cluster.Sync.Mode,
				"push_on_save":  cfg.Cluster.Sync.PushOnSave,
				"pull_interval": cfg.Cluster.Sync.PullInterval.String(),
			},
			"peers": func() []map[string]interface{} {
				out := make([]map[string]interface{}, 0, len(cfg.Cluster.Peers))
				for _, p := range cfg.Cluster.Peers {
					tokenVal := ""
					if strings.TrimSpace(p.APIToken) != "" {
						tokenVal = "***REDACTED***"
					}
					out = append(out, map[string]interface{}{
						"name":          p.Name,
						"enabled":       p.Enabled,
						"api_base":      p.APIBase,
						"api_token":     tokenVal,
						"api_token_set": strings.TrimSpace(p.APIToken) != "",
						"sync_fields":   p.SyncFields,
					})
				}
				return out
			}(),
		},
		"local_zones": func() []map[string]interface{} {
			out := make([]map[string]interface{}, 0, len(cfg.LocalZones))
			for _, z := range cfg.LocalZones {
				out = append(out, map[string]interface{}{
					"name": z.Name,
					"type": z.Type,
					"data": z.Data,
				})
			}
			return out
		}(),
		"forward_zones": func() []map[string]interface{} {
			out := make([]map[string]interface{}, 0, len(cfg.ForwardZones))
			for _, z := range cfg.ForwardZones {
				out = append(out, map[string]interface{}{
					"name":  z.Name,
					"addrs": z.Addrs,
				})
			}
			return out
		}(),
		"stub_zones": func() []map[string]interface{} {
			out := make([]map[string]interface{}, 0, len(cfg.StubZones))
			for _, z := range cfg.StubZones {
				out = append(out, map[string]interface{}{
					"name":  z.Name,
					"addrs": z.Addrs,
				})
			}
			return out
		}(),
	})
}

type configEditRequest struct {
	Content string `json:"content"`
}

func extractPasswordHashFromYAML(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "password_hash:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(trimmed, "password_hash:"))
		if val == "" {
			return "", true
		}
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			val = strings.Trim(val, "\"'")
		}
		return val, true
	}
	return "", false
}

func (s *AdminServer) ensurePasswordHashUnchanged(content string) error {
	current := strings.TrimSpace(s.config.Web.Auth.PasswordHash)
	incoming, found := extractPasswordHashFromYAML(content)
	incoming = strings.TrimSpace(incoming)

	// Admin password is managed only via /api/auth/change-password.
	if current == "" {
		if found && incoming != "" {
			return fmt.Errorf("admin password cannot be set from config editor; use change password")
		}
		return nil
	}
	if !found || incoming == "" {
		return fmt.Errorf("admin password cannot be removed from config editor; use change password")
	}
	if incoming != current {
		return fmt.Errorf("admin password cannot be changed from config editor; use change password")
	}
	return nil
}

// handleValidateConfig handles POST /api/config/validate.
func (s *AdminServer) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req configEditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.ensurePasswordHashUnchanged(req.Content); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	if _, err := config.Parse([]byte(req.Content)); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{"valid": true})
}

// handleConfigRaw handles GET/PUT /api/config/raw for full YAML editing.
func (s *AdminServer) handleConfigRaw(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		path := s.configFilePath()
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				jsonResponse(w, http.StatusNotFound, map[string]string{"error": "config file not found"})
				return
			}
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config: " + err.Error()})
			return
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"path":    path,
			"content": string(data),
		})
	case http.MethodPut:
		var req configEditRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := s.ensurePasswordHashUnchanged(req.Content); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		parsedCfg, err := config.Parse([]byte(req.Content))
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		path := s.configFilePath()
		if err := writeFileAtomically(path, []byte(req.Content)); err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to save config: " + err.Error()})
			return
		}

		// Keep API responses in sync with the last validated file content.
		s.config = parsedCfg

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":           "saved",
			"path":             path,
			"restart_required": true,
		})
	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *AdminServer) configFilePath() string {
	p := strings.TrimSpace(s.configPath)
	if p == "" {
		return "labyrinth.yaml"
	}
	return p
}

func writeFileAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}

	tmp, err := os.CreateTemp(dir, ".labyrinth-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	backupPath := path + ".bak"
	hadOriginal := false
	if _, err := os.Stat(path); err == nil {
		hadOriginal = true
		_ = os.Remove(backupPath)
		if err := os.Rename(path, backupPath); err != nil {
			return fmt.Errorf("backup existing config: %w", err)
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if hadOriginal {
			_ = os.Rename(backupPath, path)
		}
		return fmt.Errorf("replace config file: %w", err)
	}
	cleanupTmp = false

	return nil
}
