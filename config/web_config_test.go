package config

import "testing"

func TestApplyYAMLWebConfig(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"web.enabled":            "true",
		"web.addr":               "0.0.0.0:8080",
		"web.query_log_buffer":   "5000",
		"web.auth.username":      "admin",
		"web.auth.password_hash": "$2a$10$test",
	}
	applyYAML(cfg, values)

	if !cfg.Web.Enabled {
		t.Error("web.enabled should be true")
	}
	if cfg.Web.Addr != "0.0.0.0:8080" {
		t.Errorf("web.addr: got %q", cfg.Web.Addr)
	}
	if cfg.Web.QueryLogBuffer != 5000 {
		t.Errorf("query_log_buffer: got %d", cfg.Web.QueryLogBuffer)
	}
	if cfg.Web.Auth.Username != "admin" {
		t.Errorf("username: got %q", cfg.Web.Auth.Username)
	}
	if cfg.Web.Auth.PasswordHash != "$2a$10$test" {
		t.Errorf("password_hash: got %q", cfg.Web.Auth.PasswordHash)
	}
}

func TestApplyYAMLDaemonConfig(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"daemon.enabled":  "true",
		"daemon.pid_file": "/tmp/labyrinth.pid",
	}
	applyYAML(cfg, values)

	if !cfg.Daemon.Enabled {
		t.Error("daemon.enabled should be true")
	}
	if cfg.Daemon.PIDFile != "/tmp/labyrinth.pid" {
		t.Errorf("pid_file: got %q", cfg.Daemon.PIDFile)
	}
}

func TestApplyYAMLZabbixConfig(t *testing.T) {
	cfg := defaultConfig()
	values := map[string]string{
		"zabbix.enabled": "true",
		"zabbix.addr":    "127.0.0.1:10050",
	}
	applyYAML(cfg, values)

	if !cfg.Zabbix.Enabled {
		t.Error("zabbix.enabled should be true")
	}
	if cfg.Zabbix.Addr != "127.0.0.1:10050" {
		t.Errorf("addr: got %q", cfg.Zabbix.Addr)
	}
}

func TestDefaultWebConfig(t *testing.T) {
	cfg := defaultConfig()

	if !cfg.Web.Enabled {
		t.Error("web should be enabled by default")
	}
	if cfg.Web.Addr != "127.0.0.1:9153" {
		t.Errorf("default addr: got %q", cfg.Web.Addr)
	}
	if cfg.Web.QueryLogBuffer != 1000 {
		t.Errorf("default buffer: got %d", cfg.Web.QueryLogBuffer)
	}
	if cfg.Daemon.Enabled {
		t.Error("daemon should be disabled by default")
	}
	if cfg.Zabbix.Enabled {
		t.Error("zabbix should be disabled by default")
	}
}

func TestParseYAMLWebSection(t *testing.T) {
	yaml := `
web:
  enabled: true
  addr: "0.0.0.0:9153"
  query_log_buffer: 2000
  auth:
    username: "admin"
    password_hash: "$2a$10$hash"
`
	values, err := parseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	checks := map[string]string{
		"web.enabled":            "true",
		"web.addr":               "0.0.0.0:9153",
		"web.query_log_buffer":   "2000",
		"web.auth.username":      "admin",
		"web.auth.password_hash": "$2a$10$hash",
	}

	for key, expected := range checks {
		if got, ok := values[key]; !ok {
			t.Errorf("key %q not found", key)
		} else if got != expected {
			t.Errorf("key %q: expected %q, got %q", key, expected, got)
		}
	}
}
