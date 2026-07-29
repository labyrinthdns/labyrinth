package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labyrinthdns/labyrinth/config"
)

// Sanity caps on user-supplied setup fields. Real values are tiny;
// these ceilings only filter pathological inputs that would round-trip
// into YAML on disk and crash on next startup or balloon memory.
const (
	setupMaxStringLen     = 256
	setupMaxCacheEntries  = 10_000_000
	setupMaxResolverDepth = 1024
	setupMaxRateLimitRate = 1_000_000.0
	setupMaxRateBurst     = 1_000_000
)

// validateSetupRequest enforces the caps above. Returns the first
// violation as an error so the operator gets a clear message about
// which field is wrong.
func validateSetupRequest(req *SetupRequest) error {
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}
	if len(req.ListenAddr) > setupMaxStringLen {
		return fmt.Errorf("listen_addr exceeds %d-byte cap", setupMaxStringLen)
	}
	if len(req.WebAddr) > setupMaxStringLen {
		return fmt.Errorf("web_addr exceeds %d-byte cap", setupMaxStringLen)
	}
	if len(req.Username) > setupMaxStringLen {
		return fmt.Errorf("username exceeds %d-byte cap", setupMaxStringLen)
	}
	if strings.ContainsAny(req.Username, "\r\n\x00") {
		return fmt.Errorf("username contains invalid control characters")
	}
	if len(req.LogLevel) > setupMaxStringLen {
		return fmt.Errorf("log_level exceeds %d-byte cap", setupMaxStringLen)
	}
	if len(req.LogFormat) > setupMaxStringLen {
		return fmt.Errorf("log_format exceeds %d-byte cap", setupMaxStringLen)
	}
	if req.MaxCacheSize > setupMaxCacheEntries {
		return fmt.Errorf("max_cache_size exceeds %d entries", setupMaxCacheEntries)
	}
	if req.MaxDepth > setupMaxResolverDepth {
		return fmt.Errorf("max_depth exceeds %d", setupMaxResolverDepth)
	}
	if req.RateLimitRate < 0 || req.RateLimitRate > setupMaxRateLimitRate {
		return fmt.Errorf("rate_limit_rate out of range [0, %g]", setupMaxRateLimitRate)
	}
	if req.RateLimitBurst < 0 || req.RateLimitBurst > setupMaxRateBurst {
		return fmt.Errorf("rate_limit_burst out of range [0, %d]", setupMaxRateBurst)
	}
	return nil
}

// SetupRequest represents the JSON body for the setup completion endpoint.
type SetupRequest struct {
	ListenAddr     string  `json:"listen_addr"`
	WebAddr        string  `json:"web_addr"`
	Username       string  `json:"username"`
	Password       string  `json:"password"`
	MaxCacheSize   int     `json:"max_cache_size"`
	MaxDepth       int     `json:"max_depth"`
	RateLimitRate  float64 `json:"rate_limit_rate"`
	RateLimitBurst int     `json:"rate_limit_burst"`
	LogLevel       string  `json:"log_level"`
	LogFormat      string  `json:"log_format"`
}

// handleSetupStatus handles GET /api/setup/status — returns setup state.
func (s *AdminServer) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"setup_required": !s.setupDone.Load(),
		"version":        Version,
	})
}

// handleSetupComplete handles POST /api/setup/complete — creates initial config.
func (s *AdminServer) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.setupDone.Load() {
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "setup already completed"})
		return
	}

	// Singleflight gate: the endpoint is unauthenticated, and an
	// attacker could otherwise fire dozens of concurrent POSTs that
	// all race past the setupDone check and into writeConfigYAML —
	// where os.Create's O_TRUNC semantics let the second writer
	// blow away the first writer's bytes mid-flush, producing a
	// corrupt config on disk. The CAS gate serialises the handler;
	// the loser sees 409 immediately without touching the file system.
	if !s.setupRunning.CompareAndSwap(false, true) {
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "setup already in progress"})
		return
	}
	defer s.setupRunning.Store(false)

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Sanity-cap user-controlled fields before they round-trip into
	// YAML on disk. The setup endpoint can be hit before any
	// authentication exists, so an attacker reaching it first could
	// otherwise submit pathological values that crash on next
	// startup or balloon resolver memory.
	if err := validateSetupRequest(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		// validateSetupRequest already checked the password policy; reaching
		// this branch means bcrypt itself failed.
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}

	// Apply defaults
	if req.ListenAddr == "" {
		req.ListenAddr = ":53"
	}
	if req.WebAddr == "" {
		req.WebAddr = "127.0.0.1:8080"
	}
	if req.MaxCacheSize <= 0 {
		req.MaxCacheSize = 100000
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 30
	}
	if req.LogLevel == "" {
		req.LogLevel = "info"
	}
	if req.LogFormat == "" {
		req.LogFormat = "json"
	}

	// Write config file at the configured path (not a hardcoded relative
	// "labyrinth.yaml"). Refuse if a usable file already exists at that
	// path — defence in depth for C-1 in case setupDone was somehow not
	// seeded (older configs, manual flag flips, etc.).
	cfgPath := s.configFilePath()
	if info, statErr := os.Stat(cfgPath); statErr == nil && !info.IsDir() && info.Size() > 0 {
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "config already exists; refusing to overwrite"})
		return
	}
	if err := writeConfigYAML(cfgPath, req, passwordHash); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to write config: " + err.Error()})
		return
	}
	// L-2: tighten permissions on the file containing the bcrypt hash.
	// Best-effort — Windows permissions semantics differ; ignore failure.
	_ = os.Chmod(cfgPath, 0o600)

	// Setup changes the auth boundary immediately. Parse the bytes just written
	// and publish that complete snapshot in one atomic Store so protected APIs
	// and /api/auth/login observe exactly the persisted credentials together.
	persisted, err := os.ReadFile(cfgPath)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to load written config: " + err.Error()})
		return
	}
	published, err := config.Parse(persisted)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to load written config: " + err.Error()})
		return
	}
	s.config.Store(published)
	s.setupDone.Store(true)
	s.logger.Info("setup completed, config written", "path", cfgPath)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "setup complete"})
}

// writeConfigYAML writes a labyrinth.yaml config file using fmt.Fprintf (no YAML library).
func writeConfigYAML(path string, cfg SetupRequest, passwordHash string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer f.Close()

	// Escape YAML string values that might contain special characters
	escYAML := func(s string) string {
		if strings.ContainsAny(s, ":#{}[]&*!|>'\"%@`") || s == "" {
			return fmt.Sprintf("%q", s)
		}
		return s
	}

	fmt.Fprintf(f, "# Labyrinth DNS configuration\n")
	fmt.Fprintf(f, "# Generated by setup wizard\n\n")

	fmt.Fprintf(f, "server:\n")
	fmt.Fprintf(f, "  listen_addr: %s\n", escYAML(cfg.ListenAddr))
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "resolver:\n")
	fmt.Fprintf(f, "  max_depth: %d\n", cfg.MaxDepth)
	fmt.Fprintf(f, "  qname_minimization: true\n")
	fmt.Fprintf(f, "  prefer_ipv4: true\n")
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "cache:\n")
	fmt.Fprintf(f, "  max_entries: %d\n", cfg.MaxCacheSize)
	fmt.Fprintf(f, "\n")

	if cfg.RateLimitRate > 0 {
		fmt.Fprintf(f, "security:\n")
		fmt.Fprintf(f, "  rate_limit:\n")
		fmt.Fprintf(f, "    enabled: true\n")
		fmt.Fprintf(f, "    rate: %g\n", cfg.RateLimitRate)
		if cfg.RateLimitBurst > 0 {
			fmt.Fprintf(f, "    burst: %d\n", cfg.RateLimitBurst)
		}
		fmt.Fprintf(f, "\n")
	}

	fmt.Fprintf(f, "logging:\n")
	fmt.Fprintf(f, "  level: %s\n", escYAML(cfg.LogLevel))
	fmt.Fprintf(f, "  format: %s\n", escYAML(cfg.LogFormat))
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "web:\n")
	fmt.Fprintf(f, "  enabled: true\n")
	fmt.Fprintf(f, "  addr: %s\n", escYAML(cfg.WebAddr))
	if cfg.Username != "" {
		fmt.Fprintf(f, "  auth:\n")
		fmt.Fprintf(f, "    username: %s\n", escYAML(cfg.Username))
		fmt.Fprintf(f, "    password_hash: %s\n", escYAML(passwordHash))
	}

	return nil
}
