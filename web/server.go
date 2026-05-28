package web

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/certmanager"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/server"
	"github.com/quic-go/quic-go/http3"
)

// Version info variables — set at build time from main.go.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GoVersion = "unknown"
)

// clientQueryEntry tracks query counts with last access time for TTL-based cleanup.
type clientQueryEntry struct {
	count      atomic.Uint64
	lastAccess time.Time
}

// AdminServer provides the admin dashboard HTTP backend.
type AdminServer struct {
	cache                 *cache.Cache
	metrics               *metrics.Metrics
	resolver              *resolver.Resolver
	config                *config.Config
	configPath            string
	queryLog              *QueryLog
	timeSeries            *TimeSeriesAggregator
	logger                *slog.Logger
	jwtSecret          []byte
	revokedTokens     sync.Map // maps revoked jti string → bool; cleared on secret rotation
	// setupDone is set true when the bootstrap config exists (either
	// seeded from disk at NewAdminServer time, or after a successful
	// /api/setup/complete). atomic so concurrent setup requests race
	// safely instead of producing torn reads on the gate.
	setupDone atomic.Bool
	// setupRunning is the CAS gate around /api/setup/complete. The
	// endpoint is unauthenticated by design (it bootstraps the very
	// first admin), so an attacker who reaches it before a legitimate
	// operator could fire dozens of concurrent POSTs and race the
	// "is config already written?" check against the actual file
	// create. The CAS gate serialises the handler — first caller runs,
	// others see 409 immediately without touching disk.
	setupRunning atomic.Bool
	// configFileMu serialises read-modify-write of the on-disk YAML
	// config across /api/config/raw PUT and /api/dashboard/layout PUT.
	// Both handlers do (1) os.ReadFile(path) → (2) compute new content
	// → (3) writeFileAtomically(path). Without mutual exclusion two
	// concurrent admin PUTs (e.g. one editor + one dashboard reorder)
	// race: both read the same baseline, both write their independent
	// modifications, and the second writer's writeFileAtomically wipes
	// the first writer's delta — classic lost-update. The mutex covers
	// the entire read-modify-write so the loser sees the winner's bytes.
	configFileMu sync.Mutex
	// updateApplyRunning is the CAS gate around /api/system/update/apply.
	// The handler downloads a ~10–30 MiB binary, writes it to a temp
	// file, verifies SHA-256, and renames it over the running executable
	// before re-execing. Two concurrent admin POSTs (or a runaway
	// automation script, or a duplicated WebSocket-triggered click)
	// would each download the binary independently, fight for the
	// Windows rename of the running exe → .old, and race two restart()s.
	// The gate serialises the handler; the loser sees 409 immediately.
	updateApplyRunning atomic.Bool
	nextID                atomic.Uint64
	topClients            *TopTracker
	topDomains            *TopTracker
	// clientQueryNum tracks a monotonic per-client query counter so
	// the dashboard can show "this is the N-th query from 10.0.0.5".
	// Populated lazily on every distinct client IP by RecordQuery.
	// Before v0.7.66 the map grew without bound between cleanup
	// ticks (default 5 minutes); a busy ISP-side resolver can see
	// 100k+ distinct legitimate clients in that window, and a UDP-
	// source-spoofing attacker can populate millions. The cap is
	// enforced by RecordQuery with oldest-lastAccess LRU eviction;
	// same defence-in-depth pattern as RateLimiter.clients (v0.7.65).
	clientQueryNum        map[string]*clientQueryEntry
	clientNumMu           sync.Mutex
	clientCleanupInterval time.Duration
	// clientQueryNumCapOverride lets tests use a smaller cap so the
	// over-cap LRU eviction path can be exercised without inserting
	// MaxClientQueryNumEntries entries. Zero means use the package
	// constant; production paths never set this.
	clientQueryNumCapOverride int
	updateCache           *UpdateInfo
	updateCheckedAt       time.Time
	updateMu              sync.RWMutex
	blocklist             *blocklist.Manager
	dohEnabled            bool
	dohHandler            server.Handler
	certMgr               *certmanager.Manager
	loginLimiter          *loginLimiter
	runtimeApplier        func(*config.Config)
}

// NewAdminServer creates a new AdminServer. The bl parameter is optional and
// may be nil when the blocklist feature is disabled.
func NewAdminServer(cfg *config.Config, c *cache.Cache, m *metrics.Metrics, r *resolver.Resolver, logger *slog.Logger, bl *blocklist.Manager) (*AdminServer, error) {
	bufSize := cfg.Web.QueryLogBuffer
	if bufSize <= 0 {
		bufSize = 1000
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	cleanupInterval := 5 * time.Minute
	topTrackingLimitClients := cfg.Web.TopClientsLimit
	if topTrackingLimitClients < 1000 {
		topTrackingLimitClients = 1000
	}
	topTrackingLimitDomains := cfg.Web.TopDomainsLimit
	if topTrackingLimitDomains < 1000 {
		topTrackingLimitDomains = 1000
	}

	// SECURITY (C-1): seed setupDone from on-disk config so that
	// /api/setup/complete cannot be replayed on every restart of an
	// already-provisioned server. The handler still gates on this flag,
	// but it now defaults to true whenever auth credentials exist.
	setupDone := cfg.Web.Auth.Username != "" && cfg.Web.Auth.PasswordHash != ""

	s := &AdminServer{
		cache:                 c,
		metrics:               m,
		resolver:              r,
		config:                cfg,
		configPath:            "labyrinth.yaml",
		queryLog:              NewQueryLog(bufSize),
		timeSeries:            NewTimeSeriesAggregator(),
		logger:                logger,
		jwtSecret:             secret,
		topClients:            NewTopTracker(topTrackingLimitClients),
		topDomains:            NewTopTracker(topTrackingLimitDomains),
		clientQueryNum:        make(map[string]*clientQueryEntry),
		clientCleanupInterval: cleanupInterval,
		blocklist:             bl,
		loginLimiter:          newLoginLimiter(),
	}
	s.setupDone.Store(setupDone)

	// Wire fallback time-series: route fallback events into the aggregator.
	s.wireFallbackTimeSeries()

	return s, nil
}

func (s *AdminServer) wireFallbackTimeSeries() {
	m := s.metrics
	ts := s.timeSeries
	m.RecordFallbackFunc = func(query, recovery int64) {
		ts.RecordFallback(query, recovery)
	}
}
func (s *AdminServer) SetConfigPath(path string) {
	if path == "" {
		return
	}
	s.configPath = path
}

// SetCertManager sets the auto-TLS certificate manager.
func (s *AdminServer) SetCertManager(cm *certmanager.Manager) {
	s.certMgr = cm
}

// SetRuntimeApplier registers a callback invoked after a successful
// /api/config/raw save. The runtime uses it to hot-apply settings that do
// not require a process restart (e.g. security.private_address_filter,
// blocklist toggles). Settings the runtime cannot reload at runtime
// (listen addresses, TLS material, web server bind) still need a restart.
func (s *AdminServer) SetRuntimeApplier(fn func(*config.Config)) {
	s.runtimeApplier = fn
}

// CertManager returns the auto-TLS certificate manager (may be nil).
func (s *AdminServer) CertManager() *certmanager.Manager {
	return s.certMgr
}

// Start starts the HTTP server and blocks until the context is cancelled.
func (s *AdminServer) Start(ctx context.Context) error {
	// Start client query cleanup goroutine
	go s.startClientCleanup(ctx)
	// Start login-limiter idle eviction goroutine
	go s.loginLimiter.startCleanup(ctx)

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	addr := s.config.Web.Addr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	autoTLS := s.certMgr != nil

	// H-1 advisory: warn when bound to a non-loopback address without auth.
	// We do not refuse to start (would break test fixtures and explicit
	// "behind reverse proxy with mTLS" deployments), but the operator
	// should see this clearly in logs.
	if s.config.Web.Auth.Username == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			ip := net.ParseIP(host)
			if ip == nil || (!ip.IsLoopback() && host != "localhost") {
				s.logger.Warn("admin dashboard bound to non-loopback without auth — every endpoint is unauthenticated",
					"addr", addr,
					"hint", "set web.auth.username/password_hash, or bind web.addr to 127.0.0.1")
			}
		}
	}

	var h3Server *http3.Server
	tlsActive := func() bool {
		return autoTLS || (s.config.Web.TLSEnabled && s.config.Web.TLSCertFile != "" && s.config.Web.TLSKeyFile != "")
	}
	// H-3: emit security response headers globally.
	baseHandler := securityHeaders(tlsActive)(mux)

	if s.config.Web.DoH3Enabled {
		if !autoTLS && (!s.config.Web.TLSEnabled || s.config.Web.TLSCertFile == "" || s.config.Web.TLSKeyFile == "") {
			return fmt.Errorf("web.doh3_enabled=true requires TLS (auto_tls or tls_cert_file/tls_key_file)")
		}

		h3Server = &http3.Server{
			Addr:    addr,
			Handler: securityHeaders(tlsActive)(mux),
		}
		if autoTLS {
			h3Server.TLSConfig = s.certMgr.TLSConfig()
		}
		baseHandler = withQUICHeaders(baseHandler, h3Server, s.logger)
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: baseHandler,
		// ReadHeaderTimeout is the dedicated slowloris guard: it caps
		// the time to receive the request HEAD specifically, which is
		// the half-open / one-byte-at-a-time attack window. Without
		// this an attacker can send headers slowly forever and only
		// trip ReadTimeout once they finally end the request — which
		// is exactly what slowloris exploits. 10s is well above any
		// realistic browser timing.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// 16 KiB header cap: ReadHeaderTimeout limits time, this
		// limits volume. Real admin sessions send a few KB (cookie +
		// session + auth + UA). Go's 1 MiB default is a generous
		// amplification primitive when paired with many concurrent
		// connections under the slowloris deadline.
		MaxHeaderBytes: 16 << 10,
	}

	// Apply auto-TLS config to the HTTP server
	if autoTLS {
		srv.TLSConfig = s.certMgr.TLSConfig()
	}

	errCh := make(chan error, 3)

	// Start HTTP-01 challenge handler + HTTPS redirect on port 80
	if autoTLS {
		go func() {
			// Slowloris defence: the HTTP-01 challenge listener is on a
			// well-known port reachable from the internet during certificate
			// renewal. Without ReadHeaderTimeout an attacker could open
			// thousands of half-open connections sending one header byte at
			// a time and hold them open forever — exhausting the resolver's
			// file descriptor table. Match the same timeout regime as the
			// main admin server so the surface is uniform.
			httpSrv := &http.Server{
				Addr:              ":80",
				Handler:           s.certMgr.HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
				// 16 KiB header cap on the HTTP-01 challenge listener.
				// ACME validators send a single short GET — anything
				// approaching even 4 KiB is anomalous. Paired with the
				// slowloris timeouts, this bounds the worst-case memory
				// footprint of a hostile actor camping on :80.
				MaxHeaderBytes: 16 << 10,
			}
			s.logger.Info("auto-tls: HTTP-01 challenge listener starting", "addr", ":80")
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// Port 80 may be unavailable — log but don't fail; TLS-ALPN-01 is primary.
				s.logger.Warn("auto-tls: HTTP-01 listener failed (TLS-ALPN-01 still active)", "error", err)
			}
		}()
	}

	if h3Server != nil {
		go func() {
			s.logger.Info("admin dashboard HTTP/3 starting", "addr", addr)
			var err error
			if autoTLS {
				// TLSConfig already set on h3Server
				err = h3Server.ListenAndServeTLS("", "")
			} else {
				err = h3Server.ListenAndServeTLS(s.config.Web.TLSCertFile, s.config.Web.TLSKeyFile)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("admin HTTP/3 server error: %w", err):
				default:
				}
			}
		}()
	}

	go func() {
		if autoTLS {
			s.logger.Info("admin dashboard starting with auto-TLS", "addr", addr, "domain", s.certMgr.Domain())
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				select {
				case errCh <- err:
				default:
				}
			}
		} else if s.config.Web.TLSEnabled && s.config.Web.TLSCertFile != "" && s.config.Web.TLSKeyFile != "" {
			s.logger.Info("admin dashboard starting with TLS", "addr", addr)
			if err := srv.ListenAndServeTLS(s.config.Web.TLSCertFile, s.config.Web.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				select {
				case errCh <- err:
				default:
				}
			}
		} else {
			s.logger.Info("admin dashboard starting", "addr", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				select {
				case errCh <- err:
				default:
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("admin dashboard shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpErr := srv.Shutdown(shutdownCtx)

		var h3Err error
		if h3Server != nil {
			h3Err = h3Server.Shutdown(shutdownCtx)
		}

		if httpErr != nil {
			return httpErr
		}
		return h3Err
	case err := <-errCh:
		return fmt.Errorf("admin server error: %w", err)
	}
}

func withQUICHeaders(next http.Handler, h3 *http3.Server, logger *slog.Logger) http.Handler {
	var warned atomic.Bool

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h3.SetQUICHeaders(w.Header()); err != nil {
			if warned.CompareAndSwap(false, true) {
				logger.Warn("failed to set Alt-Svc header for HTTP/3", "error", err)
			}
		}
		if w.Header().Get("Alt-Svc") == "" {
			if altSvc := defaultAltSvc(h3); altSvc != "" {
				w.Header().Set("Alt-Svc", altSvc)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func defaultAltSvc(h3 *http3.Server) string {
	port := h3.Port
	if port <= 0 {
		_, p, err := net.SplitHostPort(h3.Addr)
		if err == nil {
			if parsed, convErr := strconv.Atoi(p); convErr == nil {
				port = parsed
			}
		}
	}
	if port <= 0 {
		return ""
	}
	return fmt.Sprintf(`h3=":%d"; ma=2592000`, port)
}

// MaxClientQueryNumEntries caps the size of AdminServer.clientQueryNum.
// The map is populated lazily by RecordQuery on every distinct client
// IP the resolver sees, and the TTL cleanup (default 5 minutes) only
// evicts entries idle past 2x the cleanup interval — between ticks a
// UDP-source-spoofing attacker can populate millions of entries from a
// single host, and even a busy ISP-side deployment can see 100k+
// distinct legitimate clients in a 10-minute window. The cap stops
// unbounded growth without changing the per-client counter contract:
// on insert past the cap, the OLDEST-lastAccess entry is evicted. A
// returning client that was evicted simply restarts at 1 — the
// counter is a UI convenience, not a security boundary, so resetting
// it is acceptable when memory pressure forces eviction.
const MaxClientQueryNumEntries = 1_000_000

// clientQueryNumCap returns the effective cap. Tests set
// clientQueryNumCapOverride to exercise the cap without inserting
// MaxClientQueryNumEntries entries up-front; production paths see
// the zero value and fall back to the package-level cap.
func (s *AdminServer) clientQueryNumCap() int {
	if s.clientQueryNumCapOverride > 0 {
		return s.clientQueryNumCapOverride
	}
	return MaxClientQueryNumEntries
}

// evictOldestClientLocked drops the clientQueryNum entry with the
// oldest lastAccess timestamp. Caller holds s.clientNumMu.
func (s *AdminServer) evictOldestClientLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range s.clientQueryNum {
		if first || v.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastAccess
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.clientQueryNum, oldestKey)
	}
}

// RecordQuery is called from the DNS handler hook to log a query.
func (s *AdminServer) RecordQuery(client, qname, qtype, rcode string, cached bool, durationMs float64) {
	id := s.nextID.Add(1)

	// Track top clients and domains
	s.topClients.Inc(client)
	s.topDomains.Inc(qname)

	// Track per-client query number with TTL-based cleanup AND a
	// bounded cap so a UDP-source-spoofing attacker cannot inflate
	// the map between cleanup ticks. The cap is checked only when
	// inserting a new client; existing clients always update
	// without restriction so legitimate traffic patterns are
	// unaffected.
	s.clientNumMu.Lock()
	clientEntry, ok := s.clientQueryNum[client]
	if !ok {
		if len(s.clientQueryNum) >= s.clientQueryNumCap() {
			s.evictOldestClientLocked()
		}
		clientEntry = &clientQueryEntry{lastAccess: time.Now()}
		s.clientQueryNum[client] = clientEntry
	}
	// Update last access time
	clientEntry.lastAccess = time.Now()
	s.clientNumMu.Unlock()
	clientNum := clientEntry.count.Add(1)

	blocked := rcode == "BLOCKED"

	queryEntry := QueryEntry{
		ID:         id,
		GlobalNum:  id,
		ClientNum:  clientNum,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Client:     client,
		QName:      qname,
		QType:      qtype,
		RCode:      rcode,
		Cached:     cached,
		DurationMs: durationMs,
		Blocked:    blocked,
	}
	s.queryLog.Record(queryEntry)

	isError := rcode == "SERVFAIL" || rcode == "FORMERR" || rcode == "REFUSED"
	s.timeSeries.Record(cached, durationMs, isError)
}

// startClientCleanup periodically removes stale client query entries to prevent memory leak.
func (s *AdminServer) startClientCleanup(ctx context.Context) {
	ticker := time.NewTicker(s.clientCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupStaleClients()
		}
	}
}

// cleanupStaleClients removes client entries that haven't been accessed recently.
func (s *AdminServer) cleanupStaleClients() {
	s.clientNumMu.Lock()
	defer s.clientNumMu.Unlock()

	// Use 2x the cleanup interval as the TTL for client entries
	ttl := s.clientCleanupInterval * 2
	cutoff := time.Now().Add(-ttl)

	removed := 0
	for ip, entry := range s.clientQueryNum {
		if entry.lastAccess.Before(cutoff) {
			delete(s.clientQueryNum, ip)
			removed++
		}
	}

	if removed > 0 && s.logger != nil {
		s.logger.Debug("cleaned up stale client query entries", "count", removed)
	}
}

// registerRoutes sets up all API routes on the given mux.
func (s *AdminServer) registerRoutes(mux *http.ServeMux) {
	// robots.txt — explicit Disallow:/ so any crawler that lands on
	// an accidentally-exposed admin host skips indexing the entire
	// surface. Belt-and-braces with the X-Robots-Tag header set by
	// the security headers middleware.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})

	// Auth routes (no auth required, but still body-capped so a 1GB
	// JSON POST to /api/auth/login can't OOM the resolver before the
	// JSON decoder gives up).
	mux.HandleFunc("/api/auth/login", withBodyCap(s.handleLogin))

	// Setup routes (no auth required, body-capped — see above).
	mux.HandleFunc("/api/setup/status", withBodyCap(s.handleSetupStatus))
	mux.HandleFunc("/api/setup/complete", withBodyCap(s.handleSetupComplete))

	// Public routes (no auth required)
	mux.HandleFunc("/api/system/health", s.handleHealth)
	mux.HandleFunc("/api/system/readyz", s.handleReadyz)
	mux.HandleFunc("/api/system/livez", s.handleLivez)
	mux.HandleFunc("/api/system/version", s.handleVersion)
	mux.HandleFunc("/api/dns-guide", s.handleDNSGuide)
	mux.HandleFunc("/api/system/profile", s.requireAuth(s.handleSystemProfile))
	mux.HandleFunc("/api/dashboard/layout", s.requireAuth(s.handleDashboardLayout))

	// Protected routes
	mux.HandleFunc("/api/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("/api/auth/change-password", s.requireAuth(s.handleChangePassword))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/api/stats/timeseries", s.requireAuth(s.handleTimeSeries))
	mux.HandleFunc("/api/cache/stats", s.requireAuth(s.handleCacheStats))
	mux.HandleFunc("/api/cache/lookup", s.requireAuth(s.handleCacheLookup))
	mux.HandleFunc("/api/cache/flush", s.requireAuth(s.handleCacheFlush))
	mux.HandleFunc("/api/cache/entry", s.requireAuth(s.handleCacheDelete))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleGetConfig))
	mux.HandleFunc("/api/config/raw", s.requireAuth(s.handleConfigRaw))
	mux.HandleFunc("/api/config/validate", s.requireAuth(s.handleValidateConfig))
	mux.HandleFunc("/api/queries/recent", s.requireAuth(s.handleRecentQueries))
	mux.HandleFunc("/api/queries/stream", s.requireAuth(s.handleQueryStreamWS))
	mux.HandleFunc("/api/stats/timeseries/ws", s.requireAuth(s.handleTimeSeriesWS))
	mux.HandleFunc("/api/zabbix/items", s.requireAuth(s.handleZabbixItems))
	mux.HandleFunc("/api/zabbix/item", s.requireAuth(s.handleZabbixItem))
	mux.HandleFunc("/api/stats/top-clients", s.requireAuth(s.handleTopClients))
	mux.HandleFunc("/api/stats/top-domains", s.requireAuth(s.handleTopDomains))
	mux.HandleFunc("/api/cache/negative", s.requireAuth(s.handleNegativeCache))
	mux.HandleFunc("/api/system/update/check", s.requireAuth(s.handleCheckUpdate))
	mux.HandleFunc("/api/system/update/apply", s.requireAuth(s.handleApplyUpdate))
	mux.HandleFunc("/api/blocklist/stats", s.requireAuth(s.handleBlocklistStats))
	mux.HandleFunc("/api/fallback-events", s.requireAuth(s.handleFallbackEvents))
	mux.HandleFunc("/api/blocklist/lists", s.requireAuth(s.handleBlocklistLists))
	mux.HandleFunc("/api/blocklist/refresh", s.requireAuth(s.handleBlocklistRefresh))
	mux.HandleFunc("/api/blocklist/block", s.requireAuth(s.handleBlocklistBlock))
	mux.HandleFunc("/api/blocklist/unblock", s.requireAuth(s.handleBlocklistUnblock))
	mux.HandleFunc("/api/blocklist/check", s.requireAuth(s.handleBlocklistCheck))
	mux.HandleFunc("/api/blocklist/domains", s.requireAuth(s.handleBlocklistDomains))
	mux.HandleFunc("/api/system/tls", s.requireAuth(s.handleTLSStatus))
	mux.HandleFunc("/api/system/tls/renew", s.requireAuth(s.handleTLSRenew))
	mux.HandleFunc("/api/diagnostics/trace", s.requireAuth(s.handleDiagnosticsTrace))
	mux.HandleFunc("/api/dnssec", s.requireAuth(s.handleDNSSEC))
	mux.HandleFunc("/api/security", s.requireAuth(s.handleSecurity))
	mux.HandleFunc("/api/dnssec/nta", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			s.handleNTAAdd(w, r)
		case http.MethodDelete:
			s.handleNTARemove(w, r)
		default:
			jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	// DNS-over-HTTPS (RFC 8484)
	if s.dohEnabled && s.dohHandler != nil {
		mux.HandleFunc("/dns-query", s.handleDoH)
	}

	// SPA handler — serves embedded React frontend with SPA routing fallback
	mux.Handle("/", SPAHandler())
}
