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
	count     atomic.Uint64
	lastAccess time.Time
}

// AdminServer provides the admin dashboard HTTP backend.
type AdminServer struct {
	cache           *cache.Cache
	metrics         *metrics.Metrics
	resolver        *resolver.Resolver
	config          *config.Config
	configPath      string
	queryLog        *QueryLog
	timeSeries      *TimeSeriesAggregator
	logger          *slog.Logger
	jwtSecret       []byte
	setupDone       bool
	nextID          atomic.Uint64
	topClients      *TopTracker
	topDomains      *TopTracker
	clientQueryNum  map[string]*clientQueryEntry
	clientNumMu     sync.Mutex
	clientCleanupInterval time.Duration
	updateCache     *UpdateInfo
	updateCheckedAt time.Time
	updateMu        sync.RWMutex
	blocklist       *blocklist.Manager
	dohEnabled      bool
	dohHandler      server.Handler
}

// NewAdminServer creates a new AdminServer. The bl parameter is optional and
// may be nil when the blocklist feature is disabled.
func NewAdminServer(cfg *config.Config, c *cache.Cache, m *metrics.Metrics, r *resolver.Resolver, logger *slog.Logger, bl *blocklist.Manager) (*AdminServer, error) {
	bufSize := cfg.Web.QueryLogBuffer
	if bufSize <= 0 {
		bufSize = 1000
	}

	// Generate a random JWT secret - this is required
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	// Determine cleanup interval, default to 5 minutes
	cleanupInterval := 5 * time.Minute

	return &AdminServer{
		cache:          c,
		metrics:        m,
		resolver:       r,
		config:         cfg,
		configPath:     "labyrinth.yaml",
		queryLog:       NewQueryLog(bufSize),
		timeSeries:     NewTimeSeriesAggregator(),
		logger:         logger,
		jwtSecret:      secret,
		topClients:     NewTopTracker(cfg.Web.TopClientsLimit),
		topDomains:     NewTopTracker(cfg.Web.TopDomainsLimit),
		clientQueryNum: make(map[string]*clientQueryEntry),
		clientCleanupInterval: cleanupInterval,
		blocklist:      bl,
	}, nil
}

// SetConfigPath sets the path used by config edit endpoints.
func (s *AdminServer) SetConfigPath(path string) {
	if path == "" {
		return
	}
	s.configPath = path
}

// Start starts the HTTP server and blocks until the context is cancelled.
func (s *AdminServer) Start(ctx context.Context) error {
	// Start client query cleanup goroutine
	go s.startClientCleanup(ctx)

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	addr := s.config.Web.Addr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	var h3Server *http3.Server
	baseHandler := http.Handler(mux)

	if s.config.Web.DoH3Enabled {
		if !s.config.Web.TLSEnabled || s.config.Web.TLSCertFile == "" || s.config.Web.TLSKeyFile == "" {
			return fmt.Errorf("web.doh3_enabled=true requires web.tls_enabled=true and web.tls_cert_file/web.tls_key_file")
		}

		h3Server = &http3.Server{
			Addr:    addr,
			Handler: mux,
		}
		baseHandler = withQUICHeaders(baseHandler, h3Server, s.logger)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      baseHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 2)

	if h3Server != nil {
		go func() {
			s.logger.Info("admin dashboard HTTP/3 starting", "addr", addr)
			if err := h3Server.ListenAndServeTLS(s.config.Web.TLSCertFile, s.config.Web.TLSKeyFile); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("admin HTTP/3 server error: %w", err):
				default:
				}
			}
		}()
	}

	go func() {
		if s.config.Web.TLSEnabled && s.config.Web.TLSCertFile != "" && s.config.Web.TLSKeyFile != "" {
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

// RecordQuery is called from the DNS handler hook to log a query.
func (s *AdminServer) RecordQuery(client, qname, qtype, rcode string, cached bool, durationMs float64) {
	id := s.nextID.Add(1)

	// Track top clients and domains
	s.topClients.Inc(client)
	s.topDomains.Inc(qname)

	// Track per-client query number with TTL-based cleanup
	s.clientNumMu.Lock()
	clientEntry, ok := s.clientQueryNum[client]
	if !ok {
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
	// Auth routes (no auth required)
	mux.HandleFunc("/api/auth/login", s.handleLogin)

	// Setup routes (no auth required)
	mux.HandleFunc("/api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("/api/setup/complete", s.handleSetupComplete)

	// System routes
	mux.HandleFunc("/api/system/health", s.handleHealth)
	mux.HandleFunc("/api/system/version", s.handleVersion)

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
	mux.HandleFunc("/api/zabbix/items", s.requireAuth(s.handleZabbixItems))
	mux.HandleFunc("/api/zabbix/item", s.requireAuth(s.handleZabbixItem))
	mux.HandleFunc("/api/stats/top-clients", s.requireAuth(s.handleTopClients))
	mux.HandleFunc("/api/stats/top-domains", s.requireAuth(s.handleTopDomains))
	mux.HandleFunc("/api/cache/negative", s.requireAuth(s.handleNegativeCache))
	mux.HandleFunc("/api/system/update/check", s.requireAuth(s.handleCheckUpdate))
	mux.HandleFunc("/api/system/update/apply", s.requireAuth(s.handleApplyUpdate))
	mux.HandleFunc("/api/blocklist/stats", s.requireAuth(s.handleBlocklistStats))
	mux.HandleFunc("/api/blocklist/lists", s.requireAuth(s.handleBlocklistLists))
	mux.HandleFunc("/api/blocklist/refresh", s.requireAuth(s.handleBlocklistRefresh))
	mux.HandleFunc("/api/blocklist/block", s.requireAuth(s.handleBlocklistBlock))
	mux.HandleFunc("/api/blocklist/unblock", s.requireAuth(s.handleBlocklistUnblock))
	mux.HandleFunc("/api/blocklist/check", s.requireAuth(s.handleBlocklistCheck))

	// DNS-over-HTTPS (RFC 8484)
	if s.dohEnabled && s.dohHandler != nil {
		mux.HandleFunc("/dns-query", s.handleDoH)
	}

	// SPA handler — serves embedded React frontend with SPA routing fallback
	mux.Handle("/", SPAHandler())
}
