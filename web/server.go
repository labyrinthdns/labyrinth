package web

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// Version info variables — set at build time from main.go.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GoVersion = "unknown"
)

// AdminServer provides the admin dashboard HTTP backend.
type AdminServer struct {
	cache      *cache.Cache
	metrics    *metrics.Metrics
	resolver   *resolver.Resolver
	config     *config.Config
	queryLog   *QueryLog
	timeSeries *TimeSeriesAggregator
	logger     *slog.Logger
	jwtSecret  []byte
	setupDone  bool
	nextID     atomic.Uint64
}

// NewAdminServer creates a new AdminServer.
func NewAdminServer(cfg *config.Config, c *cache.Cache, m *metrics.Metrics, r *resolver.Resolver, logger *slog.Logger) *AdminServer {
	bufSize := cfg.Web.QueryLogBuffer
	if bufSize <= 0 {
		bufSize = 1000
	}

	// Generate a random JWT secret if none is configured
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback to a deterministic secret (not ideal, but functional)
		secret = []byte("labyrinth-default-jwt-secret-key!")
	}

	return &AdminServer{
		cache:      c,
		metrics:    m,
		resolver:   r,
		config:     cfg,
		queryLog:   NewQueryLog(bufSize),
		timeSeries: NewTimeSeriesAggregator(),
		logger:     logger,
		jwtSecret:  secret,
	}
}

// Start starts the HTTP server and blocks until the context is cancelled.
func (s *AdminServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	addr := s.config.Web.Addr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("admin dashboard starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("admin dashboard shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("admin server error: %w", err)
	}
}

// RecordQuery is called from the DNS handler hook to log a query.
func (s *AdminServer) RecordQuery(client, qname, qtype, rcode string, cached bool, durationMs float64) {
	id := s.nextID.Add(1)
	entry := QueryEntry{
		ID:         id,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Client:     client,
		QName:      qname,
		QType:      qtype,
		RCode:      rcode,
		Cached:     cached,
		DurationMs: durationMs,
	}
	s.queryLog.Record(entry)

	isError := rcode == "SERVFAIL" || rcode == "FORMERR" || rcode == "REFUSED"
	s.timeSeries.Record(cached, durationMs, isError)
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
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/api/stats/timeseries", s.requireAuth(s.handleTimeSeries))
	mux.HandleFunc("/api/cache/stats", s.requireAuth(s.handleCacheStats))
	mux.HandleFunc("/api/cache/lookup", s.requireAuth(s.handleCacheLookup))
	mux.HandleFunc("/api/cache/flush", s.requireAuth(s.handleCacheFlush))
	mux.HandleFunc("/api/cache/entry", s.requireAuth(s.handleCacheDelete))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleGetConfig))
	mux.HandleFunc("/api/queries/recent", s.requireAuth(s.handleRecentQueries))
	mux.HandleFunc("/api/queries/stream", s.requireAuth(s.handleQueryStreamWS))
	mux.HandleFunc("/api/zabbix/items", s.requireAuth(s.handleZabbixItems))
	mux.HandleFunc("/api/zabbix/item", s.requireAuth(s.handleZabbixItem))

	// SPA handler — serves embedded React frontend with SPA routing fallback
	mux.Handle("/", SPAHandler())
}
