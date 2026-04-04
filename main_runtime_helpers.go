package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/daemon"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/server"
	"github.com/labyrinthdns/labyrinth/web"
)

const dnsServerErrorBuffer = 4

var (
	waitSignalNotify = signal.Notify
	waitSignalStop   = signal.Stop
)

func startHTTPServices(
	ctx context.Context,
	cfg *config.Config,
	c *cache.Cache,
	m *metrics.Metrics,
	res *resolver.Resolver,
	handler *server.MainHandler,
	logger *slog.Logger,
	blocklistMgr *blocklist.Manager,
	configPath string,
) error {
	// Start web dashboard (replaces standalone metrics server when enabled)
	if cfg.Web.Enabled {
		adminServer, err := web.NewAdminServer(cfg, c, m, res, logger, blocklistMgr)
		if err != nil {
			logger.Error("failed to create admin server", "error", err)
			return err
		}
		adminServer.SetConfigPath(configPath)

		// Enable DoH endpoint if any DoH transport is configured.
		if cfg.Web.DoHEnabled || cfg.Web.DoH3Enabled {
			adminServer.SetDoHHandler(handler)
			adminServer.SetDoHEnabled(true)
			logger.Info("DoH endpoint enabled on web dashboard",
				"path", "/dns-query",
				"http", cfg.Web.DoHEnabled,
				"http3", cfg.Web.DoH3Enabled,
			)
			if !cfg.Web.TLSEnabled {
				logger.Warn("DoH is enabled without web TLS; terminate TLS at reverse proxy or enable web.tls_* settings")
			}
			if cfg.Web.DoH3Enabled {
				logger.Info("DoH/HTTP3 requested; web server will advertise Alt-Svc and accept QUIC connections")
			}
		}

		// Wire query log hook
		handler.OnQuery = func(client, qname, qtype, rcode string, cached bool, durationMs float64) {
			adminServer.RecordQuery(client, qname, qtype, rcode, cached, durationMs)
		}

		go func() {
			logger.Info("web dashboard starting", "addr", cfg.Web.Addr)
			if err := adminServer.Start(ctx); err != nil && ctx.Err() == nil {
				logger.Error("web dashboard error", "error", err)
			}
		}()

		// Background update checker
		go adminServer.StartUpdateChecker(ctx)

		// Start Zabbix agent if enabled
		if cfg.Zabbix.Enabled && cfg.Zabbix.Addr != "" {
			go func() {
				logger.Info("zabbix agent starting", "addr", cfg.Zabbix.Addr)
				web.StartZabbixAgent(ctx, cfg.Zabbix.Addr, m, c, logger)
			}()
		}
		return nil
	}

	// Standalone metrics server (legacy mode)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m)
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			stats := c.Stats()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"healthy","cache_entries":%d,"uptime":"%s"}`,
				stats.Entries, time.Since(m.StartTime()).Round(time.Second))
		})
		mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
			if res.IsReady() {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"status":"ready"}`)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"status":"not ready"}`)
			}
		})
		logger.Info("metrics server starting", "addr", cfg.Server.MetricsAddr)
		if err := http.ListenAndServe(cfg.Server.MetricsAddr, mux); err != nil {
			logger.Error("metrics server error", "error", err)
		}
	}()

	return nil
}

func startDNSServers(
	ctx context.Context,
	cfg *config.Config,
	handler *server.MainHandler,
	logger *slog.Logger,
) (chan error, error) {
	errCh := make(chan error, dnsServerErrorBuffer)

	udpServer, err := server.NewUDPServer(cfg.Server.ListenAddr, handler, cfg.Server.MaxUDPWorkers, logger)
	if err != nil {
		logger.Error("failed to start UDP server", "error", err)
		return nil, err
	}
	go func() { errCh <- udpServer.Serve(ctx) }()

	tcpServer, err := server.NewTCPServer(cfg.Server.ListenAddr, handler, cfg.Server.TCPTimeout, cfg.Server.MaxTCPConns, logger,
		server.WithPipelineMax(cfg.Server.TCPPipelineMax),
		server.WithIdleTimeout(cfg.Server.TCPIdleTimeout),
	)
	if err != nil {
		logger.Error("failed to start TCP server", "error", err)
		return nil, err
	}
	go func() { errCh <- tcpServer.Serve(ctx) }()

	// Start DoT server if enabled
	if cfg.Server.DoTEnabled && cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		dotServer, dotErr := server.NewDoTServer(
			cfg.Server.DoTListenAddr,
			handler,
			cfg.Server.TLSCertFile,
			cfg.Server.TLSKeyFile,
			cfg.Server.TCPTimeout,
			cfg.Server.MaxTCPConns,
			logger,
		)
		if dotErr != nil {
			logger.Error("failed to start DoT server", "error", dotErr)
			return nil, dotErr
		}
		go func() { errCh <- dotServer.Serve(ctx) }()
		logger.Info("DoT server started", "addr", cfg.Server.DoTListenAddr)
	} else if cfg.Server.DoTEnabled {
		err := fmt.Errorf("DoT enabled but TLS certificate/key is missing")
		logger.Error(err.Error(), "tls_cert_file", cfg.Server.TLSCertFile, "tls_key_file", cfg.Server.TLSKeyFile)
		return nil, err
	}

	return errCh, nil
}

func waitForShutdown(
	ctx context.Context,
	cancel context.CancelFunc,
	cfg *config.Config,
	c *cache.Cache,
	daemonMode bool,
	errCh <-chan error,
	logger *slog.Logger,
) int {
	sigCh := make(chan os.Signal, 1)
	waitSignalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer waitSignalStop(sigCh)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutting down", "signal", sig)
				cancel()
				time.Sleep(cfg.Server.GracefulPeriod)
				stats := c.Stats()
				logger.Info("final stats", "cache_entries", stats.Entries)
				// Clean up PID file if running as daemon
				if daemonMode && cfg.Daemon.PIDFile != "" {
					daemon.RemovePID(cfg.Daemon.PIDFile)
				}
				return 0
			}

		case err := <-errCh:
			if ctx.Err() != nil {
				continue
			}
			logger.Error("server error", "error", err)
			cancel()
			return 1
		}
	}
}
