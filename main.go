package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/labyrinth-dns/labyrinth/cache"
	"github.com/labyrinth-dns/labyrinth/config"
	applog "github.com/labyrinth-dns/labyrinth/log"
	"github.com/labyrinth-dns/labyrinth/metrics"
	"github.com/labyrinth-dns/labyrinth/resolver"
	"github.com/labyrinth-dns/labyrinth/security"
	"github.com/labyrinth-dns/labyrinth/server"
)

var (
	version   = "dev"
	buildTime = "unknown"
	goVersion = "unknown"
)

func main() {
	// CLI flags
	listenAddr := flag.String("listen", "", "listen address (default :53)")
	metricsAddr := flag.String("metrics", "", "metrics HTTP address")
	configPath := flag.String("config", "labyrinth.yaml", "config file path")
	logLevel := flag.String("log-level", "", "log level: debug|info|warn|error")
	logFormat := flag.String("log-format", "", "log format: json|text")
	cacheSize := flag.Int("cache-size", 0, "max cache entries")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Labyrinth %s\nPure Go Recursive DNS Resolver\nBuilt: %s\nGo: %s\nOS/Arch: %s/%s\n",
			version, buildTime, goVersion, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Subcommands
	if args := flag.Args(); len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Printf("Labyrinth %s\nPure Go Recursive DNS Resolver\nBuilt: %s\nGo: %s\nOS/Arch: %s/%s\n",
				version, buildTime, goVersion, runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		case "check":
			_, err := config.Load(*configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "config error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("configuration is valid")
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\nUsage: labyrinth [flags] [check|version]\n", args[0])
			os.Exit(1)
		}
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides
	if *listenAddr != "" {
		cfg.Server.ListenAddr = *listenAddr
	}
	if *metricsAddr != "" {
		cfg.Server.MetricsAddr = *metricsAddr
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if *logFormat != "" {
		cfg.Logging.Format = *logFormat
	}
	if *cacheSize > 0 {
		cfg.Cache.MaxEntries = *cacheSize
	}

	// Initialize logger
	logger := applog.NewLogger(cfg.Logging.Level, cfg.Logging.Format)

	// Initialize components
	m := metrics.NewMetrics()
	c := cache.NewCacheWithStale(cfg.Cache.MaxEntries, cfg.Cache.MinTTL, cfg.Cache.MaxTTL, cfg.Cache.NegMaxTTL,
		cfg.Cache.ServeStale, cfg.Cache.StaleTTL, m)

	var rl *security.RateLimiter
	if cfg.Security.RateLimit.Enabled {
		rl = security.NewRateLimiter(cfg.Security.RateLimit.Rate, cfg.Security.RateLimit.Burst)
	}

	var rrl *security.RRL
	if cfg.Security.RRL.Enabled {
		rrl = security.NewRRL(
			cfg.Security.RRL.ResponsesPerSecond,
			cfg.Security.RRL.SlipRatio,
			cfg.Security.RRL.IPv4Prefix,
			cfg.Security.RRL.IPv6Prefix,
		)
	}

	var acl *security.ACL
	if len(cfg.ACL.Allow) > 0 || len(cfg.ACL.Deny) > 0 {
		acl, err = security.NewACL(cfg.ACL.Allow, cfg.ACL.Deny)
		if err != nil {
			logger.Error("failed to parse ACL", "error", err)
			os.Exit(1)
		}
	}

	res := resolver.NewResolver(c, resolver.ResolverConfig{
		MaxDepth:        cfg.Resolver.MaxDepth,
		MaxCNAMEDepth:   cfg.Resolver.MaxCNAMEDepth,
		UpstreamTimeout: cfg.Resolver.UpstreamTimeout,
		UpstreamRetries: cfg.Resolver.UpstreamRetries,
		QMinEnabled:     cfg.Resolver.QMinEnabled,
		PreferIPv4:      cfg.Resolver.PreferIPv4,
	}, m, logger)

	handler := server.NewMainHandler(res, c, rl, rrl, acl, m, logger)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background tasks
	go c.StartSweeper(ctx, cfg.Cache.SweepInterval)
	if rl != nil {
		go rl.StartCleanup(ctx)
	}

	// Root hint priming
	go func() {
		if err := res.PrimeRootHints(); err != nil {
			logger.Warn("root hint priming failed", "error", err)
		}
	}()

	// Start metrics HTTP server
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

	// Start DNS servers
	errCh := make(chan error, 2)

	udpServer, err := server.NewUDPServer(cfg.Server.ListenAddr, handler, cfg.Server.MaxUDPWorkers, logger)
	if err != nil {
		logger.Error("failed to start UDP server", "error", err)
		os.Exit(1)
	}
	go func() { errCh <- udpServer.Serve(ctx) }()

	tcpServer, err := server.NewTCPServer(cfg.Server.ListenAddr, handler, cfg.Server.TCPTimeout, cfg.Server.MaxTCPConns, logger)
	if err != nil {
		logger.Error("failed to start TCP server", "error", err)
		os.Exit(1)
	}
	go func() { errCh <- tcpServer.Serve(ctx) }()

	// Setup SIGUSR1/SIGUSR2 handlers (Unix only, no-op on Windows)
	setupUnixSignals(logger, c)

	logger.Info("labyrinth started",
		"listen", cfg.Server.ListenAddr,
		"metrics", cfg.Server.MetricsAddr,
		"cache_max", cfg.Cache.MaxEntries,
		"qmin", cfg.Resolver.QMinEnabled,
	)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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
				os.Exit(0)
			}

		case err := <-errCh:
			if ctx.Err() != nil {
				// Expected error on shutdown
				continue
			}
			logger.Error("server error", "error", err)
			cancel()
			os.Exit(1)
		}
	}
}
