package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/daemon"
	applog "github.com/labyrinthdns/labyrinth/log"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/security"
	"github.com/labyrinthdns/labyrinth/server"
	"github.com/labyrinthdns/labyrinth/web"
)

var (
	version   = "dev"
	buildTime = "unknown"
	goVersion = "unknown"
)

func main() {
	// Set version info for web package
	web.Version = version
	web.BuildTime = buildTime
	web.GoVersion = goVersion

	// CLI flags
	listenAddr := flag.String("listen", "", "listen address (default :53)")
	metricsAddr := flag.String("metrics", "", "metrics HTTP address")
	webAddr := flag.String("web", "", "web dashboard address (overrides config)")
	configPath := flag.String("config", "labyrinth.yaml", "config file path")
	logLevel := flag.String("log-level", "", "log level: debug|info|warn|error")
	logFormat := flag.String("log-format", "", "log format: json|text")
	cacheSize := flag.Int("cache-size", 0, "max cache entries")
	daemonMode := flag.Bool("daemon", false, "run as background daemon")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Subcommands
	if args := flag.Args(); len(args) > 0 {
		switch args[0] {
		case "version":
			printVersion()
			os.Exit(0)
		case "check":
			_, err := config.Load(*configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "config error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("configuration is valid")
			os.Exit(0)
		case "hash":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "usage: labyrinth hash <password>")
				fmt.Fprintf(os.Stderr, "\nGenerates a bcrypt hash for use in labyrinth.yaml web.auth.password_hash.\n")
				fmt.Fprintf(os.Stderr, "Password must be at least %d characters.\n", web.MinPasswordLength)
				fmt.Fprintf(os.Stderr, "\nExample:\n")
				fmt.Fprintf(os.Stderr, "  labyrinth hash MySecurePass123\n")
				fmt.Fprintf(os.Stderr, "\nThen add to labyrinth.yaml:\n")
				fmt.Fprintf(os.Stderr, "  web:\n")
				fmt.Fprintf(os.Stderr, "    auth:\n")
				fmt.Fprintf(os.Stderr, "      username: admin\n")
				fmt.Fprintf(os.Stderr, "      password_hash: <paste hash here>\n")
				os.Exit(1)
			}
			hash, err := web.HashPassword(args[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(hash)
			os.Exit(0)
		case "daemon":
			handleDaemonCommand(args[1:], *configPath)
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\nUsage: labyrinth [flags] [check|version|hash|daemon]\n", args[0])
			os.Exit(1)
		}
	}

	// Daemon mode
	if *daemonMode {
		cfg, _ := config.Load(*configPath)
		pidFile := "/var/run/labyrinth.pid"
		if cfg != nil && cfg.Daemon.PIDFile != "" {
			pidFile = cfg.Daemon.PIDFile
		}
		isDaemon, err := daemon.Daemonize(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
			os.Exit(1)
		}
		if !isDaemon {
			os.Exit(0) // parent exits
		}
		// child continues
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
	if *webAddr != "" {
		cfg.Web.Addr = *webAddr
		cfg.Web.Enabled = true
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
		DNSSECEnabled:   cfg.Resolver.DNSSECEnabled,
	}, m, logger)

	// Build local zones from config + default localhost zone
	res.SetLocalZones(buildLocalZones(cfg, logger))

	// Build forward/stub zone table from config
	if len(cfg.ForwardZones) > 0 || len(cfg.StubZones) > 0 {
		res.SetForwardTable(buildForwardTable(cfg, logger))
	}

	handler := server.NewMainHandler(res, c, rl, rrl, acl, m, logger)

	if len(cfg.Cache.NoCacheClients) > 0 {
		handler.SetNoCacheClients(cfg.Cache.NoCacheClients)
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Blocklist
	var blocklistMgr *blocklist.Manager
	if cfg.Blocklist.Enabled {
		blocklistMgr = blocklist.NewManager(blocklist.ManagerConfig{
			Lists:           convertBlocklistEntries(cfg.Blocklist.Lists),
			Whitelist:       cfg.Blocklist.Whitelist,
			BlockingMode:    cfg.Blocklist.BlockingMode,
			CustomIP:        cfg.Blocklist.CustomIP,
			RefreshInterval: cfg.Blocklist.RefreshInterval,
		}, logger)
		handler.SetBlocklist(blocklistMgr)
		go blocklistMgr.Start(ctx)
	}

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
		if cfg.Resolver.DNSSECEnabled {
			res.EnableDNSSEC(logger)
			logger.Info("DNSSEC validation enabled")
		}
	}()

	// Start web dashboard (replaces standalone metrics server when enabled)
	if cfg.Web.Enabled {
		adminServer := web.NewAdminServer(cfg, c, m, res, logger, blocklistMgr)

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
	} else {
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
	}

	// Start DNS servers
	errCh := make(chan error, 2)

	udpServer, err := server.NewUDPServer(cfg.Server.ListenAddr, handler, cfg.Server.MaxUDPWorkers, logger)
	if err != nil {
		logger.Error("failed to start UDP server", "error", err)
		os.Exit(1)
	}
	go func() { errCh <- udpServer.Serve(ctx) }()

	tcpServer, err := server.NewTCPServer(cfg.Server.ListenAddr, handler, cfg.Server.TCPTimeout, cfg.Server.MaxTCPConns, logger,
		server.WithPipelineMax(cfg.Server.TCPPipelineMax),
		server.WithIdleTimeout(cfg.Server.TCPIdleTimeout),
	)
	if err != nil {
		logger.Error("failed to start TCP server", "error", err)
		os.Exit(1)
	}
	go func() { errCh <- tcpServer.Serve(ctx) }()

	// Setup SIGUSR1/SIGUSR2 handlers (Unix only, no-op on Windows)
	setupUnixSignals(logger, c)

	logger.Info("labyrinth started",
		"listen", cfg.Server.ListenAddr,
		"web", cfg.Web.Addr,
		"web_enabled", cfg.Web.Enabled,
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
				// Clean up PID file if running as daemon
				if *daemonMode && cfg.Daemon.PIDFile != "" {
					daemon.RemovePID(cfg.Daemon.PIDFile)
				}
				os.Exit(0)
			}

		case err := <-errCh:
			if ctx.Err() != nil {
				continue
			}
			logger.Error("server error", "error", err)
			cancel()
			os.Exit(1)
		}
	}
}

func printVersion() {
	fmt.Printf("Labyrinth %s\nPure Go Recursive DNS Resolver\nBuilt: %s\nGo: %s\nOS/Arch: %s/%s\nWebsite: https://labyrinthdns.com\nGitHub: https://github.com/labyrinthdns/labyrinth\n",
		version, buildTime, goVersion, runtime.GOOS, runtime.GOARCH)
}

func handleDaemonCommand(args []string, configPath string) {
	cfg, _ := config.Load(configPath)
	pidFile := "/var/run/labyrinth.pid"
	if cfg != nil && cfg.Daemon.PIDFile != "" {
		pidFile = cfg.Daemon.PIDFile
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: labyrinth daemon [start|stop|status]")
		os.Exit(1)
	}

	switch args[0] {
	case "start":
		isDaemon, err := daemon.Daemonize(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if !isDaemon {
			os.Exit(0)
		}
	case "stop":
		if err := daemon.StopDaemon(pidFile); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		running, pid, err := daemon.StatusDaemon(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not running (no PID file)\n")
			os.Exit(1)
		}
		if running {
			fmt.Printf("running (PID %d)\n", pid)
		} else {
			fmt.Printf("not running (stale PID %d)\n", pid)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown daemon command: %s\n", args[0])
		os.Exit(1)
	}
}

func convertBlocklistEntries(entries []config.BlocklistEntry) []blocklist.ListEntry {
	result := make([]blocklist.ListEntry, len(entries))
	for i, e := range entries {
		result[i] = blocklist.ListEntry{URL: e.URL, Format: e.Format}
	}
	return result
}

// buildLocalZones constructs a LocalZoneTable from config, always including the
// default localhost zone (localhost → 127.0.0.1 / ::1).
func buildLocalZones(cfg *config.Config, logger *slog.Logger) *resolver.LocalZoneTable {
	var zones []resolver.LocalZone

	// Default localhost zone
	localhostZone := resolver.LocalZone{
		Name: "localhost",
		Type: resolver.LocalStatic,
	}
	defaultRecords := []string{
		"localhost. A 127.0.0.1",
		"localhost. AAAA ::1",
	}
	for _, s := range defaultRecords {
		rec, err := resolver.ParseLocalRecord(s)
		if err != nil {
			logger.Error("failed to parse default local record", "record", s, "error", err)
			continue
		}
		localhostZone.Records = append(localhostZone.Records, *rec)
	}
	zones = append(zones, localhostZone)

	// Config-defined zones
	for _, zc := range cfg.LocalZones {
		zt, ok := resolver.ParseLocalZoneType(zc.Type)
		if !ok {
			logger.Warn("unknown local zone type, skipping", "zone", zc.Name, "type", zc.Type)
			continue
		}
		zone := resolver.LocalZone{
			Name: zc.Name,
			Type: zt,
		}
		for _, s := range zc.Data {
			rec, err := resolver.ParseLocalRecord(s)
			if err != nil {
				logger.Warn("failed to parse local record", "zone", zc.Name, "record", s, "error", err)
				continue
			}
			zone.Records = append(zone.Records, *rec)
		}
		zones = append(zones, zone)
	}

	return resolver.NewLocalZoneTable(zones)
}

func buildForwardTable(cfg *config.Config, logger *slog.Logger) *resolver.ForwardTable {
	var zones []resolver.ForwardZone

	for _, fz := range cfg.ForwardZones {
		zones = append(zones, resolver.ForwardZone{
			Name:  fz.Name,
			Addrs: fz.Addrs,
		})
		logger.Info("forward zone configured", "zone", fz.Name, "addrs", fz.Addrs)
	}

	for _, sz := range cfg.StubZones {
		zones = append(zones, resolver.ForwardZone{
			Name:   sz.Name,
			Addrs:  sz.Addrs,
			IsStub: true,
		})
		logger.Info("stub zone configured", "zone", sz.Name, "addrs", sz.Addrs)
	}

	return resolver.NewForwardTable(zones)
}
