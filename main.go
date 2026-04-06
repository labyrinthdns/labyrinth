package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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
	version             = "dev"
	buildTime           = "unknown"
	goVersion           = "unknown"
	daemonizeProcess    = daemon.Daemonize
	stopDaemonProcess   = daemon.StopDaemon
	statusDaemonProcess = daemon.StatusDaemon
	startHTTPServicesFn = startHTTPServices
	startDNSServersFn   = startDNSServers
)

const (
	infraCleanupInterval = 10 * time.Minute
	infraEntryMaxAge     = time.Hour
)

func main() {
	os.Exit(run())
}

func run() int {
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
		return 0
	}

	// Subcommands
	if args := flag.Args(); len(args) > 0 {
		switch args[0] {
		case "version":
			printVersion()
			return 0
		case "check":
			_, err := config.Load(*configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "config error: %v\n", err)
				return 1
			}
			fmt.Println("configuration is valid")
			return 0
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
				return 1
			}
			hash, err := web.HashPassword(args[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
			fmt.Println(hash)
			return 0
		case "daemon":
			return handleDaemonCommand(args[1:], *configPath)
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\nUsage: labyrinth [flags] [check|version|hash|daemon]\n", args[0])
			return 1
		}
	}

	// Daemon mode
	if *daemonMode {
		cfg, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config load error in daemon mode: %v\n", err)
			return 1
		}
		pidFile := "/var/run/labyrinth.pid"
		if cfg != nil && cfg.Daemon.PIDFile != "" {
			pidFile = cfg.Daemon.PIDFile
		}
		isDaemon, err := daemonizeProcess(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
			return 1
		}
		if !isDaemon {
			return 0 // parent exits
		}
		// child continues
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 1
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
	if len(cfg.ACL.Allow) > 0 || len(cfg.ACL.Deny) > 0 || len(cfg.ACL.Zones) > 0 {
		acl, err = security.NewACL(cfg.ACL.Allow, cfg.ACL.Deny)
		if err != nil {
			logger.Error("failed to parse ACL", "error", err)
			return 1
		}
		for _, zc := range cfg.ACL.Zones {
			if err := acl.AddZoneACL(security.ZoneACLConfig{
				Zone:  zc.Zone,
				Allow: zc.Allow,
				Deny:  zc.Deny,
			}); err != nil {
				logger.Error("failed to parse zone ACL", "zone", zc.Zone, "error", err)
				return 1
			}
		}
	}

	resCfg := resolver.ResolverConfig{
		MaxDepth:          cfg.Resolver.MaxDepth,
		MaxCNAMEDepth:     cfg.Resolver.MaxCNAMEDepth,
		UpstreamTimeout:   cfg.Resolver.UpstreamTimeout,
		UpstreamRetries:   cfg.Resolver.UpstreamRetries,
		QMinEnabled:       cfg.Resolver.QMinEnabled,
		Caps0x20Enabled:   cfg.Resolver.Caps0x20Enabled,
		PreferIPv4:        cfg.Resolver.PreferIPv4,
		DNSSECEnabled:     cfg.Resolver.DNSSECEnabled,
		DNS64Enabled:      cfg.Resolver.DNS64Enabled,
		FallbackResolvers: cfg.Resolver.FallbackResolvers,
	}
	if cfg.Resolver.DNS64Enabled {
		prefix, prefixErr := resolver.ParseDNS64Prefix(cfg.Resolver.DNS64Prefix)
		if prefixErr != nil {
			logger.Error("invalid dns64 prefix", "prefix", cfg.Resolver.DNS64Prefix, "error", prefixErr)
			return 1
		}
		resCfg.DNS64Prefix = prefix
		logger.Info("DNS64 enabled", "prefix", cfg.Resolver.DNS64Prefix)
	}
	if len(resCfg.FallbackResolvers) > 0 {
		logger.Info("fallback resolvers configured", "addrs", resCfg.FallbackResolvers)
	}
	res := resolver.NewResolver(c, resCfg, m, logger)

	// Build local zones from config + default localhost zone
	res.SetLocalZones(buildLocalZones(cfg, logger))

	// Build forward/stub zone table from config
	if len(cfg.ForwardZones) > 0 || len(cfg.StubZones) > 0 {
		res.SetForwardTable(buildForwardTable(cfg, logger))
	}

	handler := server.NewMainHandler(res, c, rl, rrl, acl, m, logger)

	// Security: private address filtering
	handler.SetPrivateFilter(cfg.Security.PrivateAddressFilter)

	// Cache: harden-below-nxdomain (RFC 8020)
	c.SetHardenBelowNX(cfg.Resolver.HardenBelowNXDomain)

	// Cache: prefetch
	c.SetPrefetchEnabled(cfg.Cache.Prefetch)
	if cfg.Cache.Prefetch {
		c.SetPrefetchFunc(func(name string, qtype, qclass uint16) {
			_, _ = res.Resolve(name, qtype, qclass)
		})
	}

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

	// Infra cache cleanup (stale NS RTT entries)
	go res.InfraCache().StartCleanup(ctx, infraCleanupInterval, infraEntryMaxAge)

	// Root hint priming
	go func() {
		if err := res.PrimeRootHints(); err != nil {
			logger.Warn("root hint priming failed", "error", err)
		}
		if cfg.Resolver.DNSSECEnabled {
			res.EnableDNSSEC(logger)
			logger.Info("DNSSEC validation enabled")
		}
		// Root hints auto-refresh (RFC 8109)
		if cfg.Resolver.RootHintsRefresh > 0 {
			go res.StartRootRefresh(ctx, cfg.Resolver.RootHintsRefresh)
		}
	}()

	if err := startHTTPServicesFn(ctx, cfg, c, m, res, handler, logger, blocklistMgr, *configPath); err != nil {
		return 1
	}

	errCh, err := startDNSServersFn(ctx, cfg, handler, logger)
	if err != nil {
		return 1
	}

	// Setup SIGUSR1/SIGUSR2 handlers (Unix only, no-op on Windows)
	setupUnixSignals(logger, c)

	logger.Info("labyrinth started",
		"listen", cfg.Server.ListenAddr,
		"web", cfg.Web.Addr,
		"web_enabled", cfg.Web.Enabled,
		"cache_max", cfg.Cache.MaxEntries,
		"qmin", cfg.Resolver.QMinEnabled,
	)

	return waitForShutdown(ctx, cancel, cfg, c, *daemonMode, errCh, logger)
}
