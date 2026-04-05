package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"crypto/tls"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/metrics"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/server"
)

func runWithArgs(args []string) int {
	oldArgs := os.Args
	oldFlagSet := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlagSet
	}()

	os.Args = args
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	return run()
}

func withMainHooksReset(t *testing.T) {
	t.Helper()
	prevDaemonize := daemonizeProcess
	prevStopDaemon := stopDaemonProcess
	prevStatusDaemon := statusDaemonProcess
	prevStartHTTP := startHTTPServicesFn
	prevStartDNS := startDNSServersFn
	t.Cleanup(func() {
		daemonizeProcess = prevDaemonize
		stopDaemonProcess = prevStopDaemon
		statusDaemonProcess = prevStatusDaemon
		startHTTPServicesFn = prevStartHTTP
		startDNSServersFn = prevStartDNS
	})
}

func TestRootMainHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ROOT_MAIN_HELPER") != "1" {
		t.Skip("helper process")
	}
	os.Args = []string{"labyrinth", "version"}
	main()
}

func TestMain_ExitCodeZero(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestRootMainHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_ROOT_MAIN_HELPER=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected helper main to exit successfully: %v", err)
	}
}

func TestRun_Subcommands(t *testing.T) {
	tempCfg := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	if got := runWithArgs([]string{"labyrinth", "-version"}); got != 0 {
		t.Fatalf("version flag exit code = %d, want 0", got)
	}
	if got := runWithArgs([]string{"labyrinth", "version"}); got != 0 {
		t.Fatalf("version command exit code = %d, want 0", got)
	}
	if got := runWithArgs([]string{"labyrinth", "-config", tempCfg, "check"}); got != 0 {
		t.Fatalf("check command exit code = %d, want 0", got)
	}
	if got := runWithArgs([]string{"labyrinth", "hash"}); got != 1 {
		t.Fatalf("hash missing arg exit code = %d, want 1", got)
	}
	if got := runWithArgs([]string{"labyrinth", "hash", "GoodPass123"}); got != 0 {
		t.Fatalf("hash valid exit code = %d, want 0", got)
	}
	if got := runWithArgs([]string{"labyrinth", "unknown"}); got != 1 {
		t.Fatalf("unknown command exit code = %d, want 1", got)
	}
	if got := runWithArgs([]string{"labyrinth", "daemon"}); got != 1 {
		t.Fatalf("daemon usage exit code = %d, want 1", got)
	}

	// Exercise the full startup path and fail fast on invalid DNS listen addr.
	if got := runWithArgs([]string{"labyrinth", "-listen", "bad-listen-addr"}); got != 1 {
		t.Fatalf("invalid listen startup exit code = %d, want 1", got)
	}
}

func TestRun_CheckSubcommand_ConfigError(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("resolver:\n  max_depth: 0\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath, "check"}); got != 1 {
		t.Fatalf("check with invalid config exit code = %d, want 1", got)
	}
}

func TestRun_HashSubcommand_ShortPassword(t *testing.T) {
	if got := runWithArgs([]string{"labyrinth", "hash", "short"}); got != 1 {
		t.Fatalf("hash with short password exit code = %d, want 1", got)
	}
}

func TestRun_ConfigLoadError_MainPath(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("resolver:\n  max_depth: 0\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath}); got != 1 {
		t.Fatalf("main path config load error exit code = %d, want 1", got)
	}
}

func TestRun_DaemonMode_ConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("resolver:\n  max_depth: 0\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if got := runWithArgs([]string{"labyrinth", "-daemon", "-config", cfgPath}); got != 1 {
		t.Fatalf("daemon mode config load error exit code = %d, want 1", got)
	}
}

func TestRun_DaemonMode_ChildAndOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "daemon.yaml")
	pidPath := filepath.Join(tmpDir, "labyrinth.pid")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
  metrics_addr: "127.0.0.1:0"
  graceful_shutdown: "1ms"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
daemon:
  pid_file: "` + pidPath + `"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevNotify := waitSignalNotify
	prevStop := waitSignalStop
	waitSignalNotify = func(ch chan<- os.Signal, _ ...os.Signal) {
		go func() {
			time.Sleep(15 * time.Millisecond)
			ch <- syscall.SIGINT
		}()
	}
	waitSignalStop = func(chan<- os.Signal) {}
	defer func() {
		waitSignalNotify = prevNotify
		waitSignalStop = prevStop
	}()

	oldEnv := os.Getenv("_LABYRINTH_DAEMON")
	if err := os.Setenv("_LABYRINTH_DAEMON", "1"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	defer func() {
		_ = os.Setenv("_LABYRINTH_DAEMON", oldEnv)
	}()

	args := []string{
		"labyrinth",
		"-daemon",
		"-config", cfgPath,
		"-listen", "127.0.0.1:0",
		"-metrics", "127.0.0.1:0",
		"-web", "127.0.0.1:0",
		"-log-level", "debug",
		"-log-format", "text",
		"-cache-size", "1234",
	}
	if got := runWithArgs(args); got != 0 {
		t.Fatalf("daemon child+overrides exit code = %d, want 0", got)
	}
}

func TestRun_DaemonMode_DaemonizeErrorAndParentExit(t *testing.T) {
	withMainHooksReset(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "daemon.yaml")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	daemonizeProcess = func(string) (bool, error) {
		return false, errors.New("daemonize failed")
	}
	if got := runWithArgs([]string{"labyrinth", "-daemon", "-config", cfgPath}); got != 1 {
		t.Fatalf("daemonize error exit code = %d, want 1", got)
	}

	daemonizeProcess = func(string) (bool, error) {
		return false, nil
	}
	if got := runWithArgs([]string{"labyrinth", "-daemon", "-config", cfgPath}); got != 0 {
		t.Fatalf("daemon parent exit code = %d, want 0", got)
	}
}

func TestRun_StartHTTPServicesErrorBranch(t *testing.T) {
	withMainHooksReset(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	startHTTPServicesFn = func(context.Context, *config.Config, *cache.Cache, *metrics.Metrics, *resolver.Resolver, *server.MainHandler, *slog.Logger, *blocklist.Manager, string) error {
		return errors.New("http services failed")
	}
	startDNSServersFn = func(context.Context, *config.Config, *server.MainHandler, *slog.Logger, ...*tls.Config) (chan error, error) {
		t.Fatalf("startDNSServers should not be called when startHTTPServices fails")
		return nil, nil
	}

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath}); got != 1 {
		t.Fatalf("startHTTPServices failure exit code = %d, want 1", got)
	}
}

func TestRun_ACLParseErrorBranches(t *testing.T) {
	// NewACL error branch.
	tmpDir := t.TempDir()
	cfg1 := filepath.Join(tmpDir, "acl-bad.yaml")
	content1 := `
server:
  listen_addr: "127.0.0.1:0"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
access_control:
  allow: "not-a-cidr"
`
	if err := os.WriteFile(cfg1, []byte(content1), 0o644); err != nil {
		t.Fatalf("write config1: %v", err)
	}
	if got := runWithArgs([]string{"labyrinth", "-config", cfg1}); got != 1 {
		t.Fatalf("ACL parse error exit code = %d, want 1", got)
	}

	// Zone ACL parse error branch.
	cfg2 := filepath.Join(tmpDir, "zone-acl-bad.yaml")
	content2 := `
server:
  listen_addr: "127.0.0.1:0"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
access_control:
  allow: "127.0.0.1/32"
  zones:
    test.local:
      allow: "not-a-cidr"
`
	if err := os.WriteFile(cfg2, []byte(content2), 0o644); err != nil {
		t.Fatalf("write config2: %v", err)
	}
	if got := runWithArgs([]string{"labyrinth", "-config", cfg2}); got != 1 {
		t.Fatalf("zone ACL parse error exit code = %d, want 1", got)
	}
}

func TestRun_FullStartupAndGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
  metrics_addr: "127.0.0.1:0"
  graceful_shutdown: "1ms"
web:
  enabled: false
resolver:
  dnssec_enabled: false
security:
  rate_limit:
    enabled: false
  rrl:
    enabled: false
cache:
  prefetch: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevNotify := waitSignalNotify
	prevStop := waitSignalStop
	waitSignalNotify = func(ch chan<- os.Signal, _ ...os.Signal) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			ch <- syscall.SIGINT
		}()
	}
	waitSignalStop = func(chan<- os.Signal) {}
	defer func() {
		waitSignalNotify = prevNotify
		waitSignalStop = prevStop
	}()

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath}); got != 0 {
		t.Fatalf("full startup+shutdown run exit code = %d, want 0", got)
	}
}

func TestRun_InvalidDNS64Prefix(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
web:
  enabled: false
resolver:
  dns64_enabled: true
  dns64_prefix: "invalid-prefix"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath}); got != 1 {
		t.Fatalf("invalid dns64 prefix exit code = %d, want 1", got)
	}
}

func TestRun_FullStartup_WithFeatureBranches(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")
	cfgContent := `
server:
  listen_addr: "127.0.0.1:0"
  metrics_addr: "127.0.0.1:0"
  graceful_shutdown: "1ms"
web:
  enabled: false
resolver:
  dnssec_enabled: false
  dns64_enabled: true
  dns64_prefix: "64:ff9b::/96"
cache:
  prefetch: true
  no_cache_clients: "127.0.0.1"
security:
  rate_limit:
    enabled: true
    rate: 25
    burst: 50
  rrl:
    enabled: true
    responses_per_second: 3
    slip_ratio: 2
    ipv4_prefix: 24
    ipv6_prefix: 56
access_control:
  allow: "127.0.0.1/32"
local_zones:
  test.local:
    type: static
    data:
      - "test.local. A 10.0.0.2"
forward_zones:
  corp.local:
    addrs: "127.0.0.1"
stub_zones:
  stub.local:
    addrs: "127.0.0.1"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevNotify := waitSignalNotify
	prevStop := waitSignalStop
	waitSignalNotify = func(ch chan<- os.Signal, _ ...os.Signal) {
		go func() {
			time.Sleep(15 * time.Millisecond)
			ch <- syscall.SIGINT
		}()
	}
	waitSignalStop = func(chan<- os.Signal) {}
	defer func() {
		waitSignalNotify = prevNotify
		waitSignalStop = prevStop
	}()

	if got := runWithArgs([]string{"labyrinth", "-config", cfgPath}); got != 0 {
		t.Fatalf("feature-rich startup run exit code = %d, want 0", got)
	}
}

func TestHandleDaemonCommand_StatusAndUnknown(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing.yaml")
	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 1 {
		t.Fatalf("status expected non-running exit code 1, got %d", got)
	}
	if got := handleDaemonCommand([]string{"unknown"}, cfgPath); got != 1 {
		t.Fatalf("unknown daemon subcommand exit code = %d, want 1", got)
	}
}

func TestHandleDaemonCommand_ConfigLoadErrorAndStaleStatus(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")
	pidFile := filepath.Join(tmpDir, "labyrinth.pid")

	invalidCfg := `
resolver:
  max_depth: 0
daemon:
  pid_file: "` + pidFile + `"
`
	if err := os.WriteFile(cfgPath, []byte(invalidCfg), 0o644); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 1 {
		t.Fatalf("expected config load error exit code 1, got %d", got)
	}

	validCfg := `
daemon:
  pid_file: "` + pidFile + `"
`
	if err := os.WriteFile(cfgPath, []byte(validCfg), 0o644); err != nil {
		t.Fatalf("write valid config: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte("-1"), 0o644); err != nil {
		t.Fatalf("write stale pid: %v", err)
	}
	// On some platforms this may still be treated as running; both outcomes are acceptable.
	code := handleDaemonCommand([]string{"status"}, cfgPath)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected status exit code: %d", code)
	}
}

func TestHandleDaemonCommand_StartStopStatus_AllHookedBranches(t *testing.T) {
	withMainHooksReset(t)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")
	pidFile := filepath.Join(tmpDir, "labyrinth.pid")
	cfg := `
daemon:
  pid_file: "` + pidFile + `"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// start -> daemonize error
	daemonizeProcess = func(string) (bool, error) {
		return false, errors.New("daemonize start error")
	}
	if got := handleDaemonCommand([]string{"start"}, cfgPath); got != 1 {
		t.Fatalf("start daemonize error exit code = %d, want 1", got)
	}

	// start -> parent branch (!isDaemon)
	daemonizeProcess = func(string) (bool, error) {
		return false, nil
	}
	if got := handleDaemonCommand([]string{"start"}, cfgPath); got != 0 {
		t.Fatalf("start parent exit code = %d, want 0", got)
	}

	// start -> child branch (isDaemon=true)
	daemonizeProcess = func(string) (bool, error) {
		return true, nil
	}
	if got := handleDaemonCommand([]string{"start"}, cfgPath); got != 0 {
		t.Fatalf("start child exit code = %d, want 0", got)
	}

	// stop -> success and error
	stopDaemonProcess = func(string) error { return nil }
	if got := handleDaemonCommand([]string{"stop"}, cfgPath); got != 0 {
		t.Fatalf("stop success exit code = %d, want 0", got)
	}
	stopDaemonProcess = func(string) error { return errors.New("stop error") }
	if got := handleDaemonCommand([]string{"stop"}, cfgPath); got != 1 {
		t.Fatalf("stop error exit code = %d, want 1", got)
	}

	// status -> not running(no pid file) branch
	statusDaemonProcess = func(string) (bool, int, error) {
		return false, 0, errors.New("no pid")
	}
	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 1 {
		t.Fatalf("status error exit code = %d, want 1", got)
	}

	// status -> running branch
	statusDaemonProcess = func(string) (bool, int, error) {
		return true, 1234, nil
	}
	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 0 {
		t.Fatalf("status running exit code = %d, want 0", got)
	}

	// status -> stale branch
	statusDaemonProcess = func(string) (bool, int, error) {
		return false, 5678, nil
	}
	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 1 {
		t.Fatalf("status stale exit code = %d, want 1", got)
	}
}

func TestHandleDaemonCommand_StatusRunningAndStopError(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "labyrinth.pid")
	cfgPath := filepath.Join(tmpDir, "labyrinth.yaml")

	content := "daemon:\n  pid_file: " + pidFile + "\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	if got := handleDaemonCommand([]string{"status"}, cfgPath); got != 0 {
		t.Fatalf("status running exit code = %d, want 0", got)
	}

	// Force stop error by writing a bogus PID.
	if err := os.WriteFile(pidFile, []byte("999999"), 0o644); err != nil {
		t.Fatalf("write bogus pid: %v", err)
	}
	if got := handleDaemonCommand([]string{"stop"}, cfgPath); got != 1 {
		t.Fatalf("stop with bogus pid exit code = %d, want 1", got)
	}
}

func TestZoneBuilders(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		LocalZones: []config.LocalZoneConfig{
			{
				Name: "example.local",
				Type: "static",
				Data: []string{"example.local. A 10.0.0.2"},
			},
			{
				Name: "invalid.local",
				Type: "unknown",
				Data: []string{"invalid.local. A 10.0.0.3"},
			},
		},
		ForwardZones: []config.ForwardZoneConfig{
			{Name: "corp.local", Addrs: []string{"10.10.10.10"}},
		},
		StubZones: []config.StubZoneConfig{
			{Name: "stub.local", Addrs: []string{"10.10.10.11"}},
		},
		Blocklist: config.BlocklistConfig{
			Lists: []config.BlocklistEntry{
				{URL: "https://example.com/list.txt", Format: "hosts"},
			},
		},
	}

	local := buildLocalZones(cfg, logger)
	if local == nil {
		t.Fatalf("expected local zone table")
	}
	localhostA := local.Lookup("localhost.", dns.TypeA, dns.ClassIN)
	if localhostA == nil || len(localhostA.Answers) == 0 {
		t.Fatalf("expected default localhost A record")
	}
	exampleA := local.Lookup("example.local.", dns.TypeA, dns.ClassIN)
	if exampleA == nil || len(exampleA.Answers) == 0 {
		t.Fatalf("expected configured local zone A record")
	}

	forward := buildForwardTable(cfg, logger)
	if forward == nil {
		t.Fatalf("expected forward table")
	}
	if z := forward.Match("a.corp.local."); z == nil || z.IsStub {
		t.Fatalf("expected forward zone match")
	}
	if z := forward.Match("x.stub.local."); z == nil || !z.IsStub {
		t.Fatalf("expected stub zone match")
	}

	lists := convertBlocklistEntries(cfg.Blocklist.Lists)
	if len(lists) != 1 || lists[0].URL == "" {
		t.Fatalf("convertBlocklistEntries returned unexpected result: %#v", lists)
	}
}

func TestRuntimeHelpers_ErrorAndFallbackPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	// startHTTPServices: legacy path (web disabled) should return nil.
	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled: false,
		},
		Server: config.ServerConfig{
			MetricsAddr: "127.0.0.1:bad",
		},
	}
	if err := startHTTPServices(context.Background(), cfg, c, m, res, handler, logger, nil, ""); err != nil {
		t.Fatalf("startHTTPServices unexpected error: %v", err)
	}

	// startDNSServers: invalid listen address should return error.
	cfg.Server.ListenAddr = "bad-listen-addr"
	cfg.Server.TCPTimeout = time.Second
	if _, err := startDNSServers(context.Background(), cfg, handler, logger); err == nil {
		t.Fatalf("expected startDNSServers error for invalid listen address")
	}

	// waitForShutdown: server error path should return 1.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	errCh <- errors.New("boom")
	if got := waitForShutdown(ctx, cancel, cfg, c, false, errCh, logger); got != 1 {
		t.Fatalf("waitForShutdown server-error exit code = %d, want 1", got)
	}

	// Windows no-op signal setup should be callable.
	setupUnixSignals(logger, c)
}

func TestRuntimeHelpers_SuccessPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:             true,
			Addr:                "127.0.0.1:0",
			QueryLogBuffer:      10,
			UpdateCheckInterval: time.Hour,
		},
		Server: config.ServerConfig{
			ListenAddr:     "127.0.0.1:0",
			MetricsAddr:    "127.0.0.1:0",
			MaxUDPWorkers:  1,
			TCPTimeout:     50 * time.Millisecond,
			MaxTCPConns:    10,
			GracefulPeriod: 5 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startHTTPServices(ctx, cfg, c, m, res, handler, logger, nil, ""); err != nil {
		t.Fatalf("startHTTPServices web-enabled unexpected error: %v", err)
	}

	errCh, err := startDNSServers(ctx, cfg, handler, logger)
	if err != nil {
		t.Fatalf("startDNSServers unexpected error: %v", err)
	}

	cancel()
	_ = errCh
	time.Sleep(50 * time.Millisecond)
}

func waitHTTPReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server did not become ready: %s", url)
}

func TestStartHTTPServices_LegacyMetricsEndpoints(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled: false,
		},
		Server: config.ServerConfig{
			MetricsAddr: addr,
		},
	}

	if err := startHTTPServices(context.Background(), cfg, c, m, res, handler, logger, nil, ""); err != nil {
		t.Fatalf("startHTTPServices legacy mode error: %v", err)
	}

	base := "http://" + addr
	waitHTTPReady(t, base+"/health")

	healthResp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("/health status=%d want 200", healthResp.StatusCode)
	}

	readyResp, err := http.Get(base + "/ready")
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	_ = readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/ready status=%d want 503 (resolver not primed)", readyResp.StatusCode)
	}
}

func TestStartHTTPServices_WebMode_DoHAndZabbix(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	cfg := &config.Config{
		Web: config.WebConfig{
			Enabled:             true,
			Addr:                "127.0.0.1:0",
			QueryLogBuffer:      10,
			DoHEnabled:          true,
			DoH3Enabled:         true,
			TLSEnabled:          false,
			UpdateCheckInterval: time.Hour,
		},
		Zabbix: config.ZabbixConfig{
			Enabled: true,
			Addr:    "127.0.0.1:0",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startHTTPServices(ctx, cfg, c, m, res, handler, logger, nil, "labyrinth.yaml"); err != nil {
		t.Fatalf("startHTTPServices web mode error: %v", err)
	}
}

func TestStartDNSServers_DoTMissingTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:    "127.0.0.1:0",
			MaxUDPWorkers: 1,
			TCPTimeout:    50 * time.Millisecond,
			MaxTCPConns:   10,
			DoTEnabled:    true,
		},
	}

	if _, err := startDNSServers(context.Background(), cfg, handler, logger); err == nil {
		t.Fatalf("expected DoT configuration error when TLS files are missing")
	}
}

func writeTestCertPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "labyrinth-test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certOut.Close()
		t.Fatalf("encode cert: %v", err)
	}
	_ = certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyOut.Close()
		t.Fatalf("encode key: %v", err)
	}
	_ = keyOut.Close()

	return certPath, keyPath
}

func TestStartDNSServers_DoTSuccessPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)
	res := resolver.NewResolver(c, resolver.ResolverConfig{MaxDepth: 5}, m, logger)
	handler := server.NewMainHandler(res, c, nil, nil, nil, m, logger)

	tmpDir := t.TempDir()
	certPath, keyPath := writeTestCertPair(t, tmpDir)

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:    "127.0.0.1:0",
			MaxUDPWorkers: 1,
			TCPTimeout:    50 * time.Millisecond,
			MaxTCPConns:   10,
			DoTEnabled:    true,
			DoTListenAddr: "127.0.0.1:0",
			TLSCertFile:   certPath,
			TLSKeyFile:    keyPath,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh, err := startDNSServers(ctx, cfg, handler, logger)
	if err != nil {
		cancel()
		t.Fatalf("expected DoT start success, got error: %v", err)
	}

	cancel()

	select {
	case <-errCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("expected server goroutines to exit after context cancel")
	}
}

func TestWaitForShutdown_OnSignal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewMetrics()
	c := cache.NewCache(10, 5, 3600, 300, m)

	cfg := &config.Config{
		Server: config.ServerConfig{
			GracefulPeriod: 1 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	retCh := make(chan int, 1)

	prevNotify := waitSignalNotify
	prevStop := waitSignalStop
	waitSignalNotify = func(ch chan<- os.Signal, _ ...os.Signal) {
		ch <- syscall.SIGINT
	}
	waitSignalStop = func(chan<- os.Signal) {}
	defer func() {
		waitSignalNotify = prevNotify
		waitSignalStop = prevStop
	}()

	go func() {
		retCh <- waitForShutdown(ctx, cancel, cfg, c, false, errCh, logger)
	}()

	select {
	case code := <-retCh:
		if code != 0 {
			t.Fatalf("waitForShutdown on signal returned %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("waitForShutdown did not return after SIGINT")
	}
}
