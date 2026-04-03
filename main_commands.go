package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/daemon"
)

func printVersion() {
	fmt.Printf("Labyrinth %s\nPure Go Recursive DNS Resolver\nBuilt: %s\nGo: %s\nOS/Arch: %s/%s\nWebsite: https://labyrinthdns.com\nGitHub: https://github.com/labyrinthdns/labyrinth\n",
		version, buildTime, goVersion, runtime.GOOS, runtime.GOARCH)
}

func handleDaemonCommand(args []string, configPath string) int {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load error: %v\n", err)
		return 1
	}
	pidFile := "/var/run/labyrinth.pid"
	if cfg != nil && cfg.Daemon.PIDFile != "" {
		pidFile = cfg.Daemon.PIDFile
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: labyrinth daemon [start|stop|status]")
		return 1
	}

	switch args[0] {
	case "start":
		isDaemon, err := daemon.Daemonize(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if !isDaemon {
			return 0
		}
	case "stop":
		if err := daemon.StopDaemon(pidFile); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	case "status":
		running, pid, err := daemon.StatusDaemon(pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not running (no PID file)\n")
			return 1
		}
		if running {
			fmt.Printf("running (PID %d)\n", pid)
		} else {
			fmt.Printf("not running (stale PID %d)\n", pid)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown daemon command: %s\n", args[0])
		return 1
	}
	return 0
}
