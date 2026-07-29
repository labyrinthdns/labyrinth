//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/labyrinthdns/labyrinth/cache"
)

func setupUnixSignals(logger *slog.Logger, c *cache.Cache) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGUSR1:
				logger.Info("flushing cache (SIGUSR1)")
				c.Flush()
				stats := c.Stats()
				logger.Info("cache flushed", "entries", stats.Entries)

			case syscall.SIGUSR2:
				stats := c.Stats()
				logger.Info("cache stats (SIGUSR2)", "entries", stats.Entries)

			case syscall.SIGHUP:
				logger.Info("config reload requested (SIGHUP)")
				// Note: full hot-reload would require re-reading the config file
				// and applying non-disruptive settings. For now, log the event.
				logger.Info("SIGHUP received — restart to apply config changes")
			}
		}
	}()
}
