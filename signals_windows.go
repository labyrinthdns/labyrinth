//go:build windows

package main

import (
	"log/slog"

	"github.com/labyrinthdns/labyrinth/cache"
)

func setupUnixSignals(_ *slog.Logger, _ *cache.Cache) {
	// SIGUSR1/SIGUSR2 are not available on Windows.
	// Cache flush can be triggered via the admin API or restart.
}
