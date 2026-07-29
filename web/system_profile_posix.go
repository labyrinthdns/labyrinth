//go:build !windows && !linux

package web

import (
	"net"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Non-Linux Unix targets (for example Darwin/BSD) do not expose Linux
// sysinfo/proc APIs. Return zero for optional fields and keep disk metrics.
func readSystemTotalMemoryBytes() uint64 {
	return 0
}

func readSystemFreeMemoryBytes() uint64 {
	return 0
}

func readSystemLoadAverages() (one float64, five float64, fifteen float64) {
	return 0, 0, 0
}

func readDiskUsageBytes(path string) (total uint64, free uint64, targetPath string, err error) {
	targetPath = path
	if targetPath == "" {
		targetPath = "/"
	}
	targetPath = filepath.Clean(targetPath)

	var stat unix.Statfs_t
	if err = unix.Statfs(targetPath, &stat); err != nil {
		return 0, 0, targetPath, err
	}

	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bavail * uint64(stat.Bsize)
	return total, free, targetPath, nil
}

func readNetworkIOCounters() (rxBytes uint64, txBytes uint64, rxPackets uint64, txPackets uint64) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, 0, 0, 0
	}

	// net.Interface does not provide byte/packet counters portably on these targets.
	// We still report interface count elsewhere in the profile.
	_ = interfaces
	return 0, 0, 0, 0
}

