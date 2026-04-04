//go:build windows

package web

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func readSystemTotalMemoryBytes() uint64 {
	// x/sys/windows doesn't expose a stable GlobalMemoryStatusEx wrapper
	// across versions; keep this optional metric as unknown on Windows.
	return 0
}

func readSystemFreeMemoryBytes() uint64 {
	return 0
}

func readSystemLoadAverages() (one float64, five float64, fifteen float64) {
	// Windows has no POSIX-style load average metric.
	return 0, 0, 0
}

func readNetworkIOCounters() (rxBytes uint64, txBytes uint64, rxPackets uint64, txPackets uint64) {
	return 0, 0, 0, 0
}

func readDiskUsageBytes(path string) (total uint64, free uint64, targetPath string, err error) {
	targetPath = path
	if targetPath == "" {
		targetPath = "C:\\"
	}
	targetPath = filepath.Clean(targetPath)

	// Windows disk APIs need a drive root path.
	volume := filepath.VolumeName(targetPath)
	if volume == "" {
		volume = "C:"
	}
	targetPath = strings.TrimRight(volume, "\\/") + "\\"

	p, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return 0, 0, targetPath, err
	}

	var freeBytesAvailable uint64
	var totalBytes uint64
	var totalFreeBytes uint64
	if err = windows.GetDiskFreeSpaceEx(p, &freeBytesAvailable, &totalBytes, &totalFreeBytes); err != nil {
		return 0, 0, targetPath, err
	}

	return totalBytes, totalFreeBytes, targetPath, nil
}
