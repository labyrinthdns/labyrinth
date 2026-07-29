//go:build linux

package web

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func readSystemTotalMemoryBytes() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return info.Totalram * uint64(info.Unit)
}

func readSystemFreeMemoryBytes() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return info.Freeram * uint64(info.Unit)
}

func readSystemLoadAverages() (one float64, five float64, fifteen float64) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, 0, 0
	}

	// Linux sysinfo stores load averages as fixed-point values where
	// 1.0 is represented as 65536.
	const fixedPointScale = 65536.0
	return float64(info.Loads[0]) / fixedPointScale,
		float64(info.Loads[1]) / fixedPointScale,
		float64(info.Loads[2]) / fixedPointScale
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
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		// Skip headers.
		if lineNo <= 2 {
			continue
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}

		fields := strings.Fields(parts[1])
		// rx bytes, packets ... then tx bytes, packets ...
		if len(fields) < 10 {
			continue
		}

		rxB, err1 := strconv.ParseUint(fields[0], 10, 64)
		rxP, err2 := strconv.ParseUint(fields[1], 10, 64)
		txB, err3 := strconv.ParseUint(fields[8], 10, 64)
		txP, err4 := strconv.ParseUint(fields[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}

		rxBytes += rxB
		rxPackets += rxP
		txBytes += txB
		txPackets += txP
	}

	return rxBytes, txBytes, rxPackets, txPackets
}
