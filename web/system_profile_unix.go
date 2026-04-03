//go:build !windows

package web

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readSystemTotalMemoryBytes() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return info.Totalram * uint64(info.Unit)
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
