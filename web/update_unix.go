//go:build !windows

package web

import (
	"os"
	"syscall"
)

func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
