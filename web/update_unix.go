//go:build !windows

package web

import (
	"os"
	"path/filepath"
	"syscall"
)

func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
