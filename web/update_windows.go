//go:build windows

package web

import (
	"os"
	"os/exec"
	"path/filepath"
)

var (
	restartExecutable  = os.Executable
	restartEvalSymlinks = filepath.EvalSymlinks
	restartCommand     = func(name string, args ...string) *exec.Cmd {
		return exec.Command(name, args...)
	}
	restartExit = os.Exit
)

func restartSelf() error {
	exePath, err := restartExecutable()
	if err != nil {
		return err
	}
	exePath, err = restartEvalSymlinks(exePath)
	if err != nil {
		return err
	}
	cmd := restartCommand(exePath, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	restartExit(0)
	return nil
}
