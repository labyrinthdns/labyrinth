//go:build windows

package web

import (
	"os"
	"os/exec"
)

var (
	restartExecutable = os.Executable
	restartCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command(name, args...)
	}
	restartExit = os.Exit
)

func restartSelf() error {
	exePath, err := restartExecutable()
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
