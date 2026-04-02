//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
)

const daemonEnvKey = "_LABYRINTH_DAEMON"

// Signal0 returns nil (Windows doesn't support signal 0).
// Process existence is checked via FindProcess which fails on Windows for non-existent PIDs.
func Signal0() os.Signal {
	return nil
}

// Daemonize re-executes the current binary as a detached background process on Windows.
func Daemonize(pidFile string) (bool, error) {
	if os.Getenv(daemonEnvKey) == "1" {
		if pidFile != "" {
			if err := WritePID(pidFile); err != nil {
				return true, fmt.Errorf("write PID file: %w", err)
			}
		}
		return true, nil
	}

	executable, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("get executable: %w", err)
	}

	cmd := exec.Command(executable, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnvKey+"=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start daemon: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Labyrinth daemon started (PID %d)\n", cmd.Process.Pid)
	return false, nil
}

// StopDaemon terminates the process in the PID file on Windows.
func StopDaemon(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return fmt.Errorf("read PID file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := process.Kill(); err != nil {
		return fmt.Errorf("kill process %d: %w", pid, err)
	}

	fmt.Fprintf(os.Stdout, "Terminated PID %d\n", pid)
	return nil
}

// StatusDaemon checks if the daemon is running.
func StatusDaemon(pidFile string) (bool, int, error) {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return false, 0, err
	}
	// On Windows, FindProcess succeeds even for dead processes,
	// but we can try opening the process to check.
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, pid, nil
	}
	_ = process
	return true, pid, nil
}
