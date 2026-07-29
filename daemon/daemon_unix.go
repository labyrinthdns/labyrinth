//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const daemonEnvKey = "_LABYRINTH_DAEMON"

// Signal0 returns syscall signal 0 for process existence check.
func Signal0() os.Signal {
	return syscall.Signal(0)
}

// Daemonize re-executes the current binary as a background process.
// The parent process exits after the child starts successfully.
// Returns true if this is the daemon child process, false if parent.
func Daemonize(pidFile string) (bool, error) {
	// If we're already the daemon child, just write PID and continue
	if os.Getenv(daemonEnvKey) == "1" {
		if pidFile != "" {
			if err := WritePID(pidFile); err != nil {
				return true, fmt.Errorf("write PID file: %w", err)
			}
		}
		return true, nil
	}

	// Re-exec self with daemon env var set
	executable, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("get executable: %w", err)
	}

	cmd := exec.Command(executable, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnvKey+"=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start daemon: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Labyrinth daemon started (PID %d)\n", cmd.Process.Pid)
	return false, nil
}

// StopDaemon sends SIGTERM to the process in the PID file.
//
// H-9: verify the recorded PID actually belongs to a labyrinth process
// before signalling. Without this guard, a stale PID file (after crash
// + PID reuse) or an attacker-planted PID file lets `labyrinth daemon
// stop` SIGTERM an arbitrary process. We accept either /proc/<pid>/comm
// containing "labyrinth" or, if /proc is unavailable, a liveness probe
// via signal 0 (best-effort match — the kill primitive is still bounded
// because the parent CLI tool runs as the same user as the daemon, but
// the cmdline check makes accidental kills impossible on Linux).
func StopDaemon(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return fmt.Errorf("read PID file: %w", err)
	}

	if err := verifyPIDIsLabyrinth(pid); err != nil {
		return fmt.Errorf("refusing to signal PID %d: %w", pid, err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
	}

	fmt.Fprintf(os.Stdout, "Sent SIGTERM to PID %d\n", pid)
	return nil
}

// verifyPIDIsLabyrinth returns nil only when the given PID belongs to a
// process whose executable name appears to be labyrinth. On Linux it reads
// /proc/<pid>/comm. On other Unix systems, it falls back to a signal-0
// liveness check (refuses if the process does not exist).
func verifyPIDIsLabyrinth(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID")
	}
	// Linux fast path
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		name := strings.TrimSpace(string(data))
		if !strings.Contains(strings.ToLower(name), "labyrinth") {
			return fmt.Errorf("PID belongs to %q, not labyrinth", name)
		}
		return nil
	}
	// Other Unix: at least confirm liveness — can't identify the process
	// reliably without /proc, but `kill -0` rejects non-existent PIDs.
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("process not running")
	}
	return nil
}

// StatusDaemon checks if the daemon is running.
func StatusDaemon(pidFile string) (bool, int, error) {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return false, 0, err
	}
	return IsRunning(pid), pid, nil
}
