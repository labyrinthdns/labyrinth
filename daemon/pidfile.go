package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WritePID writes the current process ID to the given file path.
func WritePID(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644)
}

// ReadPID reads a PID from the given file path.
func ReadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file: %w", err)
	}
	return pid, nil
}

// RemovePID removes the PID file.
func RemovePID(path string) error {
	return os.Remove(path)
}

// IsRunning checks if a process with the given PID is still running.
func IsRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	sig := Signal0()
	if sig == nil {
		// Windows: FindProcess succeeded means process likely exists
		return true
	}
	err = process.Signal(sig)
	return err == nil
}
