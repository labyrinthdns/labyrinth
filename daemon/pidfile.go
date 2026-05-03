package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WritePID writes the current process ID to the given file path.
//
// H-9: open with the platform's most-restrictive flags so a pre-planted
// symlink at the PID-file path cannot redirect this write to an arbitrary
// target (the historical /var/run TOCTOU). On systems that support it,
// O_NOFOLLOW prevents traversal of a symlink at the destination; we always
// truncate explicitly via O_TRUNC. Mode 0640 (was 0644) keeps the file
// readable by the service group only.
func WritePID(path string) error {
	pid := os.Getpid()
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC | platformPIDOpenFlags()
	f, err := os.OpenFile(path, flags, 0o640)
	if err != nil {
		return err
	}
	if _, werr := f.Write([]byte(strconv.Itoa(pid) + "\n")); werr != nil {
		f.Close()
		return werr
	}
	return f.Close()
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
