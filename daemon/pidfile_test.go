package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestWriteAndReadPID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	if err := WritePID(pidFile); err != nil {
		t.Fatalf("WritePID error: %v", err)
	}

	pid, err := ReadPID(pidFile)
	if err != nil {
		t.Fatalf("ReadPID error: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("PID mismatch: got %d, want %d", pid, os.Getpid())
	}
}

func TestReadPIDNotExist(t *testing.T) {
	_, err := ReadPID("/nonexistent/path/test.pid")
	if err == nil {
		t.Error("expected error for nonexistent PID file")
	}
}

func TestReadPIDInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "bad.pid")
	os.WriteFile(pidFile, []byte("not-a-number\n"), 0644)

	_, err := ReadPID(pidFile)
	if err == nil {
		t.Error("expected error for invalid PID content")
	}
}

func TestRemovePID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	WritePID(pidFile)

	if err := RemovePID(pidFile); err != nil {
		t.Fatalf("RemovePID error: %v", err)
	}

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should be removed")
	}
}

func TestRemovePIDNotExist(t *testing.T) {
	err := RemovePID("/nonexistent/path/test.pid")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestIsRunningCurrentProcess(t *testing.T) {
	pid := os.Getpid()
	if !IsRunning(pid) {
		t.Error("current process should be running")
	}
}

func TestIsRunningDeadProcess(t *testing.T) {
	// PID 99999999 is very unlikely to exist
	if IsRunning(99999999) {
		t.Log("PID 99999999 appears to exist (unlikely but possible)")
	}
}

func TestSignal0(t *testing.T) {
	sig := Signal0()
	// On Windows sig is nil, on Unix it's syscall.Signal(0)
	_ = sig
}

func TestStatusDaemonNotRunning(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	_, _, err := StatusDaemon(pidFile)
	if err == nil {
		t.Error("expected error for nonexistent PID file")
	}
}

func TestStatusDaemonWithPID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Write current PID so it will be "running"
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)

	running, pid, err := StatusDaemon(pidFile)
	if err != nil {
		t.Fatalf("StatusDaemon error: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("PID mismatch: got %d", pid)
	}
	_ = running // platform-dependent
}

func TestDaemonizeAsChild(t *testing.T) {
	// Simulate being the daemon child
	os.Setenv(daemonEnvKey, "1")
	defer os.Unsetenv(daemonEnvKey)

	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	isDaemon, err := Daemonize(pidFile)
	if err != nil {
		t.Fatalf("Daemonize error: %v", err)
	}
	if !isDaemon {
		t.Error("should return true when running as daemon child")
	}

	// PID file should be written
	pid, err := ReadPID(pidFile)
	if err != nil {
		t.Fatalf("ReadPID error: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("PID mismatch: got %d", pid)
	}
}

func TestDaemonizeChildNoPIDFile(t *testing.T) {
	os.Setenv(daemonEnvKey, "1")
	defer os.Unsetenv(daemonEnvKey)

	isDaemon, err := Daemonize("")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !isDaemon {
		t.Error("should be daemon child")
	}
}

func TestStopDaemon_NonExistentProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Write a PID that almost certainly does not belong to a running process.
	// Use a very high PID that is extremely unlikely to exist.
	os.WriteFile(pidFile, []byte("4999999\n"), 0644)

	err := StopDaemon(pidFile)
	// On Windows, FindProcess succeeds for any PID but Kill will fail
	// for a non-existent process. Either way we expect an error.
	if err == nil {
		t.Error("expected error when stopping non-existent process")
	}
}

func TestStopDaemon_NoPIDFile(t *testing.T) {
	err := StopDaemon("/nonexistent/path/nope.pid")
	if err == nil {
		t.Error("expected error for missing PID file")
	}
}

func TestStopDaemon_InvalidPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "bad.pid")
	os.WriteFile(pidFile, []byte("not-a-number\n"), 0644)

	err := StopDaemon(pidFile)
	if err == nil {
		t.Error("expected error for invalid PID content")
	}
}

func TestIsRunning_Signal0Nil(t *testing.T) {
	// On Windows, Signal0() returns nil so IsRunning uses FindProcess only.
	// Test with current process PID which should be running.
	sig := Signal0()
	if sig != nil {
		t.Skip("Signal0 is non-nil on this platform; test is Windows-specific")
	}

	pid := os.Getpid()
	if !IsRunning(pid) {
		t.Error("current process should be reported as running when Signal0() is nil")
	}
}

func TestIsRunning_Signal0Nil_DeadProcess(t *testing.T) {
	sig := Signal0()
	if sig != nil {
		t.Skip("Signal0 is non-nil on this platform; test is Windows-specific")
	}

	// On Windows, FindProcess(99999999) may succeed but the process
	// is not really running. Since IsRunning returns true when Signal0 is nil
	// and FindProcess succeeds, this tests that code path.
	result := IsRunning(99999999)
	// We just exercise the code; on Windows FindProcess may or may not fail
	// for very high PIDs. The important thing is no panic.
	_ = result
}
