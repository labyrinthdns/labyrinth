//go:build linux

package daemon

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// startNamedLabyrinth runs a copy of sleep named "labyrinth", so the
// /proc/<pid>/comm ownership check sees a live labyrinth instance.
func startNamedLabyrinth(t *testing.T) *exec.Cmd {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	bin := filepath.Join(t.TempDir(), "labyrinth")
	src, err := os.Open(sleep)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	dst.Close()
	cmd := exec.Command(bin, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// TestPIDFileOwnership pins that a second instance can neither take over nor
// delete the PID file of a running labyrinth. Before, a daemon started by
// mistake overwrote the file, failed to bind, and removed it on exit, leaving
// the running daemon invisible to `labyrinth daemon stop|status`.
func TestPIDFileOwnership(t *testing.T) {
	running := startNamedLabyrinth(t)
	pidFile := filepath.Join(t.TempDir(), "labyrinth.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(running.Process.Pid)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := WritePID(pidFile); err == nil {
		t.Error("WritePID took over the PID file of a running labyrinth")
	}
	if err := RemovePID(pidFile); err == nil {
		t.Error("RemovePID deleted the PID file of a running labyrinth")
	}
	if got, err := ReadPID(pidFile); err != nil || got != running.Process.Pid {
		t.Fatalf("running instance's PID file changed: pid=%d err=%v", got, err)
	}

	// Once that instance is gone the file is stale and is taken over.
	running.Process.Kill()
	running.Wait()
	if err := WritePID(pidFile); err != nil {
		t.Fatalf("stale PID file not taken over: %v", err)
	}
	if err := RemovePID(pidFile); err != nil {
		t.Fatalf("own PID file not removed: %v", err)
	}
}
