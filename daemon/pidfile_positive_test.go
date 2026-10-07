package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestReadPIDRejectsNonpositiveValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.pid")
	failed := false
	for _, value := range []int{os.Getpid(), 0, -1} {
		if err := os.WriteFile(path, []byte(strconv.Itoa(value)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		pid, err := ReadPID(path)
		want := value > 0
		t.Logf("PID %d EXPECTED: accepted=%v ACTUAL: accepted=%v pid=%d", value, want, err == nil, pid)
		running, _, statusErr := StatusDaemon(path)
		t.Logf("EXPECTED: status error=%v ACTUAL: error=%v running=%v", !want, statusErr != nil, running)
		if (err == nil) != want || (statusErr == nil) != want {
			failed = true
		}
	}
	if failed {
		t.Fatal("PROBLEM CONFIRMED")
	}
	for _, value := range []string{"", "not-a-number", "1", "  1\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadPID(path)
		want := value == "1" || value == "  1\n"
		if (err == nil) != want {
			t.Fatalf("boundary %q: err=%v", value, err)
		}
	}
	if _, err := ReadPID(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing-file edge failed")
	}
	t.Log("FIX VERIFIED")
}
