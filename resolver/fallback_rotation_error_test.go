package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFallbackLog_RotationFailurePreservesSizeBound(t *testing.T) {
	rec := fallbackLogRecord{Time: "2026-10-04T00:00:00Z", Name: "example.com", Reason: "SERVFAIL"}
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, blocked := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "fallback.jsonl")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(fallbackLogMaxBytes); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if blocked {
			if err := os.Mkdir(path+".1", 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path+".1", "owner"), []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		log := newFallbackFileLog(path)
		t.Cleanup(func() {
			if log.f != nil {
				_ = log.f.Close()
			}
		})
		for range 3 {
			log.write(rec)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !blocked {
			archive, err := os.Stat(path + ".1")
			if err != nil || archive.Size() != fallbackLogMaxBytes || st.Size() != int64(3*(len(line)+1)) {
				t.Fatalf("unaffected rotation control failed: archive=%v current=%v err=%v", archive, st, err)
			}
			continue
		}
		t.Logf("EXPECTED: blocked rotation size=%d ACTUAL: size=%d", fallbackLogMaxBytes, st.Size())
		if st.Size() != fallbackLogMaxBytes {
			t.Fatal("PROBLEM CONFIRMED")
		}
		marker := filepath.Join(path+".1", "owner")
		data, err := os.ReadFile(marker)
		if err != nil || string(data) != "preserve" {
			t.Fatalf("archive obstruction changed: %q %v", data, err)
		}
		// Removing the injected fault permits a subsequent write to rotate normally.
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path + ".1"); err != nil {
			t.Fatal(err)
		}
		log.write(rec)
		archive, err := os.Stat(path + ".1")
		if err != nil || archive.Size() != fallbackLogMaxBytes {
			t.Fatalf("recovery archive=%v err=%v", archive, err)
		}
		st, err = os.Stat(path)
		if err != nil || st.Size() != int64(len(line)+1) {
			t.Fatalf("recovery active=%v err=%v", st, err)
		}
	}
	// Exactly reaching the size bound does not rotate prematurely.
	dir := t.TempDir()
	path := filepath.Join(dir, "boundary.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(fallbackLogMaxBytes - int64(len(line)+1)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	log := newFallbackFileLog(path)
	t.Cleanup(func() {
		if log.f != nil {
			_ = log.f.Close()
		}
	})
	log.write(rec)
	st, err := os.Stat(path)
	if err != nil || st.Size() != fallbackLogMaxBytes {
		t.Fatalf("exact boundary: size=%v err=%v", st, err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("premature rotation: %v", err)
	}
	log.write(rec)
	st, err = os.Stat(path)
	if err != nil || st.Size() != int64(len(line)+1) {
		t.Fatalf("boundary rotation: size=%v err=%v", st, err)
	}
	// A pre-existing archive is replaced on the next successful rotation.
	if err := os.Truncate(path, fallbackLogMaxBytes); err != nil {
		t.Fatal(err)
	}
	log.write(rec)
	st, err = os.Stat(path + ".1")
	if err != nil || st.Size() != fallbackLogMaxBytes {
		t.Fatalf("archive replacement: size=%v err=%v", st, err)
	}
	var disabled *fallbackFileLog
	disabled.write(rec)
	newFallbackFileLog("").write(rec)
	t.Log("FIX VERIFIED")
}
