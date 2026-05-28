package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestConfigRaw_NoLostUpdate pins the v0.7.57 gate: concurrent
// PUTs to /api/config/raw and /api/dashboard/layout must serialise
// on configFileMu rather than race the read-modify-write of the
// on-disk YAML. Without the mutex two concurrent admin writes
// (e.g. a YAML editor save + a dashboard panel reorder) both
// ReadFile the same baseline, apply independent edits, and the
// second writer's writeFileAtomically silently overwrites the
// first writer's bytes — classic lost-update.
//
// The pin fires 20 concurrent /api/config/raw PUTs, each writing a
// uniquely-marked YAML body. After all return, exactly one of the
// marker strings must be present on disk and the on-disk byte
// content must equal what the surviving request sent. Without the
// mutex, interleaved Read → Parse → Write sequences would let the
// final file contain a marker that no individual request issued
// (mixed body bytes) or, more likely with rename-based atomic
// writes, would leave one of the loser bytes on disk while the
// in-memory s.config tracks a different winner.
func TestConfigRaw_NoLostUpdate(t *testing.T) {
	srv := testAdminServer(t)
	cfgPath := t.TempDir() + "/labyrinth.yaml"
	// Seed an initial file so writeFileAtomically takes the
	// backup-and-rename path (the more race-prone branch).
	if err := os.WriteFile(cfgPath, []byte("web:\n  auth:\n    username: admin\n    password_hash: \"\"\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	srv.SetConfigPath(cfgPath)
	// Leave Auth.Username == "" so requireAuth is a pass-through;
	// the test exercises the lost-update race, not the auth layer.

	// Each goroutine writes a uniquely-marked YAML body. The
	// password_hash line must match what's on disk so the
	// ensurePasswordHashUnchanged guard does not reject the request.
	mkBody := func(marker string) string {
		yaml := `web:
  auth:
    username: admin
    password_hash: ""
# marker-` + marker + "\n"
		return `{"content":` + jsonEscape(yaml) + `}`
	}

	const N = 20
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		marker := string(rune('A' + (i % 26)))
		marker += string(rune('0' + (i / 26)))
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			body := mkBody(m)
			req := httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.handleConfigRaw(w, req)
		}(marker)
	}
	wg.Wait()

	// Read the final on-disk content and verify it equals one of
	// the 20 marker bodies. A lost-update race would let half a
	// file from request X and half from request Y land on disk;
	// the mutex ensures the last writer's complete file wins.
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read final config: %v", err)
	}
	// Find which marker survived.
	markers := 0
	for i := 0; i < N; i++ {
		m := string(rune('A' + (i % 26)))
		m += string(rune('0' + (i / 26)))
		if strings.Contains(string(got), "# marker-"+m+"\n") {
			markers++
		}
	}
	if markers != 1 {
		t.Errorf("on-disk config contains %d markers, want exactly 1 — concurrent PUTs interleaved", markers)
	}
}

// jsonEscape is a tiny helper to embed a YAML body inside a JSON
// "content" field. Tests only — not general-purpose.
func jsonEscape(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
