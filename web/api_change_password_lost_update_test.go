package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestChangePassword_NoLostUpdateVsConfigRaw pins the v0.7.58 gate:
// /api/auth/change-password must take configFileMu so a concurrent
// /api/config/raw PUT cannot silently overwrite the on-disk
// password_hash with the previous value AFTER the in-memory hash
// has already rotated. Without the lock the sequence is:
//
//   1. change-password rotates s.config.Load().Web.Auth.PasswordHash in memory
//   2. config-raw PUT (started concurrently) finishes its on-disk
//      write carrying the OLD hash that ensurePasswordHashUnchanged
//      compared against before step 1 landed
//   3. on-disk YAML now has the OLD hash, in-memory has the NEW hash
//   4. operator restarts — the new password is silently lost,
//      authentication reverts to the old password
//
// The pin runs change-password and config-raw PUT concurrently and
// verifies the on-disk password_hash matches the in-memory hash
// after both finish. The mutex makes the serialisation deterministic:
// whichever lands second sees the other's bytes on disk and either
// no-ops (config-raw enforces the password_hash is unchanged) or
// the password change is durable.
func TestChangePassword_NoLostUpdateVsConfigRaw(t *testing.T) {
	srv, _ := testAdminServerWithAuth(t)
	originalHash := srv.config.Load().Web.Auth.PasswordHash

	cfgPath := t.TempDir() + "/labyrinth.yaml"
	seed := "web:\n  auth:\n    username: admin\n    password_hash: " + originalHash + "\n"
	if err := os.WriteFile(cfgPath, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	srv.SetConfigPath(cfgPath)

	// Fire change-password and config-raw PUT concurrently. The
	// config-raw PUT carries the ORIGINAL password_hash (so it
	// passes ensurePasswordHashUnchanged at the time of read), while
	// change-password is mid-flight rotating to a NEW password.
	rawBody := `{"content":` + jsonEscape(seed+"# config-raw-edit\n") + `}`
	cpBody := `{"current_password":"s3cretPass!","new_password":"newS3cret!"}`

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", strings.NewReader(cpBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleChangePassword(w, req)
	}()

	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader(rawBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleConfigRaw(w, req)
	}()

	wg.Wait()

	// On-disk hash must equal in-memory hash. Without the mutex,
	// config-raw can finish AFTER change-password's disk write and
	// silently restore the old hash to disk — but the in-memory
	// hash has rotated, so they diverge.
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read final config: %v", err)
	}
	inMem := strings.TrimSpace(srv.config.Load().Web.Auth.PasswordHash)
	if !strings.Contains(string(got), "password_hash: "+inMem) {
		t.Errorf("on-disk password_hash does not match in-memory hash — change-password lost update vs config-raw PUT.\nin-memory: %q\nfile: %s", inMem, string(got))
	}
}
