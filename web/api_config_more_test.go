package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labyrinthdns/labyrinth/config"
)

func TestExtractPasswordHashFromYAML_Variants(t *testing.T) {
	v, ok := extractPasswordHashFromYAML("web:\n  auth:\n    password_hash: \"abc\"\n")
	if !ok || v != "abc" {
		t.Fatalf("quoted hash parse mismatch: ok=%v v=%q", ok, v)
	}

	v, ok = extractPasswordHashFromYAML("web:\n  auth:\n    password_hash: \n")
	if !ok || v != "" {
		t.Fatalf("empty hash parse mismatch: ok=%v v=%q", ok, v)
	}

	if _, ok := extractPasswordHashFromYAML("web:\n  auth:\n    username: admin\n"); ok {
		t.Fatalf("expected not found when password_hash is absent")
	}
}

func TestEnsurePasswordHashUnchanged_Branches(t *testing.T) {
	srv := testAdminServer(t)

	// current empty + incoming non-empty should fail
	if err := srv.ensurePasswordHashUnchanged("web:\n  auth:\n    password_hash: abc\n"); err == nil {
		t.Fatalf("expected error when setting password from config editor")
	}

	srvAuth, _ := testAdminServerWithAuth(t)
	current := srvAuth.config.Web.Auth.PasswordHash

	// current non-empty + missing password_hash should fail
	if err := srvAuth.ensurePasswordHashUnchanged("web:\n  auth:\n    username: admin\n"); err == nil {
		t.Fatalf("expected error when removing password_hash from config")
	}

	// current non-empty + empty password_hash should fail
	if err := srvAuth.ensurePasswordHashUnchanged("web:\n  auth:\n    password_hash:\n"); err == nil {
		t.Fatalf("expected error when clearing password_hash from config")
	}

	// unchanged should pass
	content := "web:\n  auth:\n    username: admin\n    password_hash: " + current + "\n"
	if err := srvAuth.ensurePasswordHashUnchanged(content); err != nil {
		t.Fatalf("expected unchanged hash to pass, got: %v", err)
	}
}

func TestHandleValidateConfig_MethodBodyAndValid(t *testing.T) {
	srv := testAdminServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/config/validate", nil)
	w := httptest.NewRecorder()
	srv.handleValidateConfig(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader("not-json"))
	w = httptest.NewRecorder()
	srv.handleValidateConfig(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d", w.Code)
	}

	validContent := "resolver:\n  max_depth: 31\n"
	payload, _ := json.Marshal(map[string]string{"content": validContent})
	req = httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader(string(payload)))
	w = httptest.NewRecorder()
	srv.handleValidateConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid config, got %d body=%s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["valid"] != true {
		t.Fatalf("expected valid=true, got %#v", body["valid"])
	}
}

func TestHandleConfigRaw_GET_ErrorBranches(t *testing.T) {
	srv := testAdminServer(t)

	// not found branch
	srv.SetConfigPath(filepath.Join(t.TempDir(), "missing.yaml"))
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	w := httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing config file, got %d", w.Code)
	}

	// generic read error branch (path is a directory)
	dirPath := t.TempDir()
	srv.SetConfigPath(dirPath)
	req = httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	w = httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for read error, got %d", w.Code)
	}
}

func TestHandleConfigRaw_PUT_MethodBodyAndParseErrors(t *testing.T) {
	srv := testAdminServer(t)

	// method not allowed branch
	req := httptest.NewRequest(http.MethodDelete, "/api/config/raw", nil)
	w := httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}

	// invalid body
	req = httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader("not-json"))
	w = httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d", w.Code)
	}

	// parse error
	badCfg := "resolver:\n  max_depth: 0\n"
	payload, _ := json.Marshal(map[string]string{"content": badCfg})
	req = httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader(string(payload)))
	w = httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for parse error, got %d", w.Code)
	}
}

func TestHandleConfigRaw_PUT_WriteAndNoOriginalPaths(t *testing.T) {
	srv := testAdminServer(t)
	validCfg := "resolver:\n  max_depth: 31\n"
	payload, _ := json.Marshal(map[string]string{"content": validCfg})

	// write failure branch via non-existent parent dir (CreateTemp error)
	badPath := filepath.Join(t.TempDir(), "missing-parent", "labyrinth.yaml")
	srv.SetConfigPath(badPath)
	req := httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader(string(payload)))
	w := httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for write failure, got %d body=%s", w.Code, w.Body.String())
	}

	// success path with no original config file (hadOriginal=false)
	dir := t.TempDir()
	newPath := filepath.Join(dir, "new-labyrinth.yaml")
	srv.SetConfigPath(newPath)
	req = httptest.NewRequest(http.MethodPut, "/api/config/raw", strings.NewReader(string(payload)))
	w = httptest.NewRecorder()
	srv.handleConfigRaw(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for save without original file, got %d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("expected new config file to be created: %v", err)
	}
}

func TestConfigFilePath_DefaultAndSet(t *testing.T) {
	srv := testAdminServer(t)
	srv.configPath = "   "
	if got := srv.configFilePath(); got != "labyrinth.yaml" {
		t.Fatalf("default config path mismatch: %q", got)
	}
	srv.SetConfigPath("  custom.yaml  ")
	if got := srv.configFilePath(); got != "custom.yaml" {
		t.Fatalf("trimmed config path mismatch: %q", got)
	}
}

func TestWriteFileAtomically_CreateTempError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.yaml")
	if err := writeFileAtomically(path, []byte("x")); err == nil {
		t.Fatalf("expected create temp failure for missing directory")
	}
}

type stubAtomicTempFile struct {
	path     string
	writeErr error
	syncErr  error
	closeErr error
}

func (s *stubAtomicTempFile) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}

func (s *stubAtomicTempFile) Sync() error  { return s.syncErr }
func (s *stubAtomicTempFile) Close() error { return s.closeErr }
func (s *stubAtomicTempFile) Name() string { return s.path }

func withConfigFileHooksReset(t *testing.T) {
	t.Helper()
	prevCreate := configCreateTemp
	prevRemove := configRemove
	prevStat := configStat
	prevRename := configRename
	t.Cleanup(func() {
		configCreateTemp = prevCreate
		configRemove = prevRemove
		configStat = prevStat
		configRename = prevRename
	})
}

func TestWriteFileAtomically_WriteSyncCloseErrors(t *testing.T) {
	withConfigFileHooksReset(t)

	basePath := filepath.Join(t.TempDir(), "cfg.yaml")

	configCreateTemp = func(dir, pattern string) (atomicTempFile, error) {
		return &stubAtomicTempFile{
			path:     filepath.Join(dir, "tmp-write.err"),
			writeErr: errors.New("write failed"),
		}, nil
	}
	if err := writeFileAtomically(basePath, []byte("x")); err == nil {
		t.Fatalf("expected write error")
	}

	configCreateTemp = func(dir, pattern string) (atomicTempFile, error) {
		return &stubAtomicTempFile{
			path:    filepath.Join(dir, "tmp-sync.err"),
			syncErr: errors.New("sync failed"),
		}, nil
	}
	if err := writeFileAtomically(basePath, []byte("x")); err == nil {
		t.Fatalf("expected sync error")
	}

	configCreateTemp = func(dir, pattern string) (atomicTempFile, error) {
		return &stubAtomicTempFile{
			path:     filepath.Join(dir, "tmp-close.err"),
			closeErr: errors.New("close failed"),
		}, nil
	}
	if err := writeFileAtomically(basePath, []byte("x")); err == nil {
		t.Fatalf("expected close error")
	}
}

func TestWriteFileAtomically_BackupAndReplaceFailures(t *testing.T) {
	withConfigFileHooksReset(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "labyrinth.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	realCreate := configCreateTemp

	// Backup failure branch.
	configCreateTemp = realCreate
	configRename = func(oldpath, newpath string) error {
		if oldpath == path {
			return errors.New("backup rename failed")
		}
		return os.Rename(oldpath, newpath)
	}
	if err := writeFileAtomically(path, []byte("new")); err == nil {
		t.Fatalf("expected backup rename error")
	}

	// Replace failure + rollback branch.
	configCreateTemp = realCreate
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("rewrite old file: %v", err)
	}
	var renameCalls int
	configRename = func(oldpath, newpath string) error {
		renameCalls++
		switch renameCalls {
		case 1:
			return os.Rename(oldpath, newpath) // path -> backup
		case 2:
			return errors.New("replace failed") // tmp -> path
		case 3:
			return os.Rename(oldpath, newpath) // backup -> path rollback
		default:
			return os.Rename(oldpath, newpath)
		}
	}
	if err := writeFileAtomically(path, []byte("new")); err == nil {
		t.Fatalf("expected replace error")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(raw) != "old" {
		t.Fatalf("expected rollback to restore old content, got %q", string(raw))
	}
}

func TestHandleGetConfig_RedactsSensitiveValues(t *testing.T) {
	srv := testAdminServer(t)
	srv.config.Web.Auth.PasswordHash = "secret-hash"
	srv.config.Blocklist.Lists = []config.BlocklistEntry{
		{URL: "https://example.com/list.txt", Format: "hosts"},
	}
	srv.config.Cluster.Peers = []config.ClusterPeerConfig{
		{
			Name:       "peer-a",
			Enabled:    true,
			APIBase:    "https://peer-a.local",
			APIToken:   "token-a",
			SyncFields: []string{"cache"},
		},
		{
			Name:       "peer-b",
			Enabled:    true,
			APIBase:    "https://peer-b.local",
			APIToken:   "",
			SyncFields: []string{"blocklist"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w := httptest.NewRecorder()
	srv.handleGetConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := decodeJSON(t, w)
	webObj := body["web"].(map[string]interface{})
	authObj := webObj["auth"].(map[string]interface{})
	if authObj["password_hash"] != "***REDACTED***" {
		t.Fatalf("expected redacted password hash, got %#v", authObj["password_hash"])
	}

	clusterObj := body["cluster"].(map[string]interface{})
	peers, ok := clusterObj["peers"].([]interface{})
	if !ok || len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %#v", clusterObj["peers"])
	}

	peerA := peers[0].(map[string]interface{})
	if peerA["api_token"] != "***REDACTED***" {
		t.Fatalf("expected peer api token redaction, got %#v", peerA["api_token"])
	}
	if peerA["api_token_set"] != true {
		t.Fatalf("expected api_token_set=true for peerA, got %#v", peerA["api_token_set"])
	}

	peerB := peers[1].(map[string]interface{})
	if peerB["api_token_set"] != false {
		t.Fatalf("expected api_token_set=false for peerB, got %#v", peerB["api_token_set"])
	}

	blocklistObj := body["blocklist"].(map[string]interface{})
	if blocklistObj["list_count"] != float64(1) {
		t.Fatalf("expected list_count=1, got %#v", blocklistObj["list_count"])
	}
}
