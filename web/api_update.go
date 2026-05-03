package web

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UpdateInfo holds information about available updates.
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReadOnly        bool   `json:"read_only"`
	ReadOnlyHint    string `json:"read_only_hint,omitempty"`
	ReleaseURL      string `json:"release_url,omitempty"`
	ReleaseNotes    string `json:"release_notes,omitempty"`
	AssetName       string `json:"asset_name,omitempty"`
}

// githubRelease is the JSON structure returned by the GitHub releases API.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Body    string        `json:"body"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

const githubReleasesURL = "https://api.github.com/repos/labyrinthdns/labyrinth/releases/latest"

var (
	updateInitialDelay  = 30 * time.Second
	updateTickerFactory = func(d time.Duration) *time.Ticker {
		return time.NewTicker(d)
	}
	// H-11: dedicated client with a hard timeout so a hung GitHub or
	// asset CDN cannot pin a goroutine + temp file forever. Replaces the
	// previous `http.Get` (=> http.DefaultClient => no timeout).
	updateHTTPClient = &http.Client{Timeout: 60 * time.Second}
	updateHTTPGet    = func(url string) (*http.Response, error) { return updateHTTPClient.Get(url) }

	updateExecutable   = os.Executable
	updateEvalSymlinks = filepath.EvalSymlinks
	updateCreateTemp   = os.CreateTemp
	updateChmod        = os.Chmod
	updateRename       = os.Rename
	updateRemove       = os.Remove
	updateSleep        = time.Sleep
	updateRestartSelf  = restartSelf
)

// maxUpdateBodyBytes caps how large a downloaded binary may be. 200 MiB is
// well above any realistic Labyrinth release size and well below
// disk-pressure DoS territory.
const maxUpdateBodyBytes = 200 << 20

func isReadOnlyFS(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EROFS) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "read-only file system")
}

func updateReadOnlyHint(exePath string) string {
	return fmt.Sprintf("self-update is disabled because the install path is read-only (%s); use install/update script on the host or redeploy your container image", filepath.Dir(exePath))
}

// handleCheckUpdate handles GET /api/system/update/check — returns cached update info or fetches fresh.
func (s *AdminServer) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	force := false
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("force"))) {
	case "1", "true", "yes", "on":
		force = true
	}

	// Return cached result if fresh enough
	s.updateMu.RLock()
	cached := s.updateCache
	checkedAt := s.updateCheckedAt
	s.updateMu.RUnlock()

	if !force && cached != nil && time.Since(checkedAt) < s.config.Web.UpdateCheckInterval {
		jsonResponse(w, http.StatusOK, cached)
		return
	}

	// Fetch fresh
	info, err := checkForUpdate()
	if err != nil {
		// Return stale cache if available for non-forced checks.
		if cached != nil && !force {
			jsonResponse(w, http.StatusOK, cached)
			return
		}
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("update check failed: %v", err)})
		return
	}

	s.updateMu.Lock()
	s.updateCache = info
	s.updateCheckedAt = time.Now()
	s.updateMu.Unlock()

	jsonResponse(w, http.StatusOK, info)
}

// StartUpdateChecker runs a background goroutine that periodically checks for updates.
func (s *AdminServer) StartUpdateChecker(ctx context.Context) {
	if !s.config.Web.AutoUpdate {
		return
	}

	interval := s.config.Web.UpdateCheckInterval
	if interval < time.Minute {
		interval = 24 * time.Hour
	}

	// Initial check after 30 seconds (let server finish starting)
	select {
	case <-ctx.Done():
		return
	case <-time.After(updateInitialDelay):
	}

	info, err := checkForUpdate()
	if err == nil {
		s.updateMu.Lock()
		s.updateCache = info
		s.updateCheckedAt = time.Now()
		s.updateMu.Unlock()
		if info.UpdateAvailable {
			s.logger.Info("update available", "current", info.CurrentVersion, "latest", info.LatestVersion)
		}
	}

	ticker := updateTickerFactory(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := checkForUpdate()
			if err != nil {
				s.logger.Debug("update check failed", "error", err)
				continue
			}
			s.updateMu.Lock()
			s.updateCache = info
			s.updateCheckedAt = time.Now()
			s.updateMu.Unlock()
			if info.UpdateAvailable {
				s.logger.Info("update available", "current", info.CurrentVersion, "latest", info.LatestVersion)
			}
		}
	}
}

// handleApplyUpdate handles POST /api/system/update/apply — downloads and applies an update.
func (s *AdminServer) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	info, err := checkForUpdate()
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("update check failed: %v", err)})
		return
	}

	if !info.UpdateAvailable {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "already up to date"})
		return
	}

	// Find the download URL for the correct asset.
	// C-2 (interim): also resolve the URL of the release-bundled
	// checksums.txt so we can verify integrity before swapping the
	// running binary. release.yml already produces this file; the audit
	// findings C-2/C-3 flagged that nothing on the client side consumed
	// it. The follow-up is cosign/minisign release signatures (the
	// checksum still trusts the GitHub asset host); this commit adds
	// the missing verification step.
	assetName := info.AssetName
	downloadURL, checksumsURL, err := findAssetURLWithChecksums(assetName)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("failed to find asset: %v", err)})
		return
	}

	// Pre-fetch the expected SHA-256 BEFORE the binary download so a
	// missing checksums.txt aborts the flow without touching disk.
	expectedSHA, shaErr := fetchExpectedSHA256(checksumsURL, assetName)
	if shaErr != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("checksum lookup failed: %v", shaErr)})
		return
	}

	// Download the binary
	resp, err := updateHTTPGet(downloadURL)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("download failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("download returned status %d", resp.StatusCode)})
		return
	}

	// Write to temp file
	exePath, err := updateExecutable()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to get executable path: %v", err)})
		return
	}
	exePath, err = updateEvalSymlinks(exePath)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to resolve executable path: %v", err)})
		return
	}

	tmpFile, err := updateCreateTemp(filepath.Dir(exePath), "labyrinth-update-*")
	if err != nil {
		if isReadOnlyFS(err) {
			jsonResponse(w, http.StatusConflict, map[string]string{
				"error": updateReadOnlyHint(exePath),
			})
			return
		}
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to create temp file: %v", err)})
		return
	}
	tmpPath := tmpFile.Name()

	// H-11: cap the download to avoid disk-pressure DoS via a hostile redirect.
	// C-2 (interim): hash while we copy so we don't have to re-read the file.
	hasher := sha256.New()
	tee := io.TeeReader(io.LimitReader(resp.Body, maxUpdateBodyBytes), hasher)
	_, err = io.Copy(tmpFile, tee)
	tmpFile.Close()
	if err != nil {
		updateRemove(tmpPath)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to write update: %v", err)})
		return
	}

	// C-2 (interim): refuse to install if the SHA-256 does not match the
	// release-bundled checksums.txt entry. Constant-time compare to be
	// safe even though the hashes are not secret.
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !secureCompareHex(expectedSHA, actualSHA) {
		updateRemove(tmpPath)
		jsonResponse(w, http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("checksum mismatch: expected %s, got %s — refusing to install unverified binary", expectedSHA, actualSHA),
		})
		return
	}

	// Make executable on unix
	if runtime.GOOS != "windows" {
		if err := updateChmod(tmpPath, 0755); err != nil {
			updateRemove(tmpPath)
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to set permissions: %v", err)})
			return
		}
	}

	// Replace current executable
	// On Windows, rename running exe to .old first since overwrite is blocked
	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		updateRemove(oldPath) // clean up previous .old if exists
		if err := updateRename(exePath, oldPath); err != nil {
			updateRemove(tmpPath)
			if isReadOnlyFS(err) {
				jsonResponse(w, http.StatusConflict, map[string]string{
					"error": updateReadOnlyHint(exePath),
				})
				return
			}
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to move current executable: %v", err)})
			return
		}
	}

	if err := updateRename(tmpPath, exePath); err != nil {
		updateRemove(tmpPath)
		if isReadOnlyFS(err) {
			jsonResponse(w, http.StatusConflict, map[string]string{
				"error": updateReadOnlyHint(exePath),
			})
			return
		}
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to replace executable: %v", err)})
		return
	}

	s.logger.Info("update applied", "from", Version, "to", info.LatestVersion)

	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "updated",
		"version": info.LatestVersion,
		"message": "restarting...",
	})

	// Flush the response before restarting
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Delay restart slightly to ensure HTTP response is sent
	go func() {
		updateSleep(500 * time.Millisecond)
		if err := updateRestartSelf(); err != nil {
			s.logger.Error("restart failed", "error", err)
		}
	}()
}

// checkForUpdate fetches the latest release from GitHub and compares with the current version.
func checkForUpdate() (*UpdateInfo, error) {
	resp, err := updateHTTPGet(githubReleasesURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(Version, "v")

	assetName := fmt.Sprintf("labyrinth-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	// dev builds always show update available if there's a release
	updateAvailable := false
	if currentVersion == "dev" || currentVersion == "" {
		updateAvailable = release.TagName != ""
	} else {
		updateAvailable = compareSemver(currentVersion, latestVersion) < 0
	}

	// Probe whether the install directory is writable.
	readOnly := false
	readOnlyHint := ""
	if exePath, err := updateExecutable(); err == nil {
		if resolved, err := updateEvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		dir := filepath.Dir(exePath)
		tmp, err := updateCreateTemp(dir, ".labyrinth-probe-*")
		if err != nil {
			if isReadOnlyFS(err) {
				readOnly = true
				readOnlyHint = updateReadOnlyHint(exePath)
			}
		} else {
			tmp.Close()
			updateRemove(tmp.Name())
		}
	}

	info := &UpdateInfo{
		CurrentVersion:  Version,
		LatestVersion:   release.TagName,
		UpdateAvailable: updateAvailable,
		ReadOnly:        readOnly,
		ReadOnlyHint:    readOnlyHint,
		ReleaseURL:      release.HTMLURL,
		ReleaseNotes:    release.Body,
		AssetName:       assetName,
	}

	return info, nil
}

// findAssetURL fetches the latest release and finds the download URL for the given asset name.
func findAssetURL(assetName string) (string, error) {
	url, _, err := findAssetURLWithChecksums(assetName)
	return url, err
}

// findAssetURLWithChecksums returns both the asset download URL and the
// URL of the release's checksums.txt sidecar. Both come from the same
// GitHub release JSON to ensure they refer to the same artifacts. C-2.
func findAssetURLWithChecksums(assetName string) (string, string, error) {
	resp, err := updateHTTPGet(githubReleasesURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("failed to parse release info: %w", err)
	}

	var assetURL, checksumsURL string
	for _, asset := range release.Assets {
		switch {
		case asset.Name == assetName:
			assetURL = asset.BrowserDownloadURL
		case strings.EqualFold(asset.Name, "checksums.txt"):
			checksumsURL = asset.BrowserDownloadURL
		}
	}
	if assetURL == "" {
		return "", "", fmt.Errorf("asset %q not found in release", assetName)
	}
	if checksumsURL == "" {
		return "", "", fmt.Errorf("checksums.txt not found in release — refusing unverified install")
	}
	return assetURL, checksumsURL, nil
}

// fetchExpectedSHA256 downloads checksums.txt and returns the SHA-256
// hex digest line corresponding to assetName. Returns an error if the
// file cannot be fetched, parsed, or the asset entry is missing — in any
// of those cases the update flow MUST be aborted (fail-closed).
func fetchExpectedSHA256(checksumsURL, assetName string) (string, error) {
	resp, err := updateHTTPGet(checksumsURL)
	if err != nil {
		return "", fmt.Errorf("fetch checksums.txt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums.txt returned status %d", resp.StatusCode)
	}
	// 1 MiB cap is plenty for a checksums.txt with hundreds of assets.
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "<hex>  <name>" or "<hex> *<name>" (sha256sum binary mode).
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == assetName {
			sha := strings.ToLower(fields[0])
			if len(sha) != 64 {
				return "", fmt.Errorf("malformed sha256 entry for %q", assetName)
			}
			if _, decodeErr := hex.DecodeString(sha); decodeErr != nil {
				return "", fmt.Errorf("malformed sha256 entry for %q: %w", assetName, decodeErr)
			}
			return sha, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksums.txt: %w", err)
	}
	return "", fmt.Errorf("no checksum entry for %q in checksums.txt", assetName)
}

// secureCompareHex constant-time compares two hex strings (lowercased).
func secureCompareHex(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// compareSemver compares two semantic version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareSemver(a, b string) int {
	aParts := parseSemverParts(a)
	bParts := parseSemverParts(b)

	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

// parseSemverParts parses a semver string into [major, minor, patch].
func parseSemverParts(v string) [3]int {
	var parts [3]int
	segments := strings.SplitN(v, ".", 3)
	for i, seg := range segments {
		if i >= 3 {
			break
		}
		// Strip any pre-release suffix (e.g., "1-rc1" -> "1")
		if idx := strings.IndexAny(seg, "-+"); idx >= 0 {
			seg = seg[:idx]
		}
		n, err := strconv.Atoi(seg)
		if err == nil {
			parts[i] = n
		}
	}
	return parts
}
