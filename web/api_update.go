package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UpdateInfo holds information about available updates.
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
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

// handleCheckUpdate handles GET /api/system/update/check — checks for available updates.
func (s *AdminServer) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	info, err := checkForUpdate()
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("update check failed: %v", err)})
		return
	}

	jsonResponse(w, http.StatusOK, info)
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

	// Find the download URL for the correct asset
	assetName := info.AssetName
	downloadURL, err := findAssetURL(assetName)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("failed to find asset: %v", err)})
		return
	}

	// Download the binary
	resp, err := http.Get(downloadURL)
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
	exePath, err := os.Executable()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to get executable path: %v", err)})
		return
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to resolve executable path: %v", err)})
		return
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(exePath), "labyrinth-update-*")
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to create temp file: %v", err)})
		return
	}
	tmpPath := tmpFile.Name()

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to write update: %v", err)})
		return
	}

	// Make executable on unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to set permissions: %v", err)})
			return
		}
	}

	// Replace current executable
	// On Windows, rename running exe to .old first since overwrite is blocked
	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		os.Remove(oldPath) // clean up previous .old if exists
		if err := os.Rename(exePath, oldPath); err != nil {
			os.Remove(tmpPath)
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to move current executable: %v", err)})
			return
		}
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
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
		time.Sleep(500 * time.Millisecond)
		if err := restartSelf(); err != nil {
			s.logger.Error("restart failed", "error", err)
		}
	}()
}

// checkForUpdate fetches the latest release from GitHub and compares with the current version.
func checkForUpdate() (*UpdateInfo, error) {
	resp, err := http.Get(githubReleasesURL)
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

	info := &UpdateInfo{
		CurrentVersion:  Version,
		LatestVersion:   release.TagName,
		UpdateAvailable: updateAvailable,
		ReleaseURL:      release.HTMLURL,
		ReleaseNotes:    release.Body,
		AssetName:       assetName,
	}

	return info, nil
}

// findAssetURL fetches the latest release and finds the download URL for the given asset name.
func findAssetURL(assetName string) (string, error) {
	resp, err := http.Get(githubReleasesURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse release info: %w", err)
	}

	for _, asset := range release.Assets {
		if asset.Name == assetName {
			return asset.BrowserDownloadURL, nil
		}
	}

	return "", fmt.Errorf("asset %q not found in release", assetName)
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
