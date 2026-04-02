package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// jwtHeader is the fixed JWT header for HS256.
var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type jwtPayload struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// generateJWT creates a JWT token with a 24-hour expiry using HMAC-SHA256.
func generateJWT(username string, secret []byte) (string, error) {
	now := time.Now().Unix()
	payload := jwtPayload{
		Sub: username,
		Iat: now,
		Exp: now + 86400, // 24 hours
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := jwtHeaderB64 + "." + payloadB64

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// validateJWT verifies a JWT token and returns the username (sub) claim.
func validateJWT(tokenStr string, secret []byte) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]

	// Verify signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("invalid signature encoding")
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return "", errors.New("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid payload encoding")
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > payload.Exp {
		return "", errors.New("token expired")
	}

	if payload.Sub == "" {
		return "", errors.New("missing subject claim")
	}

	return payload.Sub, nil
}

// MinPasswordLength is the minimum required password length.
const MinPasswordLength = 8

// ValidatePassword checks if a password meets minimum requirements.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password too short: minimum %d characters required (got %d)", MinPasswordLength, len(password))
	}
	return nil
}

// HashPassword hashes a plaintext password using bcrypt.
// Returns an error if the password is shorter than MinPasswordLength.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// checkPassword verifies a plaintext password against a bcrypt hash.
func checkPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// handleLogin handles POST /api/auth/login — validates credentials and returns a JWT.
func (s *AdminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	cfgUser := s.config.Web.Auth.Username
	cfgHash := s.config.Web.Auth.PasswordHash

	if cfgUser == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "authentication not configured"})
		return
	}

	if req.Username != cfgUser || !checkPassword(req.Password, cfgHash) {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	token, err := generateJWT(req.Username, s.jwtSecret)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"token":    token,
		"username": req.Username,
	})
}

// handleMe handles GET /api/auth/me — returns the current user from JWT context.
func (s *AdminServer) handleMe(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(ctxKeyUser).(string)
	if !ok || username == "" {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"username": username,
	})
}

// handleChangePassword handles POST /api/auth/change-password — changes the admin password.
// Requires current password verification, validates new password, updates YAML config on disk.
func (s *AdminServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Verify current password
	if !checkPassword(req.CurrentPassword, s.config.Web.Auth.PasswordHash) {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	// Validate new password
	if err := ValidatePassword(req.NewPassword); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Hash new password
	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}

	// Update config in memory
	s.config.Web.Auth.PasswordHash = newHash

	// Update YAML config file on disk
	if err := updatePasswordInConfig(newHash); err != nil {
		s.logger.Error("failed to update password in config file", "error", err)
		// Password is still updated in memory for this session
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":  "partial",
			"message": "Password updated in memory but config file could not be saved: " + err.Error(),
		})
		return
	}

	s.logger.Info("admin password changed via web UI")
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// updatePasswordInConfig reads the YAML config, updates the password_hash line, and writes it back.
func updatePasswordInConfig(newHash string) error {
	paths := []string{"labyrinth.yaml", "/etc/labyrinth/labyrinth.yaml"}
	var configPath string
	var data []byte

	for _, p := range paths {
		d, err := os.ReadFile(p)
		if err == nil {
			configPath = p
			data = d
			break
		}
	}
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "password_hash:") {
			// Preserve indentation
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "password_hash: " + newHash
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("password_hash field not found in config file")
	}

	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
}
