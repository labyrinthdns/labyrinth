package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// jwtHeader is the fixed JWT header for HS256.
var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// dummyBcryptHash is a precomputed bcrypt hash used for constant-time
// comparison when the supplied username does not match the configured one.
// It is generated once at package init so unknown-user login attempts run
// the same bcrypt work as known-user attempts (defeats username enumeration
// via response-time side channel).
var dummyBcryptHash []byte

func init() {
	// Cost 10 matches bcrypt.DefaultCost; a constant placeholder password is
	// fine because the resulting hash is only used as a timing absorber.
	h, err := bcrypt.GenerateFromPassword([]byte("labyrinth-timing-absorber"), bcrypt.DefaultCost)
	if err != nil {
		// Generating a bcrypt hash with a constant input cannot realistically
		// fail; if it does the security posture of the binary is degraded so
		// fail loudly rather than ship a vulnerable login path.
		panic("web: failed to precompute dummy bcrypt hash: " + err.Error())
	}
	dummyBcryptHash = h
}

type jwtPayload struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti,omitempty"`
}

// jwtHeader is the parsed shape of a JWT header. Only HS256 is accepted.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// generateJWT creates a JWT token with a 24-hour expiry using HMAC-SHA256.
// It generates a unique jti for each token to support revocation.
func generateJWT(username string, secret []byte) (string, error) {
	now := time.Now().Unix()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	payload := jwtPayload{
		Sub: username,
		Iat: now,
		Exp: now + 86400, // 24 hours
		Jti: base64.RawURLEncoding.EncodeToString(jtiBytes),
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
// The header is parsed and the algorithm must be exactly "HS256"; "none"
// and any other algorithm (including unknown asymmetric ones) are rejected.
// It also checks that the token's jti is not in the revokedTokens blocklist.
func validateJWT(tokenStr string, secret []byte, revokedTokens *sync.Map) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	// Pin the alg header before doing any cryptographic work. This blocks
	// the classic alg=none / alg-confusion family of attacks.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid header encoding")
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return "", errors.New("invalid header JSON")
	}
	if hdr.Alg != "HS256" {
		return "", errors.New("unsupported algorithm")
	}
	if hdr.Typ != "" && hdr.Typ != "JWT" {
		return "", errors.New("unsupported token type")
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

	// Reject tokens without a jti — prevents empty-string bypass of revocation.
	if payload.Jti == "" {
		return "", errors.New("missing jti claim")
	}

	// Check revocation blocklist (tokens issued before a password change)
	if revokedTokens != nil {
		if _, revoked := revokedTokens.Load(payload.Jti); revoked {
			return "", errors.New("token has been revoked")
		}
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

	clientIP := loginClientIP(r)
	if s.loginLimiter != nil {
		if ok, retryAfter := s.loginLimiter.allow(clientIP); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			jsonResponse(w, http.StatusTooManyRequests, map[string]string{
				"error": "too many failed login attempts; try again later",
			})
			return
		}
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

	// Constant-time username comparison and unconditional bcrypt verification
	// to prevent username enumeration via response-time side channel. When the
	// supplied username is wrong we still run bcrypt against a precomputed
	// dummy hash so the timing matches a known-user-wrong-password path.
	userMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfgUser)) == 1
	hashToCheck := cfgHash
	if !userMatch || hashToCheck == "" {
		hashToCheck = string(dummyBcryptHash)
	}
	passMatch := checkPassword(req.Password, hashToCheck)

	if !userMatch || !passMatch {
		if s.loginLimiter != nil {
			s.loginLimiter.recordFailure(clientIP)
		}
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	token, err := generateJWT(req.Username, s.jwtSecret)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	if s.loginLimiter != nil {
		s.loginLimiter.recordSuccess(clientIP)
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

	// Rotate JWT secret to invalidate all outstanding tokens (M-1 fix).
	// Clear revocation blocklist — the new secret supersedes it.
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		// crypto/rand failure is fatal — abort the entire password change
		// rather than leave an inconsistent state where the password is
		// rotated but existing JWTs remain valid.
		s.logger.Error("failed to rotate JWT secret during password change", "error", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate session secret; password not changed"})
		return
	}
	s.jwtSecret = newSecret
	s.revokedTokens.Range(func(k, _ any) bool {
		s.revokedTokens.Delete(k)
		return true
	})

	// Update config in memory — only after secret rotation succeeded.
	s.config.Web.Auth.PasswordHash = newHash

	// Update YAML config file on disk
	if err := updatePasswordInConfigAtPath(s.configFilePath(), newHash); err != nil {
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

// updatePasswordInConfig reads the default YAML config locations, updates the
// password_hash line, and writes it back.
func updatePasswordInConfig(newHash string) error {
	paths := []string{"labyrinth.yaml", "/etc/labyrinth/labyrinth.yaml"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return updatePasswordInConfigAtPath(p, newHash)
		}
	}
	return fmt.Errorf("config file not found")
}

// updatePasswordInConfigAtPath reads the YAML config at path, updates the
// password_hash line, and writes it back atomically.
func updatePasswordInConfigAtPath(configPath, newHash string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file not found")
		}
		return fmt.Errorf("read config file: %w", err)
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

	updated := strings.Join(lines, "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}

	// writeFileAtomically is shared with config raw save path.
	if err := writeFileAtomically(configPath, []byte(updated)); err != nil {
		return err
	}

	// The config file holds a bcrypt hash (and other sensitive values).
	// Restrict to owner-only access so co-tenants can't read it.
	_ = os.Chmod(configPath, 0600)
	return nil
}
