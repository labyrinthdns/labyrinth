package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
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
