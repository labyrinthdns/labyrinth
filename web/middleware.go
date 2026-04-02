package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// contextKey is the type for context keys used by the web package.
type contextKey int

const (
	ctxKeyUser contextKey = iota
)

// requireAuth returns a middleware that validates the JWT from the Authorization header
// or ?token= query parameter. If no auth is configured (username is empty), it passes through.
func (s *AdminServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no auth configured, pass through
		if s.config.Web.Auth.Username == "" {
			next(w, r)
			return
		}

		var token string

		// Try Authorization: Bearer <token> header first
		if auth := r.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		// Fall back to ?token= query parameter
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token == "" {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "missing authentication token"})
			return
		}

		username, err := validateJWT(token, s.jwtSecret)
		if err != nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUser, username)
		next(w, r.WithContext(ctx))
	}
}

// jsonResponse writes a JSON response with the given status code and data.
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
