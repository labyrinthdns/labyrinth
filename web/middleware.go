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

		// H-4 (partial): only honour ?token= for WebSocket upgrade requests.
		// Browsers cannot set Authorization on `new WebSocket(...)`, so the
		// query-string fallback is needed there until the SPA migrates to
		// Sec-WebSocket-Protocol auth. For ordinary HTTP routes, refusing
		// ?token= prevents JWTs leaking via Referer / proxy access logs /
		// browser history.
		if token == "" && isWebSocketUpgrade(r) {
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

// isWebSocketUpgrade reports whether the request is a WebSocket upgrade.
// RFC 6455 §4.1: requires Upgrade: websocket and Connection: Upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
			return true
		}
	}
	return false
}

// jsonResponse writes a JSON response with the given status code and data.
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// securityHeaders returns a middleware that emits defence-in-depth response
// headers: clickjacking, MIME-sniffing, referrer leakage, and (when TLS is
// active on the request) HSTS. Implements audit finding H-3.
//
// Note: WebSocket upgrade responses must not have CSP applied to the
// negotiated 101 response in a way that breaks browser handshake validation.
// nhooyr/websocket calls Hijack() before the response is written, so any
// headers set here on the http.ResponseWriter prior to upgrade are sent on
// the 101 response and are ignored by the browser for the WS payload.
func securityHeaders(tlsActive func() bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// Clickjacking
			if h.Get("X-Frame-Options") == "" {
				h.Set("X-Frame-Options", "DENY")
			}
			// MIME-sniffing
			if h.Get("X-Content-Type-Options") == "" {
				h.Set("X-Content-Type-Options", "nosniff")
			}
			// Referrer leakage (relevant because of `?token=` legacy)
			if h.Get("Referrer-Policy") == "" {
				h.Set("Referrer-Policy", "no-referrer")
			}
			// Permissions-Policy: deny everything we don't use
			if h.Get("Permissions-Policy") == "" {
				h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
			}
			// CSP: same-origin only. `unsafe-inline` for styles is required
			// by the current Tailwind setup; future work is to switch to a
			// nonce. The connect-src allows ws/wss for the dashboard.
			if h.Get("Content-Security-Policy") == "" {
				h.Set("Content-Security-Policy",
					"default-src 'self'; "+
						"img-src 'self' data:; "+
						"script-src 'self'; "+
						"style-src 'self' 'unsafe-inline'; "+
						"connect-src 'self' ws: wss:; "+
						"frame-ancestors 'none'; "+
						"base-uri 'none'; "+
						"form-action 'self'")
			}
			// HSTS only on TLS connections (avoid pinning HTTP-only deployments).
			if tlsActive != nil && tlsActive() && h.Get("Strict-Transport-Security") == "" {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
