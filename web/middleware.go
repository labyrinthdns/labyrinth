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

// MaxRequestBodyBytes caps the size of any JSON request body the
// admin API will read. Every POST/PUT/PATCH handler decodes the body
// into a struct; without a cap, an attacker (or a buggy automation
// script) could POST a 1GB JSON blob and exhaust resolver RAM before
// the decoder failed. 1 MiB is well above any legitimate API request
// (the largest is a few-hundred-byte NTA install or blocklist domain
// list) and well below the threshold at which a single body would
// cause memory pressure. The middleware uses http.MaxBytesReader so
// Decode() naturally errors with http.MaxBytesError once the cap is
// exceeded, which jsonResponse turns into a clean 400.
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

// withBodyCap wraps a handler so that any read from r.Body returns
// http.MaxBytesError once MaxRequestBodyBytes has been read. This is
// MaxWebSocketMessageBytes caps the size of any single WebSocket
// message the admin API will read from a client. All three live-stream
// endpoints (queries, trace, time-series) receive only tiny JSON
// control messages — subscription updates, trace start/cancel — that
// are well under 1 KiB in normal use. The coder/websocket library's
// default is 32 KiB, which is large enough that a regression to the
// library default (or a future bump in upstream) would silently widen
// the attack surface for an authenticated client trying to bloat the
// server's per-conn read buffer. Pinning to 4 KiB makes the bound
// explicit at every Accept site and keeps headroom for tagged messages
// without permitting megabyte-scale floods.
const MaxWebSocketMessageBytes = 4 << 10 // 4 KiB

// the OOM defence and MUST be applied to every POST/PUT/PATCH route
// — including unauthenticated ones like /api/auth/login, where an
// attacker has not yet been turned away and so the cap is the only
// thing standing between a malicious 1GB JSON blob and the JSON
// decoder allocating it all into RAM.
//
// WebSocket upgrade requests have a small handshake body that is
// well under the cap; once upgraded, the cap no longer applies (the
// protocol moves off http.Request.Body).
func withBodyCap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		next(w, r)
	}
}

// requireAuth returns a middleware that validates the JWT from the Authorization header
// or ?token= query parameter. If no auth is configured (username is empty), it passes through.
func (s *AdminServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apply the body cap on every authenticated request. WebSocket
		// upgrade requests have a small handshake body that is well
		// under the cap; once the connection is upgraded the cap no
		// longer applies (the protocol moves off http.Request.Body).
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)

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

		username, err := validateJWT(token, s.jwtSecret, &s.revokedTokens)
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
	// API responses are live observability data — never cacheable by
	// intermediate proxies or the browser. Without Cache-Control a
	// reverse proxy (or a misconfigured browser) could serve a 30-s-
	// old /api/stats payload as if it were current, masking real
	// failures during an incident. `no-store` is stricter than
	// `no-cache` and is the right choice here because we never want
	// these responses persisted at all (not even revalidated).
	w.Header().Set("Cache-Control", "no-store")
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
			// Search-engine indexing: the admin UI is internal infra and
			// must never be in a public search index, even if an operator
			// accidentally exposes the management port to the internet
			// (or runs Labyrinth on a routable cloud instance during
			// commissioning). X-Robots-Tag is the HTTP-header equivalent
			// of <meta name="robots" content="noindex,nofollow"> and is
			// honoured by every major crawler.
			if h.Get("X-Robots-Tag") == "" {
				h.Set("X-Robots-Tag", "noindex, nofollow")
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
