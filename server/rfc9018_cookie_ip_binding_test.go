package server

import (
	"testing"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestServerCookie_BindsClientIP pins RFC 9018 §4.2 / RFC 7873 §5.2.4:
// the server cookie is computed as a hash of (clientCookie, clientIP,
// timestamp, secret). The client IP is part of the input by design —
// a cookie issued to client A MUST NOT validate when presented from
// client B's IP. Without this binding, a cookie leaked by any one
// client could be replayed by any other to bypass cookie-based source
// validation entirely.
//
// The pin generates a server cookie for clientIP=A, then attempts to
// validate it from clientIP=B; rejection is mandatory. We also pin
// the affirmative case — the same IP MUST validate — as the
// regression target for a refactor that broke the IP-input wiring.
//
// Beyond rebinding defense, this is also RFC 7873 §5.2.5's anti-
// amplification posture: an attacker spoofing source addresses to
// trigger amplified responses cannot replay one victim's cookie
// from another spoofed source, because the server-side hash would
// not align.
func TestServerCookie_BindsClientIP(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = 0xA5
	}
	h.EnableCookiesWithSecret(secret)

	clientCookie := []byte{0xC1, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Issue a cookie under IP=A.
	const ipA = "192.0.2.10"
	const ipB = "198.51.100.20"
	cookieFromA := h.generateServerCookie(clientCookie, ipA)

	t.Run("same IP validates", func(t *testing.T) {
		if !h.validateServerCookie(clientCookie, cookieFromA, ipA) {
			t.Errorf("cookie issued for %s failed validation from same IP — generator/validator out of sync on the IP-input path", ipA)
		}
	})

	t.Run("different IP rejects (rebinding defense)", func(t *testing.T) {
		if h.validateServerCookie(clientCookie, cookieFromA, ipB) {
			t.Errorf("cookie issued for %s validated when presented from %s — RFC 9018 §4.2 violation: a leaked cookie could be replayed from any IP, bypassing cookie-based source validation entirely",
				ipA, ipB)
		}
	})

	t.Run("IPv6 different from IPv4 — separate hash space", func(t *testing.T) {
		// 192.0.2.10's IPv4-mapped IPv6 representation. parseIPBytes
		// canonicalises to 4 bytes for IPv4, distinct from any pure
		// 16-byte IPv6 value. A pin that catches a refactor that
		// collapsed both into the same byte form.
		const ipV6 = "2001:db8::1"
		if h.validateServerCookie(clientCookie, cookieFromA, ipV6) {
			t.Errorf("IPv4-issued cookie validated against an IPv6 client — distinct address families must hash to different cookie inputs")
		}
	})
}
