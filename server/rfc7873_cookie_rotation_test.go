package server

import (
	"testing"
	"time"
)

// TestRotateCookieSecret_GraceWindowAcceptsOldCookie pins the Y20 fix
// to RFC 7873 §5.2.5: "Cookies created with old secrets remain valid
// until they expire." After RotateCookieSecret, server cookies the
// client received just before rotation MUST still validate against the
// previous secret during a grace window equal to the cookie lifetime
// (RFC 9018 §4.3 — one hour). Without this grace, every routine
// rotation would force every active client through a BADCOOKIE round
// trip, turning an operational action into a service blip.
func TestRotateCookieSecret_GraceWindowAcceptsOldCookie(t *testing.T) {
	h := testHandler()
	h.logger = nil
	if err := h.EnableCookies(); err != nil {
		t.Fatalf("EnableCookies: %v", err)
	}

	// Mint a server cookie under the current (= first) secret.
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientIP := "192.0.2.10"
	cookie := h.generateServerCookie(clientCookie, clientIP)
	if !h.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Fatal("just-minted cookie must validate under the current secret")
	}

	// Rotate. The previously-minted cookie must STILL validate (grace).
	if err := h.RotateCookieSecret(); err != nil {
		t.Fatalf("RotateCookieSecret: %v", err)
	}
	if !h.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("cookie issued before rotation must validate during the grace window (RFC 7873 §5.2.5)")
	}

	// Fresh cookie under the NEW secret must also validate.
	freshCookie := h.generateServerCookie(clientCookie, clientIP)
	if !h.validateServerCookie(clientCookie, freshCookie, clientIP) {
		t.Error("cookie minted after rotation must validate under the new secret")
	}

	// The two cookies are bound to different secrets so they must
	// produce different bytes — otherwise rotation accomplishes nothing.
	if equalBytes(cookie, freshCookie) {
		t.Error("rotation did not change the secret: same cookie before/after")
	}
}

// TestRotateCookieSecret_GraceExpiresAfterOneHour pins the upper bound:
// once the grace window passes, the previous secret MUST stop being
// honoured. Otherwise a leaked-then-rotated secret remains valid forever.
func TestRotateCookieSecret_GraceExpiresAfterOneHour(t *testing.T) {
	h := testHandler()
	h.logger = nil
	if err := h.EnableCookies(); err != nil {
		t.Fatalf("EnableCookies: %v", err)
	}

	clientCookie := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02}
	clientIP := "192.0.2.99"
	cookie := h.generateServerCookie(clientCookie, clientIP)

	if err := h.RotateCookieSecret(); err != nil {
		t.Fatalf("RotateCookieSecret: %v", err)
	}

	// Forcibly age the grace deadline into the past.
	h.cookieMu.Lock()
	h.prevExpiresAt = time.Unix(int64(nowFunc())-10, 0)
	h.cookieMu.Unlock()

	if h.validateServerCookie(clientCookie, cookie, clientIP) {
		t.Error("cookie under previous secret must NOT validate after grace window expires")
	}
}

// TestRotateCookieSecret_RefusesWhenCookiesDisabled is the defensive
// negative: calling rotate without cookies enabled must error rather
// than silently generate a secret in a no-op state.
func TestRotateCookieSecret_RefusesWhenCookiesDisabled(t *testing.T) {
	h := testHandler()
	if err := h.RotateCookieSecret(); err == nil {
		t.Error("RotateCookieSecret on cookies-disabled handler must error")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
