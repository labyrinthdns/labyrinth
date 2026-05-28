package server

import (
	"testing"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// TestCookieSecret_RotationGraceWindow pins RFC 9018 §4.3 + RFC 7873
// §5.2.5: a server-cookie issued under the immediately-previous
// secret MUST still validate for the rotation grace window (the
// handler keeps exactly one previous secret). Without this, a routine
// secret rotation — recommended hourly to limit the blast radius of a
// secret leak — would simultaneously invalidate every active client's
// cookie and force the entire population through a BADCOOKIE round-
// trip. With it, clients smoothly transition: their old cookie
// validates until the grace window closes, by which time they have
// (via normal traffic) been issued a fresh cookie under the new
// secret.
//
// The pin drives four steps:
//
//   1. Issue a cookie under secret A.
//   2. Rotate to secret B → old cookie still validates (grace path).
//   3. Verify a freshly issued cookie under B also validates.
//   4. Rotate to secret C → cookie issued under A no longer validates
//      (only ONE previous secret is retained, not a chain).
//
// Step 4 is the security invariant: an unbounded chain of previous
// secrets would mean a single historical-secret leak compromises the
// entire ring of rotations, defeating the point of rotation.
func TestCookieSecret_RotationGraceWindow(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	secretA := make([]byte, 16)
	for i := range secretA {
		secretA[i] = 0xA0 | byte(i)
	}
	h.EnableCookiesWithSecret(secretA)

	clientCookie := []byte{0xC1, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	clientIP := "192.0.2.42"
	cookieUnderA := h.generateServerCookie(clientCookie, clientIP)

	// Sanity: cookie A validates under secret A.
	if !h.validateServerCookie(clientCookie, cookieUnderA, clientIP) {
		t.Fatalf("cookie issued under secret A failed to validate under secret A — generator/validator out of sync")
	}

	// Step 2: rotate to secret B.
	if err := h.RotateCookieSecret(); err != nil {
		t.Fatalf("rotate to B: %v", err)
	}
	if !h.validateServerCookie(clientCookie, cookieUnderA, clientIP) {
		t.Errorf("cookie issued under secret A failed to validate AFTER rotation to B — grace window broken (RFC 7873 §5.2.5)")
	}

	// Step 3: fresh cookie under B also validates.
	cookieUnderB := h.generateServerCookie(clientCookie, clientIP)
	if !h.validateServerCookie(clientCookie, cookieUnderB, clientIP) {
		t.Errorf("cookie freshly issued under secret B failed to validate — current-secret path broken")
	}

	// Step 4: rotate again to C. Cookie A is now TWO rotations old and
	// must no longer validate — only the immediately-previous secret
	// (B) is kept in grace, not a chain.
	if err := h.RotateCookieSecret(); err != nil {
		t.Fatalf("rotate to C: %v", err)
	}
	if h.validateServerCookie(clientCookie, cookieUnderA, clientIP) {
		t.Errorf("cookie issued under secret A validated after TWO rotations — handler keeps an unbounded chain of previous secrets, defeating rotation security (single historical leak → all-time compromise)")
	}
	// And cookie B (one rotation back) still validates.
	if !h.validateServerCookie(clientCookie, cookieUnderB, clientIP) {
		t.Errorf("cookie issued under secret B failed to validate after rotation to C — grace window broken")
	}
}

// TestCookieSecret_GraceWindowExpires pins the time-bound on the
// grace window: even the immediately-previous secret stops accepting
// cookies once its grace expiry passes. The handler sets the expiry
// to now+1h on rotation. Without this bound, a long-lived but
// rotated-away secret could be replayed forever — a leaked secret
// retains attack value indefinitely.
//
// We drive the time-check by overriding nowFunc to jump past the
// 1-hour expiry without sleeping, then assert the previous-secret
// cookie is rejected.
func TestCookieSecret_GraceWindowExpires(t *testing.T) {
	handlerMetrics := metrics.NewMetrics()
	cacheMetrics := metrics.NewMetrics()
	ca := cache.NewCacheWithStale(1000, 5, 86400, 3600, true, 30, cacheMetrics)
	res := newPanickingResolver(ca)
	h := NewMainHandler(res, ca, nil, nil, nil, handlerMetrics, discardLogger())

	// Pin nowFunc to a fixed reference time so the timestamp embedded
	// in the issued cookie aligns with the validator's clock view.
	baseTime := time.Now()
	origNowFunc := nowFunc
	t.Cleanup(func() { nowFunc = origNowFunc })
	nowFunc = func() uint32 { return uint32(baseTime.Unix()) }

	secretA := make([]byte, 16)
	for i := range secretA {
		secretA[i] = byte(i)
	}
	h.EnableCookiesWithSecret(secretA)

	clientCookie := []byte{0xC0, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	clientIP := "192.0.2.99"
	cookieUnderA := h.generateServerCookie(clientCookie, clientIP)

	if err := h.RotateCookieSecret(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Within grace window: still valid.
	if !h.validateServerCookie(clientCookie, cookieUnderA, clientIP) {
		t.Fatalf("cookie under A failed in-grace after rotation")
	}

	// Jump nowFunc past the grace expiry (1 hour + slack). The
	// embedded timestamp in the cookie also ages; the 1-hour max-age
	// check at handler.go:371 will reject it as expired. That is the
	// belt-and-suspenders enforcement of the §4.3 max age and is the
	// pin's target.
	nowFunc = func() uint32 { return uint32(baseTime.Add(2 * time.Hour).Unix()) }

	if h.validateServerCookie(clientCookie, cookieUnderA, clientIP) {
		t.Errorf("cookie under previous secret validated past 1-hour expiry — RFC 9018 §4.3 max-age not enforced; a leaked secret would retain attack value indefinitely")
	}
}
