package dnssec

import (
	"testing"
	"time"
)

// TestRRSIGClockSkew_InSensibleRange pins RFC 4035 §5.3.1's tolerance
// for real-world clock drift on RRSIG Inception and Expiration checks.
// The validator applies `rrsigClockSkew` symmetrically:
//
//   - reject if  now + skew < Inception   (signature not yet valid)
//   - reject if  now > Expiration + skew  (signature expired)
//
// The constant occupies a security/operations trade-off:
//
//   - **Too small (e.g. 0)** — every clock-drift incident on the
//     resolver or auth side triggers spurious Bogus verdicts at
//     signature boundaries. Operators see periodic DNSSEC outages
//     for zones that are actually fine.
//
//   - **Too large (e.g. > 1 hour)** — an attacker who replayed an
//     expired signature would have a long window in which forged
//     responses pass validation. RFC 4034 inception-expiration
//     windows are typically days; a multi-hour skew erodes that
//     freshness guarantee meaningfully.
//
// The sensible range, supported by published guidance (BIND, Knot,
// Unbound all use 5s–5min defaults), is roughly 1s to 5min. The
// current value (60s) sits squarely in the recommended band.
//
// A regression that bumped the constant to "1 day for stability"
// or zeroed it for "strict mode" would slip past code review but
// would be caught by this pin immediately.
func TestRRSIGClockSkew_InSensibleRange(t *testing.T) {
	const minSkew = 1 * time.Second
	const maxSkew = 5 * time.Minute

	if rrsigClockSkew < minSkew {
		t.Errorf("rrsigClockSkew = %v, below minimum %v — signature-boundary clock drift would Bogus legitimately-valid zones; operators see periodic DNSSEC outages",
			rrsigClockSkew, minSkew)
	}
	if rrsigClockSkew > maxSkew {
		t.Errorf("rrsigClockSkew = %v, above maximum %v — an attacker replaying an expired signature gets a wide window of validity; erodes the freshness guarantee RFC 4034 inception-expiration was designed to provide",
			rrsigClockSkew, maxSkew)
	}
}
