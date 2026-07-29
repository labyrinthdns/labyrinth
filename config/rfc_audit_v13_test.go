package config

import "testing"

// TestDefault_Caps0x20EnabledOn pins the Y1 fix: RFC 5452 §9.2 0x20 case
// randomization is now on by default. With it off (the pre-0.6.13 default)
// off-path spoofers had 2^16 = 65536 TXID guesses to brute-force; flipping
// the per-letter case randomly across a typical 10-letter qname adds up to
// 2^10 effective bits of extra entropy, raising the bar dramatically with
// zero protocol cost (auth servers preserve the case in their replies).
// A regression that flips this back to false would silently halve the
// resolver's anti-spoofing defense.
func TestDefault_Caps0x20EnabledOn(t *testing.T) {
	cfg := defaultConfig()
	if !cfg.Resolver.Caps0x20Enabled {
		t.Error("RFC 5452 §9.2: Caps0x20Enabled must default to true")
	}
}
