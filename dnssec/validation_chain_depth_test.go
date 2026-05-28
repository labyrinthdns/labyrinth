package dnssec

import (
	"strings"
	"testing"
)

// TestBuildZoneChain_DepthGrowsLinearWithLabels — sanity pin on
// buildZoneChain's growth profile. A 127-label name produces a
// 128-element chain (one root entry + one entry per label). The cap
// in validateTrustChain refuses to walk anything beyond
// maxTrustChainDepth, so this test serves the dual purpose of
// (a) confirming buildZoneChain hasn't quietly changed its growth
// rule, and (b) letting `maxTrustChainDepth` carry a verified upper-
// bound semantics rather than an unaudited magic number.
func TestBuildZoneChain_DepthGrowsLinearWithLabels(t *testing.T) {
	cases := []struct {
		zone        string
		wantDepth   int
		description string
	}{
		{"example.com.", 3, "two-label name → root + com + example.com"},
		{"a.b.c.example.com.", 6, "five-label name → root + 5 progressively narrower zones"},
	}
	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			chain := buildZoneChain(c.zone)
			if len(chain) != c.wantDepth {
				t.Errorf("chain depth = %d, want %d (for zone %q)", len(chain), c.wantDepth, c.zone)
			}
		})
	}
}

// TestValidateTrustChain_RefusesPathologicalDepth — M5.5 pin. A
// hostile authoritative can publish an RRSIG whose SignerName carries
// many labels; without a cap, the trust-chain walker would issue a
// DNSKEY + DS fetch for each one (potentially 100+ network round-
// trips per query). Pin: we construct a synthetic zone name with
// label count > maxTrustChainDepth and assert validateTrustChain
// returns Indeterminate WITHOUT calling into any querier (no network
// I/O attributable to depth-walk).
//
// We use a nil querier — if the cap leaks and the walker tries to
// dispatch the first fetchDNSKEYs call, the resolver field is nil
// inside the test and we'd see a panic rather than a clean
// Indeterminate verdict. The "no panic, clean verdict" property is
// exactly what the cap promises.
func TestValidateTrustChain_RefusesPathologicalDepth(t *testing.T) {
	// 200 labels → chain depth 201, well above the cap of 32.
	labels := make([]string, 200)
	for i := range labels {
		labels[i] = "x"
	}
	deep := strings.Join(labels, ".") + "."

	v := NewValidator(nil, nil)

	result := v.validateTrustChain(deep, nil)
	if result != Indeterminate {
		t.Errorf("validateTrustChain on %d-label zone returned %v, want Indeterminate (cap should have engaged)", len(labels), result)
	}
}

// TestValidateTrustChain_DepthCapValueIsSane — guards against a
// future refactor that drops the cap to a value below any legitimate
// production zone. Real DNSSEC-signed zones top out around 7 labels;
// 32 is a comfortable margin. If somebody pushes the cap to 5
// "to be safe", this test surfaces the regression.
func TestValidateTrustChain_DepthCapValueIsSane(t *testing.T) {
	const realisticUpperBound = 16 // No real zone is deeper than this.
	if maxTrustChainDepth < realisticUpperBound {
		t.Errorf("maxTrustChainDepth = %d is below the realistic-name upper bound of %d", maxTrustChainDepth, realisticUpperBound)
	}
}
