package server

import "testing"

// TestAdvertisedUDPBufferSize_TruthTable pins Y54: the resolver's EDNS
// UDP buffer-size advertisement (the OPT pseudo-record's CLASS field)
// is constrained by two RFC clauses:
//
//   - RFC 6891 §6.2.5: receiver MUST support at least 512 bytes
//   - RFC 9018 §3.1 / dnsflagday.net: 1232 is the "safe" path-MTU-aware
//     default that survives IPv6 fragmentation issues end-to-end
//
// The implementation clamps unset (0), too-small (< 512), and too-large
// (> 65535 — impossible in uint16, but the int field could carry it)
// values back to 1232. Without this clamp, a misconfigured integer in
// the operator YAML could ship an OPT advertising "8" or "70000"
// bytes — the former would cause fragmentation under any non-trivial
// answer, the latter overflows uint16 and wraps to nonsense on the wire.
//
// We pin both ends of the truth table:
//   - explicit-default and in-range values pass through
//   - unset and out-of-range values clamp to 1232
//
// A refactor that swapped the inequality direction (or used `<= minSize`
// instead of `< minSize`) would silently regress one of these cells.
func TestAdvertisedUDPBufferSize_TruthTable(t *testing.T) {
	const fallback uint16 = 1232

	for _, c := range []struct {
		name string
		set  int
		want uint16
	}{
		{"unset (0) falls back to 1232", 0, fallback},
		{"under-minimum (256) falls back to 1232", 256, fallback},
		{"exactly 512 (the §6.2.5 floor) passes through", 512, 512},
		{"common 1232 default passes through", 1232, 1232},
		{"4096 (BIND default) passes through", 4096, 4096},
		{"65535 (uint16 ceiling) passes through", 65535, 65535},
		{"over-range (70000) falls back to 1232", 70000, fallback},
		{"negative (operator typo) falls back to 1232", -1, fallback},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHandler()
			h.SetDownstreamUDPBufferSize(c.set)
			if got := h.advertisedUDPBufferSize(); got != c.want {
				t.Errorf("set=%d advertisedUDPBufferSize()=%d, want %d", c.set, got, c.want)
			}
		})
	}
}
