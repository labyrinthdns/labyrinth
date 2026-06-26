package dnssec

import (
	"testing"
)

// TestCanonicalWildcardOwner_RFC4035_5_3_2 pins the wildcard
// reconstruction rule of RFC 4035 §5.3.2:
//
//	When an answer is synthesised from a wildcard, the owner name on
//	the wire is the QUERIED name (e.g. "foo.example.com"), but the
//	owner the auth server SIGNED was "*.example.com". The validator
//	must rebuild the signed owner before computing canonical wire
//	form, or every wildcard-served answer comes back Bogus.
//
// The rebuild rule:
//   - rrsig.Labels counts labels in the originally-signed owner,
//     root excluded, and the wildcard "*" label NOT counted.
//   - If rrName has STRICTLY MORE labels than rrsig.Labels, the RR
//     is a wildcard expansion → rebuild as "*." + (last rrsig.Labels labels).
//   - If rrName has equal-or-fewer labels, the owner is used as-is.
//
// Special cases:
//   - rrsig.Labels == 0 → root-zone apex signature; never rebuild
//     (kept for compatibility with tests that leave Labels unset).
//   - rrsig.Labels == rrName label count → no rebuild (exact owner).
//   - Defensive: a buggy or hostile RRSIG might carry Labels > rrName
//     label count; canonicalWildcardOwner should not crash or
//     produce a malformed name.
func TestCanonicalWildcardOwner_RFC4035_5_3_2(t *testing.T) {
	cases := []struct {
		name   string
		rrName string
		labels uint8
		want   string
	}{
		{
			name:   "Labels=0 root apex — owner used as-is",
			rrName: "example.com", labels: 0,
			want: "example.com",
		},
		{
			name:   "Labels == rrName labels — exact owner, no rebuild",
			rrName: "foo.example.com", labels: 3,
			want: "foo.example.com",
		},
		{
			name:   "rrName 4 labels, Labels=2 — wildcard expansion → *.example.com",
			rrName: "a.b.example.com", labels: 2,
			want: "*.example.com",
		},
		{
			name:   "rrName 5 labels, Labels=2 — deep wildcard expansion → *.example.com",
			rrName: "a.b.c.example.com", labels: 2,
			want: "*.example.com",
		},
		{
			name:   "rrName 3 labels, Labels=1 — wildcard at TLD → *.com",
			rrName: "foo.bar.com", labels: 1,
			want: "*.com",
		},
		{
			name:   "trailing dot tolerated",
			rrName: "a.b.example.com.", labels: 2,
			want: "*.example.com",
		},
		{
			name:   "defensive — Labels > rrName label count, used as-is (no crash)",
			rrName: "example.com", labels: 99,
			want: "example.com",
		},
		{
			name:   "defensive — empty rrName, used as-is",
			rrName: "", labels: 2,
			want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := canonicalWildcardOwner(c.rrName, c.labels)
			if got != c.want {
				t.Errorf("canonicalWildcardOwner(%q, %d) = %q, want %q\nRFC 4035 §5.3.2: a regression here Bogus-es every wildcard-served signed zone answer", c.rrName, c.labels, got, c.want)
			}
		})
	}
}
