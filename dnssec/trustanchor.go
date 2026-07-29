package dnssec

import (
	"encoding/hex"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RootDSRecords contains the trust anchors for the DNS root zone.
// These are the well-known IANA root KSK trust anchors used to anchor
// the DNSSEC chain of trust.
//
// Key tag 20326: Root KSK (2017), RSA/SHA-256
// Key tag 38696: Root KSK (2024), RSA/SHA-256 — added per audit H-7 to
// avoid a forced validation outage at the next root KSK rollover (the
// resolver intentionally bypasses fallback on DNSSEC failure, so missing
// the new anchor would take the entire resolver dark).
// See: https://data.iana.org/root-anchors/root-anchors.xml
var RootDSRecords = []dns.DSRecord{
	{
		KeyTag:     20326,
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     hexDecode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
	},
	{
		KeyTag:     38696,
		Algorithm:  dns.AlgRSASHA256,
		DigestType: dns.DigestSHA256,
		Digest:     hexDecode("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
	},
}

// hexDecode decodes a hexadecimal string into bytes.
// It panics if the input is not valid hex, which is acceptable
// since this is only used for compile-time constant trust anchors.
func hexDecode(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("dnssec: invalid hex in trust anchor: " + err.Error())
	}
	return b
}
