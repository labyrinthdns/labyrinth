package dnssec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/labyrinthdns/labyrinth/dns"
)

// buildCDSWire builds CDS RDATA. Wire layout is identical to DS
// (RFC 7344 §3.1), so this is a copy of the DS encoder kept local
// to the test so the production path doesn't accidentally grow a
// public encoder it doesn't otherwise need.
func buildCDSWire(keyTag uint16, algorithm, digestType uint8, digest []byte) []byte {
	out := make([]byte, 4+len(digest))
	binary.BigEndian.PutUint16(out[0:2], keyTag)
	out[2] = algorithm
	out[3] = digestType
	copy(out[4:], digest)
	return out
}

// TestParseCDSRRset_PublishVsDelete_TruthTable pins RFC 7344 §3.1 +
// RFC 8078 §4: a CDS RRset with one record whose Algorithm == 0 is
// the "delete DS, take delegation insecure" sentinel; any other
// well-formed RRset is a "publish DS" intent. A regression that
// dropped either branch would either prevent a child operator from
// going insecure (CDSActionDelete missed) or silently honour every
// algorithm-0 record as a normal DS (CDSActionPublish promoted).
func TestParseCDSRRset_PublishVsDelete_TruthTable(t *testing.T) {
	publishRR := dns.ResourceRecord{
		Name:  "child.example.",
		Type:  dns.TypeCDS,
		Class: dns.ClassIN,
		TTL:   3600,
		RData: buildCDSWire(12345, dns.AlgRSASHA256, dns.DigestSHA256, bytes.Repeat([]byte{0xAA}, 32)),
	}
	deleteRR := dns.ResourceRecord{
		Name:  "child.example.",
		Type:  dns.TypeCDS,
		Class: dns.ClassIN,
		TTL:   3600,
		// Algorithm 0 → "delete" sentinel.
		RData: buildCDSWire(0, 0, 0, []byte{0x00}),
	}

	cases := []struct {
		name       string
		rrs        []dns.ResourceRecord
		wantAction CDSUpdateAction
		wantErr    error
	}{
		{
			name:       "single publish — normal DS",
			rrs:        []dns.ResourceRecord{publishRR},
			wantAction: CDSActionPublish,
		},
		{
			name:       "two publish — rollover (multiple new DS, parent will accept superset)",
			rrs:        []dns.ResourceRecord{publishRR, publishRR},
			wantAction: CDSActionPublish,
		},
		{
			name:       "single delete sentinel — RFC 8078 §4",
			rrs:        []dns.ResourceRecord{deleteRR},
			wantAction: CDSActionDelete,
		},
		{
			name: "delete + publish mixed — MALFORMED, alg-0 must stand alone",
			// Critical: a regression that silently allowed the
			// publish record to win would mean an attacker could
			// inject an extra well-formed DS alongside a victim's
			// delete intent and HIJACK the delegation. We MUST
			// reject the whole RRset.
			rrs:        []dns.ResourceRecord{deleteRR, publishRR},
			wantAction: CDSActionUnknown,
			wantErr:    ErrCDSMalformed,
		},
		{
			name:       "empty RRset — distinct error class",
			rrs:        nil,
			wantAction: CDSActionUnknown,
			wantErr:    ErrCDSEmpty,
		},
		{
			name: "wrong RR type in input — malformed",
			rrs: []dns.ResourceRecord{
				{Name: "x.", Type: dns.TypeDS, RData: publishRR.RData},
			},
			wantAction: CDSActionUnknown,
			wantErr:    ErrCDSMalformed,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseCDSRRset(c.rrs)
			if got.Action != c.wantAction {
				t.Errorf("Action = %v, want %v", got.Action, c.wantAction)
			}
			if c.wantErr == nil {
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, c.wantErr) {
					t.Errorf("err = %v, want errors.Is(_, %v)", err, c.wantErr)
				}
			}
		})
	}
}

// TestCDSMatchesParentDS_Detection pins the no-op-vs-real-change
// detection used by the diagnostic UI. When a child publishes a CDS
// that exactly matches the parent's current DS, the operator should
// see "no change" — not a spurious "rollover signalled" badge that
// teaches them to ignore the alert.
func TestCDSMatchesParentDS_Detection(t *testing.T) {
	digestA := bytes.Repeat([]byte{0x11}, 32)
	digestB := bytes.Repeat([]byte{0x22}, 32)

	parent := []*dns.DSRecord{
		{KeyTag: 100, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA256, Digest: digestA},
	}

	t.Run("exact match — no-op", func(t *testing.T) {
		cds := CDSUpdate{
			Action: CDSActionPublish,
			DSRecords: []*dns.DSRecord{
				{KeyTag: 100, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA256, Digest: digestA},
			},
		}
		if !cds.CDSMatchesParentDS(parent) {
			t.Errorf("identical DS not detected as match — UI would falsely flag a rollover")
		}
	})

	t.Run("superset — child adds a key (rollover)", func(t *testing.T) {
		cds := CDSUpdate{
			Action: CDSActionPublish,
			DSRecords: []*dns.DSRecord{
				{KeyTag: 100, Algorithm: dns.AlgRSASHA256, DigestType: dns.DigestSHA256, Digest: digestA},
				{KeyTag: 200, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA256, Digest: digestB},
			},
		}
		if !cds.CDSMatchesParentDS(parent) {
			t.Errorf("superset (parent ⊆ child) not detected — every parent DS is in the child set, this is a 'parent has nothing to remove' signal that should still report match")
		}
	})

	t.Run("child shrinks — parent DS absent from CDS — NOT a match", func(t *testing.T) {
		cds := CDSUpdate{
			Action: CDSActionPublish,
			DSRecords: []*dns.DSRecord{
				{KeyTag: 200, Algorithm: dns.AlgECDSAP256, DigestType: dns.DigestSHA256, Digest: digestB},
			},
		}
		if cds.CDSMatchesParentDS(parent) {
			t.Errorf("child wants to remove the key 100 DS — must NOT report as no-op; UI must flag the change")
		}
	})

	t.Run("delete action — never a match", func(t *testing.T) {
		cds := CDSUpdate{
			Action: CDSActionDelete,
			DSRecords: []*dns.DSRecord{
				{KeyTag: 0, Algorithm: 0, DigestType: 0, Digest: []byte{0x00}},
			},
		}
		if cds.CDSMatchesParentDS(parent) {
			t.Errorf("delete sentinel matched parent DS — Action=Delete must short-circuit to false regardless of byte content")
		}
	})
}

// TestParseCDNSKEYRRset_DeleteAndPublish pins the CDNSKEY twin of the
// CDS classifier. CDNSKEY (type 60) shares the DNSKEY wire format
// (RFC 7344 §3.2) so the parser sits on top of ParseDNSKEY; the
// classification rules are RFC 8078 §4 again: single record with
// Algorithm=0 → delete sentinel; otherwise publish.
func TestParseCDNSKEYRRset_DeleteAndPublish(t *testing.T) {
	pubKey := bytes.Repeat([]byte{0xCD}, 64)
	publishKeyRData := make([]byte, 4+len(pubKey))
	binary.BigEndian.PutUint16(publishKeyRData[0:2], 256) // ZSK flags
	publishKeyRData[2] = 3
	publishKeyRData[3] = dns.AlgECDSAP256
	copy(publishKeyRData[4:], pubKey)

	deleteKeyRData := make([]byte, 5) // Flags=0, Protocol=3, Alg=0, single zero byte key per RFC 8078 §4
	deleteKeyRData[2] = 3             // Protocol per RFC 4034 §2.1.2
	deleteKeyRData[3] = 0             // Algorithm 0 = sentinel
	deleteKeyRData[4] = 0             // 1-byte public key (placeholder)

	cases := []struct {
		name       string
		rrs        []dns.ResourceRecord
		wantAction CDSUpdateAction
		wantErr    error
	}{
		{
			name: "single publish",
			rrs: []dns.ResourceRecord{
				{Name: "child.", Type: dns.TypeCDNSKEY, RData: publishKeyRData},
			},
			wantAction: CDSActionPublish,
		},
		{
			name: "single delete sentinel",
			rrs: []dns.ResourceRecord{
				{Name: "child.", Type: dns.TypeCDNSKEY, RData: deleteKeyRData},
			},
			wantAction: CDSActionDelete,
		},
		{
			name: "delete + publish mixed — malformed",
			rrs: []dns.ResourceRecord{
				{Name: "child.", Type: dns.TypeCDNSKEY, RData: deleteKeyRData},
				{Name: "child.", Type: dns.TypeCDNSKEY, RData: publishKeyRData},
			},
			wantAction: CDSActionUnknown,
			wantErr:    ErrCDSMalformed,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, action, err := ParseCDNSKEYRRset(c.rrs)
			if action != c.wantAction {
				t.Errorf("action = %v, want %v", action, c.wantAction)
			}
			if c.wantErr == nil {
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, c.wantErr) {
					t.Errorf("err = %v, want errors.Is(_, %v)", err, c.wantErr)
				}
			}
		})
	}
}

// TestCDSUpdateAction_String pins the string form used by logs and the
// observability API. A typo in either direction (e.g. "publishing"
// instead of "publish") would silently break dashboards filtering on
// the value.
func TestCDSUpdateAction_String(t *testing.T) {
	cases := map[CDSUpdateAction]string{
		CDSActionUnknown: "unknown",
		CDSActionPublish: "publish",
		CDSActionDelete:  "delete",
	}
	for action, want := range cases {
		got := action.String()
		if got != want {
			t.Errorf("CDSUpdateAction(%d).String() = %q, want %q", action, got, want)
		}
	}
}
