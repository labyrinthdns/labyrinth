package dnssec

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/labyrinthdns/labyrinth/dns"
)

// RFC 7344 / RFC 8078 — child-signalled DS update.
//
// CDS (type 59) and CDNSKEY (type 60) records published at the apex of
// the CHILD zone instruct the parent that the child wants its
// delegation updated. The RDATA is byte-identical to DS (CDS) and
// DNSKEY (CDNSKEY); the distinction is purely the owner-side semantics.
//
// LabyrinthDNS is a recursive resolver — it never authoritatively
// serves a parent zone, so it does not "apply" a CDS update. What it
// does is expose CDS/CDNSKEY observations through this package so
// operator tooling (e.g. the diagnostic API and the UI's delegation
// inspector) can:
//
//   - Detect when a child zone has published a rollover intent;
//   - Tell the operator whether the published intent matches the
//     parent's current DS (no-op) or signals an upcoming change;
//   - Recognise the RFC 8078 §4 "delete DS" sentinel (single record
//     with Algorithm = 0) so the UI can flag a planned insecure
//     downgrade explicitly instead of mis-reporting it as a bogus
//     algorithm.
//
// The functions here are pure — no I/O — so the validator's hot path
// is unaffected.

// CDSUpdateAction is the action a CDS RRset is signalling.
type CDSUpdateAction int

const (
	// CDSActionUnknown — RRset is malformed or empty.
	CDSActionUnknown CDSUpdateAction = iota
	// CDSActionPublish — the child wants the parent to publish the DS
	// records carried in the CDS RRset. May be a no-op (matches the
	// existing DS), a key add, a key remove, or an algorithm rollover.
	CDSActionPublish
	// CDSActionDelete — RFC 8078 §4: a single CDS record with
	// Algorithm = 0 means "delete the DS, take this delegation
	// insecure". This is the canonical signal for a child operator
	// who wants to take their zone out of DNSSEC entirely.
	CDSActionDelete
)

// String returns a stable token for logs/metrics.
func (a CDSUpdateAction) String() string {
	switch a {
	case CDSActionPublish:
		return "publish"
	case CDSActionDelete:
		return "delete"
	}
	return "unknown"
}

// CDSUpdate is the parsed-and-classified view of a CDS RRset.
type CDSUpdate struct {
	// Action says what the RRset signals (publish, delete, unknown).
	Action CDSUpdateAction
	// DSRecords is the list of DS records carried in the CDS RRset
	// (one DSRecord per CDS RR). For CDSActionDelete this still
	// contains the single Algorithm=0 sentinel record so the caller
	// can log exactly what was received.
	DSRecords []*dns.DSRecord
}

// ParseCDSRRset extracts and classifies the action signalled by a CDS
// RRset. The owner of the records is not validated here — the caller
// must ensure they came from the apex of the child zone in question.
//
// Wire format: CDS RDATA == DS RDATA (RFC 7344 §3.1), so ParseDS is
// reused directly.
//
// Errors:
//
//   - errors.Is(err, ErrCDSEmpty) — empty input (no records).
//   - errors.Is(err, ErrCDSMalformed) — at least one CDS RR failed to
//     parse as DS wire form. The Action returned alongside is
//     CDSActionUnknown; well-formed siblings are NOT silently honoured
//     because RFC 8078 §3.1 makes the RRset a single atomic intent —
//     partial trust would defeat the purpose.
func ParseCDSRRset(rrs []dns.ResourceRecord) (CDSUpdate, error) {
	if len(rrs) == 0 {
		return CDSUpdate{Action: CDSActionUnknown}, ErrCDSEmpty
	}
	out := CDSUpdate{}
	for _, rr := range rrs {
		if rr.Type != dns.TypeCDS {
			// Caller passed mixed-type RRset; treat as malformed
			// rather than silently filtering.
			return CDSUpdate{Action: CDSActionUnknown},
				fmt.Errorf("%w: non-CDS RR in input (type=%d)", ErrCDSMalformed, rr.Type)
		}
		ds, err := dns.ParseDS(rr.RData)
		if err != nil {
			return CDSUpdate{Action: CDSActionUnknown},
				fmt.Errorf("%w: %v", ErrCDSMalformed, err)
		}
		out.DSRecords = append(out.DSRecords, ds)
	}

	// RFC 8078 §4: the "delete" sentinel is a SINGLE record with
	// Algorithm == 0. Any other shape with Algorithm == 0 (multiple
	// records, or one alg-0 mixed with normal algs) is malformed and
	// MUST be rejected — otherwise an attacker who can inject a
	// truncated CDS could downgrade an in-progress rollover.
	if len(out.DSRecords) == 1 && out.DSRecords[0].Algorithm == 0 {
		out.Action = CDSActionDelete
		return out, nil
	}
	for _, ds := range out.DSRecords {
		if ds.Algorithm == 0 {
			return CDSUpdate{Action: CDSActionUnknown},
				fmt.Errorf("%w: algorithm-0 sentinel must be the only record (RFC 8078 §4)", ErrCDSMalformed)
		}
	}
	out.Action = CDSActionPublish
	return out, nil
}

// ParseCDNSKEYRRset is the dual of ParseCDSRRset for CDNSKEY records.
// The classification logic mirrors RFC 8078 §4: a single record with
// Algorithm=0 (and protocol=3, flags=0 per §4) means "delete".
// Otherwise the records carry the child's desired DNSKEY set for the
// next delegation. Wire format == DNSKEY (RFC 7344 §3.2).
func ParseCDNSKEYRRset(rrs []dns.ResourceRecord) ([]*dns.DNSKEYRecord, CDSUpdateAction, error) {
	if len(rrs) == 0 {
		return nil, CDSActionUnknown, ErrCDSEmpty
	}
	keys := make([]*dns.DNSKEYRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Type != dns.TypeCDNSKEY {
			return nil, CDSActionUnknown,
				fmt.Errorf("%w: non-CDNSKEY RR in input (type=%d)", ErrCDSMalformed, rr.Type)
		}
		k, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			return nil, CDSActionUnknown,
				fmt.Errorf("%w: %v", ErrCDSMalformed, err)
		}
		keys = append(keys, k)
	}
	// RFC 8078 §4 delete sentinel for CDNSKEY: single record,
	// Algorithm=0, Protocol=3, Flags=0, PublicKey=0x00. We accept the
	// looser "single record with Algorithm==0" form to match the
	// CDS sentinel logic and because real-world signers vary in how
	// strictly they encode the marker bytes.
	if len(keys) == 1 && keys[0].Algorithm == 0 {
		return keys, CDSActionDelete, nil
	}
	for _, k := range keys {
		if k.Algorithm == 0 {
			return nil, CDSActionUnknown,
				fmt.Errorf("%w: algorithm-0 CDNSKEY must be the only record (RFC 8078 §4)", ErrCDSMalformed)
		}
	}
	return keys, CDSActionPublish, nil
}

// CDSMatchesParentDS reports whether the CDSUpdate's DS records are a
// SUPERSET of the parent's current DS RRset under structural equality
// (KeyTag + Algorithm + DigestType + Digest bytes). A "publish" CDS
// whose set equals the parent's existing DS is a no-op — useful to
// distinguish from a real rollover when surfacing the signal to an
// operator.
//
// Returns false unconditionally for CDSActionDelete (the parent's DS
// is supposed to disappear, not be matched).
func (u CDSUpdate) CDSMatchesParentDS(parentDS []*dns.DSRecord) bool {
	if u.Action != CDSActionPublish {
		return false
	}
	if len(parentDS) == 0 {
		return false
	}
	for _, p := range parentDS {
		found := false
		for _, c := range u.DSRecords {
			if dsRecordsEqual(p, c) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func dsRecordsEqual(a, b *dns.DSRecord) bool {
	if a == nil || b == nil {
		return false
	}
	if a.KeyTag != b.KeyTag || a.Algorithm != b.Algorithm || a.DigestType != b.DigestType {
		return false
	}
	return bytes.Equal(a.Digest, b.Digest)
}

var (
	// ErrCDSEmpty — empty input passed to a CDS/CDNSKEY parser. Distinct
	// from malformed so callers can choose to log differently.
	ErrCDSEmpty = errors.New("dnssec: CDS/CDNSKEY RRset is empty")
	// ErrCDSMalformed — input violates RFC 7344 / 8078 structural rules.
	// The CDSUpdate returned alongside is always Action=Unknown.
	ErrCDSMalformed = errors.New("dnssec: CDS/CDNSKEY RRset malformed")
)
