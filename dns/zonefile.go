package dns

// BIND-format zone file writer (RFC 1035 §5, RFC 3597 §5).
//
// A zone file is a presentation-format serialisation of a DNS zone: an SOA
// RR at the apex, followed by the rest of the apex records and delegations
// from apex, and optionally $INCLUDE directives and $TTL/$ORIGIN directives.
// This package implements the subset Labyrinth needs to round-trip the
// records it has loaded via AXFR/IXFR and the records it serves from the
// local zone table:
//
//   - one owner per line, with continuation in parentheses for long RDATA
//   - class IN is implicit; other classes are spelled out
//   - RFC 3597 §5 generic form for types Labyrinth does not model as a struct
//   - DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3) get their presentation
//     form from the dedicated rdata encoders already in this package
//   - characters outside the DNS master-file safe set (RFC 1035 §5.1) are
//     escaped with the backslash sequences BIND defines
//
// What is deliberately *not* here:
//
//   - $GENERATE, $INCLUDE — both are preprocessor directives Labyrinth has
//     no reason to emit. They can be added when a caller needs them.
//   - the "$TTL <seconds>" directive — every record carries its own TTL
//     field, and Labyrinth's writer is round-trip-oriented (input was an
//     XFR, not a hand-authored file). Emitting a $TTL would lose the
//     per-record TTL of any record shorter than the directive.
//
// # Why a separate writer rather than reusing the existing wire-format packer
//
// The wire-format code in Encoders.go is compressed and binary; BIND format
// is line-oriented and human-readable. The two diverge at the RDATA
// encoders (SOA RDATA is a structured tuple on the wire and a parenthesised
// keyword list in text), and an attempt to share them would force BIND
// syntax through the compression dictionary. So the writer is its own
// type, and so is the parser.
//
// The parser/writer pair is in dns/zonefile.go and dns/zonefile_parser.go;
// callers that want to read a BIND file into a slice of dns.ResourceRecord
// use ParseZoneFile, callers that want to write a slice back to BIND format
// use FormatZone.

import (
	"fmt"
	"sort"
	"strings"
)

// FormatZone writes a zone file in BIND master-file format.
//
// The records do not need to be sorted; the writer groups them by owner
// name. SOA records are emitted first at the apex (the zone's own name as
// the first Record argument), then NS, then everything else. Within one
// owner the records are emitted in the order given, except DNSSEC types
// (DNSKEY, DS, RRSIG, NSEC, NSEC3) which are emitted at the end of the
// owner block because BIND readers and tooling do not care about the
// ordering inside an owner but DNSKEY/DS precede RRSIG/NSEC/NSEC3 in
// DNSSEC-aware tooling.
//
// apex is the zone apex (e.g. "example.com." — the trailing dot is the
// presentation form). The writer starts the zone with a $TTL directive
// synthesised from the SOA's minimum TTL (or 86400 if no SOA is present)
// only if the caller has not supplied a $TTL; we do not synthesise one
// here because every record carries its own TTL.
//
// FormatZone returns the formatted text. Errors are only returned for
// RDATA the writer recognises as structurally broken (e.g. an SOA with
// fewer than five space-separated fields). Unknown RR types are emitted
// in RFC 3597 §5 generic form; the parser is responsible for round-trip.
//
func FormatZone(apex string, records []ResourceRecord) ([]byte, error) {
	// Group records by owner. The map keyed by lowercased name with the
	// trailing dot stripped — `$ORIGIN` is the canonical way to glue a
	// bare label to the apex, and the writer always emits the apex in
	// absolute form so a reader without $ORIGIN support can still parse.
	byOwner := make(map[string][]ResourceRecord)
	ownerOrder := []string{}
	for _, r := range records {
		owner := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if _, ok := byOwner[owner]; !ok {
			ownerOrder = append(ownerOrder, owner)
		}
		byOwner[owner] = append(byOwner[owner], r)
	}

	// Apex name with trailing dot for $ORIGIN keyboarding.
	apexLower := strings.TrimSuffix(strings.ToLower(apex), ".")

	// Per-owner ordering: SOA first, then NS, then DNSSEC, then everything else.
	var sb strings.Builder
	if apex != "" {
		// $TTL — set to the smallest TTL of any record in the zone, or
		// 86400 if none. This is a soft default; the per-record TTL
		// still wins on every line.
		var minTTL uint32 = 86400
		if len(records) > 0 {
			minTTL = records[0].TTL
			for _, r := range records {
				if r.TTL > 0 && r.TTL < minTTL {
					minTTL = r.TTL
				}
			}
		}
		// apex is the absolute zone name with a trailing dot. We rely
		// on that trailing dot in the SOA header; do not add another.
		apexDot := apex
		if !strings.HasSuffix(apexDot, ".") {
			apexDot += "."
		}
		fmt.Fprintf(&sb, "$TTL %d\n", minTTL)
		// The opener of the SOA — `<mname> <rname> (` — goes on the
		// header line. The five timers and the closing paren are emitted
		// immediately below, before the per-owner loop, so the SOA body
		// is contiguous in the output.
		soaRec := firstSOA(records)
		if soaRec != nil && len(soaRec.RData) > 0 {
			mname, rname := parseSOANames(soaRec.RData)
			fmt.Fprintf(&sb, "@\t%s\tSOA\t%s. %s. (\n",
				zoneClassText(soaRec.Class), escapeName(mname), escapeName(rname))
			if err := emitSOAMiddle(&sb, *soaRec); err != nil {
				return nil, err
			}
		} else {
			// No SOA present or the SOA record has no RDATA (some
			// operator-configured local zones strip the SOA). Emit a
			// placeholder so the file is still valid BIND; the parser
			// will see the literal "SOA" keyword and reject the zone
			// for lack of a serial. A real operator-facing tool would
			// warn here.
			fmt.Fprintf(&sb, "@\tIN\tSOA\t%s invalid. invalid. (\n", escapeName(apexDot))
		}
	}

	// Sort owners by suffix specificity: apex first, then explicit owners
	// in the records, longest suffix first. Local-zone ordering is a
	// different problem (handled by resolver.NewLocalZoneTable); this
	// ordering is just for the human-readable file.
	sort.SliceStable(ownerOrder, func(i, j int) bool {
		// Apex first.
		if ownerOrder[i] == apexLower {
			return true
		}
		if ownerOrder[j] == apexLower {
			return false
		}
		return len(ownerOrder[i]) > len(ownerOrder[j])
	})

	// Defer SOA; the writer already emitted the header above.
	for _, owner := range ownerOrder {
		if owner == apexLower {
			// Emit everything but the SOA at apex (the SOA was emitted
			// in the header so the $TTL directive it implies is visible
			// to a reader that processes directives lazily).
			others := []ResourceRecord{}
			for _, r := range byOwner[owner] {
				if r.Type == TypeSOA {
					continue
				}
				others = append(others, r)
			}
			if len(others) > 0 {
				if err := emitOwner(&sb, "@", others); err != nil {
					return nil, err
				}
			}
			continue
		}
		emit := ownerRelative(apexLower, owner)
		if err := emitOwner(&sb, emit, byOwner[owner]); err != nil {
			return nil, err
		}
	}

	return []byte(sb.String()), nil
}

func zoneClassText(class uint16) string {
	switch class {
	case ClassIN:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 254:
		return "NONE"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", class)
	}
}

// emitOwner writes one owner block.
func emitOwner(sb *strings.Builder, name string, records []ResourceRecord) error {
	// Per-owner ordering: NS first (because every delegation needs them
	// at the top of the block for human readers), then SOA, then DNSSEC,
	// then everything else, all stable.
	soa := []ResourceRecord{}
	ns := []ResourceRecord{}
	dnssec := []ResourceRecord{}
	other := []ResourceRecord{}
	for _, r := range records {
		switch r.Type {
		case TypeSOA:
			soa = append(soa, r)
		case TypeNS:
			ns = append(ns, r)
		case TypeDNSKEY, TypeDS, TypeRRSIG, TypeNSEC, TypeNSEC3:
			dnssec = append(dnssec, r)
		default:
			other = append(other, r)
		}
	}
	ordered := append(append(append(append([]ResourceRecord{}, ns...), soa...), dnssec...), other...)

	for _, r := range ordered {
		// SOA is special: the header line already opened the parens,
		// so emitting the SOA here writes the five timers and the
		// closing paren on a single continuation line.
		if r.Type == TypeSOA {
			if err := emitSOAMiddle(sb, r); err != nil {
				return err
			}
			continue
		}
		rdata, err := FormatRData(r)
		if err != nil {
			return fmt.Errorf("zone %q owner %q type %d: %w", name, r.Name, r.Type, err)
		}
		ttl := r.TTL
		if ttl == 0 {
			ttl = 86400
		}
		// Owner | TTL | CLASS | TYPE | RDATA
		// The class column is unconditional so the file is unambiguous
		// even if a future record carries a non-IN class.
		fmt.Fprintf(sb, "%s\t%d\t%s\t%s\t%s\n",
			name, ttl, zoneClassText(r.Class), TypeName(r.Type), rdata)
	}
	return nil
}

// emitSOAMiddle writes the five timers of a single SOA record and the
// closing paren, in the parenthesised form the FormatZone header opened.
// Each timer gets a BIND-style inline comment so the file is human-
// readable without losing the structured parseability.
//
func emitSOAMiddle(sb *strings.Builder, r ResourceRecord) error {
	rec, err := ParseSOA(r.RData, 0)
	if err != nil {
		return fmt.Errorf("SOA RDATA: %w", err)
	}
	fmt.Fprintf(sb, "\t\t%d\t; serial\n\t\t%d\t; refresh\n\t\t%d\t; retry\n\t\t%d\t; expire\n\t\t%d\t; minimum\n\t\t)\n",
		rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minimum)
	return nil
}

// parseSOANames extracts the two name fields from a wire-format SOA RDATA.
// The rest of the record is laid out by emitSOAMiddle;
// this helper is only used to produce the header opener.
//
func parseSOANames(rdata []byte) (mname, rname string) {
	// SOA RDATA: mname, rname, serial, refresh, retry, expire, minimum.
	// mname and rname are wire-format names; we parse them with the
	// existing ParseNS helper that takes a single name.
	off := 0
	m, err := ParseNS(rdata, off)
	if err == nil {
		mname = m
		adv, olen := nameLen(rdata, off)
		off += adv + olen
		r, err := ParseNS(rdata, off)
		if err == nil {
			rname = r
		}
	}
	return mname, rname
}

// nameLen returns the consumed byte length of a wire-format name at
// offset off, including the terminating zero byte. The companion
// helpers in the dns package assume an offset-relative parse and
// currently do not report the consumed length; this thin wrapper
// does it locally so parseSOANames can step through two names.
//
func nameLen(b []byte, off int) (adv, olen int) {
	// Loop through labels until the zero terminator.
	for off < len(b) {
		l := int(b[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			// Compression pointer — not expected in SOA RDATA, but
			// avoid a runaway loop on malformed input.
			break
		}
		off += 1 + l
	}
	return off, 0
}

// firstSOA returns the first SOA record from a slice, or nil if there
// are none. The lookup is O(n) in the caller's slice; the records are
// typically few at the apex so this is fine.
//
func firstSOA(records []ResourceRecord) *ResourceRecord {
	for i := range records {
		if records[i].Type == TypeSOA {
			return &records[i]
		}
	}
	return nil
}

// ownerRelative returns the relative owner name to emit at the start of a
// record line. If the owner equals the apex, "@" is returned. Otherwise
// the apex suffix is stripped from the owner and the remaining prefix is
// returned. If the owner is not under the apex, it is emitted in absolute
// form.
func ownerRelative(apex, owner string) string {
	if owner == apex {
		return "@"
	}
	if strings.HasSuffix(owner, "."+apex) {
		return owner[:len(owner)-len(apex)-1]
	}
	return owner + "."
}

// escapeName performs BIND master-file escaping on a domain name. Per
// RFC 1035 §5.1, a dot inside a label terminates it; a backslash escapes
// the next character. The hyphen, underscore, and digits are taken
// literally because they cannot appear in a DNS label except as ordinary
// characters. The space and other control characters get backslash-escaped.
func escapeName(name string) string {
	var sb strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.':
			sb.WriteByte('.')
		case c == '\\':
			sb.WriteString(`\\`)
		case c == ' ':
			sb.WriteString(`\ `)
		case c >= 0x21 && c <= 0x7E && c != '"' && c != ';':
			// Printable ASCII, not the master-file comment (;) or
			// string (") delimiters.
			sb.WriteByte(c)
		default:
			// Non-printable or special: emit the decimal escape.
			fmt.Fprintf(&sb, "\\%03d", c)
		}
	}
	return sb.String()
}
