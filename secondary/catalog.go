package secondary

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// Catalog zones (RFC 9432).
//
// A catalog zone solves a provisioning problem, not a resolution one. Without
// it, adding a zone to a fleet of secondaries means editing every secondary's
// configuration and reloading each one — so the set of zones a server holds
// drifts from what the operator believes it holds, one missed host at a time.
// A catalog zone turns that into ordinary DNS: the primary publishes a zone
// whose *contents* are a list of other zones, secondaries transfer it like any
// other zone, and each one provisions the members it names.
//
// # The format is deliberately strange
//
// A catalog zone is a normal DNS zone carrying no useful DNS data. Member
// zones appear as PTR records under `zones.<catalog>`:
//
//	<unique-id>.zones.catalog.example.  IN PTR  member.example.
//
// The unique-id label is opaque and exists only so two entries can coexist
// while being edited independently — it carries no meaning and must not be
// interpreted (RFC 9432 §4.3.1). Properties hang off the same owner name:
//
//	group.<unique-id>.zones.catalog.example.  IN TXT  "internal"
//
// # The version property is a hard gate
//
// RFC 9432 §4.2.2 requires `version.<catalog> TXT "2"` and says a catalog
// whose version is absent or unrecognised MUST NOT be processed. That is
// stricter than it first appears and the strictness is the point: a future
// catalog format could reuse the same record shapes with different meanings,
// and a consumer that processed it anyway would provision the wrong zones —
// silently, since every record would parse. So an unversioned catalog yields
// an error rather than an empty member list, and the manager keeps serving
// whatever it had rather than treating the catalog as newly empty.

// CatalogVersion is the only catalog schema version defined (RFC 9432 §4.2.2).
const CatalogVersion = "2"

var (
	// ErrCatalogNoVersion is returned when the version property is missing.
	// Distinct from a parse failure: a catalog with no version is
	// well-formed DNS that must not be acted on.
	ErrCatalogNoVersion = errors.New("catalog: no version property — RFC 9432 §4.2.2 requires version.<catalog> TXT")
	// ErrCatalogBadVersion is returned for a version this build does not
	// implement.
	ErrCatalogBadVersion = errors.New("catalog: unsupported catalog version")
)

// MemberZone is one zone listed by a catalog.
type MemberZone struct {
	// Name is the member zone's name, from the PTR record's target.
	Name string
	// UniqueID is the opaque label the entry lives under. Kept for logging
	// and for change-of-ownership handling; it carries no meaning and must
	// not be parsed (RFC 9432 §4.3.1).
	UniqueID string
	// Group is the optional group property (RFC 9432 §5.1). The RFC leaves
	// its use implementation-defined; here it is surfaced for logging and
	// for operators to key their own conventions on.
	Group string
}

// ParseCatalog extracts the member zones from a transferred catalog zone.
//
// `catalogName` is the catalog zone's own apex, needed because every owner
// name in the zone is interpreted relative to it.
//
// Returns an error rather than an empty list when the catalog cannot be
// processed. The distinction matters to the caller: "this catalog lists no
// zones" is an instruction to withdraw everything, while "this catalog cannot
// be understood" must leave the current provisioning alone.
func ParseCatalog(catalogName string, records []dns.ResourceRecord) ([]MemberZone, error) {
	catalogName = normaliseZone(catalogName)
	if catalogName == "" {
		return nil, errors.New("catalog: empty catalog zone name")
	}

	versionOwner := "version." + catalogName
	zonesSuffix := ".zones." + catalogName

	var (
		version   string
		seenVer   bool
		members   = map[string]*MemberZone{} // unique-id -> member
		groups    = map[string]string{}      // unique-id -> group
		nameSeen  = map[string]string{}      // member zone name -> unique-id that claimed it
		duplicate []string
	)

	for _, rr := range records {
		owner := normaliseZone(rr.Name)

		if rr.Type == dns.TypeTXT && owner == versionOwner {
			strs, err := dns.ParseTXT(rr.RData)
			if err != nil || len(strs) == 0 {
				continue
			}
			version, seenVer = strs[0], true
			continue
		}

		// Everything else of interest lives under `*.zones.<catalog>`.
		if !strings.HasSuffix(owner, zonesSuffix) {
			continue
		}
		prefix := strings.TrimSuffix(owner, zonesSuffix)
		if prefix == "" {
			continue
		}
		labels := strings.Split(prefix, ".")

		switch {
		case len(labels) == 1 && rr.Type == dns.TypePTR:
			// <unique-id>.zones.<catalog> PTR <member zone>
			target, err := dns.ParsePTR(rr.RData, 0)
			if err != nil {
				continue
			}
			member := normaliseZone(target)
			if member == "" {
				continue
			}
			id := labels[0]
			// RFC 9432 §4.3.1: a zone should be listed once. A duplicate
			// is not a fatal error — the rest of the catalog is still
			// usable — but silently provisioning it twice would leave two
			// transfer loops fighting over one zone's data.
			if prev, dup := nameSeen[member]; dup {
				duplicate = append(duplicate, fmt.Sprintf("%s (ids %s, %s)", member, prev, id))
				continue
			}
			nameSeen[member] = id
			members[id] = &MemberZone{Name: member, UniqueID: id}

		case len(labels) == 2 && labels[0] == "group" && rr.Type == dns.TypeTXT:
			// group.<unique-id>.zones.<catalog> TXT "<group>"
			strs, err := dns.ParseTXT(rr.RData)
			if err != nil || len(strs) == 0 {
				continue
			}
			groups[labels[1]] = strs[0]
		}
	}

	if !seenVer {
		return nil, ErrCatalogNoVersion
	}
	if version != CatalogVersion {
		return nil, fmt.Errorf("%w: %q (this build implements %q)",
			ErrCatalogBadVersion, version, CatalogVersion)
	}

	out := make([]MemberZone, 0, len(members))
	for id, mz := range members {
		mz.Group = groups[id]
		out = append(out, *mz)
	}
	// Sorted so logs and reconciliation are deterministic across transfers;
	// map iteration order would otherwise make every refresh look different.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	if len(duplicate) > 0 {
		return out, fmt.Errorf("catalog: duplicate member zones ignored: %s",
			strings.Join(duplicate, ", "))
	}
	return out, nil
}

// normaliseZone lowercases a name and strips the trailing dot, matching how
// zone names are compared everywhere else in the resolver (RFC 4343).
func normaliseZone(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
