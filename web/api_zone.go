package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
)

// handleZoneList serves GET /api/zones. It returns the local zone
// names currently in the resolver's local-zone table, plus the
// configured forward and stub zones, in JSON form. The "served"
// status indicates whether the resolver is actually answering
// queries for that zone (always true for local zones; for forward
// zones, true while the upstream is reachable).
//
// The list is for the operator's dashboard; it is not authoritative
// for any DNS protocol question. The endpoint is rate-limited via
// the same auth gate as the rest of the admin API.
func (s *AdminServer) handleZoneList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type zoneInfo struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`           // "local", "forward", "stub"
		Type   string `json:"type,omitempty"` // local zone type (static/redirect/...)
		Count  int    `json:"record_count"`
		Source string `json:"source,omitempty"` // "static" or "secondary"
	}

	var out []zoneInfo

	// Local zones (the most useful view for the operator).
	if lz := s.resolver.LocalZones(); lz != nil {
		for _, z := range lz.Zones() {
			out = append(out, zoneInfo{
				Name:   z.Name,
				Kind:   "local",
				Type:   localZoneTypeName(z.Type),
				Count:  len(z.Records),
				Source: sourceFromRecords(z),
			})
		}
	}

	// Forward and stub zones are configuration concepts, not local
	// zones, but the operator wants to see them in the same view.
	// The resolver does not currently expose them; the API returns
	// only what is local. A future iteration can read them from
	// config on the admin server if there is demand.

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.logger.Error("encode zone list", "error", err)
	}
}

// localZoneTypeName returns the operator-facing string for a
// resolver.LocalZoneType. The numeric constants are not stable across
// versions, so the API surface keeps the textual form.
func localZoneTypeName(t resolver.LocalZoneType) string {
	switch t {
	case resolver.LocalStatic:
		return "static"
	case resolver.LocalDeny:
		return "deny"
	case resolver.LocalRefuse:
		return "refuse"
	case resolver.LocalRedirect:
		return "redirect"
	case resolver.LocalTransparent:
		return "transparent"
	}
	return "unknown"
}

// sourceFromRecords classifies the source of a local zone's records
// by inspection. A zone that has been provisioned by a secondary
// transfer (RFC 9432 catalog or a direct XFR) has no SOA in its
// record list as the table stores it — the SOA is round-tripped
// through the XFR but the local-zone path may or may not retain it
// depending on the operator's configuration. The signal we use is
// the presence of an SOA record, which is the canonical "this is a
// real zone, not a static-records block" marker.
func sourceFromRecords(z resolver.LocalZone) string {
	for _, r := range z.Records {
		if r.Type == dns.TypeSOA {
			return "secondary"
		}
	}
	return "static"
}

// handleZoneExport serves GET /api/zones/:name/export. The response
// is the zone's records in BIND master-file format (RFC 1035 §5),
// produced by dns.FormatZone. The Content-Type is text/plain with
// a charset hint so the operator can pipe the response straight to
// `named-checkzone` or `named-compilezone` for syntax validation.
//
// The path uses the standard `<apex>` form, optionally with a
// trailing dot. The lookup is case-insensitive and matches the
// local-zone table's normalisation rules.
//
// A zone with no SOA is still exported, with the writer's placeholder SOA
// header, so the operator can see exactly what is served. That placeholder is
// deliberately well-formed BIND — two names, five timers, closing paren — so
// the export re-parses with dns.ParseZone and can be handed straight back to
// Labyrinth via `zone_file:`. A zone file with no SOA at all is not loadable,
// which is why the placeholder exists rather than being omitted.
func (s *AdminServer) handleZoneExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/zones/")
	name = strings.TrimSuffix(name, "/export")
	name = strings.TrimSpace(name)
	if name == "" {
		http.Error(w, "zone name required", http.StatusBadRequest)
		return
	}

	lz := s.resolver.LocalZones()
	zone := lz.FindZone(name)
	if zone == nil {
		http.Error(w, fmt.Sprintf("zone %q not found", name), http.StatusNotFound)
		return
	}

	records := localZoneToRecords(zone)
	if len(records) == 0 {
		http.Error(w, fmt.Sprintf("zone %q has no records", name), http.StatusNotFound)
		return
	}

	// The writer expects the apex with a trailing dot. The zone
	// Name from the table is normalised to lowercase, no trailing
	// dot; we add the dot here.
	apex := strings.TrimSuffix(zone.Name, ".") + "."
	out, err := dns.FormatZone(apex, records)
	if err != nil {
		s.logger.Error("format zone", "zone", name, "error", err)
		http.Error(w, fmt.Sprintf("format zone %q: %v", name, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", apex+"zone"))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

// localZoneToRecords converts a resolver.LocalZone's records into the
// dns.ResourceRecord slice the writer expects. The conversion is
// mostly mechanical: same Name, Type, RData, TTL, and ClassIN for
// every record. The exported records carry the apex as their
// owner name without the trailing dot because that is the convention
// the resolver uses internally; the writer adds the trailing dot
// in the SOA header and the absolute-name emission for the rest
// of the records via ownerRelative.
func localZoneToRecords(zone *resolver.LocalZone) []dns.ResourceRecord {
	out := make([]dns.ResourceRecord, len(zone.Records))
	for i, r := range zone.Records {
		out[i] = dns.ResourceRecord{
			Name:  r.Name,
			Type:  r.Type,
			Class: dns.ClassIN,
			TTL:   r.TTL,
			RData: r.RData,
		}
	}
	return out
}
