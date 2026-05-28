package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/dnssec"
)

// handleDNSSEC handles GET /api/dnssec — operator-facing DNSSEC state.
// Surfaces:
//
//   - The active Negative Trust Anchor list (RFC 7646), including
//     expired entries that have not yet been swept by Cleanup. The
//     UI uses this to render a status row per NTA with the remaining
//     validity window or "expired".
//   - NTA match counter (cumulative validations short-circuited by
//     an active NTA). Same number the metrics endpoint exposes;
//     mirrored here so the UI can render it without separately
//     polling Prometheus text format.
//   - Whether DNSSEC validation is enabled on the resolver, plus the
//     SHA-1 acceptance toggle. Without these the operator cannot tell
//     a missing NTA list from a missing validator.
//
// Returns 200 with an empty payload (all zero-valued) when the
// resolver is up but DNSSEC is not enabled; the UI handles that as
// "DNSSEC off" rather than "API broken".
func (s *AdminServer) handleDNSSEC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	resp := map[string]interface{}{
		"enabled":     false,
		"allow_sha1":  false,
		"nta_count":   0,
		"nta_matches": int64(0),
		"ntas":        []interface{}{},
	}

	if s.resolver == nil {
		jsonResponse(w, http.StatusOK, resp)
		return
	}
	v := s.resolver.DNSSECValidator()
	if v == nil {
		jsonResponse(w, http.StatusOK, resp)
		return
	}
	resp["enabled"] = true
	resp["allow_sha1"] = v.SHA1Allowed()
	resp["nta_matches"] = v.NTAMatches()

	store := v.NTAStore()
	if store == nil {
		jsonResponse(w, http.StatusOK, resp)
		return
	}
	now := time.Now()
	entries := store.List()
	ntas := make([]map[string]interface{}, 0, len(entries))
	for _, nta := range entries {
		state := "active"
		if !nta.Expiry.After(now) {
			state = "expired"
		}
		ntas = append(ntas, map[string]interface{}{
			"zone":             nta.Zone,
			"expires_at":       nta.Expiry.Format(time.RFC3339),
			"expires_in_seconds": int64(nta.Expiry.Sub(now).Seconds()),
			"reason":           nta.Reason,
			"state":            state,
		})
	}
	resp["nta_count"] = len(ntas)
	resp["ntas"] = ntas
	jsonResponse(w, http.StatusOK, resp)
}

// addNTARequest is the POST body for installing a new NTA at runtime.
// The expiry is operator-chosen RFC3339; we reject already-past
// timestamps so a typo cannot accidentally install a permanently-
// inactive entry that the operator thinks is doing work.
type addNTARequest struct {
	Zone           string `json:"zone"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	DurationHours  int    `json:"duration_hours,omitempty"`
	Reason         string `json:"reason"`
}

// handleNTAAdd handles POST /api/dnssec/nta — installs a single NTA
// at runtime without requiring a config reload. Two ways to specify
// expiry: explicit RFC3339 `expires_at` or a `duration_hours` offset
// from now. The latter is the operator UI shortcut for incident
// response ("disable validation for 4 hours, file a ticket, sleep").
// Bounded — values <= 0 or > 30 days are clamped to 30 days. RFC 7646
// §6 — bounded lifetime is the entire safety story.
//
// Authentication: protected by requireAuth; only the local operator
// (token holder) can install NTAs.
func (s *AdminServer) handleNTAAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.resolver == nil || s.resolver.DNSSECValidator() == nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "DNSSEC validator not enabled"})
		return
	}
	v := s.resolver.DNSSECValidator()
	store := v.NTAStore()
	if store == nil {
		// Validator is enabled but no NTA store was wired (operator did
		// not set the config key). Create one now so the runtime
		// install path is usable without a restart.
		store = dnssec.NewNTAStore()
		v.SetNTAStore(store)
	}

	var req addNTARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	zone := strings.TrimSpace(req.Zone)
	if zone == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "zone is required"})
		return
	}

	var expiry time.Time
	switch {
	case req.ExpiresAt != "":
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "expires_at: " + err.Error()})
			return
		}
		expiry = t
	case req.DurationHours > 0:
		// Clamp to the 30-day RFC 7646 guidance ceiling so a UI typo
		// (1000 vs 100 hours) cannot install a multi-year override.
		hours := req.DurationHours
		const maxHours = 24 * 30
		if hours > maxHours {
			hours = maxHours
		}
		expiry = time.Now().Add(time.Duration(hours) * time.Hour)
	default:
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "expires_at or duration_hours required"})
		return
	}

	if !expiry.After(time.Now()) {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "expiry is already in the past"})
		return
	}

	store.Add(zone, expiry, req.Reason)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"zone":       zone,
		"expires_at": expiry.Format(time.RFC3339),
	})
}

// handleNTARemove handles DELETE /api/dnssec/nta?zone=example.test —
// removes an NTA. Returns 404 if the zone is not in the store. Idempotent
// on the operator-experience side: the UI does not need to re-fetch
// before deleting.
func (s *AdminServer) handleNTARemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.resolver == nil || s.resolver.DNSSECValidator() == nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "DNSSEC validator not enabled"})
		return
	}
	store := s.resolver.DNSSECValidator().NTAStore()
	if store == nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "no NTA store configured"})
		return
	}
	zone := strings.TrimSpace(r.URL.Query().Get("zone"))
	if zone == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "zone query parameter required"})
		return
	}
	removed := store.Remove(zone)
	if !removed {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "no NTA for zone " + zone})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "zone": zone})
}
