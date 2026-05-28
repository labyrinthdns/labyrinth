package web

import (
	"net/http"
	"time"
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
