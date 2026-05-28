package web

import (
	"net/http"
	"strconv"
)

// handleSecurity handles GET /api/security — operator-facing security
// posture snapshot. Surfaces the three knobs that materially affect
// whether the resolver can be abused as an amplifier or weaponised
// against a downstream target:
//
//   - DNS Cookies (RFC 7873 + RFC 9018): on/off + strict §5.4 mode.
//     BADCOOKIE-rejected count comes from the responses_by_rcode
//     bucket — a non-zero value with enforce=false means clients are
//     speaking cookies and getting stale rotations rejected; the
//     same number with enforce=true means spoofed UDP is being
//     refused. The label alone doesn't disambiguate; the UI shows
//     both flags so the operator can interpret the count.
//   - Rate limiting (per-IP query budget): drops + configured rate.
//   - RRL (RFC-style per-prefix response rate limiting): drops +
//     SLIP TC responses. Distinct from the per-IP rate-limit above
//     because it bins by /24 (v4) or /56 (v6) and bins responses by
//     class (NXDOMAIN, error, referral, identical-answer) — that's
//     the standard amplification-defence shape, not a "user fairness"
//     limit.
//   - Refused-by-ACL count, blocked-by-blocklist count.
//
// Returns 200 with all-zero values when the resolver / metrics are
// not wired (e.g. early startup) so the UI handles that as "not yet
// initialised" rather than "API broken".
func (s *AdminServer) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	resp := map[string]interface{}{
		"cookies": map[string]interface{}{
			"enabled":             s.config != nil && s.config.Security.DNSCookies,
			"enforce_strict_udp":  s.config != nil && s.config.Security.DNSCookiesEnforce,
			"badcookie_responses": int64(0),
		},
		"rate_limit": map[string]interface{}{
			"enabled":            s.config != nil && s.config.Security.RateLimit.Enabled,
			"rate_per_second":    float64(0),
			"burst":              0,
			"rate_limited_total": int64(0),
		},
		"rrl": map[string]interface{}{
			"enabled":              s.config != nil && s.config.Security.RRL.Enabled,
			"responses_per_second": float64(0),
			"slip_ratio":           0,
			"ipv4_prefix":          0,
			"ipv6_prefix":          0,
		},
		"acl_refused_total":      int64(0),
		"blocklist_blocked_total": int64(0),
		// UI-M6.3 — per-EDE-code emission counters (RFC 8914 §4).
		// Map of "code" → emission count. Empty when no EDE has been
		// emitted yet — the UI shows that as "no diagnostic emissions
		// recorded" rather than "API broken". String keys (not uint16)
		// so the JSON shape is stable across language clients.
		"ede_counts": map[string]int64{},
	}

	if s.config != nil {
		resp["rate_limit"].(map[string]interface{})["rate_per_second"] = s.config.Security.RateLimit.Rate
		resp["rate_limit"].(map[string]interface{})["burst"] = s.config.Security.RateLimit.Burst
		resp["rrl"].(map[string]interface{})["responses_per_second"] = s.config.Security.RRL.ResponsesPerSecond
		resp["rrl"].(map[string]interface{})["slip_ratio"] = s.config.Security.RRL.SlipRatio
		resp["rrl"].(map[string]interface{})["ipv4_prefix"] = s.config.Security.RRL.IPv4Prefix
		resp["rrl"].(map[string]interface{})["ipv6_prefix"] = s.config.Security.RRL.IPv6Prefix
	}

	if s.metrics != nil {
		// EDE breakdown — convert uint16 keys to strings so JSON
		// consumers can use them as map keys without coercion.
		edeCounts := s.metrics.EDECounts()
		if len(edeCounts) > 0 {
			out := make(map[string]int64, len(edeCounts))
			for code, n := range edeCounts {
				out[strconv.FormatUint(uint64(code), 10)] = n
			}
			resp["ede_counts"] = out
		}

		snap := s.metrics.Snapshot()
		// BADCOOKIE rejections sit in the responses_by_rcode bucket
		// (handler.go emits IncResponses("BADCOOKIE") for both the
		// stale-cookie and §5.4 strict-mode paths). The combined
		// figure is the right shape for the operator's question
		// "how much is my cookie defence doing" — both reasons
		// fire the same downstream consequence (client retries).
		if v, ok := snap.ResponsesByRCode["BADCOOKIE"]; ok {
			resp["cookies"].(map[string]interface{})["badcookie_responses"] = v
		}
		resp["rate_limit"].(map[string]interface{})["rate_limited_total"] = snap.RateLimited
		resp["blocklist_blocked_total"] = snap.BlockedQueries
		if v, ok := snap.ResponsesByRCode["REFUSED"]; ok {
			resp["acl_refused_total"] = v
		}
	}

	jsonResponse(w, http.StatusOK, resp)
}
