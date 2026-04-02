package web

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// formatRData converts raw DNS RDATA bytes to a human-readable string.
func formatRData(rr dns.ResourceRecord) string {
	switch rr.Type {
	case dns.TypeA:
		ip, err := dns.ParseA(rr.RData)
		if err == nil {
			return ip.String()
		}
	case dns.TypeAAAA:
		ip, err := dns.ParseAAAA(rr.RData)
		if err == nil {
			return ip.String()
		}
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
		name, _, err := dns.DecodeName(rr.RData, 0)
		if err == nil {
			return name
		}
	case dns.TypeMX:
		mx, err := dns.ParseMX(rr.RData, 0)
		if err == nil {
			return fmt.Sprintf("%d %s", mx.Preference, mx.Exchange)
		}
	case dns.TypeTXT:
		txts, err := dns.ParseTXT(rr.RData)
		if err == nil {
			return strings.Join(txts, " ")
		}
	case dns.TypeSOA:
		soa, err := dns.ParseSOA(rr.RData, 0)
		if err == nil {
			return fmt.Sprintf("%s %s %d %d %d %d %d",
				soa.MName, soa.RName, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
		}
	case dns.TypeSRV:
		srv, err := dns.ParseSRV(rr.RData, 0)
		if err == nil {
			return fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target)
		}
	}
	// Fallback: hex-encode raw RDATA
	return hex.EncodeToString(rr.RData)
}

// stringToType maps type name strings to DNS type constants.
var stringToType = map[string]uint16{
	"A":     dns.TypeA,
	"NS":    dns.TypeNS,
	"CNAME": dns.TypeCNAME,
	"SOA":   dns.TypeSOA,
	"PTR":   dns.TypePTR,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"AAAA":  dns.TypeAAAA,
	"SRV":   dns.TypeSRV,
}

// handleCacheStats handles GET /api/cache/stats.
func (s *AdminServer) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	stats := s.cache.DetailedStats()
	snap := s.metrics.Snapshot()

	hitRate := float64(0)
	total := snap.CacheHits + snap.CacheMisses
	if total > 0 {
		hitRate = float64(snap.CacheHits) / float64(total) * 100
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"entries":          stats.Entries,
		"positive_entries": stats.PositiveEntries,
		"negative_entries": stats.NegativeEntries,
		"hits":             snap.CacheHits,
		"misses":           snap.CacheMisses,
		"evictions":        snap.CacheEvictions,
		"hit_rate":         hitRate,
	})
}

// handleCacheLookup handles GET /api/cache/lookup?name=X&type=A.
func (s *AdminServer) handleCacheLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	name := r.URL.Query().Get("name")
	typeStr := r.URL.Query().Get("type")

	if name == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing name parameter"})
		return
	}
	if typeStr == "" {
		typeStr = "A"
	}

	qtype, ok := stringToType[strings.ToUpper(typeStr)]
	if !ok {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "unsupported query type"})
		return
	}

	entry, found := s.cache.Lookup(name, qtype, dns.ClassIN)
	if !found {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}

	// Format records for JSON
	records := make([]map[string]interface{}, 0, len(entry.Records))
	for _, rr := range entry.Records {
		records = append(records, map[string]interface{}{
			"name":  rr.Name,
			"type":  dns.TypeToString[rr.Type],
			"ttl":   rr.TTL,
			"rdata": formatRData(rr),
		})
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"name":     name,
		"type":     typeStr,
		"records":  records,
		"negative": entry.Negative,
		"ttl":      entry.RemainingTTL(),
	})
}

// handleCacheFlush handles POST /api/cache/flush.
func (s *AdminServer) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	s.cache.Flush()
	s.logger.Info("cache flushed via admin API")

	jsonResponse(w, http.StatusOK, map[string]string{"status": "flushed"})
}

// handleCacheDelete handles DELETE /api/cache/entry?name=X&type=A.
func (s *AdminServer) handleCacheDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	name := r.URL.Query().Get("name")
	typeStr := r.URL.Query().Get("type")

	if name == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing name parameter"})
		return
	}
	if typeStr == "" {
		typeStr = "A"
	}

	qtype, ok := stringToType[strings.ToUpper(typeStr)]
	if !ok {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "unsupported query type"})
		return
	}

	deleted := s.cache.Delete(name, qtype, dns.ClassIN)
	if !deleted {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}

	s.logger.Info("cache entry deleted via admin API", "name", name, "type", typeStr)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}
