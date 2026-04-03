package web

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
)

const clusterFanoutHeader = "X-Labyrinth-Cluster-Fanout"

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
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR, dns.TypeDNAME:
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
	"DNAME": dns.TypeDNAME,
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

	typeUpper := strings.ToUpper(typeStr)

	// ALL: return all cached types for this name
	if typeUpper == "ALL" {
		entries := s.cache.LookupAll(name, dns.ClassIN)
		if len(entries) == 0 {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "no entries found"})
			return
		}

		var results []map[string]interface{}
		for _, entry := range entries {
			records := make([]map[string]interface{}, 0, len(entry.Records))
			entryType := ""
			for _, rr := range entry.Records {
				if entryType == "" {
					entryType = dns.TypeToString[rr.Type]
				}
				records = append(records, map[string]interface{}{
					"name":  rr.Name,
					"type":  dns.TypeToString[rr.Type],
					"ttl":   rr.TTL,
					"rdata": formatRData(rr),
				})
			}
			if entryType == "" {
				entryType = "UNKNOWN"
			}
			results = append(results, map[string]interface{}{
				"name":     name,
				"type":     entryType,
				"records":  records,
				"negative": entry.Negative,
				"ttl":      entry.RemainingTTL(),
			})
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"name":    name,
			"type":    "ALL",
			"entries": results,
		})
		return
	}

	qtype, ok := stringToType[typeUpper]
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

func normalizePeerBase(base string) string {
	base = strings.TrimSpace(base)
	base = strings.TrimRight(base, "/")
	return base
}

func cacheFlushURL(peer config.ClusterPeerConfig) string {
	base := normalizePeerBase(peer.APIBase)
	if base == "" {
		return ""
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return ""
	}
	return base + "/api/cache/flush"
}

func (s *AdminServer) fanoutCacheFlush() (int, int) {
	okCount, failCount := 0, 0
	client := &http.Client{Timeout: 5 * time.Second}

	for _, peer := range s.config.Cluster.Peers {
		if !peer.Enabled {
			continue
		}
		target := cacheFlushURL(peer)
		if target == "" {
			failCount++
			s.logger.Warn("cluster peer has invalid api_base", "peer", peer.Name, "api_base", peer.APIBase)
			continue
		}

		req, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			failCount++
			s.logger.Warn("failed to build cluster cache flush request", "peer", peer.Name, "error", err)
			continue
		}
		req.Header.Set(clusterFanoutHeader, "1")
		if strings.TrimSpace(peer.APIToken) != "" {
			req.Header.Set("Authorization", "Bearer "+peer.APIToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			failCount++
			s.logger.Warn("cluster cache flush request failed", "peer", peer.Name, "error", err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			okCount++
		} else {
			failCount++
			s.logger.Warn("cluster cache flush returned non-2xx", "peer", peer.Name, "status", resp.StatusCode)
		}
	}

	return okCount, failCount
}

// handleCacheFlush handles POST /api/cache/flush.
func (s *AdminServer) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	s.cache.Flush()
	s.logger.Info("cache flushed via admin API")
	fromPeer := r.Header.Get(clusterFanoutHeader) == "1"
	fanoutOK, fanoutFailed := 0, 0
	if !fromPeer && s.config.Cluster.Enabled && s.config.Cluster.Actions.FanoutCacheFlush {
		fanoutOK, fanoutFailed = s.fanoutCacheFlush()
		s.logger.Info("cluster cache flush fanout completed", "ok", fanoutOK, "failed", fanoutFailed)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "flushed",
		"cluster_fanout": map[string]interface{}{
			"attempted": fanoutOK + fanoutFailed,
			"ok":        fanoutOK,
			"failed":    fanoutFailed,
			"skipped":   fromPeer || !s.config.Cluster.Enabled || !s.config.Cluster.Actions.FanoutCacheFlush,
		},
	})
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

// handleNegativeCache handles GET /api/cache/negative — returns negative cache entries.
func (s *AdminServer) handleNegativeCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	entries := s.cache.NegativeEntries(limit)
	if entries == nil {
		entries = []cache.NegativeEntryInfo{}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}
