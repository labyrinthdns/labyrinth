package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/labyrinthdns/labyrinth/dns"
)

// trustChainLevel represents one level in the DNSSEC delegation chain.
type trustChainLevel struct {
	Zone    string       `json:"zone"`
	Status  string       `json:"status"` // "secure", "insecure", "bogus", "unreachable"
	DNSKEYs []dnskeyInfo `json:"dnskey,omitempty"`
	DS      []dsInfo     `json:"ds,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type dnskeyInfo struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	KeyTag    uint16 `json:"key_tag"`
	ZoneKey   bool   `json:"zone_key"`
	KeyData   string `json:"key_data"`
}

type dsInfo struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

// handleTrustChain handles GET /api/dnssec/trustchain?name=example.com
// Returns the DNSSEC delegation chain from root to the queried name.
func (s *AdminServer) handleTrustChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "name query parameter required"})
		return
	}

	if s.resolver == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"name":   name,
			"levels": []trustChainLevel{},
		})
		return
	}

	chain := s.buildTrustChain(name)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"name":   name,
		"levels": chain,
	})
}

// buildTrustChain walks the delegation labels of name from the root downward,
// fetching DNSKEY records at each zone and DS records from each parent via
// the resolver's DNSSEC-aware query path (which caches results).
func (s *AdminServer) buildTrustChain(name string) []trustChainLevel {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}

	// Build the zone list: root, then each label from right to left.
	labels := strings.Split(name, ".")
	zones := make([]string, 0, len(labels)+1)
	zones = append(zones, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		zones = append(zones, strings.Join(labels[i:], "."))
	}

	levels := make([]trustChainLevel, 0, len(zones))

	for i, zone := range zones {
		level := trustChainLevel{Zone: zone, Status: "unknown"}

		// Fetch DNSKEY records for this zone via the DNSSEC query path.
		dnskeyMsg, dnskeyErr := s.resolver.QueryDNSSEC(zone, dns.TypeDNSKEY, dns.ClassIN)
		if dnskeyErr == nil && dnskeyMsg != nil {
			for _, rr := range dnskeyMsg.Answers {
				if rr.Type != dns.TypeDNSKEY {
					continue
				}
				k, parseErr := dns.ParseDNSKEY(rr.RData)
				if parseErr != nil {
					continue
				}
				keyType := k.Flags == 257
				level.DNSKEYs = append(level.DNSKEYs, dnskeyInfo{
					Flags:     k.Flags,
					Protocol:  k.Protocol,
					Algorithm: k.Algorithm,
					KeyTag:    k.KeyTag(),
					ZoneKey:   keyType,
					KeyData:   base64.StdEncoding.EncodeToString(k.PublicKey),
				})
			}
		} else if dnskeyErr != nil {
			level.Error = dnskeyErr.Error()
		}

		// Fetch DS records from the parent zone (not for root).
		if i > 0 {
			dsMsg, dsErr := s.resolver.QueryDNSSEC(zone, dns.TypeDS, dns.ClassIN)
			if dsErr == nil && dsMsg != nil {
				for _, rr := range dsMsg.Answers {
					if rr.Type != dns.TypeDS {
						continue
					}
					ds, parseErr := dns.ParseDS(rr.RData)
					if parseErr != nil {
						continue
					}
					level.DS = append(level.DS, dsInfo{
						KeyTag:     ds.KeyTag,
						Algorithm:  ds.Algorithm,
						DigestType: ds.DigestType,
						Digest:     fmt.Sprintf("%x", ds.Digest),
					})
				}
			}
		}

		// Determine status.
		switch {
		case len(level.DNSKEYs) > 0:
			level.Status = "secure"
		case level.Error != "":
			level.Status = "unreachable"
		default:
			level.Status = "insecure"
		}

		levels = append(levels, level)
	}

	return levels
}
