package dnssec

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

// ValidationResult represents the outcome of DNSSEC validation.
type ValidationResult int

const (
	// Secure means all signatures validated and the chain of trust is intact.
	Secure ValidationResult = iota
	// Insecure means the zone does not have DNSSEC (no RRSIG/DS records).
	Insecure
	// Bogus means signature validation failed - the response cannot be trusted.
	Bogus
	// Indeterminate means validation could not be completed (e.g., missing keys).
	Indeterminate
)

// String returns a human-readable name for the validation result.
func (v ValidationResult) String() string {
	switch v {
	case Secure:
		return "Secure"
	case Insecure:
		return "Insecure"
	case Bogus:
		return "Bogus"
	case Indeterminate:
		return "Indeterminate"
	default:
		return fmt.Sprintf("ValidationResult(%d)", int(v))
	}
}

// Querier is the interface the validator uses to fetch DNSKEY and DS records
// needed for DNSSEC chain-of-trust validation.
type Querier interface {
	// QueryDNSSEC sends a DNS query with the DO (DNSSEC OK) bit set
	// and returns the response.
	QueryDNSSEC(name string, qtype uint16, qclass uint16) (*dns.Message, error)
}

// dnskeyCache holds cached DNSKEY records for a zone.
type dnskeyCache struct {
	keys      []dns.ResourceRecord
	fetchedAt time.Time
	ttl       time.Duration
}

// Validator performs DNSSEC signature verification and trust chain validation.
type Validator struct {
	querier      Querier
	trustAnchors []dns.DSRecord
	logger       *slog.Logger

	mu       sync.RWMutex
	keyCache map[string]*dnskeyCache
}

// NewValidator creates a new DNSSEC Validator that uses the given Querier to
// fetch DNSKEY/DS records and the root trust anchors for chain validation.
func NewValidator(querier Querier, logger *slog.Logger) *Validator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Validator{
		querier:      querier,
		trustAnchors: RootDSRecords,
		logger:       logger,
		keyCache:     make(map[string]*dnskeyCache),
	}
}

// ValidateResponse validates DNSSEC signatures in a DNS response.
// It checks RRSIG records in the answer section and validates the
// trust chain from the signer back to the root trust anchors.
// For NXDOMAIN/NODATA responses, it also validates NSEC3 proofs.
func (v *Validator) ValidateResponse(response *dns.Message, qname string, qtype uint16) ValidationResult {
	if response == nil {
		return Insecure
	}

	// Handle NXDOMAIN/NODATA: validate NSEC3 proofs in authority section
	rcode := response.Header.RCODE()
	if rcode == dns.RCodeNXDomain || (rcode == dns.RCodeNoError && len(response.Answers) == 0) {
		return v.validateDenialResponse(response, qname, qtype)
	}

	if len(response.Answers) == 0 {
		return Insecure
	}

	// Collect RRSIG records and the non-RRSIG answer RRs.
	var rrsigs []*dns.RRSIGRecord
	var answerRRs []dns.ResourceRecord

	for _, rr := range response.Answers {
		if rr.Type == dns.TypeRRSIG {
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err != nil {
				v.logger.Debug("failed to parse RRSIG", "error", err)
				continue
			}
			rrsigs = append(rrsigs, parsed)
		} else {
			answerRRs = append(answerRRs, rr)
		}
	}

	// No RRSIG records at all means unsigned (insecure) zone.
	if len(rrsigs) == 0 {
		return Insecure
	}

	// Try to validate each RRSIG.
	for _, rrsig := range rrsigs {
		// Filter the RRset: records matching the type covered by this RRSIG.
		rrset := filterRRSet(answerRRs, rrsig.TypeCovered)
		if len(rrset) == 0 {
			v.logger.Debug("no RRs matching RRSIG type covered",
				"type_covered", rrsig.TypeCovered,
				"signer", rrsig.SignerName)
			continue
		}

		// Check RRSIG time validity.
		now := uint32(time.Now().Unix())
		if now < rrsig.Inception {
			v.logger.Debug("RRSIG not yet valid",
				"inception", rrsig.Inception,
				"now", now)
			return Bogus
		}
		if now > rrsig.Expiration {
			v.logger.Debug("RRSIG expired",
				"expiration", rrsig.Expiration,
				"now", now)
			return Bogus
		}

		// Fetch DNSKEY for the signer zone.
		signerZone := normalizeName(rrsig.SignerName)
		dnskeys, err := v.fetchDNSKEYs(signerZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs",
				"zone", signerZone,
				"error", err)
			return Indeterminate
		}

		// Find the matching DNSKEY by key tag.
		matchingKey, err := findMatchingDNSKEY(dnskeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			v.logger.Debug("no matching DNSKEY found",
				"key_tag", rrsig.KeyTag,
				"zone", signerZone)
			return Indeterminate
		}

		// Verify the RRSIG signature.
		if err := VerifyRRSIG(rrset, rrsig, matchingKey); err != nil {
			v.logger.Debug("RRSIG verification failed",
				"key_tag", rrsig.KeyTag,
				"zone", signerZone,
				"error", err)
			return Bogus
		}

		// Validate the trust chain from the signer zone back to root.
		result := v.validateTrustChain(signerZone, dnskeys)
		if result != Secure {
			return result
		}

		// At least one RRSIG validated with a complete trust chain.
		v.logger.Debug("DNSSEC validation successful",
			"zone", signerZone,
			"key_tag", rrsig.KeyTag)
		return Secure
	}

	// No RRSIG could be validated.
	return Indeterminate
}

// validateTrustChain validates the DNSKEY trust chain from the given zone
// back to the root trust anchors.
func (v *Validator) validateTrustChain(zone string, dnskeys []dns.ResourceRecord) ValidationResult {
	// Build the chain of zones from root to the signer zone.
	chain := buildZoneChain(zone)

	for i, chainZone := range chain {
		zoneKeys, err := v.fetchDNSKEYs(chainZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs for chain zone",
				"zone", chainZone,
				"error", err)
			return Indeterminate
		}

		if i == 0 {
			// Root zone: verify DNSKEY against trust anchors.
			if !v.verifyAgainstTrustAnchors(chainZone, zoneKeys) {
				v.logger.Debug("root DNSKEY does not match trust anchors")
				return Bogus
			}
		} else {
			// Non-root zone: fetch DS from parent and verify.
			parentZone := chain[i-1]
			dsRecords, err := v.fetchDS(chainZone, parentZone)
			if err != nil {
				v.logger.Debug("failed to fetch DS records",
					"zone", chainZone,
					"parent", parentZone,
					"error", err)
				return Indeterminate
			}
			if len(dsRecords) == 0 {
				// No DS at parent means insecure delegation.
				v.logger.Debug("no DS records at parent, insecure delegation",
					"zone", chainZone,
					"parent", parentZone)
				return Insecure
			}

			if !verifyDNSKEYWithDS(zoneKeys, dsRecords, chainZone) {
				v.logger.Debug("DNSKEY does not match DS",
					"zone", chainZone)
				return Bogus
			}
		}
	}

	return Secure
}

// verifyAgainstTrustAnchors checks if any DNSKEY for the root zone matches
// one of the configured trust anchors.
func (v *Validator) verifyAgainstTrustAnchors(zone string, dnskeys []dns.ResourceRecord) bool {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		for _, anchor := range v.trustAnchors {
			if VerifyDS(dnskey, &anchor, zone) {
				return true
			}
		}
	}
	return false
}

// verifyDNSKEYWithDS checks if any DNSKEY (specifically KSK) matches any
// of the provided DS records.
func verifyDNSKEYWithDS(dnskeys []dns.ResourceRecord, dsRecords []*dns.DSRecord, ownerName string) bool {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if !dnskey.IsKSK() {
			continue
		}
		for _, ds := range dsRecords {
			if VerifyDS(dnskey, ds, ownerName) {
				return true
			}
		}
	}
	return false
}

// fetchDNSKEYs retrieves (possibly cached) DNSKEY records for a zone.
func (v *Validator) fetchDNSKEYs(zone string) ([]dns.ResourceRecord, error) {
	normalized := normalizeName(zone)

	// Check cache.
	v.mu.RLock()
	cached, ok := v.keyCache[normalized]
	v.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < cached.ttl {
		return cached.keys, nil
	}

	// Fetch from querier.
	resp, err := v.querier.QueryDNSSEC(normalized, dns.TypeDNSKEY, dns.ClassIN)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY query for %s: %w", normalized, err)
	}

	var keys []dns.ResourceRecord
	var minTTL uint32 = 3600 // default TTL if no records
	for _, rr := range resp.Answers {
		if rr.Type == dns.TypeDNSKEY {
			keys = append(keys, rr)
			if rr.TTL > 0 && rr.TTL < minTTL {
				minTTL = rr.TTL
			}
		}
	}

	// Cache the result.
	v.mu.Lock()
	v.keyCache[normalized] = &dnskeyCache{
		keys:      keys,
		fetchedAt: time.Now(),
		ttl:       time.Duration(minTTL) * time.Second,
	}
	v.mu.Unlock()

	return keys, nil
}

// fetchDS retrieves DS records for a zone from its parent zone.
func (v *Validator) fetchDS(zone, parentZone string) ([]*dns.DSRecord, error) {
	resp, err := v.querier.QueryDNSSEC(zone, dns.TypeDS, dns.ClassIN)
	if err != nil {
		return nil, fmt.Errorf("DS query for %s: %w", zone, err)
	}

	var dsRecords []*dns.DSRecord
	for _, rr := range resp.Answers {
		if rr.Type == dns.TypeDS {
			ds, err := dns.ParseDS(rr.RData)
			if err != nil {
				continue
			}
			dsRecords = append(dsRecords, ds)
		}
	}

	return dsRecords, nil
}

// findMatchingDNSKEY finds a DNSKEY record matching the given key tag and algorithm.
func findMatchingDNSKEY(dnskeys []dns.ResourceRecord, keyTag uint16, algorithm uint8) (*dns.DNSKEYRecord, error) {
	for _, rr := range dnskeys {
		dnskey, err := dns.ParseDNSKEY(rr.RData)
		if err != nil {
			continue
		}
		if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
			return dnskey, nil
		}
	}
	return nil, fmt.Errorf("no DNSKEY with tag %d and algorithm %d", keyTag, algorithm)
}

// filterRRSet returns only the ResourceRecords matching the given type.
func filterRRSet(rrs []dns.ResourceRecord, rrtype uint16) []dns.ResourceRecord {
	var result []dns.ResourceRecord
	for _, rr := range rrs {
		if rr.Type == rrtype {
			result = append(result, rr)
		}
	}
	return result
}

// buildZoneChain builds the list of zones from the root to the given zone.
// For example, "example.com." returns [".", "com.", "example.com."].
func buildZoneChain(zone string) []string {
	zone = normalizeName(zone)

	if zone == "." {
		return []string{"."}
	}

	// Strip trailing dot for splitting.
	trimmed := strings.TrimSuffix(zone, ".")
	labels := strings.Split(trimmed, ".")

	chain := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		name := strings.Join(labels[i:], ".") + "."
		chain = append(chain, name)
	}
	return chain
}

// normalizeName ensures a domain name ends with a trailing dot.
func normalizeName(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// validateDenialResponse validates NSEC3 proofs in NXDOMAIN/NODATA responses.
// It first checks for RRSIG signatures in the authority section, then validates
// NSEC3 records to prove the queried name does not exist or the type is absent.
func (v *Validator) validateDenialResponse(response *dns.Message, qname string, qtype uint16) ValidationResult {
	// Collect RRSIG and NSEC3 records from authority section
	var rrsigs []*dns.RRSIGRecord
	var nsec3Records []*dns.NSEC3Record

	for _, rr := range response.Authority {
		switch rr.Type {
		case dns.TypeRRSIG:
			parsed, err := dns.ParseRRSIG(rr.RData, 0)
			if err != nil {
				v.logger.Debug("failed to parse authority RRSIG", "error", err)
				continue
			}
			rrsigs = append(rrsigs, parsed)
		case dns.TypeNSEC3:
			parsed, err := dns.ParseNSEC3(rr.RData)
			if err != nil {
				v.logger.Debug("failed to parse NSEC3", "error", err)
				continue
			}
			nsec3Records = append(nsec3Records, parsed)
		}
	}

	// No RRSIG in authority means unsigned (insecure)
	if len(rrsigs) == 0 {
		return Insecure
	}

	// Validate RRSIG signatures over NSEC3 records
	for _, rrsig := range rrsigs {
		if rrsig.TypeCovered != dns.TypeNSEC3 && rrsig.TypeCovered != dns.TypeSOA {
			continue
		}

		rrset := filterRRSet(response.Authority, rrsig.TypeCovered)
		if len(rrset) == 0 {
			continue
		}

		// Check time validity
		now := uint32(time.Now().Unix())
		if now < rrsig.Inception || now > rrsig.Expiration {
			v.logger.Debug("authority RRSIG time invalid",
				"inception", rrsig.Inception,
				"expiration", rrsig.Expiration)
			return Bogus
		}

		signerZone := normalizeName(rrsig.SignerName)
		dnskeys, err := v.fetchDNSKEYs(signerZone)
		if err != nil {
			v.logger.Debug("failed to fetch DNSKEYs for denial validation",
				"zone", signerZone, "error", err)
			return Indeterminate
		}

		matchingKey, err := findMatchingDNSKEY(dnskeys, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			v.logger.Debug("no matching DNSKEY for authority RRSIG",
				"key_tag", rrsig.KeyTag, "zone", signerZone)
			return Indeterminate
		}

		if err := VerifyRRSIG(rrset, rrsig, matchingKey); err != nil {
			v.logger.Debug("authority RRSIG verification failed",
				"key_tag", rrsig.KeyTag, "zone", signerZone, "error", err)
			return Bogus
		}
	}

	// Validate NSEC3 denial proof
	if len(nsec3Records) > 0 {
		denied, err := VerifyNSEC3Denial(qname, nsec3Records)
		if err != nil {
			v.logger.Debug("NSEC3 denial verification error",
				"qname", qname, "error", err)
			return Indeterminate
		}
		if denied {
			v.logger.Debug("NSEC3 denial proof valid", "qname", qname)
			return Secure
		}
		v.logger.Debug("NSEC3 denial proof inconclusive", "qname", qname)
	}

	// RRSIG validated but no NSEC3 proof — the signed authority section is enough
	// for a basic Secure result on NXDOMAIN/NODATA with SOA+RRSIG.
	for _, rrsig := range rrsigs {
		if rrsig.TypeCovered == dns.TypeSOA {
			return Secure
		}
	}

	return Insecure
}
