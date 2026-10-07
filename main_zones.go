package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/secondary"
)

func convertBlocklistEntries(entries []config.BlocklistEntry) []blocklist.ListEntry {
	result := make([]blocklist.ListEntry, len(entries))
	for i, e := range entries {
		result[i] = blocklist.ListEntry{URL: e.URL, Format: e.Format}
	}
	return result
}

// buildLocalZones constructs a LocalZoneTable from config, always including the
// default localhost zone (localhost -> 127.0.0.1 / ::1).
func buildLocalZones(cfg *config.Config, logger *slog.Logger) *resolver.LocalZoneTable {
	return resolver.NewLocalZoneTable(buildStaticLocalZones(cfg, logger))
}

// buildStaticLocalZones returns the operator-configured local zones as a
// slice.
//
// The secondary-zone manager needs these separately from the assembled table:
// it rebuilds the whole table on every successful transfer (the table is
// immutable by design), so it must hold onto the zones it did not create or
// the first transfer would silently delete every configured local zone.
func buildStaticLocalZones(cfg *config.Config, logger *slog.Logger) []resolver.LocalZone {
	var zones []resolver.LocalZone

	// Default localhost zone
	localhostZone := resolver.LocalZone{
		Name: "localhost",
		Type: resolver.LocalStatic,
	}
	defaultRecords := []string{
		"localhost. A 127.0.0.1",
		"localhost. AAAA ::1",
	}
	for _, s := range defaultRecords {
		rec, err := resolver.ParseLocalRecord(s)
		if err != nil {
			logger.Error("failed to parse default local record", "record", s, "error", err)
			continue
		}
		localhostZone.Records = append(localhostZone.Records, *rec)
	}
	zones = append(zones, localhostZone)

	// Config-defined zones
	for _, zc := range cfg.LocalZones {
		zt, ok := resolver.ParseLocalZoneType(zc.Type)
		if !ok {
			logger.Warn("unknown local zone type, skipping", "zone", zc.Name, "type", zc.Type)
			continue
		}
		zone := resolver.LocalZone{
			Name: zc.Name,
			Type: zt,
		}

		// zone_file takes precedence over inline data, as LocalZoneConfig
		// documents. It is the round-trip partner of the export endpoint: an
		// operator writes a BIND master-file, points Labyrinth at it, and the
		// parser's strict (round-trip-only) grammar surfaces their mistakes at
		// startup rather than as silently wrong answers later.
		if zc.ZoneFile != "" {
			records, err := loadZoneFileRecords(zc.Name, zc.ZoneFile)
			if err != nil {
				// A bad zone file is skipped with a loud error rather than
				// aborting startup, matching buildSecondaryZones: a resolver
				// that refuses to boot over one malformed internal zone is
				// worse than one that resolves everything else, and the
				// absence is visible in the logs and in queries for that zone.
				logger.Error("local zone file rejected", "zone", zc.Name, "file", zc.ZoneFile, "error", err)
				continue
			}
			zone.Records = records
			logger.Info("local zone loaded from file",
				"zone", zc.Name, "file", zc.ZoneFile, "records", len(records))
			zones = append(zones, zone)
			continue
		}

		for _, s := range zc.Data {
			rec, err := resolver.ParseLocalRecord(s)
			if err != nil {
				logger.Warn("failed to parse local record", "zone", zc.Name, "record", s, "error", err)
				continue
			}
			zone.Records = append(zone.Records, *rec)
		}
		zones = append(zones, zone)
	}

	return zones
}

// loadZoneFileRecords parses a BIND master-file (RFC 1035 §5) into local-zone
// records.
//
// An empty result is an error rather than an empty zone: a zone with no records
// would answer NXDOMAIN for everything under it, which is a very different — and
// much more confusing — thing to discover than a startup log line saying the
// file was empty.
func loadZoneFileRecords(zone, path string) ([]resolver.LocalRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open zone file: %w", err)
	}
	defer f.Close()

	rrs, err := dns.ReadZone(zone, f)
	if err != nil {
		return nil, err
	}
	if len(rrs) == 0 {
		return nil, fmt.Errorf("zone file %q contains no records", path)
	}

	records := make([]resolver.LocalRecord, 0, len(rrs))
	for _, rr := range rrs {
		// The table normalises owner names (lowercase, no trailing dot) when it
		// is built, so the name here is only used for that normalisation.
		records = append(records, resolver.LocalRecord{
			Name:  rr.Name,
			Type:  rr.Type,
			RData: rr.RData,
			TTL:   rr.TTL,
		})
	}
	return records, nil
}

func buildForwardTable(cfg *config.Config, logger *slog.Logger) *resolver.ForwardTable {
	var zones []resolver.ForwardZone

	for _, fz := range cfg.ForwardZones {
		// RFC 8310 Strict Privacy is the only DoT profile we implement, so a
		// TLS zone that cannot authenticate its upstream is dropped rather
		// than downgraded to plaintext. Silently falling back would leave
		// the operator believing a zone is encrypted when it is not — the
		// exact failure the Opportunistic profile invites.
		if err := fz.Validate(); err != nil {
			logger.Error("forward zone rejected", "zone", fz.Name, "error", err)
			continue
		}
		zones = append(zones, resolver.ForwardZone{
			Name:  fz.Name,
			Addrs: fz.Addrs,
			TLS:   fz.TLS,
			DoT: resolver.DoTPolicy{
				AuthName: fz.TLSAuthName,
				Pins:     fz.TLSPins,
			},
		})
		logger.Info("forward zone configured",
			"zone", fz.Name,
			"addrs", fz.Addrs,
			"tls", fz.TLS,
			"tls_auth_name", fz.TLSAuthName,
			"tls_pins", len(fz.TLSPins),
		)
	}

	for _, sz := range cfg.StubZones {
		zones = append(zones, resolver.ForwardZone{
			Name:   sz.Name,
			Addrs:  sz.Addrs,
			IsStub: true,
		})
		logger.Info("stub zone configured", "zone", sz.Name, "addrs", sz.Addrs)
	}

	return resolver.NewForwardTable(zones)
}

// buildDDRConfig assembles the RFC 9462 designation from what is actually
// running.
//
// The transports advertised are exactly the ones enabled in config: a
// designation for a listener that is switched off would send clients to a
// closed port, and a client that fails to reach a designated resolver falls
// back to plaintext — so an over-eager designation makes things worse than
// publishing nothing.
//
// Ports come from the listener addresses rather than being configured
// separately, so an operator who moves DoT off 853 does not have to remember
// to update the designation too.
func buildDDRConfig(cfg *config.Config) dns.DDRConfig {
	ddr := dns.DDRConfig{
		TargetName:  cfg.Server.DDRTargetName,
		DoTEnabled:  cfg.Server.DoTEnabled,
		DoTPort:     portFromListenAddr(cfg.Server.DoTListenAddr, 853),
		DoQEnabled:  cfg.Server.DoQEnabled,
		DoQPort:     portFromListenAddr(cfg.Server.DoQListenAddr, 853),
		DoHEnabled:  cfg.Web.DoHEnabled,
		DoH3Enabled: cfg.Web.DoH3Enabled,
		DoHPath:     cfg.Server.DDRDoHPath,
	}
	if cfg.Server.DDRDoHPort > 0 && cfg.Server.DDRDoHPort <= 65535 {
		ddr.DoHPort = uint16(cfg.Server.DDRDoHPort)
	}
	return ddr
}

// portFromListenAddr extracts the port from a ":853"-style listen address,
// falling back to def when the address has no parseable port.
//
// The fallback matters for the DDR case specifically: emitting port 0 would
// be indistinguishable from "use the ALPN default" in the SVCB encoding, so
// a malformed listen address would silently produce a designation pointing at
// whatever default the client assumes rather than where we are listening.
func portFromListenAddr(addr string, def uint16) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return def
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return def
	}
	return uint16(port)
}

// buildResolverInfo assembles the RFC 9606 RESINFO self-description.
//
// Every field is read from the live config rather than hardcoded. A resolver
// that advertises QNAME minimisation it has switched off is worse than one
// advertising nothing at all: the client makes a privacy decision on the
// strength of the claim, and has no way to verify it.
//
// The extended-error list names the codes that carry a *policy* meaning here
// — the ones that mean "we deliberately did not answer that" rather than
// "something broke". A client seeing EDE 17 from a resolver that declared it
// knows the answer was filtered by design and can say so to the user, instead
// of showing a generic failure.
func buildResolverInfo(cfg *config.Config) dns.ResolverInfo {
	info := dns.ResolverInfo{
		QnameMinimisation: cfg.Resolver.QMinEnabled,
	}
	if cfg.Blocklist.Enabled {
		info.ExtendedErrors = append(info.ExtendedErrors,
			dns.EDECodeFiltered,   // 17 — blocked by blocklist policy
			dns.EDECodeProhibited, // 18 — refused by ACL
		)
	}
	return info
}

// buildSecondaryZones converts secondary-zone config into the manager's form,
// dropping zones that cannot work as configured.
//
// A misconfigured zone is skipped with a loud error rather than aborting
// startup. A resolver that refuses to start because one internal zone has a
// typo in its TSIG secret is worse than one that starts and resolves
// everything else — the zone's absence is visible in the logs and in the
// failure of queries for that zone specifically.
func buildSecondaryZones(cfg *config.Config, logger *slog.Logger) []secondary.ZoneConfig {
	var out []secondary.ZoneConfig
	for _, sz := range cfg.SecondaryZones {
		if err := sz.Validate(); err != nil {
			logger.Error("secondary zone rejected", "zone", sz.Name, "error", err)
			continue
		}
		zc, err := transferZoneConfig(sz, logger, "secondary zone")
		if err != nil {
			logger.Error("secondary zone rejected", "zone", sz.Name, "error", err)
			continue
		}
		out = append(out, zc)
		logger.Info("secondary zone configured",
			"zone", sz.Name, "primary", sz.Primary, "tls", sz.TLS,
			"tsig", sz.TSIGKeyName != "")
	}
	return out
}

// buildCatalogZones converts catalog-zone config (RFC 9432) into the
// manager's form.
func buildCatalogZones(cfg *config.Config, logger *slog.Logger) []secondary.CatalogConfig {
	var out []secondary.CatalogConfig
	for _, cz := range cfg.CatalogZones {
		if err := cz.Validate(); err != nil {
			logger.Error("catalog zone rejected", "zone", cz.Name, "error", err)
			continue
		}
		zc, err := transferZoneConfig(config.SecondaryZoneConfig(cz), logger, "catalog zone")
		if err != nil {
			logger.Error("catalog zone rejected", "zone", cz.Name, "error", err)
			continue
		}
		out = append(out, secondary.CatalogConfig(zc))
		logger.Info("catalog zone configured",
			"zone", cz.Name, "primary", cz.Primary, "tls", cz.TLS,
			"tsig", cz.TSIGKeyName != "")
	}
	return out
}

// transferZoneConfig turns a config block into transfer parameters, decoding
// the TSIG secret.
//
// The secret is decoded here rather than at use time so a malformed one is a
// startup error the operator sees immediately, instead of a transfer that
// keeps failing hours later with an authentication error that looks like the
// primary's fault.
func transferZoneConfig(sz config.SecondaryZoneConfig, logger *slog.Logger, kind string) (secondary.ZoneConfig, error) {
	zc := secondary.ZoneConfig{
		Name:          sz.Name,
		PrimaryAddr:   sz.Primary,
		UseTLS:        sz.TLS,
		TLSServerName: sz.TLSAuthName,
	}
	if sz.TSIGKeyName == "" {
		logger.Warn(kind+" configured without TSIG",
			"zone", sz.Name,
			"detail", "the transferred zone is authenticated only by whatever "+
				"source-address filtering the primary applies")
		return zc, nil
	}
	secret, err := base64.StdEncoding.DecodeString(sz.TSIGSecret)
	if err != nil {
		return zc, fmt.Errorf("tsig_secret is not valid base64: %w", err)
	}
	zc.TSIGKey = dns.TSIGKey{
		Name:      sz.TSIGKeyName,
		Algorithm: sz.TSIGAlgorithm,
		Secret:    secret,
	}
	return zc, nil
}
