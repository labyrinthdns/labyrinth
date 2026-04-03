package main

import (
	"log/slog"

	"github.com/labyrinthdns/labyrinth/blocklist"
	"github.com/labyrinthdns/labyrinth/config"
	"github.com/labyrinthdns/labyrinth/resolver"
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

	return resolver.NewLocalZoneTable(zones)
}

func buildForwardTable(cfg *config.Config, logger *slog.Logger) *resolver.ForwardTable {
	var zones []resolver.ForwardZone

	for _, fz := range cfg.ForwardZones {
		zones = append(zones, resolver.ForwardZone{
			Name:  fz.Name,
			Addrs: fz.Addrs,
		})
		logger.Info("forward zone configured", "zone", fz.Name, "addrs", fz.Addrs)
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
