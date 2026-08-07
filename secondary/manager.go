// Package secondary keeps locally-served copies of zones transferred from a
// primary server (RFC 5936 AXFR, RFC 1995 IXFR, RFC 9103 over TLS, RFC 8945
// TSIG), including zones discovered through a catalog zone (RFC 9432).
//
// This is what makes the xfr package reachable. Labyrinth had a correct
// AXFR-over-TLS client for some time that nothing called: the transfer code
// existed, the compliance matrix claimed RFC 9103, and no configuration could
// cause a single byte to be transferred. A zone transfer is only useful if
// something serves the result, and that is this package's job.
//
// # What a secondary zone is here
//
// Labyrinth is a recursive resolver, not an authoritative server. A secondary
// zone is served from the local zone table — the same mechanism that answers
// operator-configured static records — so queries for names inside it are
// answered from the transferred copy instead of being resolved iteratively.
// It does not make Labyrinth authoritative for the zone on the public
// internet: there is no AA-bit authority delegation, no NOTIFY listener, and
// no onward transfer to other secondaries.
//
// The use case it serves is the common internal one: an organisation runs a
// private zone on a primary, and wants every resolver in the fleet to answer
// from a local copy rather than forwarding each query.
//
// # Refresh strategy
//
// The zone's own SOA governs when to re-transfer (RFC 1035 §3.3.13): REFRESH
// between successful checks, RETRY after a failure, and EXPIRE as the point
// past which the copy must not be served at all. Honouring EXPIRE matters
// more than it looks — a secondary that keeps answering from a copy whose
// primary vanished a month ago is serving data the zone owner believes they
// retired.
package secondary

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
	"github.com/labyrinthdns/labyrinth/resolver"
	"github.com/labyrinthdns/labyrinth/xfr"
)

// Bounds applied to SOA timers, which come from the primary and are therefore
// not fully trusted.
const (
	// minRefresh stops a zone whose SOA names a tiny REFRESH from turning
	// this resolver into a transfer flood against its own primary.
	minRefresh = 30 * time.Second
	// maxRefresh bounds the other direction so a zone with an absurd
	// REFRESH still gets checked occasionally.
	maxRefresh = 24 * time.Hour
	// minRetry paces failure retries.
	minRetry = 30 * time.Second
	// defaultExpire applies when the SOA has no usable EXPIRE.
	defaultExpire = 7 * 24 * time.Hour
	// catalogRetry paces catalog re-transfer after a failure. Shorter than
	// a zone's retry because a stalled catalog blocks provisioning of every
	// member behind it, not just one zone's data.
	catalogRetry = time.Minute
)

// ZoneConfig describes one secondary zone.
type ZoneConfig struct {
	// Name is the zone apex, e.g. "internal.example".
	Name string
	// PrimaryAddr is the primary server to transfer from.
	PrimaryAddr string
	// UseTLS enables XFR-over-TLS (RFC 9103).
	UseTLS bool
	// TLSServerName is the name the primary's certificate must match.
	TLSServerName string
	// TSIGKey authenticates the transfer. Strongly recommended: without it
	// the only thing standing between this resolver and a substituted zone
	// is whatever address filtering the primary happens to do.
	TSIGKey dns.TSIGKey
}

// CatalogConfig describes a catalog zone (RFC 9432) whose members are
// provisioned automatically.
//
// Members inherit this catalog's transfer parameters — same primary, same
// TSIG key, same transport. RFC 9432 §5.1 leaves the mapping from catalog
// entries to transfer configuration implementation-defined, and inheritance is
// the only mapping that needs no second configuration surface: the catalog
// says *which* zones, the catalog's own settings say *how*.
type CatalogConfig struct {
	Name          string
	PrimaryAddr   string
	UseTLS        bool
	TLSServerName string
	TSIGKey       dns.TSIGKey
}

// memberZoneConfig derives a member's transfer configuration.
func (c CatalogConfig) memberZoneConfig(name string) ZoneConfig {
	return ZoneConfig{
		Name:          name,
		PrimaryAddr:   c.PrimaryAddr,
		UseTLS:        c.UseTLS,
		TLSServerName: c.TLSServerName,
		TSIGKey:       c.TSIGKey,
	}
}

// zoneState is the live state of one secondary zone.
type zoneState struct {
	cfg ZoneConfig
	// source names the catalog zone that provisioned this zone, or "" when
	// it came from static configuration. Reconciliation only ever withdraws
	// zones a catalog owns — a statically configured zone is the operator's
	// explicit instruction and must not be removed because some catalog
	// stopped listing it.
	source string

	serial      uint32
	records     []dns.ResourceRecord
	lastSuccess time.Time
	expire      time.Duration
	refresh     time.Duration
	retry       time.Duration
	loaded      bool
}

// Manager transfers and refreshes secondary zones, republishing the
// resolver's local zone table after each successful transfer.
type Manager struct {
	mu    sync.Mutex
	zones map[string]*zoneState
	// cancels holds the stop function for each running zone loop, so a
	// catalog that drops a member can shut its transfer loop down rather
	// than leaving it querying a primary about a zone nobody wants.
	cancels map[string]context.CancelFunc

	catalogs []CatalogConfig
	res      *resolver.Resolver
	static   []resolver.LocalZone
	logger   *slog.Logger
	wg       sync.WaitGroup
}

// NewManager creates a secondary-zone manager.
//
// `static` is the set of locally-configured zones that must survive every
// republish. The manager rebuilds the whole table each time a transfer
// completes — the table is immutable by design — so it has to hold onto the
// zones it did not create, or the first successful transfer would silently
// delete every operator-configured local zone.
func NewManager(res *resolver.Resolver, static []resolver.LocalZone, zones []ZoneConfig, catalogs []CatalogConfig, logger *slog.Logger) *Manager {
	m := &Manager{
		zones:    make(map[string]*zoneState),
		cancels:  make(map[string]context.CancelFunc),
		catalogs: catalogs,
		res:      res,
		static:   static,
		logger:   logger,
	}
	for _, z := range zones {
		name := normaliseZone(z.Name)
		z.Name = name
		m.zones[name] = &zoneState{cfg: z, expire: defaultExpire}
	}
	return m
}

// Run transfers every configured zone, follows every catalog, and keeps them
// refreshed until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	initial := make([]*zoneState, 0, len(m.zones))
	for _, z := range m.zones {
		initial = append(initial, z)
	}
	m.mu.Unlock()

	for _, z := range initial {
		m.startZone(ctx, z)
	}
	for _, c := range m.catalogs {
		m.wg.Add(1)
		go func(c CatalogConfig) {
			defer m.wg.Done()
			m.runCatalog(ctx, c)
		}(c)
	}

	<-ctx.Done()
	m.wg.Wait()
}

// startZone launches a zone's transfer/refresh loop under a cancellable
// context derived from the manager's.
func (m *Manager) startZone(parent context.Context, z *zoneState) {
	ctx, cancel := context.WithCancel(parent)

	m.mu.Lock()
	if _, running := m.cancels[z.cfg.Name]; running {
		m.mu.Unlock()
		cancel()
		return
	}
	m.cancels[z.cfg.Name] = cancel
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.runZone(ctx, z)
	}()
}

// runZone drives one zone's transfer/refresh loop.
func (m *Manager) runZone(ctx context.Context, z *zoneState) {
	for {
		wait := m.transferOnce(ctx, z)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// runCatalog keeps one catalog zone transferred and its members reconciled.
func (m *Manager) runCatalog(ctx context.Context, c CatalogConfig) {
	for {
		wait := m.refreshCatalog(ctx, c)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refreshCatalog transfers a catalog zone and reconciles its member set.
//
// A full transfer each time rather than IXFR: catalog zones are a handful of
// records per member, so the bandwidth saving is negligible, while the
// reconciliation below needs the complete member list anyway — applying deltas
// to reconstruct it would add a stateful step whose only possible outcome is
// being subtly wrong.
func (m *Manager) refreshCatalog(ctx context.Context, c CatalogConfig) time.Duration {
	records, err := xfr.AXFR(ctx, xfr.ClientConfig{
		PrimaryAddr:   c.PrimaryAddr,
		Zone:          c.Name,
		UseTLS:        c.UseTLS,
		TLSServerName: c.TLSServerName,
		TSIGKey:       c.TSIGKey,
	})
	if err != nil {
		m.logger.Warn("catalog zone transfer failed", "catalog", c.Name, "error", err)
		return catalogRetry
	}

	members, perr := ParseCatalog(c.Name, records)
	if perr != nil {
		// A catalog we cannot understand must leave provisioning untouched.
		// Treating an unreadable catalog as an empty one would withdraw
		// every member zone it had provisioned — turning a schema mismatch
		// into an outage across the whole fleet at once.
		if errors.Is(perr, ErrCatalogNoVersion) || errors.Is(perr, ErrCatalogBadVersion) {
			m.logger.Error("catalog zone not processed; existing members left in place",
				"catalog", c.Name, "error", perr)
			return catalogRetry
		}
		// Anything else (duplicate members) is advisory: `members` is still
		// usable and the reconcile proceeds.
		m.logger.Warn("catalog zone has problems", "catalog", c.Name, "error", perr)
	}

	m.reconcile(ctx, c, members)
	return clampRefresh(catalogRefreshFrom(records))
}

// catalogRefreshFrom reads the REFRESH timer out of a catalog's SOA.
func catalogRefreshFrom(records []dns.ResourceRecord) time.Duration {
	soa := findSOA(records)
	if soa == nil {
		return minRefresh
	}
	parsed, err := dns.ParseSOA(soa.RData, 0)
	if err != nil || parsed == nil {
		return minRefresh
	}
	return time.Duration(parsed.Refresh) * time.Second
}

// reconcile brings the running member zones in line with what the catalog
// lists: start loops for new members, stop them for withdrawn ones.
func (m *Manager) reconcile(ctx context.Context, c CatalogConfig, members []MemberZone) {
	desired := make(map[string]MemberZone, len(members))
	for _, mz := range members {
		desired[mz.Name] = mz
	}

	var (
		toStart []*zoneState
		toStop  []string
	)

	m.mu.Lock()
	for name, z := range m.zones {
		if z.source != c.Name {
			continue
		}
		if _, keep := desired[name]; !keep {
			toStop = append(toStop, name)
		}
	}
	for name, mz := range desired {
		if existing, ok := m.zones[name]; ok {
			// A member colliding with an existing zone. Static
			// configuration wins: it is the operator's explicit
			// instruction, and letting a catalog silently retarget it
			// would move a zone's primary without anyone editing a file.
			if existing.source != c.Name {
				m.logger.Warn("catalog member ignored: zone already configured elsewhere",
					"catalog", c.Name, "zone", name, "existing_source", sourceLabel(existing.source))
			}
			continue
		}
		z := &zoneState{
			cfg:    c.memberZoneConfig(name),
			source: c.Name,
			expire: defaultExpire,
		}
		m.zones[name] = z
		toStart = append(toStart, z)
		m.logger.Info("catalog member added", "catalog", c.Name, "zone", name,
			"unique_id", mz.UniqueID, "group", mz.Group)
	}
	// Detach the withdrawn zones under the same lock so a concurrent
	// republish cannot observe a half-removed set.
	stopFuncs := make([]context.CancelFunc, 0, len(toStop))
	for _, name := range toStop {
		if cancel, ok := m.cancels[name]; ok {
			stopFuncs = append(stopFuncs, cancel)
			delete(m.cancels, name)
		}
		delete(m.zones, name)
		m.logger.Info("catalog member withdrawn", "catalog", c.Name, "zone", name)
	}
	m.mu.Unlock()

	for _, cancel := range stopFuncs {
		cancel()
	}
	for _, z := range toStart {
		m.startZone(ctx, z)
	}
	if len(toStop) > 0 {
		// Withdrawn zones must stop being answered immediately, not at the
		// next successful transfer of some unrelated zone.
		m.republish()
	}
}

func sourceLabel(source string) string {
	if source == "" {
		return "static configuration"
	}
	return "catalog " + source
}

// transferOnce performs one transfer attempt and returns how long to wait
// before the next.
func (m *Manager) transferOnce(ctx context.Context, z *zoneState) time.Duration {
	cfg := xfr.ClientConfig{
		PrimaryAddr:   z.cfg.PrimaryAddr,
		Zone:          z.cfg.Name,
		UseTLS:        z.cfg.UseTLS,
		TLSServerName: z.cfg.TLSServerName,
		TSIGKey:       z.cfg.TSIGKey,
	}

	// Ask incrementally once a copy is held. A primary that cannot answer
	// incrementally falls back to a full zone on its own (RFC 1995 §2), so
	// there is no need to probe first or to fall back here.
	m.mu.Lock()
	loaded, serial := z.loaded, z.serial
	m.mu.Unlock()

	if loaded {
		res, err := xfr.IXFR(ctx, cfg, serial)
		if err != nil {
			return m.onFailure(z, err)
		}
		return m.applyIXFR(z, res)
	}

	records, err := xfr.AXFR(ctx, cfg)
	if err != nil {
		return m.onFailure(z, err)
	}
	return m.applyFull(z, records)
}

// applyIXFR folds an incremental result into the held copy.
func (m *Manager) applyIXFR(z *zoneState, res *xfr.Result) time.Duration {
	switch {
	case res.UpToDate:
		m.mu.Lock()
		z.lastSuccess = time.Now()
		wait := z.refresh
		m.mu.Unlock()
		m.logger.Debug("secondary zone already current", "zone", z.cfg.Name, "serial", res.Serial)
		return clampRefresh(wait)

	case !res.Incremental:
		// The primary could not go back far enough and sent everything.
		return m.applyFull(z, res.Records)

	default:
		m.mu.Lock()
		for _, d := range res.Deltas {
			z.records = applyDelta(z.records, d)
		}
		z.serial = res.Serial
		z.lastSuccess = time.Now()
		wait := z.refresh
		m.mu.Unlock()

		m.logger.Info("secondary zone updated incrementally",
			"zone", z.cfg.Name, "serial", res.Serial, "deltas", len(res.Deltas))
		m.republish()
		return clampRefresh(wait)
	}
}

// applyFull replaces the held copy with a freshly transferred zone.
func (m *Manager) applyFull(z *zoneState, records []dns.ResourceRecord) time.Duration {
	soa := findSOA(records)
	if soa == nil {
		return m.onFailure(z, errNoSOA{zone: z.cfg.Name})
	}
	parsed, err := dns.ParseSOA(soa.RData, 0)
	if err != nil || parsed == nil {
		return m.onFailure(z, errNoSOA{zone: z.cfg.Name})
	}

	m.mu.Lock()
	z.records = records
	z.serial = parsed.Serial
	z.refresh = clampRefresh(time.Duration(parsed.Refresh) * time.Second)
	z.retry = clampRetry(time.Duration(parsed.Retry) * time.Second)
	if parsed.Expire > 0 {
		z.expire = time.Duration(parsed.Expire) * time.Second
	}
	z.lastSuccess = time.Now()
	z.loaded = true
	wait, expire := z.refresh, z.expire
	m.mu.Unlock()

	m.logger.Info("secondary zone transferred",
		"zone", z.cfg.Name, "serial", parsed.Serial, "records", len(records),
		"refresh", wait, "expire", expire)
	m.republish()
	return wait
}

// onFailure records a failed transfer and decides when to retry.
//
// A zone whose copy has aged past EXPIRE is dropped from the served table
// rather than kept. RFC 1035 §3.3.13 gives EXPIRE exactly this meaning, and
// continuing to answer from an expired copy would have this resolver
// asserting records the zone owner may have retired weeks ago — with no
// symptom visible to the clients relying on it.
func (m *Manager) onFailure(z *zoneState, err error) time.Duration {
	m.mu.Lock()
	loaded := z.loaded
	age := time.Since(z.lastSuccess)
	expired := loaded && age > z.expire
	if expired {
		z.loaded = false
		z.records = nil
		z.serial = 0
	}
	retry, expire := z.retry, z.expire
	m.mu.Unlock()

	if expired {
		m.logger.Error("secondary zone expired and withdrawn",
			"zone", z.cfg.Name, "age", age, "expire", expire, "error", err)
		m.republish()
	} else {
		m.logger.Warn("secondary zone transfer failed",
			"zone", z.cfg.Name, "error", err, "serving_stale", loaded)
	}
	return clampRetry(retry)
}

// republish rebuilds the resolver's local zone table from the static zones
// plus every currently-loaded secondary.
func (m *Manager) republish() {
	m.mu.Lock()
	zones := make([]resolver.LocalZone, 0, len(m.static)+len(m.zones))
	zones = append(zones, m.static...)
	for _, z := range m.zones {
		if !z.loaded || len(z.records) == 0 {
			continue
		}
		zones = append(zones, resolver.LocalZone{
			Name:    z.cfg.Name,
			Type:    resolver.LocalStatic,
			Records: toLocalRecords(z.records),
		})
	}
	m.mu.Unlock()

	m.res.SetLocalZones(resolver.NewLocalZoneTable(zones))
}

// toLocalRecords converts transferred records into local-zone records.
//
// RDATA passes through verbatim. The transfer delivered wire-format RDATA and
// the local zone table serves wire-format RDATA, so re-encoding would only
// create opportunities to corrupt record types neither layer understands
// (RFC 3597).
func toLocalRecords(records []dns.ResourceRecord) []resolver.LocalRecord {
	out := make([]resolver.LocalRecord, 0, len(records))
	for _, rr := range records {
		out = append(out, resolver.LocalRecord{
			Name:  rr.Name,
			Type:  rr.Type,
			RData: rr.RData,
			TTL:   rr.TTL,
		})
	}
	return out
}

// applyDelta removes then adds records for one IXFR version step.
//
// Order matters and is fixed by RFC 1995 §2: deletions first. A version step
// that replaces a record's RDATA appears as a delete of the old value
// followed by an add of the new one, and applying them the other way round
// would add the new record and then delete it again.
func applyDelta(records []dns.ResourceRecord, d xfr.Delta) []dns.ResourceRecord {
	for _, del := range d.Deleted {
		records = removeRecord(records, del)
	}
	return append(records, d.Added...)
}

// removeRecord drops the first record matching name, type and RDATA exactly.
//
// The RDATA comparison is what makes this correct for a zone holding several
// records of the same name and type — an RRset of A records, say. Matching on
// name+type alone would delete the whole RRset when the delta only retired one
// member of it.
func removeRecord(records []dns.ResourceRecord, target dns.ResourceRecord) []dns.ResourceRecord {
	for i, rr := range records {
		if rr.Type != target.Type || !strings.EqualFold(rr.Name, target.Name) {
			continue
		}
		if !equalRData(rr.RData, target.RData) {
			continue
		}
		return append(records[:i], records[i+1:]...)
	}
	return records
}

func equalRData(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func findSOA(records []dns.ResourceRecord) *dns.ResourceRecord {
	for i := range records {
		if records[i].Type == dns.TypeSOA {
			return &records[i]
		}
	}
	return nil
}

func clampRefresh(d time.Duration) time.Duration {
	if d < minRefresh {
		return minRefresh
	}
	if d > maxRefresh {
		return maxRefresh
	}
	return d
}

func clampRetry(d time.Duration) time.Duration {
	if d < minRetry {
		return minRetry
	}
	if d > maxRefresh {
		return maxRefresh
	}
	return d
}

type errNoSOA struct{ zone string }

func (e errNoSOA) Error() string {
	return "secondary: transfer of " + e.zone + " contained no usable SOA"
}
