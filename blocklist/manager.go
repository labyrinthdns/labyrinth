package blocklist

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ListSource describes a single remote blocklist and its current state.
type ListSource struct {
	URL        string    `json:"url"`
	Format     string    `json:"format"` // "hosts", "domains", "abp"
	Enabled    bool      `json:"enabled"`
	LastUpdate time.Time `json:"last_update"`
	RuleCount  int       `json:"rule_count"`
	Error      string    `json:"error,omitempty"`
}

// ManagerConfig holds the configuration for a blocklist Manager.
type ManagerConfig struct {
	Lists           []ListEntry
	Whitelist       []string
	BlockingMode    string // "nxdomain", "null_ip", "custom_ip"
	CustomIP        string
	RefreshInterval time.Duration
}

// ListEntry is a URL+format pair used to seed the initial list sources.
type ListEntry struct {
	URL    string
	Format string
}

// Stats holds aggregate blocklist statistics.
type Stats struct {
	Enabled      bool   `json:"enabled"`
	TotalRules   int    `json:"total_rules"`
	ListCount    int    `json:"list_count"`
	BlockedTotal int64  `json:"blocked_total"`
	CustomBlocks int    `json:"custom_blocks"`
	CustomAllows int    `json:"custom_allows"`
	BlockingMode string `json:"blocking_mode"`
}

// Manager coordinates blocklist downloads, parsing, and matching. It is
// safe for concurrent use.
type Manager struct {
	matcher         *Matcher
	sources         []*ListSource
	customBlocks    map[string]struct{}
	customAllows    map[string]struct{}
	blockingMode    string
	customIP        string
	refreshInterval time.Duration
	blockedTotal    atomic.Int64
	httpClient      *http.Client
	logger          *slog.Logger
	mu              sync.RWMutex
}

// NewManager creates a Manager from the supplied configuration. The
// manager is idle until Start is called.
func NewManager(cfg ManagerConfig, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	blockingMode := cfg.BlockingMode
	if blockingMode == "" {
		blockingMode = "nxdomain"
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = 24 * time.Hour
	}

	sources := make([]*ListSource, 0, len(cfg.Lists))
	for _, entry := range cfg.Lists {
		sources = append(sources, &ListSource{
			URL:     entry.URL,
			Format:  entry.Format,
			Enabled: true,
		})
	}

	customAllows := make(map[string]struct{}, len(cfg.Whitelist))
	for _, d := range cfg.Whitelist {
		customAllows[strings.ToLower(strings.TrimSuffix(d, "."))] = struct{}{}
	}

	mgr := &Manager{
		matcher:         NewMatcher(),
		sources:         sources,
		customBlocks:    make(map[string]struct{}),
		customAllows:    customAllows,
		blockingMode:    blockingMode,
		customIP:        cfg.CustomIP,
		refreshInterval: refreshInterval,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
	return mgr
}

// Start runs the background refresh loop. It performs an immediate refresh
// and then re-downloads all lists on the configured interval. It blocks
// until ctx is cancelled.
func (mgr *Manager) Start(ctx context.Context) {
	mgr.RefreshAll()

	ticker := time.NewTicker(mgr.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			mgr.logger.Info("blocklist manager stopped")
			return
		case <-ticker.C:
			mgr.RefreshAll()
		}
	}
}

// IsBlocked checks whether domain is blocked and, if so, increments the
// global blocked-query counter.
func (mgr *Manager) IsBlocked(domain string) bool {
	if mgr.matcher.Match(domain) {
		mgr.blockedTotal.Add(1)
		return true
	}
	return false
}

// BlockingMode returns the active blocking mode ("nxdomain", "null_ip",
// or "custom_ip").
func (mgr *Manager) BlockingMode() string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.blockingMode
}

// CustomIP returns the IP address used when the blocking mode is
// "custom_ip".
func (mgr *Manager) CustomIP() string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.customIP
}

// RefreshAll downloads and parses every enabled list source, rebuilds the
// matcher, and atomically swaps it in. Errors on individual lists are
// logged but do not prevent other lists from loading.
func (mgr *Manager) RefreshAll() {
	mgr.logger.Info("blocklist refresh started")
	start := time.Now()

	newMatcher := NewMatcher()

	mgr.mu.RLock()
	sources := make([]*ListSource, len(mgr.sources))
	copy(sources, mgr.sources)
	mgr.mu.RUnlock()

	for _, src := range sources {
		if !src.Enabled {
			continue
		}

		domains, err := mgr.downloadAndParse(src.URL, src.Format)
		if err != nil {
			mgr.logger.Error("blocklist download failed",
				"url", src.URL,
				"error", err,
			)
			mgr.mu.Lock()
			src.Error = err.Error()
			mgr.mu.Unlock()
			continue
		}

		for _, d := range domains {
			newMatcher.AddExact(d)
		}

		mgr.mu.Lock()
		src.LastUpdate = time.Now()
		src.RuleCount = len(domains)
		src.Error = ""
		mgr.mu.Unlock()

		mgr.logger.Info("blocklist loaded",
			"url", src.URL,
			"rules", len(domains),
		)
	}

	// Apply custom block and whitelist rules.
	mgr.mu.RLock()
	for d := range mgr.customBlocks {
		newMatcher.AddExact(d)
	}
	for d := range mgr.customAllows {
		newMatcher.AddWhitelist(d)
	}
	mgr.mu.RUnlock()

	// Atomic swap of the matcher.
	mgr.mu.Lock()
	mgr.matcher = newMatcher
	mgr.mu.Unlock()

	exact, wildcards, wl := newMatcher.Stats()
	mgr.logger.Info("blocklist refresh complete",
		"exact_rules", exact,
		"wildcard_rules", wildcards,
		"whitelist_rules", wl,
		"duration", time.Since(start).Round(time.Millisecond),
	)
}

// downloadAndParse fetches a remote URL and parses it according to the
// given format.
func (mgr *Manager) downloadAndParse(url, format string) ([]string, error) {
	resp, err := mgr.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Limit read to 50 MB to avoid memory issues with huge files.
	limited := io.LimitReader(resp.Body, 50<<20)

	switch strings.ToLower(format) {
	case "hosts":
		return ParseHostsFile(limited), nil
	case "domains":
		return ParseDomainList(limited), nil
	case "abp":
		return ParseABP(limited), nil
	default:
		return nil, fmt.Errorf("unknown list format %q", format)
	}
}

// AddList adds a new list source at runtime. The list will be fetched on
// the next RefreshAll cycle.
func (mgr *Manager) AddList(url, format string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// Avoid duplicates.
	for _, s := range mgr.sources {
		if s.URL == url {
			s.Format = format
			s.Enabled = true
			return
		}
	}

	mgr.sources = append(mgr.sources, &ListSource{
		URL:     url,
		Format:  format,
		Enabled: true,
	})
	mgr.logger.Info("blocklist source added", "url", url, "format", format)
}

// RemoveList removes a list source by URL.
func (mgr *Manager) RemoveList(url string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for i, s := range mgr.sources {
		if s.URL == url {
			mgr.sources = append(mgr.sources[:i], mgr.sources[i+1:]...)
			mgr.logger.Info("blocklist source removed", "url", url)
			return
		}
	}
}

// BlockDomain adds a custom exact-match block rule that persists across
// refreshes.
func (mgr *Manager) BlockDomain(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	mgr.mu.Lock()
	mgr.customBlocks[domain] = struct{}{}
	mgr.mu.Unlock()

	mgr.matcher.AddExact(domain)
	mgr.logger.Info("custom block added", "domain", domain)
}

// UnblockDomain adds a custom whitelist rule that persists across
// refreshes.
func (mgr *Manager) UnblockDomain(domain string) {
	domain = normalize(domain)
	if domain == "" {
		return
	}
	mgr.mu.Lock()
	mgr.customAllows[domain] = struct{}{}
	delete(mgr.customBlocks, domain)
	mgr.mu.Unlock()

	mgr.matcher.AddWhitelist(domain)
	mgr.matcher.Remove(domain)
	mgr.logger.Info("custom unblock added", "domain", domain)
}

// CheckDomain returns whether a domain is blocked without incrementing
// the blocked-query counter.
func (mgr *Manager) CheckDomain(domain string) bool {
	return mgr.matcher.Match(domain)
}

// Stats returns aggregate blocklist statistics.
func (mgr *Manager) Stats() Stats {
	exact, wildcards, wl := mgr.matcher.Stats()
	_ = wl

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	enabledCount := 0
	for _, s := range mgr.sources {
		if s.Enabled {
			enabledCount++
		}
	}

	return Stats{
		Enabled:      len(mgr.sources) > 0 || len(mgr.customBlocks) > 0,
		TotalRules:   exact + wildcards,
		ListCount:    enabledCount,
		BlockedTotal: mgr.blockedTotal.Load(),
		CustomBlocks: len(mgr.customBlocks),
		CustomAllows: len(mgr.customAllows),
		BlockingMode: mgr.blockingMode,
	}
}

// Sources returns a snapshot of the current list sources.
func (mgr *Manager) Sources() []*ListSource {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	result := make([]*ListSource, len(mgr.sources))
	for i, s := range mgr.sources {
		cp := *s
		result[i] = &cp
	}
	return result
}
