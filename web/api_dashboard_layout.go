package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/labyrinthdns/labyrinth/config"
)

const (
	dashboardLayoutBeginMarker = "# labyrinth:webui-layout begin"
	dashboardLayoutEndMarker   = "# labyrinth:webui-layout end"
)

var allowedDashboardPanels = map[string]struct{}{
	"query_types":      {},
	"network_security": {},
	"top_lists":        {},
}

type dashboardLayoutPayload struct {
	PanelOrder   []string `json:"panel_order"`
	HiddenPanels []string `json:"hidden_panels"`
}

func normalizeDashboardPanelIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(strings.ToLower(raw))
		if id == "" {
			continue
		}
		if _, ok := allowedDashboardPanels[id]; !ok {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func buildDashboardLayoutBlock(panelOrder, hiddenPanels []string) string {
	var b strings.Builder
	b.WriteString(dashboardLayoutBeginMarker)
	b.WriteString("\n")
	b.WriteString("web:\n")
	b.WriteString("  dashboard:\n")

	b.WriteString("    panel_order:")
	if len(panelOrder) == 0 {
		b.WriteString(" \"\"\n")
	} else {
		b.WriteString("\n")
		for _, id := range panelOrder {
			b.WriteString("      - ")
			b.WriteString(id)
			b.WriteString("\n")
		}
	}

	b.WriteString("    hidden_panels:")
	if len(hiddenPanels) == 0 {
		b.WriteString(" \"\"\n")
	} else {
		b.WriteString("\n")
		for _, id := range hiddenPanels {
			b.WriteString("      - ")
			b.WriteString(id)
			b.WriteString("\n")
		}
	}

	b.WriteString(dashboardLayoutEndMarker)
	b.WriteString("\n")
	return b.String()
}

func upsertDashboardLayoutBlock(content string, panelOrder, hiddenPanels []string) string {
	block := buildDashboardLayoutBlock(panelOrder, hiddenPanels)

	start := strings.Index(content, dashboardLayoutBeginMarker)
	end := strings.Index(content, dashboardLayoutEndMarker)
	if start >= 0 && end > start {
		end += len(dashboardLayoutEndMarker)
		updated := content[:start] + block + strings.TrimLeft(content[end:], "\r\n")
		if !strings.HasSuffix(updated, "\n") {
			updated += "\n"
		}
		return updated
	}

	trimmed := strings.TrimRight(content, "\r\n")
	if trimmed == "" {
		return block
	}
	return trimmed + "\n\n" + block
}

// handleDashboardLayout handles GET/PUT /api/dashboard/layout.
func (s *AdminServer) handleDashboardLayout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.config.Load()
		order := completeDashboardPanelOrder(cfg.Web.Dashboard.PanelOrder)
		hidden := normalizeDashboardPanelIDs(cfg.Web.Dashboard.HiddenPanels)
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"panel_order":   order,
			"hidden_panels": hidden,
		})
	case http.MethodPut:
		var req dashboardLayoutPayload
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		panelOrder := completeDashboardPanelOrder(req.PanelOrder)
		hiddenPanels := normalizeDashboardPanelIDs(req.HiddenPanels)

		// Serialise read-modify-write of the on-disk YAML against
		// concurrent /api/config/raw PUT and other dashboard PUTs.
		// Without the lock, two concurrent layout reorders both
		// ReadFile the same baseline, both upsert their own panel
		// order, and writeFileAtomically lets the second writer
		// silently drop the first writer's delta.
		s.configFileMu.Lock()
		defer s.configFileMu.Unlock()

		path := s.configFilePath()
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to read config: " + err.Error()})
			return
		}

		updated := upsertDashboardLayoutBlock(string(raw), panelOrder, hiddenPanels)
		if err := writeFileAtomically(path, []byte(updated)); err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "failed to save dashboard layout: " + err.Error()})
			return
		}

		// Keep in-memory config in sync; preserve runtime config if parse fails.
		// On parse failure, copy-on-write: load → shallow copy → set the
		// dashboard fields on the copy → publish. New slices come from the
		// caller (panelOrder, hiddenPanels), so no aliasing with the
		// previous-snapshot readers.
		if parsed, parseErr := config.Parse([]byte(updated)); parseErr == nil {
			s.config.Store(parsed)
		} else {
			curCfg := s.config.Load()
			newCfg := *curCfg
			newCfg.Web.Dashboard.PanelOrder = panelOrder
			newCfg.Web.Dashboard.HiddenPanels = hiddenPanels
			s.config.Store(&newCfg)
		}

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":        "saved",
			"panel_order":   panelOrder,
			"hidden_panels": hiddenPanels,
			"path":          path,
			"storage":       "yaml",
		})
	default:
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func defaultDashboardPanelOrder() []string {
	return []string{
		"query_types",
		"network_security",
		"top_lists",
	}
}

func completeDashboardPanelOrder(order []string) []string {
	if len(order) == 0 {
		return defaultDashboardPanelOrder()
	}
	existing := normalizeDashboardPanelIDs(order)
	seen := make(map[string]struct{}, len(existing))
	for _, id := range existing {
		seen[id] = struct{}{}
	}
	for _, id := range defaultDashboardPanelOrder() {
		if _, ok := seen[id]; ok {
			continue
		}
		existing = append(existing, id)
	}
	return existing
}
