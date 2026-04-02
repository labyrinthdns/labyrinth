package web

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/cache"
	"github.com/labyrinthdns/labyrinth/metrics"
)

// zabbixKeys lists all supported Zabbix metric keys.
var zabbixKeys = []string{
	"labyrinth.queries.total",
	"labyrinth.cache.hits",
	"labyrinth.cache.misses",
	"labyrinth.cache.hit_ratio",
	"labyrinth.cache.entries",
	"labyrinth.upstream.queries",
	"labyrinth.upstream.errors",
	"labyrinth.uptime",
	"labyrinth.goroutines",
}

// handleZabbixItems handles GET /api/zabbix/items — returns the list of available metric keys.
func (s *AdminServer) handleZabbixItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	items := make([]map[string]string, len(zabbixKeys))
	for i, key := range zabbixKeys {
		items[i] = map[string]string{"key": key}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"items": items,
	})
}

// handleZabbixItem handles GET /api/zabbix/item?key=X — returns plain text metric value.
func (s *AdminServer) handleZabbixItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key parameter", http.StatusBadRequest)
		return
	}

	value, err := resolveZabbixKey(key, s.metrics, s.cache)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, value)
}

// resolveZabbixKey returns the string value for a given Zabbix metric key.
func resolveZabbixKey(key string, m *metrics.Metrics, c *cache.Cache) (string, error) {
	snap := m.Snapshot()

	switch key {
	case "labyrinth.queries.total":
		var total int64
		for _, v := range snap.QueriesByType {
			total += v
		}
		return fmt.Sprintf("%d", total), nil
	case "labyrinth.cache.hits":
		return fmt.Sprintf("%d", snap.CacheHits), nil
	case "labyrinth.cache.misses":
		return fmt.Sprintf("%d", snap.CacheMisses), nil
	case "labyrinth.cache.hit_ratio":
		total := snap.CacheHits + snap.CacheMisses
		if total == 0 {
			return "0.00", nil
		}
		ratio := float64(snap.CacheHits) / float64(total) * 100
		return fmt.Sprintf("%.2f", ratio), nil
	case "labyrinth.cache.entries":
		stats := c.Stats()
		return fmt.Sprintf("%d", stats.Entries), nil
	case "labyrinth.upstream.queries":
		return fmt.Sprintf("%d", snap.UpstreamQueries), nil
	case "labyrinth.upstream.errors":
		return fmt.Sprintf("%d", snap.UpstreamErrors), nil
	case "labyrinth.uptime":
		return fmt.Sprintf("%.0f", snap.UptimeSeconds), nil
	case "labyrinth.goroutines":
		return fmt.Sprintf("%d", runtime.NumGoroutine()), nil
	default:
		return "", fmt.Errorf("unknown key: %s", key)
	}
}

// StartZabbixAgent starts a TCP listener implementing the Zabbix agent protocol (ZBXD header).
func StartZabbixAgent(ctx context.Context, addr string, m *metrics.Metrics, c *cache.Cache, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("zabbix agent listen: %w", err)
	}

	logger.Info("zabbix agent starting", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Error("zabbix agent accept error", "error", err)
				continue
			}
		}
		go handleZabbixConn(conn, m, c, logger)
	}
}

// handleZabbixConn handles a single Zabbix agent protocol connection.
// Protocol: client sends a key (newline-terminated), server responds with ZBXD\x01 + 8-byte length + data.
func handleZabbixConn(conn net.Conn, m *metrics.Metrics, c *cache.Cache, logger *slog.Logger) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read the request (key name, up to 1024 bytes)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	key := strings.TrimSpace(string(buf[:n]))

	// Strip ZBXD header if present (Zabbix active check format)
	if strings.HasPrefix(key, "ZBXD\x01") && len(key) > 13 {
		key = key[13:]
	}
	key = strings.TrimSpace(key)

	value, err := resolveZabbixKey(key, m, c)
	if err != nil {
		value = "ZBX_NOTSUPPORTED\x00" + err.Error()
	}

	// Write ZBXD response: "ZBXD\x01" + 8-byte little-endian length + data
	header := []byte("ZBXD\x01")
	dataLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataLen, uint64(len(value)))

	conn.Write(header)
	conn.Write(dataLen)
	conn.Write([]byte(value))
}
