package web

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	runtimemetrics "runtime/metrics"
	"sort"
	"strings"
	"time"
)

type systemInterfaceInfo struct {
	Name         string   `json:"name"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardware_addr,omitempty"`
	Flags        []string `json:"flags,omitempty"`
	Addrs        []string `json:"addrs,omitempty"`
}

func (s *AdminServer) handleSystemProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	hostname, _ := os.Hostname()
	interfaces, ips := collectSystemInterfaces()
	memStats := readMemoryStats()
	cpuSeconds := readProcessCPUSeconds()
	disk := readDiskUsage()
	traffic := readTrafficSummary(s)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"hostname": hostname,
		"network": map[string]interface{}{
			"ip_addresses": ips,
			"interfaces":   interfaces,
		},
		"runtime": map[string]interface{}{
			"version":     Version,
			"build_time":  BuildTime,
			"go_version":  GoVersion,
			"os":          runtime.GOOS,
			"arch":        runtime.GOARCH,
			"cpu_cores":   runtime.NumCPU(),
			"go_maxprocs": runtime.GOMAXPROCS(0),
			"goroutines":  runtime.NumGoroutine(),
		},
		"cpu": map[string]interface{}{
			"process_cpu_seconds_total": cpuSeconds,
		},
		"memory": memStats,
		"disk":   disk,
		"traffic": map[string]interface{}{
			"dns_queries_total":       traffic.totalQueries,
			"upstream_queries_total":  traffic.upstreamQueries,
			"blocked_queries_total":   traffic.blockedQueries,
			"rate_limited_total":      traffic.rateLimitedQueries,
			"last_minute_qps_avg":     traffic.lastMinuteQPSAvg,
			"last_minute_qps_peak":    traffic.lastMinuteQPSPeak,
			"last_minute_error_total": traffic.lastMinuteErrors,
		},
	})
}

func collectSystemInterfaces() ([]systemInterfaceInfo, []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	result := make([]systemInterfaceInfo, 0, len(ifaces))
	seenIPs := make(map[string]struct{})
	var ips []string

	for _, iface := range ifaces {
		info := systemInterfaceInfo{
			Name:         iface.Name,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        formatInterfaceFlags(iface.Flags),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				cidr := addr.String()
				info.Addrs = append(info.Addrs, cidr)

				ipPart := cidr
				if slash := strings.IndexByte(cidr, '/'); slash > 0 {
					ipPart = cidr[:slash]
				}
				parsed := net.ParseIP(ipPart)
				if parsed == nil || parsed.IsLoopback() {
					continue
				}
				if _, ok := seenIPs[ipPart]; ok {
					continue
				}
				seenIPs[ipPart] = struct{}{}
				ips = append(ips, ipPart)
			}
		}

		sort.Strings(info.Addrs)
		result = append(result, info)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	sort.Strings(ips)
	return result, ips
}

func formatInterfaceFlags(flags net.Flags) []string {
	out := make([]string, 0, 6)
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		out = append(out, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "pointtopoint")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	return out
}

func readMemoryStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	totalRAM := readSystemTotalMemoryBytes()
	return map[string]interface{}{
		"process_alloc_bytes": m.Alloc,
		"process_heap_bytes":  m.HeapAlloc,
		"process_sys_bytes":   m.Sys,
		"system_total_bytes":  totalRAM,
		"gc_cycles":           m.NumGC,
	}
}

func readProcessCPUSeconds() float64 {
	samples := []runtimemetrics.Sample{
		{Name: "/cpu/classes/user:cpu-seconds"},
		{Name: "/cpu/classes/system:cpu-seconds"},
	}
	runtimemetrics.Read(samples)

	total := 0.0
	for _, sample := range samples {
		if sample.Value.Kind() == runtimemetrics.KindFloat64 {
			total += sample.Value.Float64()
		}
	}
	return total
}

func readDiskUsage() map[string]interface{} {
	path := "."
	if exe, err := os.Executable(); err == nil {
		path = filepath.Dir(exe)
	}

	total, free, targetPath, err := readDiskUsageBytes(path)
	if err != nil {
		return map[string]interface{}{
			"path":        targetPath,
			"total_bytes": uint64(0),
			"free_bytes":  uint64(0),
			"used_bytes":  uint64(0),
			"used_pct":    0.0,
		}
	}

	used := uint64(0)
	usedPct := 0.0
	if total >= free {
		used = total - free
	}
	if total > 0 {
		usedPct = (float64(used) / float64(total)) * 100
	}

	return map[string]interface{}{
		"path":        targetPath,
		"total_bytes": total,
		"free_bytes":  free,
		"used_bytes":  used,
		"used_pct":    usedPct,
	}
}

type trafficSummary struct {
	totalQueries       int64
	upstreamQueries    int64
	blockedQueries     int64
	rateLimitedQueries int64
	lastMinuteQPSAvg   float64
	lastMinuteQPSPeak  float64
	lastMinuteErrors   int64
}

func readTrafficSummary(s *AdminServer) trafficSummary {
	snap := s.metrics.Snapshot()
	totalQueries := int64(0)
	for _, c := range snap.QueriesByType {
		totalQueries += c
	}

	buckets := s.timeSeries.Snapshot(time.Minute)
	if len(buckets) == 0 {
		return trafficSummary{
			totalQueries:       totalQueries,
			upstreamQueries:    snap.UpstreamQueries,
			blockedQueries:     snap.BlockedQueries,
			rateLimitedQueries: snap.RateLimited,
		}
	}

	var totalBucketQueries int64
	var peak float64
	var errors int64
	for _, b := range buckets {
		totalBucketQueries += b.Queries
		errors += b.Errors
		qps := float64(b.Queries) / bucketInterval.Seconds()
		if qps > peak {
			peak = qps
		}
	}

	avg := float64(totalBucketQueries) / float64(len(buckets)) / bucketInterval.Seconds()
	return trafficSummary{
		totalQueries:       totalQueries,
		upstreamQueries:    snap.UpstreamQueries,
		blockedQueries:     snap.BlockedQueries,
		rateLimitedQueries: snap.RateLimited,
		lastMinuteQPSAvg:   avg,
		lastMinuteQPSPeak:  peak,
		lastMinuteErrors:   errors,
	}
}
