package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/labyrinthdns/labyrinth/dns"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		printUsage()
		return 1
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "quick":
		err = cmdQuick(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		return 1
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Println(`labyrinth-bench - DNS benchmark & load testing tool

Usage:
  labyrinth-bench <command> [flags]

Commands:
  run     Run benchmark queries against a DNS server
  serve   Start coordinator web UI for distributed testing
  quick   Quick standalone benchmark (results printed to stdout)
  help    Show this help message

Run "labyrinth-bench <command> -h" for more information.`)
}

func addRunFlags(fs *flag.FlagSet) (target *string, qps *int, duration *string, workers *int, domains *string, types *string, report *string, name *string) {
	target = fs.String("target", "127.0.0.1:53", "DNS server address (host:port)")
	qps = fs.Int("qps", 1000, "Target queries per second")
	duration = fs.String("duration", "30s", "Test duration (e.g. 10s, 1m)")
	workers = fs.Int("workers", 10, "Number of concurrent workers")
	domains = fs.String("domains", "builtin", "Domain list file path, or \"builtin\" for built-in list")
	types = fs.String("types", "A,AAAA", "Query types, comma-separated (A, AAAA, MX, etc.)")
	report = fs.String("report", "", "Coordinator URL to report results (e.g. http://coordinator:8080)")
	name = fs.String("name", "", "Runner name/label (default: hostname)")
	return
}

func buildRunConfig(target string, qps int, durationStr string, workers int, domainsStr string, typesStr string, reportURL string, name string) (RunConfig, error) {
	dur, err := time.ParseDuration(durationStr)
	if err != nil {
		return RunConfig{}, fmt.Errorf("invalid duration %q: %w", durationStr, err)
	}

	domainList, err := loadDomains(domainsStr)
	if err != nil {
		return RunConfig{}, fmt.Errorf("failed to load domains: %w", err)
	}

	queryTypes, err := parseTypes(typesStr)
	if err != nil {
		return RunConfig{}, err
	}

	if name == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "runner"
		}
		name = hostname
	}

	return RunConfig{
		Target:    target,
		QPS:       qps,
		Duration:  dur,
		Workers:   workers,
		Domains:   domainList,
		Types:     queryTypes,
		Name:      name,
		ReportURL: reportURL,
	}, nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target, qps, duration, workers, domains, types, report, name := addRunFlags(fs)
	fs.Parse(args)

	cfg, err := buildRunConfig(*target, *qps, *duration, *workers, *domains, *types, *report, *name)
	if err != nil {
		return err
	}

	fmt.Printf("Labyrinth DNS Benchmark - Runner Mode\n")
	fmt.Printf("Target:     %s\n", cfg.Target)
	fmt.Printf("QPS:        %d\n", cfg.QPS)
	fmt.Printf("Duration:   %s\n", cfg.Duration)
	fmt.Printf("Workers:    %d\n", cfg.Workers)
	fmt.Printf("Domains:    %d entries\n", len(cfg.Domains))
	fmt.Printf("Runner:     %s\n", cfg.Name)
	if cfg.ReportURL != "" {
		fmt.Printf("Report to:  %s\n", cfg.ReportURL)
	}
	fmt.Println()

	onSnapshot := func(r RunResult) {
		fmt.Printf("\r  [%5.1fs] queries=%d  qps=%.0f  avg=%.1fms  p95=%.1fms  success=%d  errors=%d",
			r.Duration, r.TotalQueries, r.QPS, r.AvgLatencyMs, r.P95LatencyMs, r.SuccessCount, r.ErrorCount)
	}

	result := RunBenchmark(cfg, onSnapshot)
	fmt.Println()
	PrintQuickResult(result)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "Listen address for coordinator web UI")
	fs.Parse(args)

	coordinator := NewCoordinator()
	if err := coordinator.Serve(*addr); err != nil {
		return err
	}
	return nil
}

func cmdQuick(args []string) error {
	fs := flag.NewFlagSet("quick", flag.ExitOnError)
	target, qps, duration, workers, domains, types, _, name := addRunFlags(fs)
	fs.Parse(args)

	cfg, err := buildRunConfig(*target, *qps, *duration, *workers, *domains, *types, "", *name)
	if err != nil {
		return err
	}

	fmt.Printf("Labyrinth DNS Benchmark - Quick Mode\n")
	fmt.Printf("Target:     %s\n", cfg.Target)
	fmt.Printf("QPS:        %d\n", cfg.QPS)
	fmt.Printf("Duration:   %s\n", cfg.Duration)
	fmt.Printf("Workers:    %d\n", cfg.Workers)
	fmt.Printf("Domains:    %d entries\n", len(cfg.Domains))
	fmt.Println()
	fmt.Println("Running benchmark...")

	onSnapshot := func(r RunResult) {
		fmt.Printf("\r  [%5.1fs] queries=%d  qps=%.0f  avg=%.1fms  p95=%.1fms  err=%d",
			r.Duration, r.TotalQueries, r.QPS, r.AvgLatencyMs, r.P95LatencyMs, r.ErrorCount)
	}

	result := RunBenchmark(cfg, onSnapshot)
	fmt.Println()
	PrintQuickResult(result)
	return nil
}

func loadDomains(source string) ([]string, error) {
	if source == "builtin" || source == "" {
		return builtinDomains, nil
	}

	f, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domain file %q is empty", source)
	}
	return domains, nil
}

// stringToType maps a query type string to its uint16 constant.
var stringToType = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"NS":    dns.TypeNS,
	"CNAME": dns.TypeCNAME,
	"SOA":   dns.TypeSOA,
	"PTR":   dns.TypePTR,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"SRV":   dns.TypeSRV,
}

func parseTypes(typesStr string) ([]uint16, error) {
	parts := strings.Split(typesStr, ",")
	var types []uint16
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToUpper(p))
		if p == "" {
			continue
		}
		t, ok := stringToType[p]
		if !ok {
			return nil, fmt.Errorf("unknown query type %q (supported: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV)", p)
		}
		types = append(types, t)
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("no valid query types specified")
	}
	return types, nil
}
