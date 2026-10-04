#!/usr/bin/env python3
"""Labyrinth DNS performance monitor.

Collects process, socket, DNS latency, and (when available) Prometheus
metrics. Writes JSONL snapshots and a human-readable summary.

Usage:
  labyrinth-perfmon.py once
  labyrinth-perfmon.py watch [--interval 5] [--duration 0]
  labyrinth-perfmon.py report [--last 60]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DNS = os.environ.get("LABYRINTH_DNS", "10.20.10.20")
DEFAULT_WEB = os.environ.get("LABYRINTH_WEB", "http://10.20.10.20:9153")
DEFAULT_UNIT = os.environ.get("LABYRINTH_UNIT", "labyrinth.service")
LOG_DIR = Path(os.environ.get("LABYRINTH_PERFMON_DIR", "/var/lib/labyrinth/perfmon"))
PROBE_NAMES = [
    "google.com",
    "cloudflare.com",
    "github.com",
    "wikipedia.org",
    "example.com",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def unit_main_pid(unit: str) -> int | None:
    try:
        out = subprocess.check_output(
            ["systemctl", "show", "-p", "MainPID", "--value", unit],
            text=True,
            timeout=3,
        ).strip()
        pid = int(out)
        return pid if pid > 0 else None
    except (subprocess.SubprocessError, ValueError):
        return None


def proc_stats(pid: int) -> dict[str, Any]:
    status = read_text(f"/proc/{pid}/status")
    fields = {}
    for line in status.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields[k.strip()] = v.strip()

    rss_kb = int(fields.get("VmRSS", "0").split()[0] or 0)
    vsz_kb = int(fields.get("VmSize", "0").split()[0] or 0)
    threads = int(fields.get("Threads", "0") or 0)

    # CPU % via /proc/stat deltas would need state; expose jiffies instead.
    stat = read_text(f"/proc/{pid}/stat").split()
    utime = int(stat[13]) if len(stat) > 14 else 0
    stime = int(stat[14]) if len(stat) > 14 else 0

    return {
        "pid": pid,
        "rss_mb": round(rss_kb / 1024, 1),
        "vsz_mb": round(vsz_kb / 1024, 1),
        "threads": threads,
        "cpu_jiffies": utime + stime,
        "voluntary_ctxt": int(fields.get("voluntary_ctxt_switches", "0") or 0),
        "nonvoluntary_ctxt": int(fields.get("nonvoluntary_ctxt_switches", "0") or 0),
    }


def dns_udp_queue(listen_ip: str) -> dict[str, Any]:
    """Parse `ss -ulnp` for DNS :53 receive/send queues."""
    try:
        out = subprocess.check_output(["ss", "-ulnp"], text=True, timeout=3)
    except subprocess.SubprocessError:
        return {"recv_q": None, "send_q": None, "saturated": None}

    recv_q = send_q = None
    for line in out.splitlines():
        if ":53" not in line:
            continue
        if listen_ip and listen_ip not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            recv_q = int(parts[1])
            send_q = int(parts[2])
        except ValueError:
            continue
        break
    # UDP Recv-Q is bytes waiting in the kernel. Flag pressure above 64 KiB
    # (or when Recv-Q equals a non-zero Send-Q, which some ss builds report
    # as the effective buffer watermark when the socket is full).
    saturated = None
    if recv_q is not None:
        saturated = recv_q >= 65536 or (send_q is not None and send_q > 0 and recv_q >= send_q)
    return {"recv_q": recv_q, "send_q": send_q, "saturated": saturated}


def dig_latency(server: str, name: str, qtype: str = "A", timeout: float = 2.0) -> dict[str, Any]:
    cmd = [
        "dig",
        f"@{server}",
        name,
        qtype,
        "+time=2",
        "+tries=1",
        "+stats",
    ]
    t0 = time.perf_counter()
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout + 1)
        wall_ms = (time.perf_counter() - t0) * 1000
        status_m = re.search(r"status:\s*([A-Z]+)", out)
        qt_m = re.search(r"Query time:\s*(\d+)\s*msec", out)
        return {
            "name": name,
            "type": qtype,
            "ok": True,
            "rcode": status_m.group(1) if status_m else "UNKNOWN",
            "dig_ms": int(qt_m.group(1)) if qt_m else None,
            "wall_ms": round(wall_ms, 2),
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {
            "name": name,
            "type": qtype,
            "ok": False,
            "error": str(e),
            "wall_ms": round((time.perf_counter() - t0) * 1000, 2),
        }


def http_json(url: str, timeout: float = 2.0) -> Any | None:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def fetch_metrics(web_base: str) -> dict[str, float]:
    url = web_base.rstrip("/") + "/metrics"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            body = resp.read().decode(errors="replace")
    except (urllib.error.URLError, TimeoutError):
        return {}

    out: dict[str, float] = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        # labyrinth_cache_hits_total 123
        # labyrinth_queries_total{type="A"} 1
        m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\s+([0-9.eE+-]+)\s*$", line)
        if not m:
            continue
        try:
            out[m.group(1)] = float(m.group(2))
        except ValueError:
            continue
    return out


def derive_rates(prev: dict[str, Any] | None, cur: dict[str, Any]) -> dict[str, Any]:
    if not prev:
        return {}
    dt = cur["ts_unix"] - prev["ts_unix"]
    if dt <= 0:
        return {}
    rates: dict[str, Any] = {"interval_s": round(dt, 3)}
    p_metrics = prev.get("metrics") or {}
    c_metrics = cur.get("metrics") or {}

    def counter_delta(key: str) -> float | None:
        if key not in p_metrics or key not in c_metrics:
            return None
        return max(0.0, c_metrics[key] - p_metrics[key])

    hits = counter_delta("labyrinth_cache_hits_total")
    misses = counter_delta("labyrinth_cache_misses_total")
    if hits is not None and misses is not None:
        total = hits + misses
        rates["qps_cache_path"] = round(total / dt, 2)
        rates["cache_hit_ratio"] = round(hits / total, 4) if total else None

    up_q = counter_delta("labyrinth_upstream_queries_total")
    up_e = counter_delta("labyrinth_upstream_errors_total")
    if up_q is not None:
        rates["upstream_qps"] = round(up_q / dt, 2)
    if up_e is not None and up_q is not None and up_q > 0:
        rates["upstream_error_ratio"] = round(up_e / up_q, 4)

    if prev.get("proc") and cur.get("proc"):
        dj = cur["proc"]["cpu_jiffies"] - prev["proc"]["cpu_jiffies"]
        # jiffies are typically 100Hz
        hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"]) if hasattr(os, "sysconf_names") else 100
        rates["cpu_cores"] = round(dj / hz / dt, 3)

    return rates


def snapshot(dns: str, web: str, unit: str, prev: dict[str, Any] | None = None) -> dict[str, Any]:
    pid = unit_main_pid(unit)
    probes = [dig_latency(dns, n) for n in PROBE_NAMES]
    ok_ms = [p["wall_ms"] for p in probes if p.get("ok")]
    dig_ms = [p["dig_ms"] for p in probes if p.get("ok") and p.get("dig_ms") is not None]

    snap: dict[str, Any] = {
        "ts": utc_now(),
        "ts_unix": time.time(),
        "unit": unit,
        "dns": dns,
        "web": web,
        "proc": proc_stats(pid) if pid else None,
        "udp53": dns_udp_queue(dns),
        "health": http_json(f"{web.rstrip('/')}/api/system/health"),
        "version": http_json(f"{web.rstrip('/')}/api/system/version"),
        "metrics": fetch_metrics(web),
        "latency": {
            "probes": probes,
            "wall_avg_ms": round(statistics.fmean(ok_ms), 2) if ok_ms else None,
            "wall_p95_ms": round(sorted(ok_ms)[max(0, int(len(ok_ms) * 0.95) - 1)], 2) if ok_ms else None,
            "dig_avg_ms": round(statistics.fmean(dig_ms), 2) if dig_ms else None,
            "success": sum(1 for p in probes if p.get("ok")),
            "total": len(probes),
        },
    }
    snap["rates"] = derive_rates(prev, snap)
    return snap


def print_human(snap: dict[str, Any]) -> None:
    proc = snap.get("proc") or {}
    lat = snap.get("latency") or {}
    udp = snap.get("udp53") or {}
    ver = snap.get("version") or {}
    rates = snap.get("rates") or {}
    health = snap.get("health") or {}

    sat = udp.get("saturated")
    sat_s = "YES" if sat else ("no" if sat is False else "?")
    print(
        f"[{snap['ts']}] v={ver.get('version','?')} "
        f"rss={proc.get('rss_mb','?')}MB thr={proc.get('threads','?')} "
        f"udp53={udp.get('recv_q')}/{udp.get('send_q')} sat={sat_s} "
        f"lat_avg={lat.get('wall_avg_ms')}ms p95={lat.get('wall_p95_ms')}ms "
        f"ok={lat.get('success')}/{lat.get('total')} "
        f"health={health.get('status','?')} "
        f"hit={rates.get('cache_hit_ratio','-')} "
        f"cpu={rates.get('cpu_cores','-')}"
    )


def cmd_once(args: argparse.Namespace) -> int:
    snap = snapshot(args.dns, args.web, args.unit)
    print_human(snap)
    if args.json:
        print(json.dumps(snap, indent=2))
    if args.save:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        path = LOG_DIR / "snapshots.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(snap, separators=(",", ":")) + "\n")
        print(f"saved -> {path}", file=sys.stderr)
    return 0 if (snap.get("latency") or {}).get("success") else 1


def cmd_watch(args: argparse.Namespace) -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / "snapshots.jsonl"
    prev = None
    end = time.time() + args.duration if args.duration > 0 else None
    print(f"watching every {args.interval}s -> {path}", file=sys.stderr)
    try:
        while True:
            snap = snapshot(args.dns, args.web, args.unit, prev)
            print_human(snap)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(snap, separators=(",", ":")) + "\n")
            prev = snap
            if end is not None and time.time() >= end:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    path = LOG_DIR / "snapshots.jsonl"
    if not path.exists():
        print(f"no data at {path}", file=sys.stderr)
        return 1
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows = rows[-args.last :]
    if not rows:
        print("empty")
        return 1

    rss = [r["proc"]["rss_mb"] for r in rows if r.get("proc")]
    lat = [r["latency"]["wall_avg_ms"] for r in rows if r.get("latency", {}).get("wall_avg_ms") is not None]
    sat = sum(1 for r in rows if (r.get("udp53") or {}).get("saturated"))
    hits = [r["rates"]["cache_hit_ratio"] for r in rows if (r.get("rates") or {}).get("cache_hit_ratio") is not None]

    print(f"samples={len(rows)} window_last={args.last}")
    if rss:
        print(f"rss_mb: min={min(rss)} avg={round(statistics.fmean(rss),1)} max={max(rss)}")
    if lat:
        print(f"latency_ms: min={min(lat)} avg={round(statistics.fmean(lat),2)} max={max(lat)}")
    print(f"udp53_saturated_samples: {sat}/{len(rows)}")
    if hits:
        print(f"cache_hit_ratio: min={min(hits)} avg={round(statistics.fmean(hits),4)} max={max(hits)}")

    # Simple recommendations
    print("\nrecommendations:")
    if rss and max(rss) > 3000:
        print("- RSS > 3GB: consider lowering cache.max_entries or enabling serve_stale carefully; watch for GC pressure.")
    if sat > 0:
        print("- UDP :53 recv queue saturated: increase net.core.rmem_*; reduce max_udp_workers contention; check rate limits.")
    if lat and statistics.fmean(lat) > 50:
        print("- Average probe latency > 50ms: check upstream_timeout, prefetch, and DNSSEC path.")
    if hits and statistics.fmean(hits) < 0.7:
        print("- Cache hit ratio < 70%: review TTL clamps, negative cache, and query mix.")
    if not hits:
        print("- /metrics not scraped yet (enable web /metrics or standalone metrics_addr).")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Labyrinth performance monitor")
    p.add_argument("--dns", default=DEFAULT_DNS)
    p.add_argument("--web", default=DEFAULT_WEB)
    p.add_argument("--unit", default=DEFAULT_UNIT)
    sub = p.add_subparsers(dest="cmd", required=True)

    once = sub.add_parser("once", help="one-shot snapshot")
    once.add_argument("--json", action="store_true")
    once.add_argument("--save", action="store_true")
    once.set_defaults(func=cmd_once)

    watch = sub.add_parser("watch", help="continuous monitoring")
    watch.add_argument("--interval", type=float, default=5.0)
    watch.add_argument("--duration", type=float, default=0.0, help="0 = forever")
    watch.set_defaults(func=cmd_watch)

    report = sub.add_parser("report", help="summarize saved snapshots")
    report.add_argument("--last", type=int, default=60)
    report.set_defaults(func=cmd_report)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    # silence unused import for socket (kept for future UDP probe)
    _ = socket
    sys.exit(main())
