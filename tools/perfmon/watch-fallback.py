#!/usr/bin/env python3
"""Pretty-print Labyrinth fallback.jsonl (live tail)."""
import json, sys, time, os

path = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/labyrinth/fallback.jsonl"
print(f"watching {path}", flush=True)
os.makedirs(os.path.dirname(path), exist_ok=True)
open(path, "a").close()

with open(path, "r") as f:
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            print(line.rstrip(), flush=True)
            continue
        rec = "recovered" if o.get("recovered") else "UNRECOVERED"
        print(
            f"{o.get('time','')}  {rec:11}  {o.get('qtype_name','?'):5}  "
            f"{o.get('name')}  reason={o.get('reason')}  "
            f"dnssec={o.get('dnssec_status') or '-'}  "
            f"dnssec_reason={o.get('dnssec_reason') or '-'}  "
            f"via={o.get('fallback_addr')}  rcode={o.get('fallback_rcode')}",
            flush=True,
        )
