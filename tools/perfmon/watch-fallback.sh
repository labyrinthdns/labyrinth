#!/bin/bash
# Tail Labyrinth fallback debug log (JSONL, one line per fallback engagement).
LOG=${1:-/var/lib/labyrinth/fallback.jsonl}
echo "watching $LOG (Ctrl-C to stop)"
mkdir -p "$(dirname "$LOG")"
touch "$LOG" 2>/dev/null || true
exec tail -F "$LOG"
