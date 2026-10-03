#!/usr/bin/env bash
# Replace running Labyrinth with the newly built binary.
# Requires explicit CONFIRM=yes — does not stop the service otherwise.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_SRC="${BIN_SRC:-$ROOT/labyrinth}"
BENCH_SRC="${BENCH_SRC:-$ROOT/labyrinth-bench}"
DEST_DIR=/opt/labyrinth/bin
CONFIG=/etc/labyrinth/labyrinth.yaml

if [[ "${CONFIRM:-}" != "yes" ]]; then
  cat <<EOF
Refusing to stop production DNS without confirmation.

Current:  $(systemctl show -p MainPID,ExecMainStartTimestamp,FragmentPath --value labyrinth.service | tr '\n' ' ')
New bin:  $BIN_SRC ($( "$BIN_SRC" -version 2>&1 | head -1 ))
Dest:     $DEST_DIR/labyrinth

To proceed:
  CONFIRM=yes $0
EOF
  exit 2
fi

[[ -x "$BIN_SRC" ]] || { echo "missing binary: $BIN_SRC"; exit 1; }

echo "==> baseline snapshot"
/usr/bin/python3 /opt/labyrinth/monitor/labyrinth-perfmon.py once --save || true

TS=$(date -u +%Y%m%dT%H%M%SZ)
echo "==> backup current binary -> ${DEST_DIR}/labyrinth.bak.${TS}"
cp -a "${DEST_DIR}/labyrinth" "${DEST_DIR}/labyrinth.bak.${TS}"
[[ -x "$BENCH_SRC" ]] && cp -a "$BENCH_SRC" "${DEST_DIR}/labyrinth-bench"

echo "==> install new binary"
install -m 0755 "$BIN_SRC" "${DEST_DIR}/labyrinth"
chown labyrinth:labyrinth "${DEST_DIR}/labyrinth" 2>/dev/null || true
chmod 0751 "${DEST_DIR}/labyrinth" 2>/dev/null || chmod 0755 "${DEST_DIR}/labyrinth"
ln -sfn "${DEST_DIR}/labyrinth" /usr/local/bin/labyrinth

echo "==> restart labyrinth.service"
systemctl restart labyrinth.service
sleep 1
systemctl --no-pager --full status labyrinth.service | head -20

echo "==> health/version"
curl -fsS --max-time 3 http://10.20.10.20:9153/api/system/health; echo
curl -fsS --max-time 3 http://10.20.10.20:9153/api/system/version; echo
curl -fsS --max-time 3 http://10.20.10.20:9153/metrics | head -20 || echo "(metrics still unavailable)"

echo "==> post snapshot"
/usr/bin/python3 /opt/labyrinth/monitor/labyrinth-perfmon.py once --save || true
echo "Done. Rollback: install -m 0755 ${DEST_DIR}/labyrinth.bak.${TS} ${DEST_DIR}/labyrinth && systemctl restart labyrinth"
