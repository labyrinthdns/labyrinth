#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
install -d -m 0755 /opt/labyrinth/monitor /var/lib/labyrinth/perfmon /var/log/labyrinth
install -m 0755 "$ROOT/tools/perfmon/labyrinth-perfmon.py" /opt/labyrinth/monitor/labyrinth-perfmon.py
install -m 0644 "$ROOT/tools/perfmon/labyrinth-perfmon.service" /etc/systemd/system/labyrinth-perfmon.service
install -m 0644 "$ROOT/tools/perfmon/labyrinth-perfmon.timer" /etc/systemd/system/labyrinth-perfmon.timer
if [[ -d /etc/zabbix/zabbix_agent2.d ]]; then
  install -m 0644 "$ROOT/tools/perfmon/zabbix_labyrinth.conf" /etc/zabbix/zabbix_agent2.d/labyrinth.conf
  systemctl try-restart zabbix-agent2.service 2>/dev/null || true
fi
systemctl daemon-reload
systemctl enable --now labyrinth-perfmon.timer
systemctl start labyrinth-perfmon.service || true
echo "Installed monitor + timer. Try: labyrinth-perfmon.py once / report"
/usr/bin/python3 /opt/labyrinth/monitor/labyrinth-perfmon.py once --save
