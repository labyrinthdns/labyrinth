#!/usr/bin/env bash
set -euo pipefail

# Labyrinth DNS Resolver — Uninstall Script
# Usage: curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/uninstall.sh | sudo bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║  Labyrinth DNS Resolver — Uninstaller ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[FAIL]${NC} This script must be run as root (use sudo)"
  exit 1
fi

# Show current version
if [[ -f /usr/local/bin/labyrinth ]]; then
  CURRENT=$(/usr/local/bin/labyrinth version 2>&1 | head -1 || echo "unknown")
  info "Installed: ${CURRENT}"
fi

echo ""
echo "This will completely remove Labyrinth from your system:"
echo "  - Stop and disable the systemd service"
echo "  - Remove binaries (labyrinth, labyrinth-bench)"
echo "  - Remove service user"
echo "  - Optionally remove config and data"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# Stop and disable service
if command -v systemctl &>/dev/null; then
  if systemctl is-active labyrinth &>/dev/null; then
    systemctl stop labyrinth
    ok "Service stopped"
  fi
  if systemctl is-enabled labyrinth &>/dev/null; then
    systemctl disable labyrinth 2>/dev/null || true
    ok "Service disabled"
  fi
  rm -f /etc/systemd/system/labyrinth.service
  systemctl daemon-reload 2>/dev/null || true
  ok "Service file removed"
fi

# Remove binaries
rm -f /usr/local/bin/labyrinth
rm -f /usr/local/bin/labyrinth.bak
rm -f /usr/local/bin/labyrinth-bench
ok "Binaries removed"

# Ask about config
echo ""
read -p "Remove config directory /etc/labyrinth? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf /etc/labyrinth
  ok "Config removed"
else
  info "Config preserved at /etc/labyrinth"
fi

# Remove user
if id labyrinth &>/dev/null; then
  userdel labyrinth 2>/dev/null || true
  ok "Service user removed"
fi

# Remove PID file
rm -f /var/run/labyrinth.pid 2>/dev/null || true

echo ""
echo -e "${GREEN}Labyrinth has been uninstalled.${NC}"
echo ""
echo "  To reinstall:"
echo "  curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | sudo bash"
echo ""
