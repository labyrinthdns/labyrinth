#!/usr/bin/env bash
set -euo pipefail

# Labyrinth DNS Resolver — Update Script
# Usage: curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/update.sh | sudo bash
# Or:    sudo bash update.sh [--version v0.4.8] [--no-restart] [--check]

REPO="labyrinthdns/labyrinth"
INSTALL_DIR="/usr/local/bin"
BINARY="${INSTALL_DIR}/labyrinth"
VERSION=""
NO_RESTART=false
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --version) VERSION="$2"; shift 2 ;;
    --no-restart) NO_RESTART=true; shift ;;
    --check) CHECK_ONLY=true; shift ;;
    --help|-h)
      echo "Labyrinth DNS Resolver — Updater"
      echo ""
      echo "Usage: update.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --check         Check for updates without installing"
      echo "  --version TAG   Install specific version (default: latest)"
      echo "  --no-restart    Download only, don't restart the service"
      echo "  --help, -h      Show this help"
      echo ""
      echo "Examples:"
      echo "  sudo bash update.sh                  # Update to latest"
      echo "  sudo bash update.sh --check          # Just check"
      echo "  sudo bash update.sh --version v0.4.8 # Specific version"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   Labyrinth DNS Resolver — Updater    ║"
echo "  ║   https://labyrinthdns.com            ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Check root (unless --check)
if [[ "$CHECK_ONLY" == false ]] && [[ $EUID -ne 0 ]]; then
  fail "This script must be run as root (use sudo)"
fi

# Detect current version
CURRENT_VERSION="not installed"
if [[ -f "$BINARY" ]]; then
  CURRENT_VERSION=$("$BINARY" version 2>&1 | grep -oP 'Labyrinth \K[^\s]+' || echo "unknown")
fi
info "Current version: ${CURRENT_VERSION}"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# Get latest version if not specified
if [[ -z "$VERSION" ]]; then
  info "Checking for updates..."
  RELEASE_JSON=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || echo "")
  if [[ -z "$RELEASE_JSON" ]]; then
    fail "Could not reach GitHub API. Check your internet connection."
  fi
  VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
  if [[ -z "$VERSION" ]]; then
    fail "Could not determine latest version."
  fi
fi

info "Latest version:  ${VERSION}"

# Compare versions
CURRENT_CLEAN="${CURRENT_VERSION#v}"
LATEST_CLEAN="${VERSION#v}"

SAME_VERSION=false
if [[ "$CURRENT_CLEAN" == "$LATEST_CLEAN" ]]; then
  SAME_VERSION=true
fi

echo ""
if [[ "$SAME_VERSION" == true ]]; then
  warn "Installed version matches target (${VERSION}). Continuing with forced reinstall..."
else
  info "Update available: ${CURRENT_VERSION} -> ${VERSION}"
fi

if [[ "$CHECK_ONLY" == true ]]; then
  if [[ "$SAME_VERSION" == true ]]; then
    ok "Already up to date (${VERSION})"
    exit 0
  fi
  echo ""
  echo "Run the following to update:"
  echo "  curl -sSL https://raw.githubusercontent.com/${REPO}/main/update.sh | sudo bash"
  exit 0
fi

# Download new binary
BINARY_NAME="labyrinth-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"

TMP_FILE=$(mktemp)
info "Downloading ${BINARY_NAME}..."
if ! curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"; then
  rm -f "$TMP_FILE"
  fail "Download failed: ${DOWNLOAD_URL}"
fi

chmod +x "$TMP_FILE"

# Verify the new binary works
NEW_VERSION=$("$TMP_FILE" version 2>&1 | head -1 || echo "")
if [[ -z "$NEW_VERSION" ]]; then
  rm -f "$TMP_FILE"
  fail "Downloaded binary verification failed"
fi
ok "Downloaded: ${NEW_VERSION}"

# Download bench tool (optional)
BENCH_NAME="labyrinth-bench-${OS}-${ARCH}"
BENCH_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BENCH_NAME}"
TMP_BENCH=$(mktemp)
if curl -fsSL -o "$TMP_BENCH" "$BENCH_URL" 2>/dev/null; then
  chmod +x "$TMP_BENCH"
  mv "$TMP_BENCH" "${INSTALL_DIR}/labyrinth-bench"
  ok "Bench tool updated"
else
  rm -f "$TMP_BENCH"
fi

# Stop service before replacing binary
SERVICE_WAS_RUNNING=false
if command -v systemctl &>/dev/null && systemctl is-active labyrinth &>/dev/null; then
  SERVICE_WAS_RUNNING=true
  info "Stopping labyrinth service..."
  systemctl stop labyrinth
  ok "Service stopped"
fi

# Backup old binary
if [[ -f "$BINARY" ]]; then
  cp "$BINARY" "${BINARY}.bak"
  ok "Backup: ${BINARY}.bak"
fi

# Replace binary
mv "$TMP_FILE" "$BINARY"
ok "Binary updated: ${BINARY}"

# Restart service
if [[ "$NO_RESTART" == true ]]; then
  info "Skipping restart (--no-restart)"
elif [[ "$SERVICE_WAS_RUNNING" == true ]]; then
  info "Starting labyrinth service..."
  systemctl start labyrinth
  sleep 2
  if systemctl is-active labyrinth &>/dev/null; then
    ok "Service running"
  else
    warn "Service failed to start. Rolling back..."
    if [[ -f "${BINARY}.bak" ]]; then
      mv "${BINARY}.bak" "$BINARY"
      systemctl start labyrinth
      if systemctl is-active labyrinth &>/dev/null; then
        ok "Rolled back to previous version"
      else
        fail "Rollback failed. Check: journalctl -u labyrinth -e"
      fi
    fi
    fail "Update failed. Previous version restored."
  fi
  # Clean up backup on success
  rm -f "${BINARY}.bak"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Labyrinth updated successfully!      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo "  ${CURRENT_VERSION} → ${VERSION}"
echo ""
echo "  Status:    systemctl status labyrinth"
echo "  Logs:      journalctl -u labyrinth -f"
echo "  Dashboard: http://127.0.0.1:9153"
echo ""

