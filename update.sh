#!/usr/bin/env bash
set -euo pipefail

# Labyrinth DNS Resolver — Update Script
# Usage: curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/update.sh | sudo bash
# Or:    sudo bash update.sh [--version v0.4.8] [--no-restart] [--check]

REPO="labyrinthdns/labyrinth"
# New layout: binary at /opt/labyrinth/bin/labyrinth (labyrinth-owned, so the
# web-UI self-update can rewrite it), with /usr/local/bin/labyrinth as a
# symlink for PATH compat. Old layout had the real binary at /usr/local/bin.
# This script migrates the old layout to the new one in place, idempotently.
INSTALL_DIR="/opt/labyrinth/bin"
PATH_LINK_DIR="/usr/local/bin"
BINARY="${INSTALL_DIR}/labyrinth"
PATH_LINK="${PATH_LINK_DIR}/labyrinth"
SERVICE_USER="labyrinth"
SERVICE_FILE="/etc/systemd/system/labyrinth.service"
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

# Detect current version — look in both new and old install locations.
CURRENT_VERSION="not installed"
CURRENT_BINARY=""
for candidate in "$BINARY" "${PATH_LINK_DIR}/labyrinth"; do
  if [[ -x "$candidate" ]]; then
    CURRENT_BINARY="$candidate"
    CURRENT_VERSION=$("$candidate" version 2>&1 | grep -oP 'Labyrinth \K[^\s]+' || echo "unknown")
    break
  fi
done
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
  mkdir -p "$INSTALL_DIR"
  mv "$TMP_BENCH" "${INSTALL_DIR}/labyrinth-bench"
  # PATH-compat symlink for the bench tool too.
  if [[ -e "${PATH_LINK_DIR}/labyrinth-bench" && ! -L "${PATH_LINK_DIR}/labyrinth-bench" ]]; then
    rm -f "${PATH_LINK_DIR}/labyrinth-bench"
  fi
  ln -sf "${INSTALL_DIR}/labyrinth-bench" "${PATH_LINK_DIR}/labyrinth-bench"
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

# ---------------------------------------------------------------------------
# Migration: detect pre-0.6.8 layout (binary directly at /usr/local/bin) and
# move it under /opt/labyrinth/bin so the web-UI self-update path can rewrite
# it without root privileges. Idempotent: a no-op if already migrated.
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"

LEGACY_BINARY="${PATH_LINK_DIR}/labyrinth"
MIGRATED_LAYOUT=false
if [[ -e "$LEGACY_BINARY" && ! -L "$LEGACY_BINARY" ]]; then
  info "Migrating binary to ${INSTALL_DIR} (was at ${LEGACY_BINARY})"
  cp -a "$LEGACY_BINARY" "${LEGACY_BINARY}.pre-migration.bak"
  mv "$LEGACY_BINARY" "$BINARY"
  ln -sf "$BINARY" "$LEGACY_BINARY"
  ok "Migrated: $LEGACY_BINARY -> $BINARY (symlinked back for PATH compat)"
  MIGRATED_LAYOUT=true
elif [[ ! -L "$LEGACY_BINARY" && ! -e "$LEGACY_BINARY" ]]; then
  # Fresh install or upgrade after a previous migration: ensure symlink exists.
  :
fi

# Backup current binary in new location (if present) before swap.
if [[ -f "$BINARY" ]]; then
  cp "$BINARY" "${BINARY}.bak"
  ok "Backup: ${BINARY}.bak"
fi

# Replace binary at the new canonical path.
mv "$TMP_FILE" "$BINARY"
ok "Binary updated: ${BINARY}"

# Ensure the labyrinth user owns /opt/labyrinth/bin so the web-UI self-update
# (running as that user) can atomically rename a new binary into place.
if id "$SERVICE_USER" &>/dev/null; then
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" 2>/dev/null || true
fi

# Maintain /usr/local/bin/labyrinth as a symlink — replace a stale real file
# if migration above didn't already do so (e.g. fresh install on a system
# that never had a binary at the legacy path).
if [[ -e "$LEGACY_BINARY" && ! -L "$LEGACY_BINARY" ]]; then
  rm -f "$LEGACY_BINARY"
fi
ln -sf "$BINARY" "$LEGACY_BINARY"

# ---------------------------------------------------------------------------
# Service unit migration: rewrite ExecStart + ReadWritePaths if the existing
# unit still points at /usr/local/bin or lacks the self-update writable path.
# Backup is kept at ${SERVICE_FILE}.bak. Idempotent.
# ---------------------------------------------------------------------------
if [[ -f "$SERVICE_FILE" ]]; then
  # Portable word-boundary substitute: a path is "present" in ReadWritePaths
  # if it is preceded by either '=' or whitespace AND followed by whitespace
  # or end-of-line. \b is unreliable around '/' on BSD/Win grep.
  has_path() {
    local file="$1" path="$2"
    grep -qE "^ReadWritePaths=.*(=|[[:space:]])${path}([[:space:]]|\$)" "$file"
  }

  NEEDS_UNIT_PATCH=false
  if grep -qE '^ExecStart=/usr/local/bin/labyrinth' "$SERVICE_FILE"; then
    NEEDS_UNIT_PATCH=true
  fi
  if ! has_path "$SERVICE_FILE" "/opt/labyrinth/bin"; then
    NEEDS_UNIT_PATCH=true
  fi
  # Legacy units used ReadOnlyPaths=/etc/labyrinth, which blocks the live
  # config reload that PUT /api/config/raw needs. Replace with ReadWritePaths.
  if grep -qE '^ReadOnlyPaths=/etc/labyrinth' "$SERVICE_FILE"; then
    NEEDS_UNIT_PATCH=true
  fi

  if [[ "$NEEDS_UNIT_PATCH" == true ]]; then
    info "Patching ${SERVICE_FILE} for autonomous self-update + live config reload"
    cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
    # Rewrite ExecStart, fold ReadOnlyPaths into ReadWritePaths.
    sed -i \
      -e 's|^ExecStart=/usr/local/bin/labyrinth|ExecStart=/opt/labyrinth/bin/labyrinth|' \
      -e '/^ReadOnlyPaths=\/etc\/labyrinth$/d' \
      "$SERVICE_FILE"
    # Ensure a ReadWritePaths line exists with both required paths.
    if grep -qE '^ReadWritePaths=' "$SERVICE_FILE"; then
      if ! has_path "$SERVICE_FILE" "/opt/labyrinth/bin"; then
        sed -i 's|^ReadWritePaths=\(.*\)$|ReadWritePaths=\1 /opt/labyrinth/bin|' "$SERVICE_FILE"
      fi
      if ! has_path "$SERVICE_FILE" "/etc/labyrinth"; then
        sed -i 's|^ReadWritePaths=\(.*\)$|ReadWritePaths=\1 /etc/labyrinth|' "$SERVICE_FILE"
      fi
    else
      # Insert before [Install] section.
      sed -i '/^\[Install\]/i ReadWritePaths=/etc/labyrinth /opt/labyrinth/bin' "$SERVICE_FILE"
    fi
    systemctl daemon-reload
    ok "Service unit patched (backup: ${SERVICE_FILE}.bak)"
  fi
fi

if [[ "$MIGRATED_LAYOUT" == true ]]; then
  warn "Binary relocated to ${INSTALL_DIR}. Pre-migration copy kept at ${LEGACY_BINARY}.pre-migration.bak — remove once you confirm everything is working."
fi

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
echo "  Binary:    ${BINARY}"
echo "  Symlink:   ${PATH_LINK} -> ${BINARY}"
echo "  Status:    systemctl status labyrinth"
echo "  Logs:      journalctl -u labyrinth -f"
echo "  Dashboard: http://127.0.0.1:9153"
echo ""
echo "  Future updates can be applied from the dashboard's About/Updates page"
echo "  (no need to re-run this script)."
echo ""

