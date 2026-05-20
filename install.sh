#!/usr/bin/env bash
set -euo pipefail

# Labyrinth DNS Resolver — Install Script
# Usage: curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash
# Or:    bash install.sh [--no-service] [--version v0.5.1]

REPO="labyrinthdns/labyrinth"
# Binary lives in a labyrinth-owned dir so the web-UI self-update can
# rewrite it as the service user. /usr/local/bin/labyrinth is a symlink for
# shell PATH compatibility — older installs that used /usr/local/bin directly
# are migrated by update.sh.
INSTALL_DIR="/opt/labyrinth/bin"
PATH_LINK_DIR="/usr/local/bin"
CONFIG_DIR="/etc/labyrinth"
CONFIG_FILE="${CONFIG_DIR}/labyrinth.yaml"
SERVICE_USER="labyrinth"
SERVICE_FILE="/etc/systemd/system/labyrinth.service"
VERSION=""
NO_SERVICE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --no-service) NO_SERVICE=true; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --help|-h)
      echo "Labyrinth DNS Resolver — Installer"
      echo ""
      echo "Usage: install.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --no-service    Skip systemd service installation"
      echo "  --version TAG   Install specific version (default: latest)"
      echo "  --help, -h      Show this help"
      echo ""
      echo "Examples:"
      echo "  curl -sSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash"
      echo "  bash install.sh --version v0.5.1"
      echo "  bash install.sh --no-service"
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
echo "  ║   Labyrinth DNS Resolver — Installer  ║"
echo "  ║   https://labyrinthdns.com            ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
  fail "This script must be run as root (use sudo)"
fi

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

info "Detected: ${OS}/${ARCH}"

# Get latest version if not specified
if [[ -z "$VERSION" ]]; then
  info "Fetching latest release..."
  VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' 2>/dev/null || echo "")
  if [[ -z "$VERSION" ]]; then
    fail "Could not determine latest version. Use --version to specify."
  fi
fi

info "Installing Labyrinth ${VERSION}..."

# Check if already installed (resolve symlink so we report the real binary)
if command -v labyrinth &>/dev/null; then
  EXISTING=$(command -v labyrinth)
  CURRENT=$("$EXISTING" version 2>&1 | head -1 || echo "unknown")
  warn "Labyrinth already installed: ${CURRENT}"
  warn "Continuing with forced reinstall (same version is allowed)."
fi

# Ensure target dirs exist before we download into them.
mkdir -p "$INSTALL_DIR"

# Download binaries
BINARY_NAME="labyrinth-${OS}-${ARCH}"
BENCH_NAME="labyrinth-bench-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
BENCH_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BENCH_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

# C-3: integrity verification. The release pipeline produces checksums.txt;
# verify the downloaded binary against it before installing. Refuse to
# install if the checksum cannot be obtained or does not match. (Long term:
# replace with cosign signature verification.)
SHA_TOOL=""
if command -v sha256sum &>/dev/null; then
  SHA_TOOL="sha256sum"
elif command -v shasum &>/dev/null; then
  SHA_TOOL="shasum -a 256"
fi

if [[ -z "$SHA_TOOL" ]]; then
  fail "Neither sha256sum nor shasum found — cannot verify download integrity. Aborting."
fi

TMP_CHECKSUMS=$(mktemp)
info "Fetching checksums.txt..."
if ! curl -fsSL -o "$TMP_CHECKSUMS" "$CHECKSUMS_URL"; then
  rm -f "$TMP_CHECKSUMS"
  fail "Could not download checksums.txt from ${CHECKSUMS_URL}. Refusing to install unverified binary."
fi

verify_sha() {
  local file="$1"
  local name="$2"
  local expected
  expected=$(grep -E "[[:space:]]\\*?${name}\$" "$TMP_CHECKSUMS" | awk '{print $1}' | head -n1)
  if [[ -z "$expected" ]]; then
    fail "No checksum entry for ${name} in checksums.txt"
  fi
  local actual
  actual=$($SHA_TOOL "$file" | awk '{print $1}')
  if [[ "$expected" != "$actual" ]]; then
    fail "Checksum mismatch for ${name}: expected ${expected}, got ${actual}"
  fi
  ok "Checksum verified: ${name}"
}

TMP_FILE=$(mktemp)
info "Downloading labyrinth..."
if ! curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"; then
  rm -f "$TMP_FILE" "$TMP_CHECKSUMS"
  fail "Download failed: ${DOWNLOAD_URL}"
fi

verify_sha "$TMP_FILE" "$BINARY_NAME"

chmod +x "$TMP_FILE"
mv "$TMP_FILE" "${INSTALL_DIR}/labyrinth"
ok "Binary installed: ${INSTALL_DIR}/labyrinth"

# Maintain a PATH-visible symlink. If an old install left a real binary at
# the symlink path, replace it (its content has just been re-deployed to
# INSTALL_DIR via the verified download).
if [[ -e "${PATH_LINK_DIR}/labyrinth" && ! -L "${PATH_LINK_DIR}/labyrinth" ]]; then
  rm -f "${PATH_LINK_DIR}/labyrinth"
fi
ln -sf "${INSTALL_DIR}/labyrinth" "${PATH_LINK_DIR}/labyrinth"
ok "Symlink: ${PATH_LINK_DIR}/labyrinth -> ${INSTALL_DIR}/labyrinth"

# Download bench tool (optional, don't fail) — but if downloaded, it MUST verify.
TMP_BENCH=$(mktemp)
info "Downloading labyrinth-bench..."
if curl -fsSL -o "$TMP_BENCH" "$BENCH_URL" 2>/dev/null; then
  verify_sha "$TMP_BENCH" "$BENCH_NAME"
  chmod +x "$TMP_BENCH"
  mv "$TMP_BENCH" "${INSTALL_DIR}/labyrinth-bench"
  ok "Bench tool installed: ${INSTALL_DIR}/labyrinth-bench"
  if [[ -e "${PATH_LINK_DIR}/labyrinth-bench" && ! -L "${PATH_LINK_DIR}/labyrinth-bench" ]]; then
    rm -f "${PATH_LINK_DIR}/labyrinth-bench"
  fi
  ln -sf "${INSTALL_DIR}/labyrinth-bench" "${PATH_LINK_DIR}/labyrinth-bench"
else
  rm -f "$TMP_BENCH"
  warn "Bench tool not available (optional)"
fi

rm -f "$TMP_CHECKSUMS"

# Verify
INSTALLED_VERSION=$("${INSTALL_DIR}/labyrinth" version 2>&1 | head -1)
ok "${INSTALLED_VERSION}"

# Create config directory
if [[ ! -d "$CONFIG_DIR" ]]; then
  mkdir -p "$CONFIG_DIR"
  ok "Created ${CONFIG_DIR}"
fi

# Create default config if not exists
if [[ ! -f "$CONFIG_FILE" ]]; then
  cat > "$CONFIG_FILE" << 'YAML'
# Labyrinth DNS Resolver Configuration
# Documentation: https://labyrinthdns.com/docs
# GitHub: https://github.com/labyrinthdns/labyrinth

server:
  listen_addr: "0.0.0.0:53"
  metrics_addr: "127.0.0.1:9153"
  tcp_timeout: 10s
  max_tcp_connections: 256
  graceful_shutdown: 5s

resolver:
  max_depth: 30
  max_cname_depth: 10
  upstream_timeout: 2s
  upstream_retries: 3
  qname_minimization: true
  prefer_ipv4: true
  dnssec_enabled: true

cache:
  max_entries: 100000
  min_ttl: 5
  max_ttl: 86400
  negative_max_ttl: 3600
  sweep_interval: 60s
  serve_stale: false
  serve_stale_ttl: 30

security:
  rate_limit:
    enabled: true
    rate: 50
    burst: 100
  rrl:
    enabled: true
    responses_per_second: 5
    slip_ratio: 2
    ipv4_prefix: 24
    ipv6_prefix: 56

logging:
  level: info
  format: json

web:
  enabled: true
  addr: "127.0.0.1:9153"
  query_log_buffer: 1000
  top_clients_limit: 2000
  top_domains_limit: 2000
  auto_update: true
  update_check_interval: 24h
  # Set up admin credentials via the web setup wizard
  # or manually with: labyrinth hash <password>
  # auth:
  #   username: admin
  #   password_hash: <bcrypt hash>

# blocklist:
#   enabled: true
#   lists: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|hosts"
#   refresh_interval: 24h
#   blocking_mode: nxdomain

# access_control:
#   allow: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
#   deny:
YAML
  ok "Default config written to ${CONFIG_FILE}"
else
  warn "Config already exists at ${CONFIG_FILE}, not overwriting"
fi

# Service installation
if [[ "$NO_SERVICE" == true ]]; then
  info "Skipping service installation (--no-service)"
else
  # Create service user
  if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
    ok "Created service user: ${SERVICE_USER}"
  fi

  chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR" 2>/dev/null || true
  # /opt/labyrinth/bin must be writable by the service user so the web UI
  # self-update can atomically swap the binary without needing root.
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" 2>/dev/null || true

  if command -v systemctl &>/dev/null; then
    cat > "$SERVICE_FILE" << 'SERVICE'
[Unit]
Description=Labyrinth Recursive DNS Resolver
Documentation=https://labyrinthdns.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=labyrinth
Group=labyrinth
# Binary lives in /opt/labyrinth/bin so the web-UI self-update can rewrite
# it as the service user. /usr/local/bin/labyrinth is a symlink for PATH compat.
ExecStart=/opt/labyrinth/bin/labyrinth -config /etc/labyrinth/labyrinth.yaml
ExecReload=/bin/kill -SIGUSR1 $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
# /etc/labyrinth: live config reload writes labyrinth.yaml from the admin API.
# /opt/labyrinth/bin: self-update rename target (also writable by service user).
ReadWritePaths=/etc/labyrinth /opt/labyrinth/bin
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
SERVICE
    ok "Systemd service installed"

    systemctl daemon-reload
    systemctl enable labyrinth 2>/dev/null || true
    ok "Service enabled"

    if systemctl is-active labyrinth &>/dev/null; then
      systemctl restart labyrinth
      ok "Service restarted"
    else
      systemctl start labyrinth
      ok "Service started"
    fi

    sleep 2
    if systemctl is-active labyrinth &>/dev/null; then
      ok "Labyrinth is running"
    else
      warn "Service may have failed to start. Check: journalctl -u labyrinth -e"
    fi
  else
    warn "systemd not found. Start manually: labyrinth -config ${CONFIG_FILE}"
  fi
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Labyrinth installed successfully!    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo "  Binary:    ${INSTALL_DIR}/labyrinth"
echo "  Symlink:   ${PATH_LINK_DIR}/labyrinth -> ${INSTALL_DIR}/labyrinth"
echo "  Config:    ${CONFIG_FILE}"
echo "  Dashboard: http://127.0.0.1:9153"
echo ""
echo "  Test:      dig @localhost google.com A"
echo "  Logs:      journalctl -u labyrinth -f"
echo "  Status:    systemctl status labyrinth"
echo "  Update:    curl -sSL https://raw.githubusercontent.com/${REPO}/main/update.sh | sudo bash"
echo ""
echo "  Visit the dashboard to complete setup:"
echo "  http://127.0.0.1:9153"
echo ""

