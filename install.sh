#!/usr/bin/env bash
set -euo pipefail

# Labyrinth DNS Resolver — Install Script
# Usage: curl -sSL https://raw.githubusercontent.com/labyrinth-dns/labyrinth/main/install.sh | bash
# Or:    bash install.sh [--no-service] [--version v1.0.0]

REPO="labyrinth-dns/labyrinth"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/labyrinth"
CONFIG_FILE="${CONFIG_DIR}/labyrinth.yaml"
SERVICE_USER="labyrinth"
SERVICE_FILE="/etc/systemd/system/labyrinth.service"
VERSION=""
NO_SERVICE=false

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --no-service) NO_SERVICE=true; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: install.sh [--no-service] [--version v1.0.0]"
      echo ""
      echo "Options:"
      echo "  --no-service    Skip systemd service installation"
      echo "  --version TAG   Install specific version (default: latest)"
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
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

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

# Download binary
BINARY_NAME="labyrinth-${OS}-${ARCH}"
if [[ "$OS" == "windows" ]]; then
  BINARY_NAME="${BINARY_NAME}.exe"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
TMP_FILE=$(mktemp)

info "Downloading from ${DOWNLOAD_URL}..."
if ! curl -sSL -o "$TMP_FILE" "$DOWNLOAD_URL"; then
  # Fallback: try tar.gz archive
  ARCHIVE_URL="https://github.com/${REPO}/releases/download/${VERSION}/labyrinth-${VERSION}-${OS}-${ARCH}.tar.gz"
  info "Direct binary not found, trying archive: ${ARCHIVE_URL}..."
  TMP_DIR=$(mktemp -d)
  if ! curl -sSL "$ARCHIVE_URL" | tar xz -C "$TMP_DIR"; then
    fail "Download failed. Check the version and try again."
  fi
  TMP_FILE=$(find "$TMP_DIR" -name "labyrinth*" -type f | head -1)
  if [[ -z "$TMP_FILE" ]]; then
    fail "Binary not found in archive"
  fi
fi

# Install binary
chmod +x "$TMP_FILE"
mv "$TMP_FILE" "${INSTALL_DIR}/labyrinth"
ok "Binary installed to ${INSTALL_DIR}/labyrinth"

# Verify
if ! "${INSTALL_DIR}/labyrinth" -version > /dev/null 2>&1; then
  fail "Binary verification failed"
fi

INSTALLED_VERSION=$("${INSTALL_DIR}/labyrinth" -version 2>&1 | head -1)
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
# See: https://github.com/labyrinthdns/labyrinth

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

  # Set ownership
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR" 2>/dev/null || true

  # Check for systemd
  if command -v systemctl &>/dev/null; then
    cat > "$SERVICE_FILE" << 'SERVICE'
[Unit]
Description=Labyrinth Recursive DNS Resolver
Documentation=https://github.com/labyrinthdns/labyrinth
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=labyrinth
Group=labyrinth
ExecStart=/usr/local/bin/labyrinth -config /etc/labyrinth/labyrinth.yaml
ExecReload=/bin/kill -SIGUSR1 $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/labyrinth
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
SERVICE
    ok "Systemd service installed"

    systemctl daemon-reload
    systemctl enable labyrinth 2>/dev/null || true
    ok "Service enabled"

    # Start the service
    if systemctl is-active labyrinth &>/dev/null; then
      systemctl restart labyrinth
      ok "Service restarted"
    else
      systemctl start labyrinth
      ok "Service started"
    fi

    # Wait and verify
    sleep 2
    if systemctl is-active labyrinth &>/dev/null; then
      ok "Labyrinth is running"
    else
      warn "Service may have failed to start. Check: journalctl -u labyrinth"
    fi
  else
    warn "systemd not found. Start manually: labyrinth -config ${CONFIG_FILE}"
  fi
fi

echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Labyrinth installed successfully!  ${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo "  Binary:    ${INSTALL_DIR}/labyrinth"
echo "  Config:    ${CONFIG_FILE}"
echo "  Dashboard: http://127.0.0.1:9153"
echo ""
echo "  Test:      dig @localhost google.com A"
echo "  Logs:      journalctl -u labyrinth -f"
echo "  Status:    systemctl status labyrinth"
echo ""
echo "  First visit the dashboard to complete setup:"
echo "  http://127.0.0.1:9153"
echo ""
