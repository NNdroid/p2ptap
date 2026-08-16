#!/bin/bash
# P2P TAP VPN Client (p2ptap) Systemd Service Installer & Manager for Linux
# Supports: install | uninstall | update | status | start | stop | restart

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root (sudo)."
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "[!] Error: This installation script only supports Linux OS."
    exit 1
fi

BIN_PATH="/usr/local/bin/p2ptap"
WORK_DIR="/usr/local/etc/p2ptap"
CONFIG_FILE="$WORK_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/p2ptap.service"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# Version injection
VERSION="${P2PTAP_VERSION:-v1.0.$(date -u +%Y%m%d)}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$( (git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo 'unknown') | head -1)"
VER_FLAGS="-X p2ptap/pkg/version.Version=$VERSION -X p2ptap/pkg/version.BuildTime=$BUILD_TIME -X p2ptap/pkg/version.GitCommit=$GIT_COMMIT"

install_service() {
    echo "[*] Installing p2ptap client service..."

    mkdir -p "$WORK_DIR"
    mkdir -p "/usr/local/bin"

    # Find binary to install (prefer existing binary, fallback to compile if go toolchain exists)
    if [ -f "$SCRIPT_DIR/p2ptap" ]; then
        cp "$SCRIPT_DIR/p2ptap" "$BIN_PATH"
    elif [ -f "$ROOT_DIR/bin/p2ptap" ]; then
        cp "$ROOT_DIR/bin/p2ptap" "$BIN_PATH"
    elif [ -f "./p2ptap" ]; then
        cp "./p2ptap" "$BIN_PATH"
    elif [ -f "$ROOT_DIR/cmd/p2ptap/main.go" ] && command -v go >/dev/null 2>&1; then
        echo "[*] Compiling p2ptap binary from source..."
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w $VER_FLAGS" -o "$BIN_PATH" ./cmd/p2ptap)
    else
        echo "[!] Error: p2ptap binary or Go build environment not found!"
        exit 1
    fi

    chmod +x "$BIN_PATH"

    # Generate default config if missing
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "[*] Generating default config.json in $CONFIG_FILE..."
        "$BIN_PATH" genconf -o "$CONFIG_FILE"
    fi

    # Create Systemd Service Unit
    echo "[*] Creating systemd service file $SERVICE_FILE..."
    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=P2P TAP VPN Node Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
ExecStart=$BIN_PATH run -c $CONFIG_FILE
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable p2ptap.service
    systemctl restart p2ptap.service

    echo "========================================================="
    echo "  [+] p2ptap service successfully installed & started!  "
    echo "========================================================="
    echo "  Service Status : systemctl status p2ptap"
    echo "  Config File    : $CONFIG_FILE"
    echo "  Binary Path    : $BIN_PATH"
    echo "  Work Directory : $WORK_DIR"
    echo "========================================================="
}

uninstall_service() {
    echo "[*] Uninstalling p2ptap service..."
    systemctl stop p2ptap.service 2>/dev/null || true
    systemctl disable p2ptap.service 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -f "$BIN_PATH"
    
    read -p "Do you want to remove configuration directory ($WORK_DIR)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$WORK_DIR"
        echo "[+] Configuration directory removed."
    fi

    echo "[+] p2ptap service successfully uninstalled."
}

update_service() {
    echo "[*] Updating p2ptap binary..."
    if [ -f "$SCRIPT_DIR/p2ptap" ]; then
        cp "$SCRIPT_DIR/p2ptap" "$BIN_PATH"
    elif [ -f "$ROOT_DIR/bin/p2ptap" ]; then
        cp "$ROOT_DIR/bin/p2ptap" "$BIN_PATH"
    elif [ -f "./p2ptap" ]; then
        cp "./p2ptap" "$BIN_PATH"
    elif [ -f "$ROOT_DIR/cmd/p2ptap/main.go" ] && command -v go >/dev/null 2>&1; then
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w $VER_FLAGS" -o "$BIN_PATH" ./cmd/p2ptap)
    else
        echo "[!] Error: Updated p2ptap binary or Go build environment not found!"
        exit 1
    fi
    chmod +x "$BIN_PATH"
    systemctl restart p2ptap.service
    echo "[+] p2ptap successfully updated & restarted!"
}

status_service() {
    systemctl status p2ptap.service
}

case "$1" in
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    update)
        update_service
        ;;
    status)
        status_service
        ;;
    start)
        systemctl start p2ptap.service
        ;;
    stop)
        systemctl stop p2ptap.service
        ;;
    restart)
        systemctl restart p2ptap.service
        ;;
    *)
        echo "Usage: $0 {install|uninstall|update|status|start|stop|restart}"
        exit 1
        ;;
esac
