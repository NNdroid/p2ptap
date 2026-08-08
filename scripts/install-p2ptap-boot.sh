#!/bin/bash
# p2ptap Standalone Bootstrap Server (p2ptap-boot) Systemd Service Installer & Manager for Linux
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

BIN_PATH="/usr/local/bin/p2ptap-boot"
WORK_DIR="/usr/local/etc/p2ptap"
KEY_FILE="$WORK_DIR/boot.key"
SERVICE_FILE="/etc/systemd/system/p2ptap-boot.service"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
PORT="${2:-4001}"

# Version injection
VERSION="${P2PTAP_VERSION:-v1.0.$(date -u +%Y%m%d)}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$( (git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo 'unknown') | head -1)"
VER_FLAGS="-X p2ptap/pkg/version.Version=$VERSION -X p2ptap/pkg/version.BuildTime=$BUILD_TIME -X p2ptap/pkg/version.GitCommit=$GIT_COMMIT"

install_service() {
    echo "[*] Installing p2ptap-boot standalone bootstrap service..."

    mkdir -p "$WORK_DIR"
    mkdir -p "/usr/local/bin"

    # Find binary to install
    if [ -f "$ROOT_DIR/cmd/p2ptap-boot/main.go" ]; then
        echo "[*] Compiling p2ptap-boot binary..."
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w $VER_FLAGS" -o "$BIN_PATH" ./cmd/p2ptap-boot)
    elif [ -f "$SCRIPT_DIR/p2ptap-boot" ]; then
        cp "$SCRIPT_DIR/p2ptap-boot" "$BIN_PATH"
    elif [ -f "./p2ptap-boot" ]; then
        cp "./p2ptap-boot" "$BIN_PATH"
    else
        echo "[!] Error: p2ptap-boot binary or source code not found!"
        exit 1
    fi

    chmod +x "$BIN_PATH"

    # Create Systemd Service Unit
    echo "[*] Creating systemd service file $SERVICE_FILE..."
    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=p2ptap Standalone Bootstrap Server Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
ExecStart=$BIN_PATH -port $PORT -key $KEY_FILE
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable p2ptap-boot.service
    systemctl restart p2ptap-boot.service

    echo "========================================================="
    echo "  [+] p2ptap-boot service successfully installed!      "
    echo "========================================================="
    echo "  Service Status : systemctl status p2ptap-boot"
    echo "  Binary Path    : $BIN_PATH"
    echo "  Key File       : $KEY_FILE"
    echo "  Work Directory : $WORK_DIR"
    echo "========================================================="
    echo "  Run '$BIN_PATH -port $PORT -key $KEY_FILE' once to print"
    echo "  the bootstrap multiaddrs for client config.json files."
    echo "========================================================="
}

uninstall_service() {
    echo "[*] Uninstalling p2ptap-boot service..."
    systemctl stop p2ptap-boot.service 2>/dev/null || true
    systemctl disable p2ptap-boot.service 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -f "$BIN_PATH"

    read -p "Do you want to remove identity key file ($KEY_FILE)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$KEY_FILE"
        echo "[+] Identity key removed."
    fi

    echo "[+] p2ptap-boot service successfully uninstalled."
}

update_service() {
    echo "[*] Updating p2ptap-boot binary..."
    if [ -f "$ROOT_DIR/cmd/p2ptap-boot/main.go" ]; then
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w $VER_FLAGS" -o "$BIN_PATH" ./cmd/p2ptap-boot)
    elif [ -f "$SCRIPT_DIR/p2ptap-boot" ]; then
        cp "$SCRIPT_DIR/p2ptap-boot" "$BIN_PATH"
    else
        echo "[!] Error: Updated p2ptap-boot binary not found!"
        exit 1
    fi
    chmod +x "$BIN_PATH"
    systemctl restart p2ptap-boot.service
    echo "[+] p2ptap-boot successfully updated & restarted!"
}

status_service() {
    systemctl status p2ptap-boot.service
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
        systemctl start p2ptap-boot.service
        ;;
    stop)
        systemctl stop p2ptap-boot.service
        ;;
    restart)
        systemctl restart p2ptap-boot.service
        ;;
    *)
        echo "Usage: $0 {install|uninstall|update|status|start|stop|restart} [port]"
        exit 1
        ;;
esac
