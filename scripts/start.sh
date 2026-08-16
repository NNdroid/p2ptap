#!/bin/bash
# P2P TAP VPN Quick Startup Script for Linux / macOS

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Notice: TAP virtual interface creation usually requires root/sudo privileges."
  echo "    Running without root will fallback to in-memory MemTAP pipeline mode."
fi

CONFIG_FILE="config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[*] config.json not found, generating default config..."
    ./p2ptap genconf -o "$CONFIG_FILE"
fi

echo "[*] Starting p2ptap VPN node..."
./p2ptap run -c "$CONFIG_FILE"
