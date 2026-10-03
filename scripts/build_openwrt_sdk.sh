#!/usr/bin/env bash
# OpenWrt 25.12 APK SDK entry point; version defaults to 25.12.5.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
export P2PTAP_PKG_VERSION="${VERSION:-${P2PTAP_PKG_VERSION:-}}"
exec bash "$ROOT_DIR/scripts/build_openwrt_apk.sh" "$@"
