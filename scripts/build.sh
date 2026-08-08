#!/usr/bin/env bash
# P2P TAP VPN Multi-Architecture Cross-Compilation Script (Bash for Linux/macOS)
# Usage:
#   ./scripts/build.sh                      # Build all targets
#   ./scripts/build.sh -t current           # Build for current host OS/Arch (fast)
#   ./scripts/build.sh -t openwrt           # Build all OpenWrt targets
#   ./scripts/build.sh -o linux -a arm64    # Build specific OS/Arch
#   ./scripts/build.sh -t linux-amd64       # Build specific target alias

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

# ---- Version injection (matching build.ps1 logic) ----
VERSION="${P2PTAP_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="v1.0.$(date -u +%Y%m%d)"
fi
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$( (git rev-parse HEAD 2>/dev/null || echo 'unknown') | head -1)"
VER_FLAGS="-X p2ptap/pkg/version.Version=$VERSION -X p2ptap/pkg/version.BuildTime=$BUILD_TIME -X p2ptap/pkg/version.GitCommit=$GIT_COMMIT"

OS_FILTER=""
ARCH_FILTER=""
TARGET="all"

while getopts "o:a:t:h" opt; do
  case $opt in
    o) OS_FILTER="$OPTARG" ;;
    a) ARCH_FILTER="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    h)
      echo "Usage: $0 [-o os] [-a arch] [-t target]"
      echo "Targets: all, current, openwrt, <os>-<arch>"
      exit 0
      ;;
    *) exit 1 ;;
  esac
done

ALL_TARGETS=(
  "linux amd64"
  "linux 386"
  "linux arm64"
  "linux arm"
  "linux mips64le"
  "linux mipsle"
  "linux mips"
  "linux riscv64"
  "linux loong64"
  "windows amd64"
  "windows 386"
  "windows arm64"
  "darwin amd64"
  "darwin arm64"
)

SELECTED_TARGETS=()

if [ -n "$OS_FILTER" ] && [ -n "$ARCH_FILTER" ]; then
  SELECTED_TARGETS+=("$OS_FILTER $ARCH_FILTER")
elif [ "$TARGET" = "current" ]; then
  SYS_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$SYS_OS" in
    darwin*) SYS_OS="darwin" ;;
    linux*) SYS_OS="linux" ;;
    msys*|cygwin*|mingw*) SYS_OS="windows" ;;
  esac
  SYS_ARCH="$(uname -m)"
  case "$SYS_ARCH" in
    x86_64|amd64) SYS_ARCH="amd64" ;;
    aarch64|arm64) SYS_ARCH="arm64" ;;
    i386|i686) SYS_ARCH="386" ;;
    arm*) SYS_ARCH="arm" ;;
  esac
  SELECTED_TARGETS+=("$SYS_OS $SYS_ARCH")
elif [ "$TARGET" = "openwrt" ]; then
  for t in "${ALL_TARGETS[@]}"; do
    os=$(echo $t | cut -d' ' -f1)
    arch=$(echo $t | cut -d' ' -f2)
    if [ "$os" = "linux" ] && [[ "$arch" =~ ^(mipsle|mips|arm|arm64|amd64|386|mips64le|riscv64)$ ]]; then
      SELECTED_TARGETS+=("$t")
    fi
  done
elif [ "$TARGET" != "all" ] && [ -n "$TARGET" ]; then
  OS_PART="${TARGET%%-*}"
  ARCH_PART="${TARGET#*-}"
  SELECTED_TARGETS+=("$OS_PART $ARCH_PART")
else
  SELECTED_TARGETS=("${ALL_TARGETS[@]}")
fi

echo "========================================================="
echo "       Building P2P TAP VPN Releases (${#SELECTED_TARGETS[@]} target(s)) "
echo "========================================================="

for t in "${SELECTED_TARGETS[@]}"; do
  os=$(echo $t | cut -d' ' -f1)
  arch=$(echo $t | cut -d' ' -f2)
  pkg_name="p2ptap-$os-$arch"
  stage_dir="$BIN_DIR/$pkg_name"
  
  rm -rf "$stage_dir"
  mkdir -p "$stage_dir"

  ext=""
  if [ "$os" = "windows" ]; then ext=".exe"; fi

  echo "[+] Compiling for $os/$arch..."
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap$ext" ./cmd/p2ptap
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap-boot$ext" ./cmd/p2ptap-boot

ensure_wintun_dll() {
  local target_arch="$1"
  local wintun_dll="$SCRIPT_DIR/wintun/$target_arch/wintun.dll"
  if [ ! -f "$wintun_dll" ]; then
    echo "[+] Auto-downloading latest WireGuard Wintun release from wintun.net..."
    local tmp_dir="$(mktemp -d)"
    curl -sSL "https://www.wintun.net/builds/wintun-0.14.1.zip" -o "$tmp_dir/wintun.zip"
    unzip -q "$tmp_dir/wintun.zip" -d "$tmp_dir/extracted"
    mkdir -p "$SCRIPT_DIR/wintun/amd64" "$SCRIPT_DIR/wintun/386" "$SCRIPT_DIR/wintun/arm64"
    cp "$tmp_dir/extracted/wintun/bin/amd64/wintun.dll" "$SCRIPT_DIR/wintun/amd64/"
    cp "$tmp_dir/extracted/wintun/bin/x86/wintun.dll" "$SCRIPT_DIR/wintun/386/"
    cp "$tmp_dir/extracted/wintun/bin/arm64/wintun.dll" "$SCRIPT_DIR/wintun/arm64/"
    rm -rf "$tmp_dir"
  fi
}

  if [ "$os" = "windows" ]; then
    echo "[+] Compiling p2ptap-tray.exe GUI for $os/$arch..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -H windowsgui $VER_FLAGS" -o "$stage_dir/p2ptap-tray.exe" ./cmd/p2ptap-tray
    cp "$SCRIPT_DIR/start.bat" "$stage_dir/"
    ensure_wintun_dll "$arch"
    if [ -f "$SCRIPT_DIR/wintun/$arch/wintun.dll" ]; then
      cp "$SCRIPT_DIR/wintun/$arch/wintun.dll" "$stage_dir/"
    fi
  else
    cp "$SCRIPT_DIR/start.sh" "$stage_dir/"
  fi

  zip_path="$BIN_DIR/$pkg_name.zip"
  rm -f "$zip_path"
  (cd "$BIN_DIR" && zip -r "$pkg_name.zip" "$pkg_name")
done

echo "========================================================="
echo "  Build Complete! Generated release artifacts in bin/ :"
ls -lh "$BIN_DIR"/* 2>/dev/null || true
echo "========================================================="
