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
OUT_DIR=""
NO_ARCHIVE=false

while getopts "o:a:t:d:nh" opt; do
  case $opt in
    o) OS_FILTER="$OPTARG" ;;
    a) ARCH_FILTER="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    d) OUT_DIR="$OPTARG" ;;
    n) NO_ARCHIVE=true ;;
    h)
  echo "Usage: $0 [-o os] [-a arch] [-t target] [-d out_dir] [-n]"
  echo "Targets: all, current, openwrt, aar, <os>-<arch>"
  echo "  -t current    Build only for the current operating system and CPU architecture"
  echo "  -t openwrt    Build all OpenWrt router architectures"
  echo "  -t aar        Build the Android AAR library (requires gomobile + Android SDK/NDK)"
  echo "  -d <dir>      Output compiled binaries directly to the specified directory"
  echo "  -n            Direct binary output without packaging into archives"
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

# Determine targets to build
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
elif [ "$TARGET" = "aar" ]; then
  # Android AAR library build (delegates to the gomobile-based script).
  exec "$SCRIPT_DIR/build-aar.sh"
elif [ "$TARGET" != "all" ] && [ -n "$TARGET" ]; then
  OS_PART="${TARGET%%-*}"
  ARCH_PART="${TARGET#*-}"
  SELECTED_TARGETS+=("$OS_PART $ARCH_PART")
else
  SELECTED_TARGETS=("${ALL_TARGETS[@]}")
fi

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

echo "========================================================="
echo "       Building P2P TAP VPN Releases (${#SELECTED_TARGETS[@]} target(s)) "
echo "========================================================="

for t in "${SELECTED_TARGETS[@]}"; do
  os=$(echo $t | cut -d' ' -f1)
  arch=$(echo $t | cut -d' ' -f2)
  pkg_name="p2ptap-$os-$arch"
  ext=""
  if [ "$os" = "windows" ]; then ext=".exe"; fi

  # If OUT_DIR is specified and NO_ARCHIVE is true, output directly to OUT_DIR
  if [ -n "$OUT_DIR" ] && [ "$NO_ARCHIVE" = true ]; then
    mkdir -p "$OUT_DIR"
    echo "[+] Compiling directly for $os/$arch -> $OUT_DIR..."
    out_prefix="p2ptap-$os-$arch"
    if [ "$os" = "windows" ] && [ "$arch" = "amd64" ]; then
      out_prefix="p2ptap"
    fi
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$OUT_DIR/$out_prefix$ext" ./cmd/p2ptap
    
    boot_prefix="p2ptap-boot-$os-$arch"
    if [ "$os" = "windows" ] && [ "$arch" = "amd64" ]; then
      boot_prefix="p2ptap-boot"
    fi
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$OUT_DIR/$boot_prefix$ext" ./cmd/p2ptap-boot

    if [ "$os" = "windows" ]; then
      tray_prefix="p2ptap-tray-$os-$arch.exe"
      if [ "$arch" = "amd64" ]; then
        tray_prefix="p2ptap-tray.exe"
      fi
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -H windowsgui $VER_FLAGS" -o "$OUT_DIR/$tray_prefix" ./cmd/p2ptap-tray
      [ -f "$SCRIPT_DIR/start.bat" ] && cp "$SCRIPT_DIR/start.bat" "$OUT_DIR/"
      [ -f "$SCRIPT_DIR/launcher.vbs" ] && cp "$SCRIPT_DIR/launcher.vbs" "$OUT_DIR/"
      ensure_wintun_dll "$arch"
      if [ -f "$SCRIPT_DIR/wintun/$arch/wintun.dll" ]; then
        cp "$SCRIPT_DIR/wintun/$arch/wintun.dll" "$OUT_DIR/"
      fi
      if [ -f "$SCRIPT_DIR/tap-windows-9.21.2.exe" ]; then
        cp "$SCRIPT_DIR/tap-windows-9.21.2.exe" "$OUT_DIR/"
      fi
    fi
    continue
  fi

  stage_dir="$BIN_DIR/$pkg_name"
  rm -rf "$stage_dir"
  mkdir -p "$stage_dir"

  echo "[+] Compiling for $os/$arch..."
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap$ext" ./cmd/p2ptap
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap-boot$ext" ./cmd/p2ptap-boot

  if [ "$os" = "windows" ]; then
    echo "[+] Compiling p2ptap-tray.exe GUI for $os/$arch..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -H windowsgui $VER_FLAGS" -o "$stage_dir/p2ptap-tray.exe" ./cmd/p2ptap-tray
    [ -f "$SCRIPT_DIR/start.bat" ] && cp "$SCRIPT_DIR/start.bat" "$stage_dir/"
    [ -f "$SCRIPT_DIR/launcher.vbs" ] && cp "$SCRIPT_DIR/launcher.vbs" "$stage_dir/"
    ensure_wintun_dll "$arch"
    if [ -f "$SCRIPT_DIR/wintun/$arch/wintun.dll" ]; then
      cp "$SCRIPT_DIR/wintun/$arch/wintun.dll" "$stage_dir/"
    fi
    if [ -f "$SCRIPT_DIR/tap-windows-9.21.2.exe" ]; then
      cp "$SCRIPT_DIR/tap-windows-9.21.2.exe" "$stage_dir/"
    fi
  else
    [ -f "$SCRIPT_DIR/start.sh" ] && cp "$SCRIPT_DIR/start.sh" "$stage_dir/"
  fi

  target_archive_dir="$BIN_DIR"
  if [ -n "$OUT_DIR" ]; then
    target_archive_dir="$OUT_DIR"
    mkdir -p "$target_archive_dir"
  fi

  # Compress release bundle
  if [ "$os" = "windows" ] && command -v zip >/dev/null 2>&1; then
    zip_path="$target_archive_dir/$pkg_name.zip"
    rm -f "$zip_path"
    (cd "$BIN_DIR" && zip -rq "$zip_path" "$pkg_name")
    rm -rf "$stage_dir"
  else
    tar_path="$target_archive_dir/$pkg_name.tar.gz"
    rm -f "$tar_path"
    tar -czf "$tar_path" -C "$BIN_DIR" "$pkg_name"
    rm -rf "$stage_dir"
  fi
done

echo "========================================================="
if [ -n "$OUT_DIR" ]; then
  echo "  Build Complete! Generated release artifacts in $OUT_DIR :"
  ls -lh "$OUT_DIR"/* 2>/dev/null || true
else
  echo "  Build Complete! Generated release artifacts in bin/ :"
  ls -lh "$BIN_DIR"/* 2>/dev/null || true
fi
echo "========================================================="
