#!/usr/bin/env bash
# ┌──────────────────────────────────────────────────────────────────────┐
# │  🛠️  p2ptap — 多平台交叉编译脚本 (Linux / macOS)                      │
# └──────────────────────────────────────────────────────────────────────┘
#
# 用法:
#   ./scripts/build.sh                      # 编译全部目标
#   ./scripts/build.sh -t current           # 只编译当前系统/架构 (最快)
#   ./scripts/build.sh -t openwrt           # 编译全部 OpenWrt 路由目标
#   ./scripts/build.sh -o linux -a arm64    # 编译指定 OS/架构
#   ./scripts/build.sh -t linux-amd64       # 按目标别名编译
#
# 说明: 本脚本只负责「编译 + 打包」。Windows 上请改用 PowerShell 版:
#       .\scripts\build.ps1   (Git Bash 下路径处理会静默出错)
#
# 环境变量:
#   P2PTAP_VERSION   覆盖版本号 (默认 v1.0.YYYYMMDD)
#   NO_COLOR         设置后禁用彩色输出 (CI 日志更干净)
#   FORCE_COLOR      设置后在非 TTY 下也强制彩色输出

set -e

# ── 终端样式 ───────────────────────────────────────────────────────────
# 仅在真实终端下着色; 管道 / 重定向 / CI / NO_COLOR 时自动降级为纯文本,
# 避免 ANSI 色码污染日志。需要强制彩色(例如带 TTY 的 CI)时设 FORCE_COLOR=1。
if [ -z "${NO_COLOR:-}" ] && { [ -n "${FORCE_COLOR:-}" ] || { [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; }; }; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  BLUE=$'\033[34m'; MAGENTA=$'\033[35m'; CYAN=$'\033[36m'
else
  BOLD=""; DIM=""; RESET=""
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""
fi

# 构建中断时给出可读提示, 并保持原退出码 (set -e 的语义不变)。
trap 'rc=$?; printf "\n%s❌ 构建中断%s (退出码 %d)\n" "$RED$BOLD" "$RESET" "$rc" >&2; exit "$rc"' ERR

# ── 展示辅助 (纯输出, 不参与构建逻辑) ──────────────────────────────────
rule() { printf '%s%s%s\n' "$DIM" "──────────────────────────────────────────────────────────────" "$RESET"; }

os_emoji() {
  case "$1" in
    linux)   printf '🐧' ;;
    windows) printf '🪟' ;;
    darwin)  printf '🍎' ;;
    *)       printf '💻' ;;
  esac
}

# human_size 打印文件的可读大小; 失败时安静返回, 绝不影响 set -e。
human_size() {
  [ -f "$1" ] || return 0
  ls -lh "$1" 2>/dev/null | awk 'NR==1 {print $5}' || true
}

# fmt_elapsed 把秒数格式化成 1m23s / 45s。
fmt_elapsed() {
  local s="$1"
  if [ "$s" -ge 60 ]; then
    printf '%dm%02ds' "$((s / 60))" "$((s % 60))"
  else
    printf '%ds' "$s"
  fi
}

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
  printf '%s🛠️  p2ptap 构建脚本%s\n\n' "$BOLD" "$RESET"
  printf '%s用法:%s %s [选项]\n\n' "$BOLD" "$RESET" "$0"
  printf '%s选项:%s\n' "$BOLD" "$RESET"
  echo "  -o <os>       指定操作系统 (linux / windows / darwin)"
  echo "  -a <arch>     指定 CPU 架构 (amd64 / arm64 / arm / 386 / mips ...)"
  echo "  -t <target>   构建目标, 可选:"
  echo "                  all       全部平台 (默认)"
  echo "                  current   仅当前系统与架构 (最快)"
  echo "                  openwrt   全部 OpenWrt 路由架构"
  echo "                  aar       Android AAR 库 (需 gomobile + Android SDK/NDK)"
  echo "                  <os>-<arch>  例如 linux-amd64"
  echo "  -d <dir>      直接输出二进制到指定目录 (不打包归档)"
  echo "  -n            只输出二进制, 不压缩成归档"
  echo "  -h            显示本帮助"
  echo
  printf '%s示例:%s\n' "$BOLD" "$RESET"
  echo "  $0 -t current            # 本机快速构建"
  echo "  $0 -t openwrt            # 全部路由目标"
  echo "  $0 -o linux -a arm64     # 指定平台"
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
    printf '%s   ⬇️  正在从 wintun.net 下载 WireGuard Wintun...%s\n' "$DIM" "$RESET"
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

TOTAL=${#SELECTED_TARGETS[@]}
IDX=0
START_SECONDS=$SECONDS

# ── 构建头 ─────────────────────────────────────────────────────────────
printf '\n'
rule
printf '  %s🛠️  p2ptap 交叉编译%s\n' "$BOLD$MAGENTA" "$RESET"
rule
printf '  %s📌 版本%s      %s\n' "$DIM" "$RESET" "$VERSION"
printf '  %s🕐 构建时间%s  %s\n' "$DIM" "$RESET" "$BUILD_TIME"
printf '  %s🔖 提交%s      %s\n' "$DIM" "$RESET" "$GIT_COMMIT"
printf '  %s🎯 目标数%s    %s\n' "$DIM" "$RESET" "$TOTAL"
if [ -n "$OUT_DIR" ]; then
  printf '  %s📂 输出目录%s  %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$OUT_DIR" "$RESET"
fi
rule

for t in "${SELECTED_TARGETS[@]}"; do
  os=$(echo $t | cut -d' ' -f1)
  arch=$(echo $t | cut -d' ' -f2)
  pkg_name="p2ptap-$os-$arch"
  ext=""
  if [ "$os" = "windows" ]; then ext=".exe"; fi

  IDX=$((IDX + 1))
  printf '\n%s▶ [%d/%d]%s %s %s%s/%s%s\n' \
    "$CYAN$BOLD" "$IDX" "$TOTAL" "$RESET" \
    "$(os_emoji "$os")" "$BOLD" "$os" "$arch" "$RESET"

  # If OUT_DIR is specified and NO_ARCHIVE is true, output directly to OUT_DIR
  if [ -n "$OUT_DIR" ] && [ "$NO_ARCHIVE" = true ]; then
    mkdir -p "$OUT_DIR"
    printf '   %s🔨 编译 p2ptap、p2ptap-boot%s\n' "$DIM" "$RESET"
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
      printf '   %s🪟 编译 p2ptap-tray (GUI)%s\n' "$DIM" "$RESET"
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
    printf '   %s✅ 完成%s\n' "$GREEN" "$RESET"
    continue
  fi

  stage_dir="$BIN_DIR/$pkg_name"
  rm -rf "$stage_dir"
  mkdir -p "$stage_dir"

  printf '   %s🔨 编译 p2ptap、p2ptap-boot%s\n' "$DIM" "$RESET"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap$ext" ./cmd/p2ptap
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w $VER_FLAGS" -o "$stage_dir/p2ptap-boot$ext" ./cmd/p2ptap-boot

  if [ "$os" = "windows" ]; then
    printf '   %s🪟 编译 p2ptap-tray (GUI) + 附带驱动文件%s\n' "$DIM" "$RESET"
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
    printf '   %s📦 打包%s %s (%s)\n' "$DIM" "$RESET" "$(basename "$zip_path")" "$(human_size "$zip_path")"
  else
    tar_path="$target_archive_dir/$pkg_name.tar.gz"
    rm -f "$tar_path"
    tar -czf "$tar_path" -C "$BIN_DIR" "$pkg_name"
    rm -rf "$stage_dir"
    printf '   %s📦 打包%s %s (%s)\n' "$DIM" "$RESET" "$(basename "$tar_path")" "$(human_size "$tar_path")"
  fi
  printf '   %s✅ 完成%s\n' "$GREEN" "$RESET"
done

ELAPSED="$(fmt_elapsed $((SECONDS - START_SECONDS)))"

# ── 构建尾 ─────────────────────────────────────────────────────────────
printf '\n'
rule
if [ -n "$OUT_DIR" ]; then
  printf '  %s✅ 构建完成%s  %s%d 个目标%s · 用时 %s%s%s\n' \
    "$GREEN$BOLD" "$RESET" "$BOLD" "$TOTAL" "$RESET" "$BOLD" "$ELAPSED" "$RESET"
  printf '  %s📂 产物目录%s %s\n' "$DIM" "$RESET" "$OUT_DIR"
  rule
  ls -lh "$OUT_DIR"/* 2>/dev/null || true
else
  printf '  %s✅ 构建完成%s  %s%d 个目标%s · 用时 %s%s%s\n' \
    "$GREEN$BOLD" "$RESET" "$BOLD" "$TOTAL" "$RESET" "$BOLD" "$ELAPSED" "$RESET"
  printf '  %s📂 产物目录%s %s\n' "$DIM" "$RESET" "$BIN_DIR"
  rule
  ls -lh "$BIN_DIR"/* 2>/dev/null || true
fi
rule
printf '\n'
