#!/usr/bin/env bash
# =============================================================================
# Build the p2ptap Android AAR (Android Archive) via `gomobile bind`.
#
# An AAR is Android's reusable library format. Because p2ptap is written in Go,
# the AAR is produced by binding the `p2ptap/pkg/android` package: gomobile
# cross-compiles the ENTIRE Go dependency tree (libp2p, crypto, the node core,
# the tun<->tap layer, etc.) into the AAR's JNI native libraries (.so) and emits
# a Java wrapper class. All dependencies are therefore bundled inside the AAR —
# there is nothing else the consuming app needs to ship.
#
# -----------------------------------------------------------------------------
# PREREQUISITES (must be installed/exported BEFORE running this script):
#   1. Android SDK        -> set ANDROID_HOME  (e.g. $HOME/Android/Sdk)
#   2. Android NDK (r25+) -> set ANDROID_NDK_HOME (e.g. $ANDROID_HOME/ndk/<ver>)
#   3. gomobile:
#        go install golang.org/x/mobile/cmd/gomobile@latest
#        gomobile init        # downloads the NDK sysroot on first use
#
# Trigger the build:
#   ./scripts/build-aar.sh
#   P2PTAP_VERSION=v1.2.3 ./scripts/build-aar.sh
#   ANDROID_HOME=... ANDROID_NDK_HOME=... ./scripts/build-aar.sh
#
# Output: bin/p2ptap.aar  (import into an Android app as a module dependency)
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# ---- Locate Android SDK / NDK (best-effort auto-detect) ----
: "${ANDROID_HOME:=$HOME/Android/Sdk}"
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK_ROOT:-}" ]; then
  ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_NDK_LATEST_HOME:-}" ]; then
  ANDROID_NDK_HOME="$ANDROID_NDK_LATEST_HOME"
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
  ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME/ndk"/*/ 2>/dev/null | sort -V | tail -1)"
  ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk-bundle" ]; then
  ANDROID_NDK_HOME="$ANDROID_HOME/ndk-bundle"
fi
export ANDROID_HOME
export ANDROID_NDK_HOME

# ---- Version injection (matches scripts/build.sh) ----
VERSION="${P2PTAP_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="v1.0.$(date -u +%Y%m%d)"
fi
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$( (git rev-parse HEAD 2>/dev/null || echo 'unknown') | head -1)"
VER_FLAGS="-checklinkname=0 -X p2ptap/pkg/version.Version=$VERSION -X p2ptap/pkg/version.BuildTime=$BUILD_TIME -X p2ptap/pkg/version.GitCommit=$GIT_COMMIT"
export GOFLAGS="-ldflags=-checklinkname=0"

# ---- Sanity checks ----
if ! command -v gomobile >/dev/null 2>&1; then
  echo "ERROR: gomobile not found." >&2
  echo "       Install it with:  go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init" >&2
  exit 1
fi
if [ ! -d "$ANDROID_HOME" ]; then
  echo "ERROR: ANDROID_HOME not found: $ANDROID_HOME" >&2
  echo "       Set ANDROID_HOME to your Android SDK root." >&2
  exit 1
fi
if [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "ERROR: ANDROID_NDK_HOME not found: $ANDROID_NDK_HOME" >&2
  echo "       Set ANDROID_NDK_HOME to your NDK root (r25+)." >&2
  exit 1
fi

OUT_DIR="$ROOT_DIR/bin"
mkdir -p "$OUT_DIR"
AAR="$OUT_DIR/p2ptap.aar"

# Target ABIs. Default to arm64 only — it is the validated ABI for p2ptap and
# covers essentially all modern (minSdk 21+) Android devices. To build a fat AAR
# covering 32-bit devices as well, set AAR_TARGET=android (arm64 + arm + 386 +
# amd64). Note: building every ABI compiles the large libp2p dependency tree
# several times and requires substantial CPU/memory.
AAR_TARGET="${AAR_TARGET:-android/arm64}"

echo "========================================================="
echo "  Building p2ptap Android AAR"
echo "  version : $VERSION"
echo "  target  : $AAR_TARGET"
echo "  sdk     : $ANDROID_HOME"
echo "  ndk     : $ANDROID_NDK_HOME"
echo "  output  : $AAR"
echo "========================================================="

# gomobile bind:
#   -target=android[/arm64] cross-compile for Android (optionally a single ABI)
#   -androidapi 21         minSdk 21
#   -javapkg com.p2ptap    Java package for the generated wrapper class
#   -o bin/p2ptap.aar      AAR output path
#   ./pkg/android          the package to bind (only this pkg is exported)
#
# NOTE: do NOT set CGO_ENABLED=0 here. gomobile bind emits a small Cgo-based JNI
# bridge and compiles it with the Android NDK, so it needs CGO enabled. The p2ptap
# dependency tree itself is pure-Go on Android (verified with
# `GOOS=android CGO_ENABLED=0 go build ./pkg/node/...`), so only gomobile's shim
# uses CGO.
gomobile bind \
  -target="$AAR_TARGET" \
  -androidapi 21 \
  -javapkg com.p2ptap \
  -ldflags="-s -w $VER_FLAGS" \
  -o "$AAR" \
  ./pkg/android

echo "========================================================="
echo "  AAR build complete: $AAR"
ls -lh "$AAR"
echo "========================================================="
