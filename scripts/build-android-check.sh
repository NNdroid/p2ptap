#!/usr/bin/env bash
#
# build-android-check.sh — cross-compile p2ptap for Android, without the NDK.
#
# WHY THIS EXISTS
#
# A bare `GOOS=android go build ./cmd/p2ptap` FAILS with:
#
#     link: github.com/wlynxg/anet: invalid reference to net.zoneCache
#
# Nothing is wrong with the dependency or with the source, and the reason is
# easy to miss because the error names a transitive dependency nobody imports
# by hand. The chain is:
#
#     pkg/node/protect_net.go
#       -> github.com/pion/transport/v3/stdnet
#         -> github.com/wlynxg/anet
#
# anet is how pion enumerates Android network interfaces, and it reaches into
# Go's PRIVATE net.zoneCache via //go:linkname. Since Go 1.23 the linker
# rejects that as an invalid reference unless -checklinkname=0 is set (anet's
# own README documents exactly this failure).
#
# So the flag is the fix, and it must be carried by every command that LINKS
# an Android binary:
#
#   * scripts/build-aar.sh already carries it inside its -ldflags string. That
#     is how the shipped AAR is built, and why release.yml does not need to
#     repeat it (gomobile passes -ldflags explicitly, overriding the same
#     flag if it were only supplied through GOFLAGS).
#   * Anything you run by hand from a developer machine. This script is that
#     hand-rolled path, done once and for all.
#
# It checks the same targets the AAR links, minus gomobile's Cgo JNI shim, so
# it needs neither the Android NDK nor a C compiler. p2ptap's dependency tree
# is pure-Go on Android, so this script forces CGO_ENABLED=0 — which is also
# what makes the tree linkable at all: android's default link mode is
# external (cgo) linking, and `go list` refuses to run without CGO enabled.
# gomobile, by contrast, must keep CGO enabled for its own shim; see the
# NOTE in scripts/build-aar.sh.
#
# USAGE
#   bash scripts/build-android-check.sh          # android/arm64
#   bash scripts/build-android-check.sh amd64    # another architecture
#
# android/arm64 is the default because it is the architecture Go cross-compiles
# for Android out of the box. The AAR also ships armv7, x86 and x86_64, but
# plain `go build` no longer supports those targets (android/armv7 is not an
# accepted GOOS/GOARCH pair any more, and android/amd64 demands external cgo
# linking); gomobile + the NDK covers them in scripts/build-aar.sh. The link
# configuration being guarded here is architecture-independent, so arm64 is a
# faithful check for all four.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Mandatory. See the header above for why omitting it produces a confusing
# linker error rather than a compile error.
LDFLAGS="-checklinkname=0"

# cmd/p2ptap-tray is a Windows-only GUI binary (//go:build windows); `go list
# ./cmd/...` still names it under GOOS=android, so filter it out explicitly.
# `go list` exits non-zero when any pattern member is excluded by build
# constraints, hence the `|| true` — under `set -e` that would abort the
# script before anything is printed.
PACKAGES=()
while IFS= read -r pkg; do
    [[ "$pkg" == *cmd/p2ptap-tray* ]] && continue
    PACKAGES+=("$pkg")
done < <(CGO_ENABLED=0 GOOS=android GOARCH=arm64 go list ./cmd/... ./pkg/... 2>/dev/null || true)

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
    echo "ERROR: no packages found — is this the repository root?" >&2
    exit 1
fi

ARCHS=(arm64)
if [[ $# -gt 0 ]]; then
    ARCHS=("$@")
fi

# Builds land in a scratch dir, so the working tree is never polluted. `-o`
# takes a path, so a library package and a main package both work with the
# same command.
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

status=0
for arch in "${ARCHS[@]}"; do
    echo "==> GOOS=android GOARCH=$arch  (${#PACKAGES[@]} packages)"
    for pkg in "${PACKAGES[@]}"; do
        if ! CGO_ENABLED=0 GOOS=android GOARCH="$arch" \
            go build -ldflags="$LDFLAGS" -o "$OUT/${pkg##*/}" "$pkg"; then
            echo "    FAILED: $pkg" >&2
            status=1
        fi
    done
done


if [[ "$status" -ne 0 ]]; then
    echo
    echo "Android cross-compile FAILED." >&2
    echo "If the error is 'invalid reference to net.zoneCache', the" >&2
    echo "-checklinkname=0 ldflag has been lost. It must stay inside an" >&2
    echo "-ldflags string — see the header of this script and" >&2
    echo "scripts/build-aar.sh." >&2
    exit 1
fi

echo
echo "Android cross-compile OK: ${ARCHS[*]} (${#PACKAGES[@]} packages each)."
