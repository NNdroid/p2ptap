#!/usr/bin/env bash
# Apply one release version to the daemon, LuCI app and translations.
set -euo pipefail
RAW_VERSION="${1:?Usage: set_openwrt_version.sh VERSION PACKAGE_ROOT...}"
shift
VERSION_NUM="${RAW_VERSION#v}"
# Releases use numeric versions (including date-based v1.0.YYYYMMDD tags).
# Reject shell/make syntax and unsupported prerelease tags instead of silently
# emitting an invalid package or changing upgrade ordering.
if [[ ! "$VERSION_NUM" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "Unsupported OpenWrt release version: $RAW_VERSION (expected v1.0.20261001 or 1.2.3)" >&2
    exit 1
fi
SOURCE_REF="${P2PTAP_SOURCE_VERSION:-HEAD}"
if [ "$(git rev-parse --is-shallow-repository)" != false ]; then
    echo 'Full Git history is required for PKG_RELEASE; fetch with depth 0' >&2
    exit 1
fi
RELEASE_COUNT=$(git rev-list --count "$SOURCE_REF")
[[ "$RELEASE_COUNT" =~ ^[1-9][0-9]*$ ]] || exit 1
[ "$#" -gt 0 ] || { echo 'No package roots specified' >&2; exit 1; }
for ROOT in "$@"; do
    for PACKAGE in p2ptap luci-app-p2ptap; do
        [ -f "$ROOT/$PACKAGE/Makefile" ] || { echo "Missing $ROOT/$PACKAGE/Makefile" >&2; exit 1; }
    done
done
for ROOT in "$@"; do
    for PACKAGE in p2ptap luci-app-p2ptap; do
        sed -i -e "s/^PKG_VERSION:=.*/PKG_VERSION:=${VERSION_NUM}/" -e "s/^PKG_RELEASE:=.*/PKG_RELEASE:=${RELEASE_COUNT}/" "$ROOT/$PACKAGE/Makefile"
    done
done
printf '%s\n' "$VERSION_NUM"
