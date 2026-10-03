#!/usr/bin/env bash
# Apply one release version to the daemon, LuCI app and translations.
set -euo pipefail
RAW_VERSION="${1:?Usage: set_openwrt_version.sh VERSION PACKAGE_ROOT...}"
shift
RELEASE_VERSION="$(bash "$(dirname "${BASH_SOURCE[0]}")/get_version.sh" "$RAW_VERSION")"
# APK versions must remain ordered numeric versions; keep HASH7 in the daemon.
VERSION_NUM="${RELEASE_VERSION#v}"
VERSION_NUM="${VERSION_NUM%-*}"
SOURCE_REF="${P2PTAP_SOURCE_VERSION:-HEAD}"
if [ "$(git rev-parse --is-shallow-repository)" != false ]; then
    echo 'Full Git history is required for PKG_RELEASE; fetch with depth 0' >&2
    exit 1
fi
COMMIT=$(git rev-parse --verify "${SOURCE_REF}^{commit}")
RELEASE_COUNT=$(git rev-list --count "$COMMIT")
[[ "$RELEASE_COUNT" =~ ^[1-9][0-9]*$ ]] || exit 1
[ "$#" -gt 0 ] || { echo 'No package roots specified' >&2; exit 1; }
for ROOT in "$@"; do
    for PACKAGE in p2ptap luci-app-p2ptap; do
        [ -f "$ROOT/$PACKAGE/Makefile" ] || { echo "Missing $ROOT/$PACKAGE/Makefile" >&2; exit 1; }
    done
done
# BSD sed requires a separate empty backup suffix; GNU sed does not.
SED_INPLACE=(-i)
if [[ "$(uname -s)" == Darwin ]]; then
    SED_INPLACE=(-i '')
fi
for ROOT in "$@"; do
    for PACKAGE in p2ptap luci-app-p2ptap; do
        sed "${SED_INPLACE[@]}" -e "s/^PKG_VERSION:=.*/PKG_VERSION:=${VERSION_NUM}/" -e "s/^PKG_RELEASE:=.*/PKG_RELEASE:=${RELEASE_COUNT}/" "$ROOT/$PACKAGE/Makefile"
    done
    sed "${SED_INPLACE[@]}" -e "s/^P2PTAP_VERSION:=.*/P2PTAP_VERSION:=${RELEASE_VERSION}/" \
        -e "s/^P2PTAP_GIT_COMMIT:=.*/P2PTAP_GIT_COMMIT:=${COMMIT}/" "$ROOT/p2ptap/Makefile"
done
printf '%s\n' "$VERSION_NUM"
