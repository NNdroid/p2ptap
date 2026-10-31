#!/usr/bin/env bash
# Materialise pkg/go-libp2p from pinned upstream + the local patch.
#
#   ./scripts/fetch-libp2p.sh            # build the tree only if it is missing
#   ./scripts/fetch-libp2p.sh --force    # always rebuild it from scratch
#
# pkg/go-libp2p is not versioned (see patches/go-libp2p/README.md). go.mod wires
# it in with:
#   replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p
# so `go build` fails until this script has run in a fresh clone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_DIR="$ROOT/patches/go-libp2p"
DEST="$ROOT/pkg/go-libp2p"
PIN_FILE="$PATCH_DIR/UPSTREAM"

FORCE=0
for arg in "$@"; do
	case "$arg" in
	--force | -f) FORCE=1 ;;
	-h | --help)
		sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

[ -f "$PIN_FILE" ] || {
	echo "missing $PIN_FILE" >&2
	exit 1
}

# Last line of UPSTREAM: "<module> <version> <commit>"
PIN_LINE="$(grep -Ev '^[[:space:]]*(#|$)' "$PIN_FILE" | tail -1)"
MODULE="$(echo "$PIN_LINE" | awk '{print $1}')"
VERSION="$(echo "$PIN_LINE" | awk '{print $2}')"
COMMIT="$(echo "$PIN_LINE" | awk '{print $3}')"
[ -n "$MODULE" ] && [ -n "$VERSION" ] && [ -n "$COMMIT" ] || {
	echo "cannot parse $PIN_FILE: '$PIN_LINE'" >&2
	exit 1
}

PATCH="$PATCH_DIR/p2ptap-${VERSION}.patch"
[ -f "$PATCH" ] || {
	echo "missing patch $PATCH (regenerate it after bumping the pin)" >&2
	exit 1
}

if [ -d "$DEST" ] && [ "$FORCE" -ne 1 ]; then
	echo "pkg/go-libp2p already present (${MODULE} ${VERSION}); use --force to rebuild"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SRC="$TMP/src"

echo "==> fetching ${MODULE} ${VERSION} (${COMMIT:0:12})"
if CLONE_ERR="$(git clone --quiet --depth 1 --branch "$VERSION" "https://${MODULE}" "$SRC" 2>&1)"; then
	GOT="$(git -C "$SRC" rev-parse HEAD)"
	if [ "$GOT" != "$COMMIT" ]; then
		echo "warning: tag ${VERSION} resolves to ${GOT}, pin says ${COMMIT}" >&2
		echo "warning: the patch was generated against ${COMMIT}; update UPSTREAM if the tag moved" >&2
	fi
	rm -rf "$SRC/.git"
else
	# No git/network: fall back to the module cache, which a previous `go mod
	# download` (or any build that once resolved the module) will have populated.
	# Say WHY the clone failed — a silent fallback turns a proxy misconfiguration
	# into an unexplained "module not found" much later.
	echo "warning: git clone of ${MODULE} ${VERSION} failed: ${CLONE_ERR}" >&2
	CACHED="$(go env GOMODCACHE 2>/dev/null)/${MODULE}@${VERSION}"
	if [ ! -d "$CACHED" ]; then
		echo "cannot fetch ${MODULE} ${VERSION}: git clone failed and $CACHED is absent" >&2
		echo "fix network/proxy access to github.com, or seed the module cache with:" >&2
		echo "  go mod download ${MODULE}@${VERSION}" >&2
		exit 1
	fi
	echo "==> using module cache $CACHED (triple-check: it must be ${VERSION})" >&2
	cp -a "$CACHED" "$SRC"
	chmod -R u+w "$SRC" 2>/dev/null || true
fi

echo "==> applying $(basename "$PATCH")"
if ! (cd "$SRC" && git apply -p1 --whitespace=nowarn "$PATCH" 2>/dev/null); then
	if command -v patch >/dev/null 2>&1; then
		(cd "$SRC" && patch -p1 --no-backup-if-mismatch -s <"$PATCH")
	else
		echo "git apply failed and no 'patch' binary is available" >&2
		exit 1
	fi
fi

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$SRC" "$DEST"

# The patch is only useful if the tree actually carries the local hooks the rest
# of the project calls; fail loudly instead of producing a build that silently
# lost socket binding or the WebRTC receive-buffer tuning.
for marker in "$DEST/p2p/transport/tcp/tcp.go" "$DEST/p2p/net/swarm/swarm_dial.go"; do
	[ -f "$marker" ] || {
		echo "materialised tree is missing ${marker#"$DEST"/}" >&2
		exit 1
	}
done
grep -q "DialPeerToAddr" "$DEST/p2p/net/swarm/swarm_dial.go" || {
	echo "patch did not apply: swarm_dial.go has no DialPeerToAddr hook" >&2
	exit 1
}

echo "==> pkg/go-libp2p ready (${MODULE} ${VERSION} + $(basename "$PATCH"))"
