#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PAYLOAD="${1:-}"
VERSION="${P2PTAP_PKG_VERSION:-v1.0.$(date -u +%Y%m%d)}"
SOURCE="$(git rev-parse HEAD)"
REMOTE="${OPENWRT_FEED_REMOTE:-$(git remote get-url origin)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  # Reset checkout's persisted header before adding the publisher credential.
  export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
  export GIT_CONFIG_VALUE_0= GIT_CONFIG_KEY_1=http.https://github.com/.extraheader
  GIT_CONFIG_VALUE_1="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 -w0)"
  export GIT_CONFIG_VALUE_1
fi
# Distinguish a missing branch from a network/authentication failure.
REF=$(git ls-remote --heads "$REMOTE" openwrt-feed)
git init -q "$WORK/tree"
git -C "$WORK/tree" remote add origin "$REMOTE"
if [[ -n "$REF" ]]; then
  git -C "$WORK/tree" fetch -q --depth=1 origin openwrt-feed
  git -C "$WORK/tree" checkout -q -B openwrt-feed FETCH_HEAD
else
  git -C "$WORK/tree" checkout -q --orphan openwrt-feed
fi
# A slow earlier build must not overwrite a newer source revision.
CURRENT_RELEASE=$(git rev-list --count HEAD)
if [[ -f "$WORK/tree/source-manifest.txt" ]]; then
  PREVIOUS_RELEASE=$(sed -n 's/^package_release=//p' "$WORK/tree/source-manifest.txt")
  if [[ "$PREVIOUS_RELEASE" =~ ^[0-9]+$ ]] && (( PREVIOUS_RELEASE > CURRENT_RELEASE )); then
    echo 'A newer source revision has already been published; leaving it intact'
    exit 0
  fi
fi
mkdir -p "$WORK/tree/package"
for pkg in p2ptap luci-app-p2ptap; do
  rm -rf "$WORK/tree/package/$pkg"
  cp -a "openwrt/package/$pkg" "$WORK/tree/package/"
done
bash scripts/set_openwrt_version.sh "$VERSION" "$WORK/tree/package" >/dev/null
sed -i -e "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$SOURCE/" \
  -e 's/^PKG_MIRROR_HASH:=.*/PKG_MIRROR_HASH:=skip/' "$WORK/tree/package/p2ptap/Makefile"
if [[ -n "$PAYLOAD" ]]; then
  expected="$WORK/expected.pem"
  bash scripts/prepare_openwrt_feed_keys.sh public "$expected"
  openssl pkey -pubin -in "$expected" -outform DER -out "$WORK/expected.der"
  mapfile -t keys < <(find "$PAYLOAD/releases/$OPENWRT_VERSION" -name p2ptap-feed.pem -type f)
  [[ "${#keys[@]}" == 7 ]] || { echo 'Expected all seven target feeds' >&2; exit 1; }
  for key in "${keys[@]}"; do
    openssl pkey -pubin -in "$key" -outform DER -out "$WORK/candidate.der"
    cmp -s "$WORK/expected.der" "$WORK/candidate.der" || { echo 'Unexpected feed public key' >&2; exit 1; }
    (cd "$(dirname "$key")"; sha256sum -c SHA256SUMS)
  done
  mkdir -p "$WORK/tree/releases"
  rm -rf "$WORK/tree/releases/$OPENWRT_VERSION"
  cp -a "$PAYLOAD/releases/$OPENWRT_VERSION" "$WORK/tree/releases/"
  cp "$expected" "$WORK/tree/p2ptap-feed.pem"
fi
cat > "$WORK/tree/README.md" <<'EOF'
# p2ptap OpenWrt feed

Source feed (SDK / Buildroot feeds.conf.default):

    src-git p2ptap https://github.com/NNdroid/p2ptap.git;openwrt-feed

Then run `./scripts/feeds update p2ptap` and `./scripts/feeds install -a -p p2ptap`.

Signed APK repositories are published after successful OpenWrt Signed APK Feed runs.
Repository layout: `releases/<OpenWrt release>/<target>/<subtarget>/packages.adb`.

On an APK-based router, after the repository for your release/target has been published:

```sh
. /etc/openwrt_release
BASE=https://raw.githubusercontent.com/NNdroid/p2ptap/openwrt-feed
mkdir -p /etc/apk/keys /etc/apk/repositories.d
wget -O /etc/apk/keys/p2ptap-feed.pem "$BASE/p2ptap-feed.pem"
printf '%s\n' "$BASE/releases/$DISTRIB_RELEASE/$DISTRIB_TARGET/packages.adb" > /etc/apk/repositories.d/p2ptap.list
apk update
apk add p2ptap luci-app-p2ptap luci-i18n-p2ptap-zh-cn
```
EOF
printf 'source_commit=%s\npackage_version=%s\npackage_release=%s\n' "$SOURCE" "$VERSION" "$(git rev-list --count HEAD)" > "$WORK/tree/source-manifest.txt"
touch "$WORK/tree/.nojekyll"
git -C "$WORK/tree" config user.name 'github-actions[bot]'
git -C "$WORK/tree" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git -C "$WORK/tree" add -A
if git -C "$WORK/tree" diff --cached --quiet; then echo 'Feed is unchanged'; exit 0; fi
git -C "$WORK/tree" commit -q -m "feed: publish p2ptap $VERSION from ${SOURCE:0:12}"
git -C "$WORK/tree" push origin HEAD:openwrt-feed
