#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86}"
OPENWRT_SUBTARGET="${OPENWRT_SUBTARGET:-64}"
SOURCE_VERSION="${P2PTAP_SOURCE_VERSION:-$(git rev-parse HEAD)}"
RELEASE_VERSION="${P2PTAP_PKG_VERSION:-v1.0.$(date -u +%Y%m%d)}"
WORK_DIR="${OPENWRT_WORK_DIR:-${RUNNER_TEMP:-/tmp}/p2ptap-openwrt-sdk/$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"
SDK_DIR="$WORK_DIR/sdk"
DOWNLOAD_DIR="$WORK_DIR/download"
OUTPUT_DIR="${OPENWRT_OUTPUT_DIR:-$ROOT_DIR/bin/openwrt}"
JOBS="${JOBS:-2}"
for value in "$OPENWRT_VERSION" "$OPENWRT_TARGET" "$OPENWRT_SUBTARGET"; do
  [[ "$value" =~ ^[a-zA-Z0-9._-]+$ && "$value" != *..* ]] || exit 2
done
[[ "$SOURCE_VERSION" =~ ^[0-9a-f]{40}$ ]] || { echo 'Source must be an immutable Git commit' >&2; exit 2; }
[[ "$OPENWRT_VERSION" == 25.12.* ]] || exit 2
mkdir -p "$DOWNLOAD_DIR" "$OUTPUT_DIR"
BASE="https://downloads.openwrt.org/releases/$OPENWRT_VERSION/targets/$OPENWRT_TARGET/$OPENWRT_SUBTARGET"
INDEX=$(curl --retry 4 --fail -sSL "$BASE/")
SDK_NAME=$(printf '%s' "$INDEX" | grep -oE 'openwrt-sdk-[^"<> ]+\.Linux-x86_64\.tar\.zst' | sort -u | head -1)
[[ -n "$SDK_NAME" ]] || { echo 'SDK archive not found' >&2; exit 1; }
curl --retry 4 --fail -sSL "$BASE/$SDK_NAME" -o "$DOWNLOAD_DIR/$SDK_NAME"
curl --retry 4 --fail -sSL "$BASE/sha256sums" -o "$DOWNLOAD_DIR/sha256sums"
CHECKSUM=$(awk -v name="$SDK_NAME" '$2 == name || $2 == "*" name {print;exit}' "$DOWNLOAD_DIR/sha256sums")
[[ -n "$CHECKSUM" ]] || exit 1
(cd "$DOWNLOAD_DIR"; printf '%s\n' "$CHECKSUM" | sha256sum -c -)
# Work directories are dedicated to this builder; do not reuse arbitrary SDK trees.
[[ ! -e "$SDK_DIR" ]] || { echo "SDK directory already exists: $SDK_DIR" >&2; exit 1; }
mkdir -p "$SDK_DIR"
tar --zstd -xf "$DOWNLOAD_DIR/$SDK_NAME" -C "$SDK_DIR" --strip-components=1
(cd "$SDK_DIR"; ./scripts/feeds update -a)
# The release SDK pins older feeds. Overlay only Go host recipes from a pinned
# 25.12 packages revision containing Go 1.27.1; keep runtime packages unchanged.
GO_FEED_REF=92bc64441b8508979d1242145ff82d26e378a4a4
GO_FEED="$WORK_DIR/go-feed"
git init -q "$GO_FEED"
git -C "$GO_FEED" remote add origin https://github.com/openwrt/packages.git
git -C "$GO_FEED" fetch -q --depth=1 origin "$GO_FEED_REF"
git -C "$GO_FEED" sparse-checkout init --cone
git -C "$GO_FEED" sparse-checkout set lang/golang
git -C "$GO_FEED" checkout -q --detach FETCH_HEAD
cp -a "$GO_FEED/lang/golang/." "$SDK_DIR/feeds/packages/lang/golang/"
(cd "$SDK_DIR"; ./scripts/feeds update -i packages; ./scripts/feeds install -a)
cp -a openwrt/package/p2ptap openwrt/package/luci-app-p2ptap "$SDK_DIR/package/"
P2PTAP_SOURCE_VERSION="$SOURCE_VERSION" bash scripts/set_openwrt_version.sh "$RELEASE_VERSION" "$SDK_DIR/package"
sed -i -e "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$SOURCE_VERSION/" \
  -e 's/^PKG_MIRROR_HASH:=.*/PKG_MIRROR_HASH:=skip/' "$SDK_DIR/package/p2ptap/Makefile"
# The source is fetched by immutable SHA; no stale hash of the moving main archive.
# SDK defaults may select every package and bootloader variant. Restrict this
# build to the application and dependencies while retaining target settings.
touch "$SDK_DIR/.config"
sed -i -e '/^CONFIG_ALL=/d' -e '/^CONFIG_ALL_NONSHARED=/d' -e '/^CONFIG_ALL_KMODS=/d' "$SDK_DIR/.config"
cat >> "$SDK_DIR/.config" <<'EOF'
# CONFIG_ALL is not set
# CONFIG_ALL_NONSHARED is not set
# CONFIG_ALL_KMODS is not set
CONFIG_PACKAGE_p2ptap=m
CONFIG_PACKAGE_luci-app-p2ptap=m
CONFIG_PACKAGE_luci-i18n-p2ptap-zh-cn=m
CONFIG_PACKAGE_luci-i18n-p2ptap-fr=m
CONFIG_PACKAGE_luci-i18n-p2ptap-ja=m
EOF
make -C "$SDK_DIR" defconfig
make -C "$SDK_DIR" -j"$JOBS" package/p2ptap/compile V=sc
make -C "$SDK_DIR" -j"$JOBS" package/luci-app-p2ptap/compile V=sc
for pkg in p2ptap luci-app-p2ptap luci-i18n-p2ptap-zh-cn luci-i18n-p2ptap-fr luci-i18n-p2ptap-ja; do
  mapfile -t files < <(find "$SDK_DIR/bin" -type f -name "$pkg-[0-9]*.apk")
  [[ "${#files[@]}" -ge 1 ]] || { echo "Missing APK: $pkg" >&2; exit 1; }
  for file in "${files[@]}"; do cp "$file" "$OUTPUT_DIR/"; done
done
