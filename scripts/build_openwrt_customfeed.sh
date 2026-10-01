#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86}"
OPENWRT_SUBTARGET="${OPENWRT_SUBTARGET:-64}"
OPENWRT_FEED_OUTPUT_DIR="${OPENWRT_FEED_OUTPUT_DIR:-$ROOT_DIR/bin/openwrt-customfeed}"
OPENWRT_WORK_DIR="${OPENWRT_WORK_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/p2ptap-openwrt-customfeed/$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"
OPENWRT_FEED_SIGNING_KEY_FILE="${OPENWRT_FEED_SIGNING_KEY_FILE:-}"
OPENWRT_FEED_PUBLIC_KEY_FILE="${OPENWRT_FEED_PUBLIC_KEY_FILE:-}"
P2PTAP_SOURCE_VERSION="${P2PTAP_SOURCE_VERSION:-$(git rev-parse HEAD)}"
P2PTAP_PKG_VERSION="${P2PTAP_PKG_VERSION:-v1.0.$(date -u +%Y%m%d)}"
JOBS="${JOBS:-2}"
OPENWRT_APK_BUILD_SCRIPT="${OPENWRT_APK_BUILD_SCRIPT:-$ROOT_DIR/scripts/build_openwrt_apk.sh}"

BUILD_STAGE="startup"
log_debug() {
  printf '[openwrt-feed][%s][%s/%s] %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OPENWRT_TARGET" "$OPENWRT_SUBTARGET" "$*"
}

fail_with_context() {
  local status=$?
  local line="${BASH_LINENO[0]:-${LINENO}}"
  local command="${BASH_COMMAND:-unknown}"
  trap - ERR
  printf 'error: OpenWrt custom feed failed: stage=%s line=%s exit=%s command=%q\n' \
    "$BUILD_STAGE" "$line" "$status" "$command" >&2
  printf 'error: context: version=%s target=%s/%s source=%s package_version=%s work_dir=%s output_dir=%s\n' \
    "$OPENWRT_VERSION" "$OPENWRT_TARGET" "$OPENWRT_SUBTARGET" \
    "$P2PTAP_SOURCE_VERSION" "${P2PTAP_PKG_VERSION:-<empty>}" \
    "$OPENWRT_WORK_DIR" "$OPENWRT_FEED_OUTPUT_DIR" >&2
  exit "$status"
}
trap fail_with_context ERR

set_stage() {
  BUILD_STAGE="$1"
  shift
  log_debug "stage=$BUILD_STAGE $*"
}

set_stage validate-inputs \
  "version=$OPENWRT_VERSION source=$P2PTAP_SOURCE_VERSION package_version=${P2PTAP_PKG_VERSION:-<empty>} jobs=$JOBS"

# On pull_request workflows GitHub checks out refs/pull/<n>/merge and github.sha
# points at that synthetic merge commit. OpenWrt's GitHub source downloader and
# fallback clone cannot fetch that SHA through normal repository refs. When the
# requested source SHA is exactly the checked-out merge commit, use its second
# parent instead: that is the real PR head commit and is fetchable from GitHub.
if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  checkout_sha="$(git rev-parse HEAD)"
  if [[ "$P2PTAP_SOURCE_VERSION" == "$checkout_sha" ]]; then
    if pr_head_sha="$(git rev-parse HEAD^2 2>/dev/null)" && [[ -n "$pr_head_sha" ]]; then
      printf 'Pull request merge SHA %s is not a stable source ref; using PR head %s\n' \
        "$P2PTAP_SOURCE_VERSION" "$pr_head_sha"
      P2PTAP_SOURCE_VERSION="$pr_head_sha"
    fi
  fi
fi

[[ -n "$OPENWRT_FEED_SIGNING_KEY_FILE" ]] || {
  echo "error: OPENWRT_FEED_SIGNING_KEY_FILE is required" >&2
  exit 2
}
[[ -s "$OPENWRT_FEED_SIGNING_KEY_FILE" ]] || {
  echo "error: signing key not found: $OPENWRT_FEED_SIGNING_KEY_FILE" >&2
  exit 2
}
[[ -n "$OPENWRT_FEED_PUBLIC_KEY_FILE" ]] || {
  echo "error: OPENWRT_FEED_PUBLIC_KEY_FILE is required" >&2
  exit 2
}
[[ -s "$OPENWRT_FEED_PUBLIC_KEY_FILE" ]] || {
  echo "error: public key not found: $OPENWRT_FEED_PUBLIC_KEY_FILE" >&2
  exit 2
}

case "$OPENWRT_VERSION" in
  25.12.*) ;;
  *) echo "error: custom APK feeds require OpenWrt 25.12+" >&2; exit 2 ;;
esac

# Build through the existing SDK path, but assemble the repository from the
# SDK's canonical APK filenames. Release assets intentionally carry additional
# target suffixes and are not valid repository package filenames.
[[ -x "$OPENWRT_APK_BUILD_SCRIPT" ]] || {
  echo "error: OpenWrt APK build script is not executable: $OPENWRT_APK_BUILD_SCRIPT" >&2
  exit 2
}
set_stage build-sdk "builder=$OPENWRT_APK_BUILD_SCRIPT"
OPENWRT_INCLUDE_ARCH_INDEPENDENT=1 \
OPENWRT_WORK_DIR="$OPENWRT_WORK_DIR" \
OPENWRT_OUTPUT_DIR="$ROOT_DIR/bin/openwrt-customfeed-release/$OPENWRT_TARGET-$OPENWRT_SUBTARGET" \
OPENWRT_VERSION="$OPENWRT_VERSION" \
OPENWRT_TARGET="$OPENWRT_TARGET" \
OPENWRT_SUBTARGET="$OPENWRT_SUBTARGET" \
JOBS="$JOBS" \
P2PTAP_SOURCE_VERSION="$P2PTAP_SOURCE_VERSION" \
P2PTAP_PKG_VERSION="$P2PTAP_PKG_VERSION" \
  "$OPENWRT_APK_BUILD_SCRIPT"

SDK_DIR="$OPENWRT_WORK_DIR/sdk"
APK_TOOL="$SDK_DIR/staging_dir/host/bin/apk"
OPENSSL_TOOL="$SDK_DIR/staging_dir/host/bin/openssl"
set_stage inspect-sdk-tools "sdk=$SDK_DIR"
[[ -x "$APK_TOOL" ]] || { echo "error: SDK apk host tool missing: $APK_TOOL" >&2; exit 1; }
[[ -x "$OPENSSL_TOOL" ]] || { echo "error: SDK openssl host tool missing: $OPENSSL_TOOL" >&2; exit 1; }
log_debug "apk_tool=$APK_TOOL"
"$APK_TOOL" --version 2>&1 | sed 's/^/[openwrt-feed][apk-version] /' || true
log_debug "openssl_tool=$OPENSSL_TOOL"
"$OPENSSL_TOOL" version 2>&1 | sed 's/^/[openwrt-feed][openssl-version] /' || true
if command -v file >/dev/null 2>&1; then
  file "$APK_TOOL" "$OPENSSL_TOOL" | sed 's/^/[openwrt-feed][tool-file] /'
fi

FEED_DIR="$OPENWRT_FEED_OUTPUT_DIR/releases/$OPENWRT_VERSION/$OPENWRT_TARGET/$OPENWRT_SUBTARGET"
rm -rf "$FEED_DIR"
mkdir -p "$FEED_DIR"

set_stage collect-packages "sdk_bin=$SDK_DIR/bin feed_dir=$FEED_DIR"
main_count=0
package_count=0
while IFS= read -r apk; do
  base="$(basename "$apk")"
  case "$base" in
    luci-app-p2ptap-*.apk|luci-i18n-p2ptap-*.apk)
      ;;
    p2ptap-*.apk)
      main_count=$((main_count + 1))
      ;;
    *)
      continue
      ;;
  esac

  dest="$FEED_DIR/$base"
  if [[ -e "$dest" ]]; then
    cmp -s "$apk" "$dest" || {
      echo "error: conflicting APKs with the same canonical filename: $base" >&2
      exit 1
    }
    continue
  fi
  cp -f "$apk" "$dest"
  package_count=$((package_count + 1))
done < <(find "$SDK_DIR/bin" -type f -name '*.apk' | sort)

[[ "$main_count" -ge 1 ]] || { echo "error: canonical p2ptap APK was not found" >&2; exit 1; }
[[ "$package_count" -ge 3 ]] || { echo "error: custom feed package set is incomplete ($package_count APKs)" >&2; exit 1; }
log_debug "collected_packages=$package_count main_packages=$main_count"
find "$FEED_DIR" -maxdepth 1 -type f -name '*.apk' -printf '[openwrt-feed][apk] %f %s bytes\n' | sort

# Canonicalize both keys with the SDK OpenSSL build and prove that the public
# key configured for clients belongs to the private key used to sign the feed.
# The configured public key, never a separately derived trust root, is what gets
# published as p2ptap-feed.pem.
set_stage validate-signing-keys "private_key=$OPENWRT_FEED_SIGNING_KEY_FILE public_key=$OPENWRT_FEED_PUBLIC_KEY_FILE"
chmod 600 "$OPENWRT_FEED_SIGNING_KEY_FILE"
canonical_private_public="$OPENWRT_WORK_DIR/signing-key-derived-public.pem"
# OpenWrt's host OpenSSL is intentionally minimal. Match OpenWrt's own APK
# signing path and use the EC command instead of assuming the generic `pkey`
# command or OpenSSL-only `ec -check` flag is compiled into the SDK's LibreSSL.
# Successfully deriving the public key proves that the private EC key parses;
# the byte-for-byte comparison below then proves it matches the configured key.
"$OPENSSL_TOOL" ec -in "$OPENWRT_FEED_SIGNING_KEY_FILE" -pubout > "$canonical_private_public"
"$OPENSSL_TOOL" ec -pubin -in "$OPENWRT_FEED_PUBLIC_KEY_FILE" -pubout > "$FEED_DIR/p2ptap-feed.pem"
derived_public_sha256="$(sha256sum "$canonical_private_public" | awk '{print $1}')"
configured_public_sha256="$(sha256sum "$FEED_DIR/p2ptap-feed.pem" | awk '{print $1}')"
log_debug "derived_public_key_sha256=$derived_public_sha256 configured_public_key_sha256=$configured_public_sha256"
cmp -s "$canonical_private_public" "$FEED_DIR/p2ptap-feed.pem" || {
  echo "error: configured OpenWrt feed public key does not match the signing private key" >&2
  exit 1
}

# Packages and repository index use the same stable trust root.
VERIFY_ROOT="$OPENWRT_WORK_DIR/feed-verify-root"
rm -rf "$VERIFY_ROOT"
mkdir -p "$VERIFY_ROOT/etc/apk/keys"
cp "$FEED_DIR/p2ptap-feed.pem" "$VERIFY_ROOT/etc/apk/keys/p2ptap-feed.pem"
set_stage sign-packages "apk_count=$package_count"
# The locally built inputs carry the SDK's ephemeral key. Permit reading those
# only while replacing signatures, then verify each result against our key.
# Invoke separately: this apk version retains signing state between arguments.
for package in "$FEED_DIR"/*.apk; do
  "$APK_TOOL" adbsign --allow-untrusted --sign "$OPENWRT_FEED_SIGNING_KEY_FILE" --reset-signatures "$package"
  "$APK_TOOL" --root "$VERIFY_ROOT" --keys-dir etc/apk/keys verify "$package"
done

set_stage build-index "apk_count=$package_count"
(
  cd "$FEED_DIR"
  "$APK_TOOL" mkndx \
    --root "$VERIFY_ROOT" \
    --keys-dir etc/apk/keys \
    --sign "$OPENWRT_FEED_SIGNING_KEY_FILE" \
    --output packages.adb \
    ./*.apk

  # Ensure apk v3 can decode the generated repository and retain a JSON form
  # for diagnostics without making clients depend on it.
  "$APK_TOOL" --root "$VERIFY_ROOT" --keys-dir etc/apk/keys adbdump --format json packages.adb > index.json
)
log_debug "repository_index_bytes=$(wc -c < "$FEED_DIR/packages.adb") diagnostic_index_bytes=$(wc -c < "$FEED_DIR/index.json")"

# Verify the signed repository using only the configured public key that clients
# receive. This catches a wrong Actions Variable before anything can publish.
set_stage verify-index "verify_root=$OPENWRT_WORK_DIR/feed-verify-root"
"$APK_TOOL" \
  --root "$VERIFY_ROOT" \
  --keys-dir etc/apk/keys \
  verify "$FEED_DIR/packages.adb" "$FEED_DIR"/*.apk
rm -rf "$VERIFY_ROOT"

set_stage write-metadata "feed_dir=$FEED_DIR"
cat > "$FEED_DIR/feed-info.json" <<EOF
{
  "repository": "NNdroid/p2ptap",
  "openwrt_version": "$OPENWRT_VERSION",
  "target": "$OPENWRT_TARGET",
  "subtarget": "$OPENWRT_SUBTARGET",
  "source_commit": "$P2PTAP_SOURCE_VERSION",
  "source_version": "$P2PTAP_PKG_VERSION",
  "package_count": $package_count
}
EOF

(
  cd "$FEED_DIR"
  sha256sum ./*.apk packages.adb index.json p2ptap-feed.pem feed-info.json > SHA256SUMS
)

set_stage complete "feed_dir=$FEED_DIR"
printf 'Custom feed ready: %s\n' "$FEED_DIR"
printf 'Repository index: %s/packages.adb\n' "$FEED_DIR"
find "$FEED_DIR" -maxdepth 1 -type f -printf '%f\n' | sort
