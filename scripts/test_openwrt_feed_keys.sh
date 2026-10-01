#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/private.pem"
openssl ec -in "$WORK/private.pem" -pubout -out "$WORK/public.pem" 2>/dev/null
export OPENWRT_FEED_SIGNING_KEY_B64=$(base64 -w0 "$WORK/private.pem")
export OPENWRT_FEED_PUBLIC_KEY_B64=$(base64 -w0 "$WORK/public.pem")
bash "$ROOT/scripts/prepare_openwrt_feed_keys.sh" pair "$WORK/normalized-private.pem" "$WORK/normalized-public.pem" >/dev/null
cmp "$WORK/public.pem" "$WORK/normalized-public.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/other.pem"
openssl ec -in "$WORK/other.pem" -pubout -out "$WORK/other-public.pem" 2>/dev/null
export OPENWRT_FEED_PUBLIC_KEY_B64=$(base64 -w0 "$WORK/other-public.pem")
if bash "$ROOT/scripts/prepare_openwrt_feed_keys.sh" pair "$WORK/bad-private.pem" "$WORK/bad-public.pem" >"$WORK/failure.log" 2>&1; then
  echo 'Mismatched signing key was accepted' >&2; exit 1
fi
grep -q 'does not match' "$WORK/failure.log"
export OPENWRT_FEED_SIGNING_KEY_B64=$(printf 'untrusted comment: minisign secret key\ninvalid' | base64 -w0)
if bash "$ROOT/scripts/prepare_openwrt_feed_keys.sh" pair "$WORK/bad-private.pem" "$WORK/bad-public.pem" >"$WORK/failure.log" 2>&1; then
  echo 'Minisign key was accepted' >&2; exit 1
fi
grep -q 'Minisign' "$WORK/failure.log"
echo 'Signing key pair and rejection checks passed'
