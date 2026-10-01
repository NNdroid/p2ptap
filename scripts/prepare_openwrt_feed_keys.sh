#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  prepare_openwrt_feed_keys.sh pair <private-key-output> <public-key-output>
  prepare_openwrt_feed_keys.sh public <public-key-output>

The pair command reads OPENWRT_FEED_SIGNING_KEY_B64 and
OPENWRT_FEED_PUBLIC_KEY_B64. The public command only reads the public-key
variable. Base64-encoded PEM and DER are accepted. Raw PEM and one accidental
extra Base64 layer around PEM or DER are also normalized for recovery.
EOF
  exit 2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command -v openssl >/dev/null 2>&1 || die 'openssl is required to validate OpenWrt feed keys'
command -v base64 >/dev/null 2>&1 || die 'base64 is required to decode OpenWrt feed keys'

umask 077
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

pem_label() {
  LC_ALL=C tr -d '\r' < "$1" | \
    sed -n 's/^-----BEGIN \(.*\)-----$/\1/p' | sed -n '1p'
}

normalize_literal_newlines() {
  local value="$1"
  # Some secret-management UIs export multiline PEM as a single line with
  # literal \n sequences. Expanding those sequences is safe here because the
  # result is still parsed and normalized by OpenSSL before use.
  value="${value//\\r\\n/$'\n'}"
  value="${value//\\n/$'\n'}"
  printf '%s' "$value"
}

decode_key_value() {
  local setting="$1"
  local value="$2"
  local output="$3"
  local first="$tmp_dir/${setting}.first"
  local second="$tmp_dir/${setting}.second"
  local compact=''
  local label=''
  local padding=0

  [[ -n "$value" ]] || die "$setting is empty"

  if [[ "$value" == *'-----BEGIN '* ]]; then
    normalize_literal_newlines "$value" > "$output"
    printf '[openwrt-feed-key] %s encoding=raw-pem bytes=%s\n' \
      "$setting" "$(wc -c < "$output")"
    return
  fi

  compact="$(printf '%s' "$value" | tr -d '[:space:]')"
  if ! printf '%s' "$compact" | base64 --decode > "$first" 2>/dev/null; then
    die "$setting is neither PEM nor valid Base64; encode the PEM file bytes, not its path"
  fi

  label="$(pem_label "$first")"
  if [[ -n "$label" ]]; then
    cp "$first" "$output"
    printf '[openwrt-feed-key] %s encoding=base64 pem_label=%s bytes=%s\n' \
      "$setting" "$label" "$(wc -c < "$output")"
    return
  fi

  # Recover a common configuration mistake where a value that was already
  # Base64 text was encoded a second time. The second layer may contain PEM or
  # DER, and the caller still requires OpenSSL to parse and validate the result.
  # Do not recurse beyond one extra layer: accepting arbitrary wrapping would
  # conceal a genuinely wrong key.
  if ! LC_ALL=C grep -a -q '[^[:print:][:space:]]' "$first"; then
    compact="$(tr -d '[:space:]' < "$first")"
    compact="${compact//\\r\\n/}"
    compact="${compact//\\n/}"
    if [[ "$compact" =~ ^[A-Za-z0-9_-]+={0,2}$ ]]; then
      compact="${compact//-/+}"
      compact="${compact//_/\/}"
      padding=$(( (4 - ${#compact} % 4) % 4 ))
      if (( padding == 1 )); then compact+='='; elif (( padding == 2 )); then compact+='=='; fi
    fi
    if [[ -n "$compact" && "$compact" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] && \
       (( ${#compact} % 4 == 0 )) && \
       printf '%s' "$compact" | base64 --decode > "$second" 2>/dev/null && \
       [[ -s "$second" ]]; then
      cp "$second" "$output"
      label="$(pem_label "$output")"
      printf '[openwrt-feed-key] %s encoding=double-base64 pem_label=%s bytes=%s\n' \
        "$setting" "${label:-none}" "$(wc -c < "$output")"
      return
    fi
  fi

  cp "$first" "$output"
  printf '[openwrt-feed-key] %s encoding=base64 pem_label=none bytes=%s\n' \
    "$setting" "$(wc -c < "$output")"
}

content_class() {
  local input="$1"
  local compact=''
  if LC_ALL=C grep -a -q '^untrusted comment: minisign' "$input"; then
    printf 'minisign-key'
    return
  fi
  if LC_ALL=C grep -a -q '[^[:print:][:space:]]' "$input"; then
    printf 'unrecognized-binary'
    return
  fi
  compact="$(tr -d '[:space:]' < "$input")"
  case "$compact" in
    ssh-*) printf 'openssh-public-text' ;;
    \{*) printf 'json-text' ;;
    /*|./*|../*) printf 'path-text' ;;
    *)
      if [[ "$compact" =~ ^[0-9A-Fa-f]+$ ]]; then
        printf 'hex-text'
      elif [[ "$compact" =~ ^[A-Za-z0-9_-]+={0,2}$ ]]; then
        printf 'base64url-text'
      else
        printf 'unrecognized-text'
      fi
      ;;
  esac
}

diagnose_private_key() {
  local input="$1"
  local label
  local class
  label="$(pem_label "$input")"
  class="$(content_class "$input")"
  case "$label" in
    PUBLIC\ KEY|EC\ PUBLIC\ KEY)
      die 'OPENWRT_FEED_SIGNING_KEY_B64 contains a public key; it must contain the matching private key'
      ;;
    ENCRYPTED\ PRIVATE\ KEY)
      die 'OPENWRT_FEED_SIGNING_KEY_B64 contains an encrypted private key; CI requires an unencrypted EC P-256 key'
      ;;
    '')
      if [[ "$class" == 'minisign-key' ]]; then
        die 'OPENWRT_FEED_SIGNING_KEY_B64 contains a Minisign/Ed25519 key; OpenWrt APK repository signing requires an unencrypted OpenSSL EC P-256 private key'
      fi
      die "OPENWRT_FEED_SIGNING_KEY_B64 decoded successfully but is not a readable PEM/DER private key (content_class=$class); encode the private key file bytes, not its filename"
      ;;
    *)
      die "OPENWRT_FEED_SIGNING_KEY_B64 has PEM label '$label' but OpenSSL cannot read it as an unencrypted private key"
      ;;
  esac
}

diagnose_public_key() {
  local input="$1"
  local label
  local class
  label="$(pem_label "$input")"
  class="$(content_class "$input")"
  case "$label" in
    EC\ PRIVATE\ KEY|PRIVATE\ KEY|ENCRYPTED\ PRIVATE\ KEY)
      die 'OPENWRT_FEED_PUBLIC_KEY_B64 contains a private key; store only the derived public key in the Actions Variable'
      ;;
    '')
      if [[ "$class" == 'minisign-key' ]]; then
        die 'OPENWRT_FEED_PUBLIC_KEY_B64 contains a Minisign/Ed25519 key; OpenWrt APK clients require the matching OpenSSL EC P-256 public key'
      fi
      die "OPENWRT_FEED_PUBLIC_KEY_B64 decoded successfully but is not a readable PEM/DER public key (content_class=$class); encode the public key file bytes, not its filename"
      ;;
    *)
      die "OPENWRT_FEED_PUBLIC_KEY_B64 has PEM label '$label' but OpenSSL cannot read it as an EC public key"
      ;;
  esac
}

normalize_public_key() {
  local output="$1"
  local raw="$tmp_dir/public.raw.pem"
  local normalized="$tmp_dir/public.normalized.pem"

  decode_key_value OPENWRT_FEED_PUBLIC_KEY_B64 \
    "${OPENWRT_FEED_PUBLIC_KEY_B64:-}" "$raw"
  if openssl ec -pubin -inform PEM -in "$raw" -pubout -out "$normalized" >/dev/null 2>&1; then
    printf '[openwrt-feed-key] public_key_format=PEM\n'
  elif openssl ec -pubin -inform DER -in "$raw" -pubout -out "$normalized" >/dev/null 2>&1; then
    printf '[openwrt-feed-key] public_key_format=DER normalized=PEM\n'
  else
    diagnose_public_key "$raw"
  fi
  chmod 644 "$normalized"
  mv -f "$normalized" "$output"
  printf '[openwrt-feed-key] public_key_sha256=%s\n' \
    "$(openssl pkey -pubin -in "$output" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
}

normalize_key_pair() {
  local private_output="$1"
  local public_output="$2"
  local raw_private="$tmp_dir/private.raw.pem"
  local generic_private="$tmp_dir/private.generic.pem"
  local normalized_private="$tmp_dir/private.normalized.pem"
  local derived_public_der="$tmp_dir/private.public.der"
  local configured_public_der="$tmp_dir/configured.public.der"
  local curve=''
  local private_format='PEM'

  decode_key_value OPENWRT_FEED_SIGNING_KEY_B64 \
    "${OPENWRT_FEED_SIGNING_KEY_B64:-}" "$raw_private"
  if openssl pkey -inform PEM -in "$raw_private" -passin pass: -check -noout >/dev/null 2>&1; then
    private_format='PEM'
  elif openssl pkey -inform DER -in "$raw_private" -passin pass: -check -noout >/dev/null 2>&1; then
    private_format='DER'
  else
    diagnose_private_key "$raw_private"
  fi
  openssl pkey -inform "$private_format" -in "$raw_private" -passin pass: -out "$generic_private" >/dev/null 2>&1
  if ! openssl ec -in "$generic_private" -out "$normalized_private" >/dev/null 2>&1; then
    die 'OPENWRT_FEED_SIGNING_KEY_B64 is a private key, but it is not an EC key supported by the OpenWrt APK signer'
  fi
  printf '[openwrt-feed-key] private_key_format=%s normalized=PEM\n' "$private_format"

  curve="$(openssl ec -in "$normalized_private" -text -noout 2>/dev/null | sed -n 's/^[[:space:]]*ASN1 OID: //p' | head -n 1)"
  [[ "$curve" == 'prime256v1' ]] || \
    die "OPENWRT_FEED_SIGNING_KEY_B64 uses '${curve:-an unknown curve}'; OpenWrt feed signing requires EC P-256 (prime256v1)"

  normalize_public_key "$public_output"
  openssl ec -in "$normalized_private" -pubout -outform DER > "$derived_public_der" 2>/dev/null
  openssl ec -pubin -in "$public_output" -pubout -outform DER > "$configured_public_der" 2>/dev/null
  cmp -s "$derived_public_der" "$configured_public_der" || \
    die 'OPENWRT_FEED_PUBLIC_KEY_B64 does not match OPENWRT_FEED_SIGNING_KEY_B64'

  chmod 600 "$normalized_private"
  mv -f "$normalized_private" "$private_output"
  printf '[openwrt-feed-key] private_key_type=EC curve=%s pair_match=true\n' "$curve"
}

mode="${1:-}"
case "$mode" in
  pair)
    [[ "$#" -eq 3 ]] || usage
    normalize_key_pair "$2" "$3"
    ;;
  public)
    [[ "$#" -eq 2 ]] || usage
    normalize_public_key "$2"
    ;;
  *)
    usage
    ;;
esac
