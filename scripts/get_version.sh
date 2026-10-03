#!/usr/bin/env bash
# Print a build version only. Callers share this value across all build targets.
set -euo pipefail
RAW_VERSION="${1:-${P2PTAP_VERSION:-}}"
SOURCE_REF="${2:-HEAD}"
if [[ -n "$RAW_VERSION" ]]; then
    if [[ ! "$RAW_VERSION" =~ ^v?[0-9]+(\.[0-9]+)*(-[0-9a-f]{7})?$ ]]; then
        echo 'Invalid version: expected v1.2.3 or v1.0.YYYYMMDD.COUNT-HASH7' >&2
        exit 1
    fi
    printf 'v%s\n' "${RAW_VERSION#v}"
    exit 0
fi
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(git -C "$REPO_DIR" rev-parse --is-shallow-repository)" != false ]]; then
    echo 'Full Git history is required for automatic versioning; fetch with depth 0' >&2
    exit 1
fi
COMMIT="$(git -C "$REPO_DIR" rev-parse --verify "${SOURCE_REF}^{commit}")"
COUNT="$(git -C "$REPO_DIR" rev-list --count "$COMMIT")"
[[ "$COUNT" =~ ^[1-9][0-9]*$ ]] || exit 1
printf 'v1.0.%s.%s-%s\n' "$(date -u +%Y%m%d)" "$COUNT" "${COMMIT:0:7}"
