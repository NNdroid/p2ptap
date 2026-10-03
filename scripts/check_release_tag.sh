#!/usr/bin/env bash
# Reusing a tag is allowed only when it identifies the source being packaged.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="$(bash "$SCRIPT_DIR/get_version.sh" "${1:?Version required}")"
COMMIT="$(git -C "$REPO_DIR" rev-parse --verify "${2:-HEAD}^{commit}")"
if git -C "$REPO_DIR" show-ref --verify --quiet "refs/tags/$VERSION" &&
   [[ "$(git -C "$REPO_DIR" rev-parse "refs/tags/${VERSION}^{commit}")" != "$COMMIT" ]]; then
    echo "::error::Existing release tag points to another commit: $VERSION"
    exit 1
fi
