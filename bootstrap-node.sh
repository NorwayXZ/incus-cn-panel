#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY=${CLOUDNEST_REPOSITORY:-${INCUS_CN_REPOSITORY:-NorwayXZ/CloudNest}}
BRANCH=${CLOUDNEST_BRANCH:-${INCUS_CN_BRANCH:-main}}
command -v curl >/dev/null 2>&1 || { echo "缺少 curl 命令。" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "缺少 tar 命令。" >&2; exit 1; }
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

curl -fsSL "https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz" \
  | tar -xz -C "$TEMP_DIR" --strip-components=1

bash "$TEMP_DIR/install-node.sh"
