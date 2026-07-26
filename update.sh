#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY=${INCUS_CN_REPOSITORY:-NorwayXZ/incus-cn-panel}
BRANCH=${INCUS_CN_BRANCH:-main}
APP_DIR=/opt/incus-cn-panel
DATA_DIR=/var/lib/incus-cn-panel
STATUS_FILE=${DATA_DIR}/update-status.json
LOG_FILE=${DATA_DIR}/update.log
BOOTSTRAP=/usr/local/sbin/incus-cn-panel-bootstrap
VERSION_URL="https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/VERSION"

write_status() {
  local state=$1 message=$2 current=$3 target=$4 temporary
  install -d -m 0700 "$DATA_DIR"
  temporary="${STATUS_FILE}.$$"
  jq -n \
    --arg status "$state" \
    --arg message "$message" \
    --arg current_version "$current" \
    --arg target_version "$target" \
    --arg updated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    '{status:$status,message:$message,current_version:$current_version,target_version:$target_version,updated_at:$updated_at}' \
    > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$STATUS_FILE"
}

current_version=$(tr -d '[:space:]' < "$APP_DIR/VERSION" 2>/dev/null || printf '0.0.0')
if ! target_version=$(curl -fsSL --max-time 15 "$VERSION_URL" | tr -d '[:space:]'); then
  write_status failed "无法从 GitHub 获取最新版本" "$current_version" ""
  exit 1
fi
[[ "$target_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  write_status failed "远程版本号无效" "$current_version" "$target_version"
  exit 1
}

write_status running "正在下载并安装新版本" "$current_version" "$target_version"
install -m 0600 /dev/null "$LOG_FILE"
if INCUS_CN_REPOSITORY="$REPOSITORY" INCUS_CN_BRANCH="$BRANCH" "$BOOTSTRAP" > "$LOG_FILE" 2>&1; then
  installed_version=$(tr -d '[:space:]' < "$APP_DIR/VERSION" 2>/dev/null || printf '%s' "$target_version")
  write_status complete "版本更新完成，请重新登录" "$installed_version" "$target_version"
else
  exit_code=$?
  write_status failed "升级脚本执行失败（退出码 ${exit_code}）" "$current_version" "$target_version"
  exit "$exit_code"
fi
