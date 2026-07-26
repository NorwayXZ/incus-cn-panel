#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR=/opt/incus-cn-panel
CONFIG_DIR=/etc/incus-cn-panel
DATA_DIR=/var/lib/incus-cn-panel
SERVICE_NAME=incus-cn-panel
PANEL_PORT_WAS_SET=${PANEL_PORT+x}
PANEL_USER_WAS_SET=${PANEL_USER+x}
PANEL_PORT=${PANEL_PORT:-8443}
PANEL_USER=${PANEL_USER:-admin}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

log() { printf '\033[1;32m[Incus CN]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "请使用 root 用户运行此脚本。"
[[ -f /etc/os-release ]] || die "无法识别操作系统。"
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "当前仅支持 Ubuntu 和 Debian。" ;;
esac
if [[ -f "$CONFIG_DIR/config.env" ]]; then
  if [[ -z $PANEL_PORT_WAS_SET ]]; then
    PANEL_PORT=$(sed -n 's/^PANEL_PORT=//p' "$CONFIG_DIR/config.env" | tail -n 1)
  fi
  if [[ -z $PANEL_USER_WAS_SET ]]; then
    PANEL_USER=$(sed -n 's/^PANEL_USER=//p' "$CONFIG_DIR/config.env" | tail -n 1)
  fi
fi
[[ "$PANEL_PORT" =~ ^[0-9]+$ ]] && (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )) || die "PANEL_PORT 无效。"
[[ "$PANEL_USER" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "PANEL_USER 只能包含字母、数字、下划线和连字符。"

free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
if (( free_kb < 262144 )); then
  die "根分区可用空间不足 256 MiB，无法安全安装控制面板。"
elif (( free_kb < 1048576 )); then
  warn "根分区可用空间少于 1 GiB。"
fi

if ss -lntH "sport = :${PANEL_PORT}" 2>/dev/null | grep -q .; then
  current_pid=$(systemctl show -p MainPID --value "$SERVICE_NAME" 2>/dev/null || true)
  [[ ${current_pid:-0} != 0 ]] || die "端口 ${PANEL_PORT} 已被其他程序占用。"
fi

export DEBIAN_FRONTEND=noninteractive
log "安装基础依赖"
apt-get update
apt-get install -y ca-certificates curl gnupg openssl python3 jq

if ! command -v incus >/dev/null 2>&1; then
  log "添加 Zabbly Incus 稳定版软件源"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
  arch=$(dpkg --print-architecture)
  codename=${VERSION_CODENAME:-}
  [[ -n "$codename" ]] || die "无法确定系统代号。"
  cat > /etc/apt/sources.list.d/zabbly-incus-stable.sources <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${codename}
Components: main
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF
  apt-get update
  apt-get install -y incus-client
else
  log "检测到 Incus 客户端，保留现有安装"
fi

log "安装中文管理面板"
install -d -m 0755 "$APP_DIR"
install -d -m 0755 "$APP_DIR/static"
install -d -m 0700 "$CONFIG_DIR"
install -d -m 0700 "$CONFIG_DIR/incus-client"
install -d -m 0700 "$DATA_DIR"
install -m 0755 "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"
install -m 0644 "$SCRIPT_DIR/static/index.html" "$APP_DIR/static/index.html"
install -m 0644 "$SCRIPT_DIR/static/lucide.min.js" "$APP_DIR/static/lucide.min.js"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" /usr/local/sbin/incus-cn-panel-uninstall
install -m 0644 "$SCRIPT_DIR/incus-cn-panel.service" /etc/systemd/system/incus-cn-panel.service

if [[ -f "$CONFIG_DIR/config.env" && -f /root/incus-cn-panel-credentials.txt && -z ${PANEL_PASSWORD:-} && -z $PANEL_PORT_WAS_SET && -z $PANEL_USER_WAS_SET ]]; then
  log "保留现有面板账号、密码、端口和证书"
else
  if [[ -z ${PANEL_PASSWORD:-} ]]; then
    PANEL_PASSWORD=$(openssl rand -hex 12)
  fi
  [[ ${#PANEL_PASSWORD} -ge 10 ]] || die "PANEL_PASSWORD 至少需要 10 个字符。"
  salt=$(openssl rand -hex 16)
  password_iterations=260000
  password_hash=$(PANEL_PASSWORD_VALUE="$PANEL_PASSWORD" PANEL_SALT_VALUE="$salt" PANEL_ITERATIONS_VALUE="$password_iterations" python3 - <<'PY'
import hashlib
import os

print(hashlib.pbkdf2_hmac(
    "sha256",
    os.environ["PANEL_PASSWORD_VALUE"].encode(),
    bytes.fromhex(os.environ["PANEL_SALT_VALUE"]),
    int(os.environ["PANEL_ITERATIONS_VALUE"]),
).hex())
PY
)
  public_ip=$(curl -4fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
  [[ -n "$public_ip" ]] || public_ip=127.0.0.1

  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$CONFIG_DIR/panel.key" -out "$CONFIG_DIR/panel.crt" \
    -subj "/CN=${public_ip}" -addext "subjectAltName=IP:${public_ip}" >/dev/null 2>&1
  chmod 0600 "$CONFIG_DIR/panel.key"
  cat > "$CONFIG_DIR/config.env" <<EOF
PANEL_USER=${PANEL_USER}
PANEL_PASSWORD_SALT=${salt}
PANEL_PASSWORD_HASH=${password_hash}
PANEL_PASSWORD_ITERATIONS=${password_iterations}
PANEL_HOST=0.0.0.0
PANEL_PORT=${PANEL_PORT}
TLS_CERT=${CONFIG_DIR}/panel.crt
TLS_KEY=${CONFIG_DIR}/panel.key
INCUS_CONF=${CONFIG_DIR}/incus-client
PANEL_DATA_DIR=${DATA_DIR}
EOF
  chmod 0600 "$CONFIG_DIR/config.env"

  cat > /root/incus-cn-panel-credentials.txt <<EOF
访问地址: https://${public_ip}:${PANEL_PORT}
用户名: ${PANEL_USER}
密码: ${PANEL_PASSWORD}
注意: 当前使用自签名证书，浏览器首次访问会显示证书提醒。
EOF
  chmod 0600 /root/incus-cn-panel-credentials.txt
fi

if ! grep -q '^INCUS_CONF=' "$CONFIG_DIR/config.env"; then
  printf 'INCUS_CONF=%s/incus-client\n' "$CONFIG_DIR" >> "$CONFIG_DIR/config.env"
fi
if ! grep -q '^PANEL_DATA_DIR=' "$CONFIG_DIR/config.env"; then
  printf 'PANEL_DATA_DIR=%s\n' "$DATA_DIR" >> "$CONFIG_DIR/config.env"
fi
INCUS_CONF="$CONFIG_DIR/incus-client" incus remote list >/dev/null

systemctl daemon-reload
systemctl enable incus-cn-panel.service
systemctl restart incus-cn-panel.service
sleep 2
systemctl is-active --quiet incus-cn-panel.service || {
  journalctl -u incus-cn-panel.service -n 50 --no-pager >&2
  die "面板服务启动失败。"
}

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "${PANEL_PORT}/tcp" comment 'Incus CN Panel'
fi

log "安装完成"
cat /root/incus-cn-panel-credentials.txt
log "请在计算节点运行 install-node.sh，使用生成的 Trust Token 在 Web 面板中接入节点。"
