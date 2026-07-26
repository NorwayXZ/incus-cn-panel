#!/usr/bin/env bash
set -Eeuo pipefail

CONTROLLER_IP=${CONTROLLER_IP:-}
TRUST_NAME=${TRUST_NAME:-incus-cn-panel-$(date +%s)}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

log() { printf '\033[1;32m[Incus Node]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "请使用 root 用户运行此脚本。"
[[ -f /etc/os-release ]] || die "无法识别操作系统。"
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "当前仅支持 Ubuntu 和 Debian。" ;;
esac
[[ "$TRUST_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || die "TRUST_NAME 无效。"
if [[ -n $CONTROLLER_IP && ! $CONTROLLER_IP =~ ^[0-9a-fA-F:.]+$ ]]; then
  die "CONTROLLER_IP 格式无效。"
fi

free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
(( free_kb >= 1572864 )) || die "根分区可用空间不足 1.5 GiB。"
memory_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
(( memory_kb >= 1048576 )) || warn "内存少于 1 GiB，只适合极小型系统容器。"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg

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
  apt-get install -y incus
fi

systemctl enable --now incus.service
for _ in {1..30}; do
  incus version >/dev/null 2>&1 && break
  sleep 1
done
incus version >/dev/null 2>&1 || die "Incus 服务未能正常启动。"

if ! incus storage show default >/dev/null 2>&1; then
  log "初始化 dir 存储池和 NAT 网桥"
  incus admin init --preseed <<'EOF'
config: {}
networks:
- config:
    ipv4.address: auto
    ipv4.nat: "true"
    ipv6.address: auto
    ipv6.nat: "true"
  description: Incus managed NAT bridge
  name: incusbr0
  type: bridge
storage_pools:
- config: {}
  description: Local directory storage
  name: default
  driver: dir
profiles:
- config: {}
  description: Default Incus profile
  devices:
    eth0:
      name: eth0
      network: incusbr0
      type: nic
    root:
      path: /
      pool: default
      type: disk
  name: default
projects: []
cluster: null
EOF
fi

incus config set core.https_address "[::]:8443"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  if [[ -n $CONTROLLER_IP ]]; then
    ufw allow from "$CONTROLLER_IP" to any port 8443 proto tcp comment 'Incus controller'
  else
    warn "UFW 已启用但未设置 CONTROLLER_IP，请手动放行控制端到 8443。"
  fi
fi

if [[ -f "$SCRIPT_DIR/uninstall-node.sh" ]]; then
  install -m 0755 "$SCRIPT_DIR/uninstall-node.sh" /usr/local/sbin/incus-cn-node-uninstall
fi

token=$(incus --quiet config trust add "$TRUST_NAME")
cat > /root/incus-node-token.txt <<EOF
节点地址: https://$(curl -4fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}'):8443
Trust Token: ${token}
EOF
chmod 0600 /root/incus-node-token.txt

log "计算节点安装完成"
cat /root/incus-node-token.txt
warn "Trust Token 为一次性临时凭据，接入控制面板后即可删除该文件。"
