#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -gt 0 ]]; then
  echo "用法: $0" >&2
  exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }

systemctl disable --now incus-cn-panel.service 2>/dev/null || true
systemctl disable --now incus-cn-panel-proxy.service 2>/dev/null || true
rm -f /etc/systemd/system/incus-cn-panel.service
rm -f /etc/systemd/system/incus-cn-panel-proxy.service
rm -rf /opt/incus-cn-panel /etc/incus-cn-panel /var/lib/incus-cn-panel
rm -f /root/incus-cn-panel-credentials.txt
rm -f /usr/local/sbin/incus-cn-panel-uninstall
rm -f /usr/local/sbin/incus-cn-panel-bootstrap /usr/local/sbin/incus-cn-panel-update
systemctl daemon-reload
echo "中文控制面板及其客户端证书已卸载；远程计算节点和实例均未改动。"
