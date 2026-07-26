#!/usr/bin/env bash
set -Eeuo pipefail

PURGE=false
[[ ${1:-} == --purge ]] && PURGE=true
if [[ $# -gt 0 && ${1:-} != --purge ]]; then
  echo "用法: $0 [--purge]" >&2
  exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }

systemctl disable --now incus-cn-panel.service 2>/dev/null || true
rm -f /etc/systemd/system/incus-cn-panel.service
rm -rf /opt/incus-cn-panel /etc/incus-cn-panel
rm -f /root/incus-cn-panel-credentials.txt
rm -f /usr/local/sbin/incus-cn-panel-uninstall
systemctl daemon-reload

if [[ $PURGE == true ]]; then
  echo "即将永久删除全部 Incus 实例、镜像、网络和存储数据。"
  read -r -p "输入 PURGE 确认: " answer </dev/tty
  [[ $answer == PURGE ]] || { echo "已取消 Incus 数据清理。"; exit 0; }
  if command -v incus >/dev/null 2>&1; then
    while IFS= read -r instance; do
      [[ -n $instance ]] && incus delete "$instance" --force
    done < <(incus list --format=csv -c n 2>/dev/null || true)
  fi
  systemctl disable --now incus.service 2>/dev/null || true
  apt-get purge -y incus incus-base incus-client 2>/dev/null || true
  rm -rf /var/lib/incus /etc/incus
  rm -f /etc/apt/sources.list.d/zabbly-incus-stable.sources /etc/apt/keyrings/zabbly.asc
  apt-get autoremove -y
  echo "面板、Incus 及其实例数据已清除。"
else
  echo "中文面板已卸载；Incus、实例和数据均已保留。"
  echo "如需永久清空全部数据，请运行: $0 --purge"
fi
