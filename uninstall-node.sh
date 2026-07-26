#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }
echo "此操作会永久删除本节点上的全部 Incus 实例、镜像、网络和存储数据。"
read -r -p "输入 PURGE-NODE 确认: " answer </dev/tty
[[ $answer == PURGE-NODE ]] || { echo "已取消。"; exit 0; }

if command -v incus >/dev/null 2>&1; then
  while IFS= read -r instance; do
    [[ -n $instance ]] && incus delete "$instance" --force
  done < <(incus list --format=csv -c n 2>/dev/null || true)
fi
systemctl disable --now incus.service 2>/dev/null || true
apt-get purge -y incus incus-base incus-client 2>/dev/null || true
rm -rf /var/lib/incus /etc/incus
rm -f /root/incus-node-token.txt /usr/local/sbin/incus-cn-node-uninstall
rm -f /etc/apt/sources.list.d/zabbly-incus-stable.sources /etc/apt/keyrings/zabbly.asc
apt-get autoremove -y
echo "计算节点及全部 Incus 数据已清除。"
