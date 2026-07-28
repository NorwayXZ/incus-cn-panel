#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }
echo "此操作会永久删除本节点上的全部 Incus 实例、镜像、网络和存储数据。"
read -r -p "输入 PURGE-NODE 确认: " answer </dev/tty
[[ $answer == PURGE-NODE ]] || { echo "已取消。"; exit 0; }

if command -v incus >/dev/null 2>&1 && systemctl is-active --quiet incus.service; then
  while IFS= read -r instance; do
    [[ -n $instance ]] && incus delete "$instance" --force
  done < <(incus list --format=csv -c n 2>/dev/null || true)
  incus admin shutdown 2>/dev/null || true
fi
systemctl disable --now incus.service incus.socket incus-user.service incus-user.socket \
  2>/dev/null || true

if [[ -f /var/lib/incus-host.swap ]]; then
  swapoff /var/lib/incus-host.swap 2>/dev/null || true
  sed -i '\|^/var/lib/incus-host\.swap[[:space:]]|d' /etc/fstab
  rm -f /var/lib/incus-host.swap
fi

packages=()
for package in incus incus-base incus-client; do
  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then
    packages+=("$package")
  fi
done
if (( ${#packages[@]} )); then
  DEBIAN_FRONTEND=noninteractive apt-get purge -y "${packages[@]}"
fi

if command -v ufw >/dev/null 2>&1; then
  mapfile -t ufw_rules < <(
    ufw status numbered 2>/dev/null \
      | sed -n 's/^\[ *\([0-9][0-9]*\)\].*Incus controller.*/\1/p' \
      | sort -rn
  )
  for rule in "${ufw_rules[@]}"; do
    ufw --force delete "$rule"
  done
fi

ip link delete incusbr0 2>/dev/null || true
rm -rf /var/lib/incus /var/cache/incus /var/log/incus /run/incus /etc/incus
rm -rf /root/.cache/incus /root/.config/incus
rm -f /root/incus-node-token.txt
rm -f /usr/local/sbin/cloudnest-node-uninstall /usr/local/sbin/incus-cn-node-uninstall
rm -f /etc/apt/sources.list.d/zabbly-incus-stable.sources /etc/apt/keyrings/zabbly.asc
DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y
hash -r

residuals=()
command -v incus >/dev/null 2>&1 && residuals+=("incus 命令")
ip link show incusbr0 >/dev/null 2>&1 && residuals+=("incusbr0 网桥")
for path in /var/lib/incus /var/cache/incus /var/log/incus /etc/incus; do
  [[ -e $path ]] && residuals+=("$path")
done
if (( ${#residuals[@]} )); then
  printf '以下项目仍有残留：%s\n' "${residuals[*]}" >&2
  exit 1
fi
echo "计算节点、Incus 软件包、数据、网桥、软件源和防火墙规则已清除。"
