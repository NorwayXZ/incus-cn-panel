# Incus 中文管理面板

面向小型服务器和实验环境的 Incus 一键部署项目。安装后可通过中文 Web 页面管理 Incus 系统容器和虚拟机，底层仍使用官方 Incus 服务。

## 当前功能

- 自动安装 Incus 稳定版
- 自动初始化 `dir` 存储池和 NAT 网桥
- 中文 Web 登录和实例概览
- 创建系统容器或虚拟机
- 设置 CPU、内存和磁盘限制
- 启动、停止、重启和删除实例
- 一键卸载面板，默认保留 Incus 实例数据
- `--purge` 二次确认后彻底卸载 Incus 和全部数据

## 系统要求

- Ubuntu 22.04/24.04 或当前 Debian 稳定版
- root 权限
- 至少 1.5 GiB 可用磁盘，实际使用建议 20 GiB 以上
- 容器建议至少 1 GiB 内存；虚拟机建议至少 4 GiB 内存并提供 `/dev/kvm`

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap.sh | sudo bash
```

可通过环境变量指定账号、密码和端口：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap.sh \
  | sudo env PANEL_USER=admin PANEL_PASSWORD='请设置至少10位的强密码' PANEL_PORT=8443 bash
```

安装完成后会显示访问地址和随机密码，同时凭据保存在 root 用户可读的 `/root/incus-cn-panel-credentials.txt`。面板默认使用自签名 HTTPS 证书，首次访问需要在浏览器中确认。

## 一键卸载

只卸载中文面板，保留 Incus 和全部实例：

```bash
sudo incus-cn-panel-uninstall
```

永久删除面板、Incus 和全部实例数据：

```bash
sudo incus-cn-panel-uninstall --purge
```

`--purge` 会要求再次输入 `PURGE`，此操作不可恢复。

## 说明

这是轻量管理面板，不是完整的 VPS 销售系统。它不包含计费、用户自助中心、IP 地址池、工单、滥用控制和自动备份。公网 IPv4 也不会由 Incus 自动产生：没有额外公网 IP 时，实例默认通过 NAT 共享宿主机出口。

生产环境建议为面板绑定域名并在 Caddy 或 Nginx 上配置受信任的 HTTPS 证书，同时限制管理端口的来源 IP。

已有 Caddy 域名时，可参考 [docs/caddy.md](docs/caddy.md) 把面板挂到域名的 `/incus/` 路径。
