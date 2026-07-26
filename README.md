# Incus 中文集群面板

这是一个轻量的 Incus 多节点控制面板。中央服务器只运行中文 Web UI 和 Incus 客户端，其他 VPS 作为计算节点运行 Incus。管理员可以从一个面板接入节点，并在指定节点上创建、启动、停止、重启和删除系统容器或虚拟机。

> 这不是把任意云厂商 VPS 再切成拥有独立公网 IP 的商业 VPS。默认创建的是共享宿主机内核、通过 NAT 出网的系统容器。虚拟机需要计算节点提供 `/dev/kvm`，并且需要更多内存和磁盘。

## 架构

```text
浏览器 -> 中文控制面板 -> Incus 双向 TLS API -> 计算节点 A -> 容器/虚拟机
                                      \----> 计算节点 B -> 容器/虚拟机
```

- 控制端不保存计算节点的 root 密码。
- 节点接入使用 Incus 一次性 Trust Token，接入后由双向 TLS 客户端证书认证。
- 从面板移除节点只会删除控制端连接，不会删除节点或其中的实例。
- 控制端卸载不会操作任何远程节点。

## 当前功能

- 中文响应式 Web 控制台，包含统计概览、宿主机、添加宿主机、切割实例、实例管理和操作日志
- 使用 Trust Token 接入多个 Incus 计算节点
- 显示节点在线状态、架构、负载、CPU、内存、物理磁盘和实例数量
- 在指定节点单个或批量创建系统容器、虚拟机
- 按宿主机剩余内存、存储池空间和 SSH 端口自动计算批量创建上限
- 设置 CPU 核数与使用上限、内存和磁盘；读写 IOPS 与上下行带宽可选择不限制或自定义
- 自动安装 OpenSSH，将宿主机 TCP 端口映射到实例 `22` 端口，并生成 root 登录密码
- 为旧实例补开 SSH，集中查看和复制宿主机地址、端口、账号、密码与连接命令
- 启动、停止、重启和删除实例
- 持久化记录节点接入和实例生命周期操作
- 搜索实例并按运行状态过滤
- 控制端与计算节点分别一键安装、一键卸载

## 设计原则

- 控制面与计算节点分离：Web 服务只负责编排，工作负载始终运行在计算节点。
- 连接凭据最小化：面板不保存节点 root 密码，节点接入后只使用 Incus 双向 TLS。
- 资源参数必须真实落到 Incus 配置，不展示尚未实现的快照、迁移或批量任务按钮。
- 升级保留面板账号、证书和节点信任配置；从控制端移除节点不触碰节点上的实例。
- 当前定位是单管理员私有控制中心，不是带计费和用户自助购买流程的商业 VPS 平台。

## 系统要求

控制端：

- Ubuntu 22.04/24.04 或当前 Debian 稳定版
- root 权限、至少 256 MiB 可用磁盘
- 可通过 TCP 访问各计算节点的 `8443` 端口

计算节点：

- Ubuntu 22.04/24.04 或当前 Debian 稳定版
- root 权限、至少 1.5 GiB 可用磁盘
- 容器建议至少 1 GiB 内存，实际磁盘建议 20 GiB 以上
- 虚拟机建议至少 4 GiB 内存并提供 `/dev/kvm`

## 安装控制端

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap.sh | sudo bash
```

可以指定面板账号、密码和端口：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap.sh \
  | sudo env PANEL_USER=admin PANEL_PASSWORD='请设置至少10位的强密码' PANEL_PORT=8443 bash
```

安装完成后会显示访问地址和随机密码，凭据保存在 `/root/incus-cn-panel-credentials.txt`。面板默认使用自签名 HTTPS 证书；已有 Caddy 域名时可参考 [Caddy 反向代理](docs/caddy.md)。

## 安装计算节点

在每台计算节点执行。建议设置控制端公网 IP，这样脚本在 UFW 已启用时只向控制端放行 `8443`：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap-node.sh \
  | sudo env CONTROLLER_IP=203.0.113.10 TRUST_NAME=incus-cn-panel bash
```

脚本会安装 Incus，初始化 `dir` 存储池和 NAT 网桥，并输出节点地址与一次性 Trust Token。登录控制面板，打开“添加宿主机”，可以将脚本最后输出的节点地址与 Token 两行完整粘贴到凭据框，面板会自动识别地址。成功接入后可以删除节点上的 `/root/incus-node-token.txt`。

批量创建使用名称前缀、起始编号和补零位数生成实例名，例如 `vps-001` 至 `vps-010`。CPU 由 Incus 共享调度，单台配置不能超过宿主机物理核心数；批量上限由剩余内存、default 存储池空间和 SSH 端口数量的最小值决定。服务端会在开始批量任务前重新计算容量，任务中途失败时会尝试清理本批已经创建的实例。

操作日志保存在控制端的 `/var/lib/incus-cn-panel/operations.jsonl`，实例 SSH 凭据保存在权限为 `0600` 的 `/var/lib/incus-cn-panel/credentials.json`。再次运行控制端安装命令会原地升级并保留现有账号、证书、节点连接、凭据和操作日志。

## 卸载

卸载控制端，不触碰任何计算节点或实例：

```bash
sudo incus-cn-panel-uninstall
```

彻底卸载一台计算节点及其全部实例和 Incus 数据：

```bash
sudo incus-cn-node-uninstall
```

节点卸载会要求输入 `PURGE-NODE` 二次确认。该操作不可恢复。若只想断开节点，直接在面板点击“移除”，不要运行节点卸载命令。

## 边界

这个项目目前不包含计费、租户自助中心、IP 地址池、通用端口转发规则、工单、滥用控制、快照编排、自动备份和跨节点迁移。单个与批量创建目前仍在一个 HTTP 请求中同步执行，持久化耗时任务队列属于后续工作。

没有额外公网 IP 时，实例默认通过 NAT 共享宿主机出口。面板会为 Alpine、Debian 和 Ubuntu 镜像自动安装并启动 OpenSSH；其他发行版需要扩展配置脚本。虚拟机创建和自动配置是否可用取决于计算节点的 KVM 支持、Incus Agent、镜像变体和可用资源。
