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

- 中文响应式 Web 控制台，采用编辑部式基础设施视觉系统，包含登录页、统计概览、宿主机、添加宿主机、切割实例、实例管理、镜像管理和操作日志
- 使用 Trust Token 接入多个 Incus 计算节点
- 显示节点在线状态、架构、负载、CPU、内存、物理磁盘和实例数量
- 宿主机页面每 5 秒刷新内存、存储池、1 分钟负载，并按实例计数器显示实时 CPU 与上传/下载速率
- 在指定节点单个或批量创建系统容器、虚拟机，按部署目标、规格、网络与流量三步完成配置
- 浏览 `images.linuxcontainers.org` 公共镜像目录，在宿主机预拉取、查看和删除缓存镜像
- 将 Incus 统一镜像 tar 导入指定宿主机，并直接使用本地镜像创建实例
- 按发行版和 LXC/KVM 显示最低、推荐内存与磁盘，支持一键应用推荐规格
- 按宿主机剩余内存、存储池空间和 SSH 端口自动计算批量创建上限
- 按创建数量智能选择稳定系统并均衡 CPU 核心、CPU 使用上限、内存和磁盘；切换系统后按该镜像最低规格重新规划
- 创建前实时检查镜像最低规格、重复名称、SSH/业务端口冲突，并显示本次资源占用与创建后余量
- 设置 CPU 核数与使用上限、内存和磁盘；读写 IOPS 与上下行带宽可选择不限制或自定义
- 创建单台或批量实例时可设置每月双向流量配额；批量支持每台相同配额或输入本批总量后平均分配
- 控制端每分钟累计实例网卡流量，按 Asia/Shanghai 自然月重置，超额后可自动停止实例或仅发送通知
- 单个实例可分配连续业务端口段；批量创建可按总端口池和每台端口数自动切分无冲突区间
- 自动安装 OpenSSH，将宿主机 TCP 端口映射到实例 `22` 端口，并生成 root 登录密码
- 为旧实例补开 SSH，集中查看和复制宿主机地址、端口、账号、密码与连接命令
- 创建、停用、重置和删除普通账户，并将指定实例授权给普通账户
- 实例授权支持 1、2、3、6、12 个月或自定义到期日；到期后服务端立即拒绝访问
- 普通账户只能查看自己的有效授权、SSH 信息，并启动、停止或重启获授权实例
- 后台定时巡检宿主机离线、内存/磁盘/负载过高、镜像查询失败，以及实例状态、IPv4 和异常消失
- 异常通知中心记录首次发生、持续状态和恢复事件；每类异常可关闭、仅在面板显示或同时推送 Telegram
- Telegram Bot Token 加密传输、以 `0600` 权限保存在控制端且不会返回浏览器，支持测试消息和恢复通知
- 启动、停止、重启和删除实例
- 持久化记录节点接入和实例生命周期操作
- 搜索实例并按运行状态过滤
- 在侧边栏检查当前与 GitHub 最新版本，并由管理员一键更新控制面板
- 管理员可从页面右上角修改自己的登录密码；修改后旧密码和全部管理员会话立即失效
- 控制端与计算节点分别一键安装、一键卸载

## 设计原则

- 控制面与计算节点分离：Web 服务只负责编排，工作负载始终运行在计算节点。
- 连接凭据最小化：面板不保存节点 root 密码，节点接入后只使用 Incus 双向 TLS。
- 资源参数必须真实落到 Incus 配置，不展示尚未实现的快照、迁移或批量任务按钮。
- 权限由服务端执行：普通账户不能管理宿主机、镜像、用户、日志，也不能创建或删除实例。
- 升级保留面板账号、证书和节点信任配置；从控制端移除节点不触碰节点上的实例。
- 当前定位是管理员分配实例的私有控制中心，不是带计费和用户自助购买流程的商业 VPS 平台。

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

登录后可点击页面右上角“管理员账户”修改密码。系统会校验当前密码，并以 PBKDF2-SHA256 重新生成盐和哈希；成功后需要使用新密码重新登录。`/root/incus-cn-panel-credentials.txt` 只记录安装时的初始密码，之后不会保存新密码明文。

## 安装计算节点

在每台计算节点执行。建议设置控制端公网 IP，这样脚本在 UFW 已启用时只向控制端放行 `8443`：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/bootstrap-node.sh \
  | sudo env CONTROLLER_IP=203.0.113.10 TRUST_NAME=incus-cn-panel bash
```

脚本会安装 Incus，初始化 `dir` 存储池和 NAT 网桥，并输出节点地址与一次性 Trust Token。登录控制面板，打开“添加宿主机”，可以将脚本最后输出的节点地址与 Token 两行完整粘贴到凭据框，面板会自动识别地址。成功接入后可以删除节点上的 `/root/incus-node-token.txt`。

批量创建使用名称前缀、起始编号和补零位数生成实例名，例如 `vps-001` 至 `vps-010`。CPU 由 Incus 共享调度，单台配置不能超过宿主机物理核心数；批量上限由剩余内存、default 存储池空间和 SSH 端口数量的最小值决定。服务端会在开始批量任务前重新计算容量，任务中途失败时会尝试清理本批已经创建的实例。

智能配置默认将当前可分配内存和磁盘的 90% 按创建数量均分，保留约 10% 供宿主机和运行波动使用；CPU 核心按物理核心公平分配，CPU 使用上限按本批总配额计算。公共镜像优先选择 Debian 12，资源不足时选择 Alpine 3.22。管理员手动切换系统后，系统会保留所选镜像并重新计算规格；如果该镜像的最低规格无法容纳指定数量，页面会保留原数量、禁用创建并显示实际最大数量，不会静默减少实例数量。

操作日志保存在控制端的 `/var/lib/incus-cn-panel/operations.jsonl`，管理员密码哈希保存在 `/var/lib/incus-cn-panel/password.env`，实例 SSH 凭据保存在 `/var/lib/incus-cn-panel/credentials.json`，普通账户、密码哈希和限时授权保存在 `/var/lib/incus-cn-panel/users.json`。异常规则和 Telegram 凭据保存在 `/var/lib/incus-cn-panel/notification-config.json`，通知事件和巡检快照保存在 `/var/lib/incus-cn-panel/notifications.json`，实例月流量计数保存在 `/var/lib/incus-cn-panel/traffic-usage.json`，版本更新状态保存在 `/var/lib/incus-cn-panel/update-status.json`，这些敏感文件权限均为 `0600`。再次运行控制端安装命令会原地升级并保留这些数据。

宿主机实时监控只在管理员打开“宿主机”页面时查询，离开页面后自动停止。内存、存储池和 1 分钟负载来自 Incus 宿主机资源接口；“实例 CPU”“实例上传”“实例下载”由该宿主机上全部实例的累计计数器差分计算，不包含 Incus 服务、SSH 等宿主机系统进程自身的 CPU 与管理流量。

月流量按实例所有非回环网卡的接收与发送字节合计计算。计数器每分钟持久化一次，实例或控制端重启后会继续累计；因此超额处置最多存在一个巡检周期的流量偏差。自动停止模式下，超额实例在提高配额、重置本月用量或进入下一个自然月前不能从面板重新启动。

## 版本更新

管理员可以从侧边栏打开“版本更新”，检查 GitHub `main` 分支中的 `VERSION`，有新版时点击“一键更新”。面板通过独立的 systemd 临时任务下载安装，保留现有账号、证书、节点信任和业务数据；安装完成后面板服务会重启，需要重新登录。升级失败时旧面板继续运行，失败状态记录在 `/var/lib/incus-cn-panel/update-status.json`，详细安装输出仅保存在 root 可读的 `/var/lib/incus-cn-panel/update.log`。

## Telegram 通知

1. 在 Telegram 的 `@BotFather` 创建机器人并取得 Bot Token。
2. 先向机器人发送一条消息，再通过 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查看 `chat.id`；群组和频道通常是负数 ID，频道也可填写 `@channel`。
3. 在面板“异常通知”页面填写 Token 和 Chat ID，启用 Telegram 后点击“发送测试”。

控制端需要能够通过 HTTPS 访问 `api.telegram.org:443`。同一异常只在首次出现时发送一次；异常持续期间不会重复刷屏，恢复后按配置发送一条恢复消息。

## 卸载

卸载控制端，不触碰任何计算节点或实例：

```bash
sudo incus-cn-panel-uninstall
```

彻底卸载一台计算节点及其全部实例和 Incus 数据：

```bash
sudo incus-cn-node-uninstall
```

如果节点安装中途失败、尚未生成上述卸载命令，可以直接下载同一份清理脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/incus-cn-panel/main/uninstall-node.sh \
  -o /tmp/uninstall-incus-node.sh
sudo bash /tmp/uninstall-incus-node.sh
```

节点卸载会要求输入 `PURGE-NODE` 二次确认。该操作不可恢复。若只想断开节点，直接在面板点击“移除”，不要运行节点卸载命令。

## 边界

这个项目目前不包含计费、租户自助中心、IP 地址池、通用端口转发规则、工单、滥用控制、快照编排、自动备份和跨节点迁移。单个与批量创建目前仍在一个 HTTP 请求中同步执行，持久化耗时任务队列属于后续工作。

没有额外公网 IP 时，实例默认通过 NAT 共享宿主机出口。公共目录使用 Incus 默认的 [`images:` simplestreams 服务](https://images.linuxcontainers.org/)，当前提供 Alpine、Debian、Ubuntu、AlmaLinux 和 Rocky Linux 的精选入口；首次创建会自动下载并缓存在目标宿主机。面板会通过 `apk`、`apt`、`dnf` 或 `yum` 自动安装并启动 OpenSSH。

界面中的最低与推荐规格是面向通用公共镜像和 SSH 管理的保守运行基线，不是镜像压缩包大小。自制的极简镜像可能用更少资源，但后端仍会执行当前基线校验。虚拟机创建和自动配置是否可用取决于计算节点的 KVM 支持、Incus Agent、镜像变体和可用资源。
