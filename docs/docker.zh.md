# LemonVPN Docker 版

更新：2026-11-12。本轮为源码修复与静态检查，尚未构建新镜像或进行运行验收。2026-11-11 的 amd64 代理/TUN 冒烟结果属于旧代码；arm64 仍由 CI 构建。

本镜像把共享 Rust 引擎、doona Web UI、nginx 与固定版本 mihomo 内核打进同一个容器：浏览器打开管理界面，局域网设备通过 HTTP / SOCKS5 端口使用代理，配置与订阅落盘到 `/data`。实现方案与取舍见 [Docker 版开发计划](docker-plan.zh.md)。

## 1. 快速开始

```sh
cd docker
cp .env.example .env

# 至少设置管理面和代理面的密码；留空会在首次启动时生成随机密码。
# 随机密码只在首次启动的日志里打印一次，也会写入 ./data。
$EDITOR .env

docker compose up -d
docker logs lemonvpn | grep -E "Web UI|Proxy"
```

- 管理界面：`http://<宿主>:8080/`，HTTP Basic Auth。
- 代理入口：`http://<宿主>:18081`，同时支持 HTTP CONNECT、HTTP 转发、SOCKS5 CONNECT 和用户名密码认证。
- `docker compose` 的 `./data` 相对于 compose 文件所在目录，即 `docker/data`。

### 首次启动的凭据

| 用途 | 用户名 | 密码来源 |
|---|---|---|
| Web UI | `LEMONVPN_UI_USERNAME`，默认 `admin` | `LEMONVPN_UI_PASSWORD` / `_FILE`；留空则复用 `data/ui-password`，不存在时随机生成 |
| 局域网代理 | `LEMONVPN_LAN_USERNAME`，默认 `lemonvpn` | `LEMONVPN_LAN_PASSWORD` / `_FILE`；留空且未允许匿名时随机生成，写入 `data/lan-settings.json` |

随机生成的凭据会在首次启动时打印到容器日志：

```sh
docker logs lemonvpn 2>&1 | grep -E "Generated|Web UI|Proxy"
```

## 2. 组件与架构

```
                        ┌──────────────── container ────────────────┐
浏览器 / 管理端 ──8080──>│ nginx ──静态──> /usr/share/nginx/html       │
                        │   └── /api ──> 127.0.0.1:18080 (引擎 API)   │
                        │                                            │
代理客户端 ───18081────>│ 引擎 LAN 监听 (0.0.0.0:18081, 认证可选)      │
                        │   └── 规则/策略组/链式代理 → 节点            │
                        │        └── mihomo 内核 (协议兼容)           │
                        │                                            │
                        │ /data ← 配置、订阅缓存、LAN/DNS/Geo 设置     │
                        └────────────────────────────────────────────┘
```

进程由 `tini` 作为 PID 1，`entrypoint.sh` 负责预置配置、安装可选的 TUN 服务、拉起引擎、等待健康检查、启动 nginx，并转发终止信号。容器以 root 启动，引擎、nginx 与数据文件都由 `setpriv` 降权到 uid 1000；只有 TUN broker 需要保留 root。

| 端口 | 用途 | 是否对外 |
|---|---|---|
| 8080 | Web UI + `/api` | 是（Basic Auth） |
| 18081 | HTTP / SOCKS5 代理 | 是（默认要求用户名密码） |
| 18080 | 引擎 API / 本机混合入站 | **否**，仅容器内回环 |

关键实现点：

- 引擎主监听默认为 `127.0.0.1:18080`（可由 `LEMONVPN_ENGINE_PORT` 修改），不发布到宿主。管理面统一经 nginx 同源暴露，doona 才能探测到 `api_major: 1` 并用真实运行时数据，而不是回落到内置演示数据。
- nginx 等引擎 `/health` 通过后才启动，避免首屏竞态。
- `/api` 反代关闭缓冲并放宽超时，日志与事件流（SSE）不会卡住。
- 健康检查核对 entrypoint 启动的引擎 PID/实例标识；宿主的其他程序即使也在引擎端口返回 200，也不会被当成本容器引擎。supervisor 每 10 秒检查一次，连续三次失败后执行正常清理并退出，交给 compose 的重启策略恢复；不查询外网或节点。
- 引擎与 nginx 访问日志直接进入 Docker 日志驱动，不再另存无限增长的 `/tmp` 日志；默认 compose 保留 `10m × 3` 的轮转限制。
- nginx 先停止接收请求，再关闭本容器的 TUN、引擎及 broker；子进程退出等待有上限，compose 为清理保留 35 秒。
- 镜像内必须带 mihomo 内核与 Geo 数据；缺少内核会退回原生实现，REALITY、Vision、VMess-WS 等协议不可用。

## 3. 代理使用

```sh
# HTTP 代理（CONNECT）
curl -x http://user:pass@HOST:18081 https://example.com

# SOCKS5（远端解析域名）
curl --socks5-hostname user:pass@HOST:18081 https://example.com
```

代理沿用管理界面里的规则、策略组与链式代理。错误的用户名或密码会被拒绝。

局域网共享支持 HTTP、SOCKS5 TCP 和 UDP ASSOCIATE。UDP 必须先通过同一客户端的认证 TCP 会话建立关联；仅接收关联的客户端数据，关闭 TCP 会话即释放 UDP。入站目前为 IPv4。bridge 模式需同时发布代理端口的 TCP/UDP，并在“局域网共享”中填写宿主 LAN 地址（也可首次部署设置 `LEMONVPN_LAN_ADVERTISED_ADDRESS`），避免向客户端返回容器内部地址。

DNS 页面可配置局域网 DNS 的监听地址、端口与允许网段，支持 TCP/UDP 热更新。host 模式可以使用 `53`；bridge 模式需额外发布对应的 TCP/UDP 端口。启用 TUN 后，监听入口使用内核 Fake-IP 映射；关闭 TUN 时仅提供真实地址解析。DNS 监听不是开放递归服务，访问受允许网段限制。DNS 的 IPv6、嗅探与映射持久化也可在该页设置。

解析池支持顺序回退、全部成员竞速和独立的故障备用池。临时失败会尝试其他上游；NXDOMAIN 是有效响应。备用池最多四级，禁止循环；删除时会列出引用并要求处理关联。

## 4. 管理面安全

- 管理 API 没有独立鉴权，暴露即等于把所有写操作交给对方。容器用 nginx Basic Auth 作为过渡防线，并默认生成随机密码。
- `docker-compose.yml` 默认把 `8080` 映射到宿主所有网卡。若只想本机访问，请改成：

  ```yaml
  ports:
    - "127.0.0.1:8080:8080"
  ```

- **bridge 模式下源 IP 会被 NAT**：经 `-p 18081:18081` 进来的连接，源地址是 Docker 网关（私网），引擎的「仅私网/回环来源」检查不会拦截公网转发。认证与宿主防火墙是唯一防线。
- 容器内不做 TLS。需要 HTTPS 时，用 Caddy / Traefik / Nginx 反代到 `127.0.0.1:8080` 并终止 TLS。
- `/data` 内含凭据，建议权限 `0700`；容器内文件由 uid 1000 写入。
- 控制 API 只接受回环 `Host`；nginx 会把上游 `Host` 改写为引擎地址。直接浏览器跨站写入还受 JSON 请求类型和 CORS 限制。额外反代请指向 8080，保留原始外部 `Host`，不要直接暴露 18080。

## 5. 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `LEMONVPN_UI_USERNAME` | `admin` | Web UI 用户名，不能含 `:` |
| `LEMONVPN_UI_PASSWORD` / `_FILE` | 空 | Web UI 密码；留空自动生成并保存到 `/data/ui-password` |
| `LEMONVPN_LAN_ENABLED` | `1` | 首次启动预置局域网共享开关 |
| `LEMONVPN_LAN_BIND` | `0.0.0.0` | 共享监听地址 |
| `LEMONVPN_LAN_PORT` | `18081` | 共享端口，不能等于引擎端口 |
| `LEMONVPN_LAN_ADVERTISED_ADDRESS` | 空 | UDP 关联返回给客户端的宿主 LAN IPv4 地址；bridge 模式应填写 |
| `LEMONVPN_LAN_USERNAME` | `lemonvpn` | 代理用户名 |
| `LEMONVPN_LAN_PASSWORD` / `_FILE` | 空 | 代理密码；留空且未允许匿名时随机生成 |
| `LEMONVPN_LAN_ALLOW_ANONYMOUS` | `0` | 设为 `1` 才允许无认证代理 |
| `LEMONVPN_LAN_RESEED` | `0` | 设为 `1` 时用环境变量覆盖已有 `lan-settings.json` |
| `LEMONVPN_TUN` | `0` | 设为 `1` 启用 TUN（需 compose.tun/sidecar 的权限） |
| `LEMONVPN_TUN_STRICT` | `1` | TUN 启用失败时容器退出，而不是降级为代理模式 |
| `LEMONVPN_TUN_EXCLUDE_LAN` | `1` | host 网络下把局域网网段保留在物理路由 |
| `LEMONVPN_TUN_GATEWAY` | `0` | 为经 TUN 转发的设备添加专用防火墙放行；需宿主已启用 IPv4 转发 |
| `LEMONVPN_DATA_DIR` | `/data` | 数据目录 |
| `LEMONVPN_ENGINE_PORT` | `18080` | 引擎回环端口，1024～65535，不能为 8080；nginx 与健康检查自动跟随 |
| `TZ` | `UTC` | 日志时区 |

局域网环境变量默认仅用于首次预置，已有 `lan-settings.json` 时以保存值为准。首次设置 `LEMONVPN_LAN_ENABLED=0` 不会开启共享；要覆盖已有设置并关闭共享，同时设置 `LEMONVPN_LAN_RESEED=1`。端口和凭据会按引擎要求在预置前校验。

在 Web UI 修改共享端口会立即改变容器内监听，但 Docker 端口映射不能随 API 热更新：bridge/sidecar 模式还需修改 compose 的映射并重建容器。界面列出的是容器内地址；局域网设备应使用宿主 IP 和映射后的端口。host 网络不需要这一步。

## 6. 数据卷

| 路径 | 内容 |
|---|---|
| `/data/config.dae` | 主配置（节点、规则、策略组） |
| `/data/lan-settings.json` | 局域网共享开关、地址、端口与认证 |
| `/data/dns-settings.json` | Fake-IP / redir-host 等 DNS 设置 |
| `/data/dns-listener.json` | TCP/UDP DNS 监听、端口与允许访问网段 |
| `/data/group-selections.json` | 策略组 TCP/UDP 手动选择与固定状态，重启恢复 |
| `/data/geodata-settings.json` | Geo 数据更新设置 |
| `/data/ui-password` | 自动生成的 Web UI 密码 |
| `/data/compat/` | 普通协议兼容内核的工作目录 |
| `/var/lib/lemonvpn/Service/runtime/` | TUN 内核工作目录与 Fake-IP 映射缓存；TUN compose 通过独立的 `tun-state` 命名卷持久化，root 专用 |

TUN 的两个 compose 文件共用项目内的 `tun-state` 命名卷。启用 DNS 页的“映射持久化”后，正常停止、升级或重建容器会保留映射缓存。该卷独立于 uid 1000 的 `/data`，不把管理员服务的运行配置和控制凭据放进用户可写目录。使用 `docker run` 时也需显式挂载命名卷到 `/var/lib/lemonvpn/Service/runtime`；只挂载 `/data` 不会持久化 TUN 映射。备份或迁移 TUN 状态时需同时保留这两个卷，避免使用会删除命名卷的 `compose down -v`。旧容器已丢失的临时缓存无法补回。

迁移桌面配置：把桌面数据目录中的 `config.dae`、`lan-settings.json`、`dns-settings.json` 等复制到 `docker/data`。注意桌面 `lan-settings.json` 的 `bind_address` 可能是具体网卡地址，容器内建议改为 `0.0.0.0`。

`lan-settings.json` 的 schema 严格（不接受未知字段）：

```json
{"enabled":true,"bind_address":"0.0.0.0","port":18081,
 "authentication":{"username":"u","password":"p"}}
```

## 7. TUN 模式

TUN 会接管流量路由，需要额外权限，因此不在默认 compose 中。提供两种方式：

容器启动时由 broker 按归属清理有标记的旧出口规则；不再按优先级或路由表号批量删除。若仍有 `LemonVPN` 设备，会拒绝接管。若捕获优先级 9000～9010 或表 2022 已被其他程序/旧会话占用，也会报告冲突，不自动删除归属不明的规则。

宿主可运行 `sudo ./docker/tun-cleanup.sh` 清理带有本项目标记的出口/局域网规则。未标记的旧捕获规则仍需管理员先确认归属，再按完整规则处理；该脚本不会再删除所有 9000 规则或所有指向表 2022 的规则。

桌面版服务使用同一判定：若同一网络命名空间中仍有 Docker host-network TUN，桌面版只拒绝启用 TUN，不会结束容器内核或删除其规则；桌面版停止/卸载同样不会触碰外部实例。反向仍建议不要同时运行（见 7.1）。

### 7.1 host 网络（改动宿主路由）

```sh
cd docker
docker compose -f docker-compose.tun.yml up -d
```

- 需要 `NET_ADMIN`、`NET_RAW` 与 `/dev/net/tun`，使用 `network_mode: host`。
- 会修改宿主路由与 DNS；默认把 IPv4/IPv6 局域网网段保留在物理路由（`LEMONVPN_TUN_EXCLUDE_LAN=1`），保证 UI、代理客户端和 SSH 仍可达。
- **不要与桌面版 LemonVPN 的 TUN 模式同时运行**。请在可丢弃的主机上测试，或确保有控制台访问。
- 停止容器会恢复路由与策略规则。

作为其他设备的网关时，额外设置 `LEMONVPN_TUN_GATEWAY=1`，并先在宿主启用 `net.ipv4.ip_forward=1`。镜像只为私有来源经 `LemonVPN` 接口的流量及已建立回程添加带标记的放行规则，避免被 Docker 的默认 FORWARD DROP 拦截；不会把全局策略改为 ACCEPT，也不添加通用 NAT。停止容器会移除这些规则。IPv6 转发还需宿主自行启用对应转发设置。客户端 DNS 指向宿主的 LAN DNS 监听地址；使用 Fake-IP 的客户端必须同时经此 TUN 网关转发。

### 7.2 容器内网络命名空间

```sh
cd docker
docker compose -f docker-compose.sidecar.yml up -d
```

- 只影响该容器的 network namespace，宿主网络不变。
- 其他容器用 `network_mode: "service:lemonvpn"` 共享它的网络。
- 仍需要 `NET_ADMIN` 与 `/dev/net/tun`，但不使用 host 网络。

TUN 由 `lemonvpn-service` 独立服务代跑内核：entrypoint 把它安装到 `/var/lib/lemonvpn/Service/`，以 root 启动，并通过 `/run/lemonvpn-tun.sock` 接受引擎（uid 1000）的受限请求。引擎只通过该 socket 传递固定的桥接参数，不接触代理定义或任意内核配置。

## 8. 从源码构建

```sh
./docker/build.sh -t lemonvpn:local
```

构建参数来自 `pins.env` 的 `DOONA_DESKTOP_REVISION` 和 `app/src-tauri/tauri.conf.json` 的版本号。Dockerfile 是多阶段构建：使用指定的 Node 与 Rust 基础镜像标签，按 Release 流程应用四个 doona 前沿补丁，运行 `app/scripts/prepare.mjs` 产出前端、引擎、内核和 Geo 资源，再复制到 `debian:bookworm-slim` 运行时。

- `NPM_REGISTRY` 可覆盖 npm 源（例如内网镜像）。
- `--platform linux/arm64` 可构建 arm64；在 x86 宿主上会走 QEMU，Rust 编译很慢，推荐原生 arm64 主机或 CI。

## 9. 冒烟测试

```sh
# 代理模式：健康、认证、HTTP/SOCKS5、错误凭据、重启持久化、干净停止
./docker/smoke.sh lemonvpn:local

# TUN 模式：会修改宿主路由，自带 180 秒 watchdog
sudo ./docker/tun-smoke.sh lemonvpn:local
```

TUN 冒烟要求宿主存在 `/dev/net/tun`，并且 `capsh --has-p=cap_net_admin` 通过。

2026-11-11 在 Debian amd64 构建机上的结果：代理模式 7/7 通过，TUN 模式 6/6 通过（TUN 启用、设备与 9000/8890 策略规则、宿主出网、UI/代理仍可达、停止后路由与规则清理）。

## 10. 升级、备份与回滚

```sh
# 备份
cp -a docker/data docker/data.bak-$(date +%Y%m%d)

# 升级
cd docker
docker compose pull
docker compose up -d
```

引擎可能写入数据迁移，不保证旧版本能读取新数据。回滚时需同时恢复镜像版本与 `/data`。

## 11. CI 发布

`.github/workflows/docker.yml` 在推送 `v*` tag（或手动触发并指定 tag）时：

1. 先验证版本 tag 和固定依赖，解析实际提交 SHA；手动输入只作为环境变量/Action 参数传递；
2. amd64 / arm64 在原生 runner 上构建同一个提交，镜像 revision 标签也使用该 SHA；
3. 默认不运行测试；仅在手动触发时明确勾选 `run_smoke` 才运行 amd64 代理冒烟；
4. 两种架构都成功后按不可变 digest 合并 `<version>`，保留 `<version>-amd64`、`<version>-arm64`；合并前检查 tag 是否被移动，若已变更则停止发布；
5. `latest` 单独串行更新，只有仓库当前最高稳定版本 tag 才能更新；预发布和旧版本重建只发布自己的版本标签，不回退 `latest`。两种架构未全部完成时不会生成版本总标签。

拉取：

```sh
docker pull ghcr.io/lemon-casino/lemonvpn:latest
```

## 12. 已知限制

- 局域网代理当前仅支持 IPv4 入站；DNS 监听可绑定 IPv4/IPv6 私有地址并配置允许网段，上游 IPv6 由 DNS 页的 IPv6 开关控制。
- 一个容器一个引擎实例。
- 没有系统代理接管；系统代理开关只存在于桌面端。
- 容器内不管理 TLS 证书。
- host 网络 TUN 是宿主级改动，风险高于容器内模式。
- 首次打开 UI 时若引擎尚未就绪，doona 可能回落到演示数据；本镜像会等健康后再启动 nginx，正常不会发生。若出现，清理浏览器 localStorage 后刷新。

## 13. 故障排查

| 现象 | 排查 |
|---|---|
| 打开 UI 显示演示数据 | 引擎未就绪或 `/api` 被拦截；`docker logs` 看健康日志，确认 nginx 已启动 |
| 401 | Web UI 缺少或错误的 Basic Auth；用 `data/ui-password` 或环境变量里的密码 |
| 407 / 代理认证失败 | 检查 `data/lan-settings.json` 或 `LEMONVPN_LAN_*` |
| `admin_required: TUN 需要先安装管理员服务` | 缺少 `/dev/net/tun`、`CAP_NET_ADMIN`，或 `/var/lib/lemonvpn` 对 uid 1000 不可穿越（已修复，确保使用当前镜像） |
| 端口冲突 | `LEMONVPN_LAN_PORT` 不能等于配置中的引擎端口或 8080；宿主端口被占用时改映射 |
| 引擎 PID 还在但界面无响应 | supervisor 连续三次本机身份健康失败后会清理退出；compose 随后重启。查看 `Local engine health check failed` 日志 |
| 重建后 Fake-IP 映射丢失 | 确认已启用“映射持久化”，且保留 `tun-state` 卷；只挂载 `/data` 不足以保留 TUN 内核缓存 |
| 容器启动即退出 | `docker logs` 查看是否 LAN 凭据或配置校验失败；`lan-settings.json` 必须是严格 JSON |
| LAN 设置改不动 | 已有 `lan-settings.json` 时环境变量不会覆盖，设 `LEMONVPN_LAN_RESEED=1` |
| `another LemonVPN TUN is active` | 宿主或另一容器仍有 `LemonVPN` 设备；先停掉对应实例再启动 TUN |
| TUN 报「物理出口策略路由优先级已用尽」 | 停止 TUN 后执行 `sudo ./docker/tun-cleanup.sh`，仅清理带标记的本项目规则 |
| TUN 报「策略路由槽位已被占用」 | 先停止其他 TUN；检查 `ip -4 rule show` / `ip -6 rule show` 与表 2022，归属不明的旧捕获规则需管理员确认后处理 |

## 2026-11-12 复核范围

本轮为源码审查、Shell 语法检查与 Rust 编译检查；没有执行冒烟、网络连通或安装测试，也没有启动客户端、内核、服务或容器。上文 2026-11-11 的运行结果属于旧代码，不能当作本轮改动的运行验收。
