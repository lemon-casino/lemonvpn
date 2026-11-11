# LemonVPN Docker 版

更新：2026-11-11。状态：amd64 镜像已构建并完成代理模式与 TUN 模式冒烟验收；arm64 由 CI 构建，尚未在本机验收。

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

- 引擎主监听固定为 `127.0.0.1:18080`，不发布到宿主。管理面统一经 nginx 同源暴露，doona 才能探测到 `api_major: 1` 并用真实运行时数据，而不是回落到内置演示数据。
- nginx 等引擎 `/health` 通过后才启动，避免首屏竞态。
- `/api` 反代关闭缓冲并放宽超时，日志与事件流（SSE）不会卡住。
- 镜像内必须带 mihomo 内核与 Geo 数据；缺少内核会退回原生实现，REALITY、Vision、VMess-WS 等协议不可用。

## 3. 代理使用

```sh
# HTTP 代理（CONNECT）
curl -x http://user:pass@HOST:18081 https://example.com

# SOCKS5（远端解析域名）
curl --socks5-hostname user:pass@HOST:18081 https://example.com
```

代理沿用管理界面里的规则、策略组与链式代理。错误的用户名或密码会被拒绝。

局域网共享本身是 **TCP-only**：没有 SOCKS5 UDP ASSOCIATE，也没有 IPv6 入站，QUIC、游戏和依赖 UDP 的应用不在支持范围内。

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

## 5. 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `LEMONVPN_UI_USERNAME` | `admin` | Web UI 用户名，不能含 `:` |
| `LEMONVPN_UI_PASSWORD` / `_FILE` | 空 | Web UI 密码；留空自动生成并保存到 `/data/ui-password` |
| `LEMONVPN_LAN_ENABLED` | `1` | 首次启动预置局域网共享开关 |
| `LEMONVPN_LAN_BIND` | `0.0.0.0` | 共享监听地址 |
| `LEMONVPN_LAN_PORT` | `18081` | 共享端口，不能等于引擎端口 |
| `LEMONVPN_LAN_USERNAME` | `lemonvpn` | 代理用户名 |
| `LEMONVPN_LAN_PASSWORD` / `_FILE` | 空 | 代理密码；留空且未允许匿名时随机生成 |
| `LEMONVPN_LAN_ALLOW_ANONYMOUS` | `0` | 设为 `1` 才允许无认证代理 |
| `LEMONVPN_LAN_RESEED` | `0` | 设为 `1` 时用环境变量覆盖已有 `lan-settings.json` |
| `LEMONVPN_TUN` | `0` | 设为 `1` 启用 TUN（需 compose.tun/sidecar 的权限） |
| `LEMONVPN_TUN_STRICT` | `1` | TUN 启用失败时容器退出，而不是降级为代理模式 |
| `LEMONVPN_TUN_EXCLUDE_LAN` | `1` | host 网络下把局域网网段保留在物理路由 |
| `LEMONVPN_DATA_DIR` | `/data` | 数据目录 |
| `LEMONVPN_ENGINE_PORT` | `18080` | 引擎回环端口 |
| `TZ` | `UTC` | 日志时区 |

`LEMONVPN_LAN_ENABLED=0` 时不会创建 `lan-settings.json`，代理端口不监听。

## 6. 数据卷

| 路径 | 内容 |
|---|---|
| `/data/config.dae` | 主配置（节点、规则、策略组） |
| `/data/lan-settings.json` | 局域网共享开关、地址、端口与认证 |
| `/data/dns-settings.json` | Fake-IP / redir-host 等 DNS 设置 |
| `/data/geodata-settings.json` | Geo 数据更新设置 |
| `/data/ui-password` | 自动生成的 Web UI 密码 |
| `/data/compat/` | mihomo 内核运行目录 |

迁移桌面配置：把桌面数据目录中的 `config.dae`、`lan-settings.json`、`dns-settings.json` 等复制到 `docker/data`。注意桌面 `lan-settings.json` 的 `bind_address` 可能是具体网卡地址，容器内建议改为 `0.0.0.0`。

`lan-settings.json` 的 schema 严格（不接受未知字段）：

```json
{"enabled":true,"bind_address":"0.0.0.0","port":18081,
 "authentication":{"username":"u","password":"p"}}
```

## 7. TUN 模式

TUN 会接管流量路由，需要额外权限，因此不在默认 compose 中。提供两种方式：

### 7.1 host 网络（改动宿主路由）

```sh
cd docker
docker compose -f docker-compose.tun.yml up -d
```

- 需要 `NET_ADMIN`、`NET_RAW` 与 `/dev/net/tun`，使用 `network_mode: host`。
- 会修改宿主路由与 DNS；默认把局域网网段保留在物理路由（`LEMONVPN_TUN_EXCLUDE_LAN=1`），保证 UI、代理客户端和 SSH 仍可达。
- **不要与桌面版 LemonVPN 的 TUN 模式同时运行**。请在可丢弃的主机上测试，或确保有控制台访问。
- 停止容器会恢复路由与策略规则。

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
./docker/build.sh -t lemonvpn:local .
```

构建参数来自 `pins.env` 的 `DOONA_DESKTOP_REVISION` 和 `app/src-tauri/tauri.conf.json` 的版本号。Dockerfile 是多阶段构建：固定 Node 与 Rust 基础镜像，按 Release 流程应用四个 doona 前沿补丁，运行 `app/scripts/prepare.mjs` 产出前端、引擎、内核和 Geo 资源，再复制到 `debian:bookworm-slim` 运行时。

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

1. 在原生 amd64 / arm64 runner 上分别构建镜像；
2. amd64 构建后运行代理模式冒烟测试；
3. 推送 per-arch 镜像到 GHCR；
4. 合并多架构 manifest，生成 `<version>`、`<version>-amd64`、`<version>-arm64` 与 `latest` 标签。

拉取：

```sh
docker pull ghcr.io/lemon-casino/lemonvpn:latest
```

## 12. 已知限制

- 局域网共享是 TCP-only，不支持 UDP 代理。
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
| 端口冲突 | `LEMONVPN_LAN_PORT` 不能等于 18080/8080；宿主端口被占用时改映射 |
| 容器启动即退出 | `docker logs` 查看是否 LAN 凭据或配置校验失败；`lan-settings.json` 必须是严格 JSON |
| LAN 设置改不动 | 已有 `lan-settings.json` 时环境变量不会覆盖，设 `LEMONVPN_LAN_RESEED=1` |
