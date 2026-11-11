# LemonVPN Docker 版开发计划

更新：2026-11-11。状态：**amd64 已实现并完成代理模式与 TUN 模式冒烟验收；arm64 由 CI 构建**。使用说明见 [Docker 版](docker.zh.md)。

## 实施状态（2026-11-11）

与最初的评审稿相比，实际交付多做了容器内 TUN：

- 已构建 `lemonvpn:test`（amd64，含引擎、doona、mihomo、Geo 数据），代理模式冒烟 7/7 通过。
- TUN 模式冒烟 6/6 通过：TUN 启用、设备与 9000/8890 策略规则、宿主出网、UI/代理可达、停止后路由与规则清理。
- TUN 由镜像内的 `lemonvpn-service` 以 standalone broker 运行；entrypoint 把服务安装到 `/var/lib/lemonvpn/Service/`，引擎以 uid 1000 通过 `/run/lemonvpn-tun.sock` 请求。
- 验收中发现并修复：`prepare_lan()` 的 `umask 077` 泄漏，使 `/var/lib/lemonvpn` 变成 0700，uid 1000 无法穿越，引擎误判服务未安装。
- 新增 `docs/docker.zh.md`、`.github/workflows/docker.yml`；arm64 构建与 GHCR 发布尚未实际运行。
- 修复不干净退出后的规则残留：入口脚本在启动时清理 `8750–8799`、`8890`、`9000+` 与 table 2022 的遗留规则；检测到仍存活的 `LemonVPN` 设备时拒绝接管。宿主侧提供 `docker/tun-cleanup.sh`。

本计划基于对现有桌面版引擎（`sidecar-stub/`）、doona 前端和局域网共享实现的只读排查，目标是在不改动引擎主监听绑定（`127.0.0.1`）的前提下，交付可用的 Docker 镜像：浏览器访问 Web UI，局域网设备通过共享端口走 HTTP/SOCKS5 代理，配置与订阅持久化在数据卷中。

## 1. 目标与非目标

### 1.1 目标

1. 一条命令启动：`docker compose up -d` 后可通过 `http://<宿主>:8080` 打开完整 doona 界面，读写真实引擎状态。
2. 对外代理入口使用**局域网共享监听**（默认 `18081`，可配），支持 HTTP CONNECT、HTTP 转发、SOCKS5 CONNECT 与用户名密码认证。
3. 配置、订阅、规则、DNS/Geo 设置、LAN 设置全部落盘到 `/data`，容器重建后保留。
4. 默认安全：管理面默认只绑宿主回环；代理面默认要求认证；无密码时拒绝启动而不是静默开放。
5. 与桌面版共用同一套引擎、同一套前端补丁、同一套固定版本（`pins.env`），不引入第二套协议实现。
6. 支持 `linux/amd64` 与 `linux/arm64`，可由 tag 发布流程自动构建并推送到 GHCR。

### 1.2 非目标（首版明确不做）

- ~~**TUN / 透明网关**~~：原计划首版不做；实际已实现，容器内 TUN 需要 `NET_ADMIN` + `/dev/net/tun`，提供 host 网络与 sidecar 两种 compose。host 模式会改写宿主路由/DNS，默认把局域网网段保留在物理路由。用法与风险见 [Docker 版 §7](docker.zh.md)。
- **UDP 代理**：LAN 共享本身是 TCP-only（无 SOCKS5 UDP ASSOCIATE、无 IPv6 入站），QUIC/游戏/UDP 应用不在首版范围。
- **多实例 / 多租户**：引擎是进程级单实例、固定数据目录，一个容器一个实例。
- **系统代理接管**：浏览器版没有桌面壳能力，`系统代理` 开关只存在于桌面端。
- **Android/iOS 客户端**：不在本计划内。

### 1.3 成功标准（DoD）

- [ ] amd64 与 arm64 镜像均可构建、启动，`GET /api` 返回 `api_major: 1`。
- [ ] 浏览器打开 UI 显示真实运行时数据（不是内置 mock），可完成：添加订阅 → 选节点 → 保存规则。
- [ ] `curl -x http://user:pass@host:18081` 与 `curl --socks5-hostname user:pass@host:18081` 均能出网。
- [ ] 错误/缺失凭据返回 407；未配置认证时容器拒绝启动（除非显式允许匿名）。
- [ ] 删除并重建容器后，配置、订阅、LAN 设置、Geo 数据保留。
- [ ] 非 root 运行；`docker stop` 后无残留进程；`HEALTHCHECK` 正常。
- [ ] 文档、compose、`.env.example`、CI 工作流齐备。

## 2. 设计基线（已做决策）

| 编号 | 决策 | 理由 |
|---|---|---|
| D1 | **单容器**：引擎 + nginx + tini | 两个进程共享回环最简单；无需 `network_mode: service:` 或额外编排 |
| D2 | 引擎主监听固定 `127.0.0.1:18080`，**不 publish** | 该口同时是管理 API，且入站无认证（`runtime.rs:16-17,68`、`README.md` 代理入站段） |
| D3 | 管理面经 nginx 同源暴露：`8080`；代理面走 LAN 监听：`18081` | doona 只在同源探测到 `api_major: 1` 才接入（`doona/src/api/profiles.ts:167,191`） |
| D4 | 数据卷固定 `/data`（`LEMONVPN_DATA_DIR`） | 与桌面数据目录语义一致：`config.dae`、`lan-settings.json` 等 |
| D5 | 镜像内**必须**带 mihomo 内核与 Geo 数据 | 无内核会退回原生实现，缺 REALITY/Vision/VMess-WS 等常用协议（`outbound.rs:40`） |
| D6 | 复用仓库现有构建脚本与固定版本，不复制 SHA256 数值 | `pins.env` 单一来源；`prepare*.mjs` 已含校验与许可证 |
| D7 | 运行时基础镜像 `debian:bookworm-slim`（glibc），非 musl | Rust 产物与 mihomo 均为 glibc；避免 Alpine 兼容风险 |
| D8 | 非 root（uid 1000）运行；`/data` 需该用户可写 | nginx 监听 8080、引擎监听 18080/18081 均 >1024 |
| D9 | 管理面默认只绑宿主 `127.0.0.1`；LAN 模式必须显式开启并配认证 | 引擎 API 无鉴权，暴露即等于把所有写操作交给对方 |
| D10 | 首版不做引擎鉴权改造；用 nginx Basic Auth + 网络绑定作过渡 | 改动最小；长期方案见 9.3 |
| D11 | 镜像发布到 GHCR，tag 与 `v*` 发布对齐，amd64+arm64 | 与现有 Release 流程一致 |

## 3. 架构

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

进程模型：`tini`（PID 1，转发信号、回收僵尸）→ `entrypoint.sh`（预置配置、拉起引擎、健康等待、拉起 nginx、转发终止信号）。

## 4. 交付物与仓库布局

新增（首版）：

```
docker/
  Dockerfile              多阶段构建
  nginx.conf              静态站 + /api 反代 + SSE + 缓存策略
  entrypoint.sh           初始化、健康等待、进程监督
  docker-compose.yml      默认：管理面对局域网开放（要求认证）
  docker-compose.tun.yml  host 网络 TUN
  docker-compose.sidecar.yml 容器内网络命名空间 TUN
  .env.example            环境变量样例
  smoke.sh                镜像冒烟脚本
.dockerignore
docs/docker.zh.md         用户文档（与桌面版文档同风格）
.github/workflows/docker.yml
```

暂不修改（引擎侧改动集中到 Phase 3，且单独提交）：

```
sidecar-stub/crates/engine-core/src/tun.rs       TUN 能力开关
sidecar-stub/crates/engine-core/src/api.rs       /api/v1/tun/set 返回 501
sidecar-stub/src/main.rs                         SIGTERM/SIGINT 优雅退出
```

## 5. 镜像构建设计

### 5.1 阶段划分（首版：单一 builder，便于与 Release 流程完全一致）

```
FROM node:24-bookworm-slim AS node
FROM rust:1.<pinned>-bookworm AS builder
COPY --from=node /usr/local /usr/local        # 复用 node/pnpm，glibc 一致
apt-get install: build-essential git ca-certificates curl
COPY pins.env patches app/scripts app/branding sidecar-stub
git init doona && git fetch --depth 1 <DOONA_DESKTOP_REVISION> && checkout
RUN node app/scripts/prepare.mjs              # 前端 + 引擎 + 内核 + Geo，全部校验
RUN 收集产物到 /out：dist、引擎、kernel、geoip.dat、geosite.dat、许可证

FROM debian:bookworm-slim AS runtime
apt-get install: nginx iproute2 ca-certificates curl tini openssl
useradd -u 1000 -m lemonvpn
COPY --from=builder /out/... 
USER lemonvpn
ENTRYPOINT ["/usr/bin/tini","-g","--"]
CMD ["/usr/local/bin/entrypoint.sh"]
```

- `prepare.mjs` 是现有权威构建入口：会按顺序应用前端补丁（若未应用）、同步品牌、构建 doona、`cargo build --locked --release`、下载并校验 mihomo/Geo、生成许可证清单。
- UI 构建需要 `patches/doona-lemonvpn-desktop.patch` 先行（`prepare.mjs` 会检查 `doona/src/desktop.ts` 是否存在）。Dockerfile 中按 Release 工作流顺序应用 4 个补丁：`desktop → proxy-health → lan-sharing → rules-dns`，再由 `prepare.mjs` 幂等检查。
- 所有下载都走 `pins.env` 的 URL + SHA256；构建日志必须打印实际 commit 与补丁文件名，便于追溯。
- **`lemonvpn-service` 与 `lemonvpn-kernel` 会放进镜像**，但只用于容器内的 standalone TUN broker；桌面版的服务安装流程不适用。

### 5.2 `.dockerignore`（必须，否则上下文 10GB+）

```
.git
doona
honk
.lcode
output
tmp
sidecar-stub/target
sidecar-stub/*.etl
app/node_modules
app/dist
app/src-tauri
node_modules
**/*.log
```

保留：`pins.env`、`patches/`、`app/scripts/`、`app/branding/`、`sidecar-stub/`（除 target）。

### 5.3 多架构与缓存

- 首版：`docker buildx build --platform linux/amd64,linux/arm64`（CI 用原生 runner，避免 QEMU 下 Rust 编译过慢）。
- 优化项（Phase 4）：拆出独立 UI stage，UI 只构建一次，两个架构复用；引擎阶段使用 `--engine-only`。
- 缓存：GHA cache 或 registry cache；builder 的 `target/` 与 pnpm store 分别缓存。
- 基础镜像用 digest 固定；Rust/Node/pnpm 版本写入文件而不是浮动 tag。

### 5.4 版本戳

- `LEMONVPN_VERSION` 构建参数：写入镜像 label；Docker 内 About 页版本取自 doona `package.json`，构建时用 `pnpm pkg set version=<version>` 或在 clone 后改写，避免显示上游 `0.1.0-rc.4`。
- label：`org.opencontainers.image.version/revision/source/licenses`。

## 6. 运行时设计

### 6.1 entrypoint 状态机

```
1. 校验环境变量（见 6.4），必要目录 mkdir -p /data
2. 若 /data/lan-settings.json 不存在且 LEMONVPN_LAN_ENABLED=1 → 原子写入预置设置
3. 若配置了 UI 认证 → 生成 htpasswd（openssl passwd -apr1），供 nginx include
4. 启动引擎（后台，stdout/stderr 直连容器日志）
5. 轮询 http://127.0.0.1:18080/health，最多 30s；失败则打印引擎日志并退出 1
6. （可选）按 LEMONVPN_SUBSCRIPTION_URL 幂等导入订阅并刷新
7. 启动 nginx（daemon off，后台）
8. trap TERM/INT：先 TERM 引擎，再 TERM nginx，等待退出；任一进程意外退出则整体退出非 0
```

**必须等引擎健康后再起 nginx**：doona 首次加载只探测一次同源 `/api`，若此时 502 会回落到内置 mock 并写入 localStorage，用户之后会一直看到演示数据。

### 6.2 nginx 关键配置

| 需求 | 配置 |
|---|---|
| 静态站 | `root /usr/share/nginx/html; try_files $uri $uri/ /index.html;` |
| API 反代 | `location /api { proxy_pass http://127.0.0.1:18080; proxy_http_version 1.1; proxy_set_header Connection ""; }` |
| SSE（日志/事件） | `proxy_buffering off; proxy_cache off; proxy_read_timeout 1h;` |
| 大请求体 | `client_max_body_size 64m`（规则集导入上限 32MB，引擎 JSON 上限 1MB） |
| 缓存 | `index.html`、`sw.js`：`no-store`；`/assets/`：`immutable` 长缓存 |
| 压缩 | `gzip on`（js/css/json/svg/webmanifest） |
| MIME | `application/manifest+json webmanifest` |
| 认证 | 可选 `auth_basic` + htpasswd；对 `/` 与 `/api` 同时生效 |
| 安全头 | `X-Content-Type-Options nosniff`、`Referrer-Policy no-referrer`；CSP 暂不加（doona 首页含内联脚本） |
| 不代理 | 不回源 `/health`（仅容器内使用） |

nginx 以非 root 运行：`pid /tmp/nginx.pid`、临时目录指向 `/tmp`、`listen 8080`、日志写 `/dev/stdout`/`/dev/stderr`。

### 6.3 端口与卷

| 端口 | 用途 | 是否发布 |
|---|---|---|
| 8080 | Web UI + `/api` | 默认 `127.0.0.1:8080:8080`；LAN 模式 `8080:8080` |
| 18081 | 代理（HTTP/SOCKS5 混合） | `18081:18081` |
| 18080 | 引擎 API/本机混合入站 | **永不发布** |

| 卷 | 内容 |
|---|---|
| `/data` | `config.dae`、`lan-settings.json`、`dns-settings.json`、`geodata-settings.json`、provider 缓存、`compat/` 内核运行目录 |

### 6.4 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `LEMONVPN_LAN_ENABLED` | `1` | 首次启动预置共享开关 |
| `LEMONVPN_LAN_BIND` | `0.0.0.0` | 必须是 `0.0.0.0` 或私网 IPv4（引擎校验） |
| `LEMONVPN_LAN_PORT` | `18081` | 不能等于引擎端口 |
| `LEMONVPN_LAN_USERNAME` / `_PASSWORD` | 空 | 首次启动写入；支持 `_FILE` 形式 |
| `LEMONVPN_LAN_ALLOW_ANONYMOUS` | `0` | 无凭据时默认拒绝启动 |
| `LEMONVPN_UI_USERNAME` / `_PASSWORD` | 空 | 启用 nginx Basic Auth |
| `LEMONVPN_SUBSCRIPTION_URL` / `_NAME` | 空 | 可选，首次启动导入订阅（Phase 3） |
| `LEMONVPN_LAN_RESEED` | `0` | `1` 时用环境变量覆盖已有 `lan-settings.json` |
| `TZ` | `UTC` | 日志时间 |

约束：`lan-settings.json` 的 schema 严格（`deny_unknown_fields`），必须是：

```json
{"enabled":true,"bind_address":"0.0.0.0","port":18081,
 "authentication":{"username":"u","password":"p"}}
```

写入采用临时文件 + rename，权限 0600。

### 6.5 健康检查与日志

- `HEALTHCHECK CMD curl -fsS http://127.0.0.1:8080/api || exit 1`（经 nginx，同时验证两段）。
- 引擎 stderr 直接进容器日志；不额外做文件日志轮转（交给 Docker 日志驱动）。
- compose 建议 `logging.options.max-size=10m, max-file=3`。

### 6.6 进程终止

- 首版：`tini -g` + entrypoint trap 转发 SIGTERM；引擎不处理信号会直接退出，状态文件均为原子写，内核子进程随容器销毁。
- Phase 3 给引擎补 SIGTERM handler（`engine.shutdown()` 后退出），做到干净释放。

## 7. 配置、首次启动与升级

1. **空卷首次启动**：引擎写入默认 `config.dae`（直连 + 默认 DNS），LAN 预置后即可作为直连代理使用。
2. **迁移桌面配置**：把桌面数据目录中的 `config.dae`、`lan-settings.json`、`dns-settings.json` 等复制到 `/data`；注意桌面 `lan-settings.json` 的 `bind_address` 可能是具体网卡地址，容器内建议改为 `0.0.0.0`。
3. **备份/恢复**：整个 `/data` 目录；升级前先备份。
4. **升级**：`docker compose pull && docker compose up -d`；引擎可能写迁移，不保证向后兼容旧版本读取新数据，回滚需同时恢复 `/data`。
5. **订阅**：优先在 UI 中操作（与桌面一致）；`LEMONVPN_SUBSCRIPTION_URL` 仅作为可选自动化，必须在导入前检查同名/同 URL 已存在，避免重复。

## 8. 安全设计

### 8.1 威胁模型

| 面 | 暴露后果 | 首版措施 |
|---|---|---|
| 引擎 API（8080） | 任意改配置、删节点、关连接、切模式；无鉴权 | 默认仅宿主回环；LAN 模式强制 Basic Auth + 建议 TLS |
| 代理口（18081） | 被当作开放代理，流量与出口滥用 | 默认强制认证；无认证拒绝启动；宿主防火墙 |
| 内核/Geo 供应链 | 恶意二进制 | 全部按 `pins.env` SHA256 校验；镜像 label 记录 |
| 卷权限 | 凭据文件泄露 | `/data` 0700、文件 0600、非 root |

### 8.2 Docker 网络的两个关键事实（必须写进文档）

1. **bridge 模式下来源 IP 被 NAT**：所有经 `-p 18081:18081` 进来的连接，源地址是 docker 网关（如 `172.17.0.1`，私网），因此引擎 `lan.rs:271` 的「仅私网/回环来源」检查**不会**拦截来自公网的端口转发。**认证与宿主防火墙是唯一防线。**
2. **host 模式保留真实源 IP**：公网来源会被引擎拒绝，但会与宿主端口冲突、且更易误配。首版不推荐。

### 8.3 管理面认证选项

| 方案 | 改动 | 采用 |
|---|---|---|
| nginx Basic Auth（可选开启） | 配置 | 首版 |
| 默认仅绑 `127.0.0.1` + SSH 隧道 | 无 | 首版默认 |
| 引擎实现 password/token 认证（`/api/v1/auth/*`，doona 已有登录页） | Rust 中改 | Phase 5 评估 |

TLS：容器内不做证书管理；文档给出 Caddy/Traefik/Nginx 反代示例，或挂载证书让内置 nginx 终止 TLS（Phase 4 可选）。

### 8.4 发布前安全检查

- [ ] 镜像内无构建工具链、无源码缓存、无 `.git`。
- [ ] 非 root；`/data` 与 `/tmp` 是唯一可写路径（可测 `--read-only`）。
- [ ] 无默认口令；示例中的口令均为占位符。
- [ ] `docker inspect` 确认健康检查、`STOPSIGNAL`、`USER`。
- [ ] 许可证文件齐全（LemonVPN/doona/mihomo/GeoIP/GeoSite）。

## 9. 引擎侧小改动（Phase 3，独立提交）

### 9.1 TUN 能力开关（建议）

问题：带上 mihomo 后 `tun_supported()` 为真（`engine-platform/src/linux.rs:12-21`），UI 会显示 TUN 可开启，容器内点击只会报权限错误。

方案：环境变量 `LEMONVPN_DISABLE_TUN=1` 时：

- `tun.rs::supported()` 直接返回 `false`；
- `capabilities` 的 `tun` 报 `{"available":false}`；
- `POST /api/v1/tun/set` 返回 501 `capability_not_supported`。

镜像默认设置该变量；需要实验 TUN 的用户显式关闭。

### 9.2 信号处理

`sidecar-stub/src/main.rs` 增加 SIGTERM/SIGINT 处理：调用 `engine.shutdown()`，等待内核回收后退出 0。收益：`docker stop` 不依赖强杀，compat 目录与内核进程更干净。

### 9.3 长期：管理 API 鉴权

与 doona 的 `auth.mode=password` 契约对齐（`/api/v1/auth/setup|login|logout`、会话与过期、限速、失败计数、`anonymous_loopback` 保留）。完成后 Docker 管理面可以安全地对局域网开放，不再依赖 Basic Auth。工作量大，单独立项。

## 10. 分阶段实施计划

### Phase 0：准备（0.5 天）

- [ ] 确认本计划第 14 节待定项。
- [ ] 在装有 Docker 的机器或 CI 验证 `docker buildx` 可用。
- [ ] 建分支 `feat/docker`；确认工作区当前未提交的 sidecar 二进制处理方式（见第 13 节 R10）。

### Phase 1：镜像构建（1 天）

- [ ] `.dockerignore`、`docker/Dockerfile`（builder + runtime）。
- [ ] 用 `prepare.mjs` 产出 UI/引擎/内核/Geo，收集到 `/out`。
- [ ] amd64 本地构建成功；记录体积与构建时长。
- [ ] 产物自检：引擎可执行、`lemonvpn-kernel` 版本、Geo 文件 SHA256、UI `index.html` 存在。

**验收**：`docker build` 成功；`docker run --rm <img> /usr/local/bin/lemonvpn-engine` 能在容器内启动并监听回环。

### Phase 2：运行时（1 天）

- [ ] `entrypoint.sh`：目录准备、LAN 预置、引擎启动、`/health` 等待、nginx 启动、信号转发。
- [ ] `nginx.conf`：静态、`/api`、SSE、缓存、MIME、`client_max_body_size`。
- [ ] `docker-compose.yml` + `.env.example`（默认管理面仅回环）。
- [ ] 非 root、健康检查、`stop_grace_period`、日志上限。

**验收**：浏览器 UI 显示真实数据；`curl -x` / `--socks5-hostname` 出网；重建容器数据保留。

### Phase 3：安全与体验（1 天）

- [ ] LAN 无凭据默认拒绝启动；`ALLOW_ANONYMOUS` 才放行。
- [ ] 可选 UI Basic Auth；`LEMONVPN_LAN_RESEED`。
- [ ] 引擎 `LEMONVPN_DISABLE_TUN` + 信号处理（独立 PR/提交，附单元测试）。
- [ ] 首次访问 mock 竞态复测（引擎未就绪时的行为写入文档）。
- [ ] 订阅自动导入（可选，若时间允许）。

**验收**：安全清单 8.4 全绿；TUN 不再误导；`docker stop` 10s 内干净退出。

### Phase 4：测试、文档与发布（1 天）

- [ ] `docker/smoke.sh`：健康、UI、HTTP/SOCKS5 认证、错误凭据、持久化、重启。
- [ ] `docs/docker.zh.md` + README 入口。
- [ ] `.github/workflows/docker.yml`：tag 触发、amd64/arm64、GHCR、manifest、label、SBOM/provenance。
- [ ] 镜像体积与冷启动时间记录。

**验收**：tag 推送后 GHCR 出现 `version`、`version-arm64`、`latest`，`docker pull` 后按文档步骤可用。

### Phase 5（可选，另行评估）

- 引擎 password/token 鉴权；TLS 终止；UDP/透明网关可行性验证；`lemonvpn-engine` 极简无 UI 变体。

总工期估算：**4～5 人日**（首版可用为 Phase 1+2，约 2 天；不含 Docker 环境准备与首次排错）。

## 11. 测试计划

### 11.1 构建

- amd64 与 arm64 各构建一次；校验镜像内二进制架构（`file`/`readelf`）。
- 校验 `pins.env` 中 mihomo/Geo SHA256 与镜像内文件一致。
- 构建两次确认可复现（同一 commit、同一基础镜像 digest）。

### 11.2 运行时（本地 + CI 冒烟）

| 编号 | 用例 | 期望 |
|---|---|---|
| T1 | `GET /api` | 200，`api_major:1` |
| T2 | UI 首屏 | 真实 runtime，非 mock |
| T3 | HTTP 代理 + 正确凭据 | 200，出口 IP 变化 |
| T4 | SOCKS5 + 正确凭据 | 200 |
| T5 | 错误/缺失凭据 | 407 / 认证失败 |
| T6 | `LEMONVPN_LAN_ALLOW_ANONYMOUS=0` 且无密码 | 容器启动失败并给出明确错误 |
| T7 | 大规则集导入（>1MB） | 成功，无 413 |
| T8 | 日志页 / 事件流 | 持续刷新，无缓冲卡死 |
| T9 | 删除重建容器 | 配置/订阅/设置保留 |
| T10 | `docker stop` | 10s 内退出，无残留进程 |
| T11 | 非 root + `--read-only`（挂 `/data`、`/tmp` tmpfs） | 正常启动 |
| T12 | 已知坏配置（`lan-settings.json` 非法） | 引擎仍启动，UI 显示 LAN 错误，可修复 |
| T13 | 端口冲突（LAN 设为 18080） | 明确报错，不崩溃 |
| T14 | 内存限制 256MB 下空载 | 稳定，健康检查通过 |

### 11.3 回归

- 不改引擎默认行为：桌面端测试与构建路径不受影响（`cargo test --manifest-path sidecar-stub/Cargo.toml --workspace --locked`）。
- 若加 `LEMONVPN_DISABLE_TUN`，补 `tun.rs` 单元测试：默认行为不变、变量为 `1` 时 `supported()==false`。

## 12. 文档计划

`docs/docker.zh.md` 目录：

1. 快速开始（compose、端口、首次打开）
2. 组件与架构（引擎/nginx/内核/卷）
3. 代理使用（HTTP/SOCKS5 示例、认证、curl 命令）
4. 管理面安全（默认回环、Basic Auth、TLS 反代、bridge NAT 说明）
5. 环境变量与数据卷
6. 订阅与配置迁移
7. 升级、备份、回滚
8. 已知限制（无 UDP、无 TUN、首访竞态、容器 IP 显示）
9. 故障排查（mock、502、407、端口冲突、权限）
10. 从源码构建与发布

README 顶部增加 Docker 段落并链接本文；compose 内注释解释每个端口与环境变量。

## 13. 风险登记

| 编号 | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | 管理 API 无鉴权 | 高：暴露即被接管 | 默认回环；LAN 模式强制认证；Phase 5 引擎鉴权 |
| R2 | bridge 模式私网检查失效 | 高：误以为只有内网可达 | 文档显著提示；强制认证；建议防火墙 |
| R3 | 首访回落 mock | 中：用户以为功能坏了 | 等引擎健康再起 nginx；文档给出清理 localStorage 的方法 |
| R4 | TUN 入口误导 | 中：点击报错 | Phase 3 加 `LEMONVPN_DISABLE_TUN` |
| R5 | 无 UDP 代理 | 中：部分应用不可用 | 明确非目标；后续评估 TUN/透明网关 |
| R6 | 构建上下文过大 | 中：构建慢/失败 | `.dockerignore` + 只 COPY 必要目录 |
| R7 | arm64 构建慢 | 中：发布超时 | 原生 arm runner；UI 只构建一次 |
| R8 | 上游 doona 补丁漂移 | 中：构建失败 | 固定 commit；构建日志记录；升级时集中处理 |
| R9 | 非 root 卷权限 | 低：启动失败 | 文档 `chown 1000:1000`；entrypoint 给出明确提示 |
| R10 | 工作区已有未提交的 sidecar 二进制 | 低：提交混乱 | Docker 不依赖该文件；单独决定是否提交 |
| R11 | 镜像再分发许可证 | 中：合规 | 镜像内保留 LICENSE；发布页附来源与版本 |
| R12 | 本机无 Docker | 中：无法自测 | 在 CI 或用户机器验证；先跑构建阶段 |

## 14. 待确认决策

1. 管理面默认策略：仅宿主回环（推荐）还是直接对局域网开放并强制 Basic Auth？
2. 是否接受首版**不做 TUN**（推荐），仅代理模式？
3. 目标架构：仅 amd64，还是 amd64 + arm64（推荐）？
4. 是否本轮就接入 GHCR 自动发布，还是先本地可构建？
5. 是否把 `LEMONVPN_DISABLE_TUN` 与 SIGTERM 处理放进本轮（推荐，改动小）？
6. 订阅自动导入（`LEMONVPN_SUBSCRIPTION_URL`）是否需要首版就有？
7. 镜像命名与仓库：`ghcr.io/<owner>/lemonvpn`，还是另有命名？
8. 是否需要同时提供无 UI 的 `lemonvpn-engine` 极简镜像？
