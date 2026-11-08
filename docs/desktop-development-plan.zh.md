# LemonVPN 桌面端开发方案

> 0.1.3：已补入 Windows x64 的双栈 TUN/UDP、固定协议兼容内核、开机自启和按需 TUN 服务；按用户要求只构建，不执行测试、不替换运行中的软件。下文为历史规划，[当前实现与限制](windows-0.1.3.zh.md) 优先。正式发布和 ARM64 继续延后。

> 实现更新（2026-11-06）：本文保留初始规划。当前已拆出共享引擎库和平台层，桌面继续使用 sidecar；移动端预留库宿主接口。实际代码布局、已实现范围与限制见 [共享引擎与平台适配层](engine-architecture.zh.md)。

> 优先级调整（2026-11-06）：先稳定本机 Windows x64。当前工作集中于重复启动、代理/路由恢复、引擎异常退出、网络变化与本地回归测试；正式发布、签名/更新分发和 Windows ARM64 验收延后。完整 UDP、IPv6 和尚未实现的协议扩展仍为后续功能，不能算作本轮已完成。

- 版本:v0.2(架构决策已敲定,细节继续迭代)
- 日期:2026-11-01
- 依据代码:doona `0.1.0-rc.4`(honk `pins.env` 固定修订 `58dfe2e2`)、honk `main` 分支(引用处已对当前代码树核对)
- 决策状态:**D1–D4、D8 已敲定,许可证路线已确认开源**(2026-11-01);D5–D7 开放讨论,不阻塞 M0 启动
- 远程仓库:<https://github.com/lemon-casino/lemonvpn>(开源)

---

## 1. 目标与非目标

**目标**

1. 把 honk(代理引擎)与 doona(Web 界面)打包成一个跨平台桌面应用,安装即用,面向非技术用户;同时保留给高级用户的完整引擎能力。
2. 多平台:Windows / macOS / Linux;多架构:x86_64 + aarch64。
3. 可持续迭代:壳(shell)、引擎(honk-core)、界面(doona)三者版本解耦,可独立升级;升级有兼容性矩阵与迁移说明。
4. 复用上游:不产生平行实现;对 honk / doona 的改动尽量以可回馈上游 PR 的形态进行。

**非目标(初版)**

- iOS / Android(未来可复用同一引擎,通过 Network Extension / VpnService 接入,本文不展开)
- 账号体系、商业订阅、集中管理后台(注意与 GPL 授权的联动,见 §10)

## 2. 现状盘点(来自当前代码树的事实)

| # | 事实 | 对桌面端的意义 |
|---|---|---|
| F1 | honk-core 是"库 + 二进制"结构;`ebpf` 是可选 feature,默认构建用 `MockEbpfBackend`,`--mock-ebpf` 是官方非特权开发路径 | 引擎已存在"数据面后端可替换"的接缝,桌面端数据面可以挂在同一位置,而非侵入改造 |
| F2 | honk 已有 `native-api`(axum 0.8,认证/会话/SSE/WS 流、限额齐全)和 `native-ui`(把固定版本的 doona 标准版与 lite 版资产直接内嵌进二进制,`pins.env` 固定 DOONA_REVISION) | doona 已经是"嵌进 honk"的形态;桌面壳可以直接加载这套资产,UI 侧零改动 |
| F3 | doona 是纯静态 React SPA(openapi-fetch 调 native API),与引擎之间只有 loopback HTTP 一种耦合 | 引擎与 UI 天然可以分属两个进程甚至两台机器;桌面化不需要改它们的通信方式 |
| F4 | honk CI 已用 zig cc 交叉编译 x86_64/aarch64 × gnu/musl,BoringSSL 从源码构建,eBPF 对象单独构建 | Linux 侧交叉编译基建可直接复用;但 release 矩阵目前**只有 Linux**,Windows/macOS 的 BoringSSL 工具链需要新建并验证 |
| F5 | honk 数据面 = Linux eBPF(TC 钩子)+ NFQUEUE 320 + 自有 nftables 表;TUN 目前只出现在测试场景,不是入站路径 | Windows/macOS 完全没有数据面;这是桌面端**最大的工程缺口** |
| F6 | honk 没有本地 HTTP/SOCKS 入站(流量由 eBPF 直接注入),路由决策与出站(honk-outbound)与入站方式无关 | 需要新增 mixed 入站;但路由/出站层可以直接复用 |
| F7 | doona 自带 e2e(chromium + webkit)、a11y(axe)、i18n 检查、体积预算等完整前端质量门 | Linux 上 Tauri 用 webkitgtk,doona 已经在 webkit 下做过 e2e,风险可控 |
| F8 | honk 是 experimental alpha,内部有严格的 pin 文化(pins.env 对每个外部产物固定 SHA256)与迁移文档惯例(`doc/migration/<tag>.md`) | 桌面端应沿用同一 pin + 契约 + 迁移文档的迭代纪律 |

## 3. 总体架构

### 3.1 推荐形态(组件图)

```
┌─────────────────────────────────────────────────┐
│ 桌面壳(Tauri 2,非特权进程)                     │
│  · WebView: doona UI(加载 honk 内嵌资产)       │
│  · 系统托盘 / 主窗口 / 开机自启 / 自动更新        │
│  · 引擎进程生命周期管理(启动/停止/崩溃重启)      │
│  · Tauri commands:桌面专属操作(代理开关等)      │
└──────────────┬──────────────────────────────────┘
               │ HTTP/WS over 127.0.0.1
               │ (与浏览器版 doona 完全相同的 native API 契约)
┌──────────────▼──────────────────────────────────┐
│ honk-core 引擎进程(sidecar,独立二进制)          │
│  · native-api + native-ui(现有能力,零改动)     │
│  · 数据面按平台选择(见 §5):                     │
│      Linux    : eBPF(TC)/ NFQUEUE(现有路径)   │
│      全平台    : TUN + smoltcp(新增)            │
│      全平台    : mixed 本地入站 HTTP/SOCKS(新增) │
└──────────────┬──────────────────────────────────┘
               │ 特权操作(创建 TUN / 装路由 / 改系统代理)
┌──────────────▼──────────────────────────────────┐
│ 特权助手(按平台:Windows 服务 / launchd daemon  │
│           / systemd + polkit;懒安装,按需启用)   │
└─────────────────────────────────────────────────┘
```

### 3.2 D1:引擎进程模型 ✅ 已敲定:B(独立进程 sidecar)

| 方案 | 说明 | 评价 |
|---|---|---|
| A. 引擎作为库编进壳进程 | Tauri 后端直接依赖 honk-core,单进程 | 省一个进程;但壳被拖成特权进程(违背最小特权)、引擎崩溃 = 整个应用崩溃、honk 的 mimalloc hook / Linux main.rs 假设都要改造 |
| **B. 引擎独立进程(sidecar)(推荐)** | 壳管理官方 honk-core 二进制的生命周期,loopback native API 通信 | 崩溃隔离(引擎直面不可信网络流量)、特权分离、honk/doona **零改动**、引擎可独立替换与灰度 |

推荐 B。F3 已保证通信方式现成,这是改动量最小、且把工程预算留给数据面的路线。

### 3.3 D2:壳框架 ✅ 已敲定:Tauri 2

| 方案 | 评价 |
|---|---|
| **Tauri 2(推荐)** | Rust 后端与 honk 同语言同工具链;系统 WebView 体积小;官方插件覆盖托盘/自启/更新器/深链;sidecar 支持是内置能力 |
| Electron | 生态最成熟,但打包 ~100MB+ Chromium,Node 与 Rust 引擎跨界;仅当 Tauri 在目标平台出现不可解问题时才值得回退 |
| 其他(Wails/Slint/纯原生) | 与现有 Rust+React 栈不匹配,不考虑 |

风险注记:三平台 WebView(WebView2 / WKWebView / webkitgtk)差异由 doona 的 react-aria-components 兜底(它本来就是跨浏览器 a11y 设计),且 doona e2e 已覆盖 webkit(F7)。

## 4. 平台与架构矩阵(目标状态)

| 平台 | 架构 | 数据面 | 特权机制 | 分发与签名 |
|---|---|---|---|---|
| Windows 10 1809+ / 11 | x64, aarch64 | TUN(wintun);系统代理(无 TUN 模式) | 可选安装 Windows 服务;系统代理模式**无需提权**(仅 HKCU) | NSIS/MSI + Authenticode(或 Azure Trusted Signing) |
| macOS 13+ | x64, aarch64(通用二进制可选) | utun + smoltcp;系统代理 | SMAppService launchd daemon | .app/.dmg + Developer ID + 公证(硬前提) |
| Linux(内核 ≥ honk 现有地板) | x64, aarch64 | eBPF(TC)原生路径;无权限时回退 TUN | systemd 系统服务 / polkit 授权;或 cap 文件 | AppImage / deb / rpm(nfpm 已在工具链中) |

通用二进制(macOS lipo)与 Windows ARM64 的 BoringSSL 构建列入 M0 spike 验证项。

## 5. 数据面设计(最大工程项)

### 5.1 抽象原则

在 honk-core 引入入站/数据面抽象:**拦截层产出"连接描述"(五元组 + 进程信息可得性 + 原始目标)→ 现有路由决策 → honk-outbound 出站**。现有 eBPF 路径实现同一 trait,Linux 行为零变化;`MockEbpfBackend`(F1)证明这条接缝已被上游接受。

### 5.2 需要新增的三个入站

1. **mixed 本地入站**(HTTP CONNECT + SOCKS5,含 UDP ASSOCIATE)——中等工程量。系统代理模式的流量入口;TUN 模式下也用于承载壳自身与浏览器显式代理流量。
2. **TUN 入站**——大工程量,分平台:
   - 设备层:`tun` crate 系(Windows=wintun 驱动随安装包分发;macOS=utun;Linux=/dev/net/tun)。
   - IP 栈:smoltcp 用户态终结 TCP(等价 sing-box 的 gvisor 模式),UDP 直接按会话中继;需要 UDP NAT 会话管理(QUIC / Hysteria2 长连接、NAT 重绑定)。
   - 路由与防环路:TUN 模式必须排除引擎自身出站流量(Windows:出站 socket 绑定物理接口;macOS:绑定接口 + 排除路由;Linux eBPF 路径已天然处理)。
3. **系统代理配置器**(严格说不是入站,是配套):Windows 写 HKCU + WinINet 刷新;macOS 由 daemon 调 `networksetup`;Linux GNOME/KDE 各自的 gsettings/kwriteconfig。随安装/卸载清理。

### 5.3 分阶段(与里程碑挂钩)✅ D4 已敲定:系统代理先行(P1→P2→P3)

| 阶段 | 内容 | 产出 |
|---|---|---|
| P1 | mixed 入站 + 系统代理 | Windows/macOS 可用的第一版(显式代理,覆盖浏览器与遵守系统代理的应用) |
| P2 | TUN + smoltcp + 特权助手 | 全局模式,完整 VPN 体验(覆盖不遵守系统代理的程序、游戏等) |
| P3 | Linux 接入桌面壳 | eBPF 原生路径(已存在)+ polkit;Linux 体验反超 P1/P2 |

**备选路线(供讨论)**:Windows/macOS 永远只做系统代理(工程量约减半,但"全局"场景缺失);WFP/LSP 透明代理(开发量与驱动签名成本极高,不建议);移植 gvisor(Rust 无官方绑定,不现实)。

## 6. 特权与安全模型

- **原则**:壳永远非特权;特权只存在于引擎进程(必要时)或独立助手;所有本地 IPC 鉴权;沿用 honk 的 pin/SHA256 文化分发一切二进制。
- **Windows**:TUN 需要的服务按需安装(安装包内预置,UAC 授权一次);系统代理模式全程无提权。服务与壳走本机命名管道 + 随机 token。
- **macOS**:SMAppService 注册 launchd daemon(持 utun、改系统代理);Developer ID 签名 + 公证是分发硬前提;未来若做系统级透明代理(Network Extension)再评估 entitlement。
- **Linux**:eBPF 路径需要引擎以 root 服务运行或授予 `cap_net_admin,cap_net_raw`;polkit 提供用户确认。
- **native API(桌面模式)**:仅绑 `127.0.0.1` 随机端口;认证沿用现有 auth.rs 会话体系。**D5**:认证方式二选一——(a) 壳持随机生成密码自动登录,零引擎改动;(b) 引擎新增"loopback 受信"桌面模式(小改动,体验更干净)。
- **更新链**:安装包与更新 manifest 双签名;更新器校验签名后才落盘。

## 7. doona 集成与桌面增强

- **阶段 1(零改动)**:WebView 直接加载 honk `ui: embedded` 内嵌资产,指向本机 native-api 端口,壳自动完成认证。浏览器版 doona 与桌面版 UI 同源同版本。
- **阶段 2(小改动)**:doona 增加"桌面模式"探测,出现桌面专属设置页(系统代理开关、TUN 开关、开机自启、检查更新)。**D6**:桥接方式二选一——
  - (a) native API 新增桌面控制端点:壳把端点反代到自身,doona 仍只讲一个 API;
  - (b) Tauri JS bridge(`window.__LEMON_DESKTOP__` 注入,doona 检测后走 invoke):更直接,但 doona 需要双路径代码。
  - 倾向 (a):保持 doona "纯 HTTP 客户端"的现有架构假设(F3),浏览器演示版也能复用同一套页面。
- **阶段 3**:托盘快捷菜单、连接通知、崩溃气泡由壳实现,doona 不感知。

## 8. 仓库、版本与迭代策略

### 8.1 D3:仓库策略 ✅ 已敲定:独立仓库 `lemonvpn`(github.com/lemon-casino/lemonvpn),pin 锁定双上游

- **已敲定(2026-11-01)**:仓库已在 <https://github.com/lemon-casino/lemonvpn> 创建,承载桌面壳 + 打包 + 桌面 CI,以 pin 锁定两个上游:honk-core 走 cargo git rev pin 或 CI 下载 release 产物(sidecar 形态用后者);doona 沿用 `pins.env` 的 DOONA_VERSION/REVISION/SHA256 机制(honk 的 `ci/fetch-doona.sh` 可直接搬)。
- 反对 monorepo 合并:honk/doona 在 daeuniverse 组织有独立历史、CI 与发版节奏,合并是一次性大成本且切断回馈上游的路径。
- 桌面仓库对 honk 的**任何必要修改**:先评估能否以 PR 回馈上游;短期等不及的用桌面仓库内的小 patch 集(记录在 `patches/`,每次升级 rebase)。

### 8.2 版本与兼容矩阵

- 桌面端独立 semver;「关于」页展示三件套版本(desktop / honk-core / doona)与构建元数据。
- native API 已有 OpenAPI 契约(doona `gen:api`);桌面发布锁定 honk↔doona 组合,升级时按契约增量适配;沿用 doona 的 feature-requirements 文档说明"哪个后端版本起可用"。
- honk 仍是 experimental alpha:桌面版随 honk 破坏性变更升 minor,并在 release note 链接 honk 的 `doc/migration/<tag>.md`。

### 8.3 更新通道与自动更新

- 通道:alpha / beta / stable,与 honk 的 experimental 现状对齐,初版全公开并诚实标注。
- **D7**:更新 manifest 托管位置(GitHub Pages / Cloudflare R2 / 自建)。Tauri updater 支持 minisign 签名 manifest + 增量更新;中国网络可达性(若适用)决定是否需要镜像策略。

## 9. CI/CD 与分发

- **矩阵**:`windows-latest`(x64 + aarch64 交叉)、`macos-14`(arm64 原生;`macos-13` x64 或直接通用二进制)、`ubuntu-24.04`(x64 原生 + aarch64 用 honk 现有 zig cc 流程)。
- **BoringSSL**:Linux 沿用现有 zigcc 封装;Windows 需 MSVC + cmake + nasm(ASM);macOS 用 Xcode 工具链。全部走 sccache/缓存,key 含 boring 版本与目标三元组。
- **发布流**:tag → 三平台矩阵构建(引擎 sidecar + 壳 + doona 资产)→ 打包 → 签名/公证 → 更新 manifest → GitHub Release。
- **产物**:`.exe`(NSIS)/ `.msi`、`.dmg`、`AppImage`/`deb`/`rpm`;命名对齐 honk 现有 `honk-core-<ver>-<target>` 风格。
- **质量门**:桌面仓库的 CI 复用 doona `pnpm check` 全家桶(typecheck/lint/i18n/format/test/check:gen)做 UI 回归;引擎跑 honk `cargo test`;每平台产物做冒烟安装测试。

## 10. 许可证 ✅ 已敲定(2026-11-01):开源,GPL-3.0-only

honk 与 doona 均为 **GPL-3.0-only**。桌面应用作为二者的组合作品,**分发时必须整体 GPL-3.0 并提供对应源码**(含 honk-core 的 patch 与构建脚本)。项目确认走开源路线:

- 本仓库以 GPL-3.0-only 起步,LICENSE 随初始提交落地。
- 发布检查单固定包含:完整对应源码(含 `patches/` 与构建脚本)、上游版权与许可声明(对齐 doona 的 REUSE.toml / NOTICE 惯例)。
- 未来若引入闭源组件(如更新服务后台),需与上游协商或做严格的进程/IPC 隔离并逐案评估;在拿出明确结论前,默认一切随仓库开源。

## 11. 里程碑

| 里程碑 | 内容 | 出口标准 |
|---|---|---|
| **M0 技术验证**(1–2 周) | ① honk-core 无 ebpf 构建在 Windows/macOS 本机跑通(BoringSSL 工具链验证);② mixed 入站 POC;③ Tauri 壳加载 doona 内嵌 UI + 引擎生命周期托管;④ Windows ARM64 / macOS 通用二进制可行性结论 | 三平台各有一台真机能"壳+引擎+UI"跑通显式代理 |
| **M1 Alpha(系统代理版)** | mixed 入站完成 + 系统代理配置器 + 托盘 + 引擎日志页打通;未签名内部分发 | 团队日常可用;崩溃率与重启恢复可接受 |
| **M2 Beta(TUN 版)** | smoltcp TUN + UDP NAT + 防环路 + Windows 服务/macOS daemon + 签名与公证;大流量基准 | 全局模式稳定;吞吐达到可发布水平(以 honk bench 文化出数) |
| **M3 Linux 全功能** | eBPF 原生路径接入壳 + polkit + AppImage/deb/rpm | Linux 体验 ≥ Windows/macOS |
| **M4 1.0** | 自动更新 + 更新通道 + 全平台稳定发布 + 文档站(桌面章节并入 doona 文档站风格) | 三平台公开下载,更新链路闭环 |

## 12. 测试策略(沿用上游文化)

- 引擎:honk 现有 `cargo test` / criterion 基准 / netns e2e 不动;新增 mixed 与 TUN 入站的单元 + 集成测试(含 UDP 会话、防环路的回归)。
- UI:doona 现有 vitest + playwright(a11y/keyboard/mobile)继续作为质量门;桌面壳用 WebDriver(Tauri 官方)补窗口/托盘级 e2e。
- 打包:CI 内每平台安装→启动→本机代理自检(访问一个 echo 端点)的冒烟测试。
- 契约:OpenAPI diff 检查进 CI,契约破坏必须显式升级版本号。

## 13. 风险登记

| 风险 | 影响 | 缓解 |
|---|---|---|
| BoringSSL 在 Windows(尤其 aarch64)/macOS 的构建问题 | 阻塞 M0 | M0 首项验证;备选:rustls 出站降级路径评估(honk 目前仅 rustls 用于回环测试与下载器,不可直接替代 REALITY 等) |
| smoltcp 吞吐与 UDP NAT 复杂度 | M2 延期 | 早期基准;QUIC/Hysteria2 真实流量回归;必要时先发系统代理版 |
| macOS 公证/entitlement 政策变化 | 分发受阻 | M2 起就申请 Developer ID 并走通公证流水线 |
| honk alpha 的破坏性变更 | 迭代成本 | 严格 pin + patch 集最小化 + 契约测试 |
| webkitgtk(Linux)与 doona 兼容 | Linux UI 体验 | doona e2e 已含 webkit;发现问题按上游惯例修 doona |
| GPL 合规被忽视(尤其未来商业化) | 法律风险 | §10 前置为决策项;发布检查单加入源码披露步骤 |
| 中国网络环境更新源不可达(若适用) | 用户无法更新 | D7 决定托管与镜像策略 |

## 14. 决策点汇总(待讨论后定稿)

| # | 决策 | 选项 | 状态 |
|---|---|---|---|
| D1 | 引擎进程模型 | A 库内嵌 / B 独立进程 sidecar | **已敲定:B(2026-11-01)** |
| D2 | 壳框架 | Tauri 2 / Electron | **已敲定:Tauri 2(2026-11-01)** |
| D3 | 仓库策略 | 独立 desktop 仓库 pin 双上游 / monorepo | **已敲定:独立仓库(2026-11-01)** |
| D4 | Windows/macOS 数据面路线 | 系统代理先行 / 直接上 TUN / 双线并行 | **已敲定:系统代理先行(P1→P2)** |
| D5 | 桌面版 native API 认证 | 密码自动登录 / 新增 loopback 受信模式 | 开放;倾向 (a) 零改动 |
| D6 | doona 桌面增强桥接 | native API 反代端点 / Tauri JS bridge | 开放;倾向 (a) |
| D7 | 更新 manifest 托管 | GitHub Pages / R2 / 自建(+镜像) | 开放;取决于分发地区 |
| D8 | 产品命名 | 桌面端仓库名与应用名 | **已敲定:仓库 lemon-casino/lemonvpn(2026-11-01);应用显示名建议 LemonVPN** |
