# LemonVPN

局域网共享：在「设置 → 通用 → 局域网共享」启用独立的 HTTP / SOCKS5 TCP 端口，可选择监听网卡、设置用户名密码，并复制连接地址。默认关闭、端口 `18081`，沿用当前规则与出站；设置保存后即时启停，无需重连本机代理。管理 API 保持回环监听。设备连接方式和边界见 [局域网共享](docs/lan-sharing.zh.md)。

推送版本 tag 后自动构建并发布：Windows、macOS、Linux 各 x64/ARM64，共六种原生构建；安装包不签名，全部成功后自动公开 GitHub Release，并附带 SHA256 校验。使用方式与架构补齐见 [Tag 自动发布](docs/tag-release.zh.md)。

Windows 0.1.31：已重新构建未签名的 x64 NSIS 安装包，包含 TUN 托盘入口、状态同步及最新桌面适配。构建未运行测试或安装程序，当前运行进程与已安装文件保持不变。产物与 SHA256 见 [构建记录](docs/windows-0.1.31.zh.md)。

2026-11-09 桌面平台补齐：托盘增加 TUN 模式并同步真实开关状态；补齐 macOS/Linux 进程信息、重复启动唤起与无托盘兜底、IPv6-only 默认 DNS，以及 Linux 多服务管理器、授权和会话代理。详见 [实现与检查范围](docs/desktop-platform-completion.zh.md)。仅源码与离线编译/前端构建，未运行测试、生成原生安装包或影响当前 Windows 软件；签名与正式发布延后。

Windows 0.1.20：按实际引擎能力提供 DNS 动作，移除不支持的 asis 选项并明确诊断；补齐拖放排序提交回调，保存后回读实际顺序确认，提示全局模式覆盖普通路由的生效范围。详见 [说明](docs/windows-0.1.20.zh.md)。只读检查现有日志，静态检查与编译构建，未运行测试、修改当前配置或替换当前软件。

Windows 0.1.19：活动页“应用”紧邻模式选择，全局出站及其占位移到控件组后侧，避免按钮被空白隔远，保留三种模式的稳定布局。详见 [说明](docs/windows-0.1.19.zh.md)。仅静态检查与编译构建，未运行测试或替换当前软件。

Windows 0.1.18：左侧活动小工具仅全局模式显示全局出站，其他模式保留固定行高；活动页保留全局出站宽度占位，切换模式时控件高度和位置保持一致。详见 [说明](docs/windows-0.1.18.zh.md)。仅静态检查与编译构建，未运行测试或替换当前软件。

Windows 0.1.17：规则列表直接拖拽并自动保存，处理排序期间 React #311 的触发点；桌面模块显示实际资源并链接对应管理页，DNS 新增上游编辑；活动页模式和全局出站合并为一次应用；移除顶部报告问题按钮并处理提示框定位。详见 [说明](docs/windows-0.1.17.zh.md)。仅静态检查与编译构建，未运行测试或替换当前软件。

Windows 0.1.16：“添加节点 / 订阅”自动识别粘贴链接；修复 DNS 规则无法新建，路由与 DNS 请求、响应列表新增默认规则预览、重置和拖拽排序。详见 [说明](docs/windows-0.1.16.zh.md)。仅编译构建，未运行测试或替换当前软件。

Windows 0.1.15：勾选多个节点后支持批量加入、移出或更换所属组，整批校验后统一提交；“添加订阅”和“粘贴节点链接”合并为“添加节点 / 订阅”，同一弹窗内切换两类链接。详见 [说明](docs/windows-0.1.15.zh.md)。仅编译构建，未运行测试或替换当前软件。

Windows 0.1.14：订阅节点操作菜单增加“管理所属组”，可加入、移出、更换多个组；自动匹配的成员支持单节点排除，保留订阅和地区筛选。保存前检查配置代次，统一校验涉及的配置源并在失败时回滚。详见 [说明](docs/windows-0.1.14.zh.md)。本轮仅编译构建，未运行测试或替换使用中的软件。

Windows 0.1.13：补入 GeoIP/GeoSite 匹配、Windows 进程条件和 DNS 响应规则；连接并入活动页的标签切换，左侧“节点”改为“订阅”，订阅菜单可修改地址与更新选项。Geo 数据随包附带并校验 SHA256。详见 [实现与边界](docs/windows-0.1.13.zh.md)。本轮仅编译构建，未运行测试或替换使用中的程序、服务。

Windows 0.1.12：代理内核统一命名为 `lemonvpn-kernel`（Windows 保留 `.exe` 后缀），按页面顺序完成一轮前后端代码排查，修复状态、策略、节点、连接、分流、DNS、日志事件和配置写入问题，详见 [逐项记录与边界](docs/windows-0.1.12.zh.md)。本轮未运行测试或替换使用中的程序。

Windows 0.1.11：修复策略组解除固定后的 204/空 JSON 报错，补齐选择响应；连接新建规则增加端口、协议和组合依据，并接入共享引擎的实际匹配，详见 [说明](docs/windows-0.1.11.zh.md)。

Windows 0.1.10：TCP/UDP 分别展示健康状态并限定成员操作范围，修复单协议解除固定，支持再次点击固定节点恢复自动选择，补入真实 UDP DNS 观测，详见 [说明](docs/windows-0.1.10.zh.md)。

Windows 0.1.9：策略组支持中文名称，修复地区正则和订阅标签筛选导致组内没有匹配节点，以及中文组名的接口编码问题，详见 [说明](docs/windows-0.1.9.zh.md)。

Windows 0.1.8：无系统标题栏，窗口按钮置于主题右侧；设置与版本同行；禁用页面右键和普通内容选中；补齐策略组全部选择方式及校验诊断，详见 [说明](docs/windows-0.1.8.zh.md)。

Windows 0.1.7：活动小工具按内容收紧，去除底部撑高和空提示行，三种模式共用常驻的模式与出站行，详见 [说明](docs/windows-0.1.7.zh.md)。

Windows 0.1.6：修复侧栏小工具文字裁切，移除“应用”并改为选择模式后直接切换，“系统状态”简化为“状态”，详见 [说明](docs/windows-0.1.6.zh.md)。

Windows 0.1.5：菜单改为两列，小工具停靠高度及模式切换位置保持稳定，图表提示移至侧栏外侧，详见 [说明](docs/windows-0.1.5.zh.md)。

Windows 0.1.4 更新：修复 TUN 服务管道通信，服务安装/修复归入 TUN 模式；紧凑侧栏与默认嵌入的小工具布局见 [说明](docs/windows-0.1.4.zh.md)。仅编译构建，未运行测试或替换使用中的客户端。

基于共享 Rust 代理引擎、[doona](https://github.com/Zakkaus/doona) 界面与 Tauri 2 构建桌面代理应用，目标覆盖 Windows / macOS / Linux、x86_64 / aarch64。Windows 0.1.3 接入固定版本 mihomo 提供协议兼容和双栈 TUN，共享 Rust 引擎保留配置、规则与监控。

- 状态：Windows 0.1.3 补入 IPv4/IPv6 TCP/UDP TUN、协议兼容内核、开机自启和按需 TUN 服务；按用户要求只编译构建，不运行测试或启动新程序。具体范围与限制见 [Windows 0.1.3 说明](docs/windows-0.1.3.zh.md)。macOS 已补双栈出口、网络切换与睡眠恢复；Linux 已接入按 socket 绑定出口的 TUN、GNOME/KDE 系统代理和 XDG 自启。当前只通过编译与静态检查，原生行为验收未进行，范围见 [平台集成说明](docs/posix-network-integration.zh.md)。
- 当前优先级：稳定本机 Windows x64，正式发布和 ARM64 验收延后。已补单实例、按宿主归属恢复代理、子进程故障恢复和父进程退出兜底；长期运行与真实网络切换仍需验收。
- 当前代码架构与扩展方式：[docs/engine-architecture.zh.md](docs/engine-architecture.zh.md)
- 开发方案与架构决策:[docs/desktop-development-plan.zh.md](docs/desktop-development-plan.zh.md)
- 许可:GPL-3.0-only(上游 honk / doona 亦为 GPL-3.0-only)

## 仓库布局

本仓库承载桌面壳(Tauri 2)、引擎 sidecar 托管、打包与桌面 CI。上游代码不在本仓库跟踪:

| 路径 | 说明 |
|---|---|
| `docs/` | 开发文档 |
| `sidecar-stub/crates/engine-core/` | 共享引擎库：协议、规则、DNS、API、通用 smoltcp 协议栈与可停止的运行时 |
| `sidecar-stub/crates/engine-platform/` | 平台接口及 Windows Wintun、路由、socket 防回环实现 |
| `sidecar-stub/src/main.rs` | 桌面进程入口，保留原 sidecar 文件名兼容现有安装 |
| `app/` | Tauri 桌面壳、前端准备和按目标架构打包脚本 |
| `pins.env` | 锁定 honk 修订与 doona 版本(沿用 honk `pins.env` 机制) |
| `doona/`、`honk/` | 本地上游工作副本（已被 .gitignore 排除）；桌面 CI 按 pins 获取固定前端源码和官方内核资源 |

本地开发需要上游副本时:

```sh
git clone https://github.com/daeuniverse/honk.git honk
git clone https://github.com/Zakkaus/doona.git doona
```

所用修订以 `pins.env` 为准。

桌面 UI 使用 `DOONA_DESKTOP_REVISION` 和合并补丁 `doona-lemonvpn-desktop.patch`，包含 Windows 路径、模块名、API、LemonVPN 品牌、固定本机引擎、TUN 设置及桌面状态页适配。旧的单项补丁保留供参考，不需再次应用。

DNS 页面提供 Fake-IP 设置：切换 `fake-ip` / `redir-host`，配置 IPv4/IPv6 地址池、域名排除名单和映射持久化。设置保存在用户数据目录的 `dns-settings.json`；`GET/PUT /api/v1/dns/settings` 通过修订摘要防止并发覆盖，运行中的 TUN 内核确认热更新后才保存，失败时恢复运行配置。普通系统代理的 DNS 不受此设置影响。TUN 服务需更新到同一版本；内核工作目录保持稳定，正常退出时保存持久映射。Windows 的退出信号通过隐藏控制台与独立辅助进程发送，不改变宿主控制台。此功能仅执行静态检查与构建，未运行网络、TUN 或 UI 测试。

品牌图标采用“石墨黑白折纸猫机 + 笔记本”，键盘/底座为黑色，折纸猫机为白色。透明主图保存在 `app/branding/logo.png`，已缩减留白以放大桌面图标，页面顶部与登录页也使用更大的展示尺寸。`app/branding/web/` 保存页面、favicon、PWA 与 Apple 图标，`app/src-tauri/icons/` 保存桌面窗口、托盘、Windows 程序/安装包及 macOS 图标。桌面开发和构建会自动运行 `prepare-branding.mjs`，在已有桌面适配上幂等应用 `doona-lemonvpn-branding.patch` 并同步资源；单独开发前端时先执行 `pnpm --dir app prepare:branding`。这样新克隆的上游工作副本和重新打包的程序都会使用同一套图标。

## 本地运行骨架

本地运行由 `app/`（桌面壳）、`sidecar-stub/`（共享引擎的桌面宿主）与 `doona/`（界面，本地克隆）组成。`stub` 仅为保留的兼容名称。

前置：Node 24、pnpm 11（版本见前端 packageManager）和 Rust stable，`cargo` 需在 PATH 中。Windows 需要对应目标的 MSVC 工具链，ARM64 另需 LLVM/Clang；自动构建在 runner 内准备这些环境。

```powershell
# 1. doona 界面(终端 1)
git clone https://github.com/Zakkaus/doona.git doona
git -C doona checkout <pins.env 中的 DOONA_DESKTOP_REVISION>
git -C doona apply ..\patches\doona-lemonvpn-desktop.patch
pnpm --dir doona install
pnpm --dir doona dev          # http://localhost:5173

# 2. 共享引擎与桌面宿主
cargo build --manifest-path sidecar-stub/Cargo.toml

# 3. 桌面壳(终端 2,debug 构建会自动找到第 2 步的占位进程)
cd app
pnpm install
pnpm dev
```

`patches/doona-windows-case-collisions.patch` 修正 doona 中三对仅大小写不同的模块名(`shortcuts.ts`/`Shortcuts.tsx` 等)。Windows 与 macOS 的文件系统不区分大小写,不修则开发服务器把 `./Shortcuts` 解析到 `shortcuts.ts`,页面报 `does not provide an export named 'Shortcuts'`。

`patches/doona-dev-api-proxy.patch` 让 doona 的开发服务器把 `/api` 转发到引擎(见下节)。doona 只有在页面同源上探测到 `api_major: 1` 才会把该地址当作后端,所以这一跳是必须的。

`pnpm dev` 会打开桌面窗口并加载 doona 开发服务器;若 doona 未启动,窗口显示 `app/dist` 的占位页。引擎状态通过 `engine_status` 命令返回,取值 `running` / `restarting` / `port_in_use` / `unhealthy` / `failed` / `missing` / `stopped`。`port_in_use` 表示端口被别的进程占着:壳只接受 `/health` 里与本次启动的子进程 pid 匹配的 `instance`,不会接管陌生的监听。

冒烟检查(启动 5 秒后自动退出):

```powershell
$env:LEMONVPN_SMOKE='1'; cargo run --manifest-path app/src-tauri/Cargo.toml
```

Windows 发布包界面回归：先执行 `pnpm --dir app build`，再运行 `pnpm --dir app test:native-ui`。测试直接连接 release 程序的 WebView2，使用独立临时数据目录和随机回环端口，验证品牌、设置、真实内存数据，以及保留用户偏好的旧页面缓存升级；不修改当前应用的数据或系统代理。截图输出到 `app/src-tauri/target/ui-preview/native-*.png`。

本机稳定性回归：`cargo test --manifest-path app/src-tauri/Cargo.toml --locked` 覆盖实例锁、真实引擎崩溃重启、取消重启和端口归属；`pnpm --dir app test:native-ui` 还验证重复启动和强制结束测试宿主后的引擎回收。`pnpm --dir app test:local-workload` 使用本地回声服务进行 32 并发、288 次 HTTP/SOCKS5 回包、16 次上游拒绝后恢复的短时检查，不是长时运行或吞吐基准。系统代理逻辑在平台库测试中使用独立注册表测试键，不操作当前用户的 Internet Settings。

本轮另运行 `node app/scripts/engine-stability-smoke.mjs 120`：两分钟完成 2,176 次回包和 16 次拒绝检查，59 个常驻内存采样点的峰值为 7,950,336 字节；仅代表短时本机回归，真实断网/网卡切换、休眠唤醒和小时级运行仍需验收。

桌面端直接读取程序内嵌资源，不注册 PWA Service Worker。宿主在升级启动时移除原有 doona 页面缓存并保留 localStorage；入口 URL 带桌面版本，内嵌资源使用 `Cache-Control: no-store`，避免安装新程序后继续显示旧页面。

环境变量:

| 变量 | 作用 |
|---|---|
| `LEMONVPN_ENGINE` | 指定引擎二进制路径(优先于自动查找) |
| `LEMONVPN_ENGINE_PORT` | 引擎监听端口,默认 `18080` |
| `LEMONVPN_SMOKE` | 设为 `1` 时启动 5 秒后退出,用于冒烟检查 |
| `LEMONVPN_PROXY` | 设为 `on` / `off` 时启动后切换系统代理并立即退出,用于无界面验证 |
| `LEMONVPN_OPEN_LOGS` | 设为 `1` 时启动即打开引擎日志窗口,用于无界面验证日志页链路 |

## 代理入站(P1)

引擎在 `127.0.0.1` 上提供混合入站，按首字节分流 HTTP 和 SOCKS5。支持 HTTP `CONNECT`、绝对 URI 转发与 SOCKS5 无认证 `CONNECT`。规则可选择直连、阻断或节点出站；已有 SOCKS5、VLESS、VMess、Trojan、Shadowsocks 与 Hysteria2 实现，但不代表这些协议的所有扩展均受支持（如 REALITY、Vision、VMess WebSocket、Hysteria2 混淆尚未实现）。

```powershell
$env:LEMONVPN_ENGINE_PORT='18080'; cargo run --manifest-path sidecar-stub/Cargo.toml
# 另一个终端
curl.exe -x http://127.0.0.1:18080 https://example.com -I
curl.exe --socks5 127.0.0.1:18080 https://example.com -I
```

入站没有认证,因此只绑定回环地址——把 `BIND_ADDR` 改成可路由地址会让这台机器变成开放代理。UDP ASSOCIATE 与 SOCKS5 认证尚未实现。

当前数据面不依赖 honk-core。共享引擎与平台层独立，Windows/macOS/Linux 分别提供 socket 出口保护；macOS/Linux 的双栈 TUN 由平台管理员服务桥接。内置 smoltcp 栈与兼容内核桥接的实现范围不同，详见 [架构说明](docs/engine-architecture.zh.md)。

## Native API(M1)

引擎实现了 doona 的 native API，并提供节点/订阅管理、配置写入与重载、规则、DNS、探测、连接关闭、运行设置等控制端点。以下为基础监控端点：

| 路径 | 内容 |
|---|---|
| `GET /api` | 发现文档,`api_major: 1`,回环免认证(`anonymous_loopback: true`) |
| `GET /api/v1/version` | API 标识与引擎版本 |
| `GET /api/v1/capabilities` | 声明实际提供的资源和宿主平台能力 |
| `GET /api/v1/runtime` | 生命周期、数据面、累计字节、活动连接、速率 |
| `GET /api/v1/runtime/traffic/history` | 每秒采样的流量环,窗口与点数上限均为 600 |
| `GET /api/v1/datapath` | userspace 数据面状态 |

未实现的接口返回契约里的 `404 resource_not_found`,`capabilities` 也不声明它们,因此 doona 对应卡片显示"此后端不提供",而不是空白或报错。

计数来自引擎处理的隧道：上传为客户端→上游，下载为上游→客户端，持续传输时实时累加。`connections` 是活动隧道数，`bytes` 是进程启动以来累计值。API 仅绑定回环，保留 `anonymous_loopback`；当前包含写操作，本机进程可访问，WebView 跨域访问使用固定来源白名单。

引擎未启动时,doona 的发现探测失败,界面回落到内置 mock 后端。

## 系统代理开关(M1,Windows)

桌面壳把当前用户的 WinINet 代理指向引擎的混合入站,让遵守系统代理的程序(浏览器等)不必安装 TUN 就能走引擎。入口是托盘右键菜单「系统代理」；同一能力也通过 Tauri 命令 `proxy_status` / `proxy_set` 暴露。

- 写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:`ProxyEnable=1`、`ProxyServer=127.0.0.1:<引擎端口>`、`ProxyOverride=<local>`,再调用 `InternetSetOptionW`(39 / 37)让运行中的程序立即重读。
- 首次启用前把原值备份到 `HKCU\Software\LemonVPN`(`SavedProxy*`)。关闭时只有当前 `ProxyServer` 仍是我们写入的值才还原——用户自己改过代理,就保留用户的选择。应用正常退出时自动关闭。
- 端口被占用时壳不会接管已有的监听,`engine_status` 为 `port_in_use`(见上)。

无界面验证(引擎启动、切换代理后立即退出；退出前恢复自检写入的代理):

```powershell
$env:LEMONVPN_PROXY='on';  cargo run --manifest-path app/src-tauri/Cargo.toml
$env:LEMONVPN_PROXY='off'; cargo run --manifest-path app/src-tauri/Cargo.toml
```

macOS 系统代理基于 `networksetup`，Linux 支持 GSettings、KConfig 和其他桌面的会话代理。接管前保存原值，关闭时按归属恢复。适用范围见 [当前平台说明](docs/desktop-platform-completion.zh.md)。

## 引擎守护(M1)

壳每 2 秒检查一次引擎子进程。引擎意外退出时按 1 / 2 / 4 / 8 / 16 秒退避重启,最多 5 次;连续 5 次仍失败就停止重启,状态变为 `failed`,并关闭系统代理——避免系统代理一直指向一个没人监听的端口。引擎稳定运行超过 60 秒后重启预算清零,所以偶发崩溃不会累积到上限。主动退出(`shutdown`)会置停止标志,守护线程不会与退出流程抢进程。

重启复用同一个端口,所以系统代理不需要跟着改。日志窗口里能看到「引擎进程已退出」「第 N 次重启将在 X 秒后开始」这类记录。

## 托盘与引擎日志(M1,Windows)

壳常驻托盘:左键单击托盘图标显示主窗口,右键菜单为「显示窗口 / 系统代理 / TUN 模式 / 引擎日志 / 退出」。主窗口不再显示原生菜单栏，页面与标题栏直接衔接。

关闭主窗口隐藏到托盘；无可用托盘时保留窗口并最小化，引擎与系统代理继续工作。通过托盘「退出」或设置内「退出应用」结束，退出时会停止引擎并还原系统代理。

「引擎日志」打开独立窗口,显示引擎 stderr 与壳的托管记录(每行带相对启动时间,保留最近 500 行,每 0.5 秒刷新,可一键复制)。页面由壳通过自定义协议 `lemonvpn://localhost/logs` 提供,不依赖 doona 新增路由(桌面设置页桥接仍待 D6)。日志页通过 `engine_logs` 命令取数,主窗口与日志页互不影响。

无界面验证日志页链路(不需要 doona 开发服务器):

```powershell
$env:LEMONVPN_OPEN_LOGS='1'; $env:LEMONVPN_SMOKE='1'; cargo run --manifest-path app/src-tauri/Cargo.toml
```

页面加载并成功取到日志后会在 stderr 打印 `lemonvpn: 日志页已加载`。

## 规则、DNS 与 Fake-IP

规则集管理、地理分类、加密上游、解析池、DNS 缓存和追踪共用资源快照，支持保存后热更新。使用入口、迁移边界及管理 API 见 [管理说明](docs/rules-dns-fakeip.zh.md)。高级 Fake-IP 分类需要 TUN 服务 v2；现有配置不强制迁移。
