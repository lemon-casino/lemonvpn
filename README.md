# LemonVPN

把 [honk](https://github.com/daeuniverse/honk) 代理引擎与 [doona](https://github.com/Zakkaus/doona) 界面打包为开箱即用的跨平台桌面应用(Windows / macOS / Linux,x86_64 + aarch64)。

- 状态:桌面窗口显示引擎的实时状态与流量,托盘与菜单可切换 Windows 系统代理,引擎日志页可用,引擎崩溃后自动重启(M1 进行中)
- 开发方案与架构决策:[docs/desktop-development-plan.zh.md](docs/desktop-development-plan.zh.md)
- 许可:GPL-3.0-only(上游 honk / doona 亦为 GPL-3.0-only)

## 仓库布局

本仓库承载桌面壳(Tauri 2)、引擎 sidecar 托管、打包与桌面 CI。上游代码不在本仓库跟踪:

| 路径 | 说明 |
|---|---|
| `docs/` | 开发文档 |
| `pins.env` | 锁定 honk 修订与 doona 版本(沿用 honk `pins.env` 机制) |
| `doona/`、`honk/` | 仅存在于本地开发机的上游工作副本(已被 .gitignore 排除),CI 按 pins 拉取对应发布产物 |

本地开发需要上游副本时:

```sh
git clone https://github.com/daeuniverse/honk.git honk
git clone https://github.com/Zakkaus/doona.git doona
```

所用修订以 `pins.env` 为准。

## 本地运行骨架

骨架由三部分组成:`app/`(Tauri 2 桌面壳)、`sidecar-stub/`(引擎占位进程,验证 sidecar 接缝)与 `doona/`(界面,本地克隆)。

前置:Node 22+/24+、pnpm、Rust 1.77+(MSVC 工具链),`cargo` 需在 `PATH` 中。

```powershell
# 1. doona 界面(终端 1)
git clone https://github.com/Zakkaus/doona.git doona
git -C doona checkout <pins.env 中的 DOONA_REVISION>
git -C doona apply ..\patches\doona-windows-case-collisions.patch
git -C doona apply ..\patches\doona-dev-api-proxy.patch
pnpm --dir doona install
pnpm --dir doona dev          # http://localhost:5173

# 2. 引擎占位进程
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

环境变量:

| 变量 | 作用 |
|---|---|
| `LEMONVPN_ENGINE` | 指定引擎二进制路径(优先于自动查找) |
| `LEMONVPN_ENGINE_PORT` | 引擎监听端口,默认 `18080` |
| `LEMONVPN_SMOKE` | 设为 `1` 时启动 5 秒后退出,用于冒烟检查 |
| `LEMONVPN_PROXY` | 设为 `on` / `off` 时启动后切换系统代理并立即退出,用于无界面验证 |
| `LEMONVPN_OPEN_LOGS` | 设为 `1` 时启动即打开引擎日志窗口,用于无界面验证日志页链路 |

## 代理入站(P1)

引擎在 `127.0.0.1` 上提供混合入站,客户端按首字节分流:HTTP 客户端走 HTTP 代理,`0x05` 开头走 SOCKS5。支持 HTTP `CONNECT` 隧道、绝对 URI 的普通 HTTP 转发、SOCKS5 无认证 `CONNECT`(IPv4 / IPv6 / 域名)。出口目前是直连,honk 的拨号器与规则引擎后续接到 `proxy::dial` 后面。

```powershell
$env:LEMONVPN_ENGINE_PORT='18080'; cargo run --manifest-path sidecar-stub/Cargo.toml
# 另一个终端
curl.exe -x http://127.0.0.1:18080 https://example.com -I
curl.exe --socks5 127.0.0.1:18080 https://example.com -I
```

入站没有认证,因此只绑定回环地址——把 `BIND_ADDR` 改成可路由地址会让这台机器变成开放代理。UDP ASSOCIATE 与 SOCKS5 认证尚未实现。

真实 honk 引擎目前无法在 Windows 编译(`nix` 与 `libsystemd` 是硬依赖),`sidecar-stub` 因此承载桌面端自己的数据面;Linux/macOS 接入真实引擎是后续里程碑。

## Native API(M1)

引擎实现了 doona 首屏需要的只读 native API,响应按 `doona/contract/api-standardize/openapi.yaml` 的 schema 用 `ajv` 校验过:

| 路径 | 内容 |
|---|---|
| `GET /api` | 发现文档,`api_major: 1`,回环免认证(`anonymous_loopback: true`) |
| `GET /api/v1/version` | API 标识与引擎版本 |
| `GET /api/v1/capabilities` | 只声明实际提供的能力:`runtime`、`traffic_history`、`datapath` |
| `GET /api/v1/runtime` | 生命周期、数据面、累计字节、活动连接、速率 |
| `GET /api/v1/runtime/traffic/history` | 每秒采样的流量环,窗口与点数上限均为 600 |
| `GET /api/v1/datapath` | userspace 数据面状态 |

未实现的接口返回契约里的 `404 resource_not_found`,`capabilities` 也不声明它们,因此 doona 对应卡片显示"此后端不提供",而不是空白或报错。

计数来自混合入站的隧道:上传是客户端→上游,下载是上游→客户端,每读一次就累加,长时间传输不会等到结束时才跳变。普通 HTTP 转发的请求行与请求头也计入上传,请求体与响应体仍走同一条隧道。`connections` 是当前打开的隧道数,`bytes` 是进程启动以来的累计值。API 只绑定回环且无认证,本机任何进程都能读取;它是只读的,没有可被跨站触发的写操作。

引擎未启动时,doona 的发现探测失败,界面回落到内置 mock 后端。

## 系统代理开关(M1,Windows)

桌面壳把当前用户的 WinINet 代理指向引擎的混合入站,让遵守系统代理的程序(浏览器等)不必安装 TUN 就能走引擎。入口是窗口菜单「LemonVPN → 系统代理」;同一能力也通过 Tauri 命令 `proxy_status` / `proxy_set` 暴露,供后续的桌面设置页使用。

- 写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:`ProxyEnable=1`、`ProxyServer=127.0.0.1:<引擎端口>`、`ProxyOverride=<local>`,再调用 `InternetSetOptionW`(39 / 37)让运行中的程序立即重读。
- 首次启用前把原值备份到 `HKCU\Software\LemonVPN`(`SavedProxy*`)。关闭时只有当前 `ProxyServer` 仍是我们写入的值才还原——用户自己改过代理,就保留用户的选择。应用正常退出时自动关闭。
- 端口被占用时壳不会接管已有的监听,`engine_status` 为 `port_in_use`(见上)。

无界面验证(引擎启动、切换代理后立即退出):

```powershell
$env:LEMONVPN_PROXY='on';  cargo run --manifest-path app/src-tauri/Cargo.toml
$env:LEMONVPN_PROXY='off'; cargo run --manifest-path app/src-tauri/Cargo.toml
```

macOS(`networksetup`)与 Linux(`gsettings` / `kwriteconfig`)的系统代理配置器尚未实现,非 Windows 平台上开关报告为不可用。

## 引擎守护(M1)

壳每 2 秒检查一次引擎子进程。引擎意外退出时按 1 / 2 / 4 / 8 / 16 秒退避重启,最多 5 次;连续 5 次仍失败就停止重启,状态变为 `failed`,并关闭系统代理——避免系统代理一直指向一个没人监听的端口。引擎稳定运行超过 60 秒后重启预算清零,所以偶发崩溃不会累积到上限。主动退出(`shutdown`)会置停止标志,守护线程不会与退出流程抢进程。

重启复用同一个端口,所以系统代理不需要跟着改。日志窗口里能看到「引擎进程已退出」「第 N 次重启将在 X 秒后开始」这类记录。

## 托盘与引擎日志(M1,Windows)

壳常驻托盘:左键单击托盘图标显示主窗口,右键菜单为「显示窗口 / 系统代理 / 引擎日志 / 退出」;窗口菜单「LemonVPN」提供同样的入口,两个菜单里的「系统代理」勾选状态保持一致。

关闭主窗口只隐藏到托盘,引擎与系统代理继续工作——代理类应用的常见行为。要真正退出请用托盘或菜单里的「退出」,退出时会停止引擎并还原系统代理。

「引擎日志」打开独立窗口,显示引擎 stderr 与壳的托管记录(每行带相对启动时间,保留最近 500 行,每 0.5 秒刷新,可一键复制)。页面由壳通过自定义协议 `lemonvpn://localhost/logs` 提供,不依赖 doona 新增路由(桌面设置页桥接仍待 D6)。日志页通过 `engine_logs` 命令取数,主窗口与日志页互不影响。

无界面验证日志页链路(不需要 doona 开发服务器):

```powershell
$env:LEMONVPN_OPEN_LOGS='1'; $env:LEMONVPN_SMOKE='1'; cargo run --manifest-path app/src-tauri/Cargo.toml
```

页面加载并成功取到日志后会在 stderr 打印 `lemonvpn: 日志页已加载`。
