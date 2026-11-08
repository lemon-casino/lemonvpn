# 共享引擎与平台适配层

更新：2026-11-06。

0.1.3 更新：Windows 标准安装包新增固定版本 mihomo 协议后端与 IPv4/IPv6 TCP/UDP TUN 桥接，以及按需提权服务、开机自启。共享库的自定义 `TunConfig` 路径仍保留原生 IPv4 栈；下文涉及该路径的限制不能等同于标准 Windows 安装包。实现边界、进程模型和未运行测试的说明见 [Windows 0.1.3](windows-0.1.3.zh.md)。

当前优先级为本机 Windows x64 稳定性；正式发布及 Windows ARM64 真机验收延后。桌面单实例锁防止重复启动，代理备份按端口和宿主 PID 归属；系统代理实现收敛到平台库，桌面壳只负责序列化。引擎宿主持有桌面父进程句柄，父进程异常退出后停止引擎、释放 TUN，并恢复仍属于该宿主的系统代理。重启等待可取消，启动未通过健康检查的子进程会被回收。TUN 新连接定期重新探测物理网卡，离线时不使用未绑定的 socket 绕回捕获路由。

入站协议探测、HTTP 请求头、SOCKS5 握手和 API 请求体使用可取消的读取轮询：保留原握手超时和已经收到的部分数据，停止时不再等候长超时。事件和日志订阅也独立检查停止信号，保留原 15 秒心跳，不以心跳等待时间阻塞停止。父进程退出兜底先恢复属于该宿主的代理，再等待引擎收尾，避免远端拨号拖延代理还原。

桌面前端通过 Tauri 注入的应用信息固定连接托管引擎，不受浏览器中旧的远程配置方案影响。设置和状态弹层不再提供后端编辑、配置方案管理及 doona 关于/指南入口；原生 API 新增 `/api/v1/desktop/status`，提供本地代理、TUN、进程内存和系统内存快照。Linux 的 cgroup/OOM 空字段不用于 Windows 桌面卡片。前端源码按 `DOONA_DESKTOP_REVISION` 固定，所有改动保存在 `patches/doona-lemonvpn-desktop.patch`。

## 当前结构

`sidecar-stub/` 是一个 Cargo workspace，保留原构建目录和 `lemonvpn-engine-stub` 文件名，桌面壳和既有安装无需切换 API 或端口。

```text
桌面 Tauri 壳 → sidecar-stub/src/main.rs
                         ↓
                lemonvpn-engine-core
         协议 / 规则 / DNS / 节点 / 订阅 / API
            连接与流量统计 / smoltcp IPv4 栈
                         ↓
              lemonvpn-engine-platform
          TCP/UDP socket / TUN 数据包通道
           网卡与路由 / 内存统计 / 默认目录
                         ↓
           Windows 原生实现 | 后续宿主实现
```

依赖单向：桌面宿主依赖 core，core 依赖 platform；platform 不依赖引擎配置、日志或桌面界面。core 中没有 Windows 条件编译、Wintun 或 Win32 调用。现有 HTTP/SOCKS 入站和全部协议出站均保留。

## 嵌入与生命周期

共享库提供 `Engine::start(EngineOptions)`、`local_addr()`、`set_tun()`、`enable_tun(TunConfig)`、`tun_status_json()` 和 `shutdown()`。启动失败返回 `io::Error`，库不会退出宿主进程；只有桌面入口将端口占用转换为兼容的退出码 3。

```rust,no_run
use lemonvpn_engine_core::{Engine, EngineOptions};

let mut engine = Engine::start(EngineOptions {
    port: 0,
    data_dir: Some("./engine-data".into()),
})?;
println!("{}", engine.local_addr());
// 宿主继续运行，按需要调用 engine.set_tun(true)。
engine.shutdown()?;
# Ok::<(), std::io::Error>(())
```

停止会关闭活动代理连接、停止 TUN、清理宿主拥有的路由，并唤醒/回收监听器、采样器、事件生产者和订阅调度线程。`shutdown()` 可重复调用，`Drop` 也会清理。已开始的协议握手或控制请求仍受各自超时约束，停止不是硬实时操作。

当前配置、缓存和统计仍有进程级全局状态：**同一进程只支持一个活动引擎和一个固定配置目录**，可停止后使用同一目录重新启动；重启不会清空所有进程级统计或控制设置。此次未实现多实例隔离，也未提供 Android JNI / Apple C ABI 绑定。

## 平台接口

`Platform` 统一承接外部 TCP 拨号、UDP socket 创建、TUN 能力与设备创建、RSS 内存统计、默认数据目录。TCP/DNS/QUIC 不再直接依赖 Windows TUN 模块。

宿主可在调用引擎前用 `platform::install(Arc<dyn Platform>)` 安装后端；一旦首次使用，不再切换。TUN 后端返回 `OpenedTun`：输入/输出 IP 数据包通道及拥有资源的 `TunSession`。共享 smoltcp 栈不需要了解 Wintun 句柄、Unix fd 或 Apple packetFlow。自定义宿主负责按系统要求保护出站 socket，提供 VPN 服务生命周期和设备授权。

`TunConfig` 约定协议栈地址、宿主地址、前缀及捕获路由；两端地址必须不同且在同一子网。默认保留 `10.111.0.1`（协议栈）、`10.111.0.2/30`（宿主），通过两个 `/1` 路由接管 IPv4。支持宿主提供较窄的路由，原生冒烟测试只捕获 `203.0.113.199/32`。

| 平台 | 当前实现 |
|---|---|
| Windows | Wintun、IPv4 路由、物理接口 socket 绑定、RSS、数据目录 |
| Linux | 标准 TCP/UDP socket、RSS、数据目录；TUN 尚未实现 |
| macOS | 标准 TCP/UDP socket、数据目录；TUN 和 RSS 尚未实现 |
| Android / iOS | 预留宿主接口；原生 VPN 服务及绑定尚未实现 |

未实现的原生 TUN 在 API 能力中报告 `available:false`，写入返回 501；能力由实际安装的后端决定，移动端无需伪装 Windows。现有 TUN 仍仅支持 IPv4 TCP 和 DNS UDP，普通 UDP 中继与 IPv6 不在此次变更范围内。

Windows 后端在安装捕获路由前等待网卡地址进入 `IpDadStatePreferred`，避免系统选取其他网卡的源 IP 导致握手失败。设备、成功安装的路由和物理接口绑定由会话统一持有，部分安装失败时也清理；不额外配置系统默认网关。默认系统代理配置仍由桌面壳负责，原有备份/还原逻辑保留。

## 构建与验证

```powershell
cargo test --manifest-path sidecar-stub/Cargo.toml --workspace --locked
node --test app/scripts/engine-artifacts.test.mjs
node app/scripts/prepare.mjs --engine-only
pnpm --dir app build
```

准备脚本按 `TAURI_ENV_TARGET_TRIPLE`（或 `CARGO_BUILD_TARGET`，未指定则为宿主架构）显式传 `cargo build --target`，从 Cargo metadata 提供的目标目录读取产物，避免把宿主程序改名为其他架构。Windows DLL 从依赖中选择相应 CPU 的 Wintun，校验 PE 架构，并携带原许可证。Windows 的 NSIS 和 DLL 资源配置位于 `tauri.windows.conf.json`。

CI 为 Windows/Linux/macOS 增加 workspace 测试，为 Windows ARM64 增加编译检查；加入 CI 不代表所有平台已通过真机验收。macOS 通用二进制合并暂未实现，脚本会明确拒绝 `universal-apple-darwin`。

管理员 PowerShell 中可运行原生 Wintun 冒烟：

```powershell
$env:PATH = "$PWD\app\src-tauri\binaries;$env:PATH"
cargo test --manifest-path sidecar-stub/Cargo.toml -p lemonvpn-engine-core --test windows_tun -- --ignored
```

该测试验证 Windows TCP → Wintun → 共享协议栈 → 本地 SOCKS 节点 → 回声，以及 DNS UDP 回包、关闭和重新开启。默认测试不会创建真实网卡或修改系统路由。自动测试还覆盖库内启动/停止、占用端口、活动连接回收、宿主后端注入和无需驱动的数据包往返。
