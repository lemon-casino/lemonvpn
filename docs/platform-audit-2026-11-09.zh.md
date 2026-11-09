# macOS / Linux 平台代码审查（2026-11-09）

> 历史记录：后续源码已补齐网络/睡眠恢复、Linux TUN、桌面代理、进程归属、单实例唤起及 TUN 托盘，见 [当前实现](desktop-platform-completion.zh.md) 和 [网络集成](posix-network-integration.zh.md)。下文不是当前功能状态；本轮没有运行测试或生成原生安装包。

本次结论：macOS 已有桌面集成与 TUN 服务实现，仍有网络恢复和双栈边界待补；Linux 基础引擎与内核分发已接入，桌面集成不完整，TUN 暂不能开放。两者均不能标为适配完成。

本次只检查源码、离线编译与前端静态检查。没有运行测试、启动客户端/内核/服务、调用运行中引擎 API、安装服务或修改用户代理/TUN/配置；没有构建 macOS/Linux 安装包，也没有进行 ARM64 验收。历史 macOS 虚拟机记录保留在原文档中，不算本次验证。

## 已修复

| 问题 | 修复 |
|---|---|
| Linux sidecar 将 macOS 的 `RLIMIT_NOFILE=8` 用于 Linux；在当前目标架构上实际对应锁定内存上限 | Linux 改用 7，macOS 保留 8，软上限最多提高到 10240 且不超过硬上限。只调整将来启动的 sidecar 进程 |
| Linux Geo 数据查找缺少安装包资源目录，其他资源依赖固定路径猜测 | 壳层把 Tauri 实际解析的资源目录传给 sidecar；内核、Geo 数据和服务版本检查共用资源定位，保留开发态回退 |
| Linux 单实例锁使用 XDG_DATA_HOME，引擎配置使用 XDG_CONFIG_HOME | 锁与引擎使用同一数据目录；壳层显式传递选定目录，避免同一配置对应不同锁 |
| macOS TUN 启用前无条件删除已有 scoped default 路由，关闭时再次删除；内核启动失败还可能遗留新增路由 | 路由改由独立 RAII 对象持有；复用匹配的系统路由，只回收本会话创建且未被改动的路由；失败自动回滚，先停止内核再释放路由 |
| macOS 代理关闭时，只要某个协议仍属于本软件，就可能覆盖同服务里用户另改的协议 | HTTP、HTTPS、SOCKS 分别检查归属；保留用户改动的代理与旁路域名，部分失败回滚，回滚失败保留快照供重试 |
| macOS 代理快照直接覆盖、忽略 LEMONVPN_DATA_DIR | 先写临时文件并设置 0600，再原子替换；跟随实际数据目录；networksetup 改用系统绝对路径 |
| macOS 隐藏窗口后点击 Dock 可能不恢复窗口 | 接入 Tauri Reopen 事件显示现有窗口；未进行原生交互验证 |
| Linux 仍显示尚未实现的系统代理快捷开关 | 侧栏按平台显示；托盘的系统代理项在未支持的平台禁用 |
| macOS 缺少兼容内核时仍宣告可用 TUN | 能力检查同时要求兼容内核资源存在 |

前端桌面状态 hook 与能力读取收敛到 store 层，页面和侧栏共用，消除了侧栏直接依赖页面实现造成的 lint 错误。桌面补丁已同步更新。

## Linux TUN 的阻断问题

原实现安装 `ip rule ... uidrange <用户>:<用户> lookup main`，意图保护引擎自己的出站。但浏览器、终端及客户端通常属于同一用户：这条规则也会优先把它们送回原始路由表，绕开 TUN 捕获。由代码可推断，这会产生“已开启但同用户应用仍直连”的行为，不能把安装成功当成功能正常。

已移除整用户绕行，`tun.available` 和 `supported` 均返回 false；API、兼容桥、服务 start 和安装入口均拒绝启用，保留服务骨架、状态与卸载能力。后续需实现只保护引擎/兼容内核出站的方案，并确认 DNS、TCP、UDP、双栈及规则热更新均不会产生回环，再开放能力。不能只改回 available 标志。

Linux 尚缺系统代理与开机自启；服务骨架依赖 systemd、polkit/pkexec，不能声称覆盖所有发行版或容器环境。基础 HTTP/SOCKS 手动代理路径不因本次 TUN 限制被关闭。

## macOS 仍待处理的边界

- 服务的 scoped default 路由当前只在会话启用时建立 IPv4 条目；引擎会重新探测默认网卡，但服务未同步重建新网卡对应的 scoped 路由。Wi-Fi/有线切换、网关改变、休眠恢复不能据此认定可靠。
- IPv6 socket 虽有 IPV6_BOUND_IF，当前上行探测沿用 IPv4 默认路由，服务没有对应的 IPv6 scoped default 管理。IPv4/IPv6 出口不同、IPv6-only 网络仍有风险。
- 系统代理连接的本地进程归属查找仅有 Windows 实现；不能把 macOS 上的此类进程条件视为已支持。TUN 服务通过兼容内核的进程规则桥接是另一条路径，需单独验收。
- POSIX 已有 flock 单实例锁；activate_existing 的显式跨进程唤醒仍仅 Windows 实现。本次 Dock Reopen 修复不能等同于 Linux 重复启动时的窗口唤醒。
- macOS 原生壳层、授权弹窗、签名/公证与当前源码生成的安装包均未在本次验证；历史包不包含此次修复。通用二进制合并、正式发布及 ARM64 验收继续延后。

## 本次检查结果

- Windows 宿主 `cargo check --offline --workspace`：通过；共享引擎保留 11 条既有未使用代码警告。
- Windows Tauri 壳层 `cargo check --offline`：通过。
- engine-platform 的 `x86_64-apple-darwin`、`x86_64-unknown-linux-gnu` 离线编译检查：通过。
- 前端 TypeScript、修改文件 ESLint、Prettier：通过。
- prepare.mjs / prepare-compat.mjs 的 Node 语法检查：通过；没有执行下载或打包。

跨目标平台库编译通过只说明该库能通过类型检查，不证明 macOS/Linux 原生 GUI、链接、安装包或网络功能已经通过验证。当前 Windows 主机不能代替两平台的原生验收。

## 核对依据

- Tauri 资源路径按本机依赖 tauri-utils 2.10.2 的 platform::resource_dir 实现核对；包名由 tauri-codegen 2.7.4 的 productName 生成，运行时传递目录可避免独立组件重复猜测。
- Linux [ip-rule 手册](https://man7.org/linux/man-pages/man8/ip-rule.8.html)定义 uidrange 选择器；本项目整用户绕行的缺陷来自对服务源码和同用户应用场景的分析。
- Apple [route 官方源码手册](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.8)说明 ifscope 路由的接口归属及操作要求。
- Linux [resource.h](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jic23/iio/+/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2/include/asm-generic/resource.h)及本机 libc 源码用于核对当前 Linux x64 目标的资源编号。
