# macOS / Linux 网络恢复与桌面集成

2026-11-09：本次补齐源码和静态检查，不运行测试、不启动内核/客户端/服务、不修改实际网络设置、不构建安装包。当前使用中的 Windows 程序未被替换或重启。正式发布与 ARM64 验收继续延后。

## macOS

- 分别读取 IPv4、IPv6 默认网卡、网关、接口地址与链路状态，支持两个地址族走不同网卡；缺少某个地址族时明确返回该出口不可用，避免绑定到另一个地址族的网卡。
- 原生 TCP/UDP 分别使用 IP_BOUND_IF / IPV6_BOUND_IF；兼容内核按地址族分别持有进程，单节点与链式代理的前置端点按可用地址族解析、拨号及失败回退；TLS/SNI 保留原域名。
- TUN 服务分别维护两族 scoped default 路由。网卡切换先准备新出口，再回收旧路由；同接口网关变化只更新自己持有的条目，已有用户/系统条目保持归属。
- 自建路由使用 PROTO2 标记及 root 管理的 egress-routes.json 记录。服务启动时按记录和标记清理上次遗留条目，进程退出时按实际归属回收；服务有 flock 锁，避免重复实例争用路由与 socket。
- 使用 mach_continuous_time 与 mach_absolute_time 的差值识别睡眠时间。即使唤醒后地址和网关不变，也触发连接与 DNS 状态失效，并重建丢失的路由。
- 网络暂不可用时保留 TUN 启用意图；出口恢复后服务重载固定桥接配置、清理旧连接和 DNS 缓存。辅助内核异常退出、服务重启后也会重试恢复。

## Linux TUN

已移除原先的整用户 uidrange 放行，接入逐 socket 的 SO_BINDTODEVICE 绑定及服务持有的 oif 策略路由。普通同用户浏览器的未绑定 socket 继续进入 TUN 捕获规则；不需要给客户端设置持久的 root 权限或文件 capabilities。

此前关于“普通用户不能使用 SO_BINDTODEVICE”的笼统假设已更正：Linux 5.7 的内核实现允许无 CAP_NET_RAW 的用户对尚未绑定设备的 socket 进行首次绑定。本实现每次创建新 socket，网络变化后回收旧兼容内核，避免在已绑定 socket 上重新绑定。

- TUN 能力要求 Linux 5.7+、iproute2 和随包兼容内核。启用前验证当前出口绑定；不支持或没有可用网络时返回错误。
- privileged broker 支持 systemd、OpenRC、runit，缺少管理器时按需启动独立守护进程；用户在 TUN 页面主动授权安装。优先 pkexec，缺少时使用 sudo askpass 或终端授权。应用通过受 peer uid/pid 约束的 Unix socket 提交固定桥接参数。
- 服务为绑定实际出口设备的 socket 建立 main 表绕行规则，分别覆盖 IPv4/IPv6。规则优先级 8750..8799、protocol 242，早于显式指定的 TUN 捕获优先级 9000；捕获表为 2022，auto-redirect 关闭。
- 路由修改先记录到 root 的 journal，再操作系统；退出与服务重启只处理记录中的精确条目，保留其他程序的规则。
- 网络变化、地址变化及睡眠恢复的处理与 macOS 共用生命周期；Linux 通过 CLOCK_BOOTTIME 与 CLOCK_MONOTONIC 的差值识别睡眠。
- macOS/Linux TUN 使用安装的服务，应用无需以 root 运行。服务端失联、内核恢复或等待网络会通过 recovering 字段呈现在 TUN 设置页。

出口采样有 1.5 秒缓存，服务对未变化路由的完整核对间隔为 2 秒；恢复完成时间仍包含内核重载时间。配置热更新沿用原来的提交与发布流程。

## Linux 系统代理

支持 GNOME/Cinnamon/MATE 的 GSettings 和 KDE 5/6 的 KConfig 工具接口。设置 HTTP、HTTPS、SOCKS、本机旁路及手动模式；KDE 变更后发出配置刷新通知。其他环境使用带进程身份保护的 bash/zsh/fish 会话脚本；有 systemd 用户管理器时同步其运行期环境。界面明确显示会话代理的适用范围，已有应用的完整接管使用 TUN。

修改前原子保存每项原值、接管值和宿主 PID；部分失败回滚，端口变化保留最初原值及旧接管值，关闭时只恢复仍属于本软件的项目。用户后来修改的值保持用户选择。残留恢复同时确认宿主已退出且回环端口无监听。命令有超时，Linux IPC 在后台执行，避免阻塞桌面主线程。

桌面代理设置作用于遵循相应桌面代理接口的应用；全流量接管使用 TUN。IPv6-only 网络中，内置默认 AliDNS 上游自动使用同提供方的 IPv6 地址并依次回退；自定义上游保持用户配置，仍需能够通过现有出口访问。

## Linux 自启

使用 XDG_CONFIG_HOME/autostart/org.lemonvpn.desktop.desktop（缺省 ~/.config），用户级写入、回读和移除；Exec 参数按 Desktop Entry 规范处理引号、反斜杠和百分号。AppImage 保存 APPIMAGE 原文件路径，避免记录临时挂载路径。设置页已提供 Linux 集成标题和自启开关。

## 桌面补齐

进程条件识别、POSIX 重复启动唤起、无托盘兜底、TUN 托盘入口和会话代理的实现与边界见 [桌面平台补齐记录](desktop-platform-completion.zh.md)。

## 检查范围

- Windows 宿主共享引擎 workspace、Tauri 壳层离线编译检查。
- engine-platform 对 x86_64-apple-darwin、x86_64-unknown-linux-gnu 的离线编译检查。
- 前端 TypeScript、修改文件 ESLint 和 Prettier 检查；桌面补丁同步。
- 没有执行任何测试、连通性查询、系统代理切换、TUN 开关、服务安装或睡眠操作。

以上说明代码已经接通。macOS/Linux 原生 GUI、安装授权、真实网络切换、休眠和实际收发没有在本轮验证；Windows 上的平台库交叉编译检查不能替代这些行为验证。

## 参考

- [Linux 5.7 socket 实现](https://github.com/torvalds/linux/blob/v5.7/net/core/sock.c)：首次设备绑定的权限条件。
- [ip-rule](https://man7.org/linux/man-pages/man8/ip-rule.8.html)：oif 选择器与策略路由。
- [Apple route 实现与手册](https://github.com/apple-oss-distributions/network_cmds/tree/main/route.tproj)：双栈 ifscope 路由与 PROTO2 标记。
- [mihomo Linux 绑定](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/dialer/bind_linux.go)、[macOS 绑定](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/dialer/bind_darwin.go)：辅助内核的接口控制行为。
- [Desktop Entry 规范](https://specifications.freedesktop.org/desktop-entry/latest-single/)、[XDG Autostart](https://wiki.freedesktop.org/www/Specifications/autostart-spec/)：用户级自启与参数转义。
