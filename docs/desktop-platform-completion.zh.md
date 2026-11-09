# 桌面平台补齐记录

> 后续已接通包含六种 x64/ARM64 目标的 [tag 自动构建与发布](tag-release.zh.md)，并修正 macOS 内存 ABI。下文保留当时的源码补齐记录。

> 后续 Windows x64 安装包已按用户要求重新构建为 0.1.31，未签名、未运行测试或安装。产物和校验值见 [构建记录](windows-0.1.31.zh.md)；下文记录源码补齐阶段的检查范围。

2026-11-09。本轮补齐源码、离线编译与前端构建；没有启动应用、内核或服务，没有调用运行中的引擎，没有修改当前代理、TUN、电源配置或安装目录。未运行测试，未生成或安装新的原生安装包。签名、公证、正式发布与 ARM64 验收继续延后。

## 托盘与窗口

右键菜单顺序：**显示窗口 → 系统代理 → TUN 模式 → 引擎日志 → 退出**。

- 系统代理与 TUN 使用勾选项。后台每两秒读取实际状态；页面修改成功后主动刷新。菜单持久创建，更新状态时不重建整个菜单。
- 点击后串行执行操作，等待期间禁用开关并保留上次确认状态；失败会显示窗口与错误信息，再回读状态。引擎未就绪、能力不可用或状态读取失败时禁用相应入口。
- macOS/Linux 首次通过托盘开启 TUN 时，调用已有服务安装/修复授权流程；Linux 按需启动未运行的服务。授权由用户点击触发，不随状态轮询自动发起。
- POSIX 单实例锁仍由 flock 持有，重复启动通过同用户私有 Unix datagram socket 唤起原窗口；私有目录 0700、socket 0600，路径使用配置目录摘要以避免 macOS socket 路径超长。释放实例锁前移除 socket。
- macOS Dock Reopen 保留。请求焦点不被窗口管理器接受时请求用户注意。
- 创建托盘失败不会中止应用。Linux 缺少 StatusNotifierWatcher 时保守保留任务栏入口：自启显示窗口，关闭改为最小化。设置内增加“退出应用”，无托盘也可以正常结束并触发既有清理流程。

## 进程条件

- Linux 根据 TCP/UDP、本地 IPv4/IPv6 地址及端口读取 procfs socket inode，再在同用户进程中查找 fd，回读 socket 表确认，返回 PID、名称与可执行路径。
- macOS 使用系统 lsof 的数值地址和 NUL 字段输出，按本地端点筛选后通过 proc_pidpath 取可执行路径；设定时间与输出大小上限，避免阻塞无期限延长。
- 多个拥有者、权限不足、进程已退出或查找超时均保持未知，不随意把连接归属到其他应用。系统代理连接的进程识别与 TUN 内核的进程元数据仍是两条来源。

## IPv6-only 默认 DNS

macOS/Linux 仅有 IPv6 出口时，内置 default UDP/53 AliDNS 地址自动改用同提供方的 `2400:3200::1`，失败后尝试 `2400:3200:baba::1`。保留原来的 UDP 截断转 TCP、DNS 事务和问题验证。自定义 DNS 上游不被重写。

网络切换、睡眠恢复和两个地址族独立出口的生命周期见 [网络集成记录](posix-network-integration.zh.md)。

## Linux 服务与授权

- 优先使用 systemd；兼容 OpenRC、runit；缺少管理器时使用按需启动的独立守护进程。注册信息保存在 root 保护的服务目录，修复前停止旧进程，确认停止后才替换文件。
- OpenRC/runit 使用各自的原生服务入口。独立守护模式不修改未知发行版的启动脚本；系统重启后，首次开启 TUN 再通过授权启动服务。
- 安装和卸载优先 pkexec，缺少时使用 sudo askpass 或可用的终端；参数通过 argv 传递，不拼接 Linux shell 命令，应用不接触密码。缺少授权器时给出可操作的错误。
- 普通用户不依赖读取 root 进程的 `/proc/<pid>/exe` 判断服务存活，使用本机 Unix socket 的内核 peer credentials 验证 root 服务端；安装/卸载的 root 进程按受保护二进制路径回收实际服务进程。
- Linux 仍要求支持当前 TUN 实现的内核、iproute2、TUN 设备及管理员授权；这不等于容器可以绕过宿主网络权限。

## Linux 系统代理

- GNOME、Cinnamon、MATE 按已安装的 GSettings schema 选择接口；KDE 5/6 使用 KConfig 并通知配置更新。
- 其他桌面使用会话代理：向实际 bash 登录配置、bashrc、zshenv 写入有标记的加载块，并生成 fish 配置。有 systemd 用户管理器时同步其运行期代理环境。
- 会话脚本检查启动时的 boot ID、PID 和进程开始时间，避免已退出客户端在下次打开终端时导出失效代理。系统管理器环境以数据形式解码，绝不执行其输出。
- 快照记录原值与本软件写入值；失败回滚，关闭时仅恢复仍属于本软件的项目。修改用户已有 dotfile 时保留其他内容、权限与符号链接，并在替换前检查并发修改。
- 会话环境只影响新终端和遵循会话代理的应用，不能改变已运行应用继承的环境。界面明确提示此范围；完整接管使用 TUN。

## 已执行的检查

- Windows 宿主共享引擎 workspace 离线 cargo check。
- Windows Tauri 壳层离线 cargo check。
- engine-platform 的 x86_64-apple-darwin、x86_64-unknown-linux-gnu 离线 cargo check。
- 前端 TypeScript、修改文件 ESLint/Prettier、生产资源构建。
- 同步完整桌面前端补丁，包含未跟踪的新增源文件。

这些检查确认当前源码的编译与类型情况。macOS/Linux 原生 GUI、授权、安装包和实际网络行为没有在本轮验收，不能把平台库交叉编译当作真机验证。

## 实现依据

- [Apple libproc 头文件](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/libsyscall/wrappers/libproc/libproc.h)、[lsof 官方手册](https://raw.githubusercontent.com/lsof-org/lsof/master/Lsof.8)：进程路径与端点字段读取。
- [阿里公共 DNS 官方地址](https://help.aliyun.com/zh/dns/free-service-disclaimer)：同提供方 IPv6 地址。
- [systemctl 官方手册](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)：用户管理器运行期环境的读取、写入及输出转义。
- [OpenRC 服务脚本指南](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)：前台守护进程的后台启动与 pidfile 配置。
