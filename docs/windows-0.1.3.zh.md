# Windows x64 0.1.3：TUN、协议兼容与桌面集成

本轮只实现并构建 Windows x64，本机正在运行的旧版本没有被安装包替换。遵照用户要求，未启动新客户端、未运行测试、未切换代理/网卡、未执行睡眠或恢复操作。编译成功不能替代运行验收，本版本不应描述为“所有节点和场景均已验证”。正式发布、签名/自动更新与 Windows ARM64 继续延后。

## 数据面与协议

Windows 安装包新增固定版本 mihomo `v1.19.33`，官方 Windows amd64 compatible 发布包的 SHA256 写入 `pins.env`。构建只下载、校验和打包，不执行该内核。随安装包携带 GPL 许可证和版本/摘要清单；对应上游源码为 <https://github.com/MetaCubeX/mihomo/tree/v1.19.33>。

LemonVPN 共享引擎继续管理配置、订阅、DNS 规则、分流规则、TCP/UDP 组选择和观测 API。普通权限的协议进程以固定出站的回环 SOCKS 监听器承载选定节点，避免其他组的切换改变已作出的路由决定；非回环拨号绑定物理网卡并在新连接时重新探测。

TUN 使用独立的 mihomo/gVisor 桥接进程捕获 IPv4/IPv6 TCP、UDP，劫持 UDP/TCP DNS，启用严格路由和双栈 fake-IP。TUN 连接通过认证的回环 SOCKS 接口回到 LemonVPN，再使用原规则选出直连、阻止或节点。普通 UDP 通过 SOCKS5 UDP ASSOCIATE 转发，具有源端点约束、会话/目的地数量上限、空闲回收及退出取消；UDP 连接与流量进入连接列表和计数。

Windows TUN 使用 `dns-mode: native` 设置虚拟网卡 DNS，配合内部 UDP/TCP DNS 劫持；不启用只放行单一内核映像的全局 53 端口封锁，避免拦截独立引擎的 DNS 转发。TUN 的上游 DNS 经引擎的回环 DNS 转发器，保留现有 DNS 上游和请求规则，支持原始查询、EDNS、TCP 截断回退。fake-IP 由 TUN 内核持有。进程身份归属仍为部分可见，不能把回环入口当作原始应用的进程归属。

原有 VLESS、VMess、Trojan、Shadowsocks、Hysteria2 与 SOCKS5 节点使用兼容内核出站。分享链接转换覆盖 REALITY、Vision、WebSocket、gRPC、HTTP/H2、TLS SNI/ALPN/指纹、SS 2022 与内置 obfs/v2ray 插件、Hysteria2 UDP/Salamander。Clash YAML 节点保存完整代理对象，避免订阅导入丢失传输和插件参数；还可导入内核支持的 HTTP、SSR、TUIC、AnyTLS、Snell、WireGuard、SSH 等 Clash 节点。

“完整”指本轮补上 TCP/DNS 之外的 UDP、IPv6 和上述协议扩展，并非承诺任意协议、传输组合或第三方插件均可使用。具体能力仍受固定上游内核、节点服务端和节点自身 UDP 能力约束。未知分享协议/传输不会静默降级直连。未附带兼容内核的嵌入式宿主仍使用原 Rust 出站和 IPv4 TCP/DNS TUN，移动端/其他系统原生 VPN 适配未在本轮实现。

## Windows 集成

设置新增登录后在托盘启动的开机自启开关，以及 TUN 服务安装/卸载。安装服务时显式请求一次 UAC；主界面和协议进程继续使用普通权限。服务按需启动，用户可关闭 TUN 后卸载；程序卸载时清理本安装的开机自启项并移除服务。

提权服务只接收 start/stop/status、回环端口和随机认证凭证，不能接收任意命令、二进制路径、代理定义或完整内核配置。命名管道拒绝远程客户端，DACL 限制用户 SID，服务核对实际客户端 PID/SID，客户端核对 SCM 中服务 PID。桥接配置与控制 API 凭证只留在服务进程和受保护目录中。

服务程序从包中复制到受保护的 Program Files 目录，校验固定内核和 Wintun 摘要，拒绝重解析点。服务持有引擎进程句柄；引擎退出时终止其 TUN 进程。所有辅助进程由 Job Object 管理，正常关闭先请求撤销 TUN，异常退出由进程所有权释放设备。失败的停止请求向界面报告错误，不能先显示为已关闭。

## 构建产物

运行 `pnpm --dir app build` 生成 `app/src-tauri/target/release/bundle/nsis/LemonVPN_0.1.3_x64-setup.exe`。构建不运行安装程序，不安装服务，不设置开机自启，不启动客户端。仅交付本地构建包，不发布 release 或 ARM64 包。
