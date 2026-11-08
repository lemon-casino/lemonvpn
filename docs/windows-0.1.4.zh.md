# Windows x64 0.1.4

本轮修复服务通信并调整桌面侧栏。按用户要求只执行静态编译与打包，不启动新客户端或服务，不运行测试，不切换网络或代理，不替换正在使用的软件；运行恢复情况尚未验收。正式发布与 ARM64 继续延后。

## TUN 服务通信

0.1.3 使用 `PIPE_NOWAIT` 轮询命名管道，将 `ConnectNamedPipe` 非零返回值当作客户端已连接。微软文档说明该模式下非零返回也可能只表示管道可供连接，并明确建议使用 overlapped I/O 实现异步通信。现已改为 `PIPE_WAIT` 配合 `FILE_FLAG_OVERLAPPED`、事件和 `GetOverlappedResult`，超时/停止时取消并回收未完成操作，再释放缓冲区。

服务复用同一个安全管道实例，不在每次请求后销毁并用 `FIRST_PIPE_INSTANCE` 重建，避免上一个客户端句柄尚未释放时退出服务。消息仍有长度上限、请求期限和响应确认，保留 SID/PID 校验和只允许固定 TUN 操作的边界。

新通信协议使用 v2 管道。客户端通过已安装服务和随包服务的文件摘要识别旧版；发现旧版时直接提示修复，避免继续调用旧通信实现。安装、修复、卸载和版本状态均位于 **设置 → TUN 模式**，开机自启保留在 Windows 集成。已有服务需要用户在方便时安装新包并点击安装/修复，以更新 Program Files 中的服务副本；仅构建不会更新该副本。

参考：[ConnectNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)、[Named Pipe Server Using Overlapped I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o)。

## 侧栏与小工具

桌面侧栏改为紧凑的常用、网络与工具两组导航，保留全部原有页面入口；顶部增加连接现有接口的系统代理/TUN 快捷开关，底部独立设置入口。配色沿用当前主题，选中页面使用整行背景。

桌面小工具默认展开并嵌入侧栏。对现有桌面配置只迁移一次嵌入/展开/可见状态，保留用户的工具内容，之后的收起、浮动和隐藏选择仍会保存。“取消嵌入”和“收起/展开小工具”放入三个点菜单；原先单独的图标按钮在桌面端移除。

产物：`app/src-tauri/target/release/bundle/nsis/LemonVPN_0.1.4_x64-setup.exe`。
