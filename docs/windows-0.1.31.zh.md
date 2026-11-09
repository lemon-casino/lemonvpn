# Windows 0.1.31 本机构建

2026-11-09：重新生成 Windows x64 NSIS 安装包，未签名，未运行测试或启动安装程序。构建没有安装、替换、重启当前使用中的客户端、引擎或服务。

## 内容

- 纳入最新共享引擎、Windows 平台层和桌面前端资源。
- 托盘菜单增加 TUN 模式：显示窗口、系统代理、TUN 模式、引擎日志、退出；系统代理与 TUN 回读实际状态。
- 设置增加退出应用入口；平台补齐源码与边界见 [实现记录](desktop-platform-completion.zh.md)。此安装包只面向 Windows x64。
- 官方 mihomo ZIP、GeoIP/GeoSite 和 Wintun 资源按现有固定摘要核对；随包内核名为 lemonvpn-kernel.exe。

## 产物

- 路径：`app/src-tauri/target/release/bundle/nsis/LemonVPN_0.1.31_x64-setup.exe`
- 大小：33,287,548 字节（31.75 MiB）。
- SHA256：`bd1023a2e401e444cf7b0441307d32bc19253d8588333e47fabff3fcbdda9a46`
- 同目录提供 `.exe.sha256` 校验文件。

命令：`pnpm --dir app build --bundles nsis --no-sign --ci`。Cargo 构建并发限制为 2，并使用已缓存依赖离线编译。未执行测试、冒烟、代理/TUN 切换、服务安装或任何运行中引擎请求。

构建成功后静态读取新主程序的 PE 架构、版本与 TUN 托盘资源；主程序内部版本为 0.1.31。比对确认原有客户端、引擎、内核进程仍在运行，安装目录对应文件 SHA256 未改变。日志与构建记录位于 `app/src-tauri/target/windows-0.1.31-build/`。

本轮产物仅完成构建与静态核对；未进行安装或运行验收。签名、正式发布及 ARM64 继续延后。
