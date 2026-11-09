# Tag 自动构建与发布

推送 `vX.Y.Z` 或 `vX.Y.Z-rc.N` tag 后，`.github/workflows/release.yml` 自动构建六种桌面目标。全部构建及产物核对成功后，自动公开 GitHub Release。无需签名证书或额外发布密钥，发布任务使用 GitHub 提供的 `GITHUB_TOKEN`。

| 平台 | 架构 | 原生 runner | 产物 |
|---|---|---|---|
| Windows | x64 | windows-2022 | NSIS `.exe` |
| Windows | ARM64 | windows-11-arm | NSIS `.exe` |
| macOS | x64 | macos-15-intel | `.dmg`、`.app.tar.gz` |
| macOS | ARM64 | macos-15 | `.dmg`、`.app.tar.gz` |
| Linux | x64 | ubuntu-24.04 | `.deb`、`.AppImage` |
| Linux | ARM64 | ubuntu-24.04-arm | `.deb`、`.AppImage` |

安装包不签名，macOS 不公证。该发布工作流不执行测试、启动应用或安装 TUN 服务。旧的共享引擎测试工作流仅保留手动入口，不再响应分支、PR 或 tag 推送，避免本次提交触发测试。

## 使用

先提交并推送本次完整代码，包含新增的平台模块、摘要文件、工作流与完整桌面前端补丁，再推送版本 tag。例如：

```sh
git tag v0.1.32
git push origin v0.1.32
```

CI 从 tag 中提取版本，在独立构建目录同步 `tauri.conf.json`、桌面 `Cargo.toml` 和 `Cargo.lock` 的版本；不会自动提交或修改远程分支。软件内部版本和安装包版本保持一致，无需为了 tag 手工改三个文件。

在 Actions 页面也可手动运行该工作流，填写已存在的版本 tag；手动运行同样会自动发布。工作流文件需先存在于默认分支，页面才会显示手动入口。

## 构建与发布过程

1. 验证 tag 格式、tag 指向的提交和全部六种官方内核摘要。
2. 按 `DOONA_DESKTOP_REVISION` 检出 doona，应用完整 `doona-lemonvpn-desktop.patch`，安装锁定的 pnpm 与依赖。
3. 每个目标使用原生 runner 和显式 Rust target；Windows 初始化对应 MSVC 环境和 Clang，Linux 安装 GTK/WebKit/AppIndicator 与打包依赖。
4. 下载固定版本官方内核并校验 ZIP/GZip SHA256，构建引擎、服务与桌面壳；始终传递 `--no-sign`，Cargo 和 pnpm 使用锁文件。
5. 静态读取主程序、共享引擎、兼容内核、TUN 服务及 Windows 驱动的 PE/Mach-O/ELF 架构，拒绝资源混用。macOS 应用先归档为 tar.gz，保留可执行权限和符号链接。
6. 每种目标上传独立 Actions Artifact。发布任务等待全部六项成功，复核提交、版本、文件名、大小与 SHA256，汇总 `build-manifest.json` 和 `SHA256SUMS`。
7. 先创建草稿，上传完整文件后再次确认远程 tag 未移动，最后自动公开。带 `-rc.N` 等后缀的 tag 自动标记 prerelease，其他 tag 发布为正式 Release。

任何目标失败都不公开该版本；失败目标保留编译日志。上传失败时草稿保留，可重跑发布任务继续上传。已公开且摘要完全一致的重跑视为完成；摘要不同则拒绝覆盖，使用新 tag 发布。

## 架构补齐

- Windows ARM64：增加官方 ARM64 mihomo ZIP 固定摘要，解压后验证 PE 机器类型；新增 `mihomo-arm64.sha256` 和 `wintun-arm64.sha256`，服务安装器按编译架构分别校验。ARM64 内核或驱动不再与 x64 摘要混用。
- Windows x64/ARM64：均构建并携带对应架构的服务、引擎、内核和 Wintun；Clang 准备只允许在 GitHub Actions runner 上执行，不会在本机自动安装工具。
- macOS/Linux：两种架构分别准备官方内核、构建服务并携带 Geo 数据和许可证；发布前按实际可执行文件头确认目标，不能只靠文件名区分架构。
- macOS：修正 `MACH_TASK_BASIC_INFO` 的字段顺序，当前 RSS 与峰值 RSS 分开读取；同一布局用于 Intel 和 Apple Silicon。

Windows 内核统一名为 `lemonvpn-kernel.exe`，macOS/Linux 为 `lemonvpn-kernel`。

## 本轮检查边界

已执行 Actions 的 actionlint、YAML 解析、JavaScript/PowerShell 语法与格式检查、固定上游提交的补丁应用检查，以及六种目标平台库的编译检查。Windows x64 壳层编译检查通过。

本机 Windows ARM64 完整引擎检查遇到未安装的 ARM64 C/Clang 编译工具；发布工作流已显式准备对应工具链。本机没有运行测试，也没有安装或启动应用/服务、修改当前代理或 TUN。云端六种完整安装包尚需在推送含本工作流的 tag 后实际生成，静态检查不等于云端构建或真机验收已通过。

## 依据

- [GitHub runner 标签](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)：原生 x64/ARM64 构建环境。
- [Tauri GitHub 构建说明](https://v2.tauri.app/distribute/pipelines/github/)：桌面构建依赖与多平台打包。
- [官方 mihomo v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33)：按平台/架构下载固定资源。
- [Apple task_info.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/task_info.h)：MACH_TASK_BASIC_INFO 的实际 ABI。
