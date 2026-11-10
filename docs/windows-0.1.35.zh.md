# Windows 0.1.35：真实代理延迟与过期节点显示

2026-11-09，本地构建 Windows x64 NSIS 安装包。没有安装或替换当前运行的客户端，没有切换系统代理或 TUN。

## 行为变化

- 默认“真实代理延迟（HTTPS）”通过节点完成 TLS 证书验证，请求 `www.gstatic.com/generate_204`，仅预期的 HTTP 204 响应判为成功。端口打开、任意字节、403、502 等不能作为代理可用的证据。
- 节点列表把失败结果显示为 `-1`；成功的 TCP 端口检测只显示“仅端口连通”。其他检测失败也显示 `-1`，这个数值本身不能区分到期、断网或服务故障。
- 修复旧的端口成功记录覆盖真实代理失败，以及自动双栈探测后残留另一地址族成功记录的问题。显式测试单一地址族时保留另一个地址族的数据。
- WS 节点按真实传输配置显示 WS，避免统一显示 TCP。
- 到期授权由 miaomiaowu 和 Agent 执行。客户端在完成新的真实代理检测后显示当前状态；手动选择组不会仅凭以前的延迟数值获知服务端刚修改的期限。

## 构建复现

前端使用固定的 `DOONA_DESKTOP_REVISION`，先应用 `patches/doona-lemonvpn-desktop.patch`，再应用 `patches/doona-lemonvpn-proxy-health.patch`。本地准备脚本和 GitHub 构建均包含第二个补丁，防止只修改被忽略的 doona 工作目录导致重建丢失改动。干净前端已验证两个补丁可依次应用，并核对全部 7 个变更文件。

```powershell
pnpm --dir app build --bundles nsis --no-sign --ci
```

构建使用现有缓存依赖，Cargo 并发为 2；未签名。原先在工作区中已修改的 sidecar 二进制已按构建前摘要恢复，安装目录四个程序文件摘要保持不变。

## 验证

- 162 项前端相关测试、7 项 Rust 探测测试、TypeScript 检查通过。
- Tauri 主程序、前端及引擎发布构建完成，主程序文件版本为 0.1.35。
- 实际验证三台服务器上的 VLESS、VMess、Trojan：9 个原过期节点全部不可用，9 个有效授权对照全部返回真实 HTTPS 延迟，18 个节点均正确标记为 WS。
- 实际代理测试使用隔离的数据目录和随机回环端口，不修改当前客户端配置；结果记录见本地 `app/src-tauri/target/expiry-latency-20261109/live-engine-report.json`。
- 既有完整 i18n 扫描存在历史未翻译文字、未使用词条和繁体中文缺失词条，本次没有声称完整扫描通过。新增词条按既有键顺序写入。

## 安装包

- 文件：`app/src-tauri/target/release/bundle/nsis/LemonVPN_0.1.35_x64-setup.exe`
- 大小：33357466 字节。
- SHA256：`8c8c29ab8e85c261bac603dfa6190c1a57c0ecb599241bc70c0b49f743035f2b`。
- 同目录有 `.exe.sha256` 校验文件。本次未创建发布标签或发布 GitHub Release。
