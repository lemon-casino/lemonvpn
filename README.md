# LemonVPN

把 [honk](https://github.com/daeuniverse/honk) 代理引擎与 [doona](https://github.com/Zakkaus/doona) 界面打包为开箱即用的跨平台桌面应用(Windows / macOS / Linux,x86_64 + aarch64)。

- 状态:**规划阶段**(M0 技术验证未启动)
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
