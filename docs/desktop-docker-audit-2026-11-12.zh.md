# 桌面端与 Docker 代码复核（2026-11-12）

> 历史复核记录。2026-11-15 的候选部署、UDP/DNS 增强与实际验证见 [迁移验收台账](mihomo-migration-readiness.zh.md)，后续状态以该台账为准。

本轮从 e369c8b 的源码检查开始；不运行测试、不启动任何客户端/内核/服务/容器、不读写正在使用的应用配置、不修改宿主网络，不替换已有安装文件。

## 已修复

| 范围 | 缺陷及处理 |
|---|---|
| 桌面故障恢复 | 原来仅检测子进程退出，进程仍在但本机接口失去响应不会恢复。现连续三次本机健康失败才回收本程序子进程并进入既有重启预算；正常健康后清零。其他程序响应同端口时不接管。健康读取有总时限。 |
| 桌面路由归属 | 重试用尽后的清理分支补上 owned_datapath 和隔离运行判断，防止无路由接管权的实例执行兜底清理。 |
| Docker 启动身份 | 原来 /health 200 就放行；现检查 entrypoint 记录的 PID 和 lemonvpn-PID 实例。停止时也先验证身份再发 TUN 关闭请求。 |
| Docker 端口一致性 | 原来引擎端口可配，nginx/healthcheck 却固定 18080。现生成运行期 nginx 配置，复用一个健康检查脚本，并校验引擎/共享端口。 |
| Linux / Docker 路由 | 移除容器入口和辅助清理脚本按优先级/表号的盲删。LAN 规则带协议标记，正常退出按本次添加的地址族和 CIDR 清理；Linux broker 首次启用前检测捕获槽位是否被占用。 |
| Docker IPv6 LAN | 局域网出口保护补齐 IPv6，并记录与回收本次添加的规则。 |
| Docker 退出 | tini 先通知 supervisor，按顺序停止子进程；EXIT trap 覆盖初始化异常退出；等待有上限，compose 清理时限增至 35 秒。 |
| Docker 日志 | 删除无限 append 的临时引擎/访问日志，改为 stderr 与 FIFO 转发至 Docker 日志驱动，沿用 compose 轮转策略。 |
| Docker 共享预置 | 凭据和端口校验与共享引擎一致；reseed 可把已保存共享设为关闭，正常重启仍保留界面保存值。 |
| 共用控制 API | 限制管理请求 Host 为回环地址，阻止公共域名重绑定访问；拦截非受信浏览器的简单 POST JSON 写入。nginx 重写上游 Host 并覆盖 UI authority 标记，保留正文为空的合法 UI 操作和 TLS 前端反代兼容性。 |

## 继续复核补充

| 范围 | 缺陷及处理 |
|---|---|
| Docker 卡死恢复 | 仅 `wait -n` 子进程不足以发现引擎仍存活但无响应；新增独立 watchdog，每 10 秒检查本机 PID/实例，连续三次失败才触发正常退出清理，由 compose 重启策略恢复。 |
| TUN 映射持久化 | 根服务把内核工作目录放在 `/var/lib/lemonvpn/Service/runtime`，原先没有数据卷。两个 TUN compose 新增独立 `tun-state` 命名卷，目录保持 root/700，容器重建可保留开启持久化后的 Fake-IP 缓存。普通 `/data` 无权修改管理员配置。 |
| Docker 发布 | CI 固定 tag 对应提交，修正手动构建的镜像 revision；合并前检查远端 tag 未移动，按两种架构的 digest 发布。`latest` 单独串行，旧版本/预发布不再回退它；默认不执行冒烟，只保留手动明确勾选入口。 |

## 检查结果

- Windows x64 共享引擎 workspace 与桌面壳层：`cargo check --locked --offline`。
- engine-platform：Linux x64/ARM64、macOS x64/ARM64、Windows ARM64 编译检查。
- Docker Shell：`bash -n` 语法检查；没有执行脚本。
- 新增发布辅助脚本：`node --check`；Docker workflow 和三个 compose：严格 YAML 语法解析。没有执行发布脚本或触发 Actions。
- 未执行任何测试、安装包或 Docker 构建；编译检查不等于容器/各平台运行验收。

## 保留的边界

- `docker run` 部署 TUN 需显式挂载内核状态卷；现有已丢失的临时映射无法恢复。没有使用新 compose 的旧部署不会自动获得持久化。
- 未标记且归属不明的旧捕获规则不会自动删除；需要先确认归属。此选择避免恢复流程破坏其他 VPN 的网络。
- Docker bridge/sidecar 的宿主端口映射不能随容器内 API 热修改；Web UI 改共享端口后仍需同步 compose。界面枚举的是容器地址。
- 本轮复核时局域网共享仍为 TCP-only。2026-11-15 已补齐 SOCKS UDP ASSOCIATE 并完成候选机核验；代理 IPv6 入站仍待后续实现。
- 控制 API 仍不提供独立身份认证；Docker 必须通过带 Basic Auth 的 nginx 管理入口，不能直接公开引擎端口。
- 本轮源码未提交、推送、打 tag 或更新现有安装包；未接触预先已有改动的 Windows sidecar 二进制。
