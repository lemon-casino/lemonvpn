# Windows x64 0.1.24：调整侧栏顺序并核查链式代理

左侧“常用”第二行改为“订阅、策略”，与之前位置对调；第一行仍为“活动、状态”。路由地址和各页面内容不变。

## 链式代理核查

结论：Mihomo 内核支持通过 `dialer-proxy` 配置链式代理，但当前 LemonVPN 尚未接通用户可配置的多跳代理。

- `engine-core/src/compat.rs::render_node` 会移除节点的 `dialer-proxy` 字段；`base_config` 将单个节点映射为独立的内部代理和 SOCKS 监听端口，没有生成代理依赖关系。
- `engine-core/src/share.rs::parse_clash` 只提取订阅中的 `proxies` 节点，不导入 `proxy-groups`；因此完整 Clash 配置中的链路关系不会作为策略组保留。
- `engine-core/src/config.rs::select_member_for` 从策略组选择一个节点；`final_outbound` 是没有选出成员时的后备出站，不表示下一跳。
- 前端策略配置提供节点筛选、选择策略、默认成员和后备出站，没有前置代理或多跳顺序设置。
- 连接数据中的 `chain` 是选择结果的路径信息；TUN 到本地 Rust 路由器的桥接也不表示已支持用户定义的远程多跳链路。

后续若接入，应完整处理节点或策略组引用、内部名称映射、循环和失效引用校验、TCP/UDP 协议能力、热更新与连接展示，不能只保留 `dialer-proxy` 一个字段。

官方配置说明：<https://wiki.metacubex.one/config/proxies/dialer-proxy/>。本项目固定的 v1.19.33 版本也已在 `BasicOption.NewDialer` 中实现该参数：<https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/base.go#L182-L205>。

本版仅调整导航与桌面版本号，并记录代码核查结论，不改变代理链路行为。构建 Windows x64 安装包，不运行测试、不安装或启动客户端，不修改当前配置、代理、TUN 或服务。

安装包：`app/src-tauri/target/release/bundle/nsis/LemonVPN_0.1.24_x64-setup.exe`。
