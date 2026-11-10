# 地理数据更新修复（0.1.38）

报错 `geodata_update_failed / unexpected end of file` 表示远端在下载或 TLS 握手期间提前关闭连接。代码排查同时发现，原地理数据管理没有完整接入运行时设置：URL 数组未被正确读取，下载出站固定为直连，重启后设置也不会保留。

## 修复范围

- `GET/PATCH /runtime/settings` 接入 `geodata`；来源列表、下载出站、校验开关、自动更新间隔持久化。旧的独立设置接口使用同一实现。
- 内置来源与界面的 MetaCubeX 预设一致，依次尝试 testingcf、GitHub raw、fastly；支持自定义来源和顺序。
- 下载可遵循当前路由、指定策略组或直连。指定出站不可用时明确失败，不降级直连。基础设施域名采用独立引导解析。
- TLS/连接中断使用新连接重试一次；仍失败则尝试下一来源。支持有界重定向并验证 TLS，拒绝 HTTPS 降级和跨源携带认证头。HTTP 长度、分块与文件上限均有检查，截断内容不会作为成功文件写入。
- 默认请求同源路径的 `.sha256sum`。摘要不符拒绝替换；404 表示来源未发布校验文件，此时如实显示“未校验”，不宣称校验成功。
- GeoIP 和 GeoSite 都下载、校验完成后才进入应用阶段。不能备份旧文件时停止；应用失败恢复旧文件和旧 DNS 设置。内容未变不重载。
- 更换数据后强制重新编译源文件中的 GeoIP/GeoSite 条件、规则集中的地理条件，以及 DNS/Fake-IP 策略，避免资源文档未变化时跳过激活。更新后的分类、状态和下一次检查时间通过事件刷新。
- 手动和自动更新共用一个任务入口，禁止并行重复更新；失败后五分钟再检查。默认间隔为 24 小时，可设置 1–168 小时。

## 使用入口

在 **规则 → 地理数据** 选择来源和下载出站，再点击更新。来源的保存会立即启动更新；只修改下载出站或自动更新设置不会立刻下载。

“解析策略、DNS 服务器、解析池”是新的管理资源，尚未建立时显示为空，原配置的默认解析仍保留。可在 **DNS → 解析策略 → 国内外分流** 预览并一次建立服务器、解析池和域名策略。该方案依赖 GeoSite `cn` 分类，因此先完成地理数据更新。

## sublink-worker 可复用内容

提供的 `C:/Users/Lemon/Desktop/sublink-worker/src/config/rules.js` 定义了 18 类规则组合，包括广告、国内、国外、AI、YouTube、Google、Telegram、GitHub、流媒体和游戏等。`ruleUrls.js` 引用远程规则文件，目录内不是完整规则数据库。

LemonVPN 可使用其中 MetaCubeX **MRS** 域名/IP 规则。新增规则集时可以使用对应的直接上游地址，例如：

| 内容 | 地址 | 类型 |
|---|---|---|
| 国内域名 | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs` | domain |
| 国外域名 | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs` | domain |
| 广告域名 | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs` | domain |
| 国内 IP | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs` | ipcidr |

规则集下载出站可按本机网络选择；本次未实际访问这些规则文件。`.srs` 属于其他内核的格式，当前不支持。规则集只定义匹配范围，需在路由或 DNS 策略中选择实际动作；导入后不会自动改变流量。

## 交付边界

仅进行静态检查、编译和未签名 Windows x64 打包。没有运行单元或集成测试、实际下载探测、客户端、安装器或服务，没有修改正在使用的软件、系统代理、TUN 或现有配置。此次代码修改不等于已经在当前网络完成更新验证。
