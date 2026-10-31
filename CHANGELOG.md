## [v0.13.5] — 2026-10-31

- fix(contrib/jwt): 签发与验签必须同源——密钥轮换后自签 token 曾被自家 401；cache 冻结后 opts 不再被改写

## [v0.13.4] — 2026-10-29

- build: 依赖地板对齐——concurrency 抬到 v0.23.2

## [v0.13.3] — 2026-10-28

- fix(prometheus): 同名 collector 必须**复用已注册的实例**——此前只吞掉 `AlreadyRegisteredError`，把新建的（未注册的）collector 留在字段里 ⇒ 同一 Registry + namespace 下构造第二个 `PrometheusMetrics` 时它的全部指标都不会出现在采集端，而构造函数却「成功」返回 ⇒ 故障完全静默。代码注释写着「复用已注册的 collector」，实现并没有复用

## [v0.13.2] — 2026-10-23

- docs: 补 v0.5.1 旁支版本事实声明——该版本不在主线版本线上（发布时刻晚于 v0.6.0），当前请用主线版本 v0.13.1+（#46）

## [v0.13.1] — 2026-10-22

- build(deps): larksuite/oapi-sdk-go/v3 v3.12.1 → v3.12.2（零代码改动）

## [v0.13.0] — 2026-10-22

### feat(accesslog)：内建日志可关闭/改道——只采不写或注入宿主 logger（[#38](https://github.com/oekit/middleware/issues/38)）
- `mw.AccessLogMiddleware` 此前**总是自己写一行日志**（`logx.Delegating("access")` 写死），
  宿主想用自己的 logger 输出同一份记录就会**双写**——想用库的
  `WithAccessLogRedactPathPrefixes`（防「URL 路径即凭证」路由把 token 写进日志）
  与 `WithAccessLogSkipPaths`，又不能接受库那行输出，只能整段手搓、库的 redaction
  能力用不上
- 新增两个入口（issue 给的两个方案都做了）：
  - `mw.WithAccessLogSilent() AccessLogOption`——**只采不写**：不写任何日志
    （访问日志本身与 sink 失败/panic 的告警日志都不写），**采集行为完全不变**：
    SkipPaths 判定、路径脱敏、sink 调用（时机与顺序不变）、panic 请求的记录
    产出（`AccessRecord.Panic=true`）与按原值重抛都照常——所以库的脱敏与跳过
    能力在静默下依然可用，宿主拿 sink 或自己的采集逻辑输出记录即可
  - `mw.WithAccessLogLogger(l logx.Logger) AccessLogOption`——把内建日志改道到
    宿主 logger（消息 `request` 与字段 method/path/status/latency_ms/ip 不变），
    宿主不必再写一份；`nil` 被忽略（保持默认 logger）。宿主用 zap 等非 logx
    后端时自行实现 `logx.Logger` 适配，或用 `logx.SetDefault` 整体换后端
- 内核 `chainmw` 新增同构的 `chainmw.WithSilent()`（kitex 经 `ToKitex` 桥接
  同步获得）；根包薄壳按 `Silent`/`Logger` 装配进内核选项
- 与 `WithAccessLogLogger` 叠加时静默优先：注入的 logger 只用于 sink 告警，
  静默下也不写
- 行为变更：无参调用与既有配置的输出**逐字不变**（默认仍用内建 Delegating
  logger、仍写日志）——新增能力均为 opt-in
- 测试：内核 2 例（静默不写日志 + sink/脱敏照常、skip 与 panic 记录照常）+
  根包 4 例（静默下采集不变、sink 故障静默且不影响响应、静默下 panic 记录
  Panic=true、注入 logger 只写一条且字段不变、选项装配）

## [v0.12.1] — 2026-10-19

- build: 矩阵内依赖地板对齐（align_floors 不动点）：concurrency v0.5.4 → v0.17.0、logx v0.6.0 → v0.7.0、core v0.7.0 → v0.9.2、pkg v0.11.0 → v0.15.1

## [v0.12.0] — 2026-10-18

### fix(accesslog)：panic 请求同样产出访问记录（[#20](https://github.com/oekit/middleware/issues/20)）
- 此前栈序 Recovery → AccessLog 下 handler panic 直接穿过 AccessLog 到达外层
  Recovery——**状态码、耗时、路径全部无记录**，最需要观测的请求反而零记录，
  故障时段 access log 完全失明
- `chainmw.AccessLog` 内核在 **panic 恢复点**产出
  `AccessRecord{Panic: true, Err: "panic: <摘要>"}`——记 Warn 日志（Hertz 薄壳
  status 按 Recovery 缺省 500，字段含 `panic=true`）、照常喂 `WithAccessLogSink`
  （落库场景 panic 请求同样留痕）——随后**按原值重新抛出**，外层 Recovery
  （或框架自身 recover）照常处理；kitex 经 ToKitex 桥接同步获得
- 根包 `mw.AccessRecord` 新增 `Panic bool` 字段；`SkipPaths` 命中的 panic 不记录
  （跳过 = 不记录口径不变）；v0.11.0 CHANGELOG 的「panic 零访问记录」行为澄清
  自本版起废止
- 测试：内核 1 例（恢复点记录 + 重抛 + skip 不触发）+ 端到端 2 例
  （DefaultMiddleware 下 panic 记录 Status=500/Panic=true 且响应仍为统一错误体）

## [v0.11.0] — 2026-10-18

### feat(accesslog)：落库 sink + 响应自管一键形态 + 适用边界文档（[#18](https://github.com/oekit/middleware/issues/18)）
- **`WithAccessLogSink(AccessSink)`**：访问记录旁路消费者——同一份记录
  `AccessRecord{Method, Path, Status, Latency, ClientIP, UserAgent, TraceID}`
  （与日志字段同源，Path 已脱敏）交给调用方自己的 access_log 表 / 审计上报；
  `c *app.RequestContext` 同传，可读鉴权中间件注入的 userId 等业务键（仅本次调用内
  有效，异步落库只持有 rec）。sink 返回 error 或 panic 都只记 Warn、**绝不影响主链路**；
  多个 sink 彼此隔离按序调用；`SkipPaths` 命中不触发（跳过 = 不记录，日志与落库口径一致）
- **`chainmw.WithSink`** 内核级同构能力（`AccessSink func(ctx, req any, rec AccessRecord) error`，
  `runSink` 隔离 error/panic）——根包 Hertz 薄壳逐 sink 注册进内核，kitex 经 ToKitex
  桥接同步获得（一份逻辑两端跑，#14 口径）
- **`StackConfig.DisableResponseWrap`**：栈内不挂 ResponseMiddleware，得到
  TraceID → Recovery → AccessLog——「响应体由各 handler 自己构造、与既有 API 契约对齐」
  的服务一键形态；**`StackConfig.AccessLogOptions`** 透传 sink/脱敏等额外选项
  （SkipPaths 仍单点传入）
- 文档（doc.go / README / DefaultMiddleware godoc）新增「适用边界」：本栈面向响应契约
  统一的服务；响应自管请用 DisableResponseWrap 或 MinimalMiddleware + AccessLog；
  ResponseMiddleware 只包顶层无 `code` 的裸 JSON、已含 `code` 原样放行；中间件可按
  路由组装配（Hertz `Use`/`Group` 接受变参，栈切片直接 `...` 展开，组内再叠自家 JWT/ApiKey）
- 既有行为澄清（测试钉住）：panic 请求在栈序 Recovery → AccessLog 下无访问记录
  （panic 穿过 AccessLog 直达外层 Recovery），与 sink 无关

## [v0.10.0] — 2026-10-18

### feat(stack)：指标一步形态 `StackConfig.Prometheus`（[#16](https://github.com/oekit/middleware/issues/16)）
- `DefaultMiddleware(StackConfig{Prometheus: &PrometheusConfig{...}})`——非 nil 时
  Prometheus 中间件**保证挂栈首**（先于 TraceID 精确记录耗时），SkipPaths 单点传入
  （未显式设置时同步全栈 SkipPaths，杜绝「两处传参不一致」「忘挂栈首」两类手抄漂移）
- nil = 维持零指标，行为与现状逐位一致；旧两步写法（NewPrometheusMetrics + 手动
  h.Use 在前）保留可用
- 10+ 服务各自手抄的两步装配（含已实际观察到的漂移）可收敛为一行

## [v0.9.0] — 2026-10-18

### Added（[#14](https://github.com/oekit/middleware/issues/14)：主栈复用 chain 内核，一份逻辑两端跑）

- **`chainmw.Recovery` 新中间件**（transport 无关内核）：panic 捕获为
  `*chain.PanicError` + Error 日志 + panic 隔离的监控上报钩子
  （`WithRecoveryReporter`；钩子内部 panic 被隔离记日志、上报丢弃，不影响
  原始 panic 语义）。kitex 经 `kitex/chainmw.ToKitex` 桥接即同步获得同等
  能力——此前链侧只有 core/chain.Recovery（无日志、reporter 无 panic 隔离，
  而第三方监控 SDK 恰是最可能 panic 的代码）；`WithRecoveryLogFields`/
  `WithRecoveryLogger` 支持框架桥接定制日志
- **`chainmw.AccessLog` 增强**：`WithSkipPaths`（glob，按原始 Operation 匹配、
  不受脱敏影响）、`WithRedactPathPrefixes`（webhook/{token} 类路径脱敏）、
  `WithLogMessage`/`WithLogFields`（自定义日志消息与字段构建器）；日志升级
  为 `Ctx*` 系（自动携带 trace_id）
- **`chainmw.RedactPath` 导出**：路径前缀脱敏原语（原根包私有实现上收，
  #12 语义不变）

### Changed（内部重构，对外行为零变化）

- 根包 `RecoveryMiddleware`/`AccessLogMiddleware` 改为 chainmw 内核薄壳：
  panic 捕获/日志/上报隔离、SkipPaths 匹配、脱敏、耗时采集收敛到 chainmw
  单点维护；SkipPaths、SentryReporter、响应格式、日志 logger/消息/字段与
  顺序、公开 API 签名全部不变（reporter 隔离日志文案与 v0.8.0 前一致）
- 根包内置 hertz→core/transport 服务端适配器（与 hertz/transportx 同构；
  不能 import hertz/transportx——hertz/chainmw 反向依赖本仓成环）；经
  AccessLogMiddleware 的下游 handler 现可经 `transport.FromServerContext`
  读协议无关传输信息（纯增益，ctx 新增一个键）

### Fixed

- docs: CHANGELOG v0.7.2/v0.8.0 版本头补齐（heredoc 事故残留的 `## [` 坏头
  与 `vv0.1.7` 笔误）

## [v0.8.0] — 2026-10-18

- fix(mw): `StackConfig.SkipPaths` 贯通 ResponseMiddleware（#15）——原实现只喂给 AccessLog，「一键标准栈」把 /metrics 包成 {"code":0,...} 信封导致 Prometheus 解析失败；SkipPaths 语义更新为「跳过标准栈处理的路径」（引擎级功能测试钉住）
- fix(deps): metrics v0.1.7、tracing v0.2.2 地板对齐（零代码改动）

## [v0.7.2] — 2026-10-17

- fix(deps): logx 地板 v0.5.0 → v0.6.0、registry 地板 v0.4.0 → v0.4.1（零代码改动）

## [v0.7.0] — 2026-10-17

### Added（go-kratos 对齐）
- `chainmw` 新子包：transport 感知的框架无关中间件（基于 core/chain + core/transport）——
  `AccessLog`（Kind/Operation/耗时/错误，经 transport 上下文）、`MetadataPropagate`（req→resp
  header 透传）。一份实现可经 hertz/kitex 桥接跨协议复用；与根包 mw（Hertz 栈）互补
### Changed
- 依赖升级：registry v0.4.0（SPI 包提升至模块根）、core v0.7.0

## [v0.6.2] — 2026-10-17

- pkg 地板 v0.11.0；concurrency 地板 v0.5.4

## [v0.6.1] — 2026-10-17

- fix(deps): pkg 地板 v0.9.3 → v0.10.0（拆分版，零代码改动）；concurrency 地板 v0.5.2 → v0.5.3

## [v0.6.0] — 2026-10-17

- **fix(ratelimit)**：默认 KeyFunc 去端口——`RemoteAddr().String()` 含端口，
  限流桶按 TCP 连接而非按客户端：直连场景客户端新建连接即新桶（绕过限流），
  代理场景全体折叠进网关连接（[#13](https://github.com/oekit/middleware/issues/13)）。
  保留直连地址语义（防伪造 XFF 造无限桶）不变；代理拓扑按真实客户端 IP
  限流仍走 `engine.SetClientIPFunc` + 自定义 `KeyFunc`（godoc 已写明）
- **feat(accesslog)**：新增 `WithAccessLogRedactPathPrefixes`——「URL 路径即
  凭证」的路由（webhook/{token} 类）命中前缀后日志只记前缀、其余替换为
  `/ ***`，token 不再落日志；SkipPaths 判定不受脱敏影响
  （[#12](https://github.com/oekit/middleware/issues/12)）
- docs(hmw)：README 明确 `MinimalMiddleware`（TraceID → Recovery）为最小
  安全栈——hertz 无默认 PanicHandler，只挂非 Recovery 栈的消费方 handler
  panic 即进程崩溃（[#10](https://github.com/oekit/middleware/issues/10)）

## [v0.5.1] — 2026-10-17

- fix(deps): 内部依赖地板全量对齐最新——concurrency v0.5.2、logx v0.5.0、metrics v0.1.6、registry v0.3.1、tracing v0.2.1、pkg v0.9.3；go 维持 1.26.0（tracing/OTel 生态传导）

> **⚠️ 本版本不在主线版本线上**（旁支版本，事实声明见 [oekit/middleware#46](https://github.com/oekit/middleware/issues/46)）
>
> - 本仓主线自 **v0.5.0**（「仓库重置后的首个版本（旧版本号 v0.1.0–v0.4.0 已清空重做）」）起算；**v0.5.1 不是该主线上的版本**。
> - 发布时刻 **2026-10-17 16:52:47 +0800**，**晚于**同线的 `v0.6.0`（16:08:29）——版本号在时间线上回退，系发布时的笔误。
> - 内容为一次依赖地板对齐（自带 `registry v0.3.1` 地板——该版本仍有 `registry/registry`），现路径 `github.com/oekit/middleware` 可安装可编译。
> - **当前请使用主线版本**（`v0.13.1+`）。
> - tag **保留不删**：已发布 tag 在 Go module proxy 上有缓存，删 tag / 重推 = 已缓存消费方集体中毒。
> - 跨仓门禁口径见 [oekit/matrix-tools#88](https://github.com/oekit/matrix-tools/issues/88)（发布序列倒挂检测）。

## [v0.5.0] — 2026-10-17

仓库结构重置后的首个版本（历史与旧版本号 v0.1.0–v0.4.0 已清空重做，从 v0.5.0 起算）。

### 目录结构

```
github.com/oekit/middleware              # package mw — 自研标准中间件栈（模块根）
├── contrib/                             # package contrib — hertz-contrib 桥接
└── hmw/                                 # package hmw — trace_id 注入
```

- **核心包 `mw` 提升到模块根**：import 从 `github.com/oekit/middleware/middleware`
  改为 `github.com/oekit/middleware`（包名仍为 `mw`）
- **删除重复层** `middleware/contrib/`（与根 `contrib/` 字节级重复的副本）
- **删除废弃转发层** `middleware/traceid/hmw/`（原 Deprecated 兼容层）

### 能力面（自 ekit 拆分保留）

- `DefaultMiddleware` — 一键标准栈：TraceID → Recovery → Response → AccessLog（零指标强制）
- `MinimalMiddleware` — 最小安全栈：TraceID → Recovery
- `ResponseMiddleware` — 统一 JSON 响应 `{code, data, message, trace_id}`，
  支持 `WithSkipPaths` / `WithSkipPrefixes` 声明式跳过 + `SkipResponseWrap` 逃生舱
- `RecoveryMiddleware` — panic recovery（可选 SentryReporter 钩子）
- `AccessLogMiddleware` — 请求访问日志
- `PrometheusMetrics` — HTTP 指标（显式拼装，不在默认栈）
- `RateLimitMiddleware` / `RateLimitMiddlewareWithLimiter` — 令牌桶限流
- `SheddingMiddleware` — CPU 自适应降载（opt-in，不入默认栈）
- `BearerTokenAuth` — Bearer Token 认证（Authorizer 鉴权钩子）
- `I18n` — Accept-Language 国际化
- `Fail` / `FailWithData` / `ErrorResp` / `SuccessResp` — 统一错误出口与响应写入
- `hmw.Middleware` — trace_id 生成/透传/白名单校验
- `contrib` — JWT/Sessions/Swagger/CSRF/pprof/Gzip/ETag/BasicAuth/ReverseProxy/Sentinel/Lark 等桥接

### 迁移（从旧路径）

| 旧 | 新 |
|---|---|
| `github.com/oekit/middleware/middleware` | `github.com/oekit/middleware` |
| `github.com/oekit/middleware/middleware/contrib` | `github.com/oekit/middleware/contrib` |
| `github.com/oekit/middleware/middleware/traceid/hmw` | `github.com/oekit/middleware/hmw` |
