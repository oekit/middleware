# Changelog — oekit/middleware

所有 notable 变更记录如下。格式参考 [Keep a Changelog](https://keepachangelog.com/)。

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

## [v0.5.1] — 2026-10-17

- fix(deps): 内部依赖地板全量对齐最新——concurrency v0.5.2、logx v0.5.0、metrics v0.1.6、registry v0.3.1、tracing v0.2.1、pkg v0.9.3；go 维持 1.26.0（tracing/OTel 生态传导）

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
