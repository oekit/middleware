// Package contrib 集中承载 hertz-contrib 社区库的桥接适配。
//
// 每个 ekit 侧桥接只做三件事：类型/Option 别名透传、一行挂载（中间件或
// 路由注册）、ekit 安全默认值（如 KeyAuth 缺省 reject-all validator、
// RegisterDebug 的 token 鉴权 scope）。上游能力与语义以官方文档为准，
// ekit 不重复包装接口。
//
// 与 middleware 根包的边界：根包只保留自研标准中间件栈
// （Recovery/Response/AccessLog/RateLimit/Auth/Prometheus/I18n/TraceID 组装），
// 本包是可选的社区库接入层——import 根包不会传递引入任何 hertz-contrib
// 依赖（2026-09-19 拆分，v0.29.0 breaking：原 mw.Xxx 桥接 API 迁至本包）。
//
// 清单（上游 → ekit API）：
//   - hertz-contrib/cache      → CacheMiddleware
//   - hertz-contrib/jwt        → JWTAuth / JWTGenerateToken / JWTParse
//   - hertz-contrib/keyauth    → KeyAuth
//   - hertz-contrib/csrf       → CSRFMiddleware
//   - hertz-contrib/sessions   → Sessions / RegisterSessions
//   - hertz-contrib/pprof      → RegisterPprof / RegisterDebug(WithPrefix)
//   - swaggo/http-swagger      → SwaggerV2(WithPrefix) 系列
//   - hertz-contrib/gzip       → GzipMiddleware
//   - hertz-contrib/etag       → ETagMiddleware
//   - hertz-contrib/secure     → DefaultCSP（配合 secure.New 使用）
//   - hertz-contrib/basicauth  → BasicAuth（仅适合 HTTPS）
//   - hertz-contrib/reverseproxy → NewSingleHostReverseProxy / MountReverseProxy
//   - hertz-contrib/loadbalance → NewRoundRobinBalancer
//   - hertz-contrib/autotls    → AutoTlsNewTlsConfig / AutoTlsRunWithShutdown 等
//   - hertz-contrib/opensergo  → SentinelServerMiddleware / SentinelClientMiddleware
//   - hertz-contrib/lark-hertz → LarkCardAction / LarkEvent
package contrib
