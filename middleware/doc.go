// Package mw 提供 CloudWeGo Hertz 服务的自研标准中间件栈。
//
// 所有 enjoydream 后端服务共享此包，保持响应格式、错误处理、可观测性的一致性。
// 本包只含自研核心能力；hertz-contrib 社区库桥接（JWT/Sessions/Swagger/
// CSRF/pprof/Lark 等）见 middleware/contrib 子包，kitex 客户端 metainfo
// 透传见 kitex/kitexmeta。
//
// # 组件总览
//
//   - DefaultMiddleware  — 一键标准栈（Prometheus → TraceID → Recovery → Response → AccessLog）
//   - ResponseMiddleware — 统一 JSON 响应格式 {code, data, message, trace_id}
//   - traceid/hmw.Middleware — trace_id 生成/透传（middleware/traceid/hmw 子包）
//   - AccessLogMiddleware — 请求访问日志（method, path, status, latency, ip）
//   - PrometheusMetrics  — Prometheus HTTP 指标采集（请求数 / 延迟 / 并发 / 体积）
//   - RecoveryMiddleware — panic recovery（可选 SentryReporter 监控钩子）
//   - RateLimitMiddleware — 令牌桶限流（默认按 RemoteAddr 分键）
//   - BearerTokenAuth   — Bearer Token 认证（Authorizer 鉴权钩子）
//   - I18n              — Accept-Language 国际化（LangFromCtx / Translate）
//   - Fail / ErrorResp / SuccessResp — handler 层统一错误处理与响应写入
//
// # 快速接入
//
// 在 main.go 中注册中间件（推荐用 DefaultMiddleware 一键注册，或手动按顺序）：
//
//	h := server.Default(...)
//	stack := mw.DefaultMiddleware(mw.StackConfig{ServiceName: "svc"})
//	for _, m := range stack { h.Use(m) }
//	// 顺序: Prometheus → TraceID → Recovery → Response → AccessLog
//
// # CORS 与安全响应头
//
// CORS 与安全响应头直接使用 hertz-contrib 社区实现（功能更完整、维护更活跃），
// ekit 不自研。推荐的严格 CSP 策略见 middleware/contrib.DefaultCSP()。
//
//	import (
//	    "github.com/hertz-contrib/cors"
//	    "github.com/hertz-contrib/secure"
//	    contrib "github.com/oekit/middleware/contrib"
//	)
//
//	// CORS（如需前端直连）
//	h.Use(cors.New(cors.Config{
//	    AllowOrigins: []string{"*"},
//	    AllowMethods: []string{"GET","POST","PUT","DELETE","OPTIONS","PATCH"},
//	    AllowHeaders: []string{"Origin","Content-Type","Authorization","X-Trace-Id","X-Request-Id"},
//	}))
//
//	// 安全响应头（CSP / 防点击劫持 / nosniff / HSTS）
//	h.Use(secure.New(
//	    secure.WithContentSecurityPolicy(contrib.DefaultCSP()),
//	    secure.WithFrameDeny(true),
//	    secure.WithContentTypeNosniff(true),
//	    secure.WithReferrerPolicy("no-referrer"),
//	))
//
// 如需 Prometheus 指标：
//
//	metrics.Init("my-service")
//	pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{
//	    Namespace: "myapp",
//	    SkipPaths: []string{"/metrics", "/ping"},
//	    Registry:  metrics.Registry,
//	})
//	h.Use(pm.Middleware())
//	r.GET("/metrics", hertz.MetricsHandler())  // 暴露 /metrics 端点
//
// 如需请求体/响应体大小指标：
//
//	pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{
//	    Namespace:         "myapp",
//	    Registry:          metrics.Registry,
//	    EnableSizeMetrics: true,  // 开启 request_size_bytes / response_size_bytes
//	})
//
// 如需在指标中添加 service 标签（多服务共享同一 Prometheus 时）：
//
//	pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{
//	    Namespace:   "myapp",
//	    ServiceName: "wechat",  // 所有指标自动添加 service="wechat" 标签
//	    Registry:    metrics.Registry,
//	})
//
// # 提供的指标
//
//   - <namespace>_requests_total{method, path, status_code}     — 请求计数
//   - <namespace>_request_duration_seconds{method, path}        — 请求延迟（秒）
//   - <namespace>_requests_in_flight{method, path}              — 当前并发请求数
//   - <namespace>_request_size_bytes{method, path}              — 请求体大小（需 EnableSizeMetrics）
//   - <namespace>_response_size_bytes{method, path}             — 响应体大小（需 EnableSizeMetrics）
//
// 路径标签使用路由模板（如 /api/user/:id），未匹配路由使用 "unnamed"，避免高基数标签爆炸。
//
// 在 handler 中写入响应：
//
//	mw.SuccessResp(c, userData)
//	mw.ErrorResp(c, 400, "参数错误")
//	mw.SuccessRespMsg(c, nil, "创建成功")
//
// 在 service 层返回业务错误：
//
//	return nil, errors.NewNotFoundError("项目不存在")
//	return nil, errors.NewBizError(1001, "余额不足")
//
// # 响应格式约定
//
// 所有 API 返回统一的 JSON 结构：
//
//	{
//	  "code": 0,          // 0=成功, 非0=业务错误码（400/404/500 等）
//	  "data": ...,        // 业务数据，失败时为 null
//	  "message": "success",
//	  "trace_id": "a1b2c3d4e5f6"  // 链路追踪 ID，用于日志关联
//	}
//
// ResponseMiddleware 会自动拦截 handler 返回的裸 JSON（不含 code 字段），
// 包装成上述格式。如果 handler 已通过 SuccessResp/ErrorResp 写入了带 code 的响应，
// 中间件不会重复包装。
package mw
