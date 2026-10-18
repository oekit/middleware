package mw

import (
	"github.com/oekit/middleware/hmw"

	"github.com/cloudwego/hertz/pkg/app"
)

// StackConfig 是中间件栈配置。
type StackConfig struct {
	// SkipPaths 是跳过标准栈处理的路径（如 /metrics、/healthz、OpenAPI）——
	// v0.8.0 起贯通 AccessLog 与 Response（原实现只作用于 AccessLog，
	// 导致 /metrics 被包成 {"code":0,...} 信封，Prometheus 解析失败）。
	SkipPaths []string

	// Prometheus 指标配置（middleware#16，nil = 维持零指标，行为与现状一致）。
	// 非 nil 时 Prometheus 中间件保证挂**栈首**（先于 TraceID 才能精确记录
	// 耗时——手抄两步装配时最常见的就是忘挂栈首或 SkipPaths 两处传参不一致），
	// SkipPaths 单点传入同步作用于指标中间件，杜绝半手抄状态。
	Prometheus *PrometheusConfig

	// DisableResponseWrap 为 true 时栈内不挂 ResponseMiddleware（#18，
	// 「响应体自管」场景一键形态：TraceID → Recovery → AccessLog）。
	//
	// 适用：响应由各 handler 自己构造、与既有 API 契约对齐（如 {code,msg,data}
	// 自定义字段名、null 字段整个不出现等），不希望任何中间件接管响应构造。
	// 不设时裸 JSON（顶层无 "code" 字段）会被包成 {code,data,message,trace_id}；
	// 顶层已含 "code" 的响应本来就原样放行，见 ResponseMiddleware 文档。
	DisableResponseWrap bool

	// AccessLogOptions 透传给栈内 AccessLogMiddleware 的额外选项（追加在
	// SkipPaths 之后）：WithAccessLogSink 落库、WithAccessLogRedactPathPrefixes
	// 脱敏等。SkipPaths 仍由上面的字段单点传入，此处勿重复设置。
	AccessLogOptions []AccessLogOption
}

// DefaultMiddleware 返回标准化中间件栈：TraceID → Recovery → Response → AccessLog。
//
// # 适用边界（#18）
//
// 本栈面向「响应契约统一、由中间件包装」的服务：handler 用 SuccessResp/ErrorResp
// 或返回裸 JSON，ResponseMiddleware 统一成 {code, data, message, trace_id}。
// 如果你的响应体由各 handler 自己构造（与既有 API 对齐、自定义字段名、
// null 字段整个不出现等），不要让中间件接管响应——两条路：
//
//   - 一键：DefaultMiddleware(StackConfig{DisableResponseWrap: true})，得到
//     TraceID → Recovery → AccessLog，响应构造权完全留在 handler；
//   - 手拼：MinimalMiddleware()（TraceID → Recovery）再按需 h.Use(AccessLogMiddleware(...))。
//
// 中间件可按路由组装配——Hertz 的 Use/Group 都接受变参，栈切片直接展开：
//
//	h.Use(mw.DefaultMiddleware(cfg)...)                         // 全局
//	api := h.Group("/api", mw.DefaultMiddleware(cfg)...)        // 仅 /api 子树
//	admin := api.Group("/admin", auth.Required(), auth.ApiKey()) // 组内再叠自家鉴权
//
// 无论哪种形态 Recovery 都是硬性要求：Hertz 无默认 PanicHandler，缺失则 panic 直接断连。
//
// # 指标
//
// 零指标强制（v0.2.0 起 Prometheus 中间件从默认栈拆出）——需要 HTTP 指标时
// 用 NewPrometheusMetrics 显式拼装在栈最前（精确记录请求耗时）：
//
//	pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{
//	    Namespace:   "fuxi",
//	    ServiceName: "fuxi_engine",
//	    SkipPaths:   []string{"/metrics", "/healthz"},
//	    Registry:    emetrics.Registry, // 缺省 nil = ekit 统一注册表
//	})
//	h.Use(pm.Middleware())
//	for _, m := range mw.DefaultMiddleware(mw.StackConfig{
//	    SkipPaths: []string{"/metrics", "/healthz"},
//	}) {
//	    h.Use(m)
//	}
//
// 顺序说明：
//   - TraceID 生成 trace_id 并注入 context（供后续所有中间件与 handler 使用）
//   - Recovery 捕获 handler panic（引擎无默认 PanicHandler，缺失则 panic 直接断连）
//   - Response 包装响应格式（从 context 读取 trace_id 写入响应体；DisableResponseWrap 时不挂）
//   - AccessLog 记录请求日志（含 trace_id；AccessLogOptions 可追加落库 sink / 脱敏）
//
// 只要安全下限、不需要统一包壳/访问日志时用 MinimalMiddleware。
//
// 指标一步形态（middleware#16）：StackConfig.Prometheus 非 nil 时 Prometheus
// 中间件保证挂栈首（精确耗时），SkipPaths 单点传入；nil = 维持零指标。
// 旧两步写法（NewPrometheusMetrics + 手动 h.Use 在前）保留可用。
func DefaultMiddleware(cfg StackConfig) []app.HandlerFunc {
	// 预分配：Prometheus(1) + TraceID(2) + Recovery(1) + Response(1) + AccessLog(1) = 6
	// Recovery 必须在栈内：hertz 引擎级 recover 仅在 PanicHandler 非nil 时
	// 生效而 server.New 不设默认值——无 Recovery 的 handler panic 直接断连
	// （客户端 connection reset，无 500/无统一错误体/无 access log）
	stack := make([]app.HandlerFunc, 0, 6)
	if cfg.Prometheus != nil {
		pcfg := *cfg.Prometheus
		if pcfg.SkipPaths == nil {
			pcfg.SkipPaths = cfg.SkipPaths // SkipPaths 单点传入，杜绝两处不一致
		}
		stack = append(stack, NewPrometheusMetrics(pcfg).Middleware())
	}
	stack = append(stack, hmw.Middleware()...)
	stack = append(stack, RecoveryMiddleware())
	if !cfg.DisableResponseWrap {
		// SkipPaths 贯通全栈（#15）：/metrics、健康探针、OpenAPI 等
		// 不能被 {"code":0,...} 信封包裹的端点，一键栈即可正确服务——
		// Response 命中跳过路径时整请求不包装（原实现只喂给 AccessLog）
		stack = append(stack, ResponseMiddleware(WithSkipPaths(cfg.SkipPaths...)))
	}
	alOpts := make([]AccessLogOption, 0, 1+len(cfg.AccessLogOptions))
	alOpts = append(alOpts, WithAccessLogSkipPaths(cfg.SkipPaths...))
	alOpts = append(alOpts, cfg.AccessLogOptions...)
	stack = append(stack, AccessLogMiddleware(alOpts...))
	return stack
}

// MinimalMiddleware 返回最小安全中间件栈：TraceID → Recovery。
//
// 为不需要 DefaultMiddleware 全家桶（统一响应包壳 / 访问日志）的消费者
// 提供安全下限：trace_id 注入 + panic 恢复，零指标、零日志中间件。
//
// Recovery 是硬性要求——Hertz 无默认 PanicHandler（engine.PanicHandler
// nil 时 ServeHTTP 不挂 recover），netpoll 连接层同样不 recover，
// 缺失 Recovery 的 handler panic 会断连甚至带崩进程。任何自定义中间件
// 栈（包括自行拼装的）都必须包含 RecoveryMiddleware 或直接使用本栈。
//
// 使用方式:
//
//	for _, m := range mw.MinimalMiddleware() {
//	    h.Use(m)
//	}
func MinimalMiddleware() []app.HandlerFunc {
	// 预分配：TraceID(2) + Recovery(1) = 3
	stack := make([]app.HandlerFunc, 0, 3)
	stack = append(stack, hmw.Middleware()...)
	stack = append(stack, RecoveryMiddleware())
	return stack
}
