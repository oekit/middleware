package mw

import (
	"github.com/oekit/middleware/hmw"

	"github.com/cloudwego/hertz/pkg/app"
)

// StackConfig 是中间件栈配置。
type StackConfig struct {
	// SkipPaths 是不需要记录日志的路径（如 /healthz、/metrics）。
	SkipPaths []string
}

// DefaultMiddleware 返回标准化中间件栈：TraceID → Recovery → Response → AccessLog。
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
//   - Response 包装响应格式（从 context 读取 trace_id 写入响应体）
//   - AccessLog 记录请求日志（含 trace_id）
//
// 只要安全下限、不需要统一包壳/访问日志时用 MinimalMiddleware。
func DefaultMiddleware(cfg StackConfig) []app.HandlerFunc {
	// 预分配：TraceID(2) + Recovery(1) + Response(1) + AccessLog(1) = 5
	// Recovery 必须在栈内：hertz 引擎级 recover 仅在 PanicHandler 非nil 时
	// 生效而 server.New 不设默认值——无 Recovery 的 handler panic 直接断连
	// （客户端 connection reset，无 500/无统一错误体/无 access log）
	stack := make([]app.HandlerFunc, 0, 5)
	stack = append(stack, hmw.Middleware()...)
	stack = append(stack,
		RecoveryMiddleware(),
		ResponseMiddleware(),
		AccessLogMiddleware(WithAccessLogSkipPaths(cfg.SkipPaths...)),
	)
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
