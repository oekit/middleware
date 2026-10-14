package mw

import (
	"github.com/yi-nology/ekit-metrics"
	"github.com/yi-nology/ekit-middleware/hmw"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/prometheus/client_golang/prometheus"
)

// StackConfig 是中间件栈配置。
type StackConfig struct {
	// ServiceName 用于 Prometheus 指标中的 service 标签。
	ServiceName string

	// Namespace 是 Prometheus 指标前缀，如 "fuxi"。留空默认 "http"。
	Namespace string

	// SkipPaths 是不需要采集指标和记录日志的路径。
	SkipPaths []string

	// Registry 是自定义的 Prometheus 注册器。
	// 留空使用 ekit 统一注册表 metrics.Registry（与 /metrics 端点默认暴露的
	// 是同一个注册表）；需要隔离时可显式传入其他 Registerer。
	Registry prometheus.Registerer
}

// DefaultMiddleware 返回标准化的中间件栈：Prometheus → TraceID → Recovery → Response → AccessLog。
//
// 顺序说明：
//   - Prometheus 最前置，精确记录请求耗时（从入站到出站全程）
//   - TraceID 紧随其后，生成 trace_id 并注入 context（供后续所有中间件与 handler 使用）
//   - Recovery 捕获 handler panic（引擎无默认 PanicHandler，缺失则 panic 直接断连）
//   - Response 包装响应格式（从 context 读取 trace_id 写入响应体）
//   - AccessLog 记录请求日志（含 trace_id）
//
// 用法：
//
//	stack := mw.DefaultMiddleware(mw.StackConfig{
//	    ServiceName: "fuxi_engine",
//	    Namespace:   "fuxi",
//	    SkipPaths:   []string{"/metrics", "/ping", "/healthz"},
//	    Registry:    emetrics.Registry,
//	})
//	for _, m := range stack { h.Use(m) }
func DefaultMiddleware(cfg StackConfig) []app.HandlerFunc {
	reg := cfg.Registry
	if reg == nil {
		// 缺省使用 ekit 统一注册表：/metrics 端点（hertz/metrics）默认暴露的
		// 就是它。此前缺省 prometheus.DefaultRegisterer 会导致标准组装下
		// HTTP 指标无人暴露。
		reg = metrics.Registry
	}

	pm := NewPrometheusMetrics(PrometheusConfig{
		Namespace:   cfg.Namespace,
		ServiceName: cfg.ServiceName,
		SkipPaths:   cfg.SkipPaths,
		Registry:    reg,
	})

	// 预分配：Prometheus(1) + TraceID(2) + Recovery(1) + Response(1) + AccessLog(1) = 6
	// Recovery 必须在栈内：hertz 引擎级 recover 仅在 PanicHandler 非nil 时
	// 生效而 server.New 不设默认值——无 Recovery 的 handler panic 直接断连
	// （客户端 connection reset，无 500/无统一错误体/无 access log）
	stack := make([]app.HandlerFunc, 0, 6)
	stack = append(stack, pm.Middleware())
	stack = append(stack, hmw.Middleware()...)
	stack = append(stack,
		RecoveryMiddleware(),
		ResponseMiddleware(),
		AccessLogMiddleware(WithAccessLogSkipPaths(cfg.SkipPaths...)),
	)
	return stack
}
