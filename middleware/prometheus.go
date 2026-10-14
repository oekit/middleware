package mw

import (
	"context"
	"errors"
	"strconv"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"

	"github.com/cloudwego/hertz/pkg/app"
)

// PrometheusConfig 是 Prometheus 指标采集的配置。
type PrometheusConfig struct {
	// Namespace 是指标名称前缀，如 "fuxi" 会生成 fuxi_requests_total。
	// 留空则默认为 "http"。
	Namespace string

	// ServiceName 用于在指标中添加 service 标签（如 "wechat"、"moyu-server"）。
	// 留空则不添加 service 标签。适用于需要在同一个 Prometheus 中区分多个服务实例的场景。
	ServiceName string

	// SkipPaths 是不需要采集指标的路径列表，如 ["/metrics", "/ping", "/health"]。
	SkipPaths []string

	// Registry 是自定义的 Prometheus 注册器。
	// 传入 nil 则使用 prom.DefaultRegisterer（默认全局 Registry）。
	Registry prom.Registerer

	// Buckets 自定义 Histogram 的桶边界。
	// 留空则使用 prom.DefBuckets（0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 秒）。
	Buckets []float64

	// EnableSizeMetrics 开启请求体/响应体大小的 Histogram 指标。
	// 开启后会注册 <ns>_request_size_bytes 和 <ns>_response_size_bytes。
	EnableSizeMetrics bool
}

// PrometheusMetrics 管理 HTTP 请求的 Prometheus 指标。
//
// 提供的核心指标:
//   - <namespace>_requests_total{method, path, status_code}     — 请求计数 Counter
//   - <namespace>_request_duration_seconds{method, path}        — 请求延迟 Histogram
//   - <namespace>_requests_in_flight{method, path}              — 当前并发请求数 Gauge
//   - <namespace>_request_size_bytes{method, path}              — 请求体大小 Histogram（需 EnableSizeMetrics）
//   - <namespace>_response_size_bytes{method, path}             — 响应体大小 Histogram（需 EnableSizeMetrics）
//
// 当 ServiceName 非空时，所有指标自动添加 service 标签。
// 路径标签使用路由模板（如 /api/user/:id），未匹配路由使用 "unnamed"，避免高基数标签爆炸。
//
// 使用方式:
//
//	pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{
//	    Namespace: "fuxi",
//	    SkipPaths: []string{"/metrics", "/ping"},
//	    Registry:  metrics.Registry,
//	})
//	h.Use(pm.Middleware())
type PrometheusMetrics struct {
	// RequestsTotal 按 method/path/status_code 统计请求总数。
	RequestsTotal *prom.CounterVec

	// RequestDuration 按 method/path 记录请求延迟分布（秒）。
	RequestDuration *prom.HistogramVec

	// RequestsInFlight 记录当前正在处理的并发请求数。
	RequestsInFlight *prom.GaugeVec

	// RequestSize 记录请求体大小分布（字节），仅在 EnableSizeMetrics 时注册。
	RequestSize *prom.HistogramVec

	// ResponseSize 记录响应体大小分布（字节），仅在 EnableSizeMetrics 时注册。
	ResponseSize *prom.HistogramVec

	skipPaths   map[string]bool
	serviceName string // 存储用于标签构造
	enableSize  bool
}

// NewPrometheusMetrics 根据配置创建并注册 Prometheus 指标。
// 创建后调用 .Middleware() 获取 Hertz 中间件函数。
func NewPrometheusMetrics(cfg PrometheusConfig) *PrometheusMetrics {
	ns := cfg.Namespace
	if ns == "" {
		ns = "http"
	}

	reg := cfg.Registry
	if reg == nil {
		reg = prom.DefaultRegisterer
	}

	buckets := cfg.Buckets
	if len(buckets) == 0 {
		buckets = prom.DefBuckets
	}

	hasService := cfg.ServiceName != ""

	// 根据是否有 ServiceName 决定标签
	var pathLabels []string
	var statusLabels []string
	if hasService {
		pathLabels = []string{"service", "method", "path"}
		statusLabels = []string{"service", "method", "path", "status_code"}
	} else {
		pathLabels = []string{"method", "path"}
		statusLabels = []string{"method", "path", "status_code"}
	}

	m := &PrometheusMetrics{
		RequestsTotal: prom.NewCounterVec(
			prom.CounterOpts{
				Name:      "requests_total",
				Namespace: ns,
				Help:      "Total number of HTTP requests.",
			},
			statusLabels,
		),
		RequestDuration: prom.NewHistogramVec(
			prom.HistogramOpts{
				Name:      "request_duration_seconds",
				Namespace: ns,
				Help:      "Duration of HTTP requests in seconds.",
				Buckets:   buckets,
			},
			pathLabels,
		),
		RequestsInFlight: prom.NewGaugeVec(
			prom.GaugeOpts{
				Name:      "requests_in_flight",
				Namespace: ns,
				Help:      "Number of HTTP requests currently being served.",
			},
			pathLabels,
		),
		skipPaths:   make(map[string]bool),
		serviceName: cfg.ServiceName,
		enableSize:  cfg.EnableSizeMetrics,
	}

	if cfg.EnableSizeMetrics {
		m.RequestSize = prom.NewHistogramVec(
			prom.HistogramOpts{
				Name:      "request_size_bytes",
				Namespace: ns,
				Help:      "Size of HTTP request bodies in bytes.",
				Buckets:   prom.ExponentialBuckets(100, 10, 7), // 100B ~ 100MB
			},
			pathLabels,
		)
		m.ResponseSize = prom.NewHistogramVec(
			prom.HistogramOpts{
				Name:      "response_size_bytes",
				Namespace: ns,
				Help:      "Size of HTTP response bodies in bytes.",
				Buckets:   prom.ExponentialBuckets(100, 10, 7), // 100B ~ 100MB
			},
			pathLabels,
		)
	}

	for _, p := range cfg.SkipPaths {
		m.skipPaths[p] = true
	}

	// 用 Register 容忍 AlreadyRegisteredError：DefaultMiddleware 在同一
	// registry 上被调两次曾因 MustRegister 直接 panic（与库内"构造失败
	// 可重试"的基调不符），复用已注册的 collector
	mustRegister := func(c prom.Collector) {
		if err := reg.Register(c); err != nil {
			var are prom.AlreadyRegisteredError
			if !errors.As(err, &are) {
				panic(err)
			}
		}
	}
	mustRegister(m.RequestsTotal)
	mustRegister(m.RequestDuration)
	mustRegister(m.RequestsInFlight)
	if cfg.EnableSizeMetrics {
		mustRegister(m.RequestSize)
		mustRegister(m.ResponseSize)
	}

	return m
}

// Middleware 返回 Hertz 中间件，在每个请求结束后记录 Prometheus 指标。
// SkipPaths 中的路径会被跳过（避免 /metrics 自身被采集）。
//
// 路径标签使用 c.FullPath()（路由模板），未匹配路由使用 "unnamed"。
func (m *PrometheusMetrics) Middleware() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// 使用路由模板而非原始路径，避免高基数标签
		path := c.FullPath()
		if path == "" {
			path = "unnamed"
		}

		if m.skipPaths[path] {
			c.Next(ctx)
			return
		}

		method := string(c.Request.Method())

		// 并发请求数 +1；Dec 与指标记录统一在 defer 中执行：
		// handler panic 穿透中间件时 gauge 不残留、请求仍被计数
		m.RequestsInFlight.WithLabelValues(m.pathLabelValues(method, path)...).Inc()

		// 请求体大小（在 handler 执行前读取）
		var reqSize int
		if m.enableSize {
			reqSize = len(c.Request.Body())
		}

		start := time.Now()
		defer func() {
			duration := time.Since(start).Seconds()

			// 并发请求数 -1
			m.RequestsInFlight.WithLabelValues(m.pathLabelValues(method, path)...).Dec()

			statusCode := strconv.Itoa(c.Response.StatusCode())

			m.RequestsTotal.WithLabelValues(m.statusLabelValues(method, path, statusCode)...).Inc()
			m.RequestDuration.WithLabelValues(m.pathLabelValues(method, path)...).Observe(duration)

			// 请求/响应体大小
			if m.enableSize {
				m.RequestSize.WithLabelValues(m.pathLabelValues(method, path)...).Observe(float64(reqSize))
				m.ResponseSize.WithLabelValues(m.pathLabelValues(method, path)...).Observe(float64(len(c.Response.Body())))
			}
		}()

		c.Next(ctx)
	}
}

// pathLabelValues 构造路径维度的标签值（method, path 或 service, method, path）。
func (m *PrometheusMetrics) pathLabelValues(method, path string) []string {
	if m.serviceName != "" {
		return []string{m.serviceName, method, path}
	}
	return []string{method, path}
}

// statusLabelValues 构造状态维度的标签值（method, path, status_code 或 service, method, path, status_code）。
func (m *PrometheusMetrics) statusLabelValues(method, path, statusCode string) []string {
	if m.serviceName != "" {
		return []string{m.serviceName, method, path, statusCode}
	}
	return []string{method, path, statusCode}
}
