package mw

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/yi-nology/ekit-logx"
	"github.com/yi-nology/ekit-pathx"
)

// AccessLogOptions 是访问日志中间件的配置。
type AccessLogOptions struct {
	// SkipPaths 是不需要记录日志的路径列表，如 ["/metrics", "/ping", "/health"]。
	// 健康检查和监控端点通常请求频繁，跳过可减少日志噪音。
	SkipPaths []string
}

// AccessLogOption 配置 AccessLogMiddleware。
type AccessLogOption func(*AccessLogOptions)

// WithAccessLogSkipPaths 设置不需要记录日志的路径列表。
func WithAccessLogSkipPaths(paths ...string) AccessLogOption {
	return func(o *AccessLogOptions) {
		o.SkipPaths = append(o.SkipPaths, paths...)
	}
}

func newAccessLogOptions(opts ...AccessLogOption) *AccessLogOptions {
	cfg := &AccessLogOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

var accessLog = logx.Delegating("access")

// AccessLogMiddleware 记录每个 HTTP 请求的访问日志。
//
// 特性:
//   - 使用 scoped logger 输出结构化日志，自动携带 trace_id
//   - 可通过 WithAccessLogSkipPaths 跳过健康检查等高频路径（支持 glob 模式）
//   - 无参调用即启用默认配置（不跳过任何路径）
//
// 使用方式:
//
//	// 默认配置（不跳过任何路径）
//	h.Use(mw.AccessLogMiddleware())
//
//	// 跳过健康检查和指标端点（支持 glob 模式）
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSkipPaths("/metrics", "/ping", "/health", "/internal/*")))
func AccessLogMiddleware(opts ...AccessLogOption) app.HandlerFunc {
	cfg := newAccessLogOptions(opts...)

	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Request.URI().Path())
		if pathx.MatchesPath(cfg.SkipPaths, path) {
			c.Next(ctx)
			return
		}

		start := time.Now()
		c.Next(ctx)

		latency := time.Since(start)
		statusCode := c.Response.StatusCode()
		method := string(c.Method())
		clientIP := c.ClientIP()

		accessLog.CtxInfo(ctx, "request",
			"method", method,
			"path", path,
			"status", statusCode,
			"latency_ms", latency.Milliseconds(),
			"ip", clientIP,
		)
	}
}
