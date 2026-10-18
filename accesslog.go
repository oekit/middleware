package mw

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/core/chain"
	"github.com/oekit/logx"
	"github.com/oekit/middleware/chainmw"
)

// AccessLogOptions 是访问日志中间件的配置。
type AccessLogOptions struct {
	// SkipPaths 是不需要记录日志的路径列表，如 ["/metrics", "/ping", "/health"]。
	// 健康检查和监控端点通常请求频繁，跳过可减少日志噪音。
	SkipPaths []string

	// RedactPathPrefixes 是需要脱敏的路径前缀列表。命中前缀的路径只保留
	// 前缀本身、其余部分替换为 "/***"——「URL 路径即凭证」的路由
	// （webhook/{token} 类：钉钉/企微 access_token、GitHub webhook 自配路径）
	// 若整条落盘，token 作为调用凭证会随日志进入采集/存储体系
	// （[#12](https://github.com/oekit/middleware/issues/12)）。
	// 前缀按字节匹配；前缀命中的脱敏优先于 path 字段的记录，SkipPaths
	// 判定仍使用原始路径（跳过规则不受脱敏影响）。
	RedactPathPrefixes []string
}

// AccessLogOption 配置 AccessLogMiddleware。
type AccessLogOption func(*AccessLogOptions)

// WithAccessLogSkipPaths 设置不需要记录日志的路径列表。
func WithAccessLogSkipPaths(paths ...string) AccessLogOption {
	return func(o *AccessLogOptions) {
		o.SkipPaths = append(o.SkipPaths, paths...)
	}
}

// WithAccessLogRedactPathPrefixes 设置需要脱敏的路径前缀列表。
// 命中前缀的路径在日志中只保留前缀、其余替换为 "/***"，如前缀
// "/api/v2/webhook/alert" 命中 "/api/v2/webhook/alert/tk-123" 记为
// "/api/v2/webhook/alert/***"。
func WithAccessLogRedactPathPrefixes(prefixes ...string) AccessLogOption {
	return func(o *AccessLogOptions) {
		o.RedactPathPrefixes = append(o.RedactPathPrefixes, prefixes...)
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
//   - 可通过 WithAccessLogRedactPathPrefixes 对「URL 路径即凭证」的路由
//     （webhook/{token} 类）做路径脱敏，token 不落日志
//   - 无参调用即启用默认配置（不跳过任何路径、不脱敏）
//
// # 实现说明（#14）
//
// 本中间件是 chainmw.AccessLog 内核的 Hertz 薄壳：SkipPaths 匹配、路径
// 脱敏、耗时采集收敛在内核单点维护（kitex 侧经 ToKitex 桥接同步获得同等
// 能力），本层只注入 hertz→transport 服务端上下文并保持既有日志格式
// （logger、消息、字段与顺序不变）。下游 handler 可经
// transport.FromServerContext 读取协议无关传输信息。
//
// 使用方式:
//
//	// 默认配置（不跳过任何路径）
//	h.Use(mw.AccessLogMiddleware())
//
//	// 跳过健康检查和指标端点（支持 glob 模式）
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSkipPaths("/metrics", "/ping", "/health", "/internal/*")))
//
//	// webhook 凭证路径脱敏
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert", "/api/v2/task/trigger")))
func AccessLogMiddleware(opts ...AccessLogOption) app.HandlerFunc {
	cfg := newAccessLogOptions(opts...)

	kernel := chainmw.AccessLog(
		chainmw.WithLogger(accessLog),
		chainmw.WithLogMessage("request"),
		chainmw.WithSkipPaths(cfg.SkipPaths...),
		chainmw.WithRedactPathPrefixes(cfg.RedactPathPrefixes...),
		chainmw.WithLogFields(func(_ context.Context, req any, rec chainmw.AccessRecord) []any {
			c, ok := req.(*app.RequestContext)
			if !ok {
				return nil
			}
			return []any{
				"method", string(c.Method()),
				"path", rec.Operation,
				"status", c.Response.StatusCode(),
				"latency_ms", rec.Latency.Milliseconds(),
				"ip", c.ClientIP(),
			}
		}),
	)
	handled := kernel(chain.Handler(func(ctx context.Context, req any) (any, error) {
		if c, ok := req.(*app.RequestContext); ok {
			c.Next(ctx)
		}
		return nil, nil
	}))

	return func(ctx context.Context, c *app.RequestContext) {
		_, _ = handled(newHertzServerContext(ctx, c), c)
	}
}
