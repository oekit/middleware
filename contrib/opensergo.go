package contrib

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/protocol"
	opensergosentinel "github.com/hertz-contrib/opensergo/sentinel/adapter"
)

// SentinelServerMiddleware 透传 hertz-contrib/opensergo/sentinel/adapter
// 的 SentinelServerMiddleware,启用 hertz 服务端 sentinel 限流/熔断。
//
// 官方依据:https://github.com/hertz-contrib/opensergo (sentinel adapter
// for hertz) + OpenSergo 微服务治理 spec。
//
// 用法:
//
//	h.Use(contrib.SentinelServerMiddleware(
//	    mw.WithSentinelServerResourceExtractor(func(ctx context.Context, c *app.RequestContext) string {
//	        return string(c.Path())  // 按 URL path 限流
//	    }),
//	    mw.WithSentinelServerBlockFallback(func(ctx context.Context, c *app.RequestContext) {
//	        c.AbortWithStatus(429)
//	    }),
//	))
//
// 业务需先调 sentinel.InitWithConfig 或 sentinel.InitDefault 初始化
// sentinel 规则(流控/熔断/系统保护等),ekit 不替业务写规则。
func SentinelServerMiddleware(opts ...SentinelServerOption) app.HandlerFunc {
	return opensergosentinel.SentinelServerMiddleware(opts...)
}

// SentinelClientMiddleware 透传 opensergosentinel.SentinelClientMiddleware,
// 启用 hertz 客户端限流。
func SentinelClientMiddleware(opts ...SentinelClientOption) client.Middleware {
	return opensergosentinel.SentinelClientMiddleware(opts...)
}

// SentinelServerOption 是 opensergosentinel.ServerOption 的 type alias。
type SentinelServerOption = opensergosentinel.ServerOption

// SentinelClientOption 是 opensergosentinel.ClientOption 的 type alias。
type SentinelClientOption = opensergosentinel.ClientOption

// WithSentinelServerResourceExtractor 透传 WithServerResourceExtractor。
// 转接器:ekit 提供显式函数签名,业务不需要 import sentinel 子包。
// 用法见 SentinelServerMiddleware 注释。
func WithSentinelServerResourceExtractor(fn func(ctx context.Context, c *app.RequestContext) string) SentinelServerOption {
	return opensergosentinel.WithServerResourceExtractor(fn)
}

// WithSentinelServerBlockFallback 透传 WithServerBlockFallback。
func WithSentinelServerBlockFallback(fn func(ctx context.Context, c *app.RequestContext)) SentinelServerOption {
	return opensergosentinel.WithServerBlockFallback(fn)
}

// WithSentinelClientResourceExtractor 透传 WithClientResourceExtractor
// (上游签名 fn(ctx, req, resp) string — 同时拿到 request/response 决定资源名)。
func WithSentinelClientResourceExtractor(fn func(ctx context.Context, req *protocol.Request, resp *protocol.Response) string) SentinelClientOption {
	return opensergosentinel.WithClientResourceExtractor(fn)
}

// WithSentinelClientBlockFallback 透传 WithClientBlockFallback
// (上游签名 fn(ctx, req, resp, err) error — 业务写自定义降级逻辑)。
func WithSentinelClientBlockFallback(fn func(ctx context.Context, req *protocol.Request, resp *protocol.Response, blockError error) error) SentinelClientOption {
	return opensergosentinel.WithClientBlockFallback(fn)
}

// RegisterSentinelServer 业务用 server 直接挂载的便捷 helper(等同
// SentinelServerMiddleware + h.Use)。
func RegisterSentinelServer(h *server.Hertz, opts ...SentinelServerOption) {
	h.Use(SentinelServerMiddleware(opts...))
}
