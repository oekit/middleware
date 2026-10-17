package chainmw

import (
	"context"

	"github.com/oekit/core/chain"
	"github.com/oekit/core/transport"
)

// MetadataPropagate 返回 header 透传中间件：把服务端请求头中指定的键
// 复制到响应头（req → resp 方向），供网关/调用方透传租户、灰度标记等
// 元数据。无 transport 服务端上下文时为 no-op。
func MetadataPropagate(keys ...string) chain.Middleware {
	return func(next chain.Handler) chain.Handler {
		return func(ctx context.Context, req any) (any, error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				reqH, replyH := tr.RequestHeader(), tr.ReplyHeader()
				if reqH != nil && replyH != nil {
					for _, k := range keys {
						if v := reqH.Get(k); v != "" {
							replyH.Set(k, v)
						}
					}
				}
			}
			return next(ctx, req)
		}
	}
}
