package contrib

import (
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/etag"
)

// ETagMiddleware 返回 ETag 条件请求中间件。
//
// 基于 hertz-contrib/etag。客户端首次请求获得响应体 + ETag 头；
// 后续请求携带 If-None-Match，若 ETag 未变则返回 304 Not Empty（不传响应体，节省带宽）。
//
// 透传 contrib 的 Option，常用项：
//   - etag.WithWeak()  使用弱 ETag（W/"..."），适用于可接受语义等价的场景
//
// 用法:
//
//	h.Use(contrib.ETagMiddleware())
//	// 或弱 ETag
//	h.Use(contrib.ETagMiddleware(etag.WithWeak()))
func ETagMiddleware(opts ...etag.Option) app.HandlerFunc {
	return etag.New(opts...)
}
