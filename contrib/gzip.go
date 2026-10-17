package contrib

import (
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/gzip"
)

// GzipMiddleware 返回 gzip 响应压缩中间件。
//
// 基于 hertz-contrib/gzip，压缩等级通过 level 指定（gzip.DefaultCompression 使用默认）。
// 透传 contrib 的 Option，常用项：
//   - gzip.WithExcludedExtensions([]string{".pdf", ".mp4"})  跳过二进制扩展名
//   - gzip.WithExcludedPaths([]string{"/metrics"})           跳过指定路径
//   - gzip.WithDecompressFn(gzip.DefaultDecompressHandle)    同时解压请求体
//
// 注意: gzip 会劫持响应写入器，建议仅在确有压缩需求的路由组上注册，而非全局。
//
// 用法:
//
//	h.Use(contrib.GzipMiddleware(gzip.DefaultCompression))
//	// 或排除二进制文件
//	h.Use(contrib.GzipMiddleware(gzip.DefaultCompression,
//	    gzip.WithExcludedExtensions([]string{".pdf", ".mp4", ".png"}))
func GzipMiddleware(level int, opts ...gzip.Option) app.HandlerFunc {
	return gzip.Gzip(level, opts...)
}
