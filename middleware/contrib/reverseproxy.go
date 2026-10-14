package contrib

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	hertzconfig "github.com/cloudwego/hertz/pkg/common/config"
	hertzreverseproxy "github.com/hertz-contrib/reverseproxy"
)

// ReverseProxy 是 hertz-contrib/reverseproxy ReverseProxy 的 type alias,
// 业务用 mw.ReverseProxy 直接拿上游结构体类型做高级定制(自定义
// Director / Transport / ErrorHandler 等)。
//
// 官方依据:https://github.com/hertz-contrib/reverseproxy
type ReverseProxy = hertzreverseproxy.ReverseProxy

// NewSingleHostReverseProxy 构造单 host 反向代理(常用:网关层把
// 内部服务反向代理到外部端点,或本地开发代理到生产 API)。
//
// 内部基于 hertz client 实现,自动透传请求头 + 响应头,无需业务
// 写 Director。
//
// 用法:
//
//	rp, _ := mw.NewSingleHostReverseProxy("http://internal-service:8080")
//	h.NoRoute(func(c context.Context, ctx *app.RequestContext) {
//	    rp.ServeHTTP(c, ctx)
//	})
//
// 进阶定制:
//
//	rp.SetDirector(func(req *protocol.Request) {
//	    // 改写 path,例如剥前缀
//	    req.URI().SetPath(strings.TrimPrefix(string(req.URI().Path()), "/api"))
//	})
//	rp.SetClient(myHertzClient) // 自定义 client,带鉴权/熔断
func NewSingleHostReverseProxy(target string, options ...hertzconfig.ClientOption) (*ReverseProxy, error) {
	return hertzreverseproxy.NewSingleHostReverseProxy(target, options...)
}

// MountReverseProxy 把 rp 挂到 h 的 NoRoute 上(catch-all 反向代理)。
// 业务也可自己 h.GET/POST/Handle 单独挂。
// ⚠️ h.NoRoute 是赋值语义(hertz 未透出当前 handler,无法检测冲突):
// 多次调用或与业务自设 NoRoute 混用时后者静默失效——一个 engine 只挂一个。
func MountReverseProxy(h *server.Hertz, rp *ReverseProxy) {
	h.NoRoute(func(ctx context.Context, c *app.RequestContext) {
		rp.ServeHTTP(ctx, c)
	})
}
