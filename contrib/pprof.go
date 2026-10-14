package contrib

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/route"
	hertzcontribpprof "github.com/hertz-contrib/pprof"

	"github.com/yi-nology/ekit-logx"
)

// debugLog 是 debug 端点组件专用 logger(空 token 等配置告警)。
var debugLog = logx.Delegating("middleware-debug")

// PprofDefaultPrefix 是 hertz-contrib/pprof 默认暴露路径,业务如需隐藏可
// 通过 WithPprofPrefix 改写,例如挂到 "/internal/debug/pprof" 避免被公网
// 扫描到。
const PprofDefaultPrefix = "/debug/pprof"

// PprofOption 配置 RegisterPprof(纯 pprof 桥接,无鉴权无 fgprof)。
type PprofOption func(*pprofConfig)

type pprofConfig struct {
	prefix string
}

// WithPprofPrefix 自定义 pprof URL 前缀,默认 /debug/pprof。
func WithPprofPrefix(prefix string) PprofOption {
	return func(c *pprofConfig) {
		if prefix != "" {
			c.prefix = prefix
		}
	}
}

// PprofInfo 返回 RegisterPprof 实际生效的注册信息,供业务侧日志/健康检查
// 等场景使用。
type PprofInfo struct {
	Prefix string
}

// RegisterPprof 在 h *server.Hertz 上注册 11 个 pprof 端点(无鉴权无 fgprof)。
//
// 与 hertz-contrib/pprof.Register 等价,仅做 Option 包装,让 ekit 调用方
// 享受函数选项 + 统一默认值。
//
// 官方依据:https://github.com/cloudwego/hertz#extensions 与
// https://github.com/hertz-contrib/pprof(README)。
//
// 注意:这会向 h 注册 11 条 GET/POST 路由(/, /cmdline, /profile, /symbol,
// /trace, /allocs, /block, /goroutine, /heap, /mutex, /threadcreate),
// 务必仅在内部网络或鉴权之后暴露;公网部署请改用 RegisterDebug(支持
// WithDebugAuth 鉴权)。
func RegisterPprof(h *server.Hertz, opts ...PprofOption) PprofInfo {
	cfg := &pprofConfig{prefix: PprofDefaultPrefix}
	for _, opt := range opts {
		opt(cfg)
	}
	hertzcontribpprof.Register(h, cfg.prefix)
	return PprofInfo{Prefix: cfg.prefix}
}

// DebugOption 配置 RegisterDebug/RegisterDebugGroup。
type DebugOption func(*debugConfig)

type debugConfig struct {
	Prefix       string
	EnableAuth   bool
	Token        string
	EnableFgprof bool
}

// newDebugOptions 构造默认 debugConfig,Prefix 由调用方决定。
func newDebugOptions(opts ...DebugOption) *debugConfig {
	c := &debugConfig{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithDebugPrefix 自定义 pprof URL 前缀,默认 /debug/pprof。
func WithDebugPrefix(prefix string) DebugOption {
	return func(c *debugConfig) {
		if prefix != "" {
			c.Prefix = prefix
		}
	}
}

// WithDebugAuth 启用鉴权:请求必须带 query ?token=<value>(或 header
// X-Debug-Token: <value>)才允许访问 pprof 端点。适合公网暴露前的最后
// 一道简单防线;生产推荐走前置 gateway。
//
// ⚠️ 空 token 不会启用鉴权,并输出一条 Warn 日志 — 典型踩坑是
// WithDebugAuth(os.Getenv("PPROF_TOKEN")) 在 env 未设置时静默裸奔,
// 日志就是给这个场景的信号(2026-09-05 复审修复)。
func WithDebugAuth(token string) DebugOption {
	return func(c *debugConfig) {
		if token != "" {
			c.EnableAuth = true
			c.Token = token
			return
		}
		debugLog.Warn("WithDebugAuth called with empty token; debug endpoints will be UNAUTHENTICATED")
	}
}

// WithDebugFgprof 额外注册 fgprof 端点(非阻塞 profiling,避免长采样把
// STW 拖到秒级)。
//
// 官方依据:https://github.com/hertz-contrib/pprof/tree/main(README 提到
// fgprof 是独立 API,需要单独调用 FgprofRegister)。
func WithDebugFgprof() DebugOption {
	return func(c *debugConfig) {
		c.EnableFgprof = true
	}
}

// debugAuthGuard 简单 query/header token 鉴权中间件。
func debugAuthGuard(token string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		got := c.Query("token")
		if got == "" {
			got = c.Request.Header.Get("X-Debug-Token")
		}
		// 常量时间比较,防时序侧信道枚举 token(2026-09-06 复审加固;
		// subtle.ConstantTimeCompare 对长度不等立即返回,长度本身不泄露)
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}

// RegisterDebug 在 h *server.Hertz 上注册带鉴权 + fgprof 选项的 pprof 端点。
//
// 与 RegisterPprof 区别:支持鉴权(防止公网被扫到)和 fgprof(非阻塞 CPU
// profiling)。默认无鉴权、无 fgprof,业务按需 WithDebugAuth/WithDebugFgprof。
//
// 用法:
//
//	h := server.New()
//	RegisterDebug(h,
//	    WithDebugPrefix("/internal/pprof"),
//	    WithDebugAuth(os.Getenv("PPROF_TOKEN")),
//	    WithDebugFgprof(),
//	)
//
// 官方依据:https://github.com/hertz-contrib/pprof + hertz 官方扩展列表
// https://github.com/cloudwego/hertz#extensions。
func RegisterDebug(h *server.Hertz, opts ...DebugOption) {
	cfg := newDebugOptions(opts...)
	if cfg.Prefix == "" {
		cfg.Prefix = PprofDefaultPrefix
	}
	// 鉴权 scope(2026-09-05 复审修复:原实现 h.Use(guard) 挂到 root group,
	// hertz 在路由注册时快照 group handlers,guard 会泄漏到之后注册的
	// 全部业务路由;曾实测 RegisterDebug 后注册的 /biz 无 token 也 401)。
	// 改为把 guard 挂在独立子 group 上,pprof/fgprof 端点经
	// RouteRegister/FgprofRouteRegister 注册进该 group,鉴权精确限定在
	// debug 端点,h.Use 的调用顺序不再产生副作用。
	if cfg.EnableAuth {
		g := h.Group("")
		g.Use(debugAuthGuard(cfg.Token))
		hertzcontribpprof.RouteRegister(g, cfg.Prefix)
		if cfg.EnableFgprof {
			hertzcontribpprof.FgprofRouteRegister(g)
		}
		return
	}
	hertzcontribpprof.Register(h, cfg.Prefix)
	if cfg.EnableFgprof {
		hertzcontribpprof.FgprofRegister(h)
	}
}

// RegisterDebugGroup 在已有 router group 上注册 debug 端点,可选 token 鉴权。
//
// 用法:
//
//	admin := h.Group("/admin")
//	RegisterDebugGroup(admin, "/debug", "secret-token")
//
// token 可省略,省略时不启用鉴权(等同于 RegisterPprofWithGroup)。
func RegisterDebugGroup(g *route.RouterGroup, prefix string, token ...string) {
	cfg := &debugConfig{Prefix: prefix}
	if len(token) > 0 && token[0] != "" {
		cfg.EnableAuth = true
		cfg.Token = token[0]
	}
	if cfg.Prefix == "" {
		cfg.Prefix = PprofDefaultPrefix
	}
	// guard 只进 debug 子 group：直接 g.Use 会把鉴权泄漏到业务 group
	// 之后注册的路由（admin.POST("/reset") 被迫要求 debug token）
	if cfg.EnableAuth {
		sub := g.Group(cfg.Prefix)
		sub.Use(debugAuthGuard(cfg.Token))
		hertzcontribpprof.RouteRegister(sub, "")
		return
	}
	hertzcontribpprof.RouteRegister(g, cfg.Prefix)
}
