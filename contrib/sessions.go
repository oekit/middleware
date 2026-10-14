package contrib

import (
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	hertzcontribsessions "github.com/hertz-contrib/sessions"
)

// Session 是 hertz-contrib/sessions 的 Session 类型别名,业务拿到
// Session 后可调 Get/Set/Save/Delete/AddFlash 等 API,不需要 import
// 完整的 hertz-contrib/sessions 路径。
type Session = hertzcontribsessions.Session

// Store 是 hertz-contrib/sessions 的 Store 类型别名,业务按需 import
// cookie/redis 子包构造具体 store。
type Store = hertzcontribsessions.Store

// SessionOptions 是 hertz-contrib/sessions 的 Options 类型别名,业务
// 在 Session.Options(...) 调用时使用。
type SessionOptions = hertzcontribsessions.Options

// Sessions 注册 session 中间件,把请求 cookie 解析为 hertz-contrib
// sessions.Session 注入到 handler context。
//
// 用法:
//
//	import "github.com/hertz-contrib/sessions/cookie"
//	import contrib "github.com/yi-nology/ekit-middleware/contrib"
//
//	store := cookie.NewStore([]byte("secret"))
//	h.Use(contrib.Sessions("mysession", store))
//	h.GET("/hello", func(ctx context.Context, c *app.RequestContext) {
//	    s := mw.DefaultSession(c)
//	    s.Set("hello", "world")
//	    s.Save()
//	    c.JSON(200, utils.H{"hello": s.Get("hello")})
//	})
//
// 官方依据:https://github.com/hertz-contrib/sessions + hertz 官方扩展
// 列表 https://github.com/cloudwego/hertz#extensions。
func Sessions(name string, store Store) app.HandlerFunc {
	// 上游 Sessions/SessionsMany 已 deprecated,New/Many 为等价替代
	return hertzcontribsessions.New(name, store)
}

// SessionsMany 注册多个 session(同一个 store,不同 cookie 名),业务
// 通过 DefaultMany(c, "name") 取具体 session。
func SessionsMany(names []string, store Store) app.HandlerFunc {
	return hertzcontribsessions.Many(names, store)
}

// RegisterSessions 跟 Sessions 等价,只是用 h *server.Hertz 直接调,
// 跟 RegisterPprof/RegisterDebug 风格统一。
func RegisterSessions(h *server.Hertz, name string, store Store) {
	h.Use(Sessions(name, store))
}

// RegisterSessionsMany 跟 SessionsMany 等价,Server 风格。
func RegisterSessionsMany(h *server.Hertz, names []string, store Store) {
	h.Use(SessionsMany(names, store))
}

// DefaultSession 透传上游 Default(c),从 handler context 取默认 session。
func DefaultSession(c *app.RequestContext) Session {
	return hertzcontribsessions.Default(c)
}

// DefaultSessionMany 透传上游 DefaultMany(c, name),从 handler context
// 取指定 name 的 session。
func DefaultSessionMany(c *app.RequestContext, name string) Session {
	return hertzcontribsessions.DefaultMany(c, name)
}
