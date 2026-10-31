package contrib

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/hertz-contrib/cache"
	"github.com/hertz-contrib/cache/persist"
)

// resetCacheState 重置全局 cacheState,测试隔离。

// TestCache_DefaultReturnsMiddleware 验证 Cache() 默认参数返回有效 middleware。
func TestCache_DefaultReturnsMiddleware(t *testing.T) {
	resetCacheState()

	mw := Cache()
	if mw == nil {
		t.Fatal("Cache() should return non-nil middleware")
	}
	// 第二次调用返回相同函数值(sync.Once)
	mw2 := Cache()
	_ = mw2
}

// TestCache_WithExpiration 应用 WithCacheExpiration。
func TestCache_WithExpiration(t *testing.T) {
	resetCacheState()

	_ = Cache(WithCacheExpiration(5 * time.Minute))
	if globalCacheState.opts.expiration != 5*time.Minute {
		t.Errorf("expiration = %v, want 5m", globalCacheState.opts.expiration)
	}
}

// TestCache_WithPrefix 应用 WithCachePrefix。
func TestCache_WithPrefix(t *testing.T) {
	resetCacheState()

	_ = Cache(WithCachePrefix("my-svc"))
	if globalCacheState.opts.prefix != "my-svc" {
		t.Errorf("prefix = %q, want my-svc", globalCacheState.opts.prefix)
	}
}

// TestCache_WithStore 应用 WithCacheStore(注入自定义 store)。
func TestCache_WithStore(t *testing.T) {
	resetCacheState()

	store := persist.NewMemoryStore(30 * time.Second)
	_ = Cache(WithCacheStore(store))
	if globalCacheState.opts.store != store {
		t.Fatal("expected store to be the injected one")
	}
}

// TestCache_DefaultExpirationApplied 验证默认过期时间 1m 应用。
func TestCache_DefaultExpirationApplied(t *testing.T) {
	resetCacheState()

	_ = Cache()
	if globalCacheState.opts.expiration != time.Minute {
		t.Errorf("default expiration = %v, want 1m", globalCacheState.opts.expiration)
	}
	if globalCacheState.opts.prefix != "ekit" {
		t.Errorf("default prefix = %q, want ekit", globalCacheState.opts.prefix)
	}
}

// TestCache_IgnoreQueryOrder 应用 WithIgnoreQueryOrder。
func TestCache_IgnoreQueryOrder(t *testing.T) {
	resetCacheState()

	_ = Cache(WithIgnoreQueryOrder())
	if !globalCacheState.opts.ignoreOrder {
		t.Fatal("expected ignoreOrder = true")
	}
}

// TestCache_AllOptionsCombined 验证多选项组合不 panic。
func TestCache_AllOptionsCombined(t *testing.T) {
	resetCacheState()

	strategy := func(_ context.Context, _ *app.RequestContext) (bool, cache.Strategy) {
		return true, cache.Strategy{}
	}
	onHit := func(_ context.Context, _ *app.RequestContext) {}
	onMiss := func(_ context.Context, _ *app.RequestContext) {}

	mw := Cache(
		WithCacheExpiration(10*time.Minute),
		WithCachePrefix("test-svc"),
		WithCacheStore(persist.NewMemoryStore(60*time.Second)),
		WithCacheStrategyByRequest(strategy),
		WithOnHitCache(onHit),
		WithOnMissCache(onMiss),
		WithIgnoreQueryOrder(),
	)
	if mw == nil {
		t.Fatal("Cache with all options should return non-nil middleware")
	}
}

func resetCacheState() {
	globalCacheState = cacheState{}
}

// TestCache_FrozenInstanceKeepsOptsConsistent 钉住「opts 始终等于实际生效配置」。
//
// 缺陷形态（2026-10-31 实测）：cache 是全局单例，实例一旦构造就**冻结**
// （strategy/expiration/prefix/store 全部不再重建）。但原实现仍把二次调用
// 的 option **写进 opts** ⇒ opts.prefix 变成 "second"，而实际用的还是
// "first" ⇒ **状态与实际行为不一致**。
//
// 为什么要在意：opts 是「当前配置」的唯一记录，任何读 opts 的代码
// （新增功能、日志、诊断）都会拿到**错的**值。
//
// 本测试断言：冻结后二次调用 Cache(改 prefix) ⇒ opts.prefix **不变**。
func TestCache_FrozenInstanceKeepsOptsConsistent(t *testing.T) {
	resetCacheState()

	_ = Cache(WithCachePrefix("first-prefix"))
	if got := globalCacheState.opts.prefix; got != "first-prefix" {
		t.Fatalf("首次构造后 opts.prefix = %q，期望 first-prefix", got)
	}

	// 二次调用改 prefix —— 实例已冻结，这些 option 永远不会生效。
	_ = Cache(WithCachePrefix("second-prefix"))

	if got := globalCacheState.opts.prefix; got != "first-prefix" {
		t.Errorf("★ 冻结后 opts.prefix = %q，期望仍为 first-prefix —— "+
			"opts 必须始终等于实际生效的配置（已生效的是 first-prefix）", got)
	}
}

// TestCache_FrozenInstanceReturnsSameHandler 钉住「二次调用返回同一个 handler」。
//
// 冻结语义下，二次调用 Cache() 返回的 handler 必须与首次**完全一致**
// （含 GET 守卫与凭证放行逻辑）⇒ 否则两次注册的路由行为会分叉。
//
// 判据用**GET 是否被缓存**（可观测）：带守卫的 handler 对 GET 缓存、
// 裸 mw 对 GET 也缓存但**不分方法** ⇒ 差异要用「POST 是否被缓存」观测。
// 两次 POST 各发两次 ⇒ 带守卫时 handler 被调 2 次；裸 mw 时只调 1 次
// （第二次命中缓存）。
func TestCache_FrozenInstanceReturnsSameHandler(t *testing.T) {
	resetCacheState()

	first := Cache()
	second := Cache()
	if first == nil || second == nil {
		t.Fatal("Cache() 应返回非 nil handler")
	}

	newSrv := func(mw app.HandlerFunc) (*server.Hertz, *atomic.Int32) {
		srv := server.New(
			server.WithHostPorts("127.0.0.1:0"),
			server.WithDisablePrintRoute(true),
		)
		var hits atomic.Int32
		srv.POST("/p", mw, func(_ context.Context, c *app.RequestContext) {
			hits.Add(1)
			c.JSON(200, map[string]string{"ok": "true"})
		})
		return srv, &hits
	}

	// 首次注册：POST 两次 ⇒ 守卫放行 ⇒ handler 被调 2 次。
	h1, hits1 := newSrv(first)
	ut.PerformRequest(h1.Engine, "POST", "/p", nil)
	ut.PerformRequest(h1.Engine, "POST", "/p", nil)
	if got := hits1.Load(); got != 2 {
		t.Errorf("首次注册的 handler：POST 两次应各调一次 handler，实际 %d 次", got)
	}

	// 二次注册：必须与首次**同样**带守卫 ⇒ 同样调 2 次。
	// 若二次调用返回的是**裸 mw**（丢了守卫）⇒ POST 会被缓存 ⇒ 只调 1 次。
	h2, hits2 := newSrv(second)
	ut.PerformRequest(h2.Engine, "POST", "/p", nil)
	ut.PerformRequest(h2.Engine, "POST", "/p", nil)
	if got := hits2.Load(); got != 2 {
		t.Errorf("★ 二次调用返回的 handler 与首次语义不一致：POST 两次只调了 %d 次 handler"+
			"（期望 2 次；少了守卫 ⇒ POST 被缓存）", got)
	}
}

// TestCache_GetOnlyDefault 行为级:GET 响应被缓存(第二次命中不再调 handler),
// POST/PUT 不缓存(2026-09-05 复审修复:上游 NewCacheByRequestURI 不分方法,
// ekit 包装层加默认 GET 守卫,对齐文档宣称的"GET 缓存"语义)。
func TestCache_GetOnlyDefault(t *testing.T) {
	resetCacheState()
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var calls atomic.Int32
	h.Use(Cache())
	h.GET("/data", func(_ context.Context, c *app.RequestContext) {
		calls.Add(1)
		c.JSON(200, map[string]string{"v": "1"})
	})
	h.POST("/data", func(_ context.Context, c *app.RequestContext) {
		calls.Add(1)
		c.JSON(200, map[string]string{"v": "1"})
	})

	// 同一 URI 两次 GET:handler 只被调 1 次(第二次命中缓存)
	ut.PerformRequest(h.Engine, "GET", "/data", nil)
	ut.PerformRequest(h.Engine, "GET", "/data", nil)

	// 两次 POST:handler 被调 2 次(非 GET 不缓存)
	ut.PerformRequest(h.Engine, http.MethodPost, "/data", nil)
	ut.PerformRequest(h.Engine, http.MethodPost, "/data", nil)

	if got := calls.Load(); got != 3 {
		t.Errorf("handler calls = %d, want 3 (GET x1 缓存命中 + POST x2 不缓存)", got)
	}
}

// TestCache_CustomStrategyOptsOut 方法守卫仅在默认 strategy 下生效;
// 业务显式 WithCacheStrategyByRequest 时自行决定缓存什么。
func TestCache_CustomStrategyOptsOut(t *testing.T) {
	resetCacheState()
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var calls atomic.Int32
	h.Use(Cache(WithCacheStrategyByRequest(func(_ context.Context, c *app.RequestContext) (bool, cache.Strategy) {
		return true, cache.Strategy{CacheKey: string(c.Request.RequestURI())}
	})))
	h.POST("/data", func(_ context.Context, c *app.RequestContext) {
		calls.Add(1)
		c.JSON(200, map[string]string{"v": "1"})
	})

	// 自定义 strategy 下 POST 也被缓存:两次 POST 只调 1 次 handler
	ut.PerformRequest(h.Engine, http.MethodPost, "/data", nil)
	ut.PerformRequest(h.Engine, http.MethodPost, "/data", nil)

	if got := calls.Load(); got != 1 {
		t.Errorf("handler calls = %d, want 1 (custom strategy 下 POST 也缓存)", got)
	}
}

// TestCache_SkipsAuthenticatedRequests 回归：默认 CacheKey=RequestURI 不含
// 身份维度，上游会把 Set-Cookie 连同 body 一起重放——A 的会话在 TTL 内泄给
// 任何请求同 URI 的 B。钉住：带 Authorization/Cookie 的请求一律放行不缓存。
func TestCache_SkipsAuthenticatedRequests(t *testing.T) {
	resetCacheState()
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	count := 0
	h.GET("/private", Cache(WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			count++
			c.Header("Set-Cookie", "session=user-A")
			c.JSON(200, map[string]int{"n": count})
		})

	// 带凭证请求两次：都必须真正执行 handler（不缓存）
	for i := 0; i < 2; i++ {
		w := ut.PerformRequest(h.Engine, "GET", "/private", nil,
			ut.Header{Key: "Authorization", Value: "Bearer tok"})
		if w.Code != 200 {
			t.Fatalf("authed request %d: status %d", i, w.Code)
		}
	}
	if count != 2 {
		t.Fatalf("authed requests must not be cached: handler ran %d times, want 2", count)
	}

	// 无凭证请求两次：第二次命中缓存（count 不再增长）
	for i := 0; i < 2; i++ {
		ut.PerformRequest(h.Engine, "GET", "/private", nil)
	}
	if count != 3 {
		t.Fatalf("anonymous requests should use cache: handler ran %d times, want 3", count)
	}
}
