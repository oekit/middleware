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
