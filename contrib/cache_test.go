package contrib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
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

// TestCache_SkipsAuthenticatedRequests 回归（middleware#106 后语义更新）：
// 仅带 Cookie（无 Authorization）的请求直接放行不缓存——cookie 会话没有
// 稳定可哈希的身份头，缓存重放 Set-Cookie 的风险仍在。带 Authorization
// 的请求不再放行，改按身份哈希 key 缓存（见 TestCache_AuthHashScopesKey）。
func TestCache_SkipsAuthenticatedRequests(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	count := 0
	h.GET("/private", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			count++
			c.Header("Set-Cookie", "session=user-A")
			c.JSON(200, map[string]int{"n": count})
		})

	// 仅带 Cookie 的请求两次：都必须真正执行 handler（不缓存），
	// 且 store 不出现任何新 key（中间件根本没进缓存分支）。
	for i := 0; i < 2; i++ {
		w := ut.PerformRequest(h.Engine, "GET", "/private", nil,
			ut.Header{Key: "Cookie", Value: "sid=1"})
		if w.Code != 200 {
			t.Fatalf("cookie request %d: status %d", i, w.Code)
		}
	}
	if count != 2 {
		t.Fatalf("cookie-only requests must not be cached: handler ran %d times, want 2", count)
	}
	if n := len(store.Keys()); n != 0 {
		t.Fatalf("cookie-only requests must not touch store, got keys %v", store.Keys())
	}

	// 无凭证请求两次：第二次命中缓存（count 不再增长）
	for i := 0; i < 2; i++ {
		ut.PerformRequest(h.Engine, "GET", "/private", nil)
	}
	if count != 3 {
		t.Fatalf("anonymous requests should use cache: handler ran %d times, want 3", count)
	}
}

// recordingStore 记录经过 store 的全部 key（Get/Set 合计）——middleware#106
// 默认 key 口径的断言依据。委托内层 MemoryStore 保证真实读写语义。
type recordingStore struct {
	mu    sync.Mutex
	keys  []string
	inner persist.CacheStore
}

func newRecordingStore(expire time.Duration) *recordingStore {
	return &recordingStore{inner: persist.NewMemoryStore(expire)}
}

func (r *recordingStore) record(key string) {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
}

// Keys 返回已记录 key 的拷贝。
func (r *recordingStore) Keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

func (r *recordingStore) Get(ctx context.Context, key string, value any) error {
	r.record(key)
	return r.inner.Get(ctx, key, value)
}

func (r *recordingStore) Set(ctx context.Context, key string, value any, expire time.Duration) error {
	r.record(key)
	return r.inner.Set(ctx, key, value, expire)
}

func (r *recordingStore) Delete(ctx context.Context, key string) error {
	return r.inner.Delete(ctx, key)
}

// authKeySuffix 计算默认 key 的身份后缀（与 defaultCacheStrategy 同口径）：
// SHA-256 前 8 字节的 hex（16 字符）。
func authKeySuffix(authValue string) string {
	sum := sha256.Sum256([]byte(authValue))
	return "|auth:" + hex.EncodeToString(sum[:8])
}

// containsKey 判断 key 是否被记录过。
func containsKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// TestCache_AuthHashScopesDefaultKey middleware#106 核心：同 URI、不同
// Authorization 头 ⇒ 不同缓存条目（key 并入该头哈希）；同凭证重复请求
// 命中各自的条目。修复前默认 key=RequestURI 不含身份维度，A 的认证响应
// （含 Set-Cookie）会被 B 命中——会话泄露。
func TestCache_AuthHashScopesDefaultKey(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/private", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			n := count.Add(1)
			c.Header("Set-Cookie", "session=user-"+fmt.Sprint(n))
			c.JSON(200, map[string]int{"n": int(n)})
		})

	keyA := "ekit/private" + authKeySuffix("Bearer token-a")
	keyB := "ekit/private" + authKeySuffix("Bearer token-b")

	// A 首次：miss → handler 执行 → 写入身份隔离条目
	w := ut.PerformRequest(h.Engine, "GET", "/private", nil,
		ut.Header{Key: "Authorization", Value: "Bearer token-a"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"n":1`) {
		t.Fatalf("A first: code=%d body=%s", w.Code, w.Body.String())
	}
	if !containsKey(store.Keys(), keyA) {
		t.Fatalf("★ A 的请求必须写入身份隔离 key %q, got %v", keyA, store.Keys())
	}

	// A 二次：命中自己的条目（handler 不再执行，Set-Cookie 原样重放）
	w = ut.PerformRequest(h.Engine, "GET", "/private", nil,
		ut.Header{Key: "Authorization", Value: "Bearer token-a"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"n":1`) {
		t.Fatalf("A second (cache hit): code=%d body=%s", w.Code, w.Body.String())
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("A 二次请求应命中缓存: handler ran %d times, want 1", got)
	}

	// B 首次：同 URI 不同凭证 ⇒ 不同条目（不得命中 A 的缓存）
	w = ut.PerformRequest(h.Engine, "GET", "/private", nil,
		ut.Header{Key: "Authorization", Value: "Bearer token-b"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"n":2`) {
		t.Fatalf("B first: code=%d body=%s（不得重放 A 的响应）", w.Code, w.Body.String())
	}
	if !containsKey(store.Keys(), keyB) {
		t.Fatalf("★ B 的请求必须写入独立 key %q, got %v", keyB, store.Keys())
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("B 首次请求不得命中 A 的缓存: handler ran %d times, want 2", got)
	}

	// 无身份维度的裸 URI key 不得出现（那是跨用户共享的老默认）
	if containsKey(store.Keys(), "ekit/private") {
		t.Fatalf("★ 带凭证请求不得落在无身份 key 上: %v", store.Keys())
	}
}

// TestCache_DefaultKeyAnonymousMatchesOldDefault 回归：无 Authorization 的
// 请求默认 key 仍为 prefix+RequestURI（不含身份后缀）——不破坏现有匿名用法。
func TestCache_DefaultKeyAnonymousMatchesOldDefault(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/data", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			count.Add(1)
			c.JSON(200, map[string]string{"v": "1"})
		})

	ut.PerformRequest(h.Engine, "GET", "/data?a=1", nil)
	ut.PerformRequest(h.Engine, "GET", "/data?a=1", nil)

	if got := count.Load(); got != 1 {
		t.Fatalf("匿名 GET 两次应命中缓存: handler ran %d times, want 1", got)
	}
	// 老默认 key = prefix + RequestURI，一条不多（Get+Set 各一次恰好两个记录）
	want := "ekit/data?a=1"
	for _, k := range store.Keys() {
		if k != want {
			t.Fatalf("★ 匿名请求 key = %q, want %q（与旧默认一致）, all=%v", k, want, store.Keys())
		}
	}
	if len(store.Keys()) == 0 {
		t.Fatal("store 未记录任何 key——缓存未生效")
	}
}

// TestNormalizeQueryOrder_ByteLevelBijection #125 回归：归一化必须字节级
// 双射——url.Query() 返回已解码值，解码后直接重拼（原实现）会让字面量
// 含 %26/%2F 的 value 与语义完全不同的请求塌缩成同一缓存键（投毒/串响应）。
// 钉住三类不变量：编码字节原样保留、不同语义请求归一后必不同、顺序无关
// 归一仍成立。
func TestNormalizeQueryOrder_ByteLevelBijection(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// 编码 value 原样保留——不得解码重拼成 "filter=a&sort=desc"
		{"encoded ampersand kept", "/r?filter=a%26sort=desc", "/r?filter=a%26sort=desc"},
		{"plain multi key", "/r?filter=a&sort=desc", "/r?filter=a&sort=desc"},
		// Path 转义原样保留——%2F 与 "/" 不得塌缩
		{"encoded slash in path kept", "/files/a%2Fb?x=1", "/files/a%2Fb?x=1"},
		{"literal slash in path", "/files/a/b?x=1", "/files/a/b?x=1"},
		// 顺序无关：按原始字节升序重排
		{"reorder", "/q?y=2&x=1", "/q?x=1&y=2"},
		{"already sorted", "/q?x=1&y=2", "/q?x=1&y=2"},
		{"same key multiple values", "/q?k=2&k=1", "/q?k=1&k=2"},
		// 空段对解码语义零贡献，丢弃（对齐上游解码口径）
		{"empty segment dropped", "/q?b=2&&a=1", "/q?a=1&b=2"},
		// 无 query 原样返回
		{"no query", "/plain", "/plain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeQueryOrder(c.in)
			if err != nil {
				t.Fatalf("normalizeQueryOrder(%q) unexpected err: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("normalizeQueryOrder(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}

	// 不同语义请求归一后必须不同（原缺陷：两者同键）。
	collide := [][2]string{
		{"/r?filter=a%26sort=desc", "/r?filter=a&sort=desc"},
		{"/files/a%2Fb?x=1", "/files/a/b?x=1"},
	}
	for _, p := range collide {
		a, errA := normalizeQueryOrder(p[0])
		b, errB := normalizeQueryOrder(p[1])
		if errA != nil || errB != nil {
			t.Fatalf("normalize(%q/%q) err: %v/%v", p[0], p[1], errA, errB)
		}
		if a == b {
			t.Fatalf("★ 不同语义请求塌缩成同一缓存键: %q 与 %q 归一后同为 %q", p[0], p[1], a)
		}
	}

	// 解析失败回退错误（调用方回退原始 URI）。
	if _, err := normalizeQueryOrder("not a uri"); err == nil {
		t.Fatal("非法 URI 应返回 error 供调用方回退")
	}
}

// TestCache_IgnoreQueryOrderNoEncodedCollision #125 端到端回归（issue 原复
// 现场景）：WithIgnoreQueryOrder 下，GET /report?filter=a%26sort=desc（filter
// 的值字面量是 "a&sort=desc"）与 GET /report?filter=a&sort=desc（filter=a
// 且 sort=desc，语义完全不同）必须各自执行 handler、各自持有缓存条目——
// 修复前 B 命中 A 的缓存体，缓存投毒/串响应。
func TestCache_IgnoreQueryOrderNoEncodedCollision(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/report", Cache(
		WithCacheStore(store),
		WithCacheExpiration(time.Minute),
		WithIgnoreQueryOrder(),
	), func(ctx context.Context, c *app.RequestContext) {
		n := count.Add(1)
		c.JSON(200, map[string]string{
			"resp_of": c.Query("filter"),
			"sort":    c.Query("sort"),
			"run":     fmt.Sprint(n),
		})
	})

	// 请求 A：filter 的值字面量是 "a&sort=desc"（& 为被编码的）。
	// JSON 断言走解码后比较（body 里 & 会被转义成 \u0026，字面 Contains 不可靠）。
	var bodyA map[string]string
	wA := ut.PerformRequest(h.Engine, "GET", "/report?filter=a%26sort=desc", nil)
	if wA.Code != 200 || json.Unmarshal(wA.Body.Bytes(), &bodyA) != nil ||
		bodyA["resp_of"] != "a&sort=desc" || bodyA["sort"] != "" {
		t.Fatalf("A first: code=%d body=%s", wA.Code, wA.Body.String())
	}

	// 请求 B：filter=a 且 sort=desc，语义完全不同——不得命中 A 的缓存。
	var bodyB map[string]string
	wB := ut.PerformRequest(h.Engine, "GET", "/report?filter=a&sort=desc", nil)
	if wB.Code != 200 || json.Unmarshal(wB.Body.Bytes(), &bodyB) != nil ||
		bodyB["resp_of"] != "a" || bodyB["sort"] != "desc" {
		t.Fatalf("★ B 被投喂 A 的缓存体（缓存投毒/串响应，#125）: code=%d body=%s",
			wB.Code, wB.Body.String())
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("不同语义请求必须各自执行 handler: ran %d times, want 2", got)
	}

	// 两条目各自持有独立 key。
	keyA := "ekit/report?filter=a%26sort=desc"
	keyB := "ekit/report?filter=a&sort=desc"
	if !containsKey(store.Keys(), keyA) || !containsKey(store.Keys(), keyB) {
		t.Fatalf("★ 两个语义独立的请求必须持有独立缓存条目: want %q 与 %q, got %v",
			keyA, keyB, store.Keys())
	}

	// 各自二次请求命中自己的条目。
	ut.PerformRequest(h.Engine, "GET", "/report?filter=a%26sort=desc", nil)
	ut.PerformRequest(h.Engine, "GET", "/report?filter=a&sort=desc", nil)
	if got := count.Load(); got != 2 {
		t.Fatalf("各语义域内二次请求应命中缓存: ran %d times, want 2", got)
	}
}

// TestCache_IgnoreQueryOrderEncodedPathNotCollapsed #125 同因回归（Path）：
// /files/a%2Fb?x=1 与 /files/a/b?x=1 归一后不得同键（parsed.Path 是解码值，
// 原实现把两者塌缩成一个缓存条目）。
func TestCache_IgnoreQueryOrderEncodedPathNotCollapsed(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.NoRoute(Cache(
		WithCacheStore(store),
		WithCacheExpiration(time.Minute),
		WithIgnoreQueryOrder(),
	), func(ctx context.Context, c *app.RequestContext) {
		n := count.Add(1)
		c.JSON(200, map[string]string{"path": string(c.Request.Path()), "run": fmt.Sprint(n)})
	})

	wA := ut.PerformRequest(h.Engine, "GET", "/files/a%2Fb?x=1", nil)
	wB := ut.PerformRequest(h.Engine, "GET", "/files/a/b?x=1", nil)
	t.Logf("A: code=%d body=%s", wA.Code, wA.Body.String())
	t.Logf("B: code=%d body=%s", wB.Code, wB.Body.String())

	// 归一化层面的硬断言（路由层对 %2F 的处理不在本中间件职责内）：
	// 两个 URI 的归一化 key 必须不同。
	keyA, errA := normalizeQueryOrder("/files/a%2Fb?x=1")
	keyB, errB := normalizeQueryOrder("/files/a/b?x=1")
	if errA != nil || errB != nil {
		t.Fatalf("normalize err: %v/%v", errA, errB)
	}
	if keyA == keyB {
		t.Fatalf("★ 编码 Path 与字面量 Path 塌缩成同一缓存键（#125 同因）: %q", keyA)
	}
}

// TestCache_IgnoreQueryOrderWithAuthSuffix WithIgnoreQueryOrder 与身份后缀
// 组合：query 顺序归一化后追加 auth 哈希——两种顺序、同一凭证命中同一
// 条目（normalizeQueryOrder 是上游未导出函数的本仓复刻，需钉住口径）。
func TestCache_IgnoreQueryOrderWithAuthSuffix(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/q", Cache(
		WithCacheStore(store),
		WithCacheExpiration(time.Minute),
		WithIgnoreQueryOrder(),
	), func(ctx context.Context, c *app.RequestContext) {
		count.Add(1)
		c.JSON(200, map[string]string{"v": "1"})
	})

	suffix := authKeySuffix("Bearer token-a")
	ut.PerformRequest(h.Engine, "GET", "/q?x=1&y=2", nil,
		ut.Header{Key: "Authorization", Value: "Bearer token-a"})
	ut.PerformRequest(h.Engine, "GET", "/q?y=2&x=1", nil,
		ut.Header{Key: "Authorization", Value: "Bearer token-a"})

	if got := count.Load(); got != 1 {
		t.Fatalf("query 顺序不同应归一为同一 key: handler ran %d times, want 1", got)
	}
	want := "ekit/q?x=1&y=2" + suffix
	if !containsKey(store.Keys(), want) {
		t.Fatalf("★ 归一化 key = %q 不在记录中, got %v", want, store.Keys())
	}
}

// idKeySuffix 计算默认 key 的身份头后缀（与 defaultCacheStrategy/
// cacheIdentityHash 同口径）：全部非空头值按 "name=value\n" 规范拼接后
// SHA-256 前 8 字节的 hex（16 字符）。pairs 按请求头出现顺序给出。
func idKeySuffix(t *testing.T, pairs ...[2]string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range pairs {
		if p[1] == "" {
			continue
		}
		b.WriteString(p[0])
		b.WriteByte('=')
		b.WriteString(p[1])
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "|id:" + hex.EncodeToString(sum[:8])
}

// TestCache_AuthIdentityHeadersScopeKey middleware#142 核心回归（issue 原
// 复现场景）：trusted-gateway 身份形态——请求带 X-Auth-User-ID 而无
// Authorization/Cookie。修复前默认 key=RequestURI 不含身份维度，userA 的
// 响应被 userB 命中（缓存串答，跨用户共享私有响应）。修复后 key 并入身份
// 头哈希（|id:<hash>），不同网关用户各自持有条目；同一用户重复请求命中
// 自己的条目。
func TestCache_AuthIdentityHeadersScopeKey(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/whoami", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			n := count.Add(1)
			c.JSON(200, map[string]string{
				"call":       fmt.Sprint(n),
				"served_for": string(c.Request.Header.Peek("X-Auth-User-ID")),
			})
		})

	// A 首次：miss → handler 执行 → 写入身份隔离条目。
	w := ut.PerformRequest(h.Engine, "GET", "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "userA"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"served_for":"userA"`) {
		t.Fatalf("A first: code=%d body=%s", w.Code, w.Body.String())
	}
	keyA := "ekit/whoami" + idKeySuffix(t, [2]string{"X-Auth-User-ID", "userA"})
	if !containsKey(store.Keys(), keyA) {
		t.Fatalf("★ A 的请求必须写入身份隔离 key %q, got %v", keyA, store.Keys())
	}

	// B 首次：同 URI、不同网关用户 ⇒ 不得命中 A 的缓存（issue 复现断言）。
	w = ut.PerformRequest(h.Engine, "GET", "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "userB"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"served_for":"userB"`) ||
		!strings.Contains(w.Body.String(), `"call":"2"`) {
		t.Fatalf("★ userB 被投喂 userA 的缓存响应（middleware#142 跨用户串答）: code=%d body=%s",
			w.Code, w.Body.String())
	}
	keyB := "ekit/whoami" + idKeySuffix(t, [2]string{"X-Auth-User-ID", "userB"})
	if !containsKey(store.Keys(), keyB) {
		t.Fatalf("★ B 的请求必须写入独立 key %q, got %v", keyB, store.Keys())
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("B 首次请求必须真实执行 handler: ran %d times, want 2", got)
	}

	// B 二次：命中自己的条目（不再执行 handler）。
	w = ut.PerformRequest(h.Engine, "GET", "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "userB"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"call":"2"`) {
		t.Fatalf("B second (cache hit): code=%d body=%s", w.Code, w.Body.String())
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("B 二次请求应命中缓存: handler ran %d times, want 2", got)
	}

	// 无身份维度的裸 URI key 不得出现（那是跨用户共享的老默认）。
	if containsKey(store.Keys(), "ekit/whoami") {
		t.Fatalf("★ 带身份头请求不得落在无身份 key 上: %v", store.Keys())
	}
}

// TestCache_ServiceTokenTopologyScopesIdentity middleware#142 复现形态 3：
// 「网关注入 X-Auth-* 而服务以单一共享 service token 认证」拓扑——
// Authorization 哈希相同，身份头不同 ⇒ 必须不同条目。修复前两类请求同键
// （auth 哈希相同 + key 无身份头维度），跨用户共享。
func TestCache_ServiceTokenTopologyScopesIdentity(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/svc", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			n := count.Add(1)
			c.JSON(200, map[string]string{
				"run":       fmt.Sprint(n),
				"auth_user": string(c.Request.Header.Peek("X-Auth-User-ID")),
			})
		})

	// 同一共享 service token、两个不同的网关用户。
	auth := ut.Header{Key: "Authorization", Value: "Bearer shared-service-token"}
	w := ut.PerformRequest(h.Engine, "GET", "/svc", nil, auth,
		ut.Header{Key: "X-Auth-User-ID", Value: "userA"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"auth_user":"userA"`) {
		t.Fatalf("A first: code=%d body=%s", w.Code, w.Body.String())
	}
	w = ut.PerformRequest(h.Engine, "GET", "/svc", nil, auth,
		ut.Header{Key: "X-Auth-User-ID", Value: "userB"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"auth_user":"userB"`) ||
		!strings.Contains(w.Body.String(), `"run":"2"`) {
		t.Fatalf("★ 同 service token 不同身份头共享了缓存条目（middleware#142 形态 3）: code=%d body=%s",
			w.Code, w.Body.String())
	}

	// key 必须同时含 auth 与 id 两类后缀（独立叠加）。
	authSuffix := authKeySuffix("Bearer shared-service-token")
	keyA := "ekit/svc" + authSuffix + idKeySuffix(t, [2]string{"X-Auth-User-ID", "userA"})
	keyB := "ekit/svc" + authSuffix + idKeySuffix(t, [2]string{"X-Auth-User-ID", "userB"})
	for _, want := range []string{keyA, keyB} {
		if !containsKey(store.Keys(), want) {
			t.Fatalf("★ 缺少身份隔离 key %q, got %v", want, store.Keys())
		}
	}
}

// TestCache_IdentityHeaderWithCookieScopedCache middleware#142 守卫语义：
// Cookie + X-Auth-* 请求存在稳定可哈希的身份维度 ⇒ 照常缓存且按身份隔离
// （不同于「仅 Cookie 无身份维度」的放行不缓存——见
// TestCache_SkipsAuthenticatedRequests）。两个带 Cookie 的不同用户不得
// 共享条目。
func TestCache_IdentityHeaderWithCookieScopedCache(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/mix", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			n := count.Add(1)
			c.Header("Set-Cookie", "session=user-"+string(c.Request.Header.Peek("X-Auth-User-ID")))
			c.JSON(200, map[string]string{"run": fmt.Sprint(n)})
		})

	// userA 带 Cookie 两次：同一身份 ⇒ 第二次命中缓存。
	for i := 0; i < 2; i++ {
		ut.PerformRequest(h.Engine, "GET", "/mix", nil,
			ut.Header{Key: "Cookie", Value: "sid=a"},
			ut.Header{Key: "X-Auth-User-ID", Value: "userA"})
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("★ 同身份+Cookie 请求应命中缓存: handler ran %d times, want 1", got)
	}
	// userB 带 Cookie：不得命中 A 的条目。
	w := ut.PerformRequest(h.Engine, "GET", "/mix", nil,
		ut.Header{Key: "Cookie", Value: "sid=b"},
		ut.Header{Key: "X-Auth-User-ID", Value: "userB"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"run":"2"`) {
		t.Fatalf("★ userB 命中了 userA 的缓存条目: code=%d body=%s", w.Code, w.Body.String())
	}
	// key 均含身份后缀。
	if !containsKey(store.Keys(), "ekit/mix"+idKeySuffix(t, [2]string{"X-Auth-User-ID", "userA"})) ||
		!containsKey(store.Keys(), "ekit/mix"+idKeySuffix(t, [2]string{"X-Auth-User-ID", "userB"})) {
		t.Fatalf("★ Cookie+身份头请求必须落在身份隔离 key 上: %v", store.Keys())
	}
}

// TestCache_WithCacheIdentityHeadersCustom middleware#142 可配置性：网关以
// 非缺省头名（X-Tenant-ID）注入身份时，经 WithCacheIdentityHeaders 覆盖
// 清单后同样按身份隔离；覆盖后缺省 X-Auth-* 头不再参与 key（显式清单是
// 完整声明）。
func TestCache_WithCacheIdentityHeadersCustom(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/t", Cache(
		WithCacheStore(store),
		WithCacheExpiration(time.Minute),
		WithCacheIdentityHeaders("X-Tenant-ID"),
	), func(ctx context.Context, c *app.RequestContext) {
		count.Add(1)
		c.JSON(200, map[string]string{"v": "1"})
	})

	// 不同 X-Tenant-ID ⇒ 不同条目。
	ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Tenant-ID", Value: "t1"})
	w := ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Tenant-ID", Value: "t2"})
	if w.Code != 200 {
		t.Fatalf("t2 first: code=%d", w.Code)
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("★ 不同租户共享了缓存条目: handler ran %d times, want 2", got)
	}
	if !containsKey(store.Keys(), "ekit/t"+idKeySuffix(t, [2]string{"X-Tenant-ID", "t1"})) ||
		!containsKey(store.Keys(), "ekit/t"+idKeySuffix(t, [2]string{"X-Tenant-ID", "t2"})) {
		t.Fatalf("★ 自定义身份头必须参与 key: %v", store.Keys())
	}

	// 同一租户二次请求：命中自己的条目。
	ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Tenant-ID", Value: "t1"})
	if got := count.Load(); got != 2 {
		t.Fatalf("同租户二次请求应命中缓存: handler ran %d times, want 2", got)
	}

	// 覆盖后缺省 X-Auth-* 不再参与 key：两个不同 X-Auth-User-ID 命中同一
	// （租户维度缺失 ⇒ 匿名口径的纯 URI key）条目。
	ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Auth-User-ID", Value: "u1"})
	ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Auth-User-ID", Value: "u2"})
	if got := count.Load(); got != 3 {
		t.Fatalf("覆盖清单后 X-Auth-* 不参与 key（u1/u2 应命中同一匿名条目）: handler ran %d times, want 3", got)
	}
}

// TestCache_IdentityHeadersEmptyValueNotAnIdentity middleware#142 边界：
// 身份头存在但值为空 ⇒ 对身份零贡献（与 identity.go 缺头口径一致）。
// 此时请求仍属「无稳定身份维度」，带 Cookie 时必须被守卫放行不缓存
// （不得落在纯 RequestURI key 上）。
func TestCache_IdentityHeadersEmptyValueNotAnIdentity(t *testing.T) {
	resetCacheState()
	store := newRecordingStore(time.Minute)
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	var count atomic.Int32
	h.GET("/edge", Cache(WithCacheStore(store), WithCacheExpiration(time.Minute)),
		func(ctx context.Context, c *app.RequestContext) {
			count.Add(1)
			c.JSON(200, map[string]string{"v": "1"})
		})

	for i := 0; i < 2; i++ {
		w := ut.PerformRequest(h.Engine, "GET", "/edge", nil,
			ut.Header{Key: "Cookie", Value: "sid=1"},
			ut.Header{Key: "X-Auth-User-ID", Value: ""})
		if w.Code != 200 {
			t.Fatalf("req %d: code=%d", i, w.Code)
		}
	}
	if got := count.Load(); got != 2 {
		t.Fatalf("★ 空身份头+Cookie 必须按无身份维度放行不缓存: handler ran %d times, want 2", got)
	}
	if n := len(store.Keys()); n != 0 {
		t.Fatalf("★ store 不得出现任何 key, got %v", store.Keys())
	}
}
