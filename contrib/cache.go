package contrib

import (
	"context"
	logx "github.com/oekit/logx"
	"net/http"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/cache"
	"github.com/hertz-contrib/cache/persist"
)

const (
	defaultCacheExpiration = time.Minute
	defaultCachePrefix     = "ekit"
)

// cacheState 持有懒构造的 store + options,延迟到第一次调用 Cache 时构造。
// mu 保护全部字段(与 jwt 同款全局态,2026-09-05 复审修复:原实现无锁)。
type cacheState struct {
	mu      sync.Mutex
	mw      app.HandlerFunc
	getOnly bool // 构造时冻结:是否包 GET-only 守卫
	opts    cacheOptions
	// handler 是首次构造出的那一个 handler(含 getOnly 守卫)。
	// 后续 Cache() 调用直接复用它 ⇒ 返回值语义与首次完全一致。
	handler app.HandlerFunc
}

var globalCacheState cacheState

// cacheOptions 是 Cache 的配置集合,通过函数选项累积。
type cacheOptions struct {
	expiration  time.Duration
	prefix      string
	store       persist.CacheStore
	strategy    cache.GetCacheStrategyByRequest
	onHit       cache.OnHitCacheCallback
	onMiss      cache.OnMissCacheCallback
	onShareSngl cache.OnShareSingleFlightCallback
	beforeReply cache.BeforeReplyWithCacheCallback
	ignoreOrder bool // NewCacheByRequestURI vs NewCacheByRequestURIWithIgnoreQueryOrder
}

// CacheOption 是 Cache 的配置选项函数类型。
type CacheOption func(*cacheOptions)

// WithCacheExpiration 设置默认缓存过期时间,默认 1 分钟。
func WithCacheExpiration(d time.Duration) CacheOption {
	return func(o *cacheOptions) { o.expiration = d }
}

// WithCachePrefix 设置缓存 key 前缀(多服务共用 Redis 时防冲突),默认 "ekit"。
func WithCachePrefix(prefix string) CacheOption {
	return func(o *cacheOptions) { o.prefix = prefix }
}

// WithCacheStore 注入自定义 CacheStore(Redis 等)。
// 业务需先构造 persist.NewRedisStore(client) 再传入。
// 未设置时默认用 persist.NewMemoryStore。
func WithCacheStore(store persist.CacheStore) CacheOption {
	return func(o *cacheOptions) { o.store = store }
}

// WithCacheStrategyByRequest 自定义"是否缓存"判定。
// 返回 (cacheable, strategy) — cacheable=false 直接放行不缓存,
// strategy 用作 cache key + expire。
func WithCacheStrategyByRequest(fn cache.GetCacheStrategyByRequest) CacheOption {
	return func(o *cacheOptions) { o.strategy = fn }
}

// WithOnHitCache 缓存命中时回调(用于打点等)。
func WithOnHitCache(cb cache.OnHitCacheCallback) CacheOption {
	return func(o *cacheOptions) { o.onHit = cb }
}

// WithOnMissCache 缓存未命中时回调。
func WithOnMissCache(cb cache.OnMissCacheCallback) CacheOption {
	return func(o *cacheOptions) { o.onMiss = cb }
}

// WithOnShareSingleFlight 共享 single-flight 时的回调(防缓存击穿)。
func WithOnShareSingleFlight(cb cache.OnShareSingleFlightCallback) CacheOption {
	return func(o *cacheOptions) { o.onShareSngl = cb }
}

// WithBeforeReplyWithCache 写入响应前的回调(用于脱敏等)。
func WithBeforeReplyWithCache(cb cache.BeforeReplyWithCacheCallback) CacheOption {
	return func(o *cacheOptions) { o.beforeReply = cb }
}

// WithIgnoreQueryOrder 使用 NewCacheByRequestURIWithIgnoreQueryOrder
// (缓存 key 不计 query 顺序 — GET /a?x=1&y=2 与 /a?y=2&x=1 命中同一缓存)。
func WithIgnoreQueryOrder() CacheOption {
	return func(o *cacheOptions) { o.ignoreOrder = true }
}

var cacheLog = logx.Delegating("middleware-cache")

// Cache 返回 hertz HTTP 缓存中间件,默认按 RequestURI 作 key、60s 过期、
// 内存存储(进程级,重启失效)。Redis 等分布式场景用 WithCacheStore 注入。
//
// ⚠️ 默认只缓存 GET(2026-09-05 复审修复):上游 hertz-contrib/cache 的
// NewCacheByRequestURI strategy 恒返回 true 不分方法,全局挂载时 POST/
// PUT/DELETE 的 2xx 响应也会被缓存重放。ekit 包装层默认对非 GET 请求直接
// 放行不缓存,对齐本注释一贯宣称的"GET 缓存"语义;业务通过
// WithCacheStrategyByRequest 显式接管缓存判定时,方法过滤由业务负责。
//
// 业务使用:
//
//	// 简单 GET 缓存 1 分钟
//	h.Use(contrib.Cache())
//
//	// 自定义 5 分钟 + key 前缀
//	h.Use(contrib.Cache(
//	    mw.WithCacheExpiration(5*time.Minute),
//	    mw.WithCachePrefix("my-svc"),
//	))
//
//	// Redis 分布式缓存
//	h.Use(contrib.Cache(
//	    mw.WithCacheStore(persist.NewRedisStore(redisClient)),
//	    mw.WithCacheExpiration(10*time.Minute),
//	))
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/cache/
// (上游 strategy 返回 false 时 c.Next(ctx) 直接放行 — 非 GET 走同一通道)
func Cache(opts ...CacheOption) app.HandlerFunc {
	globalCacheState.mu.Lock()
	// 懒构造;失败可重试(无 once 毒化)。守卫与 mw 同帧冻结:
	// 构造时无自定义 strategy → 本实例永久带 GET 守卫;后续再传
	// WithCacheStrategyByRequest 不会生效(mw 不重建),守卫也不能按
	// 调用时的 opts 翻转,否则两次调用返回语义不一致的 handler
	// (2026-09-06 复审修正)
	//
	// ⚠️ **实例已冻结时,不再把新 option 写进 opts**:
	//    这些 option 永远不会生效(strategy/expiration/prefix/store 全部冻结),
	//    写进去只会让 `opts` 与**实际生效的配置**不一致
	//    (2026-10-31 实测:二次调用 Cache(WithCachePrefix("second")) 后
	//     opts.prefix 变成 "second",而实际用的还是 "first"
	//     ⇒ 任何读 opts 的代码都会拿到错误的值)。
	//    ⇒ 冻结后直接忽略并告警,让 opts 始终等于实际生效的配置。
	if globalCacheState.mw != nil {
		if len(opts) > 0 {
			// 实例已冻结：后续 option 全部忽略（静默失效最隐蔽 ⇒ 必须告警）
			cacheLog.Warn("cache middleware already built; later options are ignored (global singleton)", "ignoredOpts", len(opts))
		}
		handler := globalCacheState.handler
		globalCacheState.mu.Unlock()
		return handler
	}
	for _, opt := range opts {
		opt(&globalCacheState.opts)
	}
	// 应用默认值
	if globalCacheState.opts.expiration == 0 {
		globalCacheState.opts.expiration = defaultCacheExpiration
	}
	if globalCacheState.opts.prefix == "" {
		globalCacheState.opts.prefix = defaultCachePrefix
	}
	globalCacheState.mw = buildCacheLocked()
	globalCacheState.getOnly = globalCacheState.opts.strategy == nil
	mw, getOnly := globalCacheState.mw, globalCacheState.getOnly

	if !getOnly {
		globalCacheState.handler = mw
		globalCacheState.mu.Unlock()
		return mw
	}
	handler := func(ctx context.Context, c *app.RequestContext) {
		if string(c.Method()) != http.MethodGet {
			c.Next(ctx)
			return
		}
		// 认证后的响应禁止跨用户共享：默认 CacheKey=RequestURI 不含身份
		// 维度，上游会把 Set-Cookie 连同 body 一起重放——A 的会话在 TTL
		// 内泄给任何请求同 URI 的 B（越权/会话固定）。带凭证的请求一律
		// 放行；确实要缓存私有响应必须业务显式接管 strategy 并把身份
		// 纳入 CacheKey。
		if len(c.Request.Header.Peek("Authorization")) > 0 ||
			len(c.Request.Header.Peek("Cookie")) > 0 {
			c.Next(ctx)
			return
		}
		mw(ctx, c)
	}
	// 冻结后复用同一个 handler ⇒ 二次调用 Cache() 返回的 handler
	// 与首次**完全一致**（含 GET 守卫与凭证放行逻辑）。
	globalCacheState.handler = handler
	globalCacheState.mu.Unlock()
	return handler
}

// buildCacheLocked 构造上游 cache 中间件;调用方必须持有 globalCacheState.mu。
func buildCacheLocked() app.HandlerFunc {
	// 默认 store: memory
	store := globalCacheState.opts.store
	if store == nil {
		store = persist.NewMemoryStore(globalCacheState.opts.expiration)
	}
	// 构造 hertz-contrib/cache options
	cOpts := []cache.Option{
		cache.WithPrefixKey(globalCacheState.opts.prefix),
	}
	if globalCacheState.opts.strategy != nil {
		cOpts = append(cOpts, cache.WithCacheStrategyByRequest(globalCacheState.opts.strategy))
	}
	if globalCacheState.opts.onHit != nil {
		cOpts = append(cOpts, cache.WithOnHitCache(globalCacheState.opts.onHit))
	}
	if globalCacheState.opts.onMiss != nil {
		cOpts = append(cOpts, cache.WithOnMissCache(globalCacheState.opts.onMiss))
	}
	if globalCacheState.opts.onShareSngl != nil {
		cOpts = append(cOpts, cache.WithOnShareSingleFlight(globalCacheState.opts.onShareSngl))
	}
	if globalCacheState.opts.beforeReply != nil {
		cOpts = append(cOpts, cache.WithBeforeReplyWithCache(globalCacheState.opts.beforeReply))
	}
	// 选 middleware 工厂
	if globalCacheState.opts.ignoreOrder {
		return cache.NewCacheByRequestURIWithIgnoreQueryOrder(
			store, globalCacheState.opts.expiration, cOpts...)
	}
	return cache.NewCacheByRequestURI(
		store, globalCacheState.opts.expiration, cOpts...)
}
