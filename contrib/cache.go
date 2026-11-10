package contrib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	logx "github.com/oekit/logx"

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
	expiration      time.Duration
	prefix          string
	store           persist.CacheStore
	strategy        cache.GetCacheStrategyByRequest
	onHit           cache.OnHitCacheCallback
	onMiss          cache.OnMissCacheCallback
	onShareSngl     cache.OnShareSingleFlightCallback
	beforeReply     cache.BeforeReplyWithCacheCallback
	ignoreOrder     bool // NewCacheByRequestURI vs NewCacheByRequestURIWithIgnoreQueryOrder
	identityHeaders []string
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

// defaultCacheIdentityHeaders 是 trusted-gateway 身份形态的缺省头名清单
// (middleware#142)——与本仓 identity.go TrustedHeadersIdentity 的缺省头名
// (X-Auth-User-ID / X-Auth-Username / X-Auth-Role-IDs)对齐:矩阵内服务的
// 标准鉴权形态把用户身份放在这些头里,Authorization 头不存在。contrib 不
// 反向依赖根包,头名在此复刻;漂移由 TestCache_AuthIdentityHeadersScopeKey
// 等缓存身份语义测试钉住。
var defaultCacheIdentityHeaders = []string{
	"X-Auth-User-ID",
	"X-Auth-Username",
	"X-Auth-Role-IDs",
}

// WithCacheIdentityHeaders 自定义参与默认缓存 key 身份维度的请求头清单
// (middleware#142)。缺省为 defaultCacheIdentityHeaders(X-Auth-* 三头);
// 网关以非缺省头名注入身份(如 X-Tenant-ID)时用同名清单覆盖。
// 空参调用视作未设置(保持缺省)。
func WithCacheIdentityHeaders(names ...string) CacheOption {
	return func(o *cacheOptions) {
		if len(names) > 0 {
			o.identityHeaders = append([]string(nil), names...)
		}
	}
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
// ⚠️ 身份维度与默认 key(middleware#106,middleware#142 扩展):默认
// CacheKey=RequestURI 不含身份维度——认证后的响应(含 Set-Cookie)若跨用户
// 共享即是会话泄露。默认行为是两道防线的组合:
//
//  1. 带 Authorization 头**或 trusted-gateway 身份头**的请求照常缓存,
//     但默认 key 并入对应身份的 SHA-256 前 16 hex:Authorization 请求得
//     `RequestURI|auth:<hash>`;身份头请求(X-Auth-User-ID / X-Auth-Username /
//     X-Auth-Role-IDs——与本仓 identity.go TrustedHeadersIdentity 的缺省
//     头名对齐,矩阵内服务的标准鉴权形态即网关注入 X-Auth-* 且无
//     Authorization 头)得 `RequestURI|id:<hash>`(全部非空头值规范拼接后
//     哈希)。两类后缀独立叠加:网关注入 X-Auth-* 而服务持单一共享
//     service token 的拓扑下,Authorization 哈希相同、身份头哈希不同
//     ⇒ 不同用户不同条目。无 Authorization 也无身份头的请求保持纯
//     RequestURI(匿名用法 key 与旧默认一致)。身份头清单可经
//     WithCacheIdentityHeaders 覆盖。
//  2. 无任何可哈希身份维度(无 Authorization 且无身份头)而仅带 Cookie 的
//     请求直接放行不缓存——cookie 会话没有稳定可哈希的身份头,缓存重放
//     Set-Cookie 的风险仍在。
//
// 认证接口仍**强烈建议**经 WithCacheStrategyByRequest 自定义含业务身份
// (用户 ID 等)的 CacheKey:对身份头做哈希只保证「不跨身份共享」,不保证
// 粒度最优——token 轮换、同用户多 token 都会拆成独立缓存条目。自定义
// strategy 时上述默认防线(方法守卫/身份放行)不再生效,由业务全权负责。
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
	if len(globalCacheState.opts.identityHeaders) == 0 {
		// 拷贝兜底:不与包级缺省清单共享底层数组(只读约定)。
		globalCacheState.opts.identityHeaders = append([]string(nil), defaultCacheIdentityHeaders...)
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
		// 会话泄露防护（middleware#106，middleware#142 扩展，两道防线组合）：
		// 1) 带 Authorization 头或身份头（X-Auth-*，trusted-gateway 形态）
		//    的请求照常缓存，但默认 key 已并入对应身份的 SHA-256 短哈希
		//    （defaultCacheStrategy）——同 URI 不同凭证/不同网关用户
		//    ⇒ 不同缓存条目，私有响应（含 Set-Cookie）不跨用户共享；
		// 2) 无任何可哈希身份维度（无 Authorization 且无身份头）而仅带
		//    Cookie 的请求直接放行不缓存——cookie 会话没有稳定可哈希的
		//    身份头，缓存重放 Set-Cookie 的风险仍在（认证接口建议自定义
		//    含身份的 CacheKey，见 Cache godoc 的身份维度说明）。
		if !hasStableCacheIdentity(c, globalCacheState.opts.identityHeaders) &&
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
	// strategy:业务自定义优先;缺省走本包默认(含 Authorization 与 X-Auth-*
	// 身份维度的 key 生成,middleware#106/#142)。不再直接用上游
	// NewCacheByRequestURI/...WithIgnoreQueryOrder——它们的 key 不含
	// 身份维度且归一化函数未导出,无法在 URI 基础上追加身份后缀。
	strategy := globalCacheState.opts.strategy
	if strategy == nil {
		strategy = defaultCacheStrategy(globalCacheState.opts.ignoreOrder, globalCacheState.opts.identityHeaders)
	}
	cOpts = append(cOpts, cache.WithCacheStrategyByRequest(strategy))
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
	return cache.NewCache(store, globalCacheState.opts.expiration, cOpts...)
}

// defaultCacheStrategy 默认缓存判定(middleware#106/#142):key 取 RequestURI
// (ignoreOrder 时先做 query 顺序归一化,口径等价上游
// NewCacheByRequestURIWithIgnoreQueryOrder);请求带 Authorization 头时把
// 该头的 SHA-256 前 16 hex 并入 key(RequestURI|auth:<hash>);请求带身份头
// (identityHeaders,缺省 X-Auth-*——trusted-gateway 形态)时把全部非空头值
// 的规范拼接 SHA-256 前 16 hex 并入 key(RequestURI|id:<hash>)。两类后缀
// 独立叠加:「网关注入 X-Auth-* 而服务持单一共享 service token」拓扑下,
// Authorization 哈希相同、身份头哈希不同 ⇒ 不同用户仍不同条目(middleware
// #142 复现形态 3)。同 URI 无任何身份维度的请求保持纯 RequestURI(匿名
// 用法 key 与旧默认一致)。
// 哈希而非原样拼接:凭证/身份不得明文进 key(Redis 等共享 store 的 key
// 空间可被运维侧观察)。Cookie 会话不在此处理——由外层守卫直接放行。
func defaultCacheStrategy(ignoreOrder bool, identityHeaders []string) cache.GetCacheStrategyByRequest {
	return func(_ context.Context, c *app.RequestContext) (bool, cache.Strategy) {
		key := string(c.Request.RequestURI())
		if ignoreOrder {
			if normalized, err := normalizeQueryOrder(key); err == nil {
				key = normalized
			}
		}
		if auth := c.Request.Header.Peek("Authorization"); len(auth) > 0 {
			sum := sha256.Sum256(auth)
			key += "|auth:" + hex.EncodeToString(sum[:8])
		}
		if idHash := cacheIdentityHash(identityHeaders, c); idHash != "" {
			key += "|id:" + idHash
		}
		return true, cache.Strategy{CacheKey: key}
	}
}

// cacheIdentityHash 计算身份头清单的规范哈希(middleware#142):按配置顺序取
// 每个头的全部非空值,以 "name=value\n" 规范拼接后做 SHA-256,返回前 8 字节
// 的 hex(16 字符)。无任何非空值时返回空串(请求不含身份维度,调用方不追加
// 后缀)。多值头(如重复注入的 X-Auth-Role-IDs)逐值进入拼接,顺序即请求内
// 出现顺序——同一用户的重复请求头序稳定(Hertz 按收包序),不同序至多少命中
// 一次(方向安全,不会错命中)。
func cacheIdentityHash(headers []string, c *app.RequestContext) string {
	var b strings.Builder
	for _, name := range headers {
		for _, v := range c.Request.Header.PeekAll(name) {
			if len(v) == 0 {
				continue // 空值头对身份零贡献(与 identity.go 的缺头口径一致)
			}
			b.WriteString(name)
			b.WriteByte('=')
			b.Write(v)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// hasStableCacheIdentity 判定请求是否携带可哈希的稳定身份维度
// (middleware#142):Authorization 头或任一身份头存在非空值即为 true。
// 外层守卫据此决定「仅带 Cookie 且无身份维度」的请求是否放行不缓存。
func hasStableCacheIdentity(c *app.RequestContext, identityHeaders []string) bool {
	if len(c.Request.Header.Peek("Authorization")) > 0 {
		return true
	}
	for _, name := range identityHeaders {
		for _, v := range c.Request.Header.PeekAll(name) {
			if len(v) > 0 {
				return true
			}
		}
	}
	return false
}

// normalizeQueryOrder query 顺序归一化:k2=v2&k1=v1 与 k1=v1&k2=v2 归一为
// 同一 key。解析失败由调用方回退原始 URI(与上游错误处理一致——上游失败
// 时也回退原 URI)。
//
// 归一化必须字节级双射(#125):url.ParseRequestURI().Query() 返回**已解码**
// 的值,解码后直接重拼(原实现)会让字面量含 "&"/"=" 的 value 与语义完全
// 不同的多 key 请求塌缩成同一缓存键——GET /r?filter=a%26sort=desc(filter
// 的值是 "a&sort=desc")与 /r?filter=a&sort=desc(两个独立 key)归一后同键,
// 后者命中前者的缓存响应,攻击者可用可控 query 构造与真实请求的键碰撞,
// 投毒/串取他人响应;Path 同理(%2F 与 "/" 塌缩,/files/a%2Fb 与 /files/a/b
// 同键)。故对 parsed.RawQuery 按 "&" 切出**原始编码**的 k/v 对、按字节
// 升序重排后原样重拼(无损),路径用 parsed.EscapedPath()(保留转义):
// 归一后同键 ⟺ 原始编码字节串的有序重排相同,不同语义请求绝不塌缩;
// 语义相同而书写不同的请求(如空段 "a=1&&b=2"、%2F 与 %2f)最多少命中一次
// (方向安全,不会错命中)。纯 ASCII 无特殊字符的 query 重排结果与上游
// 解码口径一致。
func normalizeQueryOrder(requestURI string) (string, error) {
	parsed, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery == "" {
		return requestURI, nil
	}
	pairs := make([]string, 0, strings.Count(parsed.RawQuery, "&")+1)
	for _, pair := range strings.Split(parsed.RawQuery, "&") {
		if pair != "" { // 空段("a=1&&b=2")对解码语义零贡献,丢弃对齐上游口径
			pairs = append(pairs, pair)
		}
	}
	sort.Strings(pairs)
	return parsed.EscapedPath() + "?" + strings.Join(pairs, "&"), nil
}
