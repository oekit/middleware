package mw

import (
	"context"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/concurrency/ratelimit"
	"github.com/oekit/pkg/pathx"
	"golang.org/x/time/rate"
)

// RateLimitOptions 是限流中间件的配置。
type RateLimitOptions struct {
	// Rate 每秒允许的请求数。必填。
	Rate rate.Limit

	// Burst 突发容量。必填。
	Burst int

	// KeyFunc 从请求中提取限流 key。
	// 默认按 client IP 限流。
	KeyFunc func(c *app.RequestContext) string

	// LimiterTTL limiter 空闲过期时间，默认 10 分钟。
	// 内部 KeyedLimiter 会以 TTL/2 为间隔自动清理过期 limiter。
	LimiterTTL time.Duration

	// SkipPaths 豁免限流的路径模式列表（支持 glob，与 WithAccessLogSkipPaths
	// 同口径）。命中的请求整请求绕过限流：不占配额、不写限流响应头。
	// 用于 /ping /healthz /ready /metrics 等探活/监控路径——没有豁免口时
	// 健康检查会被业务流量的 429 误伤。
	//
	// 缺省语义（#137）：未显式传时用 mw.InfraPaths() 兜底（标准探活/监控
	// 端点不占配额，探针风暴不进限流计数）；显式传则**完全覆盖**缺省——
	// 不在显式清单内的路径（含 InfraPaths 里的）照常限流，不是
	// 「InfraPaths + 显式清单」的并集。
	//
	// ⚠️ glob 语义是 filepath.Match（pathx.MatchesPath）：`*` 单段不跨
	// "/"——"/health*" 只命中 /healthz 等同段路径，不命中 /health/deep
	// 等嵌套探活路径；子树豁免用 "/health/**"（"/**" 目录前缀跨层）。
	// 漏跳静默无日志线索（#127）。
	SkipPaths []string

	// Headers 是否输出限流响应头（默认关闭，保持既有消费方响应不变）。
	// 放行：X-RateLimit-Remaining；拒绝：Retry-After 与 X-RateLimit-Reset。
	// 数字全部读自 TokenBucket 的剩余配额出口（Tokens()/RetryAfter()）。
	Headers bool

	// OnReject 拒绝时的自定义响应钩子（业务需要统一错误体时用）。
	// retryAfter 是出口探测到的建议等待时长；钩子只负责写响应
	// （状态码/响应体/头），返回后由中间件 Abort 终止链路。
	// 为 nil 时走默认 ErrorResp(c, 429, "too many requests")。
	OnReject func(c *app.RequestContext, retryAfter time.Duration)
}

// RateLimitOption 配置 RateLimitMiddleware。
type RateLimitOption func(*RateLimitOptions)

// WithRateLimit 设置每秒允许的请求数与突发容量。
func WithRateLimit(r rate.Limit, burst int) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.Rate = r
		o.Burst = burst
	}
}

// WithRateLimitKeyFunc 设置限流 key 提取函数。
func WithRateLimitKeyFunc(fn func(c *app.RequestContext) string) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.KeyFunc = fn
	}
}

// WithLimiterTTL 设置 limiter 空闲过期时间。
func WithLimiterTTL(ttl time.Duration) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.LimiterTTL = ttl
	}
}

// WithRateLimitSkipPaths 设置豁免限流的路径模式列表（支持 glob，与
// WithAccessLogSkipPaths 同口径，精确路径即字面匹配）。命中的请求整请求
// 绕过限流：不占配额、不写限流响应头，探活/监控路径不会被业务流量的
// 429 误伤。
//
// ⚠️ 显式传即**完全覆盖** InfraPaths 缺省（#137）：不在显式清单内的路径
// 照常限流——需要额外豁免业务路径又想保留探活豁免时，把 mw.InfraPaths()
// 一并写进清单（`append(mw.InfraPaths(), "/api/**")`）。
//
// ⚠️ glob 语义是 filepath.Match（pathx.MatchesPath）：`*` 单段不跨 "/"，
// "/ready*" 只命中 /readyz 等同段路径，不命中 /ready/deep-check 等嵌套
// 探活路径；子树豁免用 "/ready/**"（"/**" 目录前缀跨层，#127——漏跳静默
// 无日志线索，探活路径会被 429 误伤）。语义钉子测试见
// TestRateLimitMiddleware_SkipPathsGlobSegmentSemantics。
//
// 用法:
//
//	mw.RateLimitMiddleware(
//	    mw.WithRateLimit(100, 200),
//	    mw.WithRateLimitSkipPaths("/ping", "/healthz", "/ready", "/metrics"),
//	)
func WithRateLimitSkipPaths(paths ...string) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.SkipPaths = append(o.SkipPaths, paths...)
	}
}

// WithRateLimitHeaders 开关限流响应头（默认关闭——显式打开，避免破坏
// 现有消费方的响应面）。数字全部读自 TokenBucket 的剩余配额出口，
// 消费方无需自行换算：
//
//   - 放行：X-RateLimit-Remaining —— 当前桶内剩余令牌（向下取整，下限 0；
//     读自 concurrency TokenBucket.Tokens()，不消耗配额）
//   - 拒绝：Retry-After —— 下一个可用令牌的建议等待秒数（向上取整，下限 1；
//     读自 TokenBucket.RetryAfter() 不消耗令牌的探测）；X-RateLimit-Reset ——
//     配额恢复时刻（Unix 秒）
//
// 自定义 Limiter 未实现 Tokens() 出口时 X-RateLimit-Remaining 优雅降级不输出。
//
// 用法:
//
//	mw.RateLimitMiddleware(
//	    mw.WithRateLimit(100, 200),
//	    mw.WithRateLimitHeaders(true),
//	)
func WithRateLimitHeaders(enabled bool) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.Headers = enabled
	}
}

// WithRateLimitOnReject 设置拒绝时的自定义响应钩子（业务需要统一错误体时）。
// retryAfter 是 TokenBucket 出口探测到的建议等待时长（无论 Headers 是否打开
// 都会传给钩子）；钩子只负责写响应（状态码/响应体/头），返回后由中间件
// Abort 终止链路。未设置时走默认 ErrorResp(c, 429, "too many requests")。
//
// 用法:
//
//	mw.WithRateLimitOnReject(func(c *app.RequestContext, retryAfter time.Duration) {
//	    mw.ErrorResp(c, 429, "rate limited, retry in "+retryAfter.String())
//	})
func WithRateLimitOnReject(fn func(c *app.RequestContext, retryAfter time.Duration)) RateLimitOption {
	return func(o *RateLimitOptions) {
		o.OnReject = fn
	}
}

func newRateLimitOptions(opts ...RateLimitOption) *RateLimitOptions {
	cfg := &RateLimitOptions{
		LimiterTTL: 10 * time.Minute,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.SkipPaths = withInfraPathsDefault(cfg.SkipPaths) // #137 缺省兜底
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = defaultIPKey
	}
	return cfg
}

// RateLimitMiddleware 返回一个基于令牌桶的限流中间件。
//
// 每个 key 维护独立的 rate.Limiter，超限返回 429 Too Many Requests。
// 使用 golang.org/x/time/rate（Go 标准库扩展）。
// Rate/Burst 必须通过 WithRateLimit 设置（否则所有请求都会被 429），
// 未设置时在构造阶段直接 panic。
//
// 生命周期说明：内部 KeyedLimiter 的过期清理 goroutine 随进程生命周期
// 存活 —— Hertz 中间件没有 Close 钩子，本函数无法自动停止它。每个中间件
// 实例只常驻一个清理 goroutine（每 LimiterTTL/2 tick 一次，空闲开销极小）；
// 需要显式生命周期控制（如优雅退出时统一 Close）的调用方，请使用
// RateLimitMiddlewareWithLimiter 自建并持有 KeyedLimiter。
//
// 可选能力（默认全关，保持既有消费方行为不变）：
//   - SkipPaths — 探活/监控路径豁免限流；缺省按 mw.InfraPaths() 兜底（#137，
//     标准探活/监控端点不占配额），显式传则完全覆盖缺省（不是追加）
//   - WithRateLimitHeaders — 限流响应头（X-RateLimit-Remaining / Retry-After /
//     X-RateLimit-Reset，数字读自 TokenBucket 的剩余配额出口）
//   - WithRateLimitOnReject — 拒绝时的自定义响应钩子（统一错误体）
//
// 使用方式：
//
//	h.Use(mw.RateLimitMiddleware(
//	    mw.WithRateLimit(100, 200), // 每秒 100 个请求，突发允许 200
//	    mw.WithRateLimitSkipPaths("/ping", "/healthz", "/ready", "/metrics"),
//	    mw.WithRateLimitHeaders(true),
//	))
func RateLimitMiddleware(opts ...RateLimitOption) app.HandlerFunc {
	cfg := newRateLimitOptions(opts...)
	if cfg.Rate <= 0 || cfg.Burst <= 0 {
		panic("mw.RateLimitMiddleware: rate/burst not configured, call WithRateLimit(rate, burst) first")
	}

	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(cfg.Rate, cfg.Burst)
	}, cfg.LimiterTTL)

	return newRateLimitHandler(keyed, cfg)
}

// RateLimitMiddlewareWithLimiter 与 RateLimitMiddleware 相同，但接受调用方
// 自建的 KeyedLimiter：调用方持有其引用并负责在适当时机（如优雅退出）
// 调用 Close() 停止清理 goroutine，实现显式的生命周期管理。
//
// Rate/Burst 已内建于 keyed 的工厂函数，options 仅用于配置 KeyFunc、
// SkipPaths、响应头、拒绝钩子等请求侧行为（默认按 client IP 限流）。
// keyed 为 nil 时 panic。
//
// 使用方式：
//
//	keyed := ratelimit.NewKeyedLimiter(
//	    func() ratelimit.Limiter { return ratelimit.NewTokenBucket(100, 200) },
//	    10*time.Minute,
//	)
//	h.Use(mw.RateLimitMiddlewareWithLimiter(keyed))
//	// 优雅退出时：keyed.Close()
func RateLimitMiddlewareWithLimiter(keyed *ratelimit.KeyedLimiter, opts ...RateLimitOption) app.HandlerFunc {
	if keyed == nil {
		panic("mw.RateLimitMiddlewareWithLimiter: keyed limiter must not be nil")
	}
	cfg := newRateLimitOptions(opts...)
	return newRateLimitHandler(keyed, cfg)
}

// 限流响应头（WithRateLimitHeaders 打开后输出；名称对齐业界惯例）。
const (
	headerRateLimitRemaining = "X-RateLimit-Remaining"
	headerRateLimitReset     = "X-RateLimit-Reset"
	headerRetryAfter         = "Retry-After"
)

// tokensPeeker 是 TokenBucket「剩余配额」读出口（concurrency Tokens()，
// concurrency#92）的最小面。自定义 Limiter 未实现时优雅降级：
// 不输出 X-RateLimit-Remaining。
type tokensPeeker interface {
	Tokens() float64
}

// newRateLimitHandler 构建限流处理函数（RateLimitMiddleware/WithLimiter 共用）。
func newRateLimitHandler(keyed *ratelimit.KeyedLimiter, cfg *RateLimitOptions) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// 白名单路径整请求绕过限流：不占配额、不写限流响应头。
		if len(cfg.SkipPaths) > 0 && pathx.MatchesPath(cfg.SkipPaths, string(c.Request.URI().Path())) {
			c.Next(ctx)
			return
		}

		key := cfg.KeyFunc(c)
		wait, ok := keyed.AllowWithRetryAfter(key)
		if ok {
			if cfg.Headers {
				if remaining, has := peekRemainingTokens(keyed, key); has {
					c.Response.Header.Set(headerRateLimitRemaining, strconv.Itoa(remaining))
				}
			}
			c.Next(ctx)
			return
		}

		if cfg.Headers {
			setRateLimitRejectHeaders(c, wait)
		}
		if cfg.OnReject != nil {
			cfg.OnReject(c, wait)
			c.Abort()
			return
		}
		ErrorResp(c, 429, "too many requests")
	}
}

// peekRemainingTokens 读 key 对应桶的剩余令牌数（向下取整，下限 0——桶内有
// 预留未兑现时出口可为负，回响应头取 max(0, tokens)）。自定义 Limiter 未实现
// Tokens() 出口时返回 false，响应头优雅降级不输出。
func peekRemainingTokens(keyed *ratelimit.KeyedLimiter, key string) (int, bool) {
	l := keyed.Get(key)
	if l == nil {
		return 0, false
	}
	peeker, ok := l.(tokensPeeker)
	if !ok {
		return 0, false
	}
	n := int(peeker.Tokens())
	if n < 0 {
		n = 0
	}
	return n, true
}

// setRateLimitRejectHeaders 写拒绝响应头。Retry-After 按 delay-seconds 口径
// 向上取整、下限 1（0 会被客户端解读为「立即重试」，与被拒语义矛盾）；
// X-RateLimit-Reset 为配额恢复时刻（Unix 秒）。数字来自 TokenBucket 的
// RetryAfter() 不消耗令牌探测出口。
func setRateLimitRejectHeaders(c *app.RequestContext, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	c.Response.Header.Set(headerRetryAfter, strconv.Itoa(seconds))
	c.Response.Header.Set(headerRateLimitReset, strconv.FormatInt(time.Now().Add(retryAfter).Unix(), 10))
}

// defaultIPKey 用直连地址（去端口）而非 ClientIP：hertz 默认信任任意网段的
// X-Forwarded-For，攻击者每请求换一个伪造 XFF 即可让 ClientIP key 生成
// 无限个新桶（限流形同虚设）。去端口则消除「客户端新建连接即新桶」的绕过
// 面——同一源地址的所有连接共享一个桶（[#13](https://github.com/oekit/middleware/issues/13)）。
// 代理拓扑（RemoteAddr=上游网关地址）下按真实客户端 IP 限流：先通过
// engine.SetClientIPFunc 配置可信网段，再注入自定义 KeyFunc。
func defaultIPKey(c *app.RequestContext) string {
	return hostOnly(c.RemoteAddr().String())
}

// hostOnly 从 "host:port" 拆出 host；无端口地址（unix socket/零值）原样返回。
func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
