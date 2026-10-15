package mw

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/concurrency/ratelimit"
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

func newRateLimitOptions(opts ...RateLimitOption) *RateLimitOptions {
	cfg := &RateLimitOptions{
		LimiterTTL: 10 * time.Minute,
	}
	for _, opt := range opts {
		opt(cfg)
	}
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
// 使用方式：
//
//	h.Use(mw.RateLimitMiddleware(
//	    mw.WithRateLimit(100, 200), // 每秒 100 个请求，突发允许 200
//	))
func RateLimitMiddleware(opts ...RateLimitOption) app.HandlerFunc {
	cfg := newRateLimitOptions(opts...)
	if cfg.Rate <= 0 || cfg.Burst <= 0 {
		panic("mw.RateLimitMiddleware: rate/burst not configured, call WithRateLimit(rate, burst) first")
	}

	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(cfg.Rate, cfg.Burst)
	}, cfg.LimiterTTL)

	return newRateLimitHandler(keyed, cfg.KeyFunc)
}

// RateLimitMiddlewareWithLimiter 与 RateLimitMiddleware 相同，但接受调用方
// 自建的 KeyedLimiter：调用方持有其引用并负责在适当时机（如优雅退出）
// 调用 Close() 停止清理 goroutine，实现显式的生命周期管理。
//
// Rate/Burst 已内建于 keyed 的工厂函数，options 仅用于配置 KeyFunc 等
// 请求侧行为（默认按 client IP 限流）。keyed 为 nil 时 panic。
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
	return newRateLimitHandler(keyed, cfg.KeyFunc)
}

// newRateLimitHandler 构建限流处理函数（RateLimitMiddleware/WithLimiter 共用）。
func newRateLimitHandler(keyed *ratelimit.KeyedLimiter, keyFunc func(c *app.RequestContext) string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		key := keyFunc(c)

		if !keyed.Allow(key) {
			ErrorResp(c, 429, "too many requests")
			return
		}
		c.Next(ctx)
	}
}

// defaultIPKey 用直连地址而非 ClientIP：hertz 默认信任任意网段的
// X-Forwarded-For，攻击者每请求换一个伪造 XFF 即可让 ClientIP key 生成
// 无限个新桶（限流形同虚设）。需要按真实客户端 IP 限流的业务应先通过
// engine.SetClientIPFunc 配置可信网段，再注入自定义 KeyFunc。
func defaultIPKey(c *app.RequestContext) string {
	return c.RemoteAddr().String()
}
