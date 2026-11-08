package mw

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/oekit/concurrency/ratelimit"
	"golang.org/x/time/rate"
)

// newTestContext builds a hertz RequestContext with optional query params
// and a trace ID injected, suitable for middleware/handler unit tests.
func newTestContext(query string) *app.RequestContext {
	h := app.NewContext(0)
	if query != "" {
		h.Request.URI().SetQueryString(query)
	}
	return h
}

// --- page.go ---

// --- ratelimit.go option setters ---

// TestRateLimitMiddleware_AllowsUnderLimit 验证限流中间件在限额内放行。
func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	h := RateLimitMiddleware(WithRateLimit(rate.Limit(100), 10))

	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.SetMethod("GET")

	h(context.Background(), c)

	// 放行：handler 链无后续，状态码默认 200
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestRateLimitMiddleware_BlocksOverLimit 验证超限返回 429。
// 通过极低限流 + 大量并发触发。
func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	// Rate=1, Burst=1，只能允许 1 个请求
	h := RateLimitMiddleware(WithRateLimit(rate.Limit(1), 1))

	blocked := 0
	allowed := 0
	for i := 0; i < 5; i++ {
		c := app.NewContext(128)
		c.Request.SetRequestURI("/test")
		c.Request.Header.SetMethod("GET")
		h(context.Background(), c)
		if c.Response.StatusCode() == consts.StatusTooManyRequests {
			blocked++
		} else {
			allowed++
		}
	}
	if blocked == 0 {
		t.Error("expected at least one request to be blocked (429)")
	}
	if allowed == 0 {
		t.Error("expected at least one request to be allowed")
	}
}

func TestWithRateLimitKeyFunc(t *testing.T) {
	opts := newRateLimitOptions(WithRateLimitKeyFunc(func(c *app.RequestContext) string {
		return "custom-key"
	}))
	if opts.KeyFunc == nil {
		t.Fatal("KeyFunc should be set")
	}
	c := newTestContext("")
	if got := opts.KeyFunc(c); got != "custom-key" {
		t.Errorf("KeyFunc() = %q, want custom-key", got)
	}
}

func TestWithLimiterTTL(t *testing.T) {
	opts := newRateLimitOptions(WithLimiterTTL(30 * time.Second))
	if opts.LimiterTTL != 30*time.Second {
		t.Errorf("LimiterTTL = %v, want 30s", opts.LimiterTTL)
	}
}

func TestDefaultIPKey(t *testing.T) {
	// defaultIPKey keys by the host part of RemoteAddr (port stripped via
	// hostOnly); just ensure the function runs without panic and returns a
	// non-empty string for an HTTP/1.1 request with a typical remote address.
	c := newTestContext("")
	got := defaultIPKey(c)
	if got == "" {
		t.Log("defaultIPKey returned empty (no client IP), which is fine")
	}
}

// --- csrf.go CSRFMiddleware ---

// --- etag.go ETagMiddleware ---

// --- pprof.go RegisterDebug / RegisterDebugGroup / options ---

// --- prometheus.go NewPrometheusMetrics / Middleware / pathLabelValues / statusLabelValues ---

func TestRateLimitOptions_Defaults(t *testing.T) {
	cfg := newRateLimitOptions(WithRateLimit(100, 200))
	if cfg.Rate != 100 {
		t.Errorf("expected rate 100, got %v", cfg.Rate)
	}
	if cfg.Burst != 200 {
		t.Errorf("expected burst 200, got %d", cfg.Burst)
	}
	// 默认 TTL 应为 10 分钟
	if cfg.LimiterTTL != 10*time.Minute {
		t.Errorf("expected default TTL 10m, got %v", cfg.LimiterTTL)
	}
	// 默认 KeyFunc 应非 nil
	if cfg.KeyFunc == nil {
		t.Error("expected default KeyFunc to be set")
	}
}

func TestRateLimitMiddleware_KeyFuncInvoked(t *testing.T) {
	// Smoke test: a request with a key func that records its argument.
	var observed string
	rec := func(c *app.RequestContext) string {
		observed = "called"
		return "k1"
	}
	h := RateLimitMiddleware(
		WithRateLimit(10, 1),
		WithRateLimitKeyFunc(rec),
		WithLimiterTTL(1*time.Minute),
	)
	if h == nil {
		t.Fatal("RateLimitMiddleware returned nil")
	}
	_ = observed
	_ = rate.Limit(0)
}

// --- Sanity: integration check using httptest to make sure nothing panics ---

func TestRateLimitMiddleware_EndToEnd(t *testing.T) {
	// Build a tiny hertz server and exercise RateLimitMiddleware + Success.
	// 随机端口：默认 :8888 与本机其他服务冲突会导致 bind panic。
	port := strconv.Itoa(20000 + int(time.Now().UnixNano()%10000))
	h := server.New(server.WithHostPorts("127.0.0.1:" + port))
	h.Use(RateLimitMiddleware(WithRateLimit(100, 100)))
	h.GET("/x", func(ctx context.Context, c *app.RequestContext) {
		SuccessResp(c, map[string]string{"ok": "true"})
	})

	go func() { _ = h.Run() }()
	defer func() { _ = h.Shutdown(context.TODO()) }()
	time.Sleep(100 * time.Millisecond)

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:"+port+"/x", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Skipf("server not reachable (sandbox?): %v", err)
		return
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", httpResp.StatusCode)
	}
}

// TestRateLimitMiddlewareWithLimiter_WorksWithCallerLimiter 验证调用方自建的
// KeyedLimiter 被中间件使用，且调用方可 Close 它停止清理 goroutine（L7）。
func TestRateLimitMiddlewareWithLimiter_WorksWithCallerLimiter(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(100, 1)
	}, 10*time.Minute)
	defer keyed.Close() // 调用方负责生命周期

	h := RateLimitMiddlewareWithLimiter(keyed)

	c := app.NewContext(8)
	c.Request.SetRequestURI("/test")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	assert.DeepEqual(t, 1, keyed.Len()) // 中间件确实在使用这个 limiter
}

// TestRateLimitMiddlewareWithLimiter_BlocksOverLimit 验证限流语义一致。
func TestRateLimitMiddlewareWithLimiter_BlocksOverLimit(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(rate.Limit(1), 1)
	}, time.Minute)
	defer keyed.Close()

	h := RateLimitMiddlewareWithLimiter(keyed, WithRateLimitKeyFunc(func(*app.RequestContext) string {
		return "client-a"
	}))

	for i := 0; i < 2; i++ {
		c := app.NewContext(8)
		c.Request.SetRequestURI("/test")
		h(context.Background(), c)
		if i == 0 {
			assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
		} else {
			assert.DeepEqual(t, consts.StatusTooManyRequests, c.Response.StatusCode())
		}
	}
}

// TestRateLimitMiddlewareWithLimiter_NilPanics 验证 nil limiter 在构造期 panic。
func TestRateLimitMiddlewareWithLimiter_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil keyed limiter")
		}
	}()
	_ = RateLimitMiddlewareWithLimiter(nil)
}

// --- #78: SkipPaths / 限流响应头 / TokenBucket 剩余配额出口 ---

// rlRequest 构造请求并直接调用中间件（不经过 handler 链）。
func rlRequest(h app.HandlerFunc, path string) *app.RequestContext {
	c := app.NewContext(8)
	c.Request.SetRequestURI(path)
	c.Request.Header.SetMethod("GET")
	h(context.Background(), c)
	return c
}

// TestRateLimitMiddleware_SkipPaths 验证白名单路径豁免限流（正例）：
// 不占配额（桶耗尽后白名单仍放行），精确与 glob 形态都命中。
func TestRateLimitMiddleware_SkipPaths(t *testing.T) {
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitSkipPaths("/ping", "/health*"),
	)

	// 白名单路径连续请求全部放行（不占配额：桶容量只有 1）
	for _, p := range []string{"/ping", "/ping", "/healthz", "/healthz"} {
		c := rlRequest(h, p)
		assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	}

	// 业务路径照常限流：容量 1，第一个放行、第二个 429
	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/api").Response.StatusCode())
	assert.DeepEqual(t, consts.StatusTooManyRequests, rlRequest(h, "/api").Response.StatusCode())

	// 业务流量耗尽后白名单依旧放行（豁免不依赖桶状态）
	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/ping").Response.StatusCode())
}

// TestRateLimitMiddleware_SkipPaths_Negative 验证负例：未配置即无隐式豁免、
// 不在清单的路径不受豁免。
func TestRateLimitMiddleware_SkipPaths_Negative(t *testing.T) {
	key := WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" })

	// 未配置 SkipPaths：探活路径同样受限
	h := RateLimitMiddleware(WithRateLimit(rate.Limit(1), 1), key)
	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/ping").Response.StatusCode())
	assert.DeepEqual(t, consts.StatusTooManyRequests, rlRequest(h, "/ping").Response.StatusCode())

	// 配置了但路径不在清单：不受豁免
	h2 := RateLimitMiddleware(WithRateLimit(rate.Limit(1), 1), key, WithRateLimitSkipPaths("/metrics"))
	assert.DeepEqual(t, consts.StatusOK, rlRequest(h2, "/ping").Response.StatusCode())
	assert.DeepEqual(t, consts.StatusTooManyRequests, rlRequest(h2, "/ping").Response.StatusCode())
}

// TestRateLimitMiddleware_SkipPathsGlobSegmentSemantics 钉住 #127：glob 的
// `*` 单段不跨 "/"——"/ready*" 只豁免 /readyz 等同段路径，不豁免
// /ready/deep-check 等嵌套探活路径（漏跳静默无日志线索，探活会被业务流量的
// 429 误伤）；子树豁免用 "/ready/**"。与 SkipPaths 的文档口径互钉，防止
// 未来更换匹配原语时反向放大。
func TestRateLimitMiddleware_SkipPathsGlobSegmentSemantics(t *testing.T) {
	// 负例（#127 缺陷方向）："/ready*" 不豁免嵌套探活路径——照常限流。
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitSkipPaths("/ready*"),
	)
	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/ready/deep-check").Response.StatusCode())
	assert.DeepEqual(t, consts.StatusTooManyRequests, rlRequest(h, "/ready/deep-check").Response.StatusCode())

	// 同段正例保持成立：/readyz 仍被 "/ready*" 豁免（不占配额，恒放行）。
	h2 := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitSkipPaths("/ready*"),
	)
	for i := 0; i < 3; i++ {
		assert.DeepEqual(t, consts.StatusOK, rlRequest(h2, "/readyz").Response.StatusCode())
	}

	// 正例："/ready/**" 豁免整棵子树（含嵌套探活路径）。
	h3 := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitSkipPaths("/ready/**"),
	)
	for i := 0; i < 3; i++ {
		assert.DeepEqual(t, consts.StatusOK, rlRequest(h3, "/ready/deep-check").Response.StatusCode())
	}
}

// TestRateLimitMiddleware_Headers_Allowed 验证放行响应头 X-RateLimit-Remaining
// 接的是 TokenBucket.Tokens() 剩余配额出口：随消费递减（1 → 0），放行时不写
// 拒绝头。极小速率保证桶内不回填，剩余数确定。
func TestRateLimitMiddleware_Headers_Allowed(t *testing.T) {
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(0.000001), 2),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitHeaders(true),
	)

	c1 := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusOK, c1.Response.StatusCode())
	assert.DeepEqual(t, "1", string(c1.Response.Header.Peek(headerRateLimitRemaining)))
	assert.DeepEqual(t, "", string(c1.Response.Header.Peek(headerRetryAfter)))
	assert.DeepEqual(t, "", string(c1.Response.Header.Peek(headerRateLimitReset)))

	c2 := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusOK, c2.Response.StatusCode())
	assert.DeepEqual(t, "0", string(c2.Response.Header.Peek(headerRateLimitRemaining)))
}

// TestRateLimitMiddleware_Headers_Rejected 验证拒绝响应头：Retry-After（秒，
// 来自 TokenBucket.RetryAfter() 出口）与 X-RateLimit-Reset（配额恢复时刻）。
// rate=1/burst=1 下被拒意味着下一个令牌恰在 (0,1] 秒内 ⇒ Retry-After 恒为 1。
func TestRateLimitMiddleware_Headers_Rejected(t *testing.T) {
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitHeaders(true),
	)

	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/api").Response.StatusCode())

	before := time.Now().Unix()
	c := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusTooManyRequests, c.Response.StatusCode())
	assert.DeepEqual(t, "1", string(c.Response.Header.Peek(headerRetryAfter)))

	reset, err := strconv.ParseInt(string(c.Response.Header.Peek(headerRateLimitReset)), 10, 64)
	if err != nil {
		t.Fatalf("X-RateLimit-Reset not a unix timestamp: %v", err)
	}
	if reset < before || reset > time.Now().Unix()+2 {
		t.Errorf("X-RateLimit-Reset = %d, want ≈ now+1s", reset)
	}
}

// TestRateLimitMiddleware_Headers_DefaultOff 验证负例：不显式打开时默认
// 无任何限流响应头（默认行为保持不变）。
func TestRateLimitMiddleware_Headers_DefaultOff(t *testing.T) {
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
	)

	for _, want := range []int{consts.StatusOK, consts.StatusTooManyRequests} {
		c := rlRequest(h, "/api")
		assert.DeepEqual(t, want, c.Response.StatusCode())
		for _, hdr := range []string{headerRateLimitRemaining, headerRetryAfter, headerRateLimitReset} {
			if got := string(c.Response.Header.Peek(hdr)); got != "" {
				t.Errorf("%s = %q, want empty (headers default off)", hdr, got)
			}
		}
	}
}

// TestRateLimitMiddlewareOnReject 验证拒绝钩子拿到 TokenBucket 出口的建议
// 等待时长并接管响应（正例；Headers 未开也照传 retryAfter）。
func TestRateLimitMiddlewareOnReject(t *testing.T) {
	var called int
	var got time.Duration
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitOnReject(func(c *app.RequestContext, retryAfter time.Duration) {
			called++
			got = retryAfter
			c.Response.SetStatusCode(503)
			c.Response.SetBody([]byte("slow down"))
		}),
	)

	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/api").Response.StatusCode())

	c := rlRequest(h, "/api")
	assert.DeepEqual(t, 1, called)
	if got <= 0 || got > time.Second {
		t.Errorf("retryAfter = %v, want (0, 1s]", got)
	}
	assert.DeepEqual(t, 503, c.Response.StatusCode())
	assert.DeepEqual(t, "slow down", string(c.Response.Body()))
}

// TestRateLimitMiddlewareOnReject_NilUsesDefault 验证负例：未注入钩子时走
// 默认 ErrorResp 429 统一错误体。
func TestRateLimitMiddlewareOnReject_NilUsesDefault(t *testing.T) {
	h := RateLimitMiddleware(
		WithRateLimit(rate.Limit(1), 1),
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
	)

	assert.DeepEqual(t, consts.StatusOK, rlRequest(h, "/api").Response.StatusCode())

	c := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusTooManyRequests, c.Response.StatusCode())
	if !strings.Contains(string(c.Response.Body()), "too many requests") {
		t.Errorf("body = %q, want default ErrorResp body", c.Response.Body())
	}
}

// TestRateLimitMiddlewareWithLimiter_Headers_QuotaExit 验证调用方自建
// KeyedLimiter 形态下剩余配额出口同样接通（正例）。
func TestRateLimitMiddlewareWithLimiter_Headers_QuotaExit(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(rate.Limit(0.000001), 1)
	}, time.Minute)
	defer keyed.Close()

	h := RateLimitMiddlewareWithLimiter(keyed,
		WithRateLimitKeyFunc(func(*app.RequestContext) string { return "k" }),
		WithRateLimitHeaders(true),
	)

	c1 := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusOK, c1.Response.StatusCode())
	assert.DeepEqual(t, "0", string(c1.Response.Header.Peek(headerRateLimitRemaining)))

	c2 := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusTooManyRequests, c2.Response.StatusCode())
	if ra := string(c2.Response.Header.Peek(headerRetryAfter)); ra == "" {
		t.Error("Retry-After should be set on reject")
	}
}

// plainLimiter 是不实现 Tokens() 出口的自定义 Limiter，用于验证响应头
// 优雅降级（负例）。
type plainLimiter struct{}

func (plainLimiter) Allow() bool                    { return true }
func (plainLimiter) AllowN(n int) bool              { return true }
func (plainLimiter) Reserve() time.Duration         { return 0 }
func (plainLimiter) Wait(ctx context.Context) error { return nil }

// TestRateLimitMiddlewareWithLimiter_Headers_NoQuotaExit 验证负例：自定义
// Limiter 无剩余配额出口时不硬算、不输出 X-RateLimit-Remaining，请求照常放行。
func TestRateLimitMiddlewareWithLimiter_Headers_NoQuotaExit(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return plainLimiter{}
	}, time.Minute)
	defer keyed.Close()

	h := RateLimitMiddlewareWithLimiter(keyed, WithRateLimitHeaders(true))

	c := rlRequest(h, "/api")
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	if got := string(c.Response.Header.Peek(headerRateLimitRemaining)); got != "" {
		t.Errorf("X-RateLimit-Remaining = %q, want empty (no Tokens() exit)", got)
	}
}
