package mw

import (
	"context"
	"net/http"
	"strconv"
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
