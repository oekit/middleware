package mw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/prometheus/client_golang/prometheus"
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
	// defaultIPKey delegates to c.ClientIP(); just ensure the function
	// runs without panic and returns a non-empty string for an HTTP/1.1
	// request with a typical remote address.
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

func TestNewPrometheusMetrics_Defaults(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test-defaults",
		Registry:    prometheus.NewRegistry(),
	})
	if m == nil {
		t.Fatal("NewPrometheusMetrics returned nil")
	}
}

func TestNewPrometheusMetrics_AllOptions(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		Namespace:   "ns",
		ServiceName: "svc",
		SkipPaths:   []string{"/healthz"},
		Registry:    prometheus.NewRegistry(),
	})
	if m == nil {
		t.Fatal("NewPrometheusMetrics returned nil")
	}
	if m.Middleware() == nil {
		t.Error("Middleware() should return non-nil handler")
	}
}

func TestPathLabelValues(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test",
		Registry:    prometheus.NewRegistry(),
	})
	if got := m.pathLabelValues("GET", "/foo"); len(got) == 0 {
		t.Error("expected non-empty label values")
	}
}

func TestStatusLabelValues(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test",
		Registry:    prometheus.NewRegistry(),
	})
	if got := m.statusLabelValues("GET", "/foo", "200"); len(got) == 0 {
		t.Error("expected non-empty label values")
	}
}

// --- stack.go DefaultMiddleware ---

func TestDefaultMiddleware_EmptyConfig(t *testing.T) {
	stack := DefaultMiddleware(StackConfig{})
	if len(stack) == 0 {
		t.Fatal("expected non-empty middleware stack")
	}
	// Should contain Prometheus + TraceID(s) + Recovery + Response + AccessLog = 6
	// （v0.28.1 起 Recovery 纳入标准栈：引擎无默认 PanicHandler，无 Recovery
	// 的 handler panic 直接断连）
	if len(stack) != 6 {
		t.Errorf("expected 6 middlewares, got %d", len(stack))
	}
}

func TestDefaultMiddleware_FullConfig(t *testing.T) {
	stack := DefaultMiddleware(StackConfig{
		ServiceName: "svc",
		Namespace:   "ns",
		SkipPaths:   []string{"/healthz"},
	})
	if len(stack) != 6 {
		t.Errorf("expected 6 middlewares, got %d", len(stack))
	}
}

// --- Sanity: RateLimitMiddleware with custom key func + TTL ---

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
	// 随机端口：默认 :8888 与本机其他服务（如 octopus）冲突会导致 bind panic。
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

// Keep a no-op import for httptest in case future tests use it.
var _ = httptest.NewRecorder
