package mw

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

func TestDefaultMiddleware_EmptyConfig(t *testing.T) {
	stack := DefaultMiddleware(StackConfig{})
	if len(stack) == 0 {
		t.Fatal("expected non-empty middleware stack")
	}
	// Should contain TraceID(s) + Recovery + Response + AccessLog = 5
	// （v0.28.1 起 Recovery 纳入标准栈：引擎无默认 PanicHandler，无 Recovery
	// 的 handler panic 直接断连；v0.2.0 起 Prometheus 从默认栈拆出）
	if len(stack) != 5 {
		t.Errorf("expected 5 middlewares, got %d", len(stack))
	}
}

func TestDefaultMiddleware_FullConfig(t *testing.T) {
	stack := DefaultMiddleware(StackConfig{
		SkipPaths: []string{"/healthz"},
	})
	if len(stack) != 5 {
		t.Errorf("expected 5 middlewares, got %d", len(stack))
	}
}

// --- Sanity: RateLimitMiddleware with custom key func + TTL ---

// TestMinimalMiddleware 最小安全栈 = TraceID(2) + Recovery(1)，零指标零日志。
func TestMinimalMiddleware(t *testing.T) {
	stack := MinimalMiddleware()
	if len(stack) != 3 {
		t.Fatalf("expected 3 handlers (TraceID x2 + Recovery), got %d", len(stack))
	}
}

// TestMinimalMiddleware_RecoversPanic 最小栈必须能把 handler panic 收编为 500，
// 而不是放任进程/连接崩溃（引擎无默认 PanicHandler）。
func TestMinimalMiddleware_RecoversPanic(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	for _, m := range MinimalMiddleware() {
		h.Use(m)
	}
	h.GET("/boom", func(ctx context.Context, c *app.RequestContext) {
		panic("boom")
	})

	r := ut.PerformRequest(h, http.MethodGet, "/boom", nil).Result()
	if r.StatusCode() != 500 {
		t.Errorf("status = %d, want 500 (RecoveryMiddleware should catch panic)", r.StatusCode())
	}
	if !strings.Contains(string(r.Body()), `"code"`) {
		t.Errorf("recovery should write unified error body, got %s", r.Body())
	}
}

// TestDefaultMiddleware_SkipPathsReachResponse 钉住 #15：StackConfig.SkipPaths
// 必须贯通到 ResponseMiddleware——跳过路径（/metrics）的响应不做统一信封包装，
// 其余路径正常包壳。原实现 SkipPaths 只喂给 AccessLog，/metrics 被包成
// {"code":0,...} 导致 Prometheus 解析失败。
func TestDefaultMiddleware_SkipPathsReachResponse(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	for _, m := range DefaultMiddleware(StackConfig{SkipPaths: []string{"/metrics"}}) {
		h.Use(m)
	}
	h.GET("/metrics", func(ctx context.Context, c *app.RequestContext) {
		c.String(200, "prometheus_payload")
	})
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"ok": true})
	})

	r1 := ut.PerformRequest(h, http.MethodGet, "/metrics", nil).Result()
	if bytes.Contains(r1.Body(), []byte(`"code"`)) {
		t.Fatalf("skip path should not be wrapped: %s", r1.Body())
	}
	if !bytes.Contains(r1.Body(), []byte("prometheus_payload")) {
		t.Fatalf("skip path payload lost: %s", r1.Body())
	}

	r2 := ut.PerformRequest(h, http.MethodGet, "/api", nil).Result()
	if !bytes.Contains(r2.Body(), []byte(`"code"`)) {
		t.Fatalf("non-skip path should be wrapped: %s", r2.Body())
	}
}

// TestDefaultMiddleware_DisableResponseWrap 钉住 #18「响应体自管」一键形态：
// 栈内不挂 ResponseMiddleware，裸 JSON 原样放行；Recovery 仍在（panic → 500）；
// AccessLogOptions 透传的 sink 照常拿到记录。
func TestDefaultMiddleware_DisableResponseWrap(t *testing.T) {
	var seen []AccessRecord
	stack := DefaultMiddleware(StackConfig{
		DisableResponseWrap: true,
		SkipPaths:           []string{"/metrics"},
		AccessLogOptions: []AccessLogOption{WithAccessLogSink(
			func(_ context.Context, _ *app.RequestContext, rec AccessRecord) error {
				seen = append(seen, rec)
				return nil
			})},
	})
	if len(stack) != 4 { // TraceID(2) + Recovery + AccessLog
		t.Fatalf("DisableResponseWrap 栈应为 4 个 handler，got %d", len(stack))
	}

	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(stack...) // Use 接受变参，栈切片直接展开
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"ok": true}) // 顶层无 code 的裸 JSON
	})
	h.GET("/metrics", func(ctx context.Context, c *app.RequestContext) { c.String(200, "m") })
	h.GET("/missing", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(404, map[string]any{"code": 404, "msg": "not found"})
	})
	h.GET("/boom", func(ctx context.Context, c *app.RequestContext) { panic("boom") })

	r := ut.PerformRequest(h, http.MethodGet, "/api", nil).Result()
	if bytes.Contains(r.Body(), []byte(`"code"`)) || !bytes.Contains(r.Body(), []byte(`"ok":true`)) {
		t.Fatalf("响应自管：裸 JSON 不得被包装，got %s", r.Body())
	}
	if r2 := ut.PerformRequest(h, http.MethodGet, "/boom", nil).Result(); r2.StatusCode() != 500 {
		t.Fatalf("Recovery 必须仍在栈内，status = %d", r2.StatusCode())
	}
	ut.PerformRequest(h, http.MethodGet, "/metrics", nil)
	ut.PerformRequest(h, http.MethodGet, "/missing", nil)

	// /api + /missing；/metrics 命中 SkipPaths 不记；/boom 的 panic 穿过 AccessLog
	// 直达外层 Recovery、无访问记录（既有栈序行为，与 sink 无关）
	if len(seen) != 2 {
		t.Fatalf("sink 应收到 2 条记录（SkipPaths 贯通到 sink），got %d: %+v", len(seen), seen)
	}
	if seen[0].Path != "/api" || seen[0].Status != 200 || seen[1].Path != "/missing" || seen[1].Status != 404 {
		t.Fatalf("sink 记录字段不匹配：%+v", seen)
	}
}

// TestDefaultMiddleware_PerGroup：中间件可按路由组装配——Group 接受变参，
// 栈切片直接展开；组外路由不受影响。
func TestDefaultMiddleware_PerGroup(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	api := h.Group("/api", DefaultMiddleware(StackConfig{})...)
	api.GET("/u", func(ctx context.Context, c *app.RequestContext) { c.JSON(200, map[string]any{"n": 1}) })
	h.GET("/raw", func(ctx context.Context, c *app.RequestContext) { c.JSON(200, map[string]any{"n": 1}) })

	if r := ut.PerformRequest(h, http.MethodGet, "/api/u", nil).Result(); !bytes.Contains(r.Body(), []byte(`"code"`)) {
		t.Fatalf("组内路由应被标准栈包装，got %s", r.Body())
	}
	if r := ut.PerformRequest(h, http.MethodGet, "/raw", nil).Result(); bytes.Contains(r.Body(), []byte(`"code"`)) {
		t.Fatalf("组外路由不应受影响，got %s", r.Body())
	}
}
