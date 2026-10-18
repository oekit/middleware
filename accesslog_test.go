package mw

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/oekit/middleware/hmw"
)

func TestAccessLogOptions_SkipPaths(t *testing.T) {
	cfg := newAccessLogOptions(WithAccessLogSkipPaths("/metrics", "/ping"))
	if len(cfg.SkipPaths) != 2 {
		t.Errorf("expected 2 skip paths, got %d", len(cfg.SkipPaths))
	}
}

func TestAccessLogOptions_Sinks(t *testing.T) {
	noop := func(context.Context, *app.RequestContext, AccessRecord) error { return nil }
	cfg := newAccessLogOptions(WithAccessLogSink(noop), WithAccessLogSink(nil), WithAccessLogSink(noop))
	if len(cfg.Sinks) != 2 {
		t.Errorf("nil sink 应被忽略，期望 2 个，got %d", len(cfg.Sinks))
	}
}

// TestAccessLogMiddleware_Sink 钉住 #18：sink 拿到 HTTP 语义全字段（与日志同源），
// 能经 c.Get 读到上游中间件注入的业务键（userId），trace_id 随 hmw 注入。
func TestAccessLogMiddleware_Sink(t *testing.T) {
	var got AccessRecord
	var uid any
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(hmw.Middleware()...)
	h.Use(func(ctx context.Context, c *app.RequestContext) { c.Set("userId", 42) }) // 模拟自家鉴权
	h.Use(AccessLogMiddleware(
		WithAccessLogRedactPathPrefixes("/hook"),
		WithAccessLogSink(func(_ context.Context, c *app.RequestContext, rec AccessRecord) error {
			got = rec
			uid, _ = c.Get("userId")
			return nil
		}),
	))
	h.POST("/hook/tk-123", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusCreated, map[string]any{"code": 200, "msg": "操作成功"})
	})

	r := ut.PerformRequest(h, http.MethodPost, "/hook/tk-123", nil,
		ut.Header{Key: "User-Agent", Value: "ut/1.0"}).Result()

	if r.StatusCode() != http.StatusCreated {
		t.Fatalf("status = %d", r.StatusCode())
	}
	if got.Method != "POST" || got.Status != http.StatusCreated {
		t.Errorf("method/status 不匹配：%+v", got)
	}
	if got.Path != "/hook/***" {
		t.Errorf("Path 应与日志同源（已脱敏），got %q", got.Path)
	}
	if got.UserAgent != "ut/1.0" {
		t.Errorf("UserAgent = %q", got.UserAgent)
	}
	if got.TraceID == "" {
		t.Error("挂了 hmw 后 TraceID 不应为空")
	}
	if got.Latency < 0 {
		t.Errorf("Latency 不应为负：%v", got.Latency)
	}
	if uid != 42 {
		t.Errorf("sink 应能经 c.Get 读到上游注入的业务键，got %v", uid)
	}
}

// TestAccessLogMiddleware_SinkSkipPaths：SkipPaths 命中既不记日志也不触发 sink。
func TestAccessLogMiddleware_SinkSkipPaths(t *testing.T) {
	calls := 0
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(
		WithAccessLogSkipPaths("/metrics"),
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error { calls++; return nil }),
	))
	h.GET("/metrics", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })

	ut.PerformRequest(h, http.MethodGet, "/metrics", nil)
	ut.PerformRequest(h, http.MethodGet, "/api", nil)
	if calls != 1 {
		t.Fatalf("跳过路径不应触发 sink，期望 1 次，got %d", calls)
	}
}

// TestAccessLogMiddleware_SinkFailureIsolated：sink 出错 / panic 均不影响已写出的响应，
// 后续 sink 照常执行。
func TestAccessLogMiddleware_SinkFailureIsolated(t *testing.T) {
	third := false
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error { return errors.New("db down") }),
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error { panic("sink boom") }),
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error { third = true; return nil }),
	))
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) { c.String(200, "payload") })

	r := ut.PerformRequest(h, http.MethodGet, "/api", nil).Result()
	if r.StatusCode() != 200 || string(r.Body()) != "payload" {
		t.Fatalf("sink 故障不得影响响应：%d %s", r.StatusCode(), r.Body())
	}
	if !third {
		t.Fatal("前一个 sink panic 不应阻断后续 sink")
	}
}

// TestAccessLogMiddleware_PanicRecord 钉住 #20：panic 请求产出访问记录
// （Status 按 Recovery 缺省 500、Panic 标记进 sink），响应仍由 Recovery 写统一错误体。
func TestAccessLogMiddleware_PanicRecord(t *testing.T) {
	var got AccessRecord
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(hmw.Middleware()...)
	h.Use(DefaultMiddleware(StackConfig{
		AccessLogOptions: []AccessLogOption{WithAccessLogSink(
			func(_ context.Context, _ *app.RequestContext, rec AccessRecord) error {
				got = rec
				return nil
			})},
	})...)
	h.GET("/boom", func(ctx context.Context, c *app.RequestContext) { panic("db explode") })

	r := ut.PerformRequest(h, http.MethodGet, "/boom", nil).Result()
	if r.StatusCode() != 500 || !bytes.Contains(r.Body(), []byte(`"code"`)) {
		t.Fatalf("Recovery 应照常写 500 统一错误体：%d %s", r.StatusCode(), r.Body())
	}
	if !got.Panic || got.Status != 500 || got.Path != "/boom" {
		t.Fatalf("panic 请求的 sink 记录应 Panic=true / Status=500：%+v", got)
	}
	if got.TraceID == "" {
		t.Error("panic 请求记录也应携带 trace_id")
	}
}
