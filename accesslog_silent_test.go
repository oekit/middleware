package mw

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/oekit/logx"
)

// accessLogCapture 捕获 logx 输出的最小 Logger 实现（与 chainmw 包测试同构，
// 各自包内独立）。
type accessLogCapture struct {
	entries []string
}

func (c *accessLogCapture) rec(level, msg string, kvs []any) {
	var sb strings.Builder
	sb.WriteString(level + " " + msg)
	for i := 0; i+1 < len(kvs); i += 2 {
		fmt.Fprintf(&sb, " %v=%v", kvs[i], kvs[i+1])
	}
	c.entries = append(c.entries, sb.String())
}

func (c *accessLogCapture) text() string { return strings.Join(c.entries, "\n") }

func (c *accessLogCapture) Debug(msg string, kvs ...any) { c.rec("DEBUG", msg, kvs) }
func (c *accessLogCapture) Info(msg string, kvs ...any)  { c.rec("INFO", msg, kvs) }
func (c *accessLogCapture) Warn(msg string, kvs ...any)  { c.rec("WARN", msg, kvs) }
func (c *accessLogCapture) Error(msg string, kvs ...any) { c.rec("ERROR", msg, kvs) }
func (c *accessLogCapture) Debugf(format string, args ...any) {
	c.rec("DEBUG", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) Infof(format string, args ...any) {
	c.rec("INFO", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) Warnf(format string, args ...any) {
	c.rec("WARN", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) Errorf(format string, args ...any) {
	c.rec("ERROR", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) CtxDebug(_ context.Context, msg string, kvs ...any) {
	c.rec("DEBUG", msg, kvs)
}
func (c *accessLogCapture) CtxInfo(_ context.Context, msg string, kvs ...any) {
	c.rec("INFO", msg, kvs)
}
func (c *accessLogCapture) CtxWarn(_ context.Context, msg string, kvs ...any) {
	c.rec("WARN", msg, kvs)
}
func (c *accessLogCapture) CtxError(_ context.Context, msg string, kvs ...any) {
	c.rec("ERROR", msg, kvs)
}
func (c *accessLogCapture) CtxDebugf(_ context.Context, format string, args ...any) {
	c.rec("DEBUG", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) CtxInfof(_ context.Context, format string, args ...any) {
	c.rec("INFO", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) CtxWarnf(_ context.Context, format string, args ...any) {
	c.rec("WARN", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) CtxErrorf(_ context.Context, format string, args ...any) {
	c.rec("ERROR", fmt.Sprintf(format, args...), nil)
}
func (c *accessLogCapture) WithCtx(_ context.Context) logx.Logger { return c }
func (c *accessLogCapture) WithService(_ string) logx.Logger      { return c }
func (c *accessLogCapture) WithAttrs(_ ...logx.Attr) logx.Logger  { return c }
func (c *accessLogCapture) WithGroup(_ string) logx.Logger        { return c }
func (c *accessLogCapture) SetLevel(_ logx.Level)                 {}

// TestAccessLogMiddleware_Silent 钉住 #38：静默下不写任何日志，但采集行为
// 完全不变——脱敏、跳过、sink 调用照常。
func TestAccessLogMiddleware_Silent(t *testing.T) {
	cap := &accessLogCapture{}
	var got AccessRecord
	calls := 0
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(
		WithAccessLogSilent(),
		WithAccessLogLogger(cap),
		WithAccessLogRedactPathPrefixes("/hook"),
		WithAccessLogSkipPaths("/metrics"),
		WithAccessLogSink(func(_ context.Context, _ *app.RequestContext, rec AccessRecord) error {
			got = rec
			calls++
			return nil
		}),
	))
	h.POST("/hook/tk-123", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })
	h.GET("/metrics", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })

	ut.PerformRequest(h, http.MethodPost, "/hook/tk-123", nil)
	ut.PerformRequest(h, http.MethodGet, "/metrics", nil)

	if out := cap.text(); out != "" {
		t.Errorf("静默模式不应写任何日志，got:\n%s", out)
	}
	if calls != 1 {
		t.Fatalf("静默下 sink 仍应被调用（跳过路径除外），期望 1 次，got %d", calls)
	}
	if got.Path != "/hook/***" {
		t.Errorf("静默下脱敏仍应生效，Path = %q", got.Path)
	}
	if got.Method != "POST" || got.Status != 200 {
		t.Errorf("静默下采集字段应不变：%+v", got)
	}
}

// TestAccessLogMiddleware_SilentSinkFailureSilent 钉住 #38：静默下 sink
// 故障的告警日志也不写，但 sink 的错误仍不影响主链路。
func TestAccessLogMiddleware_SilentSinkFailureSilent(t *testing.T) {
	cap := &accessLogCapture{}
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(
		WithAccessLogSilent(),
		WithAccessLogLogger(cap),
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error {
			return fmt.Errorf("db down")
		}),
		WithAccessLogSink(func(context.Context, *app.RequestContext, AccessRecord) error {
			panic("sink boom")
		}),
	))
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) { c.String(200, "payload") })

	r := ut.PerformRequest(h, http.MethodGet, "/api", nil).Result()
	if r.StatusCode() != 200 || string(r.Body()) != "payload" {
		t.Fatalf("sink 故障不得影响响应：%d %s", r.StatusCode(), r.Body())
	}
	if out := cap.text(); out != "" {
		t.Errorf("静默下 sink 故障告警也不应写日志，got:\n%s", out)
	}
}

// TestAccessLogMiddleware_SilentPanicRecord 钉住 #38：静默下 panic 请求
// 仍产出记录（Panic 标记为 true）、仍按原值重抛给 Recovery。
func TestAccessLogMiddleware_SilentPanicRecord(t *testing.T) {
	cap := &accessLogCapture{}
	var got AccessRecord
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(DefaultMiddleware(StackConfig{
		AccessLogOptions: []AccessLogOption{
			WithAccessLogSilent(),
			WithAccessLogLogger(cap),
			WithAccessLogSink(func(_ context.Context, _ *app.RequestContext, rec AccessRecord) error {
				got = rec
				return nil
			}),
		},
	})...)
	h.GET("/boom", func(ctx context.Context, c *app.RequestContext) { panic("db explode") })

	r := ut.PerformRequest(h, http.MethodGet, "/boom", nil).Result()
	if r.StatusCode() != 500 {
		t.Fatalf("Recovery 应照常写 500，got %d", r.StatusCode())
	}
	if !got.Panic || got.Status != 500 || got.Path != "/boom" {
		t.Fatalf("静默下 panic 请求的 sink 记录应 Panic=true / Status=500：%+v", got)
	}
	if out := cap.text(); out != "" {
		t.Errorf("静默下 panic 记录不应写日志，got:\n%s", out)
	}
}

// TestAccessLogMiddleware_CustomLogger 钉住 #38：注入宿主 logger 后访问记录
// 由中间件写出（消息与字段不变），宿主不必再写一份——只产生一条记录。
func TestAccessLogMiddleware_CustomLogger(t *testing.T) {
	cap := &accessLogCapture{}
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(WithAccessLogLogger(cap)))
	h.GET("/api", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })

	ut.PerformRequest(h, http.MethodGet, "/api", nil)

	out := cap.text()
	if strings.Count(out, "INFO request") != 1 {
		t.Fatalf("注入 logger 后应只写一条访问日志，got:\n%s", out)
	}
	for _, want := range []string{"method=GET", "path=/api", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("访问日志缺字段 %q：\n%s", want, out)
		}
	}
}

// TestAccessLogOptions_SilentAndLogger 钉住选项装配：静默与 logger 可独立
// 设置，nil logger 被忽略。
func TestAccessLogOptions_SilentAndLogger(t *testing.T) {
	cap := &accessLogCapture{}
	cfg := newAccessLogOptions(WithAccessLogSilent(), WithAccessLogLogger(cap))
	if !cfg.Silent {
		t.Error("Silent 未置位")
	}
	if cfg.Logger != logx.Logger(cap) {
		t.Error("Logger 未装配")
	}
	cfg2 := newAccessLogOptions(WithAccessLogLogger(nil))
	if cfg2.Logger != nil {
		t.Errorf("nil logger 应被忽略，got %v", cfg2.Logger)
	}
	if cfg2.Silent {
		t.Error("未设置静默时 Silent 应为 false")
	}
}
