package mw

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

// TestRecoveryMiddleware_RecoversPanic 验证 panic 被捕获并返回 500。
func TestRecoveryMiddleware_RecoversPanic(t *testing.T) {
	c := app.NewContext(0)
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, app.HandlerFunc(func(ctx context.Context, rc *app.RequestContext) {
		panic("boom")
	}))
	c.SetHandlers(hc)

	RecoveryMiddleware()(context.Background(), c)

	// panic 应被捕获，ErrorResp(500) 映射为 HTTP 500
	assert.DeepEqual(t, consts.StatusInternalServerError, c.Response.StatusCode())
}

// TestRecoveryMiddleware_NoPanic 验证无 panic 时正常放行。
func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	c := app.NewContext(0)
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, app.HandlerFunc(func(ctx context.Context, rc *app.RequestContext) {
		// 正常 handler，无 panic
	}))
	c.SetHandlers(hc)

	RecoveryMiddleware()(context.Background(), c)
}

// TestRecoveryMiddleware_CustomHandler 验证自定义错误处理器。
func TestRecoveryMiddleware_CustomHandler(t *testing.T) {
	called := false
	c := app.NewContext(0)
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, app.HandlerFunc(func(ctx context.Context, rc *app.RequestContext) {
		panic("boom")
	}))
	c.SetHandlers(hc)

	h := RecoveryMiddleware(WithRecoveryErrorHandler(func(c *app.RequestContext, r any, stack string) {
		called = true
		c.JSON(consts.StatusServiceUnavailable, Response{
			Code: 503, Message: "service unavailable",
		})
	}))
	h(context.Background(), c)

	if !called {
		t.Error("expected custom error handler to be called")
	}
	assert.DeepEqual(t, consts.StatusServiceUnavailable, c.Response.StatusCode())
}

// fakeSentryReporter 捕获 Report 调用,供 TestRecoveryMiddleware_PanicReporter 断言。
type fakeSentryReporter struct {
	called    bool
	gotVal    any
	gotStack  string
	gotMethod string
	gotPath   string
}

func (f *fakeSentryReporter) Report(_ context.Context, c *app.RequestContext, panicVal any, stack string) {
	f.called = true
	f.gotVal = panicVal
	f.gotStack = stack
	f.gotMethod = string(c.Method())
	f.gotPath = string(c.Request.URI().Path())
}

// TestRecoveryMiddleware_PanicReporter 验证 WithPanicReporter 在 panic
// 发生时调起 Report,ErrorHandler 仍正常执行(sentry 失败不影响响应)。
func TestRecoveryMiddleware_PanicReporter(t *testing.T) {
	fr := &fakeSentryReporter{}
	c := app.NewContext(0)
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, app.HandlerFunc(func(ctx context.Context, rc *app.RequestContext) {
		panic("report-me")
	}))
	c.SetHandlers(hc)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/test/path")

	h := RecoveryMiddleware(WithPanicReporter(fr))
	h(context.Background(), c)

	if !fr.called {
		t.Fatal("expected SentryReporter.Report to be called")
	}
	if fr.gotVal != "report-me" {
		t.Errorf("reported val = %v, want report-me", fr.gotVal)
	}
	if fr.gotStack == "" {
		t.Error("expected non-empty stack in Report call")
	}
	if fr.gotMethod != "GET" {
		t.Errorf("reported method = %q, want GET", fr.gotMethod)
	}
	if fr.gotPath != "/test/path" {
		t.Errorf("reported path = %q, want /test/path", fr.gotPath)
	}
	// ErrorHandler 仍执行(默认 500 响应)
	assert.DeepEqual(t, consts.StatusInternalServerError, c.Response.StatusCode())
}

// panickyReporter 的 Report 自身 panic(第三方监控 SDK 的现实风险)。
type panickyReporter struct{ called atomic.Bool }

func (p *panickyReporter) Report(_ context.Context, _ *app.RequestContext, _ any, _ string) {
	p.called.Store(true)
	panic("sentry sdk exploded")
}

// TestRecovery_ReporterPanicIsolated 钉住 2026-09-05 修复:Reporter 内部
// panic 必须被隔离 — 业务原始 panic 仍走 ErrorHandler(500 响应写出),
// 不是被 Reporter 的 panic 替换掉。
func TestRecovery_ReporterPanicIsolated(t *testing.T) {
	rep := &panickyReporter{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(RecoveryMiddleware(WithPanicReporter(rep)))
	h.GET("/boom", func(_ context.Context, c *app.RequestContext) {
		panic("biz panic")
	})

	w := ut.PerformRequest(h.Engine, "GET", "/boom", nil)
	if w.Code != 500 {
		t.Errorf("status = %d, want 500(ErrorHandler 必须执行)", w.Code)
	}
	if !rep.called.Load() {
		t.Error("reporter should have been invoked")
	}
}
