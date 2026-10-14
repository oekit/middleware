package mw

import (
	"context"
	"runtime/debug"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/yi-nology/ekit-logx"
)

// recoveryLog 带 component 属性的 scoped logger（同 failLog）。
var recoveryLog = logx.Delegating("middleware-recovery")

// SentryReporter 是 ekit recovery 中间件对接 Sentry/Datadog 等监控后端的接口。
//
// 设计目标:ekit 自身不依赖 sentry-go(避免大依赖),业务自己写实现适配
// 监控 SDK,然后通过 WithPanicReporter 注入 recovery。
//
// 典型实现(业务侧,伪代码):
//
//	type sentryReporter struct{ client *sentry.Client }
//
//	func (r *sentryReporter) Report(ctx context.Context, c *app.RequestContext, panicVal any, stack string) {
//	    hub := r.client.CaptureException(fmt.Errorf("%v", panicVal), &sentry.EventHint{Stacktrace: ...})
//	    _ = hub
//	}
//
//	h.Use(mw.RecoveryMiddleware(mw.WithPanicReporter(&sentryReporter{client: sentryClient})))
type SentryReporter interface {
	Report(ctx context.Context, c *app.RequestContext, panicVal any, stack string)
}

// RecoveryOptions 是 panic recovery 中间件的配置。
type RecoveryOptions struct {
	// ErrorHandler 处理 panic 后的响应写入。
	// 默认使用 ErrorResp 写入 500 响应。
	ErrorHandler func(c *app.RequestContext, r any, stack string)

	// PanicReporter 监控后端报告器(sentry/datadog 等),先于 ErrorHandler 调用,
	// 即使 ErrorHandler 写入响应,Report 仍执行(上报不应被响应影响)。
	PanicReporter SentryReporter
}

// RecoveryOption 配置 RecoveryMiddleware。
type RecoveryOption func(*RecoveryOptions)

// WithRecoveryErrorHandler 设置自定义 panic 处理器。
// r 为 recover 到的值，stack 为格式化后的调用栈。
func WithRecoveryErrorHandler(fn func(c *app.RequestContext, r any, stack string)) RecoveryOption {
	return func(o *RecoveryOptions) {
		o.ErrorHandler = fn
	}
}

// WithPanicReporter 注册监控后端报告器(sentry/datadog 等)。
// panic 发生时,在 ErrorHandler 之前调用 Reporter.Report 上报。
//
// 业务使用:
//
//	type mySentry struct{ /* ... */ }
//	func (s *mySentry) Report(...) { /* sentry.CaptureException */ }
//
//	h.Use(mw.RecoveryMiddleware(mw.WithPanicReporter(&mySentry{...})))
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/sentry/
// (ekit 不直接 import sentry-go,避免大依赖,业务自行实现 adapter)
func WithPanicReporter(r SentryReporter) RecoveryOption {
	return func(o *RecoveryOptions) {
		o.PanicReporter = r
	}
}

func newRecoveryOptions(opts ...RecoveryOption) *RecoveryOptions {
	cfg := &RecoveryOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *app.RequestContext, _ any, _ string) {
			ErrorResp(c, 500, "internal server error")
		}
	}
	return cfg
}

// RecoveryMiddleware 返回一个 panic recovery 中间件。
//
// 捕获 handler 中的 panic,记录堆栈日志,调用 PanicReporter(sentry 等),
// 返回 500 错误响应。
//
// 使用方式:
//
//	// 默认配置(仅 logx 记录 + 500 响应)
//	h.Use(mw.RecoveryMiddleware())
//
//	// 接入 Sentry
//	h.Use(mw.RecoveryMiddleware(mw.WithPanicReporter(sentryAdapter)))
//
//	// 自定义错误处理
//	h.Use(mw.RecoveryMiddleware(mw.WithRecoveryErrorHandler(func(c *app.RequestContext, r any, stack string) {
//	    mw.ErrorResp(c, 500, "panic occurred")
//	})))
func RecoveryMiddleware(opts ...RecoveryOption) app.HandlerFunc {
	cfg := newRecoveryOptions(opts...)

	return func(ctx context.Context, c *app.RequestContext) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				recoveryLog.CtxError(ctx, "[panic] recovered",
					"err", r,
					"method", string(c.Method()),
					"path", string(c.Request.URI().Path()),
					"stack", stack,
				)
				if cfg.PanicReporter != nil {
					safeReport(ctx, cfg.PanicReporter, c, r, stack)
				}
				cfg.ErrorHandler(c, r, stack)
			}
		}()
		c.Next(ctx)
	}
}

// safeReport 调 Reporter 并隔离其内部 panic(2026-09-05 复审修复:此处
// 已在 deferred 函数内、外层 recover() 消费之后,Reporter panic 原本会
// 替换业务原始 panic 且跳过 ErrorHandler/响应 — 第三方监控 SDK 恰是最
// 可能 panic 的代码)。上报失败只记日志,不影响错误响应。
func safeReport(ctx context.Context, r SentryReporter, c *app.RequestContext, panicVal any, stack string) {
	defer func() {
		if rp := recover(); rp != nil {
			recoveryLog.CtxError(ctx, "[panic] panic reporter panicked; report dropped",
				"reporter_panic", rp,
				"original_panic", panicVal,
			)
		}
	}()
	r.Report(ctx, c, panicVal, stack)
}
