package mw

import (
	"context"
	"errors"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/core/chain"
	"github.com/oekit/logx"
	"github.com/oekit/middleware/chainmw"
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
// # 为什么必须有 RecoveryMiddleware
//
// Hertz **没有默认 PanicHandler**：engine.PanicHandler 为 nil 时
// ServeHTTP 不会挂 defer recover（hertz pkg/route/engine.go：
// `if engine.PanicHandler != nil { defer engine.recv(ctx) }`，
// server.New 不设默认值），netpoll 连接层 onProcess/onRequest 也
// 不做 recover（cloudwego/netpoll connection_onevent.go）——handler
// panic 直接冲垮连接（客户端 connection reset，无 500/无统一错误体/
// 无 access log），最坏情况带崩整个进程。因此**任何自定义 HTTP 中间件
// 栈都必须包含本中间件**（或 mw.MinimalMiddleware / mw.DefaultMiddleware，
// 均已内置）。见 AGENTS.md 硬规则。
//
// # 实现说明（#14）
//
// 本中间件是 chainmw.Recovery 内核的 Hertz 薄壳：panic 捕获/日志/上报
// 隔离收敛在内核单点维护（kitex 侧经 ToKitex 桥接同步获得同等能力），
// 本层只做 SentryReporter 签名适配（带 *app.RequestContext）与响应写出。
// 日志文案、字段与顺序、reporter panic 隔离语义与 v0.8.0 前实现一致。
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

	kernel := chainmw.Recovery(
		chainmw.WithRecoveryLogger(recoveryLog),
		chainmw.WithRecoveryLogFields(func(_ context.Context, req any, pv *chain.PanicError) []any {
			kvs := []any{"err", pv.Value}
			if c, ok := req.(*app.RequestContext); ok {
				kvs = append(kvs,
					"method", string(c.Method()),
					"path", string(c.Request.URI().Path()),
				)
			}
			return append(kvs, "stack", pv.Stack)
		}),
		// SentryReporter 桥接：内核已做上报 panic 隔离（隔离日志文案/字段
		// 与 v0.8.0 前 safeReport 一致），此处直接透传调用。
		chainmw.WithRecoveryReporter(func(ctx context.Context, req any, pv *chain.PanicError) {
			if cfg.PanicReporter == nil {
				return
			}
			if c, ok := req.(*app.RequestContext); ok {
				cfg.PanicReporter.Report(ctx, c, pv.Value, pv.Stack)
			}
		}),
	)
	handled := kernel(chain.Handler(func(ctx context.Context, req any) (any, error) {
		if c, ok := req.(*app.RequestContext); ok {
			c.Next(ctx)
		}
		return nil, nil
	}))

	return func(ctx context.Context, c *app.RequestContext) {
		_, err := handled(ctx, c)
		var pv *chain.PanicError
		if errors.As(err, &pv) {
			cfg.ErrorHandler(c, pv.Value, pv.Stack)
		}
	}
}
