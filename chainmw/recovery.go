package chainmw

import (
	"context"
	"runtime/debug"

	"github.com/oekit/core/chain"
	"github.com/oekit/logx"
)

var recoveryLog = logx.Delegating("chainmw-recovery")

// panic 日志文案。根包 mw 的 RecoveryMiddleware 薄壳经 WithRecoveryLogger/
// WithRecoveryLogFields 复用本内核时依赖这两个常量保持既有日志输出不变。
const (
	panicLogMessage      = "[panic] recovered"
	reporterPanicMessage = "[panic] panic reporter panicked; report dropped"
)

// RecoveryOption 配置 Recovery 中间件。
type RecoveryOption func(*recoveryConfig)

type recoveryConfig struct {
	logger   logx.Logger
	fields   func(ctx context.Context, req any, pv *chain.PanicError) []any
	reporter func(ctx context.Context, req any, pv *chain.PanicError)
}

// WithRecoveryLogger 注入 logger（默认 logx.Delegating("chainmw-recovery")）。
// 日志经 Ctx* 方法输出，自动携带 trace_id。
func WithRecoveryLogger(l logx.Logger) RecoveryOption {
	return func(c *recoveryConfig) { c.logger = l }
}

// WithRecoveryReporter 注入监控上报钩子（sentry/datadog 等业务适配器）。
//
// 钩子在 panic 隔离下调用：钩子内部 panic 被捕获并记 Error 日志
// （reporter_panic/original_panic 字段）、本次上报被丢弃，不影响原始
// panic 的日志与错误返回——第三方监控 SDK 恰是最可能 panic 的代码
// （先例：根包 mw.RecoveryMiddleware 的 safeReport，2026-09-05 复审修复）。
//
// 与 core/chain.WithPanicReporter 的差异：本钩子带 logx 日志与 panic 隔离，
// 且参数为 *chain.PanicError（与 Recovery 的错误返回类型一致）。
func WithRecoveryReporter(fn func(ctx context.Context, req any, pv *chain.PanicError)) RecoveryOption {
	return func(c *recoveryConfig) { c.reporter = fn }
}

// WithRecoveryLogFields 自定义 panic 日志字段构建器（返回键值对序列，顺序
// 即输出顺序；默认字段 panic/stack/kind/op）。框架桥接层用此注入框架特有
// 字段——如根包 mw 薄壳注入 method/path 保持既有日志格式。
func WithRecoveryLogFields(fn func(ctx context.Context, req any, pv *chain.PanicError) []any) RecoveryOption {
	return func(c *recoveryConfig) { c.fields = fn }
}

// Recovery 返回 panic 恢复中间件（transport 无关内核）。
//
// 行为：下游 panic 被捕获为 *chain.PanicError → 记 Error 日志 → 经 panic
// 隔离的监控钩子上报 → 以错误返回（链不中断）。响应转换由调用方的错误
// 出口负责（hertz/chainmw.Wrap 的 WithOnError/默认 mw.Fail、kitex 侧透传
// 给 kitex 错误处理）。
//
// 与 core/chain.Recovery 的关系：捕获/转换语义一致；本实现叠加 logx 日志
// 与上报 panic 隔离，为「一份逻辑两端跑」的内核（根包 mw 的 Hertz 栈与
// kitex 经 ToKitex 桥接均复用本实现）。
//
// 用法：
//
//	h := chain.Finalize(terminal,
//	    chainmw.Recovery(chainmw.WithRecoveryReporter(reportPanic)),
//	    chainmw.AccessLog(),
//	)
//
// 无 transport 上下文时 kind/op 记 "-"。
func Recovery(opts ...RecoveryOption) chain.Middleware {
	cfg := &recoveryConfig{logger: recoveryLog}
	for _, opt := range opts {
		opt(cfg)
	}
	return func(next chain.Handler) chain.Handler {
		return func(ctx context.Context, req any) (resp any, err error) {
			defer func() {
				if r := recover(); r != nil {
					pv := &chain.PanicError{Value: r, Stack: string(debug.Stack())}
					cfg.logPanic(ctx, req, pv)
					cfg.reportIsolated(ctx, req, pv)
					resp, err = nil, pv
				}
			}()
			return next(ctx, req)
		}
	}
}

// logPanic 输出 panic 日志。字段顺序：自定义构建器优先；默认
// panic/stack/kind/op（无 transport 上下文时 kind/op 为 "-"）。
func (c *recoveryConfig) logPanic(ctx context.Context, req any, pv *chain.PanicError) {
	var kvs []any
	if c.fields != nil {
		kvs = c.fields(ctx, req, pv)
	} else {
		kind, op := transportInfo(ctx)
		kvs = []any{"panic", pv.Value, "stack", pv.Stack, "kind", kind, "op", op}
	}
	c.logger.CtxError(ctx, panicLogMessage, kvs...)
}

// reportIsolated 在 panic 隔离下调用上报钩子（见 WithRecoveryReporter）。
func (c *recoveryConfig) reportIsolated(ctx context.Context, req any, pv *chain.PanicError) {
	if c.reporter == nil {
		return
	}
	defer func() {
		if rp := recover(); rp != nil {
			c.logger.CtxError(ctx, reporterPanicMessage,
				"reporter_panic", rp,
				"original_panic", pv.Value,
			)
		}
	}()
	c.reporter(ctx, req, pv)
}
