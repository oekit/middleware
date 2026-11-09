package chainmw

import (
	"context"
	"fmt"
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
// 行为：下游 panic 被捕获为 *chain.PanicError → 经 panic 隔离的监控钩子
// 上报 → 记 Error 日志 → 以错误返回（链不中断）。上报先于日志（#138）：
// 日志路径自身出问题时上报钩子已经执行。下游**以 *PanicError 形式返回**
// （例如链上内层的 core/chain.Timeout 已把 panic 收编成错误再上抛）走同一
// 上报+日志口径，与「直接 panic」的路径一致。响应转换由调用方的错误出口
// 负责（hertz/chainmw.Wrap 的 WithOnError/默认 mw.Fail、kitex 侧透传给
// kitex 错误处理）。
//
// 上报与日志两条路径均在 panic 隔离下执行（#138）：panic 值自身是 Error()
// 会炸的 error、字段构建器或 logger/上报钩子再 panic 时，recovery 自身绝
// 不能被打挂——否则上报静默丢失、错误返回丢失，panic 逃出 transport 层
// （hertz 无默认 PanicHandler ⇒ 连接冲垮）。
//
// 与 core/chain.Recovery 的关系：捕获/转换语义一致（含「以 *PanicError
// 返回」这条上报路径）；本实现叠加 logx 日志与上报/日志 panic 隔离，为
// 「一份逻辑两端跑」的内核（根包 mw 的 Hertz 栈与 kitex 经 ToKitex 桥接均
// 复用本实现）。注：内外两层都是本中间件嵌套时，*PanicError 返回路径会双记
// 日志/双上报——core/chain.Recovery 同样如此，保持与 core 语义一致优先。
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
					// 先上报、后打日志（#138）：日志路径出问题时上报钩子已执行。
					cfg.reportIsolated(ctx, req, pv)
					cfg.logPanic(ctx, req, pv)
					resp, err = nil, pv
				}
			}()
			resp, err = next(ctx, req)
			// 下游以 *PanicError **形式返回**（例如下游中间的 Timeout 已把
			// panic 收编成错误再往上抛）⇒ 同样走日志与上报钩子，与「直接
			// panic」的路径口径一致（对齐 core/chain.Recovery 的第二条上报
			// 路径；否则这类 panic 不进 Sentry 等上报、连 [panic] recovered
			// 日志都没有——带日志的实现反而在该路径零观测，#123）。
			if pe, ok := err.(*chain.PanicError); ok {
				cfg.reportIsolated(ctx, req, pe)
				cfg.logPanic(ctx, req, pe)
			}
			return resp, err
		}
	}
}

// panicSafeText panic 安全地把任意值转成可打印文本：值自身的 Error()/格式化
// 再 panic（evil error 形态，#138）也不逃逸，降级为类型名描述。
func panicSafeText(v any) (s string) {
	defer func() {
		if recover() != nil {
			s = fmt.Sprintf("<unprintable %T>", v)
		}
	}()
	return fmt.Sprintf("%v", v)
}

// logIsolatedPanic 输出隔离路径的兜底日志（panicKey 区分 reporter_panic /
// logger_panic）。日志后端再 panic 时只能吞掉（已无处可记）——绝不让兜底
// 日志把 recovery 自身打穿（#138）。字段值一律经 panicSafeText：
// original_panic 可能是 Error() 会炸的 evil error，裸塞进 kv 会在日志后端
// 格式化时再次 panic。
func (c *recoveryConfig) logIsolatedPanic(ctx context.Context, msg, panicKey string, isolatedPanic any, pv *chain.PanicError) {
	func() {
		defer func() { _ = recover() }()
		c.logger.CtxError(ctx, msg,
			panicKey, panicSafeText(isolatedPanic),
			"original_panic", panicSafeText(pv.Value),
		)
	}()
}

// logPanic 输出 panic 日志（panic 隔离，#138）。字段顺序：自定义构建器优先；
// 默认 panic/stack/kind/op（无 transport 上下文时 kind/op 为 "-"）。
func (c *recoveryConfig) logPanic(ctx context.Context, req any, pv *chain.PanicError) {
	// 与 reportIsolated 同款隔离：panic 值是 Error() 会炸的 error 时，把
	// pv.Value 塞进 kv 交给日志后端（slog logValue 直接调 err.Error()）就会
	// 二次 panic；字段构建器、logger 后端同样可能炸。隔离保证日志路径永远
	// 不会把 recovery 自身打挂（上报与错误返回已在其之前完成，#138）。
	defer func() {
		if rp := recover(); rp != nil {
			c.logIsolatedPanic(ctx, panicLogMessage, "logger_panic", rp, pv)
		}
	}()
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
			c.logIsolatedPanic(ctx, reporterPanicMessage, "reporter_panic", rp, pv)
		}
	}()
	c.reporter(ctx, req, pv)
}
