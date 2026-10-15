package mw

import (
	"context"
	stderrors "errors"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
	ekiterrors "github.com/yi-nology/ekit-errors"
	"github.com/yi-nology/ekit-logx"
	"github.com/yi-nology/ekit-registry/registry"
)

// NotFoundErrChecker 是可注入的"资源未找到"错误检查函数。
// 用于 Fail 的第二层判定，将特定错误映射为 HTTP 404。
// 默认返回 false（无特殊 not-found 判定）。
// 通过 WithNotFoundChecker option 按调用注入，或在构造时设置默认值。
type NotFoundErrChecker func(err error) bool

var notFoundChecker atomic.Pointer[NotFoundErrChecker]

// failLog 带 component 属性的 scoped logger（PLATFORM_CONTRACT §3：
// SDK 组件日志以 component 标识来源；此前直接用包级 logx 无 component）。
var failLog = logx.Delegating("middleware-fail")

func init() {
	f := NotFoundErrChecker(func(error) bool { return false })
	notFoundChecker.Store(&f)
}

// FailOption 配置 Fail 函数的行为。
type FailOption func(*failOptions)

type failOptions struct {
	notFoundChecker NotFoundErrChecker
}

// WithNotFoundChecker 设置 Fail 的"资源未找到"错误检查器。
// 传入 nil 时使用全局默认 checker。
func WithNotFoundChecker(checker func(error) bool) FailOption {
	return func(o *failOptions) {
		o.notFoundChecker = checker
	}
}

// Fail 是 handler 统一错误处理, 跟 fuxi 7 service 'fail()' 同 3-tier 模式:
//  1. err 是 *ekiterrors.BizError -> writeBizError(c, bizErr) (BizCode 入 body, HTTPCode 决定 HTTP 状态)
//  2. err 匹配 NotFoundErrChecker -> ErrorResp(c, 404, "resource not found")
//  3. err 包装 registry.ErrNoInstances -> ErrorResp(c, 503, "service unavailable")
//     （依赖服务无可用实例是依赖不可用而非本服务 bug，Warn 级日志避免误告警）
//  4. 其他 err -> failLog.CtxError(ctx, "internal error", "err", err) + ErrorResp(c, 500, "internal server error")
//
// 500 fallback 路径必 log (unexpected server error), BizError / not-found / 503
// 走 4xx/5xx 语义码是 expected 状态, 不打 error noise.
//
// ctx 为 Hertz handler 的 context.Context，500 路径通过 CtxError 自动携带 trace_id。
// *app.RequestContext 不实现 context.Context，因此 ctx 需显式传入。
//
// 用法:
//
//	if err := service.X(); err != nil {
//	    middleware.Fail(ctx, c, err)
//	    return
//	}
func Fail(ctx context.Context, c *app.RequestContext, err error, opts ...FailOption) {
	if err == nil {
		return
	}
	var bizErr *ekiterrors.BizError
	if stderrors.As(err, &bizErr) {
		writeBizError(c, bizErr)
		return
	}
	// 发现类错误：上游无可用实例 → 503（依赖不可用语义）
	if stderrors.Is(err, registry.ErrNoInstances) {
		failLog.CtxWarn(ctx, "dependency has no instances", "err", err)
		ErrorResp(c, 503, "service unavailable")
		return
	}
	// Resolve not-found checker: per-call option overrides global default.
	checker := *notFoundChecker.Load()
	if len(opts) > 0 {
		o := &failOptions{}
		for _, opt := range opts {
			opt(o)
		}
		if o.notFoundChecker != nil {
			checker = o.notFoundChecker
		}
	}
	if checker(err) {
		ErrorResp(c, 404, "resource not found")
		return
	}
	failLog.CtxError(ctx, "internal error", "err", err)
	ErrorResp(c, 500, "internal server error")
}
