package mw

import (
	"context"
	stderrors "errors"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/logx"
	ekiterrors "github.com/oekit/pkg/errors"
	"github.com/oekit/registry"
)

// NotFoundErrChecker 是可注入的"资源未找到"错误检查函数。
// 用于 Fail 的第二层判定，将特定错误映射为 HTTP 404。
// 默认返回 false（无特殊 not-found 判定）。
// 通过 WithNotFoundChecker option 按调用注入，或在构造时设置默认值。
type NotFoundErrChecker func(err error) bool

var notFoundChecker atomic.Pointer[NotFoundErrChecker]

// failLog 带 component 属性的 scoped logger（平台契约 §3：
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
//  1. err 是 *ekiterrors.BizError -> writeBizError(c, bizErr, nil) (BizCode 入 body, HTTPCode 决定 HTTP 状态)
//  2. err 匹配 NotFoundErrChecker -> ErrorResp(c, 404, "resource not found")
//  3. err 包装 registry.ErrNoInstances -> BizError{BizCode: 50300, HTTPCode: 503}
//     经 writeBizError 写出（body code=50300；依赖服务无可用实例是依赖不可用
//     而非本服务 bug，Warn 级日志避免误告警。#291：原先直出 ErrorResp 503 的
//     body code=503，与 kitex 桥 no-instance / shedding 过载的 50300 分叉，
//     同一故障被码段监控拆成两个 series——本行为变更见 CHANGELOG 对应版本节）
//  4. 其他 err -> failLog.CtxError(ctx, "internal error", logx.ErrKey, err) + ErrorResp(c, 500, "internal server error")
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
	// AsBizError 对 typed-nil *BizError（`func f() *BizError { return nil }`
	// 装进 error 接口）返回 false——裸 errors.As 会匹配成功拿到 nil 指针，
	// writeBizError 解引用 bizErr.HTTPCode 直接 panic，错误出口自身崩溃（#95）。
	if bizErr, ok := ekiterrors.AsBizError(err); ok {
		// WrapBizError 的 cause 不回显到响应（防内部细节泄漏）但必须落日志：
		// 否则 "create branch failed" / "encrypt token" 这类壳文案成为排障盲区，
		// 下游曾为定位一个合并失败翻了三轮日志（实测）。
		if cause := bizErr.Unwrap(); cause != nil {
			failLog.CtxError(ctx, "biz error cause", "biz_code", bizErr.BizCode, "msg", bizErr.Message, "cause", cause)
		}
		writeBizError(c, bizErr, nil)
		return
	}
	// Resolve not-found checker: per-call option overrides global default.
	// 判定顺序按 godoc 编号钉死（#254）：tier 2 NotFoundErrChecker 先于
	// tier 3 ErrNoInstances——同一错误同时命中两者时 checker 说了算（404），
	// 与文档一致；旧实现反序，文档承诺的 404 被 503 顶掉。
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
	// 发现类错误：上游无可用实例 → BizError 50300 / HTTP 503（依赖不可用语义）。
	// #291 三轨收敛：kitex 桥 no-instance（BizCode=50300）与 shedding 过载
	// （BizError 50300）均已按 body code 50300 出码，本 tier 原直出 ErrorResp
	// 503（body code=503）使同一"依赖无可用实例"故障在码段监控里被拆成两个
	// series（503 vs 50300）。收编为 BizError 走 writeBizError：HTTP 仍 503、
	// message 仍 "service unavailable"，仅 body code 503→50300（行为变更，
	// 见 CHANGELOG 对应版本节）；cause 只进构造的错误对象不回显响应，防止
	// 内部细节泄漏（与 tier 1 同约定）。
	if stderrors.Is(err, registry.ErrNoInstances) {
		failLog.CtxWarn(ctx, "dependency has no instances", logx.ErrKey, err)
		writeBizError(c, ekiterrors.WrapBizErrorWithStatus(50300, 503, "service unavailable", err), nil)
		return
	}
	failLog.CtxError(ctx, "internal error", logx.ErrKey, err)
	ErrorResp(c, 500, "internal server error")
}

// FailWithData 与 Fail 同 3-tier 语义，BizError 路径的响应体额外携带 data：
// 202 业务态（如激活状态机的 VERIFYING——请求已受理、结果未知）需要按统一封套
// 返回 BizCode + HTTPCode + message + trace_id，并附会话数据供调用方继续轮询。
// 非 BizError 路径（not-found / 503 / 500 fallback）与 Fail 完全一致——data 不透传，
// 内部错误细节不对外暴露。其余约定见 Fail。
//
// 用法:
//
//	res, bizErr := service.X(ctx)
//	if bizErr != nil {
//	    middleware.FailWithData(ctx, c, bizErr, toView(res))
//	    return
//	}
func FailWithData(ctx context.Context, c *app.RequestContext, err error, data any, opts ...FailOption) {
	if err == nil {
		return
	}
	// 同 Fail：AsBizError 拒绝 typed-nil（#95）；cause 只落日志不回显。
	if bizErr, ok := ekiterrors.AsBizError(err); ok {
		if cause := bizErr.Unwrap(); cause != nil {
			failLog.CtxError(ctx, "biz error cause", "biz_code", bizErr.BizCode, "msg", bizErr.Message, "cause", cause)
		}
		writeBizError(c, bizErr, data)
		return
	}
	Fail(ctx, c, err, opts...)
}
