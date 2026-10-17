package mw

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/concurrency/shedding"
	ekiterrors "github.com/oekit/pkg/errors"
)

// SheddingOptions 是降载中间件的配置。
type SheddingOptions struct {
	// Shedder 降载器（nil = 用 CPU 阈值构造缺省自适应降载器）。
	Shedder shedding.Shedder

	// cpuThreshold 为 WithShedderCPUThreshold 注入的 CPU 过载阈值
	// （千分毫核记法），hasCPU 标记是否显式配置。仅在 Shedder == nil
	// 时用于构造缺省降载器；显式指定 Shedder 后整体 no-op。
	cpuThreshold int64
	hasCPU       bool
}

// SheddingOption 配置 SheddingMiddleware（函数选项模式，禁止裸 Option）。
type SheddingOption func(*SheddingOptions)

// WithShedder 注入调用方自建的降载器（如经 shedding.WithShedderClock/
// WithShedderRejectHandler 定制后 NewAdaptiveShedder 的实例，或测试 fake）。
//
// 优先级：显式 Shedder 胜出 —— 此时 WithShedderCPUThreshold 变为 no-op
// （含越界值也不会 panic）。
func WithShedder(s shedding.Shedder) SheddingOption {
	return func(o *SheddingOptions) {
		o.Shedder = s
	}
}

// WithShedderCPUThreshold 定制缺省自适应降载器的 CPU 过载阈值
// （千分毫核记法，900 即 90%）。仅在本中间件未通过 WithShedder 显式
// 指定降载器时生效；合法性校验（须在 (0, 1000) 开区间）延迟到
// SheddingMiddleware 构造缺省降载器时执行 —— 越界在构造期 panic
// （fail-fast，启动即暴露，非首次请求）。
func WithShedderCPUThreshold(milli int64) SheddingOption {
	return func(o *SheddingOptions) {
		o.cpuThreshold, o.hasCPU = milli, true
	}
}

// SheddingMiddleware 返回 CPU 自适应降载（load shedding）中间件，消费
// concurrency/shedding 包的 Shedder 接口。
//
// 行为：
//   - Allow(ctx) 返回任何 error（ErrServiceOverloaded / ctx 已取消等）
//     一律按过载拒绝处理：BizError{BizCode: 50300, HTTPCode: 503} 经
//     Fail 写出 —— HTTP 503 + body code 50300（50300 与 Fail 的
//     ErrNoInstances 503 "service unavailable" 区分：50300 特指本服务
//     过载主动丢弃，而非依赖不可用），JSON 响应结构与现有错误路径一致。
//   - 放行 → c.Next(ctx) 后按响应状态码回填 Promise：>= 500 调 Fail()
//     （4xx 是调用方错误，与服务容量无关，计 Pass），否则 Pass()。
//   - handler panic：defer 内 recover 后先 Fail() 再原样 re-panic ——
//     不吞 panic、panic 值原样透传，交由外层 RecoveryMiddleware 捕获
//     （Recovery 在外/在内两种注册顺序均能保证 Fail 被回填：后者经
//     500 状态码分类）。未注册 Recovery 时行为与未挂本中间件一致
//     （引擎无默认 PanicHandler，断连）。
//
// **opt-in，不加入 DefaultMiddleware 栈**：会丢弃请求的中间件不能默认开。
// 需要时显式 h.Use(mw.SheddingMiddleware(...))。
//
// 生命周期说明：缺省降载器首次读到 CPU 采样会惰性启动进程级唯一的
// 后台采样 goroutine（随进程存活，无法被中间件停止；对齐上游 shedding
// 包设计）。非 linux 平台 CPU 采样恒错误 → 按不过载处理（fail-open），
// 降载自动禁用、全放行。需要丢弃诊断/监控时，经
// shedding.WithShedderRejectHandler 构造降载器后用 WithShedder 注入
// （本包不强制接 logx/metrics）。
//
// 使用方式：
//
//	h.Use(mw.SheddingMiddleware())                          // 缺省 CPU 阈值 900
//	h.Use(mw.SheddingMiddleware(
//	    mw.WithShedderCPUThreshold(800),                    // 80% 过载阈值
//	))
//	shed := shedding.NewAdaptiveShedder(shedding.WithShedderRejectHandler(func(reason string) {
//	    logx.Warn("shedding drop", "reason", reason)
//	}))
//	h.Use(mw.SheddingMiddleware(mw.WithShedder(shed)))      // 显式降载器（CPU 阈值选项失效）
func SheddingMiddleware(opts ...SheddingOption) app.HandlerFunc {
	cfg := &SheddingOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	shedder := cfg.Shedder
	if shedder == nil {
		var sopts []shedding.ShedderOption
		if cfg.hasCPU {
			// 越界阈值在此 panic（构造期 fail-fast，同 ratelimit 缺配置的姿势）
			sopts = append(sopts, shedding.WithShedderCPUThreshold(cfg.cpuThreshold))
		}
		shedder = shedding.NewAdaptiveShedder(sopts...)
	}

	return func(ctx context.Context, c *app.RequestContext) {
		promise, err := shedder.Allow(ctx)
		if err != nil {
			// 任何错误一律按过载拒绝：503 + body code 50300，经 Fail 的
			// writeBizError 写出（与现有错误路径同一 JSON 响应结构 + Abort）。
			Fail(ctx, c, ekiterrors.NewBizErrorWithStatus(50300, 503, "service is overloaded"))
			return
		}
		if promise == nil {
			// Shedder 实现违约（放行却返回 nil Promise）：不回填统计，
			// 继续处理 —— 降载器自身缺陷不放大为请求失败。
			c.Next(ctx)
			return
		}
		defer func() {
			if r := recover(); r != nil {
				// handler panic：按失败回填后原样再抛。panic 值透传给外层
				// Recovery（注意：re-panic 后外层 recover 到的堆栈不含
				// handler 原始帧；Recovery 注册在本中间件之内时本 defer
				// 的 recover 读到 nil，按下方状态码分类同样 Fail）。
				promise.Fail()
				panic(r)
			}
			if c.Response.StatusCode() >= 500 {
				promise.Fail()
			} else {
				promise.Pass()
			}
		}()
		c.Next(ctx)
	}
}
