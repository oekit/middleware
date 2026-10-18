// Package chainmw 提供 transport 感知的框架无关中间件（基于 core/chain）。
//
// 与根包 mw（Hertz app.HandlerFunc 栈）互补：本包中间件面向 core/chain
// 的 Handler 形态，经 core/transport 读写协议无关的传输信息（Kind/Operation/
// Header），可在 hertz、kitex、nns-endpoint 等形态间经桥接复用。根包 mw 的
// RecoveryMiddleware/AccessLogMiddleware 亦复用本包内核（#14，一份逻辑两端
// 跑）：Hertz 栈为薄壳，kitex 经 ToKitex 桥接同步获得同等能力。
//
// 用法：
//
//	h := chain.Finalize(terminal,
//	    chainmw.Recovery(chainmw.WithRecoveryReporter(reportPanic)),
//	    chainmw.AccessLog(),
//	    chainmw.MetadataPropagate("x-tenant-id"),
//	)
package chainmw

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oekit/core/chain"
	"github.com/oekit/core/transport"
	"github.com/oekit/logx"
	"github.com/oekit/pkg/pathx"
)

var accessLog = logx.Delegating("chainmw-accesslog")

// transportInfo 从 transport 上下文读取 Kind/Operation（服务端优先，其次
// 客户端）；无上下文时返回 "-", "-"。
func transportInfo(ctx context.Context) (kind, op string) {
	kind, op = "-", "-"
	if tr, ok := transport.FromServerContext(ctx); ok {
		kind = string(tr.Kind())
		op = tr.Operation()
	} else if tr, ok := transport.FromClientContext(ctx); ok {
		kind = string(tr.Kind())
		op = tr.Operation()
	}
	return kind, op
}

// AccessRecord 是 AccessLog 单次请求的采集结果，供 WithLogFields 构建
// 自定义日志字段。Operation 已按脱敏前缀处理（SkipPaths 判定用原始值，
// 不受脱敏影响）。
type AccessRecord struct {
	// Kind 传输类型（http/grpc）；无 transport 上下文时 "-"。
	Kind string
	// Operation 操作标识（http 为请求 PATH），已脱敏。
	Operation string
	// Latency 下游处理耗时。
	Latency time.Duration
	// Err 下游返回的错误（nil = 成功）。
	Err error
}

// AccessLogOption 配置 AccessLog 中间件。
type AccessLogOption func(*accessLogConfig)

// AccessSink 是访问记录的旁路消费者（落库 / 上报 / 统计），每条记录产出后
// 按注册顺序同步调用；SkipPaths 命中的请求不触发（跳过 = 不记录，日志与
// sink 口径一致）。返回 error 或 panic 都只记 Warn 日志、绝不影响主链路——
// 访问记录是旁路，落库失败不能把请求拖垮。
type AccessSink func(ctx context.Context, req any, rec AccessRecord) error

type accessLogConfig struct {
	logger  logx.Logger
	message string
	fields  func(ctx context.Context, req any, rec AccessRecord) []any
	skip    []string
	redact  []string
	sinks   []AccessSink
}

// WithLogger 注入 logger（默认 logx.Delegating("chainmw-accesslog")）。
// 日志经 Ctx* 方法输出，自动携带 trace_id。
func WithLogger(l logx.Logger) AccessLogOption {
	return func(c *accessLogConfig) { c.logger = l }
}

// WithLogMessage 自定义日志消息（默认 "access"）。
func WithLogMessage(msg string) AccessLogOption {
	return func(c *accessLogConfig) { c.message = msg }
}

// WithLogFields 自定义日志字段构建器（返回键值对序列，顺序即输出顺序；
// 默认字段 kind/op/cost）。框架桥接层用此注入框架特有字段——如根包 mw
// 薄壳注入 method/status/latency_ms/ip 保持既有日志格式。
func WithLogFields(fn func(ctx context.Context, req any, rec AccessRecord) []any) AccessLogOption {
	return func(c *accessLogConfig) { c.fields = fn }
}

// WithSkipPaths 设置跳过记录的 Operation 模式列表（支持 glob，按原始值
// 匹配、不受脱敏影响；http 侧即请求 PATH，如 "/metrics"、"/internal/*"）。
// 命中时下游照常执行、仅不记访问日志。无 transport 上下文时不判定。
func WithSkipPaths(patterns ...string) AccessLogOption {
	return func(c *accessLogConfig) { c.skip = append(c.skip, patterns...) }
}

// WithRedactPathPrefixes 设置需要脱敏的 Operation 前缀列表。命中前缀的
// Operation 在日志中只保留前缀、其余替换为 "/***"（webhook/{token} 类
// 「URL 路径即凭证」路由的 token 不落日志，见根包 mw #12）。SkipPaths
// 判定不受脱敏影响。
func WithRedactPathPrefixes(prefixes ...string) AccessLogOption {
	return func(c *accessLogConfig) { c.redact = append(c.redact, prefixes...) }
}

// WithSink 追加访问记录旁路消费者（可多次调用，按注册顺序同步调用；
// 多个 sink 彼此隔离——前一个 panic 不影响后一个）。需要异步落库时在 sink
// 内自行入队：rec 是纯值可安全跨 goroutine 持有，req 则随框架生命周期
// （如 Hertz RequestContext 池化复用）不得逸出本次调用。
func WithSink(sink AccessSink) AccessLogOption {
	return func(c *accessLogConfig) {
		if sink != nil {
			c.sinks = append(c.sinks, sink)
		}
	}
}

// runSink 隔离执行单个 sink：error 与 panic 都只记 Warn，不向调用方传播。
func runSink(ctx context.Context, logger logx.Logger, sink AccessSink, req any, rec AccessRecord) {
	defer func() {
		if r := recover(); r != nil {
			logger.CtxWarn(ctx, "access sink panic", "op", rec.Operation, "panic", fmt.Sprint(r))
		}
	}()
	if err := sink(ctx, req, rec); err != nil {
		logger.CtxWarn(ctx, "access sink failed", "op", rec.Operation, "err", err.Error())
	}
}

// AccessLog 返回访问日志中间件：从 transport 上下文读取 Kind/Operation，
// 记录耗时、错误与 panic（配合 Recovery 使用时 panic 已在上游转换，此处
// 记录 error）。无 transport 上下文时相应字段记 "-"。日志写出后依次调用
// WithSink 注册的旁路消费者（隔离执行，不影响返回值）。
func AccessLog(opts ...AccessLogOption) chain.Middleware {
	cfg := &accessLogConfig{logger: accessLog, message: "access"}
	for _, opt := range opts {
		opt(cfg)
	}
	logger := cfg.logger
	return func(next chain.Handler) chain.Handler {
		return func(ctx context.Context, req any) (any, error) {
			kind, op := transportInfo(ctx)
			if len(cfg.skip) > 0 && op != "-" && pathx.MatchesPath(cfg.skip, op) {
				return next(ctx, req)
			}
			display := op
			if len(cfg.redact) > 0 {
				display = RedactPath(op, cfg.redact)
			}

			start := time.Now()
			resp, err := next(ctx, req)
			rec := AccessRecord{Kind: kind, Operation: display, Latency: time.Since(start), Err: err}

			var kvs []any
			if cfg.fields != nil {
				kvs = cfg.fields(ctx, req, rec)
			} else {
				kvs = []any{"kind", rec.Kind, "op", rec.Operation, "cost", rec.Latency.String()}
			}
			if rec.Err != nil {
				kvs = append(kvs, "err", rec.Err.Error())
				logger.CtxWarn(ctx, cfg.message, kvs...)
			} else {
				logger.CtxInfo(ctx, cfg.message, kvs...)
			}
			for _, sink := range cfg.sinks {
				runSink(ctx, logger, sink, req, rec)
			}
			return resp, err
		}
	}
}

// RedactPath 命中任一前缀则保留前缀、其余替换为 "/***"；未命中原样返回。
// 前缀按字节匹配（"/alert" 也会命中 "/alert-x"，多脱敏无副作用）；前缀
// 恰好等于完整路径（len 相等）视为无敏感尾段，原样返回。
func RedactPath(path string, prefixes []string) string {
	for _, p := range prefixes {
		if p == "" || !strings.HasPrefix(path, p) || len(path) == len(p) {
			continue
		}
		return p + "/***"
	}
	return path
}
