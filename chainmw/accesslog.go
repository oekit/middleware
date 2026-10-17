// Package chainmw 提供 transport 感知的框架无关中间件（基于 core/chain）。
//
// 与根包 mw（Hertz app.HandlerFunc 栈）互补：本包中间件面向 core/chain
// 的 Handler 形态，经 core/transport 读写协议无关的传输信息（Kind/Operation/
// Header），可在 hertz、kitex、nns-endpoint 等形态间经桥接复用。
//
// 用法：
//
//	h := chain.Finalize(terminal,
//	    chainmw.AccessLog(),
//	    chainmw.MetadataPropagate("x-tenant-id"),
//	)
package chainmw

import (
	"context"
	"time"

	"github.com/oekit/core/chain"
	"github.com/oekit/core/transport"
	"github.com/oekit/logx"
)

var accessLog = logx.Delegating("chainmw-accesslog")

// AccessLogOption 配置 AccessLog 中间件。
type AccessLogOption func(*accessLogConfig)

type accessLogConfig struct {
	logger logx.Logger
}

// WithLogger 注入 logger（默认 logx.Delegating("chainmw-accesslog")）。
func WithLogger(l logx.Logger) AccessLogOption {
	return func(c *accessLogConfig) { c.logger = l }
}

// AccessLog 返回访问日志中间件：从 transport 上下文读取 Kind/Operation，
// 记录耗时、错误与 panic（配合 chain.Recovery 使用时 panic 已在上游转换，
// 此处记录 error）。无 transport 上下文时相应字段记 "-"。
func AccessLog(opts ...AccessLogOption) chain.Middleware {
	cfg := &accessLogConfig{logger: accessLog}
	for _, opt := range opts {
		opt(cfg)
	}
	logger := cfg.logger
	return func(next chain.Handler) chain.Handler {
		return func(ctx context.Context, req any) (any, error) {
			start := time.Now()
			resp, err := next(ctx, req)

			kind, op := "-", "-"
			if tr, ok := transport.FromServerContext(ctx); ok {
				kind = string(tr.Kind())
				op = tr.Operation()
			} else if tr, ok := transport.FromClientContext(ctx); ok {
				kind = string(tr.Kind())
				op = tr.Operation()
			}

			kvs := []any{
				"kind", kind,
				"op", op,
				"cost", time.Since(start).String(),
			}
			if err != nil {
				kvs = append(kvs, "err", err.Error())
				logger.Warn("access", kvs...)
				return resp, err
			}
			logger.Info("access", kvs...)
			return resp, err
		}
	}
}
