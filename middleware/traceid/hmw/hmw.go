// Package hmw 提供 trace_id 的 Hertz 中间件实现。
//
// 本包是 middleware/traceid 的 Hertz 适配层，负责：
//   - 生成 trace_id 并注入 Hertz RequestContext 和标准 context.Context
//   - 提供从 RequestContext 提取 trace_id 的便捷函数
//
// 框架无关的核心定义（Key、HeaderKey、FromContext、ContextWith）
// 在 middleware/traceid 包中，本包通过 import 复用。
package hmw

import (
	"context"
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"
	"github.com/hertz-contrib/requestid"
	"github.com/yi-nology/ekit-tracing/traceid"
)

// FromRequestContext 从 Hertz RequestContext 中提取 trace_id。
// trace_id 由 Middleware 注入到 RequestContext。
// 返回空字符串表示上下文中没有 trace_id（中间件未注册）。
func FromRequestContext(c *app.RequestContext) string {
	v, exists := c.Get(traceid.Key)
	if !exists {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// Middleware 返回请求 ID 中间件链，负责 trace_id 的生成、透传与桥接。
//
// 采用社区标准实现 hertz-contrib/requestid 作为生成核心，并附加一层桥接，
// 将 requestid 生成的 ID 同步到 ekit 内部的两处存储，保证下游消费者零改动：
//   - Hertz RequestContext: c.Set(Key, ...)（供 FromRequestContext/health/version 读取）
//   - 标准 context.Context: traceid.ContextWith（供 logx.Ctx* / service 层 / NATS publisher 读取）
//
// 流程:
//  1. requestid.New — 读取请求头 traceid.HeaderKey，缺失则生成 traceid.IDLength 位 ID，写入响应头
//  2. bridge — 读取 requestid 写入的 ID，同步注入 c.Set 与标准 context
//
// 使用方式:
//
//	// 注册为最前置的中间件（在 ResponseMiddleware 之前）
//	h.Use(hmw.Middleware()...)
func Middleware() []app.HandlerFunc {
	gen := requestid.New(
		requestid.WithCustomHeaderStrKey(requestid.HeaderStrKey(traceid.HeaderKey)),
		requestid.WithGenerator(func(ctx context.Context, c *app.RequestContext) string {
			return newTraceID()
		}),
	)

	bridge := func(ctx context.Context, c *app.RequestContext) {
		// 直接从响应头读取 requestid 写入的 ID（避免依赖 requestid 包级全局变量）
		rid := c.Response.Header.Get(traceid.HeaderKey)
		if !validTraceID(rid) {
			// 客户端可控头：垃圾值（超长/任意字符）原样进响应头会撞 ID 伪造
			// 调用链关联、日志洪水。requestid 只在请求头"缺失"时生成，对
			// 非空垃圾值不兜底——这里直接替换为新生成的合法 ID 并补齐三处
			// 注入（c.Header 覆盖残留值），保证该请求 trace 链路不断。
			rid = newTraceID()
		}
		c.Header(traceid.HeaderKey, rid)
		c.Set(traceid.Key, rid)
		ctx = traceid.ContextWith(ctx, rid)
		c.Next(ctx)
	}

	return []app.HandlerFunc{gen, bridge}
}

// newTraceID 生成 traceid.IDLength 位随机 ID（与 requestid generator 同源）。
func newTraceID() string {
	return uuid.New().String()[:traceid.IDLength]
}

// validTraceID 校验客户端提供的 trace ID：非空、长度上限 64，字符白名单
// [0-9a-zA-Z-]（本包生成 12 位十六进制、W3C trace-id 为 32 位十六进制，
// 弹性接受字母数字连字符格式；白名单防日志注入/洪水）。
func validTraceID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-':
		default:
			return false
		}
	}
	return true
}
