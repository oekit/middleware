package mw

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/core/chain"
	"github.com/oekit/logx"
	"github.com/oekit/middleware/chainmw"
	"github.com/oekit/middleware/hmw"
)

// AccessLogOptions 是访问日志中间件的配置。
type AccessLogOptions struct {
	// SkipPaths 是不需要记录日志的路径列表，如 ["/metrics", "/ping", "/health"]。
	// 健康检查和监控端点通常请求频繁，跳过可减少日志噪音。
	SkipPaths []string

	// RedactPathPrefixes 是需要脱敏的路径前缀列表。命中前缀的路径只保留
	// 前缀本身、其余部分替换为 "/***"——「URL 路径即凭证」的路由
	// （webhook/{token} 类：钉钉/企微 access_token、GitHub webhook 自配路径）
	// 若整条落盘，token 作为调用凭证会随日志进入采集/存储体系
	// （[#12](https://github.com/oekit/middleware/issues/12)）。
	// 前缀按字节匹配；前缀命中的脱敏优先于 path 字段的记录，SkipPaths
	// 判定仍使用原始路径（跳过规则不受脱敏影响）。
	RedactPathPrefixes []string

	// Sinks 是访问记录的旁路消费者列表（落库 / 上报），见 WithAccessLogSink。
	Sinks []AccessSink
}

// AccessRecord 是 AccessLogMiddleware 单次请求的 HTTP 采集结果，与日志字段
// 同源同值（Path 已按 RedactPathPrefixes 脱敏）。纯值类型，可安全跨 goroutine
// 持有——异步落库时只拿它、不要带 *app.RequestContext。
type AccessRecord struct {
	// Method 请求方法。
	Method string
	// Path 请求路径（已脱敏，与日志 path 字段同值）。
	Path string
	// Status 响应状态码（handler 链执行完毕后读取）。
	Status int
	// Latency handler 链耗时。
	Latency time.Duration
	// ClientIP 客户端 IP（c.ClientIP()，尊重 X-Forwarded-For 等代理头配置）。
	ClientIP string
	// UserAgent 请求 User-Agent。
	UserAgent string
	// TraceID hmw 注入的 trace_id；未挂 hmw.Middleware 时为空串。
	TraceID string
	// Panic 为 true 表示本记录来自 panic 恢复点（#20）：请求已被记日志/喂 sink
	// 后按原值重抛给外层 Recovery；Status 按 Recovery 缺省 500 记。
	Panic bool
}

// AccessSink 接收单次请求的访问记录（[#18](https://github.com/oekit/middleware/issues/18)），
// 在日志写出后、同请求 goroutine 内同步调用。c 为当前请求上下文——可读
// c.Get 里鉴权中间件注入的 userId 等业务键、请求头、路由模板——但 **仅在本次
// 调用内有效**（Hertz RequestContext 池化复用），需异步处理时只持有 rec。
//
// 返回 error 或 panic 都只记 Warn 日志，不影响主链路（响应早已写出，访问记录
// 是旁路；落库失败不能把请求拖垮）。多个 sink 彼此隔离、按注册顺序调用。
type AccessSink func(ctx context.Context, c *app.RequestContext, rec AccessRecord) error

// AccessLogOption 配置 AccessLogMiddleware。
type AccessLogOption func(*AccessLogOptions)

// WithAccessLogSkipPaths 设置不需要记录日志的路径列表。
func WithAccessLogSkipPaths(paths ...string) AccessLogOption {
	return func(o *AccessLogOptions) {
		o.SkipPaths = append(o.SkipPaths, paths...)
	}
}

// WithAccessLogRedactPathPrefixes 设置需要脱敏的路径前缀列表。
// 命中前缀的路径在日志中只保留前缀、其余替换为 "/***"，如前缀
// "/api/v2/webhook/alert" 命中 "/api/v2/webhook/alert/tk-123" 记为
// "/api/v2/webhook/alert/***"。
func WithAccessLogRedactPathPrefixes(prefixes ...string) AccessLogOption {
	return func(o *AccessLogOptions) {
		o.RedactPathPrefixes = append(o.RedactPathPrefixes, prefixes...)
	}
}

// WithAccessLogSink 注册访问记录旁路消费者——配合调用方自己的 access_log 表
// 落库、或上报到审计/统计系统（#18）。可多次调用追加；SkipPaths 命中的请求
// 不触发（跳过 = 不记录，日志与落库口径一致）。
//
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSink(
//	    func(ctx context.Context, c *app.RequestContext, rec mw.AccessRecord) error {
//	        uid, _ := c.Get("userId") // 自家鉴权中间件注入的业务键
//	        return accessLogDAO.Save(ctx, uid, rec) // 落库失败只记 Warn，不影响响应
//	    })))
func WithAccessLogSink(sink AccessSink) AccessLogOption {
	return func(o *AccessLogOptions) {
		if sink != nil {
			o.Sinks = append(o.Sinks, sink)
		}
	}
}

func newAccessLogOptions(opts ...AccessLogOption) *AccessLogOptions {
	cfg := &AccessLogOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

var accessLog = logx.Delegating("access")

// accessRecordOf 由 Hertz 请求上下文与内核采集结果拼出 HTTP 语义的访问记录。
func accessRecordOf(c *app.RequestContext, rec chainmw.AccessRecord) AccessRecord {
	status := c.Response.StatusCode()
	if rec.Panic {
		status = 500 // panic 恢复点状态码尚未写出，按 Recovery 缺省 500 记（#20）
	}
	return AccessRecord{
		Method:    string(c.Method()),
		Path:      rec.Operation,
		Status:    status,
		Latency:   rec.Latency,
		ClientIP:  c.ClientIP(),
		UserAgent: string(c.UserAgent()),
		TraceID:   hmw.FromRequestContext(c),
		Panic:     rec.Panic,
	}
}

// AccessLogMiddleware 记录每个 HTTP 请求的访问日志。
//
// 特性:
//   - 使用 scoped logger 输出结构化日志，自动携带 trace_id
//   - 可通过 WithAccessLogSkipPaths 跳过健康检查等高频路径（支持 glob 模式）
//   - 可通过 WithAccessLogRedactPathPrefixes 对「URL 路径即凭证」的路由
//     （webhook/{token} 类）做路径脱敏，token 不落日志
//   - 可通过 WithAccessLogSink 把同一份记录（AccessRecord）旁路交给落库/上报
//     消费者；sink 出错或 panic 只记 Warn，不影响主链路（#18）
//   - panic 请求同样产出记录（#20）：恢复点记 Warn 日志（status 按 Recovery
//     缺省 500）并喂 sink（AccessRecord.Panic 标记）后按原值重抛，外层 Recovery
//     照常处理——落库场景 panic 请求同样留痕
//   - 无参调用即启用默认配置（不跳过任何路径、不脱敏、不落库）
//
// # 实现说明（#14）
//
// 本中间件是 chainmw.AccessLog 内核的 Hertz 薄壳：SkipPaths 匹配、路径
// 脱敏、耗时采集、sink 隔离执行收敛在内核单点维护（kitex 侧经 ToKitex 桥接
// 同步获得同等能力），本层只注入 hertz→transport 服务端上下文并保持既有日志
// 格式（logger、消息、字段与顺序不变）。下游 handler 可经
// transport.FromServerContext 读取协议无关传输信息。
//
// 使用方式:
//
//	// 默认配置（不跳过任何路径）
//	h.Use(mw.AccessLogMiddleware())
//
//	// 跳过健康检查和指标端点（支持 glob 模式）
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSkipPaths("/metrics", "/ping", "/health", "/internal/*")))
//
//	// webhook 凭证路径脱敏
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert", "/api/v2/task/trigger")))
//
//	// 同一份记录落到自家 access_log 表
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSink(func(ctx context.Context, c *app.RequestContext, rec mw.AccessRecord) error {
//	    return dao.SaveAccessLog(ctx, rec)
//	})))
func AccessLogMiddleware(opts ...AccessLogOption) app.HandlerFunc {
	cfg := newAccessLogOptions(opts...)

	kernelOpts := make([]chainmw.AccessLogOption, 0, 5+len(cfg.Sinks))
	kernelOpts = append(kernelOpts,
		chainmw.WithLogger(accessLog),
		chainmw.WithLogMessage("request"),
		chainmw.WithSkipPaths(cfg.SkipPaths...),
		chainmw.WithRedactPathPrefixes(cfg.RedactPathPrefixes...),
		chainmw.WithLogFields(func(_ context.Context, req any, rec chainmw.AccessRecord) []any {
			c, ok := req.(*app.RequestContext)
			if !ok {
				return nil
			}
			status := c.Response.StatusCode()
			if rec.Panic {
				// panic 恢复点记录：状态码尚未写出（Recovery 在外侧、稍后写缺省
				// 500 统一错误体），按 500 记（#20；自定义 ErrorHandler 时以
				// Recovery 自身日志为准）
				status = 500
			}
			return []any{
				"method", string(c.Method()),
				"path", rec.Operation,
				"status", status,
				"latency_ms", rec.Latency.Milliseconds(),
				"ip", c.ClientIP(),
			}
		}),
	)
	// 每个 sink 单独注册进内核：内核逐个隔离执行，前一个 panic 不影响后一个。
	for _, sink := range cfg.Sinks {
		sink := sink
		kernelOpts = append(kernelOpts, chainmw.WithSink(func(ctx context.Context, req any, rec chainmw.AccessRecord) error {
			c, ok := req.(*app.RequestContext)
			if !ok {
				return nil
			}
			return sink(ctx, c, accessRecordOf(c, rec))
		}))
	}
	kernel := chainmw.AccessLog(kernelOpts...)
	handled := kernel(chain.Handler(func(ctx context.Context, req any) (any, error) {
		if c, ok := req.(*app.RequestContext); ok {
			c.Next(ctx)
		}
		return nil, nil
	}))

	return func(ctx context.Context, c *app.RequestContext) {
		_, _ = handled(newHertzServerContext(ctx, c), c)
	}
}
