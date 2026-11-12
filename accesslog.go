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

// infraPaths 是基础设施探活/监控端点的标准路径清单（#137）：SkipPaths 类
// 配置的事实标准收编——/metrics（Prometheus 抓取）、/ping、/healthz、/livez、
// /readyz（K8s 探针）、/health、/ready（常见手抄变体）、/buildVersion（版本
// 端点）。这份清单此前由各消费方手抄，已现实漂移出 5 个变体、同仓不同
// 中间件漏跳同一路径（探针流量落进审计日志与限流计数，故障期探测风暴时
// 可能触发限流误伤），故由库单点维护、中间件缺省兜底。
//
// 只读性靠类型不靠约定（#188）：清单不再导出可变包级切片——任何消费方
// 一次 append/赋值即全进程污染三个中间件（accesslog/ratelimit）豁免面且
// 静默无信号；导出面经 InfraPaths() 函数收口，每次调用返回独立拷贝。
var infraPaths = []string{
	"/metrics",
	"/ping",
	"/healthz",
	"/livez",
	"/readyz",
	"/health",
	"/ready",
	"/buildVersion",
}

// InfraPaths 返回基础设施探活/监控端点标准路径清单的**独立副本**（#188，
// 原 v0.17 及之前是导出可变切片 `var InfraPaths []string`，v0.18 起收口为
// 函数——0.x minor 允许 breaking，消费方 `mw.InfraPaths` 改 `mw.InfraPaths()`）。
//
// 匹配语义同 SkipPaths（pathx.MatchesPath glob）——以上均为字面路径。
// 追加自定义豁免：`append(mw.InfraPaths(), "/api/**")`（副本上追加不污染
// 库内清单）。
func InfraPaths() []string {
	return append([]string(nil), infraPaths...)
}

// withInfraPathsDefault SkipPaths 缺省兜底（#137）：未显式传时用 InfraPaths；
// 显式传则**完全覆盖**缺省（不是追加）——显式清单是调用方对豁免面的完整
// 声明，不存在「补丁式追加」的隐式并集。
func withInfraPathsDefault(paths []string) []string {
	if len(paths) > 0 {
		return paths
	}
	return InfraPaths()
}

// AccessLogOptions 是访问日志中间件的配置。
type AccessLogOptions struct {
	// SkipPaths 是不需要记录日志的路径列表，如 ["/metrics", "/ping", "/health"]。
	// 健康检查和监控端点通常请求频繁，跳过可减少日志噪音。
	//
	// 缺省语义（#137）：未显式传时用 mw.InfraPaths() 兜底（标准探活/监控
	// 端点零日志零 sink）；显式传则**完全覆盖**缺省——不在显式清单内的
	// 路径（含 InfraPaths 里的）照常记录，不是「InfraPaths + 显式清单」
	// 的并集。
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

	// Silent 开启「只采不写」模式（#38）：本中间件不写任何日志（访问日志
	// 本身与 sink 故障告警都不写），但采集行为完全不变——SkipPaths 判定、
	// 路径脱敏、sink 调用、panic 请求的记录产出与原值重抛都照常。
	// 适用于宿主自带 logger 输出同一份记录、不想双写的场景。
	Silent bool

	// Logger 是访问日志的输出 logger；nil 表示用内建 logx.Delegating("access")
	// （默认行为）。注入宿主自己的 logger 后，访问记录仍由本中间件写出
	// （消息与字段不变），只是落到宿主的后端——宿主无需再写一份造成双写
	// （#38）。宿主用 zap 等非 logx 后端时可自行实现 logx.Logger 适配，
	// 或改用 logx.SetDefault 整体替换后端。
	Logger logx.Logger

	// ClientIPFunc 是客户端 IP 解析缝（#83）：签名与 pkg/convert.ResolveClientIP
	// 一致（对端地址、XFF 头、可信代理 CIDR 列表 → 客户端 IP），nil 走默认口径。
	//
	// ⚠️ 默认口径自 v0.13.9 起**不再采信任意来源的 XFF**（fail-closed）：
	// 此前走 `c.ClientIP()`——hertz 默认信任任意网段的 X-Forwarded-For，直连方
	// 可随意伪造，落库消费方（审计/安全分析按 IP 归因）的来源 IP 全被毒化，
	// 且与同仓 ratelimit 的防伪造口径（defaultIPKey 用直连地址）自相矛盾。
	// 默认=「对端地址，可信网段为空」；代理拓扑（RemoteAddr=上游网关）下按真实
	// 客户端 IP 记录：注入本缝，如 `mw.WithAccessLogClientIP(func(remote, xff string, _ []string) string {
	//     return convert.ResolveClientIP(remote, xff, myTrustedCIDRs)
	// })`（或直接用 oekit/hertz 的 clientip.GetClientIP 包一层）。字段含义与
	// 日志 ip 字段、sink 的 AccessRecord.ClientIP 同源同值。
	ClientIPFunc func(remoteAddr, xff string, trustedProxies []string) string
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
	// ClientIP 客户端 IP。默认口径为对端地址（fail-closed，不采信任意来源的
	// XFF，#83）；代理拓扑下经 WithAccessLogClientIP 注入可信网段解析。
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

// WithAccessLogSkipPaths 设置不需要记录日志的路径列表（glob 模式）。
//
// 匹配走 pathx.MatchesPath（filepath.Match 语义 + "/**" 目录前缀分支）：
// `*` 是**单段**通配符，不跨 "/"——"/internal/*" 只命中 "/internal/inspect"
// 这类直接子路径，不命中 "/internal/db/query"、"/internal/webhook/<token>"
// 等嵌套路径；要豁免整棵子树用 "/internal/**"（"/**" 目录前缀跨层）。
// 常用形态："/metrics"（精确）、"/health*"（同段前缀）、"/internal/**"
// （子树全部）。
//
// ⚠️ 显式传即**完全覆盖** InfraPaths 缺省（#137）：不在显式清单内的路径
// 照常记录——需要额外豁免业务路径又想保留探活豁免时，把 mw.InfraPaths()
// 一并写进清单（`append(mw.InfraPaths(), "/internal/**")`）。
//
// ⚠️ 嵌套路径漏跳是静默的：不报错也无日志线索——按 "/internal/*" 以为内部
// 端点已豁免，嵌套路径照常整条进日志，正是「URL 路径即凭证」（#12）要防的
// 泄露面在「我以为已经关掉」的错觉下继续泄露（#127）。语义钉子测试见
// TestAccessLogMiddleware_SkipPathsGlobSegmentSemantics。
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

// WithAccessLogSilent 开启「只采不写」模式（#38）。
//
// 中间件不再写任何日志：访问日志本身、以及 sink 失败/panic 的告警日志都
// 不写。**采集行为完全不变**——SkipPaths 判定、路径脱敏、sink 调用（时机与
// 顺序不变）、panic 请求的记录产出（AccessRecord.Panic=true）与按原值重抛
// 都照常，因此库的 redaction / skip 能力在静默下依然可用。
//
// 典型用法：宿主有自己的 logger（含业务字段、按状态码分级），想复用库的
// 脱敏与跳过能力、但不想让库再写一行造成双写——此时由 sink 或宿主自己的
// 采集逻辑输出记录，中间件只负责采集：
//
//	h.Use(mw.AccessLogMiddleware(
//	    mw.WithAccessLogSilent(),
//	    mw.WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert"),
//	    mw.WithAccessLogSink(func(ctx context.Context, c *app.RequestContext, rec mw.AccessRecord) error {
//	        return dao.SaveAccessLog(ctx, rec)
//	    }),
//	))
//
// 与 WithAccessLogLogger 同时使用时静默优先：注入的 logger 只用于 sink 告警，
// 静默下也不写。
func WithAccessLogSilent() AccessLogOption {
	return func(o *AccessLogOptions) {
		o.Silent = true
	}
}

// WithAccessLogLogger 注入访问日志的输出 logger（#38）。
//
// 默认用内建 logx.Delegating("access")；注入后访问记录仍由本中间件写出
// （消息 "request" 与字段 method/path/status/latency_ms/ip 不变），只是落到
// 宿主的后端——宿主不必再写一份，避免双写。nil 被忽略（保持默认 logger）。
//
// 宿主用 zap 等非 logx 后端时，可自行实现 logx.Logger 接口做适配；若只是
// 想换后端而不改字段，用 logx.SetDefault 整体替换更省事。
func WithAccessLogLogger(l logx.Logger) AccessLogOption {
	return func(o *AccessLogOptions) {
		if l != nil {
			o.Logger = l
		}
	}
}

// WithAccessLogClientIP 注入客户端 IP 解析函数（#83）：代理拓扑下按可信代理
// 网段解析真实客户端 IP，推荐直接包一层 pkg/convert.ResolveClientIP（或
// oekit/hertz clientip.GetClientIP，同源实现）：
//
//	mw.AccessLogMiddleware(mw.WithAccessLogClientIP(func(remote, xff string, _ []string) string {
//	    return convert.ResolveClientIP(remote, xff, []string{"10.0.0.0/8"})
//	}))
//
// nil 不覆盖既有配置。函数在每请求路径上调用，保持轻量。
func WithAccessLogClientIP(fn func(remoteAddr, xff string, trustedProxies []string) string) AccessLogOption {
	return func(o *AccessLogOptions) {
		if fn != nil {
			o.ClientIPFunc = fn
		}
	}
}

// resolveClientIP 统一出口（#83）：默认 fail-closed——只取对端地址（去端口），
// 不采信任何代理头（hertz c.ClientIP() 默认信任任意网段 XFF，直连方可伪造，
// 与同仓 ratelimit defaultIPKey 的防伪造口径必须一致——审计链的 IP 比限流
// key 更不能被毒化）。可信网段解析属部署形态知识，经 WithAccessLogClientIP
// 显式注入。
func resolveClientIP(c *app.RequestContext, fn func(remoteAddr, xff string, trustedProxies []string) string) string {
	if fn != nil {
		return fn(c.RemoteAddr().String(), string(c.Request.Header.Peek("X-Forwarded-For")), nil)
	}
	return hostOnly(c.RemoteAddr().String())
}

func newAccessLogOptions(opts ...AccessLogOption) *AccessLogOptions {
	cfg := &AccessLogOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.SkipPaths = withInfraPathsDefault(cfg.SkipPaths) // #137 缺省兜底
	return cfg
}

var accessLog = logx.Delegating("access")

// accessRecordOf 由 Hertz 请求上下文与内核采集结果拼出 HTTP 语义的访问记录。
// clientIPFunc 是 AccessLogOptions.ClientIPFunc 的透传（#83 口径缝）。
func accessRecordOf(c *app.RequestContext, rec chainmw.AccessRecord, clientIPFunc func(remoteAddr, xff string, trustedProxies []string) string) AccessRecord {
	status := c.Response.StatusCode()
	if rec.Panic {
		status = 500 // panic 恢复点状态码尚未写出，按 Recovery 缺省 500 记（#20）
	}
	return AccessRecord{
		Method:    string(c.Method()),
		Path:      rec.Operation,
		Status:    status,
		Latency:   rec.Latency,
		ClientIP:  resolveClientIP(c, clientIPFunc),
		UserAgent: string(c.UserAgent()),
		TraceID:   hmw.FromRequestContext(c),
		Panic:     rec.Panic,
	}
}

// AccessLogMiddleware 记录每个 HTTP 请求的访问日志。
//
// 特性:
//   - 使用 scoped logger 输出结构化日志，自动携带 trace_id
//   - 可通过 WithAccessLogSkipPaths 跳过健康检查等高频路径（支持 glob 模式；
//     注意 `*` 单段不跨 "/"，子树豁免用 "/**"，见该函数文档）
//   - 可通过 WithAccessLogRedactPathPrefixes 对「URL 路径即凭证」的路由
//     （webhook/{token} 类）做路径脱敏，token 不落日志
//   - 可通过 WithAccessLogSink 把同一份记录（AccessRecord）旁路交给落库/上报
//     消费者；sink 出错或 panic 只记 Warn，不影响主链路（#18）
//   - panic 请求同样产出记录（#20）：恢复点记 Warn 日志（status 按 Recovery
//     缺省 500）并喂 sink（AccessRecord.Panic 标记）后按原值重抛，外层 Recovery
//     照常处理——落库场景 panic 请求同样留痕
//   - 可通过 WithAccessLogSilent 关闭内建日志输出（只采不写，采集行为不变）
//     或通过 WithAccessLogLogger 注入宿主 logger（避免宿主再写一份造成双写）
//     （#38）
//   - ClientIP 默认 fail-closed（#83）：取对端地址，不采信任意来源的 XFF
//     （与同仓 ratelimit 防伪造口径一致）；代理拓扑经 WithAccessLogClientIP
//     注入可信网段解析（推荐包一层 pkg/convert.ResolveClientIP）
//   - SkipPaths 缺省按 mw.InfraPaths() 兜底（#137）：标准探活/监控端点零日志
//     零 sink；显式传则完全覆盖缺省（不是追加）
//   - 其余缺省：不脱敏、不落库
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
//	// 跳过健康检查和指标端点（支持 glob 模式；"/internal/**" 豁免整棵子树）
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSkipPaths("/metrics", "/ping", "/health", "/internal/**")))
//
//	// webhook 凭证路径脱敏
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert", "/api/v2/task/trigger")))
//
//	// 同一份记录落到自家 access_log 表
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogSink(func(ctx context.Context, c *app.RequestContext, rec mw.AccessRecord) error {
//	    return dao.SaveAccessLog(ctx, rec)
//	})))
//
//	// 宿主自带 logger 输出同一份记录：静默关闭内建日志，只采不写（#38）
//	h.Use(mw.AccessLogMiddleware(
//	    mw.WithAccessLogSilent(),
//	    mw.WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert"),
//	    mw.WithAccessLogSink(func(ctx context.Context, c *app.RequestContext, rec mw.AccessRecord) error {
//	        return dao.SaveAccessLog(ctx, rec)
//	    }),
//	))
//
//	// 或把内建日志改道到宿主的 logger（宿主不再自己写一份）
//	h.Use(mw.AccessLogMiddleware(mw.WithAccessLogLogger(hostLogger)))
func AccessLogMiddleware(opts ...AccessLogOption) app.HandlerFunc {
	cfg := newAccessLogOptions(opts...)

	// logger 解析顺序：显式注入 > 内建 Delegating（#38）。静默模式下 logger
	// 只用于 sink 故障告警，且静默优先——告警也不写。
	logger := cfg.Logger
	if logger == nil {
		logger = accessLog
	}

	kernelOpts := make([]chainmw.AccessLogOption, 0, 6+len(cfg.Sinks))
	kernelOpts = append(kernelOpts,
		chainmw.WithLogger(logger),
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
				"ip", resolveClientIP(c, cfg.ClientIPFunc),
			}
		}),
	)
	if cfg.Silent {
		kernelOpts = append(kernelOpts, chainmw.WithSilent())
	}
	// 每个 sink 单独注册进内核：内核逐个隔离执行，前一个 panic 不影响后一个。
	for _, sink := range cfg.Sinks {
		sink := sink
		kernelOpts = append(kernelOpts, chainmw.WithSink(func(ctx context.Context, req any, rec chainmw.AccessRecord) error {
			c, ok := req.(*app.RequestContext)
			if !ok {
				return nil
			}
			return sink(ctx, c, accessRecordOf(c, rec, cfg.ClientIPFunc))
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
