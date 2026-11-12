package mw

import (
	"context"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/concurrency/async"
	"github.com/oekit/logx"
	"github.com/oekit/middleware/hmw"
	"github.com/oekit/pkg/errors"
	"github.com/oekit/pkg/pathx"
)

// auditLog 带 component 属性的 scoped logger（平台契约 §3）。
var auditLog = logx.Delegating("audit")

// AuditEvent 是 AuditLogMiddleware 单次请求的审计事件——「谁对什么做了什么、
// 结果如何」（middleware#141）。与 accesslog 的访问记录语义不同：访问日志记
// 「请求来了」（全记 + skip），审计日志记「敏感操作留痕」（显式声明制，
// 漏记比多记危险）。纯值类型，可安全跨 goroutine 持有——异步落库时只持有
// 事件，不要带 *app.RequestContext（Hertz RequestContext 池化复用）。
type AuditEvent struct {
	// When 事件时间（请求进入审计面时刻，非落库时刻）。
	When time.Time
	// Who 操作者标识。默认取 TrustedHeadersIdentity 注入的 TrustedClaims.
	// UserID（mw.ClaimsFrom）；身份中间件未注册或匿名时为空串——空串即
	// 「匿名身份」，不是「缺字段」。租户等其它维度经 WithAuditLogWho 注入。
	Who string
	// Action 业务动作。默认取路由模板（c.FullPath()，未匹配路由为空串）；
	// 语义化动作名（如 "policy.delete"）经 WithAuditLogAction 注入。
	Action string
	// Method HTTP 方法。
	Method string
	// Path 请求路径（原始路径，未脱敏——审计面要求精确可回溯，与 accesslog
	// 的脱敏口径相反）。
	Path string
	// Status 响应状态码。panic 请求按 Recovery 缺省 500 记（对齐 accesslog
	// #20 口径）。
	Status int
	// BizCode 业务码。中间件不解析响应体——业务码在响应体里还是错误返回值
	// 里因业务而异，经 WithAuditLogBizCode 注入提取函数；未注入恒为 0。
	BizCode int64
	// Latency handler 链耗时。
	Latency time.Duration
	// TraceID hmw 注入的 trace_id；未挂 hmw.Middleware 时为空串。
	TraceID string
	// IP 客户端网络地址（#193，审计 who 的网络维度）。缺省取连接对端地址
	// host 部分（fail-closed，不读 X-Forwarded-For——#83 同口径；代理拓扑
	// 按 XFF 归因经 WithAuditLogClientIP 注入解析缝）。合规场景禁采网络
	// 维度用 WithAuditLogOmitClientFields 关闭。
	IP string
	// UA 请求 User-Agent（#193）。缺省取 User-Agent 头原值；截断/脱敏形态
	// 经 WithAuditLogUA 注入。
	UA string
	// Extra 域字段扩展承载（#193）：IP/UA/请求体摘要等审计域字段的通用
	// 缝——WithAuditLogExtra 注入提取函数，事件产出时刻在请求 goroutine
	// 内调用（池化红线安全），返回的 map 原样进事件（中间件产出后不再
	// 修改；sink 异步持有安全）。nil = 未注入。内建日志 sink 会把 Extra
	// 键值并入结构化字段。
	Extra map[string]string
	// Panic 为 true 表示本事件来自 panic 恢复点：事件产出后按原值重抛给
	// 外层 Recovery（Status 按其缺省 500 记）。
	Panic bool
}

// AuditSink 接收单条审计事件。在请求 goroutine 内同步调用；返回 error 或
// panic 都只记 Warn 日志、不影响主链路（审计是旁路，落库失败不能把请求
// 拖垮；对齐 AccessSink 的隔离口径）。多个 sink 彼此隔离、按注册顺序调用。
// 需要缓冲批量落库（DB/队列）时用 NewBufferedAuditSink 包一层——见
// BufferedAuditSink。
type AuditSink func(ctx context.Context, ev AuditEvent) error

// AuditLogOptions 是 AuditLogMiddleware 的配置。
type AuditLogOptions struct {
	// AuditedPaths 是需要审计的路径清单（glob，语义同 SkipPaths：
	// pathx.MatchesPath，`*` 单段不跨 "/"，子树用 "/**"）。
	//
	// ⚠️ 显式声明制（middleware#141，与 accesslog 的「全记+skip」相反）：
	// 审计面漏记比多记危险——清单为空时构造期 panic（fail-loud），不存在
	// 「默认不审计」的静默形态。清单是审计面的完整声明：未声明的路径
	// （含 InfraPaths 探活/监控端点——它们从不该进审计面，无需另行排除）
	// 不产出事件、不触发 sink。
	//
	// 空/纯空白项（#206）与坏 glob 同口径构造期 panic：配置源回落空串、
	// 模板渲染出空项时，清单长度 ≥1 过检、运行期却永不命中——审计声明
	// 静默归零且零信号，正是本字段要防的形态。
	AuditedPaths []string

	// Sinks 是审计事件的消费者列表（落库/上报），见 WithAuditLogSink。
	// 未注册任何 sink 时事件写内建结构化日志（logx.Delegating("audit")，
	// 可经 Logger 改道）；注册后只走 sink、不再写内建日志——「多记方向
	// 安全」指的是审计覆盖面，不是同一事件双写。
	Sinks []AuditSink

	// Logger 是内建日志 sink 的输出 logger（Sinks 为空时生效）；nil 用
	// logx.Delegating("audit")。注入宿主 logger 避免双写（对齐
	// WithAccessLogLogger 口径）。
	Logger logx.Logger

	// WhoFunc 是操作者提取缝。nil 走默认口径（TrustedClaims.UserID，
	// 见 AuditEvent.Who）。挂载顺序要求：身份中间件在审计中间件之前
	// （DefaultMiddleware 栈内自定义鉴权的标准位置）。
	WhoFunc func(ctx context.Context, c *app.RequestContext) string

	// ActionFunc 是业务动作提取缝。nil 走默认口径（路由模板，
	// 见 AuditEvent.Action）。
	ActionFunc func(ctx context.Context, c *app.RequestContext) string

	// BizCodeFunc 是业务码提取缝。nil 恒记 0（见 AuditEvent.BizCode）。
	// 在请求 goroutine 内、响应写出后调用——可读 c.Response.Body() 或
	// handler 经 c.Set 留下的业务键。
	BizCodeFunc func(ctx context.Context, c *app.RequestContext) int64

	// IPFunc 是客户端地址提取缝（#193）。nil 走默认口径：连接对端地址
	// host 部分（fail-closed，不读 XFF，#83 同口径）；代理拓扑按 XFF 归因
	// 注入，如 `mw.WithAuditLogClientIP(func(ctx, c) string {
	//     return convert.ResolveClientIP(c.RemoteAddr().String(),
	//         string(c.GetHeader("X-Forwarded-For")), myTrustedCIDRs) })`。
	// 显式注入优先于 OmitClientFields（显式配置是调用方对采集面的完整声明）。
	IPFunc func(ctx context.Context, c *app.RequestContext) string

	// UAFunc 是 User-Agent 提取缝（#193）。nil 走默认口径：User-Agent 头
	// 原值；截断/脱敏形态在此注入。显式注入优先于 OmitClientFields。
	UAFunc func(ctx context.Context, c *app.RequestContext) string

	// ExtraFunc 是域字段扩展提取缝（#193）：返回的 map 合入 AuditEvent.
	// Extra（请求体摘要/IP/UA 变体等审计域字段）。在请求 goroutine 内、
	// 事件产出时刻调用；每事件返回新 map（事件间不共享），返回 nil 无害。
	ExtraFunc func(ctx context.Context, c *app.RequestContext) map[string]string

	// OmitClientFields 置位后 AuditEvent 不填充 IP/UA 缺省采集（#193，
	// 合规场景：审计面禁采网络维度）。IPFunc/UAFunc 显式注入不受影响
	// （显式配置优先于开关）。
	OmitClientFields bool
}

// AuditLogOption 配置 AuditLogMiddleware。
type AuditLogOption func(*AuditLogOptions)

// WithAuditLogPaths 声明需要审计的路径清单（必填，glob 语义同 SkipPaths）。
// 清单为空时 AuditLogMiddleware 构造期 panic——审计面显式声明制
// （middleware#141），漏记比多记危险，不存在「静默不审计」的缺省；
// 空/纯空白串项同样构造期 panic（#206，坏 glob #201 同判据）。
//
//	mw.AuditLogMiddleware(mw.WithAuditLogPaths("/api/admin/**", "/api/v2/policy/*"))
func WithAuditLogPaths(paths ...string) AuditLogOption {
	return func(o *AuditLogOptions) {
		o.AuditedPaths = append(o.AuditedPaths, paths...)
	}
}

// WithAuditLogSink 注册审计事件消费者（落库/上报）。可多次调用追加；sink
// 出错或 panic 只记 Warn，不影响主链路。注册任一 sink 后内建日志关闭
// （事件只走 sink；需要同时留日志时再注册一个写日志的 sink）。
//
// 高频审计面建议配 NewBufferedAuditSink 缓冲批量落库：
//
//	buf := mw.NewBufferedAuditSink(func(ctx context.Context, events []mw.AuditEvent) error {
//	    return auditDAO.SaveBatch(ctx, events)
//	})
//	defer buf.Close(context.Background())
//	h.Use(mw.AuditLogMiddleware(
//	    mw.WithAuditLogPaths("/api/admin/**"),
//	    mw.WithAuditLogSink(buf.Sink),
//	))
func WithAuditLogSink(sink AuditSink) AuditLogOption {
	return func(o *AuditLogOptions) {
		if sink != nil {
			o.Sinks = append(o.Sinks, sink)
		}
	}
}

// WithAuditLogLogger 注入内建日志 sink 的输出 logger（Sinks 为空时生效）。
// nil 被忽略（保持默认 logx.Delegating("audit")）。对齐 WithAccessLogLogger
// 的防双写口径。
func WithAuditLogLogger(l logx.Logger) AuditLogOption {
	return func(o *AuditLogOptions) {
		if l != nil {
			o.Logger = l
		}
	}
}

// WithAuditLogWho 注入操作者提取缝（租户/多维度身份形态）。nil 保持默认
// （TrustedClaims.UserID）。
func WithAuditLogWho(fn func(ctx context.Context, c *app.RequestContext) string) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.WhoFunc = fn
		}
	}
}

// WithAuditLogAction 注入业务动作提取缝（如按路由返回 "policy.delete"）。
// nil 保持默认（路由模板）。
func WithAuditLogAction(fn func(ctx context.Context, c *app.RequestContext) string) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.ActionFunc = fn
		}
	}
}

// WithAuditLogBizCode 注入业务码提取缝（状态码之外的业务结果维度，如从
// 响应体 code 字段或 handler 留在 c.Set 的结果提取）。nil 恒记 0。
func WithAuditLogBizCode(fn func(ctx context.Context, c *app.RequestContext) int64) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.BizCodeFunc = fn
		}
	}
}

// WithAuditLogClientIP 注入客户端地址提取缝（#193，如可信代理 XFF 归因）。
// nil 保持默认（对端地址 host，fail-closed 不读 XFF）。显式注入优先于
// WithAuditLogOmitClientFields。
func WithAuditLogClientIP(fn func(ctx context.Context, c *app.RequestContext) string) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.IPFunc = fn
		}
	}
}

// WithAuditLogUA 注入 User-Agent 提取缝（#193，截断/脱敏形态）。nil 保持
// 默认（User-Agent 头原值）。显式注入优先于 WithAuditLogOmitClientFields。
func WithAuditLogUA(fn func(ctx context.Context, c *app.RequestContext) string) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.UAFunc = fn
		}
	}
}

// WithAuditLogExtra 注入域字段扩展提取缝（#193）：返回的 map 合入
// AuditEvent.Extra（请求体摘要等 IP/UA 之外的审计域字段）。fn 在请求
// goroutine 内、事件产出时刻调用；每事件返回新 map（事件间不共享），
// 返回 nil 无害。
func WithAuditLogExtra(fn func(ctx context.Context, c *app.RequestContext) map[string]string) AuditLogOption {
	return func(o *AuditLogOptions) {
		if fn != nil {
			o.ExtraFunc = fn
		}
	}
}

// WithAuditLogOmitClientFields 关闭 IP/UA 缺省采集（#193，合规场景：审计
// 面禁采网络维度）。IPFunc/UAFunc 显式注入不受影响。
func WithAuditLogOmitClientFields() AuditLogOption {
	return func(o *AuditLogOptions) {
		o.OmitClientFields = true
	}
}

// auditConfig 是启动期解析完毕的审计配置（请求热路径零重复解析）。
type auditConfig struct {
	auditedPaths     []string
	sinks            []AuditSink
	logger           logx.Logger
	whoFunc          func(ctx context.Context, c *app.RequestContext) string
	actionFunc       func(ctx context.Context, c *app.RequestContext) string
	bizCodeFunc      func(ctx context.Context, c *app.RequestContext) int64
	ipFunc           func(ctx context.Context, c *app.RequestContext) string
	uaFunc           func(ctx context.Context, c *app.RequestContext) string
	extraFunc        func(ctx context.Context, c *app.RequestContext) map[string]string
	omitClientFields bool
}

func newAuditConfig(opts ...AuditLogOption) *auditConfig {
	var o AuditLogOptions
	for _, opt := range opts {
		opt(&o)
	}
	if len(o.AuditedPaths) == 0 {
		// fail-loud（middleware#141）：审计面显式声明制——无声明即无审计，
		// 静默空转等于「以为在审计」的合规裸奔，与 BearerTokenAuth 未配置
		// token 的构造期 panic 同口径。
		panic("mw.AuditLogMiddleware: audited paths not configured, call WithAuditLogPaths first")
	}
	// 构造期预检 glob 语法（#201，fail-fast，与 chainmw.AccessLog #161 同一份
	// 判据）：pathx.MatchesPath 宽松档把 filepath.ErrBadPattern 吞成「不匹配」，
	// 一个坏 pattern 会让整个审计声明静默失效——敏感操作零事件落库（审计面
	// 漏记比多记危险），且零信号。误配在启动期炸响。
	//
	// 空/纯空白 pattern（#206）是 #201 的同族残留面：len 只拦空切片（[""]
	// 长度 1 过检）；filepath.Match("", "") 返回 (true, nil) 不报错（#201 预检
	// 全绿）；运行期 MatchesPath 宽松档对空 pattern 直接跳过——三道闸全放行，
	// 构造期全绿、运行期零事件零信号。与坏 glob 同口径点名炸响。
	for _, p := range o.AuditedPaths {
		if strings.TrimSpace(p) == "" {
			panic(fmt.Sprintf("mw.AuditLogMiddleware: empty audited path glob pattern %q——declare concrete audited paths via WithAuditLogPaths", p))
		}
		if _, err := filepath.Match(p, ""); err != nil {
			panic(fmt.Sprintf("mw.AuditLogMiddleware: invalid audited path glob pattern %q: %v", p, err))
		}
	}
	cfg := &auditConfig{
		auditedPaths:     append([]string(nil), o.AuditedPaths...),
		sinks:            o.Sinks,
		logger:           o.Logger,
		whoFunc:          o.WhoFunc,
		actionFunc:       o.ActionFunc,
		bizCodeFunc:      o.BizCodeFunc,
		ipFunc:           o.IPFunc,
		uaFunc:           o.UAFunc,
		extraFunc:        o.ExtraFunc,
		omitClientFields: o.OmitClientFields,
	}
	if cfg.whoFunc == nil {
		cfg.whoFunc = defaultAuditWho
	}
	if cfg.actionFunc == nil {
		cfg.actionFunc = defaultAuditAction
	}
	if cfg.bizCodeFunc == nil {
		cfg.bizCodeFunc = func(context.Context, *app.RequestContext) int64 { return 0 }
	}
	return cfg
}

// defaultAuditWho 默认操作者口径：TrustedHeadersIdentity 注入的 claims
// （middleware#141 事件模型——who 从 ctx 取）。中间件未注册或匿名时为空串。
func defaultAuditWho(ctx context.Context, _ *app.RequestContext) string {
	if claims, ok := ClaimsFrom(ctx); ok {
		return claims.UserID
	}
	return ""
}

// defaultAuditAction 默认业务动作口径：路由模板（如 /api/admin/:id）。
// 未匹配路由为空串（what 由 method+path 承载）。
func defaultAuditAction(_ context.Context, c *app.RequestContext) string {
	return c.FullPath()
}

// AuditLogMiddleware 记录显式声明路径的审计事件（middleware#141）——
// accesslog 的审计面孪生：who（TrustedClaims.UserID 或注入缝）/ what
// （method+path+业务动作）/ when / outcome（状态码+业务码）/ trace_id
// 结构化事件，交 Sink 消费（缺省内建 logx 结构化日志）。
//
// 特性:
//   - AuditedPaths 显式声明制：清单为空构造期 panic（漏记比多记危险，
//     fail-loud）；未声明路径零事件零 sink 调用（InfraPaths 探活端点天然
//     不在审计面，无需另行排除）
//   - panic 请求同样产出事件（Status 按 Recovery 缺省 500 记，Panic=true
//     标记），随后按原值重抛给外层 Recovery——对齐 accesslog #20 口径；
//     挂载位置须在 Recovery 之后（DefaultMiddleware 栈序）
//   - sink 出错/panic 只记 Warn，不影响主链路（审计是旁路）
//   - 高频审计面配 NewBufferedAuditSink：chan 缓冲 + 后台攒批 + 背压丢弃
//     （缓冲满丢弃不阻塞请求），fuxi_engine 手搓 bufferWriter 形态的原语化
//
// 与 AccessLogMiddleware 的分工：accesslog 全记（可 skip）、字段面向观测
// （ip/ua/耗时）；auditlog 只记声明的敏感操作面、字段面向追责（who/action/
// biz_code）、路径不脱敏（精确可回溯）。两者可并存，语义不重叠。
//
// 使用方式:
//
//	// 最小形态：审计事件写结构化日志
//	h.Use(mw.AuditLogMiddleware(mw.WithAuditLogPaths("/api/admin/**")))
//
//	// 落库：缓冲批量 sink（挂载在身份中间件之后，who 才有值）
//	buf := mw.NewBufferedAuditSink(func(ctx context.Context, events []mw.AuditEvent) error {
//	    return auditDAO.SaveBatch(ctx, events)
//	})
//	h.Use(mw.TrustedHeadersIdentity(...))
//	h.Use(mw.AuditLogMiddleware(
//	    mw.WithAuditLogPaths("/api/v2/policy/*", "/api/admin/**"),
//	    mw.WithAuditLogSink(buf.Sink),
//	    mw.WithAuditLogBizCode(func(ctx context.Context, c *app.RequestContext) int64 {
//	        // handler 把业务结果码留在 c.Set("bizCode") 时按其提取
//	        v, ok := c.Get("bizCode")
//	        if !ok { return 0 }
//	        n, _ := v.(int64)
//	        return n
//	    }),
//	))
//	defer buf.Close(context.Background())
func AuditLogMiddleware(opts ...AuditLogOption) app.HandlerFunc {
	cfg := newAuditConfig(opts...)
	return func(ctx context.Context, c *app.RequestContext) {
		if !pathx.MatchesPath(cfg.auditedPaths, string(c.Request.URI().Path())) {
			c.Next(ctx)
			return
		}
		start := time.Now()
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					// panic 恢复点事件：Status 按 Recovery 缺省 500 记
					// （对齐 accesslog #20），产出后按原值重抛。
					cfg.emit(ctx, auditEventOf(ctx, c, cfg, start, 500, true))
					panic(r)
				}
			}()
			c.Next(ctx)
		}()
		if !panicked {
			cfg.emit(ctx, auditEventOf(ctx, c, cfg, start, c.Response.StatusCode(), false))
		}
	}
}

// auditHookCall 提取钩子的收编壳（#210）：六个 With*Func 缝（who/action/
// biz_code/ip/ua/extra）都是用户注入的业务回调，在请求 goroutine 内、事件
// 产出时刻调用——坏钩子（nil map 写入/类型断言/下游透传）一旦 panic 会沿
// 提取缝上抛，打断审计事件产出甚至劫持 panic 恢复点语义（panic 路径的
// auditEventOf 跑在 Recovery 的 defer 里，二次 panic 会替换原始 panic 值）。
// 就地 Recovered 收编：panic 钩子按空值（零值）处理 + Warn 留痕，其余字段
// 照常提取——提取缝与 sink 缝（deliverAuditEvent）的隔离口径一致。
func auditHookCall[V any](ctx context.Context, name string, fn func() V) (v V) {
	defer func() {
		if perr := errors.Recovered(recover()); perr != nil {
			auditLog.CtxWarn(ctx, "audit hook panicked (isolated, zero value used)",
				"hook", name, logx.ErrKey, perr)
		}
	}()
	return fn()
}

// auditEventOf 由请求上下文拼出审计事件。status 由调用方给定：正常完成取
// c.Response.StatusCode()；panic 恢复点传 500（响应尚未写出）。
// IP/UA 缺省口径（#193）：IP=连接对端地址 host（fail-closed，不读 XFF——
// #83 同口径；在请求 goroutine 内提取，池化红线安全）；UA=User-Agent 头。
// OmitClientFields 关闭缺省采集；IPFunc/UAFunc/ExtraFunc 显式注入优先。
// 六个注入钩子逐个 panic 收编（#210）：坏钩子按空值处理 + Warn，事件产出
// 与其余字段不受牵连。
func auditEventOf(ctx context.Context, c *app.RequestContext, cfg *auditConfig, start time.Time, status int, panicked bool) AuditEvent {
	ev := AuditEvent{
		When:    start,
		Who:     auditHookCall(ctx, "who", func() string { return cfg.whoFunc(ctx, c) }),
		Action:  auditHookCall(ctx, "action", func() string { return cfg.actionFunc(ctx, c) }),
		Method:  string(c.Method()),
		Path:    string(c.Path()),
		Status:  status,
		BizCode: auditHookCall(ctx, "biz_code", func() int64 { return cfg.bizCodeFunc(ctx, c) }),
		Latency: time.Since(start),
		TraceID: hmw.FromRequestContext(c),
		Panic:   panicked,
	}
	if cfg.ipFunc != nil {
		ev.IP = auditHookCall(ctx, "client_ip", func() string { return cfg.ipFunc(ctx, c) })
	} else if !cfg.omitClientFields {
		ev.IP = defaultAuditClientIP(c)
	}
	if cfg.uaFunc != nil {
		ev.UA = auditHookCall(ctx, "ua", func() string { return cfg.uaFunc(ctx, c) })
	} else if !cfg.omitClientFields {
		ev.UA = string(c.GetHeader("User-Agent"))
	}
	if cfg.extraFunc != nil {
		ev.Extra = auditHookCall(ctx, "extra", func() map[string]string { return cfg.extraFunc(ctx, c) })
	}
	return ev
}

// defaultAuditClientIP 缺省客户端地址口径：连接对端地址的 host 部分
// （不读任何转发头，X-Forwarded-For 客户端可控——#83/#136 同一安全 stance）。
// 解析失败（畸形 RemoteAddr）原样保留全串，不静默丢维。
func defaultAuditClientIP(c *app.RequestContext) string {
	addr := c.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// emit 交付审计事件：无 sink 时写内建结构化日志（message "audit"，
// 字段 who/action/method/path/status/biz_code/latency_ms/trace_id/ip/ua
// 与 WithAuditLogExtra 注入的域字段键值，panic 事件升 Warn）；有 sink 时
// 逐个隔离交付。交付失败只 Warn——审计是旁路，不把请求拖垮。
func (cfg *auditConfig) emit(ctx context.Context, ev AuditEvent) {
	if len(cfg.sinks) == 0 {
		logger := cfg.logger
		if logger == nil {
			logger = auditLog
		}
		logAuditEvent(ctx, logger, ev)
		return
	}
	for _, sink := range cfg.sinks {
		deliverAuditEvent(ctx, sink, ev)
	}
}

// logAuditEvent 内建 logx sink：kv 结构化风格（平台契约，trace_id 经 Ctx*
// 方法自动携带——buffered 形态下请求 ctx 已失效，故 trace_id 字段显式进 kv）。
// IP/UA（#193）与 Extra 键值一并并入结构化字段（Extra 键排序保证输出
// 确定性，不因 map 遍历顺序抖动）。
func logAuditEvent(ctx context.Context, logger logx.Logger, ev AuditEvent) {
	kv := []any{
		"who", ev.Who,
		"action", ev.Action,
		"method", ev.Method,
		"path", ev.Path,
		"status", ev.Status,
		"biz_code", ev.BizCode,
		"latency_ms", ev.Latency.Milliseconds(),
		"trace_id", ev.TraceID,
	}
	if ev.IP != "" {
		kv = append(kv, "ip", ev.IP)
	}
	if ev.UA != "" {
		kv = append(kv, "ua", ev.UA)
	}
	if len(ev.Extra) > 0 {
		for _, k := range slices.Sorted(maps.Keys(ev.Extra)) {
			kv = append(kv, k, ev.Extra[k])
		}
	}
	if ev.Panic {
		kv = append(kv, "panic", true)
		logger.CtxWarn(ctx, "audit", kv...)
		return
	}
	logger.CtxInfo(ctx, "audit", kv...)
}

// deliverAuditEvent 单 sink 隔离交付：panic recover + error 只记 Warn
// （字段名统一 logx.ErrKey），不影响主链路与后续 sink。
func deliverAuditEvent(ctx context.Context, sink AuditSink, ev AuditEvent) {
	defer func() {
		if r := recover(); r != nil {
			auditLog.CtxWarn(ctx, "audit sink panic recovered",
				logx.ErrKey, r, "who", ev.Who, "path", ev.Path)
		}
	}()
	if err := sink(ctx, ev); err != nil {
		auditLog.CtxWarn(ctx, "audit sink failed",
			logx.ErrKey, err, "who", ev.Who, "path", ev.Path)
	}
}

// bufferedSinkLog 是缓冲批量 sink 原语（泛型面）的丢弃/flush 失败告警
// logger——原语不再绑定 audit 语义，独立 scoped logger（平台契约 §3）。
var bufferedSinkLog = logx.Delegating("middleware-bufferedsink")

// BatchSink 是缓冲批量 sink 原语（#192 泛型化）的 flush 单元：T 为消费方
// 域模型类型（fuxi *models.AuditLog、zeus op_log 行等）——不再被 AuditEvent
// 特化挡在批量原语门外，chan 攒批/背压丢弃/关闭原子化的重复手搓面单点收编。
// 在后台 goroutine 内调用；events 是本次 flush 的拷贝，sink 可安全异步持有。
// 返回 error 只记 Warn（事件已在缓冲中按丢弃策略处置过，失败重试属消费方
// 职责）。
type BatchSink[T any] func(ctx context.Context, events []T) error

// BufferedSinkOptions 是 NewBufferedSink 的配置（#192 泛型化）。
type BufferedSinkOptions[T any] struct {
	// BufferSize 事件缓冲 chan 容量。缺省 1024。
	BufferSize int
	// BatchSize 单次 flush 的事件数阈值（攒够即刷，不等间隔）。缺省 100。
	BatchSize int
	// FlushInterval 定时 flush 间隔（兜住不满一批的低频事件）。缺省 5s
	// （治理类默认区间内）。
	FlushInterval time.Duration
	// OnDrop 事件被丢弃时的回调；nil 记 Warn 日志（含累计丢弃数）。丢弃
	// 三去向同路：缓冲满（buffer_full）、Close 在途（closing）、flush 失败/
	// panic 整批逐事件（flush_failed，#207/#208）。在请求 goroutine 或后台
	// flush goroutine 内同步调用，保持轻量（自身 panic 会被 flush 侧
	// recover，不会杀死后台循环）。
	OnDrop func(ev T)
}

// BufferedSinkOption 配置 BufferedSink。
type BufferedSinkOption[T any] func(*BufferedSinkOptions[T])

// WithSinkBufferSize 设置事件缓冲 chan 容量（缺省 1024；负值构造期 panic）。
func WithSinkBufferSize[T any](n int) BufferedSinkOption[T] {
	return func(o *BufferedSinkOptions[T]) {
		o.BufferSize = n
	}
}

// WithSinkBatchSize 设置单次 flush 的事件数阈值（缺省 100；负值构造期 panic）。
func WithSinkBatchSize[T any](n int) BufferedSinkOption[T] {
	return func(o *BufferedSinkOptions[T]) {
		o.BatchSize = n
	}
}

// WithSinkFlushInterval 设置定时 flush 间隔（缺省 5s；负值构造期 panic）。
func WithSinkFlushInterval[T any](d time.Duration) BufferedSinkOption[T] {
	return func(o *BufferedSinkOptions[T]) {
		o.FlushInterval = d
	}
}

// WithSinkOnDrop 设置丢弃回调（缺省记 Warn 日志）。nil 不覆盖既有配置。
func WithSinkOnDrop[T any](fn func(ev T)) BufferedSinkOption[T] {
	return func(o *BufferedSinkOptions[T]) {
		if fn != nil {
			o.OnDrop = fn
		}
	}
}

// BufferedSink 是缓冲批量 sink **原语**（#192 泛型化，middleware#141 后半）：
// chan 缓冲 + 后台 goroutine 攒批 + 按 BatchSize/FlushInterval 触发 flush +
// 背压丢弃策略——fuxi_engine bufferWriter（351 行手搓）里最重复、最容易写错
// 的「缓冲/批量/背压/关闭」生命周期的原语化。元素类型参数化（T = 消费方
// 域模型），域模型消费者不再因 AuditEvent 特化重新手搓 chan+ticker+batch
// （#181 的关闭竞态修复对全部 T 自动生效）。
//
// 背压口径：缓冲满时丢弃事件并计数（缓冲批量是旁路，绝不阻塞/拖垮请求）——
// 丢弃是显式策略而非静默失败（Dropped() 可观测，WithSinkOnDrop 可接管处置）。
// flush 失败/panic（#207/#208）同口径：整批按丢弃计数、循环不死——「送了
// 没成」与「没送出」一样必须可观测。
//
// 方法 Sink 签名与事件投递面一致（AuditEvent 特化的方法值直接传
// WithAuditLogSink；其它域模型按各自投递面包装）。泛型选项构造器需显式
// 带元素类型实参（T 不从 flush 参数跨函数推断）：
//
//	buf := mw.NewBufferedSink(mydao.SaveBatch,
//	    mw.WithSinkBatchSize[models.AuditLog](200),
//	    mw.WithSinkFlushInterval[models.AuditLog](3*time.Second))
//	defer buf.Close(context.Background())
//
// Close 语义（平台生命周期约定 Close(ctx) error + sync.Once 幂等）：停止
// 接收、flush 已缓冲事件后退出。关闭判定与入队经 mu 原子化（#181）：不存在
// 「Sink 侧检查通过后 Close 完成 drain 退出、发送才落地」的静默漏记窗口——
// 事件要么赶在关闭前入缓冲（必被 drain 冲刷），要么看到 closed 按丢弃口径
// 计数处置，两个去向都可观测。
type BufferedSink[T any] struct {
	inner         BatchSink[T]
	bufferSize    int
	batchSize     int
	flushInterval time.Duration
	onDrop        func(ev T)
	// dropDetail（特化钩子，#192）：AuditEvent 特化保留 who/path 域字段的
	// 缺省丢弃日志形态（NewBufferedAuditSink 注入）；nil 走通用缺省（只记
	// 计数面——通用原语不解读域模型）。
	dropDetail func(ev T, reason string, total int64)
	// flushFail（特化钩子，#192）：AuditEvent 特化保留 first_path 域字段的
	// flush 失败日志形态；nil 走通用缺省（只记事件数）。
	flushFail func(err error, events []T)
	ch        chan T
	stop      chan struct{}
	done      chan struct{}
	dropped   atomic.Int64
	closeOnce sync.Once
	// closeErr（#209）：首次 Close 的 final flush 终态（超时错误）——错误
	// 不只活在首调用栈上，后续（含并发）调用回读同一终态。写入只在
	// closeOnce.Do 内，sync.Once 的 happens-before 保证后续回读无竞态。
	closeErr error
	// mu/closed（#181）：Sink 持 RLock 做「closed 判定 + 入队」原子化，
	// Close 持 Lock 置 closed + close(stop)——与 wsutil.Outbox(#117) /
	// streamx.SSESink(#144) 的收口口径同源。ch 永不关闭（run 靠 stop 退出
	// 后 drain），单靠 select 查 stop 无原子性，必须配本锁。
	mu     sync.RWMutex
	closed bool
}

// NewBufferedSink 构造缓冲批量 sink 原语并启动后台 flush goroutine。
// inner 为 nil 或选项为负值时构造期 panic（fail-fast）。
func NewBufferedSink[T any](inner BatchSink[T], opts ...BufferedSinkOption[T]) *BufferedSink[T] {
	if inner == nil {
		panic("mw.NewBufferedSink: inner sink must not be nil")
	}
	var o BufferedSinkOptions[T]
	for _, opt := range opts {
		opt(&o)
	}
	if o.BufferSize < 0 || o.BatchSize < 0 || o.FlushInterval < 0 {
		panic("mw.NewBufferedSink: negative BufferSize/BatchSize/FlushInterval")
	}
	if o.BufferSize == 0 {
		o.BufferSize = 1024
	}
	if o.BatchSize == 0 {
		o.BatchSize = 100
	}
	if o.FlushInterval == 0 {
		o.FlushInterval = 5 * time.Second
	}
	b := &BufferedSink[T]{
		inner:         inner,
		bufferSize:    o.BufferSize,
		batchSize:     o.BatchSize,
		flushInterval: o.FlushInterval,
		onDrop:        o.OnDrop,
		ch:            make(chan T, o.BufferSize),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	// 禁止裸 go func（平台契约）：panic 被 GoSafe recover，后台 flush 崩溃
	// 不冲垮进程。
	async.GoSafe(b.run)
	return b
}

// Sink 追加一条事件。非阻塞：缓冲满或已关闭时按丢弃策略处置并计数，恒
// 返回 nil——丢弃是策略不是错误，请求侧零阻塞。
//
// closed 判定与入队持 RLock 原子化（#181）：原实现「查 stop → 发 ch」两步
// 无锁，窗口内 Close 完成 drain 退出后发送仍成功（ch 永不关闭），事件滞留
// channel 永不 flush 且不计数不留痕 = 静默漏记；审计面漏记比多记危险（#141）。
func (b *BufferedSink[T]) Sink(ctx context.Context, ev T) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		b.drop(ev, "closing")
		return nil
	}
	select {
	case b.ch <- ev:
		return nil
	default:
		b.drop(ev, "buffer_full")
		return nil
	}
}

// Dropped 返回累计丢弃事件数（背压观测口：>0 说明下游消费能力不足或
// 缓冲偏小，消费方据此调 BufferSize/BatchSize 或告警）。
//
// 计入三去向（#208）：缓冲满（buffer_full）、关停在途（closing）、flush
// 失败/panic 整批逐事件（flush_failed，#207/#208——下游彻底失败时本计数
// 持续上涨，是最需要告警的形态；归因经 OnDrop/dropDetail 的 reason 区分）。
func (b *BufferedSink[T]) Dropped() int64 {
	return b.dropped.Load()
}

// Close 停止接收并落盘已缓冲事件，幂等（sync.Once）。ctx 控制 final flush
// 的等待上限，超时返回包装后的 ctx.Err()（已缓冲事件的最终处置以 inner
// sink 的实际表现为准）。Close 之后 Sink 的调用按丢弃口径计数。
//
// 终态传播（#209）：final flush 的超时错误记录在 sink 状态（closeErr）上，
// 后续（含并发）Close 调用一律等 done（以各自 ctx 为等待上限）后回读同一
// 终态——依赖「Close 返回 nil = 已落盘」的关停编排不再被「首调超时、次调
// 报成功」误导。sync.Once 保证 Do 内写入与后续回读的 happens-before。
func (b *BufferedSink[T]) Close(ctx context.Context) error {
	b.closeOnce.Do(func() {
		// 持写锁置 closed + close(stop)（#181）：与 Sink 的 RLock 互斥——
		// 任何 Sink 的「closed 判定 + 入队」要么整体发生在本段之前（事件在
		// ch 里、必被 drain 冲刷），要么在本段之后（看到 closed、按丢弃计数）。
		// close(stop) 放在写锁内，保证「stop 已闭 ⇒ 不再可能有新入队」。
		b.mu.Lock()
		b.closed = true
		close(b.stop)
		b.mu.Unlock()
		select {
		case <-b.done:
		case <-ctx.Done():
			b.closeErr = fmt.Errorf("mw.BufferedSink: close timed out waiting final flush: %w", ctx.Err())
		}
	})
	// 终态回读（#209）：每个调用方都等到 final flush 终结（done 闭合，以
	// 自己的 ctx 为上限）再取 recorded 终态——首调在途时次调不再空转返回
	// 假成功；首调超时后，次调（哪怕 ctx 宽裕）也拿到同一份真实终态。
	select {
	case <-b.done:
	case <-ctx.Done():
		if b.closeErr != nil {
			return b.closeErr
		}
		return fmt.Errorf("mw.BufferedSink: close timed out waiting final flush: %w", ctx.Err())
	}
	return b.closeErr
}

// drop 丢弃一条事件：计数 + OnDrop（或特化缺省/通用缺省 Warn 日志）。
func (b *BufferedSink[T]) drop(ev T, reason string) {
	total := b.dropped.Add(1)
	if b.onDrop != nil {
		b.onDrop(ev)
		return
	}
	if b.dropDetail != nil {
		b.dropDetail(ev, reason, total)
		return
	}
	bufferedSinkLog.Warn("buffered sink event dropped",
		"reason", reason,
		"dropped_total", total,
		"buffer_size", b.bufferSize,
	)
}

// dropBatch 整批按丢弃口径留痕（#207/#208）：flush 失败/panic 意味着整批
// 事件已出缓冲且未落盘——与缓冲满/关停丢弃同一观测口（Dropped() 逐事件
// 计入、OnDrop/dropDetail 逐事件同路，reason=flush_failed 区分归因），
// 消费方的丢弃处置面（告警/补偿/留痕）对「送了没成」同样生效。
func (b *BufferedSink[T]) dropBatch(events []T, reason string) {
	for _, ev := range events {
		b.drop(ev, reason)
	}
}

// run 后台攒批循环：BatchSize 攒满即刷、FlushInterval 兜底刷、stop 后
// drain 余量再退出。batch 交付前拷贝（sink 可安全异步持有），flush 失败
// 只记 Warn——缓冲链路的失败不回灌、不阻塞下一次攒批。
func (b *BufferedSink[T]) run() {
	defer close(b.done)
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	batch := make([]T, 0, b.batchSize)
	for {
		select {
		case ev := <-b.ch:
			batch = append(batch, ev)
			if len(batch) >= b.batchSize {
				b.flush(context.Background(), batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				b.flush(context.Background(), batch)
				batch = batch[:0]
			}
		case <-b.stop:
			// drain 关闭前已入缓冲的全部事件（含攒批中未满的尾巴）。
			for {
				select {
				case ev := <-b.ch:
					batch = append(batch, ev)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				b.flush(context.Background(), batch)
			}
			return
		}
	}
}

// flush 单次批量交付：拷贝后交 inner sink，error/panic 均就地收编（#207/#208）。
// panic 收编（#207）：inner（用户落库回调）一次裸 panic 曾沿 run 循环上抛——
// GoSafe 在 goroutine 级 recover 只保进程不保循环，run() 静默退出（done 闭合、
// Close 看似正常），此后缓冲只进不出、全部按 buffer_full 丢弃（归因错位）。
// 对齐单事件路径（deliverAuditEvent）的隔离口径：panic 转 Warn + 整批按丢弃
// 留痕 + 循环继续。失败留痕（#208）：落库失败=整批未落盘，逐事件计入
// Dropped()/OnDrop（reason=flush_failed）；既有 Warn 面保留。
func (b *BufferedSink[T]) flush(ctx context.Context, batch []T) {
	if len(batch) == 0 {
		return
	}
	events := append([]T(nil), batch...)
	// per-call recover（#207）：flush 活在 run 循环体内，就地收编保证循环不死
	// ——GoSafe 兜底只救进程，审计面的连续性靠这里。
	defer func() {
		if perr := errors.Recovered(recover()); perr != nil {
			b.dropBatch(events, "flush_failed")
			bufferedSinkLog.Warn("buffered sink flush panicked (isolated, loop continues)",
				logx.ErrKey, perr,
				"events", len(events),
			)
		}
	}()
	if err := b.inner(ctx, events); err != nil {
		// #208：批量失败按事件数计入丢弃观测口（OnDrop 同路），Warn 照旧。
		b.dropBatch(events, "flush_failed")
		if b.flushFail != nil {
			b.flushFail(err, events)
			return
		}
		bufferedSinkLog.Warn("buffered sink batch failed",
			logx.ErrKey, err,
			"events", len(events),
		)
	}
}

// —— 以下为 AuditEvent 特化（#192）：薄别名 + 缺省日志形态保留，现有 API
// 零变化（构造函数/选项/方法签名与 v0.17 完全一致）。

// AuditBatchSink 是 AuditEvent 特化的 flush 单元（BatchSink[AuditEvent]
// 别名，历史签名原样保留）。
type AuditBatchSink = BatchSink[AuditEvent]

// BufferedAuditSink 是审计事件的缓冲批量 sink（BufferedSink[AuditEvent]
// 别名）：AuditLogMiddleware 高频审计面配它缓冲批量落库——原语全量能力
// （#192 泛型化后与任意域模型共享同一实现）+ AuditEvent 特化的缺省日志
// 形态（丢弃 Warn 带 who/path、flush 失败 Warn 带 first_path）。
type BufferedAuditSink = BufferedSink[AuditEvent]

// BufferedAuditSinkOptions 是 NewBufferedAuditSink 的配置（特化别名）。
type BufferedAuditSinkOptions = BufferedSinkOptions[AuditEvent]

// BufferedAuditSinkOption 配置 BufferedAuditSink（特化别名）。
type BufferedAuditSinkOption = BufferedSinkOption[AuditEvent]

// WithAuditBufferSize 设置事件缓冲 chan 容量（缺省 1024；负值构造期 panic）。
func WithAuditBufferSize(n int) BufferedAuditSinkOption {
	return WithSinkBufferSize[AuditEvent](n)
}

// WithAuditBatchSize 设置单次 flush 的事件数阈值（缺省 100；负值构造期 panic）。
func WithAuditBatchSize(n int) BufferedAuditSinkOption {
	return WithSinkBatchSize[AuditEvent](n)
}

// WithAuditFlushInterval 设置定时 flush 间隔（缺省 5s；负值构造期 panic）。
func WithAuditFlushInterval(d time.Duration) BufferedAuditSinkOption {
	return WithSinkFlushInterval[AuditEvent](d)
}

// WithAuditOnDrop 设置丢弃回调（缺省记 Warn 日志）。nil 不覆盖既有配置。
func WithAuditOnDrop(fn func(ev AuditEvent)) BufferedAuditSinkOption {
	return WithSinkOnDrop[AuditEvent](fn)
}

// NewBufferedAuditSink 构造审计事件缓冲批量 sink 并启动后台 flush
// goroutine。inner 为 nil 或选项为负值时构造期 panic（fail-fast）。
// 与直接 NewBufferedSink[AuditEvent] 的差别仅在缺省日志形态：丢弃 Warn
// 带 who/path、flush 失败 Warn 带 first_path（v0.17 行为原样保留）。
func NewBufferedAuditSink(inner AuditBatchSink, opts ...BufferedAuditSinkOption) *BufferedAuditSink {
	if inner == nil {
		panic("mw.NewBufferedAuditSink: inner sink must not be nil")
	}
	// 预校验负值选项，保留 v0.17 的 panic 文案（特化构造函数的历史契约）。
	var probe BufferedAuditSinkOptions
	for _, opt := range opts {
		opt(&probe)
	}
	if probe.BufferSize < 0 || probe.BatchSize < 0 || probe.FlushInterval < 0 {
		panic("mw.NewBufferedAuditSink: negative BufferSize/BatchSize/FlushInterval")
	}
	b := NewBufferedSink[AuditEvent](inner, opts...)
	// AuditEvent 特化的缺省日志形态（#192：原语不解读域模型，特化在此
	// 注入域字段）。onDrop 显式接管时这两个缺省都不生效。
	b.dropDetail = func(ev AuditEvent, reason string, total int64) {
		auditLog.Warn("audit event dropped",
			"reason", reason,
			"dropped_total", total,
			"buffer_size", b.bufferSize,
			"who", ev.Who,
			"path", ev.Path,
		)
	}
	b.flushFail = func(err error, events []AuditEvent) {
		auditLog.Warn("audit batch sink failed",
			logx.ErrKey, err,
			"events", len(events),
			"first_path", events[0].Path,
		)
	}
	return b
}
