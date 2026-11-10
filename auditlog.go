package mw

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/concurrency/async"
	"github.com/oekit/logx"
	"github.com/oekit/middleware/hmw"
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

// AuditBatchSink 接收一批审计事件——BufferedAuditSink 的 flush 单元
// （chan 缓冲 + 后台 goroutine 攒批 + 按 BatchSize/FlushInterval 触发）。
// 在后台 goroutine 内调用；events 是本次 flush 的拷贝，sink 可安全异步持有。
// 返回 error 只记 Warn（事件已在缓冲中按丢弃策略处置过，失败重试属消费方
// 职责）。
type AuditBatchSink func(ctx context.Context, events []AuditEvent) error

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
}

// AuditLogOption 配置 AuditLogMiddleware。
type AuditLogOption func(*AuditLogOptions)

// WithAuditLogPaths 声明需要审计的路径清单（必填，glob 语义同 SkipPaths）。
// 清单为空时 AuditLogMiddleware 构造期 panic——审计面显式声明制
// （middleware#141），漏记比多记危险，不存在「静默不审计」的缺省。
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

// auditConfig 是启动期解析完毕的审计配置（请求热路径零重复解析）。
type auditConfig struct {
	auditedPaths []string
	sinks        []AuditSink
	logger       logx.Logger
	whoFunc      func(ctx context.Context, c *app.RequestContext) string
	actionFunc   func(ctx context.Context, c *app.RequestContext) string
	bizCodeFunc  func(ctx context.Context, c *app.RequestContext) int64
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
	cfg := &auditConfig{
		auditedPaths: append([]string(nil), o.AuditedPaths...),
		sinks:        o.Sinks,
		logger:       o.Logger,
		whoFunc:      o.WhoFunc,
		actionFunc:   o.ActionFunc,
		bizCodeFunc:  o.BizCodeFunc,
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

// auditEventOf 由请求上下文拼出审计事件。status 由调用方给定：正常完成取
// c.Response.StatusCode()；panic 恢复点传 500（响应尚未写出）。
func auditEventOf(ctx context.Context, c *app.RequestContext, cfg *auditConfig, start time.Time, status int, panicked bool) AuditEvent {
	return AuditEvent{
		When:    start,
		Who:     cfg.whoFunc(ctx, c),
		Action:  cfg.actionFunc(ctx, c),
		Method:  string(c.Method()),
		Path:    string(c.Path()),
		Status:  status,
		BizCode: cfg.bizCodeFunc(ctx, c),
		Latency: time.Since(start),
		TraceID: hmw.FromRequestContext(c),
		Panic:   panicked,
	}
}

// emit 交付审计事件：无 sink 时写内建结构化日志（message "audit"，
// 字段 who/action/method/path/status/biz_code/latency_ms/trace_id，
// panic 事件升 Warn）；有 sink 时逐个隔离交付。交付失败只 Warn——审计
// 是旁路，不把请求拖垮。
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

// BufferedAuditSinkOptions 是 NewBufferedAuditSink 的配置。
type BufferedAuditSinkOptions struct {
	// BufferSize 事件缓冲 chan 容量。缺省 1024。
	BufferSize int
	// BatchSize 单次 flush 的事件数阈值（攒够即刷，不等间隔）。缺省 100。
	BatchSize int
	// FlushInterval 定时 flush 间隔（兜住不满一批的低频事件）。缺省 5s
	// （治理类默认区间内）。
	FlushInterval time.Duration
	// OnDrop 事件被丢弃（缓冲满/Close 在途）时的回调；nil 记 Warn 日志
	// （含累计丢弃数）。在请求 goroutine 内同步调用，保持轻量。
	OnDrop func(ev AuditEvent)
}

// BufferedAuditSinkOption 配置 BufferedAuditSink。
type BufferedAuditSinkOption func(*BufferedAuditSinkOptions)

// WithAuditBufferSize 设置事件缓冲 chan 容量（缺省 1024；负值构造期 panic）。
func WithAuditBufferSize(n int) BufferedAuditSinkOption {
	return func(o *BufferedAuditSinkOptions) {
		o.BufferSize = n
	}
}

// WithAuditBatchSize 设置单次 flush 的事件数阈值（缺省 100；负值构造期 panic）。
func WithAuditBatchSize(n int) BufferedAuditSinkOption {
	return func(o *BufferedAuditSinkOptions) {
		o.BatchSize = n
	}
}

// WithAuditFlushInterval 设置定时 flush 间隔（缺省 5s；负值构造期 panic）。
func WithAuditFlushInterval(d time.Duration) BufferedAuditSinkOption {
	return func(o *BufferedAuditSinkOptions) {
		o.FlushInterval = d
	}
}

// WithAuditOnDrop 设置丢弃回调（缺省记 Warn 日志）。nil 不覆盖既有配置。
func WithAuditOnDrop(fn func(ev AuditEvent)) BufferedAuditSinkOption {
	return func(o *BufferedAuditSinkOptions) {
		if fn != nil {
			o.OnDrop = fn
		}
	}
}

// BufferedAuditSink 是审计事件的缓冲批量 sink 原语（middleware#141 后半）：
// chan 缓冲 + 后台 goroutine 攒批 + 按 BatchSize/FlushInterval 触发 flush +
// 背压丢弃策略——fuxi_engine bufferWriter（351 行手搓）里最重复、最容易写错
// 的「缓冲/批量/背压/关闭」生命周期的原语化。DB/队列消费方只需实现
// AuditBatchSink。
//
// 背压口径：缓冲满时丢弃事件并计数（审计是旁路，绝不阻塞/拖垮请求）——
// 丢弃是显式策略而非静默失败（Dropped() 可观测，OnDrop 可接管处置）。
//
// 方法 Sink 与 AuditSink 签名一致（方法值直接传 WithAuditLogSink）：
//
//	buf := mw.NewBufferedAuditSink(dao.SaveAuditBatch,
//	    mw.WithAuditBatchSize(200), mw.WithAuditFlushInterval(3*time.Second))
//	h.Use(mw.AuditLogMiddleware(mw.WithAuditLogPaths("/api/admin/**"),
//	    mw.WithAuditLogSink(buf.Sink)))
//	defer buf.Close(context.Background())
//
// Close 语义（平台生命周期约定 Close(ctx) error + sync.Once 幂等）：停止
// 接收、flush 已缓冲事件后退出。与并发 Sink 存在极小在途窗口（Close 起
// 停止保证落盘），该窗口事件按丢弃口径处置——与背压丢弃同一口径。
type BufferedAuditSink struct {
	inner         AuditBatchSink
	bufferSize    int
	batchSize     int
	flushInterval time.Duration
	onDrop        func(ev AuditEvent)
	ch            chan AuditEvent
	stop          chan struct{}
	done          chan struct{}
	dropped       atomic.Int64
	closeOnce     sync.Once
}

// NewBufferedAuditSink 构造缓冲批量 sink 并启动后台 flush goroutine。
// inner 为 nil 或选项为负值时构造期 panic（fail-fast）。
func NewBufferedAuditSink(inner AuditBatchSink, opts ...BufferedAuditSinkOption) *BufferedAuditSink {
	if inner == nil {
		panic("mw.NewBufferedAuditSink: inner sink must not be nil")
	}
	var o BufferedAuditSinkOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.BufferSize < 0 || o.BatchSize < 0 || o.FlushInterval < 0 {
		panic("mw.NewBufferedAuditSink: negative BufferSize/BatchSize/FlushInterval")
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
	b := &BufferedAuditSink{
		inner:         inner,
		bufferSize:    o.BufferSize,
		batchSize:     o.BatchSize,
		flushInterval: o.FlushInterval,
		onDrop:        o.OnDrop,
		ch:            make(chan AuditEvent, o.BufferSize),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	// 禁止裸 go func（平台契约）：panic 被 GoSafe recover，后台 flush 崩溃
	// 不冲垮进程。
	async.GoSafe(b.run)
	return b
}

// Sink 追加一条审计事件（AuditSink 签名，方法值可直接传 WithAuditLogSink）。
// 非阻塞：缓冲满或已关闭时按丢弃策略处置并计数，恒返回 nil——丢弃是策略
// 不是错误，请求侧零阻塞。
func (b *BufferedAuditSink) Sink(ctx context.Context, ev AuditEvent) error {
	select {
	case <-b.stop:
		b.drop(ev, "closing")
		return nil
	default:
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
func (b *BufferedAuditSink) Dropped() int64 {
	return b.dropped.Load()
}

// Close 停止接收并落盘已缓冲事件，幂等（sync.Once）。ctx 控制 final flush
// 的等待上限，超时返回包装后的 ctx.Err()（已缓冲事件的最终处置以 inner
// sink 的实际表现为准）。Close 之后 Sink 的调用按丢弃口径计数。
func (b *BufferedAuditSink) Close(ctx context.Context) error {
	var err error
	b.closeOnce.Do(func() {
		close(b.stop)
		select {
		case <-b.done:
		case <-ctx.Done():
			err = fmt.Errorf("mw.BufferedAuditSink: close timed out waiting final flush: %w", ctx.Err())
		}
	})
	return err
}

// drop 丢弃一条事件：计数 + OnDrop（或缺省 Warn 日志）。
func (b *BufferedAuditSink) drop(ev AuditEvent, reason string) {
	total := b.dropped.Add(1)
	if b.onDrop != nil {
		b.onDrop(ev)
		return
	}
	auditLog.Warn("audit event dropped",
		"reason", reason,
		"dropped_total", total,
		"buffer_size", b.bufferSize,
		"who", ev.Who,
		"path", ev.Path,
	)
}

// run 后台攒批循环：BatchSize 攒满即刷、FlushInterval 兜底刷、stop 后
// drain 余量再退出。batch 交付前拷贝（sink 可安全异步持有），flush 失败
// 只记 Warn——缓冲链路的失败不回灌、不阻塞下一次攒批。
func (b *BufferedAuditSink) run() {
	defer close(b.done)
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	batch := make([]AuditEvent, 0, b.batchSize)
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

// flush 单次批量交付：拷贝后交 inner sink，error 只记 Warn（logx.ErrKey）。
func (b *BufferedAuditSink) flush(ctx context.Context, batch []AuditEvent) {
	if len(batch) == 0 {
		return
	}
	events := append([]AuditEvent(nil), batch...)
	if err := b.inner(ctx, events); err != nil {
		auditLog.Warn("audit batch sink failed",
			logx.ErrKey, err,
			"events", len(events),
			"first_path", events[0].Path,
		)
	}
}
