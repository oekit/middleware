package mw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/oekit/middleware/hmw"
)

// collectingAuditSink 收集审计事件的 sink(测试断言依据),channel 交付保证
// 与后台/异步路径的同步无竞态。
type collectingAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *collectingAuditSink) record(ev AuditEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *collectingAuditSink) snapshot() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEvent(nil), s.events...)
}

func (s *collectingAuditSink) sinkFunc(_ context.Context, ev AuditEvent) error {
	s.record(ev)
	return nil
}

// TestAuditLogMiddleware_RequiresAuditedPaths 钉住 fail-loud 声明制
// (middleware#141):清单为空时构造期 panic——审计面不存在「静默不审计」
// 的缺省形态(漏记比多记危险,与 BearerTokenAuth 未配置 token 的构造期
// panic 同口径)。
func TestAuditLogMiddleware_RequiresAuditedPaths(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("★ 未声明 AuditedPaths 时构造必须 panic(fail-loud),实际未炸")
		} else if msg := fmt.Sprint(r); !strings.Contains(msg, "WithAuditLogPaths") {
			t.Fatalf("panic 信息应指明缺 WithAuditLogPaths, got %q", msg)
		}
	}()
	AuditLogMiddleware()
}

// TestAuditLogMiddleware_DeclaredPathsOnly 显式声明制语义:声明的路径产出
// 事件,未声明路径零事件零 sink 调用;glob 语义同 SkipPaths(`*` 单段不跨
// "/")。
func TestAuditLogMiddleware_DeclaredPathsOnly(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/*"),
		WithAuditLogSink(collected.sinkFunc),
	))
	handler := func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	}
	h.GET("/api/admin/users", handler)    // 声明内(单段命中)
	h.GET("/api/admin/db/users", handler) // 声明外(* 不跨段)
	h.GET("/api/public", handler)         // 声明外

	ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil)
	ut.PerformRequest(h.Engine, "GET", "/api/admin/db/users", nil)
	ut.PerformRequest(h.Engine, "GET", "/api/public", nil)

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("★ 只有声明路径产出审计事件: got %d events (%+v), want 1", len(events), events)
	}
	if events[0].Path != "/api/admin/users" {
		t.Fatalf("event path = %q, want /api/admin/users", events[0].Path)
	}
}

// TestAuditLogMiddleware_EventFields middleware#141 事件模型:who 从
// TrustedHeadersIdentity 注入的 claims 取、when 非零、outcome=状态码、
// trace_id 来自 hmw、action 缺省取路由模板。
func TestAuditLogMiddleware_EventFields(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(hmw.Middleware()...)
	h.Use(TrustedHeadersIdentity(TrustedIdentityConfig{Missing: AnonymousClaims}))
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected.sinkFunc),
	))
	h.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	w := ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"})
	if w.Code != 200 {
		t.Fatalf("request: code=%d", w.Code)
	}

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Who != "u-42" {
		t.Fatalf("★ who = %q, want u-42(who 必须从 ctx claims 取)", ev.Who)
	}
	if ev.Method != http.MethodGet || ev.Path != "/api/admin/users" {
		t.Fatalf("what = %s %s, want GET /api/admin/users", ev.Method, ev.Path)
	}
	if ev.Status != 200 {
		t.Fatalf("outcome status = %d, want 200", ev.Status)
	}
	if ev.When.IsZero() {
		t.Fatal("★ when 必须非零")
	}
	if ev.TraceID == "" {
		t.Fatal("★ trace_id 为空——hmw.Middleware 已注册,应透传")
	}
	if ev.Action != "/api/admin/users" { // 路由模板(精确路由无参数,与 path 同值)
		t.Fatalf("action 缺省应为路由模板, got %q", ev.Action)
	}
	if ev.Panic {
		t.Fatal("正常请求 Panic 必须为 false")
	}
}

// TestAuditLogMiddleware_PanicCapturedAndRethrown panic 请求同样产出审计
// 事件(#141 对齐 accesslog #20 口径):Panic=true、Status 按 Recovery 缺省
// 500 记,事件产出后按原值重抛,外层 Recovery 照常写 500。
func TestAuditLogMiddleware_PanicCapturedAndRethrown(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(RecoveryMiddleware())
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/**"),
		WithAuditLogSink(collected.sinkFunc),
	))
	h.POST("/api/boom", func(ctx context.Context, c *app.RequestContext) {
		panic("audit-test-boom")
	})

	w := ut.PerformRequest(h.Engine, "POST", "/api/boom", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Recovery 应兜住重抛的 panic 写 500, got %d", w.Code)
	}

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("★ panic 请求必须产出审计事件: got %d, want 1", len(events))
	}
	ev := events[0]
	if !ev.Panic {
		t.Fatal("★ 事件必须带 Panic=true 标记")
	}
	if ev.Status != 500 {
		t.Fatalf("panic 事件 Status 按 Recovery 缺省 500 记, got %d", ev.Status)
	}
	if ev.Method != http.MethodPost || ev.Path != "/api/boom" {
		t.Fatalf("what = %s %s, want POST /api/boom", ev.Method, ev.Path)
	}
}

// TestAuditLogMiddleware_SinkIsolation sink 出错/panic 只记 Warn,不影响
// 主链路,也不影响后续 sink(对齐 AccessSink 隔离口径)。
func TestAuditLogMiddleware_SinkIsolation(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/**"),
		WithAuditLogSink(func(_ context.Context, _ AuditEvent) error {
			return errors.New("dao down")
		}),
		WithAuditLogSink(func(_ context.Context, _ AuditEvent) error {
			panic("sink bug")
		}),
		WithAuditLogSink(collected.sinkFunc),
	))
	h.GET("/api/x", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	w := ut.PerformRequest(h.Engine, "GET", "/api/x", nil)
	if w.Code != 200 {
		t.Fatalf("★ sink 故障不得影响主链路: code=%d body=%s", w.Code, w.Body.String())
	}
	if got := len(collected.snapshot()); got != 1 {
		t.Fatalf("★ 后续 sink 不得被前面的 sink 故障截断: got %d events, want 1", got)
	}
}

// TestAuditLogMiddleware_CustomWhoActionBizCode 提取缝:who/action/biz_code
// 经 WithAuditLog* 注入后按注入口径产出(租户身份、语义化动作、业务码)。
func TestAuditLogMiddleware_CustomWhoActionBizCode(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/**"),
		WithAuditLogSink(collected.sinkFunc),
		WithAuditLogWho(func(_ context.Context, c *app.RequestContext) string {
			return "tenant:" + string(c.Request.Header.Peek("X-Tenant-ID"))
		}),
		WithAuditLogAction(func(_ context.Context, _ *app.RequestContext) string {
			return "policy.delete"
		}),
		WithAuditLogBizCode(func(_ context.Context, c *app.RequestContext) int64 {
			return int64(c.Response.StatusCode()) * 100
		}),
	))
	h.DELETE("/api/policies/1", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	ut.PerformRequest(h.Engine, "DELETE", "/api/policies/1", nil,
		ut.Header{Key: "X-Tenant-ID", Value: "acme"})

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Who != "tenant:acme" {
		t.Fatalf("who = %q, want tenant:acme", ev.Who)
	}
	if ev.Action != "policy.delete" {
		t.Fatalf("action = %q, want policy.delete", ev.Action)
	}
	if ev.BizCode != 20000 {
		t.Fatalf("biz_code = %d, want 20000", ev.BizCode)
	}
}

// TestAuditLogMiddleware_DefaultLogSink 未注册 sink 时事件写内建结构化日志
// (不 panic、不影响响应)——最小形态的可用性钉子。
func TestAuditLogMiddleware_DefaultLogSink(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(WithAuditLogPaths("/api/**")))
	h.GET("/api/y", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	w := ut.PerformRequest(h.Engine, "GET", "/api/y", nil)
	if w.Code != 200 {
		t.Fatalf("内建日志 sink 形态下请求必须正常: code=%d", w.Code)
	}
}

// --- BufferedAuditSink(middleware#141 后半:缓冲批量 Sink 原语) ---

// TestBufferedAuditSink_BatchFlush 攒满 BatchSize 立即 flush(不等间隔):
// channel 同步,无 sleep 凑,-race 稳定。
func TestBufferedAuditSink_BatchFlush(t *testing.T) {
	flushed := make(chan []AuditEvent, 4)
	buf := NewBufferedAuditSink(func(_ context.Context, events []AuditEvent) error {
		flushed <- events
		return nil
	},
		WithAuditBatchSize(2),
		WithAuditFlushInterval(time.Hour), // 若靠间隔触发本测试必然超时
	)
	defer buf.Close(context.Background())

	for i := 0; i < 2; i++ {
		if err := buf.Sink(context.Background(), AuditEvent{Who: fmt.Sprint(i), Path: "/b"}); err != nil {
			t.Fatalf("Sink err: %v", err)
		}
	}

	select {
	case events := <-flushed:
		if len(events) != 2 {
			t.Fatalf("★ batch flush = %d events, want 2", len(events))
		}
		if events[0].Who != "0" || events[1].Who != "1" {
			t.Fatalf("★ flush 顺序必须保持: got %v,%v", events[0].Who, events[1].Who)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ 攒满 BatchSize 未触发 flush")
	}
}

// TestBufferedAuditSink_IntervalFlush 不满批的事件经 FlushInterval 兜底刷出
// (轮询等条件,不定长 sleep 硬凑)。
func TestBufferedAuditSink_IntervalFlush(t *testing.T) {
	flushed := make(chan []AuditEvent, 4)
	buf := NewBufferedAuditSink(func(_ context.Context, events []AuditEvent) error {
		flushed <- events
		return nil
	},
		WithAuditBatchSize(100),
		WithAuditFlushInterval(20*time.Millisecond),
	)
	defer buf.Close(context.Background())

	_ = buf.Sink(context.Background(), AuditEvent{Who: "solo", Path: "/i"})

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case events := <-flushed:
			if len(events) != 1 || events[0].Who != "solo" {
				t.Fatalf("★ interval flush 内容不符: %d events", len(events))
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("★ FlushInterval 兜底未触发 flush")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBufferedAuditSink_DropOnFull 背压口径:下游阻塞时缓冲打满,事件按
// 丢弃策略处置并计数,请求侧 Sink 恒不阻塞、恒返回 nil。
func TestBufferedAuditSink_DropOnFull(t *testing.T) {
	// 门控 sink:阻塞后台 flush 循环,制造「下游消费不动」的堆积面。
	// gate 带缓冲(仅作抵达计数),保证后台 goroutine 不会永久阻塞在通知上。
	gate := make(chan struct{}, 8)
	release := make(chan struct{})
	buf := NewBufferedAuditSink(func(_ context.Context, _ []AuditEvent) error {
		gate <- struct{}{} // 抵达 flush 点(缓冲式,不阻塞)
		<-release          // 等测试放行
		return nil
	},
		WithAuditBufferSize(2),
		WithAuditBatchSize(1),
	)
	defer func() {
		close(release) // 放行后台 flush,Close 才能收口
		if err := buf.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	// 先发 1 条:占住后台 flush(阻塞在 release)。
	_ = buf.Sink(context.Background(), AuditEvent{Who: "stuck"})
	<-gate // 收到抵达通知 ⇒ stuck 已出缓冲,后台已停在其 flush 内

	// 缓冲容量 2:再塞 2 条满仓,第 3 条起必丢。
	_ = buf.Sink(context.Background(), AuditEvent{Who: "b1"})
	_ = buf.Sink(context.Background(), AuditEvent{Who: "b2"})
	if err := buf.Sink(context.Background(), AuditEvent{Who: "b3"}); err != nil {
		t.Fatalf("★ 缓冲满时 Sink 必须返回 nil(丢弃是策略不是错误): %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for buf.Dropped() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("★ 缓冲满后未按丢弃策略计数(Dropped 仍为 0)")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBufferedAuditSink_OnDropHook OnDrop 回调接管丢弃处置(缺省 Warn 日志
// 的替代面),回调拿到被丢事件本体。
func TestBufferedAuditSink_OnDropHook(t *testing.T) {
	gate := make(chan struct{}, 8)
	release := make(chan struct{})
	var droppedWho atomic.Value
	buf := NewBufferedAuditSink(func(_ context.Context, _ []AuditEvent) error {
		gate <- struct{}{}
		<-release
		return nil
	},
		WithAuditBufferSize(1),
		WithAuditBatchSize(1),
		WithAuditOnDrop(func(ev AuditEvent) { droppedWho.Store(ev.Who) }),
	)
	defer func() {
		close(release)
		if err := buf.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	_ = buf.Sink(context.Background(), AuditEvent{Who: "stuck"})
	<-gate                                                        // stuck 已出缓冲,后台停在其 flush 内
	_ = buf.Sink(context.Background(), AuditEvent{Who: "fill"})   // 仓满
	_ = buf.Sink(context.Background(), AuditEvent{Who: "victim"}) // 必丢

	deadline := time.Now().Add(5 * time.Second)
	for {
		if v, ok := droppedWho.Load().(string); ok && v == "victim" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("★ OnDrop 未拿到被丢事件, got %v", droppedWho.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBufferedAuditSink_CloseDrains Close 落盘已缓冲事件(平台生命周期约定:
// Close(ctx) error;ctx 只控制等待上限):未满批的尾巴也必须 flush 出去。
func TestBufferedAuditSink_CloseDrains(t *testing.T) {
	flushed := make(chan []AuditEvent, 8)
	buf := NewBufferedAuditSink(func(_ context.Context, events []AuditEvent) error {
		flushed <- events
		return nil
	},
		WithAuditBatchSize(100),           // 不满批
		WithAuditFlushInterval(time.Hour), // 间隔兜底永不触发,只有 Close 能刷
	)

	for i := 0; i < 3; i++ {
		_ = buf.Sink(context.Background(), AuditEvent{Who: fmt.Sprint(i), Path: "/c"})
	}
	if err := buf.Close(context.Background()); err != nil {
		t.Fatalf("Close err: %v", err)
	}

	select {
	case events := <-flushed:
		if len(events) != 3 {
			t.Fatalf("★ Close 必须落盘已缓冲事件: got %d, want 3", len(events))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ Close 后未 flush 已缓冲事件")
	}
}

// TestBufferedAuditSink_CloseIdempotent Close 幂等(sync.Once):二次 Close
// 不 panic 不阻塞,与首次返回一致。
func TestBufferedAuditSink_CloseIdempotent(t *testing.T) {
	buf := NewBufferedAuditSink(func(_ context.Context, _ []AuditEvent) error { return nil })
	if err := buf.Close(context.Background()); err != nil {
		t.Fatalf("first close: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- buf.Close(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second close err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("★ 二次 Close 阻塞——sync.Once 幂等失效")
	}
}

// TestBufferedAuditSink_SinkAfterCloseCounts Close 之后再 Sink:按丢弃口径
// 计数(极小在途窗口的显式口径,见 BufferedAuditSink godoc),不 panic。
func TestBufferedAuditSink_SinkAfterCloseCounts(t *testing.T) {
	buf := NewBufferedAuditSink(func(_ context.Context, _ []AuditEvent) error { return nil })
	if err := buf.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	_ = buf.Sink(context.Background(), AuditEvent{Who: "late", Path: "/l"})
	if got := buf.Dropped(); got != 1 {
		t.Fatalf("★ Close 后 Sink 必须计入丢弃: dropped=%d, want 1", got)
	}
}

// TestBufferedAuditSink_FailFast 构造期非法值 fail-fast(平台 Option 总则):
// inner nil / 负值选项 panic。
func TestBufferedAuditSink_FailFast(t *testing.T) {
	cases := []struct {
		name string
		run  func()
	}{
		{"nil inner", func() { NewBufferedAuditSink(nil) }},
		{"negative buffer", func() {
			NewBufferedAuditSink(func(context.Context, []AuditEvent) error { return nil },
				WithAuditBufferSize(-1))
		}},
		{"negative batch", func() {
			NewBufferedAuditSink(func(context.Context, []AuditEvent) error { return nil },
				WithAuditBatchSize(-1))
		}},
		{"negative interval", func() {
			NewBufferedAuditSink(func(context.Context, []AuditEvent) error { return nil },
				WithAuditFlushInterval(-time.Second))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("★ %s: 构造必须 panic(fail-fast)", c.name)
				}
			}()
			c.run()
		})
	}
}

// TestBufferedAuditSink_FlushErrorWarned flush 失败只记 Warn、不回灌、不阻塞
// 后续攒批——失败后继续 Sink/flush 照常工作。
func TestBufferedAuditSink_FlushErrorWarned(t *testing.T) {
	var calls atomic.Int32
	flushed := make(chan int, 4)
	buf := NewBufferedAuditSink(func(_ context.Context, events []AuditEvent) error {
		n := int(calls.Add(1))
		flushed <- n
		if n == 1 {
			return errors.New("db down")
		}
		return nil
	},
		WithAuditBatchSize(1),
	)
	defer buf.Close(context.Background())

	_ = buf.Sink(context.Background(), AuditEvent{Who: "a"})
	<-flushed // 首次 flush(失败)
	_ = buf.Sink(context.Background(), AuditEvent{Who: "b"})
	select {
	case n := <-flushed:
		if n != 2 {
			t.Fatalf("second flush call #%d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ flush 失败后后续攒批被阻塞")
	}
}

// —— #192 BufferedSink[T] 泛型原语 ——

// oplogRow 是泛型原语测试用的消费方域模型（模拟 fuxi *models.AuditLog 形态
// ——与 AuditEvent 字段集不相交，#192 的收编评估实证）。
type oplogRow struct {
	Action string
	IP     string
}

// TestBufferedSink_GenericDomainModel 泛型原语以任意域模型为元素类型（#192）：
// chan 攒批/批量 flush/顺序保持对 T=oplogRow 生效——AuditEvent 特化不再把
// 域模型挡在批量原语门外（旧 API 只收 func(ctx, []AuditEvent)）。
func TestBufferedSink_GenericDomainModel(t *testing.T) {
	flushed := make(chan []oplogRow, 4)
	buf := NewBufferedSink(func(_ context.Context, rows []oplogRow) error {
		flushed <- rows
		return nil
	},
		WithSinkBatchSize[oplogRow](2),
		WithSinkFlushInterval[oplogRow](time.Hour), // 攒批触发，不等间隔
	)
	defer buf.Close(context.Background())

	for i := 0; i < 2; i++ {
		if err := buf.Sink(context.Background(), oplogRow{Action: fmt.Sprint(i), IP: "10.0.0.1"}); err != nil {
			t.Fatalf("Sink err: %v", err)
		}
	}
	select {
	case rows := <-flushed:
		if len(rows) != 2 {
			t.Fatalf("★ 泛型批量 flush = %d rows, want 2", len(rows))
		}
		if rows[0].Action != "0" || rows[1].Action != "1" || rows[1].IP != "10.0.0.1" {
			t.Fatalf("★ flush 顺序/内容必须保持: %+v", rows)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ 攒满 BatchSize 未触发 flush")
	}
}

// TestBufferedSink_GenericFailFastAndDrop 泛型原语的生命周期契约对任意 T
// 一致（#192）：inner nil / 负值选项构造期 panic；Close 后 Sink 按丢弃口径
// 计数（#181 修复对全部 T 自动生效）。
func TestBufferedSink_GenericFailFastAndDrop(t *testing.T) {
	cases := []struct {
		name string
		run  func()
	}{
		{"nil inner", func() { NewBufferedSink[oplogRow](nil) }},
		{"negative buffer", func() {
			NewBufferedSink(func(context.Context, []oplogRow) error { return nil },
				WithSinkBufferSize[oplogRow](-1))
		}},
		{"negative batch", func() {
			NewBufferedSink(func(context.Context, []oplogRow) error { return nil },
				WithSinkBatchSize[oplogRow](-1))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("★ %s: 构造必须 panic(fail-fast)", c.name)
				}
			}()
			c.run()
		})
	}

	// Close 后 Sink 丢弃计数（#181 口径随泛型收编对任意 T 生效）。
	buf := NewBufferedSink(func(context.Context, []oplogRow) error { return nil })
	if err := buf.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	_ = buf.Sink(context.Background(), oplogRow{Action: "late"})
	if got := buf.Dropped(); got != 1 {
		t.Fatalf("★ Close 后 Sink 必须计入丢弃: dropped=%d, want 1", got)
	}
}

// —— #193 AuditEvent IP/UA/Extra 域字段缝 ——

// TestAuditLogMiddleware_ClientFieldsDefault 缺省采集口径（#193）：
// IP=连接对端地址 host（fail-closed，不读 XFF——#83 同口径）、
// UA=User-Agent 头原值。
func TestAuditLogMiddleware_ClientFieldsDefault(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected.sinkFunc),
	))
	h.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil,
		ut.Header{Key: "User-Agent", Value: "audit-probe/1.0"},
		ut.Header{Key: "X-Forwarded-For", Value: "203.0.113.99"}, // 可控头：缺省口径必须不读
	)

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.IP == "" {
		t.Fatal("★ 缺省 IP 必须采对端地址（非空）")
	}
	if strings.Contains(ev.IP, ":") {
		t.Fatalf("★ IP 应为 host 部分（不带端口）: %q", ev.IP)
	}
	if ev.UA != "audit-probe/1.0" {
		t.Fatalf("★ UA 缺省=User-Agent 头原值: got %q", ev.UA)
	}
}

// TestAuditLogMiddleware_OmitClientFields OmitClientFields 置位后 IP/UA 缺省
// 采集关闭（#193，合规禁采网络维度）；显式注入的 IPFunc 不受开关影响。
func TestAuditLogMiddleware_OmitClientFields(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected.sinkFunc),
		WithAuditLogOmitClientFields(),
	))
	h.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil,
		ut.Header{Key: "User-Agent", Value: "audit-probe/1.0"},
	)

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].IP != "" || events[0].UA != "" {
		t.Fatalf("★ OmitClientFields 后 IP/UA 必须为空: ip=%q ua=%q", events[0].IP, events[0].UA)
	}
}

// TestAuditLogMiddleware_ClientSeams IP/UA/Extra 提取缝（#193）：显式注入
// 覆盖缺省口径——代理拓扑按可信网段归因 IP、UA 截断形态、Extra 承载
// Body 摘要等审计域字段（fuxi op_log 域表收编的字段缝）。
func TestAuditLogMiddleware_ClientSeams(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected.sinkFunc),
		WithAuditLogClientIP(func(ctx context.Context, c *app.RequestContext) string {
			return "resolved-client-ip"
		}),
		WithAuditLogUA(func(ctx context.Context, c *app.RequestContext) string {
			return "ua-truncated"
		}),
		WithAuditLogExtra(func(ctx context.Context, c *app.RequestContext) map[string]string {
			return map[string]string{"body_digest": "sha256:deadbeef", "resource_type": "policy"}
		}),
	))
	h.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil,
		ut.Header{Key: "User-Agent", Value: "original-ua/9.9"},
	)

	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.IP != "resolved-client-ip" {
		t.Fatalf("★ IPFunc 注入必须覆盖缺省: %q", ev.IP)
	}
	if ev.UA != "ua-truncated" {
		t.Fatalf("★ UAFunc 注入必须覆盖缺省: %q", ev.UA)
	}
	if ev.Extra["body_digest"] != "sha256:deadbeef" || ev.Extra["resource_type"] != "policy" {
		t.Fatalf("★ Extra 域字段缝未生效: %+v", ev.Extra)
	}
}

// TestAuditLogMiddleware_BadGlobPatternPanics 构造期 glob 语法预检（#201，
// fail-fast 与 chainmw.AccessLog #161 同判据）：坏 pattern 会被运行期宽松
// 匹配吞成「永不命中」——审计声明静默失效、敏感操作零事件落库（漏记比
// 多记危险）且零信号，误配必须在启动期炸响。
func TestAuditLogMiddleware_BadGlobPatternPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("★ 坏 glob pattern 构造必须 panic(fail-loud，#201)")
		} else if msg := fmt.Sprint(r); !strings.Contains(msg, "/api/admin/[") {
			t.Fatalf("panic 信息应点名坏 pattern: %v", r)
		}
	}()
	AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/[x"), // 未闭合的 [ = ErrBadPattern
		WithAuditLogSink(func(context.Context, AuditEvent) error { return nil }),
	)
}

// —— #207/#208/#209/#210 回归钉 ——

// TestBufferedAuditSink_FlushPanicLoopSurvives 回归钉（#207）：inner（用户
// 落库回调）flush panic 必须就地收编——GoSafe 只保进程不保循环，原实现一次
// 裸 panic 让 run() 静默退出（done 闭合、Close 看似正常），此后缓冲只进不出。
// 修复后：panic 转 Warn + 整批按丢弃留痕（reason=flush_failed，OnDrop 同路）
// + 循环继续——首次 panic 后第二次事件仍能 flush。
func TestBufferedAuditSink_FlushPanicLoopSurvives(t *testing.T) {
	var flushed []string
	flushDone := make(chan struct{}, 8)
	var onDropCalls atomic.Int32
	// releases 每次 flush 上交一个独立放行柄（无共享可变变量——复用同一
	// release chan 会被 -race 判为测试自身竞态）。
	releases := make(chan chan struct{}, 8)
	buf := NewBufferedAuditSink(func(_ context.Context, events []AuditEvent) error {
		rel := make(chan struct{})
		releases <- rel
		<-rel
		if events[0].Who == "boom" {
			panic("db driver exploded")
		}
		for _, ev := range events {
			flushed = append(flushed, ev.Who)
		}
		flushDone <- struct{}{}
		return nil
	},
		WithAuditBatchSize(2),
		WithAuditFlushInterval(time.Hour), // 只由攒批触发,排除定时干扰
		WithAuditOnDrop(func(AuditEvent) { onDropCalls.Add(1) }),
	)
	defer func() {
		for { // 放行仍在门上的 flush,Close 才能收口
			select {
			case rel := <-releases:
				close(rel)
				continue
			default:
			}
			break
		}
		if err := buf.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	// 第一批（panic 批）：2 条攒满触发 flush，inner panic。
	_ = buf.Sink(context.Background(), AuditEvent{Who: "boom", Path: "/a"})
	_ = buf.Sink(context.Background(), AuditEvent{Who: "boom2", Path: "/a"})
	rel1 := <-releases // flush 已抵达,停在其 panic 点前
	close(rel1)
	deadline := time.Now().Add(5 * time.Second)
	for buf.Dropped() < 2 { // panic 批收编完成 = 整批计入丢弃(循环未死的旁证)
		if time.Now().After(deadline) {
			t.Fatalf("★ flush panic 批未按事件数计入 Dropped: got %d, want 2", buf.Dropped())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 整批按丢弃留痕（#207+#208 口径）：2 条事件计入 Dropped,OnDrop 同路。
	if got := buf.Dropped(); got != 2 {
		t.Fatalf("★ flush panic 整批必须按事件数计入 Dropped: got %d, want 2", got)
	}
	if n := onDropCalls.Load(); n != 2 {
		t.Fatalf("★ flush panic 必须走 OnDrop 同路: got %d calls, want 2", n)
	}

	// 循环存活：第二批正常 flush（原实现这里永远收不到 flush）。
	_ = buf.Sink(context.Background(), AuditEvent{Who: "after", Path: "/b"})
	_ = buf.Sink(context.Background(), AuditEvent{Who: "after2", Path: "/b"})
	rel2 := <-releases
	close(rel2)
	select {
	case <-flushDone:
		if len(flushed) != 2 || flushed[0] != "after" {
			t.Fatalf("★ panic 后循环必须继续 flush 后续事件: got %v", flushed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("★ flush panic 杀死后台循环(#207 病灶未修)")
	}
}

// TestBufferedAuditSink_FlushFailureCountsDropped 回归钉（#208）：flush 失败
// = 整批事件未落盘，必须按事件数计入 Dropped()（OnDrop 同路，reason 区分
// 归因），既有 Warn 面保留——下游彻底失败（DB 挂）时观测口不再恒 0。
func TestBufferedAuditSink_FlushFailureCountsDropped(t *testing.T) {
	var dropTotal atomic.Int32
	releases := make(chan chan struct{}, 8)
	buf := NewBufferedAuditSink(func(_ context.Context, _ []AuditEvent) error {
		rel := make(chan struct{})
		releases <- rel
		<-rel
		return errors.New("db down")
	},
		WithAuditBatchSize(3),
		WithAuditFlushInterval(time.Hour),
		WithAuditOnDrop(func(AuditEvent) { dropTotal.Add(1) }),
	)
	defer func() {
		for {
			select {
			case rel := <-releases:
				close(rel)
				continue
			default:
			}
			break
		}
		if err := buf.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	for i := 0; i < 3; i++ {
		_ = buf.Sink(context.Background(), AuditEvent{Who: fmt.Sprint(i), Path: "/f"})
	}
	rel := <-releases
	close(rel) // 放行 flush(失败路径)

	deadline := time.Now().Add(5 * time.Second)
	for buf.Dropped() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("★ flush 失败必须按事件数计入 Dropped: got %d, want 3 (#208)", buf.Dropped())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := dropTotal.Load(); n != 3 {
		t.Fatalf("★ flush 失败必须走 OnDrop 同路: got %d calls, want 3", n)
	}
}

// TestBufferedSink_ConcurrentSinkClose 回归钉（#209，-race）：多 goroutine
// Sink 撞 Close——closed 判定与入队原子化（#181）+ Close 终态传播（#209）
// 的并发面回归。断言：无 panic、无竞态（-race 下红即修回）、关停前入队事件
// 全部 flush 或按丢弃口径计数（两个去向都可观测，不漏记）。
func TestBufferedSink_ConcurrentSinkClose(t *testing.T) {
	var flushed atomic.Int64
	buf := NewBufferedSink(func(_ context.Context, rows []oplogRow) error {
		flushed.Add(int64(len(rows)))
		return nil
	},
		WithSinkBatchSize[oplogRow](10),
		WithSinkFlushInterval[oplogRow](50*time.Millisecond), // 快速兜底,Close 前大概率冲完
	)

	var wg sync.WaitGroup
	const writers = 8
	const perWriter = 200
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_ = buf.Sink(context.Background(), oplogRow{Action: fmt.Sprint(i), IP: "10.0.0.1"})
			}
		}()
	}
	// Close 与写并发：不等写完就关（原 #181 竞态面 + #209 终态传播面）。
	var closerErr error
	var closeOnce sync.Once
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := buf.Close(context.Background())
			closeOnce.Do(func() { closerErr = err })
		}()
	}
	wg.Wait()
	if closerErr != nil {
		t.Fatalf("close err: %v", closerErr)
	}
	// 关停前入队的全部事件必须有两个去向之一：flush 出去 或 按丢弃计数。
	// 总数 = writers*perWriter；flushed + Dropped >= 总数即为不漏记。
	if got := flushed.Load() + buf.Dropped(); got < writers*perWriter {
		t.Fatalf("★ 并发 Sink∥Close 存在漏记窗口: flushed %d + dropped %d < total %d",
			flushed.Load(), buf.Dropped(), writers*perWriter)
	}
}

// TestBufferedSink_CloseTimeoutErrorPropagates 回归钉（#209）：Close 超时错误
// 只活在首调用栈曾是假成功源——首调超时后，后续 Close（哪怕 ctx 宽裕）必须
// 回读同一份真实终态，不得返回 nil。
func TestBufferedSink_CloseTimeoutErrorPropagates(t *testing.T) {
	gate := make(chan struct{}, 8)
	release := make(chan struct{})
	buf := NewBufferedSink(func(_ context.Context, _ []oplogRow) error {
		gate <- struct{}{}
		<-release // 卡住 final flush,制造首调超时
		return nil
	})
	_ = buf.Sink(context.Background(), oplogRow{Action: "tail"})

	first := buf.Close(shortCtx(50 * time.Millisecond))
	if first == nil || !errors.Is(first, context.DeadlineExceeded) {
		t.Fatalf("★ 首调 Close 应返回超时错误: got %v", first)
	}
	// 放行 final flush,后台循环收口(done 闭合);closeErr 已在首调超时刻录下。
	close(release)
	// 次调（ctx 宽裕）等 done 后回读终态——不得假报成功（#209）。
	second := buf.Close(context.Background())
	if second == nil || !errors.Is(second, context.DeadlineExceeded) {
		t.Fatalf("★ 次调 Close 必须回读首调超时终态(不得假报成功,#209): got %v", second)
	}
	third := buf.Close(context.Background())
	if third == nil || !errors.Is(third, context.DeadlineExceeded) {
		t.Fatalf("★ done 闭合后 Close 终态应保持超时错误: got %v", third)
	}
}

// shortCtx 造一个 d 后超时的 ctx（测试辅助）。
func shortCtx(d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		<-ctx.Done()
		cancel() // 复位资源
	}()
	return ctx
}

// TestAuditLogMiddleware_HookPanicIsolated 回归钉（#210）：auditEventOf 的
// 六个 With*Func 提取钩子逐个 panic 收编——panic 钩子按空值处理 + Warn 留痕，
// 其余字段照常提取、事件照常产出（提取缝坏钩子不劫持请求与 panic 恢复点）。
func TestAuditLogMiddleware_HookPanicIsolated(t *testing.T) {
	collected := &collectingAuditSink{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected.sinkFunc),
		// 全部六个钩子都 panic:事件必须照常产出,对应字段为空值。
		WithAuditLogWho(func(context.Context, *app.RequestContext) string { panic("who hook boom") }),
		WithAuditLogAction(func(context.Context, *app.RequestContext) string { panic("action hook boom") }),
		WithAuditLogBizCode(func(context.Context, *app.RequestContext) int64 { panic("bizcode hook boom") }),
		WithAuditLogClientIP(func(context.Context, *app.RequestContext) string { panic("ip hook boom") }),
		WithAuditLogUA(func(context.Context, *app.RequestContext) string { panic("ua hook boom") }),
		WithAuditLogExtra(func(context.Context, *app.RequestContext) map[string]string { panic("extra hook boom") }),
	))
	h.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})

	ut.PerformRequest(h.Engine, "GET", "/api/admin/users", nil)
	events := collected.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1（坏钩子不得吞掉审计事件，#210）", len(events))
	}
	ev := events[0]
	if ev.Who != "" || ev.Action != "" || ev.BizCode != 0 || ev.IP != "" || ev.UA != "" || ev.Extra != nil {
		t.Fatalf("★ panic 钩子必须按空值处理: %+v", ev)
	}
	if ev.Method != "GET" || ev.Path != "/api/admin/users" || ev.Status != 200 {
		t.Fatalf("★ 其余字段必须照常提取: %+v", ev)
	}

	// 正常路径双回归（#210）：钩子正常时字段照常填充（隔离壳零行为变化）。
	collected2 := &collectingAuditSink{}
	h2 := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h2.Use(AuditLogMiddleware(
		WithAuditLogPaths("/api/admin/**"),
		WithAuditLogSink(collected2.sinkFunc),
		WithAuditLogWho(func(context.Context, *app.RequestContext) string { return "u1" }),
		WithAuditLogAction(func(context.Context, *app.RequestContext) string { return "policy.delete" }),
		WithAuditLogBizCode(func(context.Context, *app.RequestContext) int64 { return 7 }),
		WithAuditLogExtra(func(context.Context, *app.RequestContext) map[string]string {
			return map[string]string{"k": "v"}
		}),
	))
	h2.GET("/api/admin/users", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"v": "1"})
	})
	ut.PerformRequest(h2.Engine, "GET", "/api/admin/users", nil)
	events2 := collected2.snapshot()
	if len(events2) != 1 {
		t.Fatalf("got %d events, want 1", len(events2))
	}
	ev2 := events2[0]
	if ev2.Who != "u1" || ev2.Action != "policy.delete" || ev2.BizCode != 7 || ev2.Extra["k"] != "v" {
		t.Fatalf("★ 正常钩子字段必须照常填充: %+v", ev2)
	}
}
