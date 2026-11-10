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
