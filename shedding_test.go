package mw

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/oekit/concurrency/shedding"
)

// --- fakes ---

// fakePromise 记录 Pass/Fail 回填调用（race-safe，供断言）。
type fakePromise struct {
	pass atomic.Int32
	fail atomic.Int32
}

func (p *fakePromise) Pass() { p.pass.Add(1) }
func (p *fakePromise) Fail() { p.fail.Add(1) }

// fakeShedder 恒按 allowErr 拒绝，或放行并返回可观测 fakePromise。
type fakeShedder struct {
	allowErr error
	promise  *fakePromise
}

func (s *fakeShedder) Allow(_ context.Context) (shedding.Promise, error) {
	if s.allowErr != nil {
		return nil, s.allowErr
	}
	if s.promise == nil {
		// 显式返回非类型化 nil，模拟「放行却返回 nil Promise」的实现违约
		//（typed-nil 会包成非 nil 接口，不走本违约分支）。
		return nil, nil
	}
	return s.promise, nil
}

// runThrough 以待测中间件为入口、endpoint 为链尾执行一次请求
// （对齐 recovery_test.go 的直接调用姿势：中间件不入链，c.Next 落到 endpoint）。
func runThrough(mid, endpoint app.HandlerFunc) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/test")
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, endpoint)
	c.SetHandlers(hc)
	mid(context.Background(), c)
	return c
}

// --- 拒绝路径 ---

// TestSheddingMiddleware_RejectServiceOverloaded 验证恒拒 shedder（上游
// sentinel ErrServiceOverloaded）→ HTTP 503 + body code 50300，handler 不执行。
func TestSheddingMiddleware_RejectServiceOverloaded(t *testing.T) {
	handlerRan := false
	mid := SheddingMiddleware(WithShedder(&fakeShedder{allowErr: shedding.ErrServiceOverloaded}))
	c := runThrough(mid, func(_ context.Context, _ *app.RequestContext) {
		handlerRan = true
	})

	assert.False(t, handlerRan)
	assert.DeepEqual(t, consts.StatusServiceUnavailable, c.Response.StatusCode())
	body := string(c.Response.Body())
	if !strings.Contains(body, "50300") {
		t.Errorf("body should contain code 50300, got %q", body)
	}
	if !strings.Contains(body, "service is overloaded") {
		t.Errorf("body message mismatch, got %q", body)
	}
}

// TestSheddingMiddleware_RejectAnyError 验证 Allow 返回任意错误（非仅
// ErrServiceOverloaded）一律走 503 拒绝路径。
func TestSheddingMiddleware_RejectAnyError(t *testing.T) {
	handlerRan := false
	mid := SheddingMiddleware(WithShedder(&fakeShedder{allowErr: errors.New("custom shedder error")}))
	c := runThrough(mid, func(_ context.Context, _ *app.RequestContext) {
		handlerRan = true
	})

	assert.False(t, handlerRan)
	assert.DeepEqual(t, consts.StatusServiceUnavailable, c.Response.StatusCode())
	if !strings.Contains(string(c.Response.Body()), "50300") {
		t.Errorf("body should contain code 50300, got %q", string(c.Response.Body()))
	}
}

// TestSheddingMiddleware_CtxCanceledRejected 验证 ctx 已取消（真实 NopShedder
// 返回 ctx.Err()）也按拒绝处理：503 + body code 50300。
func TestSheddingMiddleware_CtxCanceledRejected(t *testing.T) {
	c := app.NewContext(0)
	c.Request.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/test")
	hc := make(app.HandlersChain, 0, 1)
	hc = append(hc, func(_ context.Context, _ *app.RequestContext) {
		t.Error("handler should not run for canceled ctx")
	})
	c.SetHandlers(hc)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	SheddingMiddleware(WithShedder(shedding.NewNopShedder()))(canceled, c)

	assert.DeepEqual(t, consts.StatusServiceUnavailable, c.Response.StatusCode())
	if !strings.Contains(string(c.Response.Body()), "50300") {
		t.Errorf("body should contain code 50300, got %q", string(c.Response.Body()))
	}
}

// --- 放行路径 ---

// TestSheddingMiddleware_AllowRunsHandler 验证恒允 shedder → handler 执行，
// 2xx 回填 Pass()（且只回填一次）。
func TestSheddingMiddleware_AllowRunsHandler(t *testing.T) {
	fp := &fakePromise{}
	mid := SheddingMiddleware(WithShedder(&fakeShedder{promise: fp}))
	handlerRan := false
	c := runThrough(mid, func(_ context.Context, rc *app.RequestContext) {
		handlerRan = true
		SuccessResp(rc, map[string]string{"ok": "1"})
	})

	assert.True(t, handlerRan)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	assert.DeepEqual(t, int32(1), fp.pass.Load())
	assert.DeepEqual(t, int32(0), fp.fail.Load())
}

// TestSheddingMiddleware_FailOn5xx 验证 handler 写出 5xx → 回填 Fail()。
func TestSheddingMiddleware_FailOn5xx(t *testing.T) {
	fp := &fakePromise{}
	mid := SheddingMiddleware(WithShedder(&fakeShedder{promise: fp}))
	c := runThrough(mid, func(_ context.Context, rc *app.RequestContext) {
		ErrorResp(rc, 500, "internal server error")
	})

	assert.DeepEqual(t, consts.StatusInternalServerError, c.Response.StatusCode())
	assert.DeepEqual(t, int32(1), fp.fail.Load())
	assert.DeepEqual(t, int32(0), fp.pass.Load())
}

// TestSheddingMiddleware_PassOn4xx 验证 4xx（调用方错误，与服务容量无关）
// 回填 Pass() 而非 Fail() —— 对齐 nns-endpoint「4xx 不计失败」语义。
func TestSheddingMiddleware_PassOn4xx(t *testing.T) {
	fp := &fakePromise{}
	mid := SheddingMiddleware(WithShedder(&fakeShedder{promise: fp}))
	c := runThrough(mid, func(_ context.Context, rc *app.RequestContext) {
		ErrorResp(rc, 404, "resource not found")
	})

	assert.DeepEqual(t, consts.StatusNotFound, c.Response.StatusCode())
	assert.DeepEqual(t, int32(1), fp.pass.Load())
	assert.DeepEqual(t, int32(0), fp.fail.Load())
}

// TestSheddingMiddleware_NilPromiseDefensive 验证 Shedder 放行却返回 nil
// Promise（实现违约）时不回填、不 panic，请求继续处理。
func TestSheddingMiddleware_NilPromiseDefensive(t *testing.T) {
	handlerRan := false
	mid := SheddingMiddleware(WithShedder(&fakeShedder{})) // promise == nil
	c := runThrough(mid, func(_ context.Context, _ *app.RequestContext) {
		handlerRan = true
	})

	assert.True(t, handlerRan)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// --- panic 路径（Recovery 交互） ---

// TestSheddingMiddleware_PanicFailsPromise_RecoveryOuter 验证 Recovery 在外、
// Shedding 在内（推荐顺序）时：handler panic → Fail() 回填 + panic 透传给
// Recovery（500 响应），Pass 不回填。
func TestSheddingMiddleware_PanicFailsPromise_RecoveryOuter(t *testing.T) {
	fp := &fakePromise{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(RecoveryMiddleware())
	h.Use(SheddingMiddleware(WithShedder(&fakeShedder{promise: fp})))
	h.GET("/boom", func(_ context.Context, _ *app.RequestContext) {
		panic("boom")
	})

	w := ut.PerformRequest(h.Engine, http.MethodGet, "/boom", nil)
	assert.DeepEqual(t, consts.StatusInternalServerError, w.Code)
	assert.DeepEqual(t, int32(1), fp.fail.Load())
	assert.DeepEqual(t, int32(0), fp.pass.Load())
}

// TestSheddingMiddleware_PanicFailsPromise_RecoveryInner 验证反序注册
// （Shedding 在外、Recovery 在内）：Recovery 先 recover 并写 500，本中间件
// defer 的 recover 读到 nil → 按 500 状态码分类，同样回填 Fail()。
func TestSheddingMiddleware_PanicFailsPromise_RecoveryInner(t *testing.T) {
	fp := &fakePromise{}
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(SheddingMiddleware(WithShedder(&fakeShedder{promise: fp})))
	h.Use(RecoveryMiddleware())
	h.GET("/boom", func(_ context.Context, _ *app.RequestContext) {
		panic("boom")
	})

	w := ut.PerformRequest(h.Engine, http.MethodGet, "/boom", nil)
	assert.DeepEqual(t, consts.StatusInternalServerError, w.Code)
	assert.DeepEqual(t, int32(1), fp.fail.Load())
	assert.DeepEqual(t, int32(0), fp.pass.Load())
}

// --- 缺省降载器与 Option 优先级 ---

// TestSheddingMiddleware_DefaultShedder 验证零参构造走缺省自适应降载器：
// 非过载（初始 CPU 采样为 0 / 非 linux 采样 fail-open）下请求正常放行。
func TestSheddingMiddleware_DefaultShedder(t *testing.T) {
	mid := SheddingMiddleware()
	handlerRan := false
	c := runThrough(mid, func(_ context.Context, rc *app.RequestContext) {
		handlerRan = true
		rc.SetStatusCode(consts.StatusOK)
	})

	assert.True(t, handlerRan)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestSheddingMiddleware_CPUThresholdBuilds 验证 WithShedderCPUThreshold 合法值
// 构造成功且请求放行（缺省降载器 + 定制阈值）。
func TestSheddingMiddleware_CPUThresholdBuilds(t *testing.T) {
	mid := SheddingMiddleware(WithShedderCPUThreshold(800))
	handlerRan := false
	c := runThrough(mid, func(_ context.Context, rc *app.RequestContext) {
		handlerRan = true
		rc.SetStatusCode(consts.StatusOK)
	})

	assert.True(t, handlerRan)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestSheddingMiddleware_CPUThresholdInvalidPanics 验证越界阈值（须在
// (0, 1000) 开区间）在中间件构造期 panic（fail-fast，非首次请求才暴露）。
func TestSheddingMiddleware_CPUThresholdInvalidPanics(t *testing.T) {
	for _, milli := range []int64{0, -100, 1000, 2000} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic for threshold %d", milli)
				}
			}()
			_ = SheddingMiddleware(WithShedderCPUThreshold(milli))
		}()
	}
}

// TestSheddingMiddleware_WithShedderWinsOverCPUThreshold 验证优先级：显式
// WithShedder 时 WithShedderCPUThreshold 整体 no-op —— 连越界阈值都不 panic，
// 且实际使用的是显式注入的降载器（恒拒 fake 生效 → 503）。
func TestSheddingMiddleware_WithShedderWinsOverCPUThreshold(t *testing.T) {
	handlerRan := false
	mid := SheddingMiddleware(
		WithShedder(&fakeShedder{allowErr: shedding.ErrServiceOverloaded}),
		WithShedderCPUThreshold(5000), // 越界，但显式 Shedder 胜出 → no-op，不 panic
	)
	c := runThrough(mid, func(_ context.Context, _ *app.RequestContext) {
		handlerRan = true
	})

	assert.False(t, handlerRan)
	assert.DeepEqual(t, consts.StatusServiceUnavailable, c.Response.StatusCode())
}

// --- 端到端（真实引擎） ---

// TestSheddingMiddleware_EndToEnd 经真实 hertz 引擎验证：恒拒 → 503 JSON
// body code 50300；恒允 → 200 handler body。
func TestSheddingMiddleware_EndToEnd(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(SheddingMiddleware(WithShedder(&fakeShedder{allowErr: shedding.ErrServiceOverloaded})))
	h.GET("/ok", func(_ context.Context, c *app.RequestContext) {
		SuccessResp(c, "fine")
	})

	w := ut.PerformRequest(h.Engine, http.MethodGet, "/ok", nil)
	assert.DeepEqual(t, consts.StatusServiceUnavailable, w.Code)
	body := w.Body.String()
	if !strings.Contains(body, `"code":50300`) {
		t.Errorf("body code mismatch, got %q", body)
	}
	if !strings.Contains(body, "service is overloaded") {
		t.Errorf("body message mismatch, got %q", body)
	}

	// 恒允：换一个引擎（同一引擎上中间件已固定）
	h2 := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	fp := &fakePromise{}
	h2.Use(SheddingMiddleware(WithShedder(&fakeShedder{promise: fp})))
	h2.GET("/ok", func(_ context.Context, c *app.RequestContext) {
		SuccessResp(c, "fine")
	})

	w2 := ut.PerformRequest(h2.Engine, http.MethodGet, "/ok", nil)
	assert.DeepEqual(t, consts.StatusOK, w2.Code)
	if !strings.Contains(w2.Body.String(), "fine") {
		t.Errorf("body should contain 'fine', got %q", w2.Body.String())
	}
	assert.DeepEqual(t, int32(1), fp.pass.Load())
	assert.DeepEqual(t, int32(0), fp.fail.Load())
}
