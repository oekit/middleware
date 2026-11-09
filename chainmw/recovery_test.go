package chainmw

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/oekit/core/chain"
	"github.com/oekit/core/transport"
)

// TestRecoveryCapturesPanic 验证 panic 被捕获为 *chain.PanicError 返回，
// 且记录 Error 日志（默认字段 panic/stack/kind/op）。
func TestRecoveryCapturesPanic(t *testing.T) {
	rec := &captureLogger{}
	tr := &stubTransporter{kind: transport.KindHTTP, endpoint: "http://127.0.0.1:8000", op: "/api/boom"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("boom")
	}, Recovery(WithRecoveryLogger(rec)))

	resp, err := h(ctx, "req")
	if resp != nil {
		t.Fatalf("resp = %v, want nil", resp)
	}
	var pv *chain.PanicError
	if !errors.As(err, &pv) {
		t.Fatalf("err = %v, want *chain.PanicError", err)
	}
	if pv.Value != "boom" {
		t.Errorf("pv.Value = %v, want boom", pv.Value)
	}
	if pv.Stack == "" {
		t.Error("expected non-empty stack")
	}

	out := rec.text()
	if !strings.Contains(out, "[panic] recovered") || !strings.Contains(out, "ERROR") {
		t.Fatalf("missing panic error log: %s", out)
	}
	for _, want := range []string{"panic=boom", "kind=http", "op=/api/boom"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s: %s", want, out)
		}
	}
	if !strings.Contains(out, "stack=") || pv.Stack == "" {
		t.Errorf("log missing stack field: %s", out)
	}
}

// TestRecoveryNoPanicPassthrough 验证无 panic 时透传且零日志。
func TestRecoveryNoPanicPassthrough(t *testing.T) {
	rec := &captureLogger{}
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		return req, nil
	}, Recovery(WithRecoveryLogger(rec)))

	got, err := h(context.Background(), "ok")
	if err != nil || got != "ok" {
		t.Fatalf("got %v, %v; want ok, nil", got, err)
	}
	if len(rec.entries) != 0 {
		t.Errorf("unexpected logs: %v", rec.entries)
	}
}

// TestRecoveryReporterCalled 验证监控上报钩子收到 PanicError。
func TestRecoveryReporterCalled(t *testing.T) {
	called := false
	var got *chain.PanicError
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("report-me")
	}, Recovery(WithRecoveryReporter(func(_ context.Context, _ any, pv *chain.PanicError) {
		called = true
		got = pv
	})))

	_, err := h(context.Background(), "req")
	if !called {
		t.Fatal("expected reporter to be called")
	}
	if got == nil || got.Value != "report-me" {
		t.Errorf("reported value = %v, want report-me", got)
	}
	if !errors.As(err, &got) || got.Value != "report-me" {
		t.Errorf("returned err = %v", err)
	}
}

// TestRecoveryReporterPanicIsolated 钉住上报隔离语义：reporter 钩子内部
// panic 必须被隔离（记 drop 日志），原始 panic 仍以 *chain.PanicError 返回。
func TestRecoveryReporterPanicIsolated(t *testing.T) {
	rec := &captureLogger{}
	reporterCalled := false
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("biz panic")
	}, Recovery(
		WithRecoveryLogger(rec),
		WithRecoveryReporter(func(_ context.Context, _ any, _ *chain.PanicError) {
			reporterCalled = true
			panic("sentry sdk exploded")
		}),
	))

	_, err := h(context.Background(), "req")
	if !reporterCalled {
		t.Error("reporter should have been invoked")
	}
	var pv *chain.PanicError
	if !errors.As(err, &pv) || pv.Value != "biz panic" {
		t.Fatalf("err = %v, want *chain.PanicError(biz panic)", err)
	}

	out := rec.text()
	if !strings.Contains(out, "report dropped") || !strings.Contains(out, "reporter_panic") {
		t.Fatalf("missing reporter-drop log: %s", out)
	}
	if !strings.Contains(out, "original_panic=biz panic") {
		t.Errorf("drop log missing original panic: %s", out)
	}
}

// TestRecoveryLogFieldsHook 验证自定义字段构建器替换默认字段。
func TestRecoveryLogFieldsHook(t *testing.T) {
	rec := &captureLogger{}
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("boom")
	}, Recovery(
		WithRecoveryLogger(rec),
		WithRecoveryLogFields(func(_ context.Context, req any, _ *chain.PanicError) []any {
			return []any{"custom", req, "stack_len", 42}
		}),
	))

	h(context.Background(), "myreq")
	out := rec.text()
	if !strings.Contains(out, "custom=myreq") || !strings.Contains(out, "stack_len=42") {
		t.Fatalf("custom fields missing: %s", out)
	}
	if strings.Contains(out, "kind=") || strings.Contains(out, "panic=boom") {
		t.Errorf("default fields should be replaced: %s", out)
	}
}

// TestRecoveryReportsPanicErrorReturnPath 回归 #123：下游**以 *PanicError
// 形式返回**（例如链上内层的 core/chain.Timeout 已把 panic 收编成错误再
// 上抛）必须与「直接 panic」同口径——记 [panic] recovered 日志 + 调上报
// 钩子。core/chain.Recovery 有这条路径（panic_isolation_test.go 的第二个
// reporter 调用点），chainmw 此前漏掉，Timeout 收编的 panic 零日志零上报。
func TestRecoveryReportsPanicErrorReturnPath(t *testing.T) {
	rec := &captureLogger{}
	called := false
	var got *chain.PanicError
	sentinel := &chain.PanicError{Value: "as-error", Stack: "fake-stack"}
	h := chain.Finalize(func(_ context.Context, _ any) (any, error) {
		return nil, sentinel
	}, Recovery(
		WithRecoveryLogger(rec),
		WithRecoveryReporter(func(_ context.Context, _ any, pv *chain.PanicError) {
			called = true
			got = pv
		}),
	))

	resp, err := h(context.Background(), "req")
	if !called {
		t.Fatal("expected reporter to be called for *PanicError return path")
	}
	if got != sentinel {
		t.Errorf("reported pv = %v, want the returned *chain.PanicError", got)
	}
	if err != sentinel {
		t.Errorf("err = %v, want unchanged *chain.PanicError passthrough", err)
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil", resp)
	}

	out := rec.text()
	if !strings.Contains(out, "[panic] recovered") || !strings.Contains(out, "ERROR") {
		t.Fatalf("missing panic error log on *PanicError return path: %s", out)
	}
	if !strings.Contains(out, "panic=as-error") {
		t.Errorf("log missing panic value: %s", out)
	}
}

// TestRecoveryPlainErrorReturnNotReported 反向钉：普通错误返回不触发 panic
// 日志/上报——*PanicError 判定必须收窄，不能把所有 error 都当 panic 记。
func TestRecoveryPlainErrorReturnNotReported(t *testing.T) {
	rec := &captureLogger{}
	reporterCalled := false
	h := chain.Finalize(func(_ context.Context, _ any) (any, error) {
		return nil, errors.New("plain biz error")
	}, Recovery(
		WithRecoveryLogger(rec),
		WithRecoveryReporter(func(_ context.Context, _ any, _ *chain.PanicError) {
			reporterCalled = true
		}),
	))

	_, err := h(context.Background(), "req")
	if err == nil {
		t.Fatal("expected plain error passthrough")
	}
	if reporterCalled {
		t.Error("reporter must not be called for plain error return")
	}
	if len(rec.entries) != 0 {
		t.Errorf("unexpected logs for plain error return: %v", rec.entries)
	}
}

// TestRecoveryNoTransportDefaults 验证无 transport 上下文时 kind/op 记 "-"。
func TestRecoveryNoTransportDefaults(t *testing.T) {
	rec := &captureLogger{}
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("boom")
	}, Recovery(WithRecoveryLogger(rec)))

	h(context.Background(), "req")
	out := rec.text()
	if !strings.Contains(out, "kind=-") || !strings.Contains(out, "op=-") {
		t.Fatalf("expected kind=-/op=- without transport: %s", out)
	}
}

// evilError 是 Error() 自身会 panic 的 evil error（#138 的缺陷触发形态：
// panic 值是 error 且其 Error() 炸 ⇒ 日志后端格式化 kv 时二次 panic）。
type evilError struct{}

func (evilError) Error() string { panic("Error() explodes") }

// evilValueLogger 模拟 logx slog 后端的 logValue 行为：对 error 值**直接调
// Error()**（不经 fmt 的 panic 保护）——#138 的真实二次 panic 触发面
// （logx/slog.go logValue 直接 err.Error()，evil error 在此炸出）。
type evilValueLogger struct {
	captureLogger
}

func (l *evilValueLogger) CtxError(ctx context.Context, msg string, kvs ...any) {
	for i := 0; i+1 < len(kvs); i += 2 {
		if e, ok := kvs[i+1].(error); ok {
			_ = e.Error() // 直接调用：Error() panic 则 panic（真实后端形态）
		}
	}
	l.captureLogger.CtxError(ctx, msg, kvs...)
}

// TestRecoveryEvilErrorPanicValueIsolated 钉住 #138：panic 值是 Error() 会炸
// 的 error 时，日志路径必须被 panic 隔离——recovery 不得整体失效：
//   - panic 不逃出中间件（此前整个 h(...) 调用 panic 逃逸）；
//   - 仍以 *chain.PanicError 返回（外层 errors.As 分支可走、ErrorHandler 可调）；
//   - 上报钩子被调用（此前一次都不被调，Sentry 静默丢失）；
//   - 日志降级为隔离兜底（logger_panic 字段），不再携带会炸的原始值。
func TestRecoveryEvilErrorPanicValueIsolated(t *testing.T) {
	rec := &evilValueLogger{}
	reporterCalled := false
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic(evilError{})
	}, Recovery(
		WithRecoveryLogger(rec),
		WithRecoveryReporter(func(_ context.Context, _ any, _ *chain.PanicError) {
			reporterCalled = true
		}),
	))

	// 此处不再 panic 逃逸即为本测试的一部分：逃逸则测试框架直接判红。
	resp, err := h(context.Background(), "req")
	if resp != nil {
		t.Errorf("resp = %v, want nil", resp)
	}
	var pv *chain.PanicError
	if !errors.As(err, &pv) {
		t.Fatalf("err = %v, want *chain.PanicError (ErrorHandler 分支可走)", err)
	}
	if _, ok := pv.Value.(evilError); !ok {
		t.Errorf("pv.Value = %v, want evilError", pv.Value)
	}
	if !reporterCalled {
		t.Error("reporter must be called before the log path explodes (#138)")
	}

	out := rec.text()
	if !strings.Contains(out, "[panic] recovered") || !strings.Contains(out, "logger_panic") {
		t.Fatalf("missing isolated log-failure fallback: %s", out)
	}
	if !strings.Contains(out, "original_panic=") {
		t.Errorf("isolated fallback missing original panic (sanitized): %s", out)
	}
}

// TestPanicSafeText panicSafeText 自身契约：对 Error() 会炸的值不 panic，
// 降级为类型名描述；普通值原样格式化。
func TestPanicSafeText(t *testing.T) {
	got := panicSafeText(evilError{}) // 此处不 panic 即为通过
	if got == "" {
		t.Error("panicSafeText should never return an empty string")
	}
	if s := panicSafeText("plain"); s != "plain" {
		t.Errorf("panicSafeText(plain) = %q, want plain", s)
	}
}

// panickyLogger CtxError 自身 panic 的 logger（日志后端故障形态）。
type panickyLogger struct {
	captureLogger
}

func (p *panickyLogger) CtxError(_ context.Context, _ string, _ ...any) {
	panic("logger backend exploded")
}

// TestRecoveryLoggerPanicIsolated 钉住 #138 的另一触发面：logger 后端自身
// panic 时 recovery 同样不得失效——上报钩子照常、*PanicError 照常返回
// （兜底日志再炸只能静默吞掉，无处可记）。
func TestRecoveryLoggerPanicIsolated(t *testing.T) {
	reporterCalled := false
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("biz panic")
	}, Recovery(
		WithRecoveryLogger(&panickyLogger{}),
		WithRecoveryReporter(func(_ context.Context, _ any, _ *chain.PanicError) {
			reporterCalled = true
		}),
	))

	_, err := h(context.Background(), "req")
	var pv *chain.PanicError
	if !errors.As(err, &pv) || pv.Value != "biz panic" {
		t.Fatalf("err = %v, want *chain.PanicError(biz panic)", err)
	}
	if !reporterCalled {
		t.Error("reporter must be called even when the logger panics (#138)")
	}
}

// TestRecoveryReportBeforeLog 钉住 #138 的顺序契约：上报先于日志——日志
// 路径出问题时上报钩子已经执行（监控不静默丢失）。
func TestRecoveryReportBeforeLog(t *testing.T) {
	var order []string
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		panic("boom")
	}, Recovery(
		WithRecoveryReporter(func(_ context.Context, _ any, _ *chain.PanicError) {
			order = append(order, "report")
		}),
		WithRecoveryLogFields(func(_ context.Context, _ any, _ *chain.PanicError) []any {
			order = append(order, "log") // 字段构建器在 logPanic 内部调用
			return nil
		}),
	))

	h(context.Background(), "req")
	if len(order) != 2 || order[0] != "report" || order[1] != "log" {
		t.Fatalf("execution order = %v, want [report log] (#138)", order)
	}
}
