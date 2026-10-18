package chainmw

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/oekit/core/chain"
	"github.com/oekit/core/transport"
	"github.com/oekit/logx"
)

// stubTransporter 测试用 Transporter。
type stubTransporter struct {
	kind     transport.Kind
	endpoint string
	op       string
	req      transport.Header
	reply    transport.Header
}

func (f *stubTransporter) Kind() transport.Kind            { return f.kind }
func (f *stubTransporter) Endpoint() string                { return f.endpoint }
func (f *stubTransporter) Operation() string               { return f.op }
func (f *stubTransporter) RequestHeader() transport.Header { return f.req }
func (f *stubTransporter) ReplyHeader() transport.Header   { return f.reply }

// captureLogger 捕获 logx 输出的最小 Logger 实现。
type captureLogger struct {
	entries []string
}

func (c *captureLogger) rec(level, msg string, kvs []any) {
	var sb strings.Builder
	sb.WriteString(level + " " + msg)
	for i := 0; i+1 < len(kvs); i += 2 {
		fmt.Fprintf(&sb, " %v=%v", kvs[i], kvs[i+1])
	}
	c.entries = append(c.entries, sb.String())
}

func (c *captureLogger) text() string { return strings.Join(c.entries, "\n") }

func (c *captureLogger) Debug(msg string, kvs ...any) { c.rec("DEBUG", msg, kvs) }
func (c *captureLogger) Info(msg string, kvs ...any)  { c.rec("INFO", msg, kvs) }
func (c *captureLogger) Warn(msg string, kvs ...any)  { c.rec("WARN", msg, kvs) }
func (c *captureLogger) Error(msg string, kvs ...any) { c.rec("ERROR", msg, kvs) }
func (c *captureLogger) Debugf(format string, args ...any) {
	c.rec("DEBUG", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) Infof(format string, args ...any) {
	c.rec("INFO", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) Warnf(format string, args ...any) {
	c.rec("WARN", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) Errorf(format string, args ...any) {
	c.rec("ERROR", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) CtxDebug(_ context.Context, msg string, kvs ...any) {
	c.rec("DEBUG", msg, kvs)
}
func (c *captureLogger) CtxInfo(_ context.Context, msg string, kvs ...any) {
	c.rec("INFO", msg, kvs)
}
func (c *captureLogger) CtxWarn(_ context.Context, msg string, kvs ...any) {
	c.rec("WARN", msg, kvs)
}
func (c *captureLogger) CtxError(_ context.Context, msg string, kvs ...any) {
	c.rec("ERROR", msg, kvs)
}
func (c *captureLogger) CtxDebugf(_ context.Context, format string, args ...any) {
	c.rec("DEBUG", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) CtxInfof(_ context.Context, format string, args ...any) {
	c.rec("INFO", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) CtxWarnf(_ context.Context, format string, args ...any) {
	c.rec("WARN", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) CtxErrorf(_ context.Context, format string, args ...any) {
	c.rec("ERROR", fmt.Sprintf(format, args...), nil)
}
func (c *captureLogger) WithCtx(_ context.Context) logx.Logger { return c }
func (c *captureLogger) WithService(_ string) logx.Logger      { return c }
func (c *captureLogger) WithAttrs(_ ...logx.Attr) logx.Logger  { return c }
func (c *captureLogger) WithGroup(_ string) logx.Logger        { return c }
func (c *captureLogger) SetLevel(_ logx.Level)                 {}

var errTest = errors.New("test-fail")

func TestAccessLogRecords(t *testing.T) {
	rec := &captureLogger{}
	tr := &stubTransporter{kind: transport.KindHTTP, endpoint: "http://127.0.0.1:8000", op: "/api/ping"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}, AccessLog(WithLogger(rec)))
	h(ctx, "req")

	out := rec.text()
	if !strings.Contains(out, "/api/ping") || !strings.Contains(out, "http") {
		t.Fatalf("access log missing op/kind: %s", out)
	}
	if !strings.Contains(out, "INFO") || !strings.Contains(out, "cost=") {
		t.Fatalf("access log missing level/cost: %s", out)
	}
}

func TestAccessLogErrorWarns(t *testing.T) {
	rec := &captureLogger{}
	tr := &stubTransporter{kind: transport.KindGRPC, endpoint: "discovery:///svc", op: "/pkg.S/M"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		return nil, errTest
	}, AccessLog(WithLogger(rec)))
	h(ctx, "req")

	out := rec.text()
	if !strings.Contains(out, "WARN") || !strings.Contains(out, errTest.Error()) {
		t.Fatalf("error path should warn with err: %s", out)
	}
}

func TestMetadataPropagate(t *testing.T) {
	req := transport.MapHeader{"X-Tenant": {"acme"}}
	reply := transport.MapHeader{}
	tr := &stubTransporter{req: req, reply: reply}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, r any) (any, error) { return r, nil },
		MetadataPropagate("X-Tenant", "X-Missing"))
	h(ctx, "req")

	if got := reply.Get("X-Tenant"); got != "acme" {
		t.Fatalf("propagate failed: %q", got)
	}
	if _, exists := reply["X-Missing"]; exists {
		t.Fatal("missing key should not be written")
	}
}

func TestMetadataPropagateNoTransport(t *testing.T) {
	// 无 transport 上下文：应为 no-op 而非 panic
	h := chain.Finalize(func(ctx context.Context, r any) (any, error) { return r, nil },
		MetadataPropagate("X-Tenant"))
	if _, err := h(context.Background(), "req"); err != nil {
		t.Fatalf("no-op path errored: %v", err)
	}
}

// TestAccessLogSkipPaths 验证命中 skip 模式的 op 不记日志、下游照常执行。
func TestAccessLogSkipPaths(t *testing.T) {
	rec := &captureLogger{}
	ran := false
	tr := &stubTransporter{kind: transport.KindHTTP, op: "/metrics"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) {
		ran = true
		return "ok", nil
	}, AccessLog(WithLogger(rec), WithSkipPaths("/metrics", "/health*")))
	h(ctx, "req")

	if !ran {
		t.Error("downstream should still run on skipped op")
	}
	if len(rec.entries) != 0 {
		t.Errorf("skipped op should not log: %v", rec.entries)
	}

	// 未命中 skip 的 op 照常记录
	rec2 := &captureLogger{}
	tr2 := &stubTransporter{kind: transport.KindHTTP, op: "/api/orders"}
	h2 := chain.Finalize(func(ctx context.Context, req any) (any, error) { return "ok", nil },
		AccessLog(WithLogger(rec2), WithSkipPaths("/metrics")))
	h2(transport.NewServerContext(context.Background(), tr2), "req")
	if len(rec2.entries) != 1 {
		t.Errorf("non-skipped op should log once: %v", rec2.entries)
	}
}

// TestAccessLogRedactPrefixes 验证脱敏前缀：日志只含前缀+/***，token 不落日志。
func TestAccessLogRedactPrefixes(t *testing.T) {
	rec := &captureLogger{}
	tr := &stubTransporter{kind: transport.KindHTTP, op: "/api/v2/webhook/alert/tk-SECRET-123"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) { return "ok", nil },
		AccessLog(WithLogger(rec), WithRedactPathPrefixes("/api/v2/webhook/alert")))
	h(ctx, "req")

	out := rec.text()
	if !strings.Contains(out, "/api/v2/webhook/alert/***") {
		t.Fatalf("redacted op missing: %s", out)
	}
	if strings.Contains(out, "tk-SECRET-123") {
		t.Errorf("token leaked into log: %s", out)
	}
}

// TestAccessLogSkipUsesRawOp 验证 skip 判定用原始 op（不受脱敏影响）。
func TestAccessLogSkipUsesRawOp(t *testing.T) {
	rec := &captureLogger{}
	op := "/api/v2/webhook/alert/tk-1"
	tr := &stubTransporter{kind: transport.KindHTTP, op: op}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) { return "ok", nil },
		AccessLog(WithLogger(rec),
			WithSkipPaths(op), // 按原始值匹配
			WithRedactPathPrefixes("/api/v2/webhook/alert"), // 若误用脱敏值则匹配失败
		))
	h(ctx, "req")

	if len(rec.entries) != 0 {
		t.Errorf("skip should match raw op before redaction: %v", rec.entries)
	}
}

// TestAccessLogMessageAndFields 验证自定义消息与字段构建器（根包薄壳依赖）。
func TestAccessLogMessageAndFields(t *testing.T) {
	rec := &captureLogger{}
	tr := &stubTransporter{kind: transport.KindHTTP, op: "/api/ping"}
	ctx := transport.NewServerContext(context.Background(), tr)
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) { return "ok", nil },
		AccessLog(
			WithLogger(rec),
			WithLogMessage("request"),
			WithLogFields(func(_ context.Context, req any, rec AccessRecord) []any {
				return []any{"method", "GET", "path", rec.Operation, "status", 200}
			}),
		))
	h(ctx, "req")

	out := rec.text()
	if !strings.Contains(out, "INFO request") {
		t.Fatalf("custom message missing: %s", out)
	}
	for _, want := range []string{"method=GET", "path=/api/ping", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("custom field %s missing: %s", want, out)
		}
	}
	if strings.Contains(out, "cost=") {
		t.Errorf("default fields should be replaced: %s", out)
	}
}

// TestAccessLogNoTransport 验证无 transport 上下文时不 panic、kind/op 记 "-"。
func TestAccessLogNoTransport(t *testing.T) {
	rec := &captureLogger{}
	h := chain.Finalize(func(ctx context.Context, req any) (any, error) { return "ok", nil },
		AccessLog(WithLogger(rec)))
	if _, err := h(context.Background(), "req"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	out := rec.text()
	if !strings.Contains(out, "kind=-") || !strings.Contains(out, "op=-") {
		t.Fatalf("expected kind=-/op=- without transport: %s", out)
	}
}

// TestRedactPath 前缀命中脱敏语义（与根包 mw #12 行为一致，单实现双栈复用）。
func TestRedactPath(t *testing.T) {
	prefixes := []string{"/api/v2/webhook/alert", "/api/v2/task/trigger", "/hooks/slack"}

	cases := []struct {
		name string
		path string
		want string
	}{
		{"命中前缀-尾段脱敏", "/api/v2/webhook/alert/tk-secret-123", "/api/v2/webhook/alert/***"},
		{"命中前缀-多段全脱", "/api/v2/task/trigger/ops/9f8e7d", "/api/v2/task/trigger/***"},
		{"恰好等于前缀-无敏感尾段原样", "/hooks/slack", "/hooks/slack"},
		{"未命中原样", "/api/v1/orders", "/api/v1/orders"},
		{"前缀字节撞车-宁可多脱敏", "/api/v2/webhook/alert-x/ok", "/api/v2/webhook/alert/***"},
		{"空前缀不命中", "/anything/here", "/anything/here"},
	}
	for _, tc := range cases {
		if got := RedactPath(tc.path, prefixes); got != tc.want {
			t.Errorf("%s: RedactPath(%q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
	if got := RedactPath("/no/config", nil); got != "/no/config" {
		t.Errorf("无前缀配置应原样返回，got %q", got)
	}
}
