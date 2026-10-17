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
