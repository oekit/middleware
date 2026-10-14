package hmw

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
)

// TestValidTraceID 回归：客户端 X-Trace-Id 曾无校验原样进响应头 + 全量
// Ctx 日志（超长垃圾/任意字符 = 撞 ID 伪造关联 + 日志洪水）。
func TestValidTraceID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"abc123def456", true},                     // 本包生成格式（12 位十六进制）
		{"0123456789abcdef0123456789abcdef", true}, // W3C trace-id 32 位十六进制
		{"trace-abc-123", true},                    // 连字符白名单内
		{"", false},                                // 空
		{strings.Repeat("a", 65), false},           // 超长
		{"<script>alert(1)</script>", false},       // 任意字符
		{"has space", false},
		{"中文id", false},
	}
	for _, c := range cases {
		if got := validTraceID(c.id); got != c.want {
			t.Errorf("validTraceID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

// TestMiddleware_InvalidClientTraceID_Regenerated 端到端回归：客户端传入非法
// X-Trace-Id 时，requestid 只对"缺失"头生成、非空垃圾值会原样写进响应头，
// bridge 曾直接放行——垃圾值残留响应头且该请求无 trace_id（链路断裂）。
// 钉住：非法入参必须替换为新生成的合法 ID，且响应头 / c.Set / ctx 三处一致。
func TestMiddleware_InvalidClientTraceID_Regenerated(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(Middleware()...)
	var inCtx string
	h.GET("/t", func(ctx context.Context, c *app.RequestContext) {
		inCtx = FromRequestContext(c)
		c.String(200, "ok")
	})

	for _, bad := range []string{"<garbage>", strings.Repeat("x", 200), "has space"} {
		w := ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Trace-Id", Value: bad})
		got := w.Header().Get("X-Trace-Id")
		if !validTraceID(got) {
			t.Errorf("inbound %q: response header %q should be a freshly generated valid ID", bad, got)
		}
		if inCtx != got {
			t.Errorf("inbound %q: ctx trace_id %q != response header %q", bad, inCtx, got)
		}
	}

	// 合法客户端 ID 原样透传
	w := ut.PerformRequest(h.Engine, "GET", "/t", nil, ut.Header{Key: "X-Trace-Id", Value: "trace-ok-123"})
	if got := w.Header().Get("X-Trace-Id"); got != "trace-ok-123" {
		t.Errorf("valid inbound should be preserved, got %q", got)
	}
}
