package mw

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/oekit/core/transport"
)

func newTransporterRequestContext(t *testing.T, host, path string) *app.RequestContext {
	t.Helper()
	c := app.NewContext(8)
	c.Request.Reset()
	c.Request.SetRequestURI("http://" + host + path)
	return c
}

// TestHertzTransporter_Basics 与 hertz/transportx 的 TestNewServerTransport +
// TestRequestHeaderRoundTrip 同构：Kind/Endpoint/Operation 与请求头读写映射。
func TestHertzTransporter_Basics(t *testing.T) {
	c := newTransporterRequestContext(t, "svc.local:8080", "/api/v1/ping")
	c.Request.Header.Set("X-Trace-ID", "abc")
	ctx := newHertzServerContext(context.Background(), c)
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		t.Fatal("transporter not injected")
	}

	if tr.Kind() != transport.KindHTTP {
		t.Fatalf("kind = %s, want http", tr.Kind())
	}
	if tr.Endpoint() != "svc.local:8080" {
		t.Fatalf("endpoint = %q, want svc.local:8080", tr.Endpoint())
	}
	if tr.Operation() != "/api/v1/ping" {
		t.Fatalf("operation = %q, want /api/v1/ping", tr.Operation())
	}

	h := tr.RequestHeader()
	h.Add("X-Multi", "a")
	h.Add("X-Multi", "b")
	if vs := h.Values("X-Multi"); len(vs) != 2 || vs[0] != "a" || vs[1] != "b" {
		t.Fatalf("request header Add must append, got %v", vs)
	}
}

// TestHertzReplyHeaderAdd_Appends 回归测试（#99）：reply header 的 Add 语义
// 是**追加**而非覆盖——此前 hertzReplyHeader.Add 误用 h.Set（覆盖），同 key
// 多次 Add 只剩最后一个值，Vary/Set-Cookie 类多值响应头被静默丢值。
//
// 本用例与 hertz 仓 transportx.TestReplyHeaderAdd_Appends 逐条对齐
// （两仓 adapter 行为一致；不能直接 import hertz/transportx 对照——
// hertz 仓 chainmw 桥接 import 本仓，反向依赖成环，见 transporter.go 头注）。
func TestHertzReplyHeaderAdd_Appends(t *testing.T) {
	c := newTransporterRequestContext(t, "h", "/")
	ctx := newHertzServerContext(context.Background(), c)
	tr, _ := transport.FromServerContext(ctx)
	reply := tr.ReplyHeader()

	reply.Add("Vary", "Accept-Encoding")
	reply.Add("Vary", "Accept")
	if vs := reply.Values("Vary"); len(vs) != 2 || vs[0] != "Accept-Encoding" || vs[1] != "Accept" {
		t.Fatalf("Add must append, got %v", vs)
	}
	if got := string(c.Response.Header.Peek("Vary")); got != "Accept-Encoding" {
		t.Fatalf("response header Peek = %q, want Accept-Encoding (first appended value)", got)
	}

	// Set 仍是单值（覆盖）语义——与 Add 区分开。
	reply.Set("X-Single", "c")
	if vs := reply.Values("X-Single"); len(vs) != 1 || vs[0] != "c" {
		t.Fatalf("Set must overwrite, got %v", vs)
	}
}

// TestHertzReplyHeaderAdd_ViaAccessLogTransporter 复现 #99 的端到端路径：
// AccessLogMiddleware 的 Transporter 注入请求 ctx 后，handler 经
// transport.FromServerContext(ctx).ReplyHeader().Add(...) 写同名多值响应头，
// 两个值都必须出现在最终响应上（此前后写的顶掉先写的）。
func TestHertzReplyHeaderAdd_ViaAccessLogTransporter(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware())
	h.GET("/vary", func(ctx context.Context, c *app.RequestContext) {
		tr, ok := transport.FromServerContext(ctx)
		if !ok {
			t.Errorf("transporter not injected by AccessLogMiddleware")
			return
		}
		reply := tr.ReplyHeader()
		reply.Add("Vary", "Accept-Encoding")
		reply.Add("Vary", "Accept")
		c.SetStatusCode(http.StatusOK)
	})

	r := ut.PerformRequest(h, http.MethodGet, "/vary", nil).Result()
	var vary []string
	for _, v := range r.Header.PeekAll("Vary") {
		vary = append(vary, string(v))
	}
	if len(vary) != 2 {
		t.Fatalf("Vary values = %v, want 2 values (Add must append, not overwrite)", vary)
	}
	joined := strings.Join(vary, ",")
	if !strings.Contains(joined, "Accept-Encoding") || !strings.Contains(joined, "Accept") {
		t.Fatalf("Vary values = %v, want both Accept-Encoding and Accept", vary)
	}
}
