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

// TestHertzTransporter_ValuesMatchesGetCaseFold 钉子测试（#163/#177/#183）：
// Get 与 Values 键匹配同口径——**大小写不敏感**。历史缺陷形态：hertz
// VisitAll 产出 MIME canonical 键（如 "X-Trace-Id"），Get 大小写不敏感命中
// 而 Values 用原文相等比较时，调用方传 "x-trace-id" 变体 Get 命中、Values
// 返回 nil——同一适配器两套键口径，「Get 命中而 Values 落空」。
//
// 该反例必须不可复现：适配层已下沉 core/transport/hertzbridge 单源（#180），
// middleware/hertz 两仓 EqualFold 口径随单源固化，不再各自漂移。
func TestHertzTransporter_ValuesMatchesGetCaseFold(t *testing.T) {
	c := newTransporterRequestContext(t, "h", "/")
	// 小写变体写入：hertz 内部规范化为 canonical 形态存储。
	c.Request.Header.Set("x-trace-id", "abc")
	c.Request.Header.Set("X-Multi", "a")
	c.Request.Header.Add("X-Multi", "b")

	ctx := newHertzServerContext(context.Background(), c)
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		t.Fatal("transporter not injected")
	}
	h := tr.RequestHeader()

	// Get 命中（大小写不敏感，hertz 既有口径）
	if got := h.Get("X-TRACE-ID"); got != "abc" {
		t.Fatalf(`Get("X-TRACE-ID") = %q, want abc`, got)
	}
	// Values 必须与 Get 同口径命中（原缺陷：原文相等比较时落空）
	for _, key := range []string{"x-trace-id", "X-Trace-Id", "X-TRACE-ID"} {
		vs := h.Values(key)
		if len(vs) != 1 || vs[0] != "abc" {
			t.Fatalf("Values(%q) = %v, want [abc]——Get 命中而 Values 落空的反例不得复现（#163/#177）", key, vs)
		}
	}
	if vs := h.Values("X-MULTI"); len(vs) != 2 || vs[0] != "a" || vs[1] != "b" {
		t.Fatalf("Values 变体键多值回读 = %v, want [a b]", vs)
	}

	// Keys() 产出 canonical 键；对其任意大小写变体做 Values 回读都不得落空
	// （键口径唯一的组合形态钉住）。
	for _, k := range h.Keys() {
		if len(h.Values(k)) == 0 || len(h.Values(strings.ToLower(k))) == 0 {
			t.Fatalf("Keys()=%q 中的键 %q：原文或小写变体 Values 落空（#163 反例）", h.Keys(), k)
		}
	}
}

// TestHertzReplyHeader_ValuesMatchesGetCaseFold 钉子测试（#163/#177/#183，
// replyHeader 同病同修——hertzbridge 单源一份口径两处生效）。
func TestHertzReplyHeader_ValuesMatchesGetCaseFold(t *testing.T) {
	c := newTransporterRequestContext(t, "h", "/")
	ctx := newHertzServerContext(context.Background(), c)
	tr, _ := transport.FromServerContext(ctx)
	reply := tr.ReplyHeader()

	reply.Add("Vary", "Accept-Encoding")
	if got := reply.Get("vary"); got != "Accept-Encoding" {
		t.Fatalf(`Get("vary") = %q, want Accept-Encoding`, got)
	}
	for _, key := range []string{"vary", "VARY", "Vary"} {
		vs := reply.Values(key)
		if len(vs) != 1 || vs[0] != "Accept-Encoding" {
			t.Fatalf("reply.Values(%q) = %v, want [Accept-Encoding]——Get 命中而 Values 落空的反例不得复现（#163/#177）", key, vs)
		}
	}
}

// TestHertzReplyHeaderAdd_Appends 回归测试（#99）：reply header 的 Add 语义
// 是**追加**而非覆盖——此前 hertzReplyHeader.Add 误用 h.Set（覆盖），同 key
// 多次 Add 只剩最后一个值，Vary/Set-Cookie 类多值响应头被静默丢值。
//
// 适配层已下沉 core/transport/hertzbridge 单源（#180），本测试与 hertz 仓
// transportx 的同款用例消费的是同一份实现，口径天然一致（不再靠注释约束）。
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
	vary := make([]string, 0, 2)
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
