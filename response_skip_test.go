package mw

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

// assertNoWrap 断言响应体未被统一包壳（无顶层 "code" 字段）且含裸载荷键。
func assertNoWrap(t *testing.T, body []byte, wantKey string) {
	t.Helper()
	if bytes.Contains(body, []byte(`"code"`)) {
		t.Errorf("body should not be wrapped (has \"code\"), got %s", body)
	}
	if !bytes.Contains(body, []byte(wantKey)) {
		t.Errorf("body should contain %q, got %s", wantKey, body)
	}
}

// assertWrapped 断言响应体已被统一包壳（含顶层 "code"）。
func assertWrapped(t *testing.T, body []byte) {
	t.Helper()
	if !bytes.Contains(body, []byte(`"code"`)) {
		t.Errorf("body should be wrapped (has \"code\"), got %s", body)
	}
}

// TestSkipResponseWrap Escape hatch：置位后 ResponseMiddleware 不得包壳。
func TestSkipResponseWrap(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware())
	h.GET("/std", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"plain": true})
	})
	h.GET("/esc", func(ctx context.Context, c *app.RequestContext) {
		SkipResponseWrap(c)
		c.JSON(200, map[string]any{"escaped": true})
	})

	r1 := ut.PerformRequest(h, http.MethodGet, "/std", nil).Result()
	t.Logf("std body: %s", string(r1.Body()))
	r2 := ut.PerformRequest(h, http.MethodGet, "/esc", nil).Result()
	t.Logf("esc body: %s", string(r2.Body()))
	assert.DeepEqual(t, true, len(r2.Body()) > 0 && string(r2.Body())[0] == '{' && !bytes.Contains(r2.Body(), []byte(`"code"`)))
}

// TestResponseMiddleware_SkipPaths 声明式跳过：精确匹配路径整请求不包壳，
// 其余路径正常包壳。
func TestResponseMiddleware_SkipPaths(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(WithSkipPaths("/token", "/jwks.json")))
	h.GET("/token", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"access_token": "tok"})
	})
	h.GET("/jwks.json", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"keys": []any{}})
	})
	h.GET("/api/data", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"name": "test"})
	})

	r := ut.PerformRequest(h, http.MethodGet, "/token", nil).Result()
	assertNoWrap(t, r.Body(), `"access_token"`)

	r = ut.PerformRequest(h, http.MethodGet, "/jwks.json", nil).Result()
	assertNoWrap(t, r.Body(), `"keys"`)

	r = ut.PerformRequest(h, http.MethodGet, "/api/data", nil).Result()
	assertWrapped(t, r.Body())
}

// TestResponseMiddleware_SkipPrefixes 声明式跳过：前缀匹配整请求不包壳。
func TestResponseMiddleware_SkipPrefixes(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(WithSkipPrefixes("/.well-known/", "/mcp")))
	h.GET("/.well-known/openid-configuration", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"issuer": "https://ex"})
	})
	h.GET("/mcp/tools", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"tools": []any{}})
	})
	h.GET("/api/mcp", func(ctx context.Context, c *app.RequestContext) {
		// 不以 /mcp 开头 → 仍包壳
		c.JSON(200, map[string]any{"name": "not-skipped"})
	})

	r := ut.PerformRequest(h, http.MethodGet, "/.well-known/openid-configuration", nil).Result()
	assertNoWrap(t, r.Body(), `"issuer"`)

	r = ut.PerformRequest(h, http.MethodGet, "/mcp/tools", nil).Result()
	assertNoWrap(t, r.Body(), `"tools"`)

	r = ut.PerformRequest(h, http.MethodGet, "/api/mcp", nil).Result()
	assertWrapped(t, r.Body())
}

// TestResponseMiddleware_SkipPathsAndPrefixesCombined 两种声明式规则叠加生效。
func TestResponseMiddleware_SkipPathsAndPrefixesCombined(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(
		WithSkipPaths("/token"),
		WithSkipPrefixes("/.well-known/"),
	))
	h.GET("/token", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"access_token": "tok"})
	})
	h.GET("/.well-known/jwks", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"keys": []any{}})
	})
	h.GET("/api/x", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"name": "test"})
	})

	for path, want := range map[string]bool{
		"/token":            false, // 跳过
		"/.well-known/jwks": false, // 跳过
		"/api/x":            true,  // 包壳
	} {
		r := ut.PerformRequest(h, http.MethodGet, path, nil).Result()
		wrapped := bytes.Contains(r.Body(), []byte(`"code"`))
		if wrapped != want {
			t.Errorf("GET %s wrapped = %v, want %v (body=%s)", path, wrapped, want, r.Body())
		}
	}
}

// TestSkipResponseWrap_HeaderCleanup 包装豁免后兼容响应头必须被删除，
// 外部观察者在响应上看不到内部标记头。
func TestSkipResponseWrap_HeaderCleanup(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware())
	h.GET("/esc", func(ctx context.Context, c *app.RequestContext) {
		SkipResponseWrap(c)
		c.JSON(200, map[string]any{"escaped": true})
	})

	r := ut.PerformRequest(h, http.MethodGet, "/esc", nil).Result()
	assertNoWrap(t, r.Body(), `"escaped"`)
	for _, name := range []string{skipResponseWrapHeader, legacySkipResponseWrapHeader} {
		if got := r.Header.Get(name); got != "" {
			t.Errorf("internal marker header %s leaked to response: %q", name, got)
		}
	}
}

// TestSkipResponseWrap_LegacyHeader 旧头名 X-Zeus-No-Wrap 一个版本内仍被识别
// （deprecated 兼容层），命中后同样跳过包壳并清理头。
func TestSkipResponseWrap_LegacyHeader(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware())
	h.GET("/legacy", func(ctx context.Context, c *app.RequestContext) {
		// 模拟旧客户端/handler 直接写旧头（不调 SkipResponseWrap）
		c.Response.Header.Set(legacySkipResponseWrapHeader, "1")
		c.JSON(200, map[string]any{"legacy": true})
	})

	r := ut.PerformRequest(h, http.MethodGet, "/legacy", nil).Result()
	assertNoWrap(t, r.Body(), `"legacy"`)
	if got := r.Header.Get(legacySkipResponseWrapHeader); got != "" {
		t.Errorf("legacy marker header should be cleaned, got %q", got)
	}
}

// TestSkipResponseWrap_NewHeaderOnly 次级机制：handler 只写新兼容头
// X-Oekit-No-Wrap（不调 SkipResponseWrap / 不置 kv）时同样跳过包壳并清理头。
func TestSkipResponseWrap_NewHeaderOnly(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware())
	h.GET("/hdr", func(ctx context.Context, c *app.RequestContext) {
		c.Response.Header.Set(skipResponseWrapHeader, "1")
		c.JSON(200, map[string]any{"hdr": true})
	})

	r := ut.PerformRequest(h, http.MethodGet, "/hdr", nil).Result()
	assertNoWrap(t, r.Body(), `"hdr"`)
	if got := r.Header.Get(skipResponseWrapHeader); got != "" {
		t.Errorf("new marker header should be cleaned, got %q", got)
	}
}

// TestResponseMiddleware_Skip_KeepsHandlerBody 跳过路径下 handler 响应体
// 一字不改（整请求不包装，而非包装后再还原）。
func TestResponseMiddleware_Skip_KeepsHandlerBody(t *testing.T) {
	raw := `{"raw":[1,2,3],"nested":{"k":"v"}}`
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(WithSkipPrefixes("/raw")))
	h.GET("/raw/echo", func(ctx context.Context, c *app.RequestContext) {
		c.SetStatusCode(200)
		c.Header("Content-Type", "application/json")
		c.Response.SetBody([]byte(raw))
	})

	r := ut.PerformRequest(h, http.MethodGet, "/raw/echo", nil).Result()
	if string(r.Body()) != raw {
		t.Errorf("skipped request body mutated:\n got %s\nwant %s", r.Body(), raw)
	}
}

// TestResponseSkipConfig_EmptyPrefixMatchesAll 回归测试（#126）：空前缀匹配
// **一切**路径——#100 之前的历史行为（strings.HasPrefix(path, "") 恒真），
// #100 曾在同一提交里静默翻转成「匹配零」且注释仍宣称「维持历史行为」。
// 单元级表驱动钉住：任意路径（含根、深层嵌套、畸形串）全部命中，且空串
// 不进入段边界分支（那里 p[len(p)-1] 对空串会越界 panic）。
func TestResponseSkipConfig_EmptyPrefixMatchesAll(t *testing.T) {
	cfg := newResponseOptions(WithSkipPrefixes(""))
	for _, path := range []string{"/", "/a", "/a/b/c", "/mcp-v2/data", "relative", ""} {
		if !cfg.skip(path) {
			t.Fatalf("空前缀必须匹配一切路径（历史行为，#126 定版）: path=%q 未命中", path)
		}
	}

	// 与普通前缀混排：空前缀依旧匹配一切。
	mixed := newResponseOptions(WithSkipPrefixes("/mcp", ""))
	for _, path := range []string{"/api/x", "/mcp/tools"} {
		if !mixed.skip(path) {
			t.Fatalf("空前缀混排时仍必须匹配一切路径: path=%q 未命中", path)
		}
	}

	// 非空前缀的 #100 段边界语义保持不变（回归互钉，防 restore 时连带破坏）。
	boundary := newResponseOptions(WithSkipPrefixes("/mcp"))
	if !boundary.skip("/mcp") || !boundary.skip("/mcp/tools") {
		t.Fatal("/mcp 段边界命中语义被破坏（#100）")
	}
	if boundary.skip("/mcp-v2/data") || boundary.skip("/api/mcp") {
		t.Fatal("/mcp 段边界不命中语义被破坏（#100）")
	}
}

// TestResponseMiddleware_SkipPrefixesEmptyMatchesAll 端到端回归（#126）：
// WithSkipPrefixes("") ⇒ 所有响应免包壳（历史行为）。以变量传参且配置缺失
// 时豁免显形（全站裸 JSON），而不是被静默收回——豁免方向翻转属契约变更，
// #100 无权在同一次段边界修复里顺手翻转。
func TestResponseMiddleware_SkipPrefixesEmptyMatchesAll(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(WithSkipPrefixes("")))
	handler := func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"biz": "payload"})
	}
	h.GET("/anything", handler)
	h.GET("/nested/deep/path", handler)

	for _, path := range []string{"/anything", "/nested/deep/path"} {
		r := ut.PerformRequest(h, http.MethodGet, path, nil).Result()
		assertNoWrap(t, r.Body(), `"biz"`)
	}
}

// TestResponseMiddleware_SkipPrefixesEmptyWarns 构造期空前缀 WARN 可观测
// （#126）：「全站豁免」级高影响配置不允许无信号——对齐 #100 修复批评的
// 「无日志、无告警」缺口；非空前缀不产生告警（避免热路径/正常路径噪音）。
func TestResponseMiddleware_SkipPrefixesEmptyWarns(t *testing.T) {
	cap := &accessLogCapture{}
	old := responseLog
	responseLog = cap
	t.Cleanup(func() { responseLog = old })

	_ = newResponseOptions(WithSkipPrefixes("", "/mcp"))
	if out := cap.text(); !strings.Contains(out, "WARN") || !strings.Contains(out, "空前缀") {
		t.Fatalf("空前缀必须打 WARN（全站豁免高影响配置），got: %q", out)
	}

	cap.entries = nil
	_ = newResponseOptions(WithSkipPrefixes("/mcp", "/.well-known/"))
	if out := cap.text(); out != "" {
		t.Fatalf("非空前缀不得产生 WARN，got: %q", out)
	}
}

// TestResponseMiddleware_SkipPrefixesSegmentBoundary 回归测试（#100）：
// 前缀命中必须是**段边界**的——裸 strings.HasPrefix 会把 "/mcp" 连带到
// "/mcp-v2/data" 等同字符开头的无关路由，命中路由静默失去统一包壳，
// 按信封 {code,data,message,trace_id} 解码的消费方直接解析失败且无信号。
//
// 矩阵边界："/mcp" 命中 "/mcp"（等于）与 "/mcp/tools"（新段），不命中
// "/mcp-v2/data"；尾斜杠前缀 "/.well-known/" 的子路径照常命中。
func TestResponseMiddleware_SkipPrefixesSegmentBoundary(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware(WithSkipPrefixes("/.well-known/", "/mcp")))
	handler := func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"biz": "payload"})
	}
	h.GET("/mcp", handler)
	h.GET("/mcp/tools", handler)
	h.GET("/mcp-v2/data", handler)
	h.GET("/.well-known/openid-configuration", handler)

	cases := []struct {
		path         string
		wantSkipped  bool
		wantContains string
	}{
		{"/mcp", true, `"biz"`},                              // 前缀等于完整路径
		{"/mcp/tools", true, `"biz"`},                        // 前缀后紧跟新段
		{"/mcp-v2/data", false, `"code"`},                    // 同字符开头、无段边界 → 不豁免（#100 缺陷方向）
		{"/.well-known/openid-configuration", true, `"biz"`}, // 尾斜杠前缀子路径照常命中
	}
	for _, tc := range cases {
		r := ut.PerformRequest(h, http.MethodGet, tc.path, nil).Result()
		body := r.Body()
		if bytes.Contains(body, []byte(`"code"`)) == tc.wantSkipped {
			t.Errorf("GET %s: wrapped=%v, want skipped=%v (body=%s)", tc.path, !tc.wantSkipped, tc.wantSkipped, body)
		}
		if !bytes.Contains(body, []byte(tc.wantContains)) {
			t.Errorf("GET %s: body should contain %q, got %s", tc.path, tc.wantContains, body)
		}
	}
}
