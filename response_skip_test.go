package mw

import (
	"bytes"
	"context"
	"net/http"
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
