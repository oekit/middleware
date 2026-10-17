package contrib

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/hertz-contrib/keyauth"
)

const testAPIKeyValid = "test-api-key-valid-12345"

// TestKeyAuth_ValidKey 验证有效 API key 通过 + validator 被调。
func TestKeyAuth_ValidKey(t *testing.T) {
	called := false
	h := KeyAuth(
		keyauth.WithKeyLookUp("header:X-API-Key", ""),
		keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, key string) (bool, error) {
			called = true
			return key == testAPIKeyValid, nil
		}),
	)

	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/api/data")
	c.Request.Header.Set("X-API-Key", testAPIKeyValid)

	h(context.Background(), c)

	if !called {
		t.Error("expected validator to be called")
	}
	// 通过(响应 200 默认,因为 c.HandlerChain 空)
}

// TestKeyAuth_FilterSkip 验证 Filter 返回 true 跳过验证。
func TestKeyAuth_FilterSkip(t *testing.T) {
	called := false
	h := KeyAuth(
		keyauth.WithKeyLookUp("header:X-API-Key", ""),
		keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, key string) (bool, error) {
			called = true
			return true, nil
		}),
		keyauth.WithFilter(func(_ context.Context, c *app.RequestContext) bool {
			return string(c.Path()) == "/healthz"
		}),
	)

	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/healthz")
	c.Request.Header.Set("X-API-Key", "wrong-key-but-filter-skip")

	h(context.Background(), c)
	if called {
		t.Error("validator should be skipped when filter returns true")
	}
}

// TestKeyAuth_QueryLookup 验证 query 参数提取。
func TestKeyAuth_QueryLookup(t *testing.T) {
	called := false
	h := KeyAuth(
		keyauth.WithKeyLookUp("query:api_key", ""),
		keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, key string) (bool, error) {
			called = true
			return key == testAPIKeyValid, nil
		}),
	)

	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/api/data")
	c.Request.SetQueryString("api_key=" + testAPIKeyValid)

	h(context.Background(), c)
	if !called {
		t.Error("expected query-based validator to be called")
	}
}

// TestKeyAuth_DefaultBehavior 验证 ekit KeyAuth 透传 hertz-contrib/keyauth。
func TestKeyAuth_DefaultBehavior(t *testing.T) {
	// 不传 option:走 keyauth.NewOptions() default(validator 返 true,
	// authScheme="Bearer",keyLookup="header:Authorization")
	h := KeyAuth()
	if h == nil {
		t.Fatal("KeyAuth() should return non-nil middleware")
	}
}

// TestKeyAuth_RejectPathNoPanic 行为级(真实 TCP):validator 返回 (false, nil)
// 的拒绝路径必须稳定 401,不得 panic。
// 钉住 2026-09-05 修复的回归:上游默认 errorHandler 对 nil err 调 err.Error()
// → nil deref(实测:bad-key 请求整个连接崩掉)。
func TestKeyAuth_RejectPathNoPanic(t *testing.T) {
	base := spinRealServerMw(t, func(h *server.Hertz) {
		h.Use(KeyAuth(
			keyauth.WithKeyLookUp("header:X-API-Key", ""),
			keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, key string) (bool, error) {
				return key == "good", nil
			}),
		))
		h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
			c.JSON(200, map[string]string{"pong": "ok"})
		})
	})

	// 坏 key → 401(修复前:panic)
	resp, err := httpGetWithHeader(base+"/ping", "X-API-Key", "bad")
	if err != nil {
		t.Fatalf("GET with bad key: %v", err)
	}
	if resp.code != 401 {
		t.Errorf("bad key: got %d (want 401)", resp.code)
	}

	// 无 key → 400(上游官方语义:ErrMissingOrMalformedAPIKey)
	resp2, err := httpGetWithHeader(base+"/ping", "", "")
	if err != nil {
		t.Fatalf("GET without key: %v", err)
	}
	if resp2.code != 400 {
		t.Errorf("missing key: got %d (want 400)", resp2.code)
	}

	// 好 key → 200
	resp3, err := httpGetWithHeader(base+"/ping", "X-API-Key", "good")
	if err != nil {
		t.Fatalf("GET with good key: %v", err)
	}
	if resp3.code != 200 {
		t.Errorf("good key: got %d (want 200)", resp3.code)
	}
}

// TestKeyAuth_UserErrorHandlerOverrides 验证业务传 WithErrorHandler 覆盖 ekit 默认。
func TestKeyAuth_UserErrorHandlerOverrides(t *testing.T) {
	var customCalled atomic.Bool
	base := spinRealServerMw(t, func(h *server.Hertz) {
		h.Use(KeyAuth(
			keyauth.WithKeyLookUp("header:X-API-Key", ""),
			keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, _ string) (bool, error) {
				return false, nil
			}),
			keyauth.WithErrorHandler(func(_ context.Context, c *app.RequestContext, _ error) {
				customCalled.Store(true)
				c.AbortWithStatus(403)
			}),
		))
		h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
			c.JSON(200, map[string]string{"pong": "ok"})
		})
	})

	resp, err := httpGetWithHeader(base+"/ping", "X-API-Key", "whatever")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if resp.code != 403 {
		t.Errorf("custom errorHandler: got %d (want 403)", resp.code)
	}
	if !customCalled.Load() {
		t.Error("user WithErrorHandler should have been called, ekit default must not shadow it")
	}
}

type keyAuthResp struct {
	code int
	body string
}

func httpGetWithHeader(url, key, val string) (keyAuthResp, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if key != "" {
		req.Header.Set(key, val)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return keyAuthResp{}, err
	}
	defer func() { _ = r.Body.Close() }()
	b, _ := io.ReadAll(r.Body)
	return keyAuthResp{code: r.StatusCode, body: string(b)}, nil
}

// TestKeyAuth_NoValidator_RejectsAll 回归：上游 keyauth.NewOptions 的默认
// validator 是 return true——裸调用 KeyAuth() 曾对任意 key 全部放行
// （接口实际无鉴权）。钉住：缺省 reject-all，任何 key 都 401。
func TestKeyAuth_NoValidator_RejectsAll(t *testing.T) {
	base := spinRealServerMw(t, func(h *server.Hertz) {
		h.Use(KeyAuth(keyauth.WithKeyLookUp("header:X-API-Key", "")))
		h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
			c.JSON(200, map[string]string{"ok": "true"})
		})
	})

	// 缺 key → 上游 ErrMissingOrMalformedAPIKey → ekit errorHandler 映射 400
	resp, err := http.Get(base + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bare KeyAuth missing key: got %d (want 400)", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", base+"/ping", nil)
	req.Header.Set("X-API-Key", "anything")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("bare KeyAuth with arbitrary key: got %d (want 401)", resp2.StatusCode)
	}
}
