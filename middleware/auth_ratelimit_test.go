package mw

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"golang.org/x/time/rate"
)

// TestRateLimitMiddleware_AllowsUnderLimit 验证限流中间件在限额内放行。
func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	h := RateLimitMiddleware(WithRateLimit(rate.Limit(100), 10))

	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.SetMethod("GET")

	h(context.Background(), c)

	// 放行：handler 链无后续，状态码默认 200
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestRateLimitMiddleware_BlocksOverLimit 验证超限返回 429。
// 通过极低限流 + 大量并发触发。
func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	// Rate=1, Burst=1，只能允许 1 个请求
	h := RateLimitMiddleware(WithRateLimit(rate.Limit(1), 1))

	blocked := 0
	allowed := 0
	for i := 0; i < 5; i++ {
		c := app.NewContext(128)
		c.Request.SetRequestURI("/test")
		c.Request.Header.SetMethod("GET")
		h(context.Background(), c)
		if c.Response.StatusCode() == consts.StatusTooManyRequests {
			blocked++
		} else {
			allowed++
		}
	}
	if blocked == 0 {
		t.Error("expected at least one request to be blocked (429)")
	}
	if allowed == 0 {
		t.Error("expected at least one request to be allowed")
	}
}

// TestBearerTokenAuth_NoToken 验证 Token 为空时直接放行。
func TestBearerTokenAuth_NoToken(t *testing.T) {
	h := BearerTokenAuth() // 无 token → 认证关闭
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_ValidToken 验证正确 token 放行。
func TestBearerTokenAuth_ValidToken(t *testing.T) {
	h := BearerTokenAuth(WithBearerToken("secret"))
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer secret")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_InvalidToken 验证错误 token 返回 401。
func TestBearerTokenAuth_InvalidToken(t *testing.T) {
	h := BearerTokenAuth(WithBearerToken("secret"))
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer wrong")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusUnauthorized, c.Response.StatusCode())
}

// TestBearerTokenAuth_SkipPath 验证跳过路径放行。
func TestBearerTokenAuth_SkipPath(t *testing.T) {
	h := BearerTokenAuth(
		WithBearerToken("secret"),
		WithAuthSkipPaths("/health"),
	)
	c := app.NewContext(128)
	c.Request.SetRequestURI("/health")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}
