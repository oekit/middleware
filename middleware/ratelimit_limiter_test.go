package mw

import (
	"context"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/yi-nology/ekit-concurrency/ratelimit"
	"golang.org/x/time/rate"
)

// --- L6: hasCodeField 字符串值内花括号/引号的鲁棒扫描 ---

// TestHasCodeField_StringWithBraces 回归测试（L6）：JSON 字符串值内部的
// { } " 不得干扰顶层 "code" 字段的层级判断 —— 此前的花括号深度计数
// 会被 `{"data":"{"}` 这类值骗过（漏判 → 重复包装，或误判嵌套）。
func TestHasCodeField_StringWithBraces(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		// 花括号出现在字符串值内，随后才是顶层 code
		{"brace in string value then code", `{"data":"{","code":1}`, true},
		{"close brace in string value then code", `{"data":"}","code":2}`, true},
		{"escaped json in string value", `{"data":"{\"code\":1}"}`, false},
		{"nested object with brace-string", `{"a":{"b":"{","code":2}}`, false},
		// 字符串值内的转义引号
		{"escaped quote inside string", `{"data":"a\"b{","code":3}`, true},
		{"escaped backslash then quote", `{"data":"x\\","code":4}`, true},
		// "code" 是字符串值而非键
		{"code as string value", `{"x":"code"}`, false},
		{"code as string value with colon after", `{"x":"code", "y":1}`, false},
		// 常规用例不回退
		{"top-level code", `{"code":0,"data":null}`, true},
		{"nested code only", `{"a":{"code":1}}`, false},
		{"empty object", `{}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCodeField([]byte(tt.body))
			if got != tt.want {
				t.Errorf("hasCodeField(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// TestResponseMiddleware_NoDoubleWrapWhenBracesInString 端到端验证：字符串值
// 含花括号且带顶层 code 的响应不会被重复包装（L6 回归）。
func TestResponseMiddleware_NoDoubleWrapWhenBracesInString(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Response.SetStatusCode(consts.StatusOK)
	c.Response.Header.Set("Content-Type", "application/json")
	c.Response.SetBody([]byte(`{"data":"{","code":1}`))

	handler := ResponseMiddleware()
	handler(context.Background(), c)

	assert.DeepEqual(t, `{"data":"{","code":1}`, string(c.Response.Body()))
}

// --- L7: RateLimitMiddlewareWithLimiter 显式生命周期 ---

// TestRateLimitMiddlewareWithLimiter_WorksWithCallerLimiter 验证调用方自建的
// KeyedLimiter 被中间件使用，且调用方可 Close 它停止清理 goroutine（L7）。
func TestRateLimitMiddlewareWithLimiter_WorksWithCallerLimiter(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(100, 1)
	}, 10*time.Minute)
	defer keyed.Close() // 调用方负责生命周期

	h := RateLimitMiddlewareWithLimiter(keyed)

	c := app.NewContext(8)
	c.Request.SetRequestURI("/test")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	assert.DeepEqual(t, 1, keyed.Len()) // 中间件确实在使用这个 limiter
}

// TestRateLimitMiddlewareWithLimiter_BlocksOverLimit 验证限流语义一致。
func TestRateLimitMiddlewareWithLimiter_BlocksOverLimit(t *testing.T) {
	keyed := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(rate.Limit(1), 1)
	}, time.Minute)
	defer keyed.Close()

	h := RateLimitMiddlewareWithLimiter(keyed, WithRateLimitKeyFunc(func(*app.RequestContext) string {
		return "client-a"
	}))

	for i := 0; i < 2; i++ {
		c := app.NewContext(8)
		c.Request.SetRequestURI("/test")
		h(context.Background(), c)
		if i == 0 {
			assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
		} else {
			assert.DeepEqual(t, consts.StatusTooManyRequests, c.Response.StatusCode())
		}
	}
}

// TestRateLimitMiddlewareWithLimiter_NilPanics 验证 nil limiter 在构造期 panic。
func TestRateLimitMiddlewareWithLimiter_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil keyed limiter")
		}
	}()
	_ = RateLimitMiddlewareWithLimiter(nil)
}
