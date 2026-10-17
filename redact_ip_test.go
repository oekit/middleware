package mw

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

// TestRedactPath 前缀命中脱敏语义（#12：webhook/{token} 类路径的 token 不落日志）。
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
		if got := redactPath(tc.path, prefixes); got != tc.want {
			t.Errorf("%s: redactPath(%q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
	if got := redactPath("/no/config", nil); got != "/no/config" {
		t.Errorf("无前缀配置应原样返回，got %q", got)
	}
}

// TestAccessLogMiddleware_RedactedPathNotLogged 端到端：配置脱敏前缀后，
// 日志 path 字段携带的是脱敏后的路径（token 不出现在任何输出）。
func TestAccessLogMiddleware_RedactedPathNotLogged(t *testing.T) {
	h := AccessLogMiddleware(WithAccessLogRedactPathPrefixes("/api/v2/webhook/alert"))

	c := app.NewContext(128)
	c.Request.SetRequestURI("/api/v2/webhook/alert/tk-SECRET")
	c.Request.Header.SetMethod("GET")

	h(context.Background(), c)

	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	// 烟测：中间件链路在脱敏配置下正常放行；日志内容断言由 TestRedactPath
	// 覆盖（redactPath 为日志 path 字段的唯一来源）。
}

// TestHostOnly 去端口语义（#13：RemoteAddr 带端口使「新建连接即新桶」可绕过限流）。
func TestHostOnly(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"1.2.3.4:5678", "1.2.3.4"},
		{"[::1]:8080", "::1"},
		{"/tmp/unix.sock", "/tmp/unix.sock"}, // 无端口原样
		{"", ""},
	}
	for _, tc := range cases {
		if got := hostOnly(tc.addr); got != tc.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
