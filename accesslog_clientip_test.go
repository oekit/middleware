package mw

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

// sinkCapture 起一个带 sink 的最小引擎，返回捕获记录的指针与请求函数。
func sinkCapture(t *testing.T, opts ...AccessLogOption) (*AccessRecord, func(headers ...ut.Header)) {
	t.Helper()
	var rec AccessRecord
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(AccessLogMiddleware(append([]AccessLogOption{WithAccessLogSink(
		func(_ context.Context, _ *app.RequestContext, r AccessRecord) error {
			rec = r
			return nil
		})}, opts...)...))
	h.GET("/ip", func(ctx context.Context, c *app.RequestContext) { c.String(http.StatusOK, "ok") })
	return &rec, func(headers ...ut.Header) {
		rec = AccessRecord{}
		ut.PerformRequest(h, http.MethodGet, "/ip", nil, headers...)
	}
}

// TestAccessLog_ClientIP_DefaultFailClosed 钉住 #83：默认口径不采信任意来源的
// XFF——直连伪造 XFF 不得毒化 ClientIP（对端地址口径，与 ratelimit 一致）。
func TestAccessLog_ClientIP_DefaultFailClosed(t *testing.T) {
	rec, do := sinkCapture(t)
	do(ut.Header{Key: "X-Forwarded-For", Value: "1.2.3.4, 5.6.7.8"})
	if rec.ClientIP == "1.2.3.4" || rec.ClientIP == "5.6.7.8" {
		t.Fatalf("伪造 XFF 不得进入 ClientIP, got %q", rec.ClientIP)
	}
	if rec.ClientIP == "" {
		t.Fatal("ClientIP 不应为空（至少是对端地址）")
	}
}

// TestAccessLog_ClientIP_InjectTrustedProxies 注入缝：可信网段解析真实客户端 IP。
func TestAccessLog_ClientIP_InjectTrustedProxies(t *testing.T) {
	rec, do := sinkCapture(t, WithAccessLogClientIP(func(remote, xff string, _ []string) string {
		// 模拟「对端是可信网关 → 取 XFF 第一个非可信」的最小解析
		if xff != "" {
			return xff
		}
		return remote
	}))
	do(ut.Header{Key: "X-Forwarded-For", Value: "203.0.113.7"})
	if rec.ClientIP != "203.0.113.7" {
		t.Fatalf("注入缝应按可信网段解析, got %q", rec.ClientIP)
	}
}

// TestAccessLog_ClientIP_InjectNilIgnored nil 注入不覆盖默认（fail-closed 不变）。
func TestAccessLog_ClientIP_InjectNilIgnored(t *testing.T) {
	rec, do := sinkCapture(t, WithAccessLogClientIP(nil))
	do(ut.Header{Key: "X-Forwarded-For", Value: "9.9.9.9"})
	if rec.ClientIP == "9.9.9.9" {
		t.Fatalf("nil 注入后仍须默认口径, got %q", rec.ClientIP)
	}
}
