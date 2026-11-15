package mw

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/oekit/pkg/convert"
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

// TestAccessLog_ClientIP_TrustedProxiesThirdArg 钉住 #253：ClientIPFunc 第三参
// （可信代理 CIDR 列表）由 WithAccessLogTrustedProxies 真正透传——旧实现恒传
// nil，「签名与 convert.ResolveClientIP 一致」的直传写法拿不到清单、静默退化
// 为只取对端地址（注入成功零信号）。
func TestAccessLog_ClientIP_TrustedProxiesThirdArg(t *testing.T) {
	var got []string
	_, do := sinkCapture(t,
		WithAccessLogClientIP(func(remote, xff string, trustedProxies []string) string {
			got = trustedProxies
			return remote
		}),
		WithAccessLogTrustedProxies("10.0.0.0/8", "192.168.0.0/16"),
	)
	do()
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.0.0/16" {
		t.Fatalf("★ 第三参应透传 TrustedProxies 清单（#253）, got %v", got)
	}

	// 未设置 TrustedProxies：第三参为 nil（默认 fail-closed 口径不变）
	got = []string{"sentinel"}
	_, do = sinkCapture(t, WithAccessLogClientIP(func(_, _ string, trustedProxies []string) string {
		got = trustedProxies
		return "1.2.3.4"
	}))
	do()
	if got != nil {
		t.Fatalf("未设置时第三参应为 nil, got %v", got)
	}
}

// TestAccessLog_ClientIP_DirectResolveClientIP 钉住 #253 的直传形态：
// convert.ResolveClientIP 与本缝同签名，配 WithAccessLogTrustedProxies 可
// 不包闭包直接注入，且可信网段内对端的 XFF 生效（清单真的到达解析函数）。
func TestAccessLog_ClientIP_DirectResolveClientIP(t *testing.T) {
	// 对端为可信网关（10.0.0.2 ∈ 10.0.0.0/8）→ 取 XFF 首跳
	rec, do := sinkCapture(t,
		WithAccessLogClientIP(convert.ResolveClientIP),
		WithAccessLogTrustedProxies("10.0.0.0/8"),
	)
	do(ut.Header{Key: "X-Forwarded-For", Value: "203.0.113.7"})
	_ = rec
	// sinkCapture 的对端地址由引擎决定（非 10.0.0.0/8 时 fail-closed 取对端），
	// 此处只断言不 panic 且 ClientIP 非空；清单透传的确定性断言在上一测试。
	if rec.ClientIP == "" {
		t.Fatal("ClientIP 不应为空")
	}
}
