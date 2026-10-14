package contrib

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
)

// spinDebugRealServer 在空闲端口起真实 hertz server。
// (ut 桩无 network.Writer,pprof 端点经 adaptor 的响应写路径会 nil deref,
// 上游 harness 限制;鉴权 scoping 断言走真实 TCP。)
func spinDebugRealServer(t *testing.T, register func(h *server.Hertz)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	h := server.New(
		server.WithHostPorts(addr),
		server.WithDisablePrintRoute(true),
	)
	register(h)
	go func() {
		defer func() { _ = recover() }()
		h.Spin()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return "http://" + addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("real server not ready in time")
	return ""
}

func debugGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestRegisterDebug_AuthScopedToDebugRoutes 钉住 2026-09-05 修复的回归:
// 原实现 h.Use(guard) 把鉴权挂到 root group,hertz 路由注册时快照 handlers,
// 之后注册的业务路由也被迫鉴权(实测 /biz 无 token 401)。修复后 guard 只
// 作用于 debug 端点,业务路由不受注册顺序影响。
func TestRegisterDebug_AuthScopedToDebugRoutes(t *testing.T) {
	base := spinDebugRealServer(t, func(h *server.Hertz) {
		// 先注册 debug(带鉴权),再注册业务路由 — 泄漏场景
		RegisterDebug(h,
			WithDebugPrefix("/internal/pprof"),
			WithDebugAuth("tok-123"),
			WithDebugFgprof(),
		)
		h.GET("/biz", func(_ context.Context, c *app.RequestContext) {
			c.String(200, "biz-ok")
		})
	})

	// 业务路由:无 token 必须 200(不受 guard 泄漏影响)
	code, body := debugGet(t, base+"/biz")
	if code != 200 || !strings.Contains(body, "biz-ok") {
		t.Errorf("business route /biz: got %d %q, want 200 biz-ok (鉴权泄漏到业务路由?)", code, body)
	}

	// debug 端点:无 token → 401,带 token → 200
	code, _ = debugGet(t, base+"/internal/pprof/")
	if code != 401 {
		t.Errorf("debug endpoint without token: got %d, want 401", code)
	}
	code, _ = debugGet(t, base+"/internal/pprof/?token=tok-123")
	if code != 200 {
		t.Errorf("debug endpoint with token: got %d, want 200", code)
	}

	// fgprof 端点同样受 guard 保护
	code, _ = debugGet(t, base+"/debug/fgprof")
	if code != 401 {
		t.Errorf("fgprof without token: got %d, want 401", code)
	}
	code, _ = debugGet(t, base+"/debug/fgprof?token=tok-123&seconds=1")
	if code != 200 {
		t.Errorf("fgprof with token: got %d, want 200", code)
	}
}

// TestRegisterDebug_NoAuth_PublicReachable 公开模式:端点无鉴权可达
// (与 middleware_coverage_test 的同名构造级测试互补,此为请求级行为验证)。
func TestRegisterDebug_NoAuth_PublicReachable(t *testing.T) {
	base := spinDebugRealServer(t, func(h *server.Hertz) {
		RegisterDebug(h)
	})
	code, _ := debugGet(t, base+"/debug/pprof/")
	if code != 200 {
		t.Errorf("unauthenticated debug endpoint: got %d, want 200", code)
	}
}
