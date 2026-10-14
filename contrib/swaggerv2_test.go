package contrib

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app/server"
	httpSwagger "github.com/swaggo/http-swagger"
)

func newSwaggerHertz() *server.Hertz {
	return server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
}

// TestSwaggerV2_ReturnsHandler 验证 SwaggerV2 返回非 nil app.HandlerFunc。
func TestSwaggerV2_ReturnsHandler(t *testing.T) {
	h := SwaggerV2(httpSwagger.URL("/swagger/doc.json"))
	if h == nil {
		t.Fatal("SwaggerV2 returned nil")
	}
}

// TestSwaggerV2WithPrefix_ReturnsHandler 验证 SwaggerV2WithPrefix 也返回非 nil。
func TestSwaggerV2WithPrefix_ReturnsHandler(t *testing.T) {
	h := SwaggerV2WithPrefix("/swagger", "/swagger/doc.json")
	if h == nil {
		t.Fatal("SwaggerV2WithPrefix returned nil")
	}
}

// TestRegisterSwaggerV2_RegistersRoute 验证 RegisterSwaggerV2 在 h 上挂载路由。
func TestRegisterSwaggerV2_RegistersRoute(t *testing.T) {
	h := newSwaggerHertz()
	RegisterSwaggerV2(h, httpSwagger.URL("/swagger/doc.json"))
	// 确认未 panic;完整路径在 hertz ut 测试中验证
}

// TestWithSwaggerURL_TypeAlias 验证 type alias 兼容。
func TestWithSwaggerURL_TypeAlias(t *testing.T) {
	var opt = WithSwaggerURL("/api/doc.json")
	if opt == nil {
		t.Fatal("WithSwaggerURL returned nil")
	}
}

// TestWithSwaggerDeepLinking 验证 deep linking option 透传。
func TestWithSwaggerDeepLinking(t *testing.T) {
	var opt = WithSwaggerDeepLinking(false)
	if opt == nil {
		t.Fatal("WithSwaggerDeepLinking returned nil")
	}
}

// TestSwaggerV2_HandlerCallable 验证 SwaggerV2 返回的 handler 不为 nil
// 且能被作为 app.HandlerFunc 调用(不一定成功,只验证签名兼容)。
func TestSwaggerV2_HandlerCallable(t *testing.T) {
	h := SwaggerV2(httpSwagger.URL("/swagger/doc.json"))
	if h == nil {
		t.Fatal("SwaggerV2 returned nil")
	}
	// SwaggerV2 返回类型即 app.HandlerFunc,编译期已验证签名兼容
	_ = h
	_ = context.Background
}

// spinRealServerMw 在空闲端口起真实 hertz server(ut 桩无 network.Writer,
// http-swagger 的 net/http 响应写路径会 nil deref,必须走真实 TCP)。
func spinRealServerMw(t *testing.T, register func(h *server.Hertz)) string {
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

// TestSwaggerV2WithPrefix_SpecURLInRenderedIndex 行为级:specURL 必须出现在
// swagger UI 渲染出的 index 页面里(上游模板 url: "{{.URL}}")。
// 钉住 2026-09-05 修复的回归:原实现组装完 httpSwagger.URL 后 `_ = all` 丢弃,
// specURL 从未生效。
func TestSwaggerV2WithPrefix_SpecURLInRenderedIndex(t *testing.T) {
	base := spinRealServerMw(t, func(h *server.Hertz) {
		h.GET("/swagger/*any", SwaggerV2WithPrefix(
			"/swagger", "/swagger/doc.json", httpSwagger.DeepLinking(true)))
	})

	resp, err := http.Get(base + "/swagger/index.html")
	if err != nil {
		t.Fatalf("GET /swagger/index.html: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /swagger/index.html: got %d (want 200)", resp.StatusCode)
	}
	// 上游模板以 JSON 形式渲染 url,斜杠被转义为 "\/"
	rendered := strings.ReplaceAll(string(body), `\/`, `/`)
	if !strings.Contains(rendered, `url: "/swagger/doc.json"`) {
		t.Errorf("specURL not wired into swagger UI index; body snippet=%q", truncate(string(body), 200))
	}
}

// TestRegisterSwaggerV2WithPrefix_CustomPrefix 行为级:自定义前缀挂载 +
// specURL 自动推导。
func TestRegisterSwaggerV2WithPrefix_CustomPrefix(t *testing.T) {
	base := spinRealServerMw(t, func(h *server.Hertz) {
		RegisterSwaggerV2WithPrefix(h, "/internal/debug/swagger")
	})

	resp, err := http.Get(base + "/internal/debug/swagger/index.html")
	if err != nil {
		t.Fatalf("GET index: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET custom prefix index: got %d (want 200)", resp.StatusCode)
	}
	rendered := strings.ReplaceAll(string(body), `\/`, `/`)
	if !strings.Contains(rendered, `url: "/internal/debug/swagger/doc.json"`) {
		t.Errorf("auto specURL missing from index; body snippet=%q", truncate(string(body), 200))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
