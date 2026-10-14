package contrib

import (
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
)

// newTestHertz 构建一个不会真 listen 的 hertz 实例(用于查路由表)。
func newTestHertzForPprof() *server.Hertz {
	opts := []config.Option{
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	}
	return server.New(opts...)
}

// getRouteList 返回 hertz router 上注册的 path 列表(用于断言 pprof 端点)。
func getRouteList(h *server.Hertz) []string {
	routes := h.Routes()
	out := make([]string, 0, len(routes))
	for _, ri := range routes {
		out = append(out, ri.Method+" "+ri.Path)
	}
	return out
}

func TestRegisterPprof_DefaultPrefix(t *testing.T) {
	h := newTestHertzForPprof()
	info := RegisterPprof(h)
	if info.Prefix != PprofDefaultPrefix {
		t.Fatalf("expected default prefix %q, got %q", PprofDefaultPrefix, info.Prefix)
	}
	routes := getRouteList(h)
	want := []string{
		"GET /debug/pprof/",
		"GET /debug/pprof/cmdline",
		"GET /debug/pprof/profile",
		"POST /debug/pprof/symbol",
		"GET /debug/pprof/symbol",
		"GET /debug/pprof/trace",
		"GET /debug/pprof/allocs",
		"GET /debug/pprof/block",
		"GET /debug/pprof/goroutine",
		"GET /debug/pprof/heap",
		"GET /debug/pprof/mutex",
		"GET /debug/pprof/threadcreate",
	}
	for _, w := range want {
		found := false
		for _, got := range routes {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected route %q in %v", w, routes)
		}
	}
}

func TestRegisterPprof_CustomPrefix(t *testing.T) {
	h := newTestHertzForPprof()
	info := RegisterPprof(h, WithPprofPrefix("/internal/pprof"))
	if info.Prefix != "/internal/pprof" {
		t.Fatalf("expected custom prefix %q, got %q", "/internal/pprof", info.Prefix)
	}
	routes := getRouteList(h)
	// 默认前缀下不应再注册
	for _, r := range routes {
		if strings.HasPrefix(r, "GET /debug/pprof") {
			t.Errorf("unexpected default route after custom prefix: %q", r)
		}
	}
	// 自定义前缀下应该注册索引路径
	found := false
	for _, r := range routes {
		if r == "GET /internal/pprof/" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected custom GET / route, got routes %v", routes)
	}
}

func TestRegisterPprof_EmptyPrefixFallsBackToDefault(t *testing.T) {
	h := newTestHertzForPprof()
	// 空字符串不应该把 prefix 清成空字符串
	info := RegisterPprof(h, WithPprofPrefix(""))
	if info.Prefix != PprofDefaultPrefix {
		t.Fatalf("expected default prefix on empty override, got %q", info.Prefix)
	}
}
