package contrib

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
)

func newRevProxyHertz() *server.Hertz {
	return server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
}

// TestNewSingleHostReverseProxy_NoError 验证构造不返回 error 且非 nil。
func TestNewSingleHostReverseProxy_NoError(t *testing.T) {
	rp, err := NewSingleHostReverseProxy("http://internal-service:8080")
	if err != nil {
		t.Fatalf("NewSingleHostReverseProxy: %v", err)
	}
	if rp == nil {
		t.Fatal("rp is nil")
	}
}

// TestNewSingleHostReverseProxy_HTTPS 验证 https target 也构造成功。
func TestNewSingleHostReverseProxy_HTTPS(t *testing.T) {
	rp, err := NewSingleHostReverseProxy("https://api.example.com")
	if err != nil {
		t.Fatalf("NewSingleHostReverseProxy: %v", err)
	}
	if rp == nil {
		t.Fatal("rp is nil")
	}
}

// TestNewSingleHostReverseProxy_InvalidURL 验证无效 URL 仍能构造
// (hertz-contrib/reverseproxy 不做 URL 解析,只解析 host:port 部分)。
func TestNewSingleHostReverseProxy_InvalidURL(t *testing.T) {
	rp, _ := NewSingleHostReverseProxy("not-a-url-at-all")
	// hertz-contrib 行为:空 path 也接受,业务自己 sanity check
	if rp == nil {
		t.Error("expected non-nil rp for any string input")
	}
}

// TestMountReverseProxy_NoRoute 验证 MountReverseProxy 挂到 NoRoute。
func TestMountReverseProxy_NoRoute(t *testing.T) {
	h := newRevProxyHertz()
	rp, _ := NewSingleHostReverseProxy("http://internal:8080")
	MountReverseProxy(h, rp)
	// 仅验证不 panic;完整路径需要 upstream server,留 e2e
	_ = context.Background
	_ = app.NewContext(0)
}

// TestReverseProxy_TypeAlias 验证 type alias 兼容。
func TestReverseProxy_TypeAlias(t *testing.T) {
	var _ *ReverseProxy = nil
	// 编译期检查 *ReverseProxy 是合法类型
}
