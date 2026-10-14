package contrib

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/protocol"
)

// TestSentinelServerMiddleware_NotNil 验证 server middleware 构造。
func TestSentinelServerMiddleware_NotNil(t *testing.T) {
	mw := SentinelServerMiddleware(
		WithSentinelServerResourceExtractor(func(_ context.Context, c *app.RequestContext) string {
			return string(c.Path())
		}),
		WithSentinelServerBlockFallback(func(_ context.Context, c *app.RequestContext) {
			c.AbortWithStatus(429)
		}),
	)
	if mw == nil {
		t.Fatal("SentinelServerMiddleware returned nil")
	}
}

// TestSentinelClientMiddleware_NotNil 验证 client middleware 构造。
func TestSentinelClientMiddleware_NotNil(t *testing.T) {
	mw := SentinelClientMiddleware(
		WithSentinelClientResourceExtractor(func(_ context.Context, _ *protocol.Request, _ *protocol.Response) string {
			return "default-resource"
		}),
		WithSentinelClientBlockFallback(func(_ context.Context, _ *protocol.Request, _ *protocol.Response, _ error) error {
			return nil
		}),
	)
	if mw == nil {
		t.Fatal("SentinelClientMiddleware returned nil")
	}
}

// TestRegisterSentinelServer_NoPanic 验证便捷注册 helper 不 panic。
func TestRegisterSentinelServer_NoPanic(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	RegisterSentinelServer(h)
	// 仅验证不 panic;实际 sentinel 规则需业务自己 InitWithConfig
}

// TestSentinelServerOption_TypeAlias 验证 type alias 编译期兼容。
func TestSentinelServerOption_TypeAlias(t *testing.T) {
	var _ = WithSentinelServerResourceExtractor(nil)
	var _ = WithSentinelClientResourceExtractor(nil)
}
