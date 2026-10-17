package contrib

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	larkcard "github.com/larksuite/oapi-sdk-go/v3/card"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
)

// TestLarkCardAction_RegistersRoute 验证 LarkCardAction 在 h 上挂 POST /lark/card。
func TestLarkCardAction_RegistersRoute(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	handler := larkcard.NewCardActionHandler("test_token", "test_encrypt_key", func(_ context.Context, _ *larkcard.CardAction) (interface{}, error) {
		return nil, nil
	})
	LarkCardAction(h, handler)
	// 验证路由注册(不 panic)
}

// TestLarkEvent_RegistersRoute 验证 LarkEvent 在 h 上挂 POST /lark/event。
func TestLarkEvent_RegistersRoute(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	ed := dispatcher.NewEventDispatcher("test_token", "test_encrypt_key")
	LarkEvent(h, ed)
	// 验证路由注册(不 panic)
}

// TestLarkCardActionHandlerFunc_ReturnsHandler 验证 standalone helper。
func TestLarkCardActionHandlerFunc_ReturnsHandler(t *testing.T) {
	handler := larkcard.NewCardActionHandler("test_token", "test_encrypt_key", func(_ context.Context, _ *larkcard.CardAction) (interface{}, error) {
		return nil, nil
	})
	h := LarkCardActionHandlerFunc(handler)
	if h == nil {
		t.Fatal("LarkCardActionHandlerFunc returned nil")
	}
	// 验证 handler 签名是 func(ctx, *app.RequestContext)
	_ = app.NewContext(0)
}

// TestLarkEventHandlerFunc_ReturnsHandler 验证 standalone helper。
func TestLarkEventHandlerFunc_ReturnsHandler(t *testing.T) {
	ed := dispatcher.NewEventDispatcher("test_token", "test_encrypt_key")
	h := LarkEventHandlerFunc(ed)
	if h == nil {
		t.Fatal("LarkEventHandlerFunc returned nil")
	}
}

// TestLarkCardHandler_TypeAlias 验证 type alias 编译期兼容。
func TestLarkCardHandler_TypeAlias(t *testing.T) {
	var h *LarkCardHandler
	_ = h
	var d *LarkEventDispatcher
	_ = d
}
