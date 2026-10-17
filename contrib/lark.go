package contrib

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	hertzlark "github.com/hertz-contrib/lark-hertz"
	larkcard "github.com/larksuite/oapi-sdk-go/v3/card"
	larkevent "github.com/larksuite/oapi-sdk-go/v3/event"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
)

// LarkCardHandler 是 larkcard.CardActionHandler 的 type alias(飞书
// 卡片交互回调 handler,业务处理用户点卡片按钮的事件)。
type LarkCardHandler = larkcard.CardActionHandler

// LarkEventDispatcher 是 dispatcher.EventDispatcher 的 type alias(飞书
// 事件分发器,业务注册所有事件类型 handler)。
type LarkEventDispatcher = dispatcher.EventDispatcher

// LarkEventOption 是 larkevent.OptionFunc 的 type alias。
type LarkEventOption = larkevent.OptionFunc

// LarkCardAction 注册飞书卡片交互回调到 hertz 路由,默认路径
// "/lark/card",业务可用 hertz 自带 h.Handle 修改路径。
//
// 官方依据:https://github.com/hertz-contrib/lark-hertz + 飞书开放平台
// 卡片回调文档 https://open.feishu.cn/document/uAjLw4CM/ukzMukzMukzM/feishu-cards/card-callback
//
// 用法:
//
//	cardHandler := larkcard.NewCardActionHandler("verification_token", func(ctx context.Context, c *larkcard.CardAction) (interface{}, error) {
//	    // 业务处理用户点卡片按钮
//	    return nil, nil
//	})
//	contrib.LarkCardAction(h, cardHandler)
func LarkCardAction(h *server.Hertz, handler *LarkCardHandler, opts ...LarkEventOption) {
	h.POST("/lark/card", hertzlark.NewCardActionHandlerFunc(handler, opts...))
}

// LarkEvent 注册飞书事件回调到 hertz 路由,默认路径 "/lark/event"。
// 业务需先构造 EventDispatcher 注册各类事件 handler。
//
// 官方依据:https://github.com/hertz-contrib/lark-hertz + 飞书事件订阅
// 文档 https://open.feishu.cn/document/uAjLw4CM/ukzMukzMukzM/event-subscription
//
// 用法:
//
//	ed := dispatcher.NewEventDispatcher("verification_token", "encrypt_key")
//	ed.OnP2MessageReceivedV1(func(ctx context.Context, event *larkevent.EventV2) {
//	    // 处理消息事件
//	})
//	contrib.LarkEvent(h, ed)
func LarkEvent(h *server.Hertz, ed *LarkEventDispatcher, opts ...LarkEventOption) {
	h.POST("/lark/event", hertzlark.NewEventHandlerFunc(ed, opts...))
}

// LarkCardActionHandlerFunc 透传 hertzlark.NewCardActionHandlerFunc 返
// 回的 app.HandlerFunc(给业务自己挂到自定义路径用)。
func LarkCardActionHandlerFunc(handler *LarkCardHandler, opts ...LarkEventOption) func(c context.Context, ctx *app.RequestContext) {
	return hertzlark.NewCardActionHandlerFunc(handler, opts...)
}

// LarkEventHandlerFunc 透传 hertzlark.NewEventHandlerFunc 返回的
// app.HandlerFunc(给业务自己挂到自定义路径用)。
func LarkEventHandlerFunc(ed *LarkEventDispatcher, opts ...LarkEventOption) func(c context.Context, ctx *app.RequestContext) {
	return hertzlark.NewEventHandlerFunc(ed, opts...)
}
