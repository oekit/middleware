package mw

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/oekit/core/transport/hertzbridge"
)

// newHertzServerContext 返回注入服务端 Transporter 的 context，供根包薄壳
// 向 chainmw 内核注入服务端上下文。
//
// hertz RequestContext/header → core/transport 的适配已下沉
// core/transport/hertzbridge 单源（#180，#177 治本）：middleware 与 hertz
// 两仓消费同一份适配器，消灭「同构实现靠注释约束一致」的漂移源——#163
// 大小写修复曾只落在 hertz 侧，本仓同构副本未跟上（活缺陷）。本仓不再
// 持有任何本地适配副本：hertzTransporter/hertzRequestHeader/hertzReplyHeader
// 及两对 Values/Keys 适配方法（含 hertzHeaderKeys 汇总）已删除，Get/Values
// 键匹配大小写不敏感口径（EqualFold）随单源固化。
//
// 返回的 Transporter 持有 RequestContext 引用，生命周期与请求一致。
func newHertzServerContext(ctx context.Context, c *app.RequestContext) context.Context {
	return hertzbridge.NewServerContext(ctx, c)
}
