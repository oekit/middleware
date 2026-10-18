package mw

import (
	"context"
	"sort"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/oekit/core/transport"
)

// hertzTransporter 把 Hertz RequestContext 适配为 core/transport Transporter，
// 供根包薄壳向 chainmw 内核注入服务端上下文。
//
// 与 hertz/transportx 同构（Kind=http、Endpoint=Host、Operation=PATH、
// header 读写映射一致）。不能直接 import hertz/transportx——hertz 仓的
// chainmw 桥接 import 本仓，反向依赖成环（矩阵分层红线），故内置同构实现。

// newHertzServerContext 返回注入服务端 Transporter 的 context。
// 返回的 Transporter 持有 RequestContext 引用，生命周期与请求一致。
func newHertzServerContext(ctx context.Context, c *app.RequestContext) context.Context {
	return transport.NewServerContext(ctx, &hertzTransporter{c: c})
}

type hertzTransporter struct {
	c *app.RequestContext
}

func (t *hertzTransporter) Kind() transport.Kind { return transport.KindHTTP }

func (t *hertzTransporter) Endpoint() string { return string(t.c.Host()) }

func (t *hertzTransporter) Operation() string { return string(t.c.Path()) }

func (t *hertzTransporter) RequestHeader() transport.Header {
	return &hertzRequestHeader{h: &t.c.Request.Header}
}

func (t *hertzTransporter) ReplyHeader() transport.Header {
	return &hertzReplyHeader{h: &t.c.Response.Header}
}

// hertzRequestHeader 适配 hertz RequestHeader。
type hertzRequestHeader struct {
	h *protocol.RequestHeader
}

func (a *hertzRequestHeader) Get(key string) string { return a.h.Get(key) }

func (a *hertzRequestHeader) Values(key string) []string {
	var out []string
	a.h.VisitAll(func(k, v []byte) {
		if string(k) == key {
			out = append(out, string(v))
		}
	})
	return out
}

func (a *hertzRequestHeader) Set(key, value string) { a.h.Set(key, value) }

func (a *hertzRequestHeader) Add(key, value string) { a.h.Add(key, value) }

func (a *hertzRequestHeader) Del(key string) { a.h.Del(key) }

func (a *hertzRequestHeader) Keys() []string {
	return hertzHeaderKeys(a.h.VisitAll)
}

// hertzReplyHeader 适配 hertz ResponseHeader。
type hertzReplyHeader struct {
	h *protocol.ResponseHeader
}

func (a *hertzReplyHeader) Get(key string) string { return a.h.Get(key) }

func (a *hertzReplyHeader) Values(key string) []string {
	var out []string
	a.h.VisitAll(func(k, v []byte) {
		if string(k) == key {
			out = append(out, string(v))
		}
	})
	return out
}

func (a *hertzReplyHeader) Set(key, value string) { a.h.Set(key, value) }

func (a *hertzReplyHeader) Add(key, value string) { a.h.Set(key, value) }

func (a *hertzReplyHeader) Del(key string) { a.h.Del(key) }

func (a *hertzReplyHeader) Keys() []string {
	return hertzHeaderKeys(a.h.VisitAll)
}

// hertzHeaderKeys 汇总 VisitAll 遍历出的去重排序 key 列表。
// visitAll 形参是 header 的遍历方法值：func(fn func(k, v []byte))。
func hertzHeaderKeys(visitAll func(fn func(k, v []byte))) []string {
	seen := make(map[string]struct{})
	visitAll(func(k, _ []byte) {
		seen[string(k)] = struct{}{}
	})
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
