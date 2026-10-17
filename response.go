package mw

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/oekit/middleware/hmw"
	"github.com/oekit/pkg/errors"
)

// Response 是所有 HTTP API 的统一响应结构。
// ResponseMiddleware 会自动将 handler 返回的裸数据包装为此格式。
// Handler 也可直接通过 SuccessResp/ErrorResp 写入此结构。
type Response struct {
	Code    int    `json:"code"`     // 业务状态码：0=成功，非0=失败
	Data    any    `json:"data"`     // 业务数据，失败时为 null
	Message string `json:"message"`  // 描述信息，如 "success"、"参数错误"
	TraceID string `json:"trace_id"` // 链路追踪 ID，贯穿请求日志，用于问题排查
}

// ResponseMiddleware 是统一响应格式中间件。
//
// 功能:
//   - 从 RequestContext 中读取 trace_id（由 TraceIDMiddleware 注入），写入响应体
//   - 拦截 handler 返回的裸 JSON（不含 "code" 字段），自动包装为 {code, data, message, trace_id}
//   - 如果 handler 已通过 SuccessResp/ErrorResp 写入了带 "code" 的响应，不会重复包装
//   - 跳过非 JSON 响应、非 200 状态码、空 body
//
// 声明式跳过（与 SkipResponseWrap 并存）:
//   - WithSkipPaths — 路径精确匹配，命中则整请求不包装
//   - WithSkipPrefixes — 路径前缀匹配（如 "/.well-known/"、"/mcp"），命中则整请求不包装
//   - SkipResponseWrap — handler 级逃生舱（写响应前调用），单响应跳过包装
//
// 注意: 本中间件不负责生成 trace_id。请确保已在其之前注册 hmw.Middleware()。
//
// 注册位置: 放在 hmw.Middleware() 之后、路由中间件链中，确保所有子路由都经过。
func ResponseMiddleware(opts ...ResponseOption) app.HandlerFunc {
	cfg := newResponseOptions(opts...)
	return func(ctx context.Context, c *app.RequestContext) {
		// 声明式跳过：命中即整请求不包装（handler 正常执行，裸响应原样输出）。
		if cfg.skip(string(c.Request.URI().Path())) {
			c.Next(ctx)
			return
		}

		c.Next(ctx)

		// 标准协议端点逃生舱（OIDC /token、discovery、JWKS 等 RFC 载荷不允许
		// 被业务包壳包裹——第三方按规范解析顶层字段）。handler 写响应前调用
		// SkipResponseWrap 置标记；标记与响应体同生命周期，读取绝对可靠。
		// 首选 RequestContext kv，兼容头随后清理，外部观察者看不到。
		_, kvSkip := c.Get(skipWrapCtxKey)
		hdrSkip := len(c.Response.Header.Peek(skipResponseWrapHeader)) > 0
		legacySkip := len(c.Response.Header.Peek(legacySkipResponseWrapHeader)) > 0
		if hdrSkip {
			c.Response.Header.Del(skipResponseWrapHeader)
		}
		if legacySkip {
			c.Response.Header.Del(legacySkipResponseWrapHeader)
		}
		if kvSkip || hdrSkip || legacySkip {
			return
		}

		body := c.Response.Body()
		if len(body) == 0 {
			return
		}

		statusCode := c.Response.StatusCode()
		if statusCode < 200 || statusCode >= 300 {
			return
		}

		ct := string(c.Response.Header.ContentType())
		if !strings.Contains(ct, "application/json") {
			return
		}

		// 快速检查：如果 body 已经包含 "code" 字段，不重复包装。
		// 使用简单的字符串搜索避免完整 JSON 反序列化。
		if hasCodeField(body) {
			return
		}

		// 使用 json.RawMessage 避免反序列化再序列化 data 字段
		wrapped, err := json.Marshal(struct {
			Code    int             `json:"code"`
			Data    json.RawMessage `json:"data"`
			Message string          `json:"message"`
			TraceID string          `json:"trace_id"`
		}{
			Code:    0,
			Data:    body,
			Message: "success",
			TraceID: hmw.FromRequestContext(c),
		})
		if err != nil {
			return
		}
		c.Response.SetBody(wrapped)
	}
}

// responseSkipConfig 是 ResponseMiddleware 的声明式跳过配置。
type responseSkipConfig struct {
	// skipPaths 精确匹配的路径集合。
	skipPaths map[string]struct{}
	// skipPrefixes 前缀匹配的路径前缀列表（按声明顺序）。
	skipPrefixes []string
}

// skip 判断给定路径是否命中声明式跳过规则。
func (c *responseSkipConfig) skip(path string) bool {
	if _, ok := c.skipPaths[path]; ok {
		return true
	}
	for _, p := range c.skipPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ResponseOption 配置 ResponseMiddleware 的函数选项。
type ResponseOption func(*responseSkipConfig)

// newResponseOptions 聚合 ResponseOption 列表。
func newResponseOptions(opts ...ResponseOption) *responseSkipConfig {
	cfg := &responseSkipConfig{skipPaths: make(map[string]struct{})}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithSkipPaths 声明精确匹配的跳过路径：命中即整请求不做统一包壳。
// 适合 OIDC/JWKS 等 RFC 标准端点的静态路径清单。
//
// 用法:
//
//	mw.ResponseMiddleware(mw.WithSkipPaths("/token", "/jwks.json"))
func WithSkipPaths(paths ...string) ResponseOption {
	return func(c *responseSkipConfig) {
		for _, p := range paths {
			c.skipPaths[p] = struct{}{}
		}
	}
}

// WithSkipPrefixes 声明前缀匹配的跳过路径：命中即整请求不做统一包壳。
// 适合 /.well-known/、/mcp 这类按前缀成组的标准端点。
//
// 用法:
//
//	mw.ResponseMiddleware(mw.WithSkipPrefixes("/.well-known/", "/mcp"))
func WithSkipPrefixes(prefixes ...string) ResponseOption {
	return func(c *responseSkipConfig) {
		c.skipPrefixes = append(c.skipPrefixes, prefixes...)
	}
}

// StatusMapper 将业务码映射为 HTTP 状态码。
// 默认实现 DefaultStatusMapper 将 HTTP 对齐的业务码（100-599）直接用作 HTTP 状态码，
// 其余自定义业务码（如 1001）映射为 400 Bad Request。
// 可通过 SetStatusMapper 自定义映射规则。
type StatusMapper func(bizCode int) int

// defaultStatusMapper 是默认的业务码 → HTTP 状态码映射。
func defaultStatusMapper(code int) int {
	switch {
	case code >= 100 && code < 600:
		return code // HTTP 对齐的业务码直接复用
	case code == 0:
		return consts.StatusOK
	default:
		// 自定义业务码（如 1001、20003）默认归为客户端错误
		return consts.StatusBadRequest
	}
}

// statusMapper 当前生效的状态码映射器（包级可替换，使用 atomic.Pointer 保护并发安全）。
var statusMapper atomic.Pointer[StatusMapper]

func init() {
	m := StatusMapper(defaultStatusMapper)
	statusMapper.Store(&m)
}

// SetStatusMapper 设置全局业务码 → HTTP 状态码映射器。
// 应在服务初始化阶段（main 中、注册路由前）调用。
func SetStatusMapper(m StatusMapper) {
	statusMapper.Store(&m)
}

// getStatusMapper 获取当前生效的状态码映射器。
func getStatusMapper() StatusMapper {
	return *statusMapper.Load()
}

// ErrorResp 写入错误响应并中断后续处理。
//
// 响应格式: {"code": <code>, "data": null, "message": "<message>", "trace_id": "..."}
// HTTP 状态码由 StatusMapper 从业务码推导（默认：HTTP 对齐码直接复用，
// 自定义码归为 400）。这样网关/监控能基于 HTTP 状态码正确识别错误率。
// 调用后会自动 c.Abort()，后续 handler 不再执行。
func ErrorResp(c *app.RequestContext, code int, message string) {
	c.JSON(getStatusMapper()(code), Response{
		Code: code, Data: nil, Message: message, TraceID: hmw.FromRequestContext(c),
	})
	c.Abort()
}

// writeBizError 是 Fail/FailWithData 共享的 BizError 写入逻辑：
//   - body code 字段使用 BizCode（业务语义）
//   - HTTP 状态码优先用 HTTPCode；为 0 时经 StatusMapper 从 BizCode 推导（向后兼容）
//   - data 为随错误返回的业务载荷（202 业务态场景；Fail 传 nil）
func writeBizError(c *app.RequestContext, bizErr *errors.BizError, data any) {
	httpCode := bizErr.HTTPCode
	if httpCode == 0 {
		httpCode = getStatusMapper()(bizErr.BizCode)
	}
	c.JSON(httpCode, Response{
		Code: bizErr.BizCode, Data: data, Message: bizErr.Message, TraceID: hmw.FromRequestContext(c),
	})
	c.Abort()
}

// SuccessResp 写入成功响应。
//
// 响应格式: {"code": 0, "data": <data>, "message": "success", "trace_id": "..."}
// 由于已经包含 "code" 字段，ResponseMiddleware 不会重复包装。
func SuccessResp(c *app.RequestContext, data any) {
	c.JSON(consts.StatusOK, Response{
		Code: 0, Data: data, Message: "success", TraceID: hmw.FromRequestContext(c),
	})
}

// SuccessRespMsg 写入成功响应（自定义 message）。
//
// 用法: mw.SuccessRespMsg(c, nil, "创建成功")
func SuccessRespMsg(c *app.RequestContext, data any, message string) {
	c.JSON(consts.StatusOK, Response{
		Code: 0, Data: data, Message: message, TraceID: hmw.FromRequestContext(c),
	})
}

// hasCodeField 快速检查 JSON body 顶层（depth==1）是否包含 "code" 字段。
// 比完整 json.Unmarshal 更高效，避免分配中间对象。
//
// 实现为 O(n) 单遍扫描：跟踪字符串字面量状态（含反斜杠转义）与花括号深度，
// 字符串值内部的 { } " 不会干扰层级判断 —— 此前简单的花括号计数会被
// `{"data":"{"}` 这类包含花括号的字符串值骗过，导致顶层 "code" 漏判
// （重复包装）或嵌套对象误判。
func hasCodeField(body []byte) bool {
	const key = `"code"`
	s := string(body)
	depth := 0
	inString := false
	escaped := false

	for i := 0; i < len(s); i++ {
		b := s[i]

		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch b {
			case '\\':
				escaped = true
			case '"':
				// 字符串结束：若处于 depth==1 且恰好是 "code"，
				// 向后跳过空白找 ':' 确认它是键而非同名字符串值。
				if depth == 1 && i+1 >= len(key) && s[i+1-len(key):i+1] == key {
					for j := i + 1; j < len(s); j++ {
						c := s[j]
						if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
							continue
						}
						if c == ':' {
							return true
						}
						break
					}
				}
				inString = false
			}
			continue
		}

		switch b {
		case '"':
			inString = true
		case '{', '[':
			// 方括号同层计数：顶层数组的元素对象在 depth>=2，
			// 其中的 "code" 字段不该被误判为顶层键而跳过包装。
			depth++
		case '}', ']':
			depth--
		}
	}
	return false
}

// skipWrapCtxKey 是包装豁免标记的 RequestContext kv 键（首选机制，
// 不落响应头、外部不可见）。SkipResponseWrap 置位，ResponseMiddleware 读取。
//
//nolint:gosec // G101 误报：这是 RequestContext kv 的键名常量，非凭证
const skipWrapCtxKey = "oekit_skip_response_wrap"

// skipResponseWrapHeader 是包装豁免标记的兼容响应头（kv 的次级兼容层）。
// 写入响应后由 ResponseMiddleware 读取并删除——外部观察者在该响应上不会看到它。
const skipResponseWrapHeader = "X-Oekit-No-Wrap"

// legacySkipResponseWrapHeader 是旧的包装豁免响应头名（历史遗留，一版后移除）。
//
// Deprecated: 仅作一个版本的兼容读取，下版本删除；请用 RequestContext kv
// （SkipResponseWrap 默认写入）或 X-Oekit-No-Wrap。
const legacySkipResponseWrapHeader = "X-Zeus-No-Wrap"

// SkipResponseWrap 标记本响应跳过统一业务包壳（RFC 标准载荷端点用：
// OIDC /token、/userinfo、discovery、JWKS 等，第三方按规范解析顶层字段）。
// 必须在写响应体之前调用。
//
// 标记同时写入 RequestContext kv（首选，外部不可见）与 X-Oekit-No-Wrap
// 兼容头；旧名 X-Zeus-No-Wrap 仍被读取一个版本后移除。
// 与 ResponseMiddleware 的 WithSkipPaths/WithSkipPrefixes 声明式跳过并存：
// 本函数是 handler 级逃生舱（单响应），声明式跳过是路由级（整请求）。
func SkipResponseWrap(c *app.RequestContext) {
	c.Set(skipWrapCtxKey, true)
	c.Response.Header.Set(skipResponseWrapHeader, "1")
}
