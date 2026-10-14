package contrib

import (
	"context"
	"errors"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/keyauth"
)

// KeyAuth 返回 hertz API Key 认证中间件,桥接 hertz-contrib/keyauth。
//
// 业务必须提供 validator(无默认实现,因为 API key 验证逻辑业务特定)。
//
// 典型用法(简单 API key 验证):
//
//	keys := map[string]bool{
//	    "client-a-key-abc123": true,
//	    "client-b-key-xyz789": true,
//	}
//	h.Use(contrib.KeyAuth(
//	    keyauth.WithKeyLookUp("header:X-API-Key", ""),
//	    keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, key string) (bool, error) {
//	        return keys[key], nil
//	    }),
//	    keyauth.WithFilter(func(_ context.Context, c *app.RequestContext) bool {
//	        return string(c.Path()) == "/healthz"
//	    }),
//	))
//
// ⚠️ 内置安全默认 errorHandler:上游默认实现在 validator 返回 (false, nil)
// 时直接 err.Error() → nil 指针 panic(keyauth v0.0.0-20221011 option.go:101,
// 已实测复现:无效 key 的拒绝路径必崩,只能靠 recovery 兜成 500)。ekit 前置
// 的默认 handler 按官方状态码语义映射(ErrMissingOrMalformedAPIKey → 400,
// 其余 → 401)并对 nil err 硬化为 401。⚠️ 与上游的 body 分歧:上游对非 nil
// 校验错误回传 err.Error() 原文,ekit 统一返回固定文案 "invalid API key"
// (避免泄漏校验器内部错误文本);业务可用 keyauth.WithErrorHandler 覆盖
// (option 按序 Apply,后传生效)。
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/keyauth/
// (默认 errorHandler:ErrMissingOrMalformedAPIKey → 400,其他校验失败 → 401,
// 均走 AbortWithMsg;WithErrorHandler 用于"设置校验 token 失败的自定义处理逻辑")
//
// ⚠️ KeyAuth 直接接受 keyauth.Option(不重新包装类型),业务需要 import
// hertz-contrib/keyauth(已在 ekit go.mod);ekit 提供 17 个 hertz-contrib
// 中间件的统一入口 KeyAuth,具体 option 用法以 hertz-contrib/keyauth 为准。
func KeyAuth(opts ...keyauth.Option) app.HandlerFunc {
	// 缺省 reject-all validator：上游 keyauth.NewOptions 的默认 validator
	// 是 `return true, nil`——裸调用 contrib.KeyAuth()（或漏传 WithValidator）时
	// 任意 key 全部放行，接口实际无鉴权。先放 reject-all（走已硬化的
	// 401 路径），业务 WithValidator 按序覆盖。
	safeDefaults := make([]keyauth.Option, 0, 2+len(opts))
	safeDefaults = append(safeDefaults,
		keyauth.WithValidator(func(_ context.Context, _ *app.RequestContext, _ string) (bool, error) {
			return false, nil
		}),
		keyauth.WithErrorHandler(
			func(_ context.Context, c *app.RequestContext, err error) {
				// 对齐上游默认语义,但对 nil err(validator 返回 false, nil)硬化,
				// 不再 deref 空指针
				status := http.StatusUnauthorized
				msg := "invalid API key"
				if errors.Is(err, keyauth.ErrMissingOrMalformedAPIKey) {
					status = http.StatusBadRequest
					msg = err.Error()
				}
				c.AbortWithMsg(msg, status)
			}),
	)
	return keyauth.New(append(safeDefaults, opts...)...)
}
