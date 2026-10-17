package contrib

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/csrf"
)

// CSRFOptions 是 CSRF 防护中间件的配置。
type CSRFOptions struct {
	// Secret 用于签发/校验 CSRF token 的密钥（必填，建议 32 字节随机串）。
	Secret string

	// IgnoredMethods 不校验的 HTTP 方法，默认 ["GET","HEAD","OPTIONS","TRACE"]。
	IgnoredMethods []string

	// KeyLookUp token 的查找位置，格式 "<source>:<key>"，默认 "header:X-CSRF-Token"。
	// source 可选: header / form / query。
	KeyLookUp string
}

// CSRFOption 配置 CSRFMiddleware。
type CSRFOption func(*CSRFOptions)

// WithCSRFSecret 设置 CSRF token 密钥。
func WithCSRFSecret(secret string) CSRFOption {
	return func(o *CSRFOptions) {
		o.Secret = secret
	}
}

// WithCSRFIgnoredMethods 设置不校验的 HTTP 方法。
func WithCSRFIgnoredMethods(methods ...string) CSRFOption {
	return func(o *CSRFOptions) {
		o.IgnoredMethods = append(o.IgnoredMethods, methods...)
	}
}

// WithCSRFKeyLookUp 设置 token 的查找位置。
// 格式 "<source>:<key>"，如 "header:X-CSRF-Token"。
func WithCSRFKeyLookUp(lookup string) CSRFOption {
	return func(o *CSRFOptions) {
		o.KeyLookUp = lookup
	}
}

// CSRFMiddleware 返回 CSRF 防护中间件。
//
// 基于 hertz-contrib/csrf。校验请求携带的 CSRF token 是否与服务端签发的匹配，
// 不匹配则拒绝。用于防御跨站请求伪造，保护状态变更类接口（POST/PUT/DELETE）。
//
// 客户端流程:
//  1. GET 一个受保护页面/接口，响应会种下 CSRF cookie + 可通过 csrf.GetToken 读取 token
//  2. 后续 POST 请求在指定位置（默认 header X-CSRF-Token）携带 token
//
// 前置条件: 必须先注册 sessions 中间件（hertz-contrib/sessions），
// 否则每个请求都会 panic（底层 csrf 依赖 sessions.Default(c)）。
// Secret 不能为空。
//
// 用法:
//
//	h.Use(contrib.CSRFMiddleware(mw.WithCSRFSecret("your-32-byte-random-secret")))
//
// 在 handler 中读取 token 透传给前端:
//
//	token := csrf.GetToken(c)
func CSRFMiddleware(opts ...CSRFOption) app.HandlerFunc {
	cfg := &CSRFOptions{}
	for _, opt := range opts {
		opt(cfg)
	}

	csrfOpts := []csrf.Option{csrf.WithSecret(cfg.Secret)}
	if len(cfg.IgnoredMethods) > 0 {
		csrfOpts = append(csrfOpts, csrf.WithIgnoredMethods(cfg.IgnoredMethods))
	}
	if cfg.KeyLookUp != "" {
		csrfOpts = append(csrfOpts, csrf.WithKeyLookUp(cfg.KeyLookUp))
	}
	// 上游默认 ErrorFunc 会 panic(c.Errors.Last())——缺 salt/ token 不匹配这类
	// "应拒绝"的常态路径会变成 500 + panic 噪音，这里改为标准 403。
	csrfOpts = append(csrfOpts, csrf.WithErrorFunc(func(ctx context.Context, c *app.RequestContext) {
		c.AbortWithStatus(http.StatusForbidden)
	}))
	return csrf.New(csrfOpts...)
}
