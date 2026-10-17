package mw

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

// Subject 描述当前请求的认证主体,供 Authorizer 决策。
// 默认 UserID 为空(纯 BearerToken 模式不解析),业务可借 WithAuthSubjectExtractor
// 从 JWT claims 填充。
type Subject struct {
	// UserID 用户唯一标识(由 SubjectExtractor 填充;默认为空——X-User-Id
	// 是客户端完全可控的请求头,v0.28.1 起默认不再读取,需要时用
	// WithAuthSubjectExtractor 显式注入提取逻辑)。
	UserID string
	// Roles 角色列表(给 RBAC 用,casbin.Enforce(sub, obj, act) 第 1 参数)。
	Roles []string
	// Claims 透传上游认证结果(例如 JWT claims),业务 Authorizer 内部自取。
	Claims map[string]any
	// Method HTTP 方法,给 Authorizer 用于 path-pattern 路由。
	Method string
	// Path 请求路径,给 Authorizer 用于 path-pattern 路由。
	Path string
}

// Authorizer 是 BearerTokenAuth 的鉴权钩子接口,token 验证通过后调起。
// 返回 (false, nil) → 业务拒绝,中间件返 403。
// 返回 (false, err) → 鉴权后端故障,中间件返 500(避免掩盖业务真实错误)。
//
// 设计:ekit 自身不依赖 casbin/jwt 等大 SDK,业务写 adapter 实现接口;
// P4 模式(SentryReporter)同款。
//
// 业务使用(casbin adapter,伪代码):
//
//	type casbinAuth struct{ e *casbin.Enforcer }
//	func (c *casbinAuth) Authorize(ctx, _, sub) (bool, error) {
//	    return c.e.Enforce(sub.UserID, sub.Path, sub.Method)
//	}
//	h.Use(mw.BearerTokenAuth(
//	    mw.WithBearerToken(token),
//	    mw.WithAuthAuthorizer(&casbinAuth{e: enforcer}),
//	))
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/casbin/
type Authorizer interface {
	Authorize(ctx context.Context, c *app.RequestContext, sub Subject) (bool, error)
}

// SubjectExtractor 是从 RequestContext 提取 Subject 的钩子,
// 业务可从 JWT claims / session 等任意来源填充。
// 默认不读任何请求头(UserID 为空;X-User-Id 等客户端可控头不可作为
// 默认 subject 来源,v0.28.1 安全修复)。
type SubjectExtractor func(c *app.RequestContext) Subject

// BearerTokenOptions 是 Bearer Token 认证中间件的配置。
type BearerTokenOptions struct {
	// Token 预共享的静态 token。为空时中间件不做校验，直接放行。
	Token string

	// SkipPaths 不需要认证的路径列表，如 ["/ping", "/healthz", "/metrics"]。
	SkipPaths []string

	// SkipFunc 自定义跳过逻辑。返回 true 表示该路径不需要认证。
	// 与 SkipPaths 可同时使用，任一命中即跳过。
	SkipFunc func(path string) bool

	// Authorizer token 验证通过后调起的鉴权钩子(可选)。
	// 不设置时,BearerToken 通过即放行(仅认证无鉴权)。
	Authorizer Authorizer

	// SubjectExtractor 从 RequestContext 提取 Subject 传给 Authorizer。
	// 默认:从 X-User-Id header 读,Method/Path 自动设置。
	SubjectExtractor SubjectExtractor
}

// BearerTokenOption 配置 BearerTokenAuth。
type BearerTokenOption func(*BearerTokenOptions)

// WithBearerToken 设置预共享的静态 token。
func WithBearerToken(token string) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.Token = token
	}
}

// WithAuthSkipPaths 设置不需要认证的路径列表。
func WithAuthSkipPaths(paths ...string) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.SkipPaths = append(o.SkipPaths, paths...)
	}
}

// WithAuthSkipFunc 设置自定义跳过逻辑。
// 返回 true 表示该路径不需要认证。
func WithAuthSkipFunc(fn func(path string) bool) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.SkipFunc = fn
	}
}

// WithAuthAuthorizer 设置 token 验证通过后的鉴权钩子(casbin 等)。
// 不设置时 BearerToken 通过即放行(无鉴权)。
func WithAuthAuthorizer(a Authorizer) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.Authorizer = a
	}
}

// WithAuthSubjectExtractor 设置从 RequestContext 提取 Subject 的钩子。
// 默认不读任何请求头(UserID 为空),需要身份信息时必须显式注入。
func WithAuthSubjectExtractor(fn SubjectExtractor) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.SubjectExtractor = fn
	}
}

func newBearerTokenOptions(opts ...BearerTokenOption) *BearerTokenOptions {
	cfg := &BearerTokenOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.SubjectExtractor == nil {
		// 默认 UserID 为空（Method/Path 自动设）：X-User-Id 是客户端完全
		// 可控的请求头，认证通过后拿它做 Authorize 的 subject 等于把鉴权
		// 粒度交给攻击者（低权 token + X-User-Id: admin 冒充管理员）。
		// 网关已过滤该头的内网场景可用 WithAuthSubjectExtractor 显式启用。
		cfg.SubjectExtractor = func(c *app.RequestContext) Subject {
			return Subject{
				Method: string(c.Method()),
				Path:   string(c.Path()),
			}
		}
	}
	return cfg
}

// cutBearerToken 从 Authorization 头切出 token（RFC 7235 scheme 大小写
// 不敏感：bearer/Bearer/BEARER 均接受）。
func cutBearerToken(header string) (string, bool) {
	i := strings.IndexByte(header, ' ')
	if i <= 0 || !strings.EqualFold(header[:i], "bearer") {
		return "", false
	}
	return header[i+1:], true
}

// BearerTokenAuth 返回一个 Bearer Token 认证中间件,可选配鉴权钩子。
//
// 校验流程:
//  1. Token 为空 → 直接放行（认证关闭）
//  2. 路径在 SkipPaths 或命中 SkipFunc → 放行
//  3. 请求头 Authorization: Bearer <token> 与配置 token 做常量时间比较
//     - 不匹配 → 401
//  4. Authorizer 不为 nil → 提取 Subject 调 Authorize
//     - 拒绝 → 403
//     - 错误 → 500
//  5. 全部通过 → c.Next(ctx)
//
// 使用方式:
//
//	// 纯 BearerToken(无鉴权)
//	h.Use(mw.BearerTokenAuth(mw.WithBearerToken(token)))
//
//	// BearerToken + casbin 鉴权
//	h.Use(mw.BearerTokenAuth(
//	    mw.WithBearerToken(token),
//	    mw.WithAuthAuthorizer(&casbinAuth{...}),
//	    mw.WithAuthSubjectExtractor(func(c) mw.Subject {
//	        return mw.Subject{UserID: jwtClaims["user_id"].(string), ...}
//	    }),
//	))
func BearerTokenAuth(opts ...BearerTokenOption) app.HandlerFunc {
	cfg := newBearerTokenOptions(opts...)

	skip := make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skip[p] = true
	}

	return func(ctx context.Context, c *app.RequestContext) {
		if cfg.Token == "" {
			c.Next(ctx)
			return
		}

		path := string(c.Path())
		if skip[path] || (cfg.SkipFunc != nil && cfg.SkipFunc(path)) {
			c.Next(ctx)
			return
		}

		header := string(c.GetHeader("Authorization"))
		// RFC 7235: scheme 大小写不敏感
		t, ok := cutBearerToken(header)
		if !ok || subtle.ConstantTimeCompare([]byte(t), []byte(cfg.Token)) != 1 {
			ErrorResp(c, 401, "unauthorized")
			return
		}

		// token 验证通过,可选鉴权
		if cfg.Authorizer != nil {
			sub := cfg.SubjectExtractor(c)
			allowed, err := cfg.Authorizer.Authorize(ctx, c, sub)
			if err != nil {
				ErrorResp(c, 500, "authorization error")
				return
			}
			if !allowed {
				ErrorResp(c, 403, "forbidden")
				return
			}
		}

		c.Next(ctx)
	}
}
