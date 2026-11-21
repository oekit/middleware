package mw

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/logx"
)

// authLog 是认证中间件的 scoped logger（平台契约 §3）。
var authLog = logx.Delegating("middleware-auth")

// ErrInvalidToken 表示凭证无效（401）。TokenVerifier 返回它（含经
// fmt.Errorf("...: %w", mw.ErrInvalidToken) 包装）时，BearerTokenAuth
// 按「静态 token 不匹配」同语义回 401。
var ErrInvalidToken = errors.New("mw: invalid token")

// ErrForbidden 表示凭证本身有效、但该主体无权使用它（403）。TokenVerifier
// 用它在认证阶段直接表达「已识别身份但拒绝接入」，与 Authorizer 的
// 403 语义一致。
var ErrForbidden = errors.New("mw: forbidden")

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

// TokenVerifier 是 BearerTokenAuth 的可插拔凭证校验接口（#293）：
// token 进、认证主体出。静态预共享 token（WithBearerToken）是其退化实现；
// 动态凭证（API key 查库比对 / JWT 验签 / 外部 IdP introspect）经本接口
// 接入，不再各自手搓 401/403/500 出口。
//
// 返回值与错误分类：
//   - (Subject, nil)：校验通过。Subject 即认证主体（UserID/Roles/Claims），
//     中间件回填 Method/Path 后注入 context（SubjectFrom /
//     SubjectFromRequestContext 双写出口），Authorizer（若配置）拿同一
//     Subject 决策。
//   - (_, ErrInvalidToken)：凭证无效 → 401（与静态 token 不匹配同语义）。
//     可用 fmt.Errorf("...: %w", mw.ErrInvalidToken) 携带细节且仍被识别。
//   - (_, ErrForbidden)：凭证有效但主体无权使用它 → 403。
//   - (_, 其他 error)：校验后端故障（DB/IdP 不可用等）→ 500 并打 Error
//     日志——不把基础设施故障伪装成 401 触发客户端无意义地重试/轮换凭据。
//
// 与静态模式互斥：WithBearerToken（非空）与 WithTokenVerifier 同时配置
// 时构造期 panic（凭证校验单源，避免「静态串过了、verifier 没跑」的
// 口径分叉）；两者都缺同样构造期 panic（#97 fail-fast 口径延续）。
//
// verifier 模式不调用 SubjectExtractor：主体唯一来源是 Verify 的返回值，
// 已校验身份不得被客户端可控请求头二次改写。需要结合请求上下文判定的
// verifier 可直接读 c（例如 mTLS 对端证书、转发头）。
type TokenVerifier interface {
	Verify(ctx context.Context, c *app.RequestContext, token string) (Subject, error)
}

// TokenVerifierFunc 把普通函数适配成 TokenVerifier（闭包注入形态）：
//
//	h.Use(mw.BearerTokenAuth(mw.WithTokenVerifier(mw.TokenVerifierFunc(
//	    func(ctx context.Context, c *app.RequestContext, token string) (mw.Subject, error) {
//	        return lookupAPIKey(ctx, token) // 业务：查库比对/验签
//	    },
//	))))
type TokenVerifierFunc func(ctx context.Context, c *app.RequestContext, token string) (Subject, error)

// Verify 实现 TokenVerifier。
func (f TokenVerifierFunc) Verify(ctx context.Context, c *app.RequestContext, token string) (Subject, error) {
	return f(ctx, c, token)
}

// verifiedSubjectCtxKey 是认证主体在标准 context.Context 中的键（非导出
// 结构体类型，杜绝键碰撞）。#293 起 BearerTokenAuth 在校验通过后写入。
type verifiedSubjectCtxKey struct{}

// verifiedSubjectRequestKey 是认证主体在 Hertz RequestContext kv 中的键。
const verifiedSubjectRequestKey = "oekit_verified_subject"

// SubjectFrom 从 handler 的 context.Context 提取 BearerTokenAuth 注入的
// 认证主体（#293）。ok=false 表示本请求未经过 BearerTokenAuth 认证
// （未注册/被 SkipPaths 或 SkipFunc 豁免/WithAuthDisabled）。
//
// 静态 token 模式下 Subject 来自 WithAuthSubjectExtractor（默认仅含
// Method/Path，UserID 为空——静态串只证明「持有共享密钥」，不解析用户）；
// verifier 模式下 Subject 即 Verify 的返回值，Method/Path 已按本次请求
// 回填。Claims 原样透传，供下游读 scope/tenant 等自定义字段。
func SubjectFrom(ctx context.Context) (Subject, bool) {
	sub, ok := ctx.Value(verifiedSubjectCtxKey{}).(Subject)
	return sub, ok
}

// SubjectFromRequestContext 从 Hertz RequestContext 提取认证主体（与
// SubjectFrom 同源——中间件双写两处）。只持有 *app.RequestContext 的
// 辅助函数用这个出口。
func SubjectFromRequestContext(c *app.RequestContext) (Subject, bool) {
	v, ok := c.Get(verifiedSubjectRequestKey)
	if !ok {
		return Subject{}, false
	}
	sub, ok := v.(Subject)
	return sub, ok
}

// BearerTokenOptions 是 Bearer Token 认证中间件的配置。
type BearerTokenOptions struct {
	// Token 预共享的静态 token。与 Verifier 二选一：未配置任一且未显式
	// WithAuthDisabled 时构造期 panic（与 RateLimitMiddleware 对 Rate/Burst
	// 的 fail-fast 同口径，#97）——此前「为空直接放行」是静默 fail-open，
	// 运维误删一行 WithBearerToken 或配置中心读到空串，整个认证层就无声
	// 消失。
	Token string

	// Verifier 动态凭证校验钩子（#293），与 Token 二选一（同时配置
	// 构造期 panic）。配置后 Authorization Bearer token 交 Verify 判定，
	// 静态 Token 不参与比较；验证结果（Subject）注入 context 供下游读取。
	Verifier TokenVerifier

	// Disabled 显式关闭认证（本地联调/明确不需要认证的服务用）。
	// 置位后中间件等价于直通，不再要求 Token。这是一个可 grep、可审计的
	// 显式开关——「没配 token」与「明确决定不要认证」必须可区分。
	Disabled bool

	// SkipPaths 不需要认证的路径列表，如 ["/ping", "/healthz", "/metrics"]。
	// 匹配语义（#187）：**精确匹配**（与 c.Path() 原文 == 比较，非 glob，
	// `*` 与 `/**` 无特殊含义——写 "/api/**" 不会豁免 /api/ 下的任何路径）；
	// glob 语义在同包的观测/限流家族（WithAccessLogSkipPaths/
	// WithRateLimitSkipPaths 的 pathx.MatchesPath），认证家族豁免面按显式
	// 声明制收窄。
	SkipPaths []string

	// SkipFunc 自定义跳过逻辑。返回 true 表示该路径不需要认证。
	// 与 SkipPaths 可同时使用，任一命中即跳过。
	SkipFunc func(path string) bool

	// Authorizer token 验证通过后调起的鉴权钩子(可选)。
	// 不设置时,BearerToken 通过即放行(仅认证无鉴权)。
	Authorizer Authorizer

	// SubjectExtractor 从 RequestContext 提取 Subject 传给 Authorizer。
	// 默认不读任何请求头(UserID 为空),Method/Path 自动设置——X-User-Id 是
	// 客户端完全可控的请求头,默认读它等于把鉴权粒度交给攻击者(v0.28.1 安全
	// 修复已移除该默认);仅可在网关已剥离该头的内网场景经 WithAuthSubject-
	// Extractor 显式注入提取逻辑(口径同 Subject 类型注释)。
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

// WithStaticToken 是 WithBearerToken 的别名：静态预共享 token 形态的
// 直白命名。两者等价，任选其一；与 WithTokenVerifier 互斥。
func WithStaticToken(token string) BearerTokenOption {
	return WithBearerToken(token)
}

// WithTokenVerifier 注入动态凭证校验（#293），替代静态 WithBearerToken。
// verifier 返回的 Subject 即认证主体，校验通过后注入 context，下游用
// SubjectFrom / SubjectFromRequestContext 读取。
//
// 与 WithBearerToken 互斥（同时配置构造期 panic）；都不配且未
// WithAuthDisabled 同样构造期 panic（#97）。
func WithTokenVerifier(v TokenVerifier) BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.Verifier = v
	}
}

// WithVerifier 是 WithTokenVerifier 的简短别名。
func WithVerifier(v TokenVerifier) BearerTokenOption {
	return WithTokenVerifier(v)
}

// WithAuthDisabled 显式关闭认证：中间件直通，不再要求 Token。
//
// 与「忘配 Token」的区别是本开关可 grep、可审计——代码评审能一眼看到
// 「明确决定不要认证」的决策点。Token 未配置且未设置本开关时，
// BearerTokenAuth 在构造期 panic（fail-fast，与 RateLimitMiddleware 同口径）。
func WithAuthDisabled() BearerTokenOption {
	return func(o *BearerTokenOptions) {
		o.Disabled = true
	}
}

// WithAuthSkipPaths 设置不需要认证的路径列表。
//
// 匹配语义（#187）：**精确匹配**（c.Path() 原文 == 比较，非 glob，`*` 与
// "/**" 无特殊含义——写 "/api/**" 不会豁免 "/api/users"，需逐条列出
// "/api/users"、"/api/orders"；glob 语义在同包观测/限流家族
// WithAccessLogSkipPaths/WithRateLimitSkipPaths）。需要前缀豁免时用
// WithAuthSkipFunc(strings.HasPrefix) 自行表达。
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
//
// RFC 7235 的 credentials 语法是 `auth-scheme [ 1*SP ( token68 / ... ) ]`，
// 1*SP = 一个或多个空格：scheme 与 token 间允许多个 SP，token68 本身不含
// 空白。因此切出后 TrimSpace——"Bearer   secret"（多 SP）与 "Bearer secret "
// （尾空白）都必须切出干净的 "secret"，否则 ConstantTimeCompare 不匹配、
// 合法 token 被拒 401（#96）。切出后为空（"Bearer   "）视为格式非法。
func cutBearerToken(header string) (string, bool) {
	i := strings.IndexByte(header, ' ')
	if i <= 0 || !strings.EqualFold(header[:i], "bearer") {
		return "", false
	}
	token := strings.TrimSpace(header[i+1:])
	if token == "" {
		return "", false
	}
	return token, true
}

// BearerTokenAuth 返回一个 Bearer Token 认证中间件,可选配鉴权钩子。
//
// 构造期校验（fail-fast，#97）:
//
//	静态 Token（WithBearerToken/WithStaticToken）与动态 verifier
//	（WithTokenVerifier/WithVerifier）必须**恰好配置一个**：
//	  - 都缺 → panic（「未配置」与「明确不要认证」必须可区分）；
//	  - 都配 → panic（凭证校验单源，避免两套口径分叉）；
//	  - WithAuthDisabled 显式关闭优先，等价于不注册本中间件。
//	此前的「Token 为空 → 直接放行」是运行期静默 fail-open（无日志无告警），
//	与同包 RateLimitMiddleware 对未配置 Rate/Burst 的构造期 panic 是两套
//	安全哲学；本函数对齐后者：误配必须在启动期炸响，而不是让认证层无声消失。
//
// 校验流程:
//  1. WithAuthDisabled → 直接放行（显式关闭，等价于不注册本中间件）
//  2. 路径在 SkipPaths（精确匹配，#187，非 glob）或命中 SkipFunc → 放行
//  3. 从 Authorization: Bearer <token> 切出 token（RFC 7235，格式非法 → 401）
//  4. 凭证校验（单源）:
//     - 静态模式：与配置 token 做常量时间比较，不匹配 → 401；
//     随后用 SubjectExtractor 提取 Subject（默认仅 Method/Path）。
//     - verifier 模式：TokenVerifier.Verify(ctx, c, token) 出 Subject；
//     ErrInvalidToken → 401，ErrForbidden → 403，其他 error → 500。
//  5. Subject 回填本次请求的 Method/Path 后注入 context（ctx +
//     RequestContext 双写），下游经 SubjectFrom / SubjectFromRequestContext
//     读取 principal 与 Claims。
//  6. Authorizer 不为 nil → 用同一 Subject 调 Authorize
//     - 拒绝 → 403
//     - 错误 → 500
//  7. 全部通过 → c.Next(ctx)
//
// 使用方式:
//
//	// 纯 BearerToken(无鉴权)
//	h.Use(mw.BearerTokenAuth(mw.WithBearerToken(token)))
//
//	// 动态凭证（API key 查库 / JWT 验签 / 外部 IdP）
//	h.Use(mw.BearerTokenAuth(mw.WithTokenVerifier(mw.TokenVerifierFunc(
//	    func(ctx context.Context, c *app.RequestContext, token string) (mw.Subject, error) {
//	        // 业务校验：查库比对 / 验签；失败按 401/403 分类返回
//	        return lookupToken(ctx, token)
//	    },
//	))))
//	// handler 侧读认证主体（静态/动态同源出口）:
//	sub, ok := mw.SubjectFrom(ctx)
//
//	// BearerToken + casbin 鉴权
//	h.Use(mw.BearerTokenAuth(
//	    mw.WithBearerToken(token),
//	    mw.WithAuthAuthorizer(&casbinAuth{...}),
//	    mw.WithAuthSubjectExtractor(func(c) mw.Subject {
//	        return mw.Subject{UserID: jwtClaims["user_id"].(string), ...}
//	    }),
//	))
//
//	// 本地联调/明确不需要认证：显式关闭（可 grep、可审计）
//	h.Use(mw.BearerTokenAuth(mw.WithAuthDisabled()))
func BearerTokenAuth(opts ...BearerTokenOption) app.HandlerFunc {
	cfg := newBearerTokenOptions(opts...)

	if cfg.Disabled {
		return func(ctx context.Context, c *app.RequestContext) { c.Next(ctx) }
	}
	if cfg.Token != "" && cfg.Verifier != nil {
		panic("mw.BearerTokenAuth: WithBearerToken/WithStaticToken and WithTokenVerifier are mutually exclusive, configure exactly one credential source")
	}
	if cfg.Token == "" && cfg.Verifier == nil {
		panic("mw.BearerTokenAuth: credential verifier not configured, call WithBearerToken(token) or WithTokenVerifier(v) first (or WithAuthDisabled() to explicitly disable auth)")
	}

	skip := make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skip[p] = true
	}

	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		if skip[path] || (cfg.SkipFunc != nil && cfg.SkipFunc(path)) {
			c.Next(ctx)
			return
		}

		// RFC 7235: scheme 大小写不敏感；格式非法统一 401，不进入校验后端。
		t, ok := cutBearerToken(string(c.GetHeader("Authorization")))
		if !ok {
			ErrorResp(c, 401, "unauthorized")
			return
		}

		var sub Subject
		if cfg.Verifier != nil {
			// 动态凭证：主体唯一来源是 Verify 的返回值（不调 SubjectExtractor，
			// 避免已校验身份被客户端可控请求头二次改写）。
			s, err := cfg.Verifier.Verify(ctx, c, t)
			if err != nil {
				switch {
				case errors.Is(err, ErrInvalidToken):
					ErrorResp(c, 401, "unauthorized")
				case errors.Is(err, ErrForbidden):
					ErrorResp(c, 403, "forbidden")
				default:
					// 校验后端故障：显式 500 + Error 日志，不伪装成 401。
					authLog.CtxError(ctx, "token verifier error", "path", path, logx.ErrKey, err)
					ErrorResp(c, 500, "authentication error")
				}
				return
			}
			sub = s
		} else {
			if subtle.ConstantTimeCompare([]byte(t), []byte(cfg.Token)) != 1 {
				ErrorResp(c, 401, "unauthorized")
				return
			}
			sub = cfg.SubjectExtractor(c)
		}

		// 路由信息以本次请求为准：verifier/extractor 填的值可能过期或不可信。
		sub.Method = string(c.Method())
		sub.Path = path

		// token 验证通过,可选鉴权（与下游读到的 Subject 同一份）。
		if cfg.Authorizer != nil {
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

		// 认证结果注入 context：ctx 与 RequestContext kv 双写（与
		// TrustedHeadersIdentity/SmartAuth 的双写出口同构），供下游 handler 读。
		ctx = context.WithValue(ctx, verifiedSubjectCtxKey{}, sub)
		c.Set(verifiedSubjectRequestKey, sub)

		c.Next(ctx)
	}
}
