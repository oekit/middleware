package contrib

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/golang-jwt/jwt/v4"
	jwthertz "github.com/hertz-contrib/jwt"
	"github.com/oekit/logx"
)

const (
	defaultJWTAlgorithm = "HS256"
	defaultJWTTimeout   = time.Hour
	defaultJWTRealm     = "ekit"
)

// jwtLog 是 JWT 组件专用 logger(构造失败等一次性告警)。
var jwtLog = logx.Delegating("middleware-jwt")

// jwtState 持有懒构造的 HertzJWTMiddleware,延迟到第一次调用 JWTAuth 时构造。
// 全部字段经 mu 保护:JWTAuth(写 opts/构造)、JWTGenerateToken(读 runtime)、
// JWTParse(读 runtime)可并发调用(2026-09-05 复审修复:原实现无锁)。
type jwtState struct {
	mu sync.Mutex
	// opts 是**配置真相源**:JWTAuth 的每次调用把 option 累积到这里。
	opts jwtOptions
	// runtime 是**当前生效的运行态**快照(原子读,无锁)。
	// 签发与验签**都以它为准** ⇒ 不可能分裂(见 jwtRuntime 注释)。
	runtime atomic.Pointer[jwtRuntime]
	// builtKey 是当前成功构造的 runtime 的 materialKey 指纹。
	// 用于判定「影响签发/验签的配置是否变了」⇒ 变了要重建。
	builtKey string
	// errLogged 保证「同一次构造失败只告警一次」,构造成功即复位。
	errLogged bool
}

// jwtRuntime 是一次成功构造(或一次失败)的**不可变快照**。
//
// ⚠️ 为什么要有它(2026-10-31 实测的真缺陷):
// 上游 HertzJWTMiddleware 把 Key/SigningAlgorithm/Timeout **拷进自己的字段**
// (构造后冻结),而全局 opts 是**可变**的。⇒ 如果「签发」读 opts、「验签」读
// instance,二次调用 JWTAuth(换 secret / 换 algorithm)后就会出现:
//   - 签发用**新** Key/算法
//   - 验签用**旧** Key/算法(冻结在 instance 里)
//
// ⇒ **签发与验签分裂**:自家 JWTGenerateToken 签的 token 被自家中间件拒绝
//
//	(实测 401 "signature is invalid");换 algorithm 则解析直接失败
//	("invalid signing algorithm")。
//
// ⇒ 修法:**签发也读 instance**(Key/SigningAlgorithm/Timeout 都是导出字段),
//
//	且 instance 在关键配置变化时**重建**。
//	⇒ 签发与验签读的是同一个对象 ⇒ 结构上不可能分裂。
type jwtRuntime struct {
	instance *jwthertz.HertzJWTMiddleware
	// inner 是 instance.MiddlewareFunc() 的预生成结果。
	// 预生成是为了避免**每个请求**都调一次 MiddlewareFunc 分配闭包。
	inner app.HandlerFunc
	// err 非 nil ⇒ 构造失败 ⇒ fail-closed(所有请求 500)。
	err error
}

// jwtOptions 是 JWTAuth 的配置集合,通过函数选项累积。
type jwtOptions struct {
	realm     string
	algorithm string
	secret    []byte
	timeout   time.Duration
	skipPaths []string
	skipFunc  func(path string) bool
}

// jwtMaterialKey 是**影响签发与验签**的配置指纹。
//
// 为什么需要它:instance 是冻结的,opts 是可变的 ⇒ 关键配置变了就必须重建
// instance,否则验签仍用旧 Key(见 jwtRuntime 的注释)。
// ⇒ 判据:只要「影响签发/验签」的配置变了,就重建。
//
// ⚠️ skipPaths/skipFunc **不进**指纹:它们只影响「跳过判定」,
//
//	与签发/验签的密钥无关(每个 handler 注册时各自快照)。
func (o *jwtOptions) materialKey() string {
	return o.realm + "\x00" + o.algorithm + "\x00" + string(o.secret) + "\x00" +
		o.timeout.String()
}

var globalJWTState jwtState

// JWTOption 是 JWTAuth 的配置选项函数类型。
type JWTOption func(*jwtOptions)

// WithJWTSecret 设置 HS256/384/512 共享密钥(对称加密用)。
// 必须设置:缺失时 JWTAuth 构造失败并 fail-closed(所有请求 500),
// 补传 secret 后再次调用 JWTAuth 即恢复。
func WithJWTSecret(secret []byte) JWTOption {
	return func(o *jwtOptions) { o.secret = secret }
}

// WithJWTAlgorithm 设置签名算法,默认 HS256。
// 支持:HS256, HS384, HS512, RS256, RS384, RS512。
func WithJWTAlgorithm(alg string) JWTOption {
	return func(o *jwtOptions) { o.algorithm = alg }
}

// WithJWTTimeout 设置 token 有效期,默认 1 小时。
// 对 JWTGenerateToken 生效:未显式传 exp 的 claims 会注入 exp=now+timeout
// (hertz-contrib/jwt 中间件要求 token 必须带 exp,缺失返回 400)。
func WithJWTTimeout(d time.Duration) JWTOption {
	return func(o *jwtOptions) { o.timeout = d }
}

// WithJWTRealm 设置认证 realm 标识,默认 "ekit"。
func WithJWTRealm(realm string) JWTOption {
	return func(o *jwtOptions) { o.realm = realm }
}

// WithJWTSkipPaths 设置不需要认证的路径(同 BearerTokenAuth)。
func WithJWTSkipPaths(paths ...string) JWTOption {
	return func(o *jwtOptions) { o.skipPaths = append(o.skipPaths, paths...) }
}

// WithJWTSkipFunc 自定义跳过逻辑(同 BearerTokenAuth)。
func WithJWTSkipFunc(fn func(path string) bool) JWTOption {
	return func(o *jwtOptions) { o.skipFunc = fn }
}

// JWTAuth 返回 hertz middleware 函数,验证请求 Authorization: Bearer {token}。
// 失败返回 401;成功把 claims 写入 ctx,hertz-contrib/jwt 内部用 c.Set("userID", ...)。
//
// 业务使用:
//
//	h.Use(contrib.JWTAuth(
//	    mw.WithJWTSecret([]byte("my-secret-key-at-least-32-bytes-long-for-HS256")),
//	    mw.WithJWTSkipPaths("/healthz", "/login"),
//	))
//
// ⚠️ fail-closed:构造失败(典型:漏传 WithJWTSecret)时返回的中间件会把
// 所有请求 500,而不是静默放行 — 认证中间件缺省方向必须是拒绝。补传
// secret 后再次调用 JWTAuth 即恢复正常(构造可重试,无 once 毒化)。
//
// ⚠️ 与 BearerTokenAuth(静态 token)互补:JWT 用于签名 token 验证,
// BearerToken 用于简单预共享。两者可同时存在但通常只用一个。
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/jwt/
// (Timeout "用于设置 token 过期时间,默认为一小时")
func JWTAuth(opts ...JWTOption) app.HandlerFunc {
	globalJWTState.mu.Lock()
	for _, opt := range opts {
		opt(&globalJWTState.opts)
	}
	// 应用默认值到 opts(JWTGenerateToken 等后续调用读 opts)
	if globalJWTState.opts.realm == "" {
		globalJWTState.opts.realm = defaultJWTRealm
	}
	if globalJWTState.opts.algorithm == "" {
		globalJWTState.opts.algorithm = defaultJWTAlgorithm
	}
	if globalJWTState.opts.timeout == 0 {
		globalJWTState.opts.timeout = defaultJWTTimeout
	}
	// 懒构造;失败可重试(后续调用补齐 secret 后重新构造,无 once 毒化)
	//
	// ⚠️ **关键配置变了必须重建 instance**:上游 HertzJWTMiddleware 把
	//    Key/SigningAlgorithm **拷进自己的字段**(冻结),而 opts 是可变的。
	//    不重建 ⇒ 验签用旧 Key、签发用新 Key ⇒ 签发与验签分裂
	//    (轮换 secret ⇒ 自家签的 token 被自家 401)。
	//    ⇒ 用 materialKey 指纹判定「影响签发/验签的配置是否变了」,
	//      变了就重建。skipPaths/skipFunc 不进指纹(与 instance 无关)。
	needRebuild := globalJWTState.runtime.Load() == nil ||
		globalJWTState.builtKey != globalJWTState.opts.materialKey()
	if needRebuild {
		// 重建前先清掉旧 runtime:构造失败时不能留着一个用旧 Key 的
		// instance 让后续请求继续验签(那会继续 401 且难以定位)。
		rt := buildJWTRuntimeLocked()
		globalJWTState.runtime.Store(rt)
		if rt.err == nil {
			globalJWTState.builtKey = globalJWTState.opts.materialKey()
			globalJWTState.errLogged = false
		}
	}
	rt := globalJWTState.runtime.Load()
	skipPaths, skipFunc := globalJWTState.opts.skipPaths, globalJWTState.opts.skipFunc
	failed := rt == nil || rt.err != nil
	var failErr error
	if failed {
		failErr = errJWTSecretRequired
		if rt != nil {
			failErr = rt.err
		}
		if !globalJWTState.errLogged {
			globalJWTState.errLogged = true
			jwtLog.Error("jwt middleware init failed; failing closed (all requests 500)",
				"err", failErr)
		}
	}
	globalJWTState.mu.Unlock()

	if failed {
		return func(_ context.Context, c *app.RequestContext) {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}

	// skipPaths/skipFunc 在外层包装生效（上游 hertz-contrib/jwt 无跳过机制，
	// 此前这两个选项被静默忽略——声明了跳过路径的鉴权实际仍在拦截）。
	//
	// ⚠️ **运行时解析当前 runtime**,不在这里捕获 instance:
	//    捕获的话,后续 JWTAuth(轮换 secret)重建了 instance 之后,
	//    本闭包仍用**旧** instance 验签 ⇒ 又变成签发/验签分裂。
	//    ⇒ 每次请求 Load 当前 runtime ⇒ 验签与签发永远读同一份快照。
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}
	return func(ctx context.Context, c *app.RequestContext) {
		cur := globalJWTState.runtime.Load()
		if cur == nil || cur.err != nil || cur.inner == nil {
			// 运行期构造失败(理论上不会:构造失败时 JWTAuth 直接返回 500 闭包)
			// ⇒ 仍然 fail-closed,不能放行。
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		path := string(c.Path())
		if skip[path] || (skipFunc != nil && skipFunc(path)) {
			c.Next(ctx)
			return
		}
		cur.inner(ctx, c)
	}
}

// buildJWTRuntimeLocked 构造 HertzJWTMiddleware 及其中间件闭包。
// 调用方必须持有 globalJWTState.mu。
//
// 返回值是**不可变快照**:instance 与 inner 一一对应,
// 签发(JWTGenerateToken)与验签(JWTAuth 返回的闭包)都读它 ⇒ 不会分裂。
func buildJWTRuntimeLocked() *jwtRuntime {
	if len(globalJWTState.opts.secret) == 0 {
		return &jwtRuntime{err: errJWTSecretRequired}
	}
	mw, err := jwthertz.New(&jwthertz.HertzJWTMiddleware{
		Realm:            globalJWTState.opts.realm,
		SigningAlgorithm: globalJWTState.opts.algorithm,
		Key:              globalJWTState.opts.secret,
		Timeout:          globalJWTState.opts.timeout,
	})
	if err != nil {
		return &jwtRuntime{err: err}
	}
	return &jwtRuntime{instance: mw, inner: mw.MiddlewareFunc()}
}

// JWTGenerateToken 用当前配置签发 token(HS256/384/512 共享密钥模式)。
// 业务在登录 handler 调:cli.POST("/login", JWTGenerateToken(MapClaims{"user_id": uid}))
//
// exp/iat 自动注入:claims 未显式带 exp 时注入 exp=now+WithJWTTimeout(默认 1h),
// 未带 iat 时注入 now。hertz-contrib/jwt 中间件要求 token 必须带 exp
// (缺失返回 400 ErrMissingExpField),官方登录签发的 payload 默认包含
// "token 的过期时间和创建时间"(2026-09-05 复审修复:原实现不注入 exp,
// 签发的 token 被自家中间件 400 拒绝)。
//
// RSA 模式需自行实现(本 helper 不覆盖 — 业务可用 HertzJWTMiddleware.TokenGenerator)。
//
// ⚠️ **签发配置取自当前 runtime(即验签用的那个 instance)**,不是取自可变 opts。
//
//	两者若不同源,轮换 secret 后就会出现「自家签的 token 被自家中间件 401」。
//	⇒ 签发与验签读同一个对象 ⇒ 结构上不可能分裂。
func JWTGenerateToken(claims jwt.MapClaims) (string, error) {
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.err != nil || rt.instance == nil {
		return "", errJWTNotInitialized
	}
	// 从 instance 取签发材料(上游把 Key/Algorithm/Timeout 拷进自己的字段)
	algorithm := rt.instance.SigningAlgorithm
	secret := rt.instance.Key
	timeout := rt.instance.Timeout

	// 拷贝 claims 后注入时间字段,不修改调用方传入的 map
	full := make(jwt.MapClaims, len(claims)+2)
	for k, v := range claims {
		full[k] = v
	}
	now := time.Now()
	if _, ok := full["exp"]; !ok {
		full["exp"] = now.Add(timeout).Unix()
	}
	if _, ok := full["iat"]; !ok {
		full["iat"] = now.Unix()
	}

	// golang-jwt v4 GetSigningMethod 在 algorithm 未注册时返回 nil pointer
	// (interface 内部 pointer 为 nil,但 interface 不等于 nil,直接 == nil 失效)。
	// 用 SignedString 内部 panic 转 error 兜底。
	var signed string
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = errJWTBadAlgorithm
			}
		}()
		method := jwt.GetSigningMethod(algorithm)
		tok := jwt.NewWithClaims(method, full)
		signed, err = tok.SignedString(secret)
	}()
	return signed, err
}

// JWTParse 验证 token 字符串并返回 claims(业务手动验证用,如
// WebSocket upgrade 前的预校验)。
func JWTParse(tokenString string) (jwt.MapClaims, error) {
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.err != nil || rt.instance == nil {
		return nil, errJWTNotInitialized
	}
	tok, err := rt.instance.ParseTokenString(tokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errJWTBadClaims
	}
	return claims, nil
}

// 错误类型
type jwtError string

func (e jwtError) Error() string { return string(e) }

const (
	errJWTSecretRequired jwtError = "ekit jwt: secret is required (use WithJWTSecret)" //nolint:gosec // 错误消息含"secret"关键词,无凭证硬编码
	errJWTNotInitialized jwtError = "ekit jwt: middleware not initialized (call JWTAuth first)"
	errJWTBadClaims      jwtError = "ekit jwt: bad claims type (expected jwt.MapClaims)"
	errJWTBadAlgorithm   jwtError = "ekit jwt: invalid signing algorithm (check WithJWTAlgorithm)"
)
