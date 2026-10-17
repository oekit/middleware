package contrib

import (
	"context"
	"net/http"
	"sync"
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
// 全部字段经 mu 保护:JWTAuth(写 opts/构造)、JWTGenerateToken(读 opts)、
// JWTParse(读 instance)可并发调用(2026-09-05 复审修复:原实现无锁)。
type jwtState struct {
	mu       sync.Mutex
	instance *jwthertz.HertzJWTMiddleware
	err      error
	opts     jwtOptions
}

var globalJWTState jwtState

// jwtErrLogOnce 构造失败只告警一次,避免每个请求刷日志。
var jwtErrLogOnce sync.Once

// jwtOptions 是 JWTAuth 的配置集合,通过函数选项累积。
type jwtOptions struct {
	realm     string
	algorithm string
	secret    []byte
	timeout   time.Duration
	skipPaths []string
	skipFunc  func(path string) bool
}

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
	if globalJWTState.instance == nil {
		globalJWTState.err = buildJWTLocked()
	}
	instance, err := globalJWTState.instance, globalJWTState.err
	skipPaths, skipFunc := globalJWTState.opts.skipPaths, globalJWTState.opts.skipFunc
	globalJWTState.mu.Unlock()

	if err != nil {
		jwtErrLogOnce.Do(func() {
			jwtLog.Error("jwt middleware init failed; failing closed (all requests 500)",
				"err", err)
		})
		return func(_ context.Context, c *app.RequestContext) {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}

	// skipPaths/skipFunc 在外层包装生效（上游 hertz-contrib/jwt 无跳过机制，
	// 此前这两个选项被静默忽略——声明了跳过路径的鉴权实际仍在拦截）。
	inner := instance.MiddlewareFunc()
	if len(skipPaths) == 0 && skipFunc == nil {
		return inner
	}
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}
	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		if skip[path] || (skipFunc != nil && skipFunc(path)) {
			c.Next(ctx)
			return
		}
		inner(ctx, c)
	}
}

// buildJWTLocked 构造 HertzJWTMiddleware;成功设置 instance 并返回 nil。
// 调用方必须持有 globalJWTState.mu。
func buildJWTLocked() error {
	if len(globalJWTState.opts.secret) == 0 {
		return errJWTSecretRequired
	}
	mw, err := jwthertz.New(&jwthertz.HertzJWTMiddleware{
		Realm:            globalJWTState.opts.realm,
		SigningAlgorithm: globalJWTState.opts.algorithm,
		Key:              globalJWTState.opts.secret,
		Timeout:          globalJWTState.opts.timeout,
	})
	if err != nil {
		return err
	}
	globalJWTState.instance = mw
	return nil
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
func JWTGenerateToken(claims jwt.MapClaims) (string, error) {
	globalJWTState.mu.Lock()
	instance := globalJWTState.instance
	algorithm := globalJWTState.opts.algorithm
	secret := globalJWTState.opts.secret
	timeout := globalJWTState.opts.timeout
	globalJWTState.mu.Unlock()
	if instance == nil {
		return "", errJWTNotInitialized
	}

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
	globalJWTState.mu.Lock()
	instance := globalJWTState.instance
	globalJWTState.mu.Unlock()
	if instance == nil {
		return nil, errJWTNotInitialized
	}
	tok, err := instance.ParseTokenString(tokenString)
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
