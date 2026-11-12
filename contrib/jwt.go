package contrib

import (
	"context"
	"fmt"
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

// jwtState 持有**显式签发/解析入口**（JWTGenerateToken/JWTParse）的默认配置
// 与运行态。全部字段经 mu 保护:JWTAuth(写 opts/构造)、JWTGenerateToken
// (读 runtime)、JWTParse(读 runtime)可并发调用(2026-09-05 复审修复:原实现无锁)。
//
// ⚠️ 验签侧**不用**本状态（#139）：JWTAuth 每次调用构造实例私有的
// opts/runtime 快照——验签密钥落全局会让第二次 JWTAuth 覆写先前实例的密钥，
// 跨服务认证边界被静默跨越（同进程多服务网关/BFF/灰度双密钥并存是常见形态）。
type jwtState struct {
	mu sync.Mutex
	// opts 是**签发缺省配置**:JWTAuth 的每次调用把 option 累积到这里，
	// JWTGenerateToken/JWTParse 读最后一次注册的缺省。
	opts jwtOptions
	// runtime 是**当前生效的签发缺省运行态**快照(原子读,无锁)。
	// JWTGenerateToken 的签发材料以它为准 ⇒ 签发与 JWTParse 不可能分裂
	// (见 jwtRuntime 注释)。
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

// globalJWTState 是**显式签发/解析入口**（JWTGenerateToken/JWTParse）的全局
// 默认状态。验签侧一律用 JWTAuth 实例私有快照（#139）——验签密钥落全局会让
// 第二次 JWTAuth 覆写先前实例的密钥，跨服务认证边界被静默跨越。
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
//
// 仅支持对称密钥算法:HS256, HS384, HS512（#185 修正失实文档——此前宣称
// 支持 RS256/RS384/RS512,但本组件只向 hertz-contrib/jwt 注入对称 Key,
// 公钥算法上游构造期必败 ErrNoPrivKeyFile;现构造期即 fail-fast 并返回
// ErrJWTBadAlgorithm,fail-closed 语义不变）。RSA 签发/验签业务直接用
// hertz-contrib/jwt 的 HertzJWTMiddleware（配 PrivKeyBytes/PrivKeyFile）。
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
//
// 匹配语义（#187）：**精确匹配**（c.Path() 原文 == 比较，非 glob，`*` 与
// "/**" 无特殊含义——写 "/api/**" 不会豁免 "/api/users"）；glob 语义在
// 根包观测/限流家族（mw.WithAccessLogSkipPaths/mw.WithRateLimitSkipPaths）。
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
// ⚠️ 实例私有验签（#139）:每次 JWTAuth 调用用**本次传入的 options** 构造
// 自己的验签快照,密钥等配置不落全局——同进程内多个 JWTAuth 实例(单进程
// 多服务网关、BFF、灰度双密钥并存)各验各的密钥,后注册的实例不会覆写先前
// 实例的密钥,跨服务认证边界不会被静默跨越。相应地,**验签密钥的轮换**不再
// 由「再次调用 JWTAuth」触发(已注册实例的快照在构造期冻结);轮换 = 用新
// 密钥构造新实例并重新注册路由。全局状态只保留显式签发/解析入口
// (JWTGenerateToken/JWTParse)的默认配置:最后一次 JWTAuth 注册的密钥成为
// 签发缺省(与既有行为一致;单实例应用签发与验签天然同源)。
//
// ⚠️ fail-closed:构造失败(典型:漏传 WithJWTSecret)时返回的中间件会把
// 所有请求 500,而不是静默放行 — 认证中间件缺省方向必须是拒绝。每个实例的
// 配置在构造期定版,补传 secret 后再次调用 JWTAuth 即得到可用的新实例。
//
// ⚠️ 与 BearerTokenAuth(静态 token)互补:JWT 用于签名 token 验证,
// BearerToken 用于简单预共享。两者可同时存在但通常只用一个。
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/jwt/
// (Timeout "用于设置 token 过期时间,默认为一小时")
func JWTAuth(opts ...JWTOption) app.HandlerFunc {
	// 实例私有配置与验签快照(#139):构造期一次性定版,闭包直接捕获。
	// 不读 globalJWTState.opts——读全局就回到了「第二次注册覆写先前实例
	// 密钥」的跨服务放行形态。全局 options 累积/「缺参继承上次配置」的
	// 写法一并废除:每个实例必须自带完整配置,缺 secret 即 fail-closed。
	local := newJWTOptions(opts...)
	rt := buildJWTRuntime(local)

	// 全局状态只维护**显式签发/解析入口**的默认配置(JWTGenerateToken/
	// JWTParse 读这里):本次注册的 options 累积进全局 opts,影响签发的材料
	// 变了就重建全局 runtime。验签侧不走这条路径。
	//
	// ⚠️ **关键配置变了必须重建 instance**:上游 HertzJWTMiddleware 把
	//    Key/SigningAlgorithm **拷进自己的字段**(冻结),而 opts 是可变的。
	//    ⇒ 用 materialKey 指纹判定「影响签发的配置是否变了」,
	//      变了就重建。skipPaths/skipFunc 不进指纹(与 instance 无关)。
	globalJWTState.mu.Lock()
	for _, opt := range opts {
		opt(&globalJWTState.opts)
	}
	if globalJWTState.opts.realm == "" {
		globalJWTState.opts.realm = defaultJWTRealm
	}
	if globalJWTState.opts.algorithm == "" {
		globalJWTState.opts.algorithm = defaultJWTAlgorithm
	}
	if globalJWTState.opts.timeout == 0 {
		globalJWTState.opts.timeout = defaultJWTTimeout
	}
	if globalJWTState.runtime.Load() == nil ||
		globalJWTState.builtKey != globalJWTState.opts.materialKey() {
		grt := buildJWTRuntimeLocked()
		// 失败快照**不 Store**（#185）：一次构造失败把全局签发 runtime 毒化
		// 成错误快照，会让此前成功注册的签发缺省（JWTGenerateToken/JWTParse
		// 的密钥来源）静默变砖。文档承诺的签发缺省 =「最后一次**成功**注册
		// 的密钥」——失败只告警，旧 runtime 原位保留继续签发；首次注册即
		// 失败时 runtime 保持 nil（JWTGenerateToken 返回 ErrJWTNotInitialized，
		// 语义不变）。失败重建每次调用都会重试（builtKey 未推进），errLogged
		// 保证同一段失败配置只告警一次。
		if grt.err == nil {
			globalJWTState.runtime.Store(grt)
			globalJWTState.builtKey = globalJWTState.opts.materialKey()
			globalJWTState.errLogged = false
		} else if !globalJWTState.errLogged {
			globalJWTState.errLogged = true
			jwtLog.Error("jwt signing default init failed (JWTGenerateToken/JWTParse keep last good key)",
				logx.ErrKey, grt.err)
		}
	}
	globalJWTState.mu.Unlock()

	if rt.err != nil {
		// 本实例构造失败 ⇒ fail-closed(所有请求 500)。实例即构造事件,
		// 每次失败的构造各告警一次。
		jwtLog.Error("jwt middleware init failed; failing closed (all requests 500)", logx.ErrKey, rt.err)
		return func(_ context.Context, c *app.RequestContext) {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}

	// skipPaths/skipFunc 在外层包装生效（上游 hertz-contrib/jwt 无跳过机制，
	// 此前这两个选项被静默忽略——声明了跳过路径的鉴权实际仍在拦截）。
	// 验签快照在构造期冻结:实例私有 ⇒ 不存在「后续 JWTAuth 覆写本实例
	// 密钥」的可能,无需每请求 Load 全局 runtime。
	skip := make(map[string]bool, len(local.skipPaths))
	for _, p := range local.skipPaths {
		skip[p] = true
	}
	skipFunc := local.skipFunc
	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		if skip[path] || (skipFunc != nil && skipFunc(path)) {
			c.Next(ctx)
			return
		}
		rt.inner(ctx, c)
	}
}

// newJWTOptions 应用 options 与默认值,返回实例私有配置(JWTAuth 每次调用
// 独享,不与全局共享)。
func newJWTOptions(opts ...JWTOption) *jwtOptions {
	o := &jwtOptions{}
	for _, opt := range opts {
		opt(o)
	}
	if o.realm == "" {
		o.realm = defaultJWTRealm
	}
	if o.algorithm == "" {
		o.algorithm = defaultJWTAlgorithm
	}
	if o.timeout == 0 {
		o.timeout = defaultJWTTimeout
	}
	return o
}

// buildJWTRuntime 构造 HertzJWTMiddleware 及其中间件闭包。
//
// 返回值是**不可变快照**:instance 与 inner 一一对应,构造后不再变化。
// JWTAuth 实例在构造期持有自己的快照验签;签发缺省(JWTGenerateToken)读
// 全局快照——同一实例注册时的密钥即签发缺省,单实例应用签发与验签同源。
//
// 构造期校验（#185 fail-fast）：secret 缺失 → ErrJWTSecretRequired；
// 非 HS256/384/512 算法 → ErrJWTBadAlgorithm（本组件只注入对称 Key，
// 公钥算法在上游必败 ErrNoPrivKeyFile——与其让上游报一个与配置无关的
// 错误，不如在这里给出指向 WithJWTAlgorithm 文档的明确失败）。
func buildJWTRuntime(o *jwtOptions) *jwtRuntime {
	if len(o.secret) == 0 {
		return &jwtRuntime{err: ErrJWTSecretRequired}
	}
	switch o.algorithm {
	case "HS256", "HS384", "HS512":
		// 仅对称密钥算法可达上游构造（#185）。
	default:
		return &jwtRuntime{err: fmt.Errorf("%w: %q (only HS256/HS384/HS512 are supported; RSA/ECDSA needs PrivKeyBytes via hertz-contrib/jwt directly)", ErrJWTBadAlgorithm, o.algorithm)}
	}
	mw, err := jwthertz.New(&jwthertz.HertzJWTMiddleware{
		Realm:            o.realm,
		SigningAlgorithm: o.algorithm,
		Key:              o.secret,
		Timeout:          o.timeout,
	})
	if err != nil {
		return &jwtRuntime{err: err}
	}
	return &jwtRuntime{instance: mw, inner: mw.MiddlewareFunc()}
}

// buildJWTRuntimeLocked 构造全局签发缺省配置的 runtime。
// 调用方必须持有 globalJWTState.mu。
func buildJWTRuntimeLocked() *jwtRuntime {
	return buildJWTRuntime(&globalJWTState.opts)
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
// ⚠️ **签发材料取自全局签发缺省 runtime**(最后一次 JWTAuth 注册的密钥,
// #139),不是取自可变 opts。验签侧是各 JWTAuth 实例的私有快照——单实例
// 应用(一个服务一套密钥)签发与验签天然同源;多实例应用若要按实例签发,
// 请用各实例注册时的密钥自行签发(或 HertzJWTMiddleware.TokenGenerator)。
func JWTGenerateToken(claims jwt.MapClaims) (string, error) {
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.err != nil || rt.instance == nil {
		return "", ErrJWTNotInitialized
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
				err = ErrJWTBadAlgorithm
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
		return nil, ErrJWTNotInitialized
	}
	tok, err := rt.instance.ParseTokenString(tokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrJWTBadClaims
	}
	return claims, nil
}

// JWT 组件的可分流错误哨兵（#186）：JWTGenerateToken/JWTParse/JWTAuth 返回
// 的错误可经 errors.Is 与下列哨兵判定，无需字符串匹配。字符串值保持历史
// 原文（既有日志/断言兼容）。
type jwtError string

func (e jwtError) Error() string { return string(e) }

const (
	// ErrJWTSecretRequired 未配置签名密钥（漏传 WithJWTSecret）。
	ErrJWTSecretRequired jwtError = "ekit jwt: secret is required (use WithJWTSecret)" //nolint:gosec // 错误消息含"secret"关键词,无凭证硬编码
	// ErrJWTNotInitialized 尚无可用签发缺省（JWTAuth 从未成功注册——构造
	// 失败不毒化全局 runtime，#185）：区分「配置错误须告警」与「token 无效
	// （常态拒绝）」的分流哨兵。
	ErrJWTNotInitialized jwtError = "ekit jwt: middleware not initialized (call JWTAuth first)"
	// ErrJWTBadClaims 验证通过但 claims 类型不是 jwt.MapClaims。
	ErrJWTBadClaims jwtError = "ekit jwt: bad claims type (expected jwt.MapClaims)"
	// ErrJWTBadAlgorithm 签名算法不可用（仅支持 HS256/HS384/HS512，#185）。
	ErrJWTBadAlgorithm jwtError = "ekit jwt: invalid signing algorithm (check WithJWTAlgorithm)"
)
