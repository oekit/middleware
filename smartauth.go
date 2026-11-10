package mw

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/logx"
)

// smartAuthLog 带 component 属性的 scoped logger（平台契约 §3，与
// identityLog 同款）：仅记安全信号（立证失败/鉴权后端故障），认证 401
// 静默（与 BearerTokenAuth 同口径——探测噪声不落日志）。
var smartAuthLog = logx.Delegating("middleware-smartauth")

// DefaultReplayWindow 是网关签名的默认时间窗（90s，与 zeus smart_auth 同
// 口径）：签名带时间戳，双向偏差超过窗口即拒——签名是可重放的凭据，
// 时间窗是唯一的重放防线。
const DefaultReplayWindow = 90 * time.Second

// GatewayAuthorizedValue 是网关「已集中鉴权」标记头的取值（X-Auth-Authorized
// 的值 "1"）。网关注入侧与 SmartRBAC 判定侧共用本常量，防两处字面量漂移。
const GatewayAuthorizedValue = "1"

// TrustHeaderNames 是网关信任头的名字集合（#169）。
//
// 零值可用：每个字段为空时取缺省 X-Auth-* 名（与 TrustedHeadersIdentity
// 的缺省头名同族）。全部字段参与签名规范串（GatewayCanonical）——
// 「签名不覆盖的头就是链上可篡改的头」，因此名字集合与规范串必须同源演进。
type TrustHeaderNames struct {
	// Signature 签名头（HMAC-SHA256 规范串签名）。默认 "X-Auth-Signature"。
	Signature string
	// Timestamp 签名时间戳头（Unix 秒）。默认 "X-Auth-Timestamp"。
	Timestamp string
	// UID 用户唯一标识头。默认 "X-Auth-User-ID"。
	UID string
	// Username 用户名头。默认 "X-Auth-Username"。
	Username string
	// RoleIDs 角色列表头（分隔符拼接）。默认 "X-Auth-Role-IDs"。
	RoleIDs string
	// Authorized 网关「已集中鉴权」标记头（值 GatewayAuthorizedValue）。
	// 默认 "X-Auth-Authorized"。
	Authorized string
	// MCP 网关注入的 MCP 标记头（语义由业务定义，库侧只透传）。
	// 默认 "X-Auth-MCP"。
	MCP string
}

// DefaultTrustHeaderNames 返回缺省头名集合。
func DefaultTrustHeaderNames() TrustHeaderNames {
	return TrustHeaderNames{}.resolved()
}

// resolved 对空字段填充缺省头名（启动期/构造期调用一次，请求热路径零解析）。
func (n TrustHeaderNames) resolved() TrustHeaderNames {
	if n.Signature == "" {
		n.Signature = "X-Auth-Signature"
	}
	if n.Timestamp == "" {
		n.Timestamp = "X-Auth-Timestamp"
	}
	if n.UID == "" {
		n.UID = "X-Auth-User-ID"
	}
	if n.Username == "" {
		n.Username = "X-Auth-Username"
	}
	if n.RoleIDs == "" {
		n.RoleIDs = "X-Auth-Role-IDs"
	}
	if n.Authorized == "" {
		n.Authorized = "X-Auth-Authorized"
	}
	if n.MCP == "" {
		n.MCP = "X-Auth-MCP"
	}
	return n
}

// all 返回全部信任头名（剥头/多值头检查的枚举面）。
func (n TrustHeaderNames) all() []string {
	return []string{n.Signature, n.Timestamp, n.UID, n.Username, n.RoleIDs, n.Authorized, n.MCP}
}

// validateTrustHeaderNames 校验头名两两不同：两个角色共用一个头名时，签名
// 规范串出现重复行、剥头清单互相覆盖，信任模型静默畸变。多字段冲突逐条
// 汇总（errors.Join 聚合）——一次炸出全部冲突，而不是逐个挤牙膏。
func validateTrustHeaderNames(n TrustHeaderNames) error {
	names := n.resolved().all()
	var errs []error
	for i := range len(names) {
		for j := i + 1; j < len(names); j++ {
			if names[i] == names[j] {
				errs = append(errs, fmt.Errorf("mw: trust header name %q used by two roles", names[i]))
			}
		}
	}
	return errors.Join(errs...)
}

// GatewayTrust 是网关信任头的立证配置（#169）：网关注入的身份头**不是**天然
// 可信的——客户端直连时可自带同名头冒充任意身份。立证路径二选一或并存
// （「仅信任内网来源/网关签名头」）：
//
//   - 来源立证：对端地址是回环或落在 TrustedSources 网段（网关/边车同机、
//     内网直连拓扑）；
//   - 签名立证：Signature 头 = HMAC-SHA256(Secret, GatewayCanonical) 且
//     Timestamp 在 ReplayWindow 内（防重放）。
//
// 两条都不成立 ⇒ 请求按伪造处理（VerifyGatewayTrust 剥头拒绝）。
type GatewayTrust struct {
	// Secret HMAC-SHA256 共享密钥（签名立证路径）。与 TrustedSources 至少
	// 配一个——都没有时 SmartAuth 构造期 panic（没有任何立证路径的
	// 「信任」是纯 fail-open）。
	Secret []byte
	// ReplayWindow 签名时间窗，<=0 取 DefaultReplayWindow（90s）。
	ReplayWindow time.Duration
	// HeaderNames 信任头名集合，零值取 DefaultTrustHeaderNames。
	HeaderNames TrustHeaderNames
	// TrustedSources 来源立证的内网网段（netip.Prefix）。回环地址恒可信
	// （网关/边车同机形态），无须列入。IPv4/IPv6 前缀均可。
	TrustedSources []netip.Prefix
}

// headerNames 返回填充缺省后的头名集合。
func (t GatewayTrust) headerNames() TrustHeaderNames { return t.HeaderNames.resolved() }

// replayWindow 返回生效的时间窗（零值回退 DefaultReplayWindow）。
func (t GatewayTrust) replayWindow() time.Duration {
	if t.ReplayWindow > 0 {
		return t.ReplayWindow
	}
	return DefaultReplayWindow
}

// GatewayCanonical 返回网关签名规范串——信任模型最易漂移的细节，**网关注入
// 侧与服务校验侧必须同源**（网关侧用 GatewaySign，服务侧 VerifyGatewayTrust
// 同一份实现），杜绝「两侧规范串不一致、签名永远对不上」：
//
//	method "\n" requestURI "\n" uid "\n" username "\n" roleIDs "\n" authorized "\n" mcp "\n" timestamp
//
// 各字段取请求上的**原始头值**（不 trim；缺省为空串占行）：method 为请求
// 方法、requestURI 为请求行 URI（path?query）。全部身份头都进规范串——
// 签名不覆盖的头就是链上可篡改的头（Authorized 不被覆盖的话，链上加一行
// X-Auth-Authorized: 1 就能跳过本地 RBAC）。uid/uri/时间戳入串：签名绑定
// 身份与端点，同一签名换用户或换路径重放都会失配。
func GatewayCanonical(t GatewayTrust, c *app.RequestContext) string {
	n := t.headerNames()
	return strings.Join([]string{
		string(c.Method()),
		string(c.Request.URI().RequestURI()),
		string(c.GetHeader(n.UID)),
		string(c.GetHeader(n.Username)),
		string(c.GetHeader(n.RoleIDs)),
		string(c.GetHeader(n.Authorized)),
		string(c.GetHeader(n.MCP)),
		string(c.GetHeader(n.Timestamp)),
	}, "\n")
}

// GatewaySign 计算签名头值（网关注入侧用）：先注入身份头与 Timestamp
// （Unix 秒），再调本函数，把返回值写进 Signature 头。
//
//	mac, err := mw.GatewaySign(trust, c) // 身份头/Timestamp 已注入
//	if err != nil { ... }
//	c.Request.Header.Set("X-Auth-Signature", mac)
//
// Secret 为空 / UID 或 Timestamp 头缺失时返回错误（规范串对这三者是强绑定，
// 缺任一都签不出可被 VerifyGatewayTrust 接受的签名）。
func GatewaySign(t GatewayTrust, c *app.RequestContext) (string, error) {
	if len(t.Secret) == 0 {
		return "", errors.New("mw: GatewaySign: empty secret")
	}
	n := t.headerNames()
	if len(c.GetHeader(n.UID)) == 0 {
		return "", errors.New("mw: GatewaySign: missing uid header")
	}
	if len(c.GetHeader(n.Timestamp)) == 0 {
		return "", errors.New("mw: GatewaySign: missing timestamp header")
	}
	mac := hmac.New(sha256.New, t.Secret)
	mac.Write([]byte(GatewayCanonical(t, c)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyGatewayTrust 对网关信任头做一次立证（HMAC + 时间窗 / 内网来源，
// #169 建议形态原样交付）：成功返回 Subject（身份头保留——已立证，下游
// SmartRBAC/TrustedHeadersIdentity 等可继续读），**失败即未认证**且把全部
// 信任头从请求上剥掉（剥头防伪造：失败请求不得携带伪造身份头进入后续
// 链路——skip_auth 路径伪造头污染 claims 的教训见 #136）。
//
// 判定顺序（全部失败路径同效：返回 (Subject{}, false) 且剥头）：
//
//  1. 任一信任头出现**多值**（同名头注入）⇒ 伪造信号，直接拒；
//  2. UID 与 Signature 均缺席 ⇒ 未呈现网关立证（false，调用方决定降级路径）；
//  3. UID 缺席（仅签名头）⇒ 立证不成立（身份是规范串的强绑定行）；
//  4. 来源立证（回环 / TrustedSources）与签名立证（HMAC-SHA256 + 时间窗）
//     至少一个成立，否则按伪造处理；
//  5. 成功：剥掉已消费的 Signature/Timestamp 头（防下游再解释出第二种
//     口径），身份头保留，组装 Subject（Roles 按 "," 切分去空项，字符串
//     精确匹配、无数字强转——与 TrustedClaims 同口径）。
//
// Subject.Claims 恒非 nil：username/mcp 键在对应头非空时出现。
func VerifyGatewayTrust(t GatewayTrust, c *app.RequestContext) (Subject, bool) {
	n := t.headerNames()
	if sub, ok := t.verify(c, n); ok {
		// 立证成立：签名/时间头已消费（规范串已吸收），剥掉防下游二次解释。
		c.Request.Header.Del(n.Signature)
		c.Request.Header.Del(n.Timestamp)
		return sub, true
	}
	stripTrustHeaders(c, n)
	return Subject{}, false
}

// verify 是立证的主体判定（不剥头，由 VerifyGatewayTrust 统一收口）。
func (t GatewayTrust) verify(c *app.RequestContext, n TrustHeaderNames) (Subject, bool) {
	// 多值信任头 = 请求走私式头注入的伪造信号，fail-closed。
	for _, name := range n.all() {
		if len(c.Request.Header.PeekAll(name)) > 1 {
			return Subject{}, false
		}
	}

	uid := strings.TrimSpace(string(c.GetHeader(n.UID)))
	sig := string(c.GetHeader(n.Signature))
	if uid == "" && sig == "" {
		return Subject{}, false // 未呈现网关立证（无头可剥、无头可信）
	}
	if uid == "" {
		return Subject{}, false // 缺 UID：签名/来源都无从绑定身份
	}
	if !t.sourceTrusted(c) && !t.signatureOK(c, n) {
		return Subject{}, false
	}

	sub := Subject{
		UserID: uid,
		Roles:  splitRoleIDs(string(c.GetHeader(n.RoleIDs))),
		Claims: map[string]any{},
		Method: string(c.Method()),
		Path:   string(c.Path()),
	}
	// Username 取 TrimSpace 后的值（与 TrustedHeadersIdentity 同口径）；
	// 规范串仍绑定原始头值（Trim 是原始值的函数，不可被利用）。
	if v := strings.TrimSpace(string(c.GetHeader(n.Username))); v != "" {
		sub.Claims["username"] = v
	}
	if v := string(c.GetHeader(n.MCP)); v != "" {
		sub.Claims["mcp"] = v
	}
	return sub, true
}

// sourceTrusted 判定来源立证：对端地址是回环（网关/边车同机形态）或落在
// TrustedSources 网段。取连接对端地址（c.RemoteAddr）——不读任何转发头，
// X-Forwarded-For 是客户端可控的（#83 同口径）。
func (t GatewayTrust) sourceTrusted(c *app.RequestContext) bool {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, p := range t.TrustedSources {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// signatureOK 判定签名立证：时间窗（重放防护）+ HMAC-SHA256 常量时间比较。
func (t GatewayTrust) signatureOK(c *app.RequestContext, n TrustHeaderNames) bool {
	sig := string(c.GetHeader(n.Signature))
	if sig == "" || len(t.Secret) == 0 {
		return false
	}
	ts, err := strconv.ParseInt(string(c.GetHeader(n.Timestamp)), 10, 64)
	if err != nil {
		return false
	}
	at := time.Unix(ts, 0)
	now := time.Now()
	// 时间窗按双向偏差取大者（过去/未来的签名都在窗口语义内被限）。
	if max(now.Sub(at), at.Sub(now)) > t.replayWindow() {
		return false
	}
	mac := hmac.New(sha256.New, t.Secret)
	mac.Write([]byte(GatewayCanonical(t, c)))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

// splitRoleIDs 按 "," 切分角色头并去空项（"1,,2 " → ["1","2"]）。角色按
// 原样字符串保留，绝不数字强转（与 TrustedClaims.Roles 同口径——"1a2" 不
// 等于 "1"，永不命中）。
func splitRoleIDs(raw string) []string {
	var roles []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			roles = append(roles, item)
		}
	}
	return roles
}

// stripTrustHeaders 把全部信任头从请求上剥掉（剥头防伪造）：立证不成立的
// 请求里这些头是纯客户端可控值，留着就是给下游直读头的代码递刀。
func stripTrustHeaders(c *app.RequestContext, n TrustHeaderNames) {
	for _, name := range n.all() {
		c.Request.Header.Del(name)
	}
}

// JWTParseFunc 是本地 JWT 模式的令牌校验面（#169）：token 进、Subject 出，
// 签名/有效期等校验由 parse 负责。与 kitx/jwt 的 Parse/ParseSymmetric/
// Manager.ParseTyped 同形收窄（它们返回 *jwt.Claims{RegisteredClaims, Extra}），
// 业务 adapter 包一层即得——middleware→kitx 依赖方向本仓 go.mod 并不存在，
// 校验面经本函数缝注入，两个模块都不新增依赖：
//
//	parse := func(ctx context.Context, token string) (mw.Subject, error) {
//	    claims, err := kitxjwt.ParseSymmetric(token, secret)
//	    if err != nil {
//	        return mw.Subject{}, err
//	    }
//	    sub := mw.Subject{UserID: claims.Subject, Claims: claims.Extra}
//	    sub.Roles, _ = claims.Extra["roles"].([]string)
//	    return sub, nil
//	}
//
// 返回错误即未认证（SmartAuth 401）。返回 Subject 的 Method/Path 由
// SmartAuth 回填（parse 侧填的同名字段被覆盖——路由信息以请求为准）。
type JWTParseFunc func(ctx context.Context, token string) (Subject, error)

// AuthMode 是 SmartAuth 双模式的切换/组合形态（#169「两模式可配置切换/
// 组合」）。
type AuthMode int

const (
	// AuthModeAuto（默认，组合）：请求呈现网关立证走网关信任（立证失败
	// 401——呈现了立证却验不过是可疑流量，不再降级）；未呈现则落本地
	// JWT 兜底。
	AuthModeAuto AuthMode = iota
	// AuthModeGatewayOnly（切换）：仅网关信任——未呈现立证或立证失败都
	// 401，本地 JWT 不启用。
	AuthModeGatewayOnly
	// AuthModeLocalOnly（切换）：仅本地 JWT——信任头一律剥除（防伪造），
	// 身份只来自令牌。
	AuthModeLocalOnly
)

// SmartAuthOptions 是 SmartAuth 的配置。
type SmartAuthOptions struct {
	// Mode 双模式切换/组合形态，零值取 AuthModeAuto。
	Mode AuthMode
	// SkipPaths 不需要认证的路径（如 /healthz）。命中即放行——但信任头
	// 照样剥除：skip ≠ 可携带伪造身份头继续（#136 教训）。
	SkipPaths []string
	// SkipFunc 自定义跳过逻辑（与 SkipPaths 任一命中即跳过）。
	SkipFunc func(path string) bool
	// Authorizer 认证通过后的内联鉴权钩子（可选，与 BearerTokenAuth 同
	// 语义：拒绝 403 / 后端故障 500）。分层装配（SmartAuth + SmartRBAC）
	// 时通常不设，鉴权由 SmartRBAC 承担。
	Authorizer Authorizer
	// AdminRoles 命中任一即视为 admin 的角色清单（注入 TrustedClaims.IsAdmin，
	// 判定口径与 TrustedHeadersIdentity 同源）。
	AdminRoles []string
	// RoleMatcher 自定义 admin 判定（与 AdminRoles 任一命中即可）。
	RoleMatcher func(role string) bool
}

// SmartAuthOption 配置 SmartAuth。
type SmartAuthOption func(*SmartAuthOptions)

// WithSmartAuthMode 设置双模式形态。
func WithSmartAuthMode(m AuthMode) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.Mode = m }
}

// WithSmartAuthSkipPaths 设置免认证路径。
func WithSmartAuthSkipPaths(paths ...string) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.SkipPaths = append(o.SkipPaths, paths...) }
}

// WithSmartAuthSkipFunc 设置自定义跳过逻辑（返回 true 表示免认证）。
func WithSmartAuthSkipFunc(fn func(path string) bool) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.SkipFunc = fn }
}

// WithSmartAuthAuthorizer 设置认证通过后的内联鉴权钩子。
func WithSmartAuthAuthorizer(a Authorizer) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.Authorizer = a }
}

// WithSmartAuthAdminRoles 设置 admin 判定的角色清单。
func WithSmartAuthAdminRoles(roles ...string) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.AdminRoles = append(o.AdminRoles, roles...) }
}

// WithSmartAuthAdminMatcher 设置自定义 admin 判定函数。
func WithSmartAuthAdminMatcher(fn func(role string) bool) SmartAuthOption {
	return func(o *SmartAuthOptions) { o.RoleMatcher = fn }
}

// SmartAuth 返回双模式认证中间件（#169）：网关信任头立证 vs 本地 JWT 兜底，
// 两模式可切换/组合——网关集中鉴权 + 内网服务本地兜底的通用部署形态，
// 信任模型的安全细节（规范串/时间窗/剥头防伪造）单点收编在本文件，
// 下游多服务同款装配不再各自手搓漂移。
//
// 构造期校验（fail-fast，#97 同哲学）：
//
//	parse 与 trust 均为 nil ⇒ panic（没有任何认证面的「认证中间件」是纯
//	fail-open）；AuthModeGatewayOnly 配 nil trust / AuthModeLocalOnly 配
//	nil parse ⇒ panic；trust 非 nil 但 Secret 与 TrustedSources 均空 ⇒
//	panic（无立证路径）；信任头名两两冲突 ⇒ panic（errors.Join 一次列全）。
//
// 请求流程：
//
//  1. SkipPaths/SkipFunc 命中 ⇒ 剥信任头后放行（免认证路径不留伪造头）；
//  2. 网关路径（trust 非 nil 且非 LocalOnly）：VerifyGatewayTrust 立证——
//     成功用网关 Subject（身份头保留）；失败已剥头，GatewayOnly 返 401，
//     Auto 落本地；
//  3. 本地路径：剥信任头后取 Authorization Bearer 交 parse（kitx/jwt 等
//     校验面），失败 401；
//  4. Authorizer（可选）：拒绝 403 / 故障 500；
//  5. 成功：Subject 注入 ctx（TrustedClaims 同源双写——handler 侧
//     ClaimsFrom/ClaimsFromRequestContext 零样板读身份），c.Next(ctx)。
//
// 用法（组合形态，下游 6 服务同款装配）：
//
//	h.Use(mw.SmartAuth(
//	    kitxParse,                              // 本地 JWT 兜底（kitx/jwt 包一层）
//	    &mw.GatewayTrust{Secret: secret},       // 网关信任头立证
//	))
//	h.Use(mw.SmartRBAC(localRBAC))              // 网关已鉴权跳过 / 本地 RBAC 兜底
func SmartAuth(parse JWTParseFunc, trust *GatewayTrust, opts ...SmartAuthOption) app.HandlerFunc {
	cfg := &SmartAuthOptions{}
	for _, opt := range opts {
		opt(cfg)
	}

	if parse == nil && trust == nil {
		panic("mw.SmartAuth: neither JWTParseFunc nor GatewayTrust configured (would fail-open)")
	}
	switch cfg.Mode {
	case AuthModeAuto:
		// 两个入口至少有一个（上面已校验）。
	case AuthModeGatewayOnly:
		if trust == nil {
			panic("mw.SmartAuth: AuthModeGatewayOnly requires GatewayTrust")
		}
	case AuthModeLocalOnly:
		if parse == nil {
			panic("mw.SmartAuth: AuthModeLocalOnly requires JWTParseFunc")
		}
	default:
		panic(fmt.Sprintf("mw.SmartAuth: unknown AuthMode %d", int(cfg.Mode)))
	}
	if trust != nil {
		if len(trust.Secret) == 0 && len(trust.TrustedSources) == 0 {
			panic("mw.SmartAuth: GatewayTrust with empty Secret and no TrustedSources (no attestation path)")
		}
		if err := validateTrustHeaderNames(trust.HeaderNames); err != nil {
			panic("mw.SmartAuth: " + err.Error())
		}
	}

	names := DefaultTrustHeaderNames()
	if trust != nil {
		names = trust.headerNames()
	}
	// admin 口径与 TrustedHeadersIdentity 同源（resolveTrustedIdentityConfig
	// 单一实现）：注入的 TrustedClaims.IsAdmin 与 OverrideTrustedClaims 的
	// 重算走同一判定，不存在两套 admin 口径。
	admin := resolveTrustedIdentityConfig(TrustedIdentityConfig{
		UserIDHeader:   names.UID,
		UsernameHeader: names.Username,
		RolesHeader:    names.RoleIDs,
		AdminRoles:     cfg.AdminRoles,
		RoleMatcher:    cfg.RoleMatcher,
	})

	skip := make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skip[p] = true
	}

	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		if skip[path] || (cfg.SkipFunc != nil && cfg.SkipFunc(path)) {
			// 免认证路径同样剥头：skip ≠ 可携带伪造身份头继续（#136）。
			stripTrustHeaders(c, names)
			c.Next(ctx)
			return
		}

		var sub Subject
		attested := false
		if trust != nil && cfg.Mode != AuthModeLocalOnly {
			s, ok := VerifyGatewayTrust(*trust, c) // false 路径已剥头
			if ok {
				sub, attested = s, true
			} else if cfg.Mode == AuthModeGatewayOnly {
				// 呈现立证却验不过（或未呈现）在 gateway-only 下都是 401；
				// 伪造尝试是安全信号，Warn 留痕（认证 401 本身静默）。
				smartAuthLog.CtxWarn(ctx, "gateway trust verification failed",
					"path", path, "remote", c.RemoteAddr().String())
				ErrorResp(c, 401, "unauthorized")
				return
			}
			// AuthModeAuto：落本地 JWT 兜底（信任头已剥净，伪造头进不了链路）。
		} else {
			// 无立证面（trust nil）或 LocalOnly：信任头一律剥除——身份只
			// 来自本地 JWT，头伪造面从结构上关死。
			stripTrustHeaders(c, names)
		}

		if !attested {
			token, ok := cutBearerToken(string(c.GetHeader("Authorization")))
			if !ok {
				ErrorResp(c, 401, "unauthorized")
				return
			}
			s, err := parse(ctx, token)
			if err != nil {
				ErrorResp(c, 401, "unauthorized")
				return
			}
			sub = s
			sub.Method = string(c.Method())
			sub.Path = string(c.Path())
		}

		if cfg.Authorizer != nil {
			allowed, err := cfg.Authorizer.Authorize(ctx, c, sub)
			if err != nil {
				smartAuthLog.CtxError(ctx, "authorizer error", "path", path, logx.ErrKey, err)
				ErrorResp(c, 500, "authorization error")
				return
			}
			if !allowed {
				ErrorResp(c, 403, "forbidden")
				return
			}
		}

		ctx = injectSmartClaims(ctx, c, sub, admin)
		c.Next(ctx)
	}
}

// injectSmartClaims 把已立证/已校验的 Subject 注入 TrustedClaims 读取面
// （ctx 与 RequestContext kv 双写，与 TrustedHeadersIdentity 同 key 同口径）：
// handler 侧 ClaimsFrom(ctx) 零样板读身份，网关/本地两模式同一读取口。
func injectSmartClaims(ctx context.Context, c *app.RequestContext, sub Subject, admin *resolvedTrustedIdentityConfig) context.Context {
	claims := TrustedClaims{
		UserID:    sub.UserID,
		Anonymous: sub.UserID == "",
		Roles:     sub.Roles,
	}
	if u, ok := sub.Claims["username"].(string); ok {
		claims.Username = u
	}
	claims.IsAdmin = admin.matchAdmin(claims.Roles)
	ctx = context.WithValue(ctx, trustedClaimsCtxKey{}, claims)
	ctx = context.WithValue(ctx, trustedIdentityCfgKey{}, admin)
	c.Set(trustedClaimsRequestKey, claims)
	return ctx
}

// SmartRBACOptions 是 SmartRBAC 的配置。
type SmartRBACOptions struct {
	// AuthorizedHeader 网关「已集中鉴权」标记头。默认 "X-Auth-Authorized"
	// （TrustHeaderNames.Authorized 缺省同名）。
	AuthorizedHeader string
}

// SmartRBACOption 配置 SmartRBAC。
type SmartRBACOption func(*SmartRBACOptions)

// WithSmartRBACAuthorizedHeader 覆盖「已集中鉴权」标记头名（网关注入名
// 非缺省时用）。
func WithSmartRBACAuthorizedHeader(name string) SmartRBACOption {
	return func(o *SmartRBACOptions) { o.AuthorizedHeader = name }
}

// SmartRBAC 返回「网关已鉴权放行，否则本地 RBAC 兜底」的鉴权中间件（#169，
// zeus SmartRBAC 同款装配面）：
//
//	Authorized 头 == GatewayAuthorizedValue（"1"）⇒ 网关已做过集中鉴权，
//	直接 c.Next 跳过本地 RBAC；否则调 local 走本地 RBAC（casbin 等）兜底。
//
// # 部署前提（信任边界）
//
// Authorized 头必须不可被客户端伪造——直连部署时客户端带
// X-Auth-Authorized: 1 就能跳过本地 RBAC。两种安全装配：
//
//  1. 置于 SmartAuth 之后：立证失败的请求已被剥头（VerifyGatewayTrust /
//     本地路径同效），Authorized 只可能来自已立证的网关注入；
//  2. trusted-gateway 形态：网关保证剥掉客户端同名头（同
//     TrustedHeadersIdentity 的部署契约）。
//
// local 担任本地 RBAC 环节：放行须自行 c.Next(ctx)，拒绝写响应并 Abort
// （ErrorResp 自动 Abort）。local 为 nil 构造期 panic——nil 会在网关未
// 鉴权时静默放行（fail-open），兜底必须显式提供。
//
// 用法：
//
//	h.Use(mw.SmartAuth(parse, trust))
//	h.Use(mw.SmartRBAC(func(ctx context.Context, c *app.RequestContext) {
//	    claims, _ := mw.ClaimsFrom(ctx)
//	    if !enforcer.Enforce(claims.UserID, string(c.Path()), string(c.Method())) {
//	        mw.ErrorResp(c, 403, "forbidden")
//	        return
//	    }
//	    c.Next(ctx)
//	}))
func SmartRBAC(local app.HandlerFunc, opts ...SmartRBACOption) app.HandlerFunc {
	if local == nil {
		panic("mw.SmartRBAC: nil local RBAC handler (would fail-open when the gateway did not authorize)")
	}
	cfg := &SmartRBACOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.AuthorizedHeader == "" {
		cfg.AuthorizedHeader = DefaultTrustHeaderNames().Authorized
	}

	return func(ctx context.Context, c *app.RequestContext) {
		if string(c.GetHeader(cfg.AuthorizedHeader)) == GatewayAuthorizedValue {
			c.Next(ctx) // 网关已集中鉴权：跳过本地 RBAC
			return
		}
		local(ctx, c) // 本地 RBAC 兜底
	}
}
