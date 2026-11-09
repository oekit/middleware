package mw

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/oekit/logx"
)

// identityLog 带 component 属性的 scoped logger（平台契约 §3）。
var identityLog = logx.Delegating("middleware-identity")

// TrustedClaims 是 TrustedHeadersIdentity 解析出的请求身份，经
// ClaimsFrom / ClaimsFromRequestContext 在 handler 侧多处读取。
//
// 字段由中间件在每请求内**单次解析**注入 ctx——handler 不再各自读头
// （octopus 形态：16 处 GetUserId/GetRole 样板、每请求重复解析）。
type TrustedClaims struct {
	// UserID 网关验签后的用户唯一标识（X-Auth-User-ID）。匿名身份为空。
	UserID string
	// Username 网关注入的用户名（X-Auth-Username）。可为空。
	Username string
	// Roles 网关注入的角色列表（X-Auth-Role-IDs，按分隔符切分）。
	// 角色按**原样字符串**参与匹配，绝不做数字强转——octopus GetRole 的
	// 宽容数字解析会把 "1a2" 静默吞成 12、错配 admin 判定；本类型从结构上
	// 排除该畸变（"1a2" 不等于 "1"，永不命中）。
	Roles []string
	// IsAdmin Roles 命中 AdminRoles（或 RoleMatcher）任一即为 true。
	// 判定口径在启动期解析一次，热更角色配置不会造成新旧请求口径交替。
	IsAdmin bool
	// Anonymous 显式匿名身份（免认证路径无身份头、Missing=AnonymousClaims
	// 时注入）。区分「中间件未注册」（ClaimsFrom 返回 ok=false）与
	// 「已解析、身份为匿名」（本字段为 true）。
	Anonymous bool
	// Rewritten 身份在本次请求内已被 OverrideTrustedClaims 可信覆写（#136）。
	// 审计/运维可据此辨识「这请求的身份被路由级改写过」；同时它是覆写口
	// 的单向闸——已置位的 claims 拒绝再次覆写（防链内多方互相覆盖）。
	Rewritten bool
}

// TrustedMissingPolicy 决定身份头缺失（UserIDHeader 无值）时的行为。
type TrustedMissingPolicy int

const (
	// MissingReject 拒载请求：401（默认，fail-closed）。受保护路径上网关
	// 应注入身份头，缺头说明链路配置有误——静默放行等于重开认证 fail-open
	// 的口子（对照 #97 的统一口径：误配必须炸响，不是无声吞掉）。
	MissingReject TrustedMissingPolicy = iota
	// AnonymousClaims 注入显式匿名身份后放行（免认证路径形态：网关对公开
	// 路径不注入身份头，handler 仍可经 ClaimsFrom 拿到 Anonymous=true）。
	AnonymousClaims
)

// TrustedBadRolesPolicy 决定角色头解析失败（出现空项/空值等非法形态）时的
// 行为——语义显式、由配置选，不静默吞字符。
type TrustedBadRolesPolicy int

const (
	// BadRolesReject 拒载请求：401（默认，fail-closed）。脏角色头视为
	// 不可信信号（网关不该产出非法形态）。
	BadRolesReject TrustedBadRolesPolicy = iota
	// BadRolesDrop 丢弃非法项、保留合法角色继续（打 Warn 留信号）。
	BadRolesDrop
	// BadRolesAnonymous 整体降级为匿名身份继续（打 Warn 留信号）——
	// 宁可降权不可错配：脏数据不参与 IsAdmin 判定。
	BadRolesAnonymous
)

// TrustedIdentityConfig 是 TrustedHeadersIdentity 的配置（启动期解析一次）。
//
// 零值可用：三个头名缺省对齐 zeus 网关注入约定（X-Auth-User-ID /
// X-Auth-Username / X-Auth-Role-IDs），Missing/BadRoles 缺省均为拒载。
type TrustedIdentityConfig struct {
	// UserIDHeader 用户 ID 注入头。默认 "X-Auth-User-ID"。
	UserIDHeader string
	// UsernameHeader 用户名注入头。默认 "X-Auth-Username"。可为空——
	// 网关未注入用户名时 Username 留空。
	UsernameHeader string
	// RolesHeader 角色列表注入头（分隔符拼接的多角色）。默认
	// "X-Auth-Role-IDs"。头整体缺失时 Roles 为 nil（合法：无角色用户）。
	RolesHeader string
	// RolesSeparator 角色头内的分隔符。默认 ","。
	RolesSeparator string
	// AdminRoles 命中任一角色即 IsAdmin=true 的角色清单（启动期构建
	// 集合，热更不生效——角色口径在全请求生命周期内稳定）。
	AdminRoles []string
	// RoleMatcher 自定义 admin 判定函数（与 AdminRoles 任一命中即可，
	// 优先于集合匹配）。需要「管理员角色集动态下发」的场景用它在启动期
	// 固化一次解析结果。
	RoleMatcher func(role string) bool
	// Missing 身份头缺失时的行为。默认 MissingReject（401）；服务含
	// 免认证路径时显式置 AnonymousClaims。
	Missing TrustedMissingPolicy
	// BadRoles 角色头解析失败时的行为。默认 BadRolesReject（401）。
	BadRoles TrustedBadRolesPolicy
}

// resolvedTrustedIdentityConfig 是启动期解析完毕的配置（头名/分隔符定版、
// AdminRoles 已建集合），请求热路径上零重复解析。
type resolvedTrustedIdentityConfig struct {
	userIDHeader   string
	usernameHeader string
	rolesHeader    string
	rolesSep       string
	adminRoles     map[string]struct{}
	roleMatcher    func(role string) bool
	missing        TrustedMissingPolicy
	badRoles       TrustedBadRolesPolicy
}

func resolveTrustedIdentityConfig(cfg TrustedIdentityConfig) *resolvedTrustedIdentityConfig {
	r := &resolvedTrustedIdentityConfig{
		userIDHeader:   cfg.UserIDHeader,
		usernameHeader: cfg.UsernameHeader,
		rolesHeader:    cfg.RolesHeader,
		rolesSep:       cfg.RolesSeparator,
		adminRoles:     make(map[string]struct{}, len(cfg.AdminRoles)),
		roleMatcher:    cfg.RoleMatcher,
		missing:        cfg.Missing,
		badRoles:       cfg.BadRoles,
	}
	if r.userIDHeader == "" {
		r.userIDHeader = "X-Auth-User-ID"
	}
	if r.usernameHeader == "" {
		r.usernameHeader = "X-Auth-Username"
	}
	if r.rolesHeader == "" {
		r.rolesHeader = "X-Auth-Role-IDs"
	}
	if r.rolesSep == "" {
		r.rolesSep = ","
	}
	for _, role := range cfg.AdminRoles {
		r.adminRoles[role] = struct{}{}
	}
	return r
}

// trustedClaimsCtxKey 是 claims 在标准 context.Context 中的键
// （非导出结构体类型，杜绝键碰撞）。
type trustedClaimsCtxKey struct{}

// trustedIdentityCfgKey 是解析后的身份配置在标准 context.Context 中的键
// （与 claims 由 TrustedHeadersIdentity 成对注入，OverrideTrustedClaims
// 据此重算 IsAdmin）。
type trustedIdentityCfgKey struct{}

// trustedClaimsRequestKey 是 claims 在 Hertz RequestContext kv 中的键。
const trustedClaimsRequestKey = "oekit_trusted_claims"

// TrustedHeadersIdentity 返回「信任网关已验签、解析注入身份头」的 identity
// 中间件：每请求做**一次**头解析，产出 TrustedClaims 注入 ctx（标准
// context 与 RequestContext 双写），handler 侧零样板读身份。
//
// 与 BearerTokenAuth 的分工：BearerTokenAuth 是**本进程**持预共享 token
// 验签；本中间件把验签交给上游统一网关（如 zeus），进程内只做「信任
// 注入头 → 身份」的解析。矩阵内服务的标准鉴权形态即后者，此前各服务
// 手搓读头样板（octopus 10 文件 16 处 GetUserId/GetRole，每请求重复解析，
// 角色「宽容数字解析」静默畸变），本中间件一次收编。
//
// # 信任边界（部署前提）
//
// 身份头（X-Auth-User-ID 等）**必须**由网关覆盖写/剥离客户端的同名头。
// 本中间件不做任何验签——若客户端可直连本服务并自带这些头，身份即被
// 伪造。这是「trusted-gateway」形态的契约：进程只部署在网关之后。
//
// # 每请求流程
//
//  1. UserIDHeader 无值 → Missing 策略（默认 401；AnonymousClaims 则
//     注入 Anonymous=true 的显式匿名身份放行）
//  2. RolesHeader 存在但解析出非法项（空值/"1,,2" 形态）→ BadRoles 策略
//     （默认 401；BadRolesDrop 丢非法项 Warn 继续；BadRolesAnonymous
//     降级匿名 Warn 继续）。头整体缺失不算失败（无角色用户）
//  3. 解析产出 TrustedClaims（IsAdmin 按 AdminRoles/RoleMatcher 判定，
//     字符串精确匹配、无数字强转）注入 ctx，c.Next(ctx)
//
// 用法：
//
//	h.Use(mw.TrustedHeadersIdentity(mw.TrustedIdentityConfig{
//	    UserIDHeader:   "X-Auth-User-ID",
//	    UsernameHeader: "X-Auth-Username",
//	    RolesHeader:    "X-Auth-Role-IDs",
//	    AdminRoles:     []string{"1"},      // 或 RoleMatcher 函数
//	    Missing:        mw.AnonymousClaims, // 免认证路径无头 → 显式匿名身份
//	}))
//	// handler 侧零样板：
//	claims, ok := mw.ClaimsFrom(ctx) // → {UserID, Username, IsAdmin}
//
// # 路由级可信覆写（#136）
//
// 「路由级中间件改写身份」的形态（API key 归属人注入、内部服务系统身份、
// 测试桩固定身份、多租户网关二级改写）经 OverrideTrustedClaims 与本中间件
// 的全局单点解析共存：入口解析的 claims（含 skip_auth 路径被伪造头污染的）
// 可被路由级中间件在身份链之后整体覆写，下游 scope 逻辑零改动。
func TrustedHeadersIdentity(cfg TrustedIdentityConfig) app.HandlerFunc {
	r := resolveTrustedIdentityConfig(cfg) // 启动期解析一次

	return func(ctx context.Context, c *app.RequestContext) {
		claims, reject := r.parse(ctx, c)
		if reject {
			return // 响应已写（401）并 Abort
		}
		// 单次解析、多处读取：标准 ctx（service 层/handler 的 ctx 参数）与
		// RequestContext kv（只持有 c 的辅助函数）双写。解析配置随 ctx 注入
		// （OverrideTrustedClaims 重算 IsAdmin 用）。
		ctx = context.WithValue(ctx, trustedClaimsCtxKey{}, claims)
		ctx = context.WithValue(ctx, trustedIdentityCfgKey{}, r)
		c.Set(trustedClaimsRequestKey, claims)
		c.Next(ctx)
	}
}

// parse 每请求一次的身份头解析。reject 为 true 时响应已写好（401），
// 调用方不得再继续链路。
func (r *resolvedTrustedIdentityConfig) parse(ctx context.Context, c *app.RequestContext) (TrustedClaims, bool) {
	userID := strings.TrimSpace(string(c.GetHeader(r.userIDHeader)))
	if userID == "" {
		if r.missing == AnonymousClaims {
			return TrustedClaims{Anonymous: true}, false
		}
		identityLog.CtxWarn(ctx, "trusted identity headers missing", "path", string(c.Path()), "user_id_header", r.userIDHeader)
		ErrorResp(c, 401, "unauthorized")
		return TrustedClaims{}, true
	}

	roles, badItems := r.parseRoles(c)
	if badItems > 0 {
		switch r.badRoles {
		case BadRolesDrop:
			identityLog.CtxWarn(ctx, "trusted identity roles header has invalid items, dropped",
				"path", string(c.Path()), "bad_items", badItems)
		case BadRolesAnonymous:
			identityLog.CtxWarn(ctx, "trusted identity roles header has invalid items, downgraded to anonymous",
				"path", string(c.Path()), "bad_items", badItems)
			return TrustedClaims{Anonymous: true}, false
		default: // BadRolesReject：脏角色头视为不可信，fail-closed
			identityLog.CtxWarn(ctx, "trusted identity roles header has invalid items, rejected",
				"path", string(c.Path()), "bad_items", badItems)
			ErrorResp(c, 401, "unauthorized")
			return TrustedClaims{}, true
		}
	}

	return TrustedClaims{
		UserID:   userID,
		Username: strings.TrimSpace(string(c.GetHeader(r.usernameHeader))),
		Roles:    roles,
		IsAdmin:  r.matchAdmin(roles),
	}, false
}

// parseRoles 解析角色头。头整体缺失 → (nil, 0)（合法：无角色用户）；
// 头存在但含非法项（空值/空项）→ badItems 计数（是否丢弃/拒载由策略定）。
// 同名多值头逐个并入解析。
func (r *resolvedTrustedIdentityConfig) parseRoles(c *app.RequestContext) (roles []string, badItems int) {
	values := c.Request.Header.PeekAll(r.rolesHeader)
	if len(values) == 0 {
		return nil, 0
	}
	for _, raw := range values {
		for _, item := range strings.Split(string(raw), r.rolesSep) {
			item = strings.TrimSpace(item)
			if item == "" {
				badItems++
				continue
			}
			roles = append(roles, item)
		}
	}
	return roles, badItems
}

// matchAdmin 判定角色列表是否命中 admin 口径（启动期定版的集合/函数，
// AdminRoles 与 RoleMatcher 任一命中即可；字符串精确匹配，无数字强转）。
func (r *resolvedTrustedIdentityConfig) matchAdmin(roles []string) bool {
	for _, role := range roles {
		if _, ok := r.adminRoles[role]; ok {
			return true
		}
		if r.roleMatcher != nil && r.roleMatcher(role) {
			return true
		}
	}
	return false
}

// ClaimsFrom 从 handler 的 context.Context 提取 TrustedClaims（由
// TrustedHeadersIdentity 注入）。ok=false 表示中间件未注册/未覆盖该请求。
//
// 用法：
//
//	claims, ok := mw.ClaimsFrom(ctx)
//	if !ok || claims.Anonymous { ... }
func ClaimsFrom(ctx context.Context) (TrustedClaims, bool) {
	claims, ok := ctx.Value(trustedClaimsCtxKey{}).(TrustedClaims)
	return claims, ok
}

// ClaimsFromRequestContext 从 Hertz RequestContext 提取 TrustedClaims
// （与 ClaimsFrom 同源——中间件双写两处）。只持有 *app.RequestContext 的
// 辅助函数用这个出口。
func ClaimsFromRequestContext(c *app.RequestContext) (TrustedClaims, bool) {
	v, ok := c.Get(trustedClaimsRequestKey)
	if !ok {
		return TrustedClaims{}, false
	}
	claims, ok := v.(TrustedClaims)
	return claims, ok
}

// OverrideTrustedClaims 以可信身份覆写当前请求的 claims（#136）：路由级
// 中间件在 TrustedHeadersIdentity 身份链**之后**改写身份，与全局单点解析
// 共存。没有覆写口时，伪造头在入口已被解析进 claims，路由级 strip-then-
// inject 发生在解析之后——claims 里留下的仍是伪造身份；有覆写口，claims
// 被整体替换，下游 scope 逻辑零改动。典型场景：
//
//   - API key 归属人注入（octopus /api/v2/ext/* 形态）：skip_auth 路径客户端
//     可伪造 X-Auth-* 头，必须先清场再注入 key 归属人身份；
//   - 内部服务间调用注入系统身份；
//   - 测试桩注入固定身份；
//   - 多租户网关二级改写。
//
// 返回更新后的 ctx（**必须**继续传给 c.Next，后续 handler 经 ClaimsFrom 读到
// 覆写结果）与是否覆写成功。
//
// # 契约
//
//   - 同 key 写回：标准 ctx（context.WithValue）与 RequestContext kv 同步
//     双写，ClaimsFrom 与 ClaimsFromRequestContext 读到同一份，覆写仅对
//     本请求后续 handler 可见。
//   - 单向闸：仅允许覆写一次——当前 claims 已带 Rewritten=true 时拒绝本次
//     覆写并 Warn（防链内多方互相覆盖；保留第一次覆写结果，调用方可据
//     ok=false 自行处置）。
//   - 需已注册身份链：ctx 中无 TrustedHeadersIdentity 注入的 claims 时拒绝
//     （覆写口不凭空造身份——绕过 Missing/BadRoles 等解析策略的口子不开）。
//   - IsAdmin 按启动期口径重算：以 TrustedIdentityConfig 的 AdminRoles /
//     RoleMatcher 对覆写后的 Roles 重新判定，调用方传入的 IsAdmin 不被
//     采信——覆写口不提供绕过 admin 口径的通道。
//   - 清场（strip-then-inject 的 strip 半场）：覆写同时剥离请求中的身份头
//     （UserIDHeader/UsernameHeader/RolesHeader）——入站伪造头对下游任何
//     直接读头的代码不可见，身份只来自本次注入。
//   - 审计标记：覆写后的 claims.Rewritten=true，随双写出口可读。
//
// 用法（API key 归属人注入）：
//
//	func APIKeyAuth() app.HandlerFunc {
//	    return func(ctx context.Context, c *app.RequestContext) {
//	        owner := authOwnerByAPIKey(c) // 校验 key 并查归属人
//	        if owner == nil {
//	            mw.ErrorResp(c, 401, "unauthorized")
//	            return
//	        }
//	        ctx, ok := mw.OverrideTrustedClaims(ctx, c, mw.TrustedClaims{
//	            UserID:   owner.ID,
//	            Username: owner.Name,
//	            Roles:    owner.Roles,
//	        })
//	        if !ok {
//	            mw.ErrorResp(c, 401, "unauthorized")
//	            return
//	        }
//	        c.Next(ctx)
//	    }
//	}
func OverrideTrustedClaims(ctx context.Context, c *app.RequestContext, claims TrustedClaims) (context.Context, bool) {
	cur, ok := ClaimsFrom(ctx)
	if !ok {
		// 未注册 TrustedHeadersIdentity：覆写口不凭空造身份（fail-closed）。
		identityLog.CtxWarn(ctx, "trusted claims override rejected: identity middleware not registered",
			"path", string(c.Path()))
		return ctx, false
	}
	if cur.Rewritten {
		// 单向闸：仅允许覆写一次，防链内多方互相覆盖。
		identityLog.CtxWarn(ctx, "trusted claims override rejected: already overridden",
			"path", string(c.Path()), "user_id", cur.UserID)
		return ctx, false
	}

	// 解析配置与 claims 成对注入；据此重算 IsAdmin（启动期口径，覆写口
	// 不提供绕过 admin 判定的通道）并剥离身份头（清场）。
	if cfg, ok := ctx.Value(trustedIdentityCfgKey{}).(*resolvedTrustedIdentityConfig); ok && cfg != nil {
		claims.IsAdmin = cfg.matchAdmin(claims.Roles)
		c.Request.Header.Del(cfg.userIDHeader)
		c.Request.Header.Del(cfg.usernameHeader)
		c.Request.Header.Del(cfg.rolesHeader)
	}
	claims.Rewritten = true
	// 同 key 写回：标准 ctx 与 RequestContext kv 同步双写（与注入侧一致）。
	ctx = context.WithValue(ctx, trustedClaimsCtxKey{}, claims)
	c.Set(trustedClaimsRequestKey, claims)
	return ctx, true
}
