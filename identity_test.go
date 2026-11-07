package mw

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

// identityProbe 捕获 handler 内经 ClaimsFrom 读到的身份（ctx 侧出口）。
type identityProbe struct {
	mu     sync.Mutex
	claims TrustedClaims
	ok     bool
}

func (p *identityProbe) store(claims TrustedClaims, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims, p.ok = claims, ok
}

func (p *identityProbe) load() (TrustedClaims, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.claims, p.ok
}

// newIdentityEngine 构建挂了 TrustedHeadersIdentity 的引擎，/whoami 处
// 捕获 ctx 侧 claims 并回显 UserID。
func newIdentityEngine(t *testing.T, cfg TrustedIdentityConfig) (*route.Engine, *identityProbe) {
	t.Helper()
	probe := &identityProbe{}
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(TrustedHeadersIdentity(cfg))
	h.GET("/whoami", func(ctx context.Context, c *app.RequestContext) {
		claims, ok := ClaimsFrom(ctx)
		probe.store(claims, ok)
		c.JSON(http.StatusOK, map[string]any{"uid": claims.UserID})
	})
	return h, probe
}

// TestTrustedHeadersIdentity_InjectsClaims 全头形态：每请求一次解析注入
// ctx（标准 context 与 RequestContext 双写），handler 侧零样板读取。
func TestTrustedHeadersIdentity_InjectsClaims(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		AdminRoles: []string{"1"},
	})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Username", Value: "alice"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1,2"},
	).Result()

	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", r.StatusCode(), r.Body())
	}
	claims, ok := probe.load()
	if !ok {
		t.Fatal("ClaimsFrom(ctx) should find claims injected by middleware")
	}
	if claims.UserID != "u-42" || claims.Username != "alice" {
		t.Errorf("claims = %+v, want UserID=u-42 Username=alice", claims)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "1" || claims.Roles[1] != "2" {
		t.Errorf("Roles = %v, want [1 2]", claims.Roles)
	}
	if !claims.IsAdmin {
		t.Errorf("IsAdmin = false, want true (roles contain admin role \"1\")")
	}
	if claims.Anonymous {
		t.Errorf("Anonymous = true, want false")
	}
	if !strings.Contains(string(r.Body()), "u-42") {
		t.Errorf("body should echo uid u-42, got %s", r.Body())
	}
}

// TestTrustedHeadersIdentity_ZeroValueDefaults 零值配置可用：头名缺省对齐
// zeus 注入约定，Missing/BadRoles 缺省均为拒载。
func TestTrustedHeadersIdentity_ZeroValueDefaults(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{})

	// 缺省头名生效：带默认头的请求被正常解析
	ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-1"})
	claims, ok := probe.load()
	if !ok || claims.UserID != "u-1" {
		t.Errorf("zero-value config should default headers to zeus names, claims=%+v ok=%v", claims, ok)
	}

	// Missing 缺省 = MissingReject：无头 → 401
	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil).Result()
	if r.StatusCode() != http.StatusUnauthorized {
		t.Errorf("zero-value Missing policy should reject with 401, got %d", r.StatusCode())
	}
}

// TestTrustedHeadersIdentity_MissingRejectDefault Missing 默认拒载：
// 受保护路径缺身份头 → 401，响应为统一错误封套（无头即链路配置有误，
// fail-closed）。
func TestTrustedHeadersIdentity_MissingRejectMissingPolicy(t *testing.T) {
	h, _ := newIdentityEngine(t, TrustedIdentityConfig{AdminRoles: []string{"1"}})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil).Result()
	if r.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.StatusCode())
	}
	if !strings.Contains(string(r.Body()), `"code":401`) {
		t.Errorf("body should be unified error envelope, got %s", r.Body())
	}
}

// TestTrustedHeadersIdentity_MissingAnonymous Missing=AnonymousClaims：
// 免认证路径无头 → 显式匿名身份放行（Anonymous=true，UserID 空）。
func TestTrustedHeadersIdentity_MissingAnonymous(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		AdminRoles: []string{"1"},
		Missing:    AnonymousClaims,
	})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (anonymous pass)", r.StatusCode())
	}
	claims, ok := probe.load()
	if !ok {
		t.Fatal("anonymous claims should still be injected (explicit identity)")
	}
	if !claims.Anonymous || claims.UserID != "" || claims.IsAdmin {
		t.Errorf("claims = %+v, want explicit anonymous identity", claims)
	}
}

// TestTrustedHeadersIdentity_BadRolesRejectDefault BadRoles 缺省拒载：
// 角色头存在但含非法项（空值/"1,,2"）→ 401。脏角色头视为不可信信号，
// 不静默吞字符。
func TestTrustedHeadersIdentity_BadRolesRejectDefault(t *testing.T) {
	h, _ := newIdentityEngine(t, TrustedIdentityConfig{AdminRoles: []string{"1"}})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1,,2"},
	).Result()
	if r.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bad roles rejected by default)", r.StatusCode())
	}
}

// TestTrustedHeadersIdentity_BadRolesDrop BadRolesDrop：丢弃非法项、保留
// 合法角色继续（Warn 留信号，身份不畸变）。
func TestTrustedHeadersIdentity_BadRolesDrop(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		AdminRoles: []string{"1"},
		BadRoles:   BadRolesDrop,
	})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1,,3"},
	).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (drop policy continues)", r.StatusCode())
	}
	claims, _ := probe.load()
	if len(claims.Roles) != 2 || claims.Roles[0] != "1" || claims.Roles[1] != "3" {
		t.Errorf("Roles = %v, want [1 3] (empty item dropped)", claims.Roles)
	}
	if !claims.IsAdmin {
		t.Errorf("IsAdmin = false, want true (valid role \"1\" kept)")
	}
}

// TestTrustedHeadersIdentity_BadRolesAnonymous BadRolesAnonymous：角色头
// 脏 → 整体降级匿名继续（宁可降权不可错配）。
func TestTrustedHeadersIdentity_BadRolesAnonymous(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		AdminRoles: []string{"1"},
		BadRoles:   BadRolesAnonymous,
	})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1,,2"},
	).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (downgraded but allowed)", r.StatusCode())
	}
	claims, _ := probe.load()
	if !claims.Anonymous || claims.UserID != "" || claims.IsAdmin {
		t.Errorf("claims = %+v, want downgraded anonymous identity (no admin)", claims)
	}
}

// TestTrustedHeadersIdentity_NoRolesHeaderOK 角色头整体缺失是合法形态
// （无角色用户）：Roles 为 nil、正常放行、不触发 BadRoles。
func TestTrustedHeadersIdentity_NoRolesHeaderOK(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{AdminRoles: []string{"1"}})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
	).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (absent roles header is valid)", r.StatusCode())
	}
	claims, _ := probe.load()
	if claims.Roles != nil || claims.IsAdmin {
		t.Errorf("claims = %+v, want nil Roles / IsAdmin=false", claims)
	}
	if claims.UserID != "u-42" {
		t.Errorf("UserID = %q, want u-42", claims.UserID)
	}
}

// TestTrustedHeadersIdentity_AdminNoNumericCoercion octopus GetRole 的畸变
// 方向钉死：角色按原样字符串精确匹配，"1a2" 永不命中 admin 角色 "1"
// （宽容数字解析会把 "1a2" 静默吞成 12）。
func TestTrustedHeadersIdentity_AdminNoNumericCoercion(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		AdminRoles: []string{"1", "12"},
	})

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1a2,99"},
	).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.StatusCode())
	}
	claims, _ := probe.load()
	if claims.IsAdmin {
		t.Errorf("IsAdmin = true, want false (\"1a2\" must not coerce into \"1\"/\"12\")")
	}
}

// TestTrustedHeadersIdentity_RoleMatcher RoleMatcher 函数形态（与 AdminRoles
// 任一命中即可），启动期固化口径。
func TestTrustedHeadersIdentity_RoleMatcher(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{
		RoleMatcher: func(role string) bool { return strings.HasPrefix(role, "admin-") },
	})

	ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "admin-ops,dev"},
	)
	claims, _ := probe.load()
	if !claims.IsAdmin {
		t.Errorf("IsAdmin = false, want true (RoleMatcher hits admin-ops)")
	}
}

// TestTrustedHeadersIdentity_RolesSeparatorAndTrim 自定义分隔符 + 项级
// TrimSpace（"1, 2" 切出 ["1","2"]）。
func TestTrustedHeadersIdentity_RolesSeparatorAndTrim(t *testing.T) {
	h, probe := newIdentityEngine(t, TrustedIdentityConfig{RolesSeparator: ";"})

	ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-User-ID", Value: "u-42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1; 2 ;3"},
	)
	claims, _ := probe.load()
	if len(claims.Roles) != 3 || claims.Roles[0] != "1" || claims.Roles[1] != "2" || claims.Roles[2] != "3" {
		t.Errorf("Roles = %v, want [1 2 3] (custom separator + per-item trim)", claims.Roles)
	}
}

// TestClaimsFromRequestContext RequestContext 侧出口（与 ClaimsFrom 同源，
// 中间件双写两处）：只持有 c 的辅助函数可用。
func TestClaimsFromRequestContext(t *testing.T) {
	h := TrustedHeadersIdentity(TrustedIdentityConfig{AdminRoles: []string{"1"}})
	c := app.NewContext(128)
	c.Request.SetRequestURI("/whoami")
	c.Request.Header.Set("X-Auth-User-ID", "u-42")
	c.Request.Header.Set("X-Auth-Role-IDs", "1")
	h(context.Background(), c)

	claims, ok := ClaimsFromRequestContext(c)
	if !ok {
		t.Fatal("ClaimsFromRequestContext should find claims")
	}
	if claims.UserID != "u-42" || !claims.IsAdmin {
		t.Errorf("claims = %+v, want UserID=u-42 IsAdmin=true", claims)
	}

	// 未经中间件的 RequestContext → ok=false
	if _, ok := ClaimsFromRequestContext(app.NewContext(8)); ok {
		t.Error("ClaimsFromRequestContext on untouched context should return ok=false")
	}
}

// TestClaimsFrom_UnregisteredContext 未注册中间件的 ctx → ok=false，
// 区分「未注册」与「匿名身份」（后者 ok=true 且 Anonymous=true）。
func TestClaimsFrom_UnregisteredContext(t *testing.T) {
	if _, ok := ClaimsFrom(context.Background()); ok {
		t.Error("ClaimsFrom on plain context should return ok=false")
	}
}
