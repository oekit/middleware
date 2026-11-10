package mw

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/route"
)

// fakeConn 只为测试覆盖 RemoteAddr（来源立证的输入）：嵌入 network.Conn
// 接口满足类型面，未实现方法调用即 panic——本测试面只用 RemoteAddr。
type fakeConn struct {
	network.Conn
	addr net.Addr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.addr }

// newTrustCtx 构造带指定对端地址与头的 RequestContext（VerifyGatewayTrust
// 单元测试用）：remoteIP 为空表示不 SetConn（对端为 zeroTCPAddr，非回环）。
func newTrustCtx(t *testing.T, method, path, remoteIP string, headers ...ut.Header) *app.RequestContext {
	t.Helper()
	c := app.NewContext(0)
	c.Request.SetMethod(method)
	c.Request.URI().SetPath(path)
	for _, h := range headers {
		c.Request.Header.Set(h.Key, h.Value)
	}
	if remoteIP != "" {
		c.SetConn(&fakeConn{addr: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 4242}})
	}
	return c
}

// signedTrustCtx 构造「网关侧已签名」的请求：按网关注入顺序（身份头 +
// Timestamp → GatewaySign → Signature 头）走一遍真实签名路径。
func signedTrustCtx(t *testing.T, trust GatewayTrust, method, path, remoteIP string, headers ...ut.Header) *app.RequestContext {
	t.Helper()
	all := append([]ut.Header{
		{Key: "X-Auth-Timestamp", Value: tsNow()},
	}, headers...)
	c := newTrustCtx(t, method, path, remoteIP, all...)
	sig, err := GatewaySign(trust, c)
	if err != nil {
		t.Fatalf("GatewaySign: %v", err)
	}
	c.Request.Header.Set("X-Auth-Signature", sig)
	return c
}

// tsNow 返回当前时间的 Unix 秒串（签名时间戳头用）。
func tsNow() string { return strconv.FormatInt(time.Now().Unix(), 10) }

// hasTrustHeaders 判断请求上是否还残留任何信任头（剥头断言用）。
func hasTrustHeaders(c *app.RequestContext, names TrustHeaderNames) []string {
	var left []string
	for _, name := range names.all() {
		if len(c.Request.Header.Peek(name)) > 0 {
			left = append(left, name)
		}
	}
	return left
}

// TestVerifyGatewayTrust_LoopbackNoSignature 回环来源立证（网关/边车同机
// 形态）：无需签名即通过，身份头保留（已立证）。
func TestVerifyGatewayTrust_LoopbackNoSignature(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1",
		ut.Header{Key: "X-Auth-User-ID", Value: " u42 "},
		ut.Header{Key: "X-Auth-Username", Value: "alice"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1, 2,,3"},
		ut.Header{Key: "X-Auth-MCP", Value: "mcp-1"},
	)
	sub, ok := VerifyGatewayTrust(trust, c)
	if !ok {
		t.Fatal("loopback 来源立证应通过")
	}
	if sub.UserID != "u42" || sub.Method != "GET" || sub.Path != "/api/users" {
		t.Fatalf("subject 不符: %+v", sub)
	}
	if len(sub.Roles) != 3 || sub.Roles[0] != "1" || sub.Roles[1] != "2" || sub.Roles[2] != "3" {
		t.Fatalf("roles 解析不符（去空项、无数字强转）: %v", sub.Roles)
	}
	if sub.Claims["username"] != "alice" || sub.Claims["mcp"] != "mcp-1" {
		t.Fatalf("claims 不符: %v", sub.Claims)
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 4 {
		t.Fatalf("已立证请求的身份头应保留（仅 Signature/Timestamp 被消费），残留: %v", left)
	}
}

// TestVerifyGatewayTrust_ForgedHeadersRejectedAndStripped 头伪造拒绝（核心
// 安全面）：非可信来源、无签名的 X-Auth-* 头就是客户端自称的身份——必须
// 拒绝且剥头，任何值都不得进入后续链路。
func TestVerifyGatewayTrust_ForgedHeadersRejectedAndStripped(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/admin", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "admin"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "9"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
	)
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("伪造头不得立证成功")
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("立证失败必须剥掉全部信任头（剥头防伪造），残留: %v", left)
	}
}

// TestVerifyGatewayTrust_SignatureAttests 非可信来源走签名立证：HMAC +
// 时间窗内即通过（网关注入侧 GatewaySign 与校验侧同源）。
func TestVerifyGatewayTrust_SignatureAttests(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := signedTrustCtx(t, trust, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
	)
	sub, ok := VerifyGatewayTrust(trust, c)
	if !ok {
		t.Fatal("合法签名应立证成功")
	}
	if sub.UserID != "u42" {
		t.Fatalf("UserID 不符: %q", sub.UserID)
	}
	// 签名/时间头已消费；身份头保留。
	if len(c.Request.Header.Peek("X-Auth-Signature")) != 0 || len(c.Request.Header.Peek("X-Auth-Timestamp")) != 0 {
		t.Fatal("Signature/Timestamp 应在立证后剥掉（防下游二次解释）")
	}
	if len(c.Request.Header.Peek("X-Auth-User-ID")) == 0 {
		t.Fatal("已立证的身份头应保留（SmartRBAC/ClaimsFrom 下游读取面）")
	}
}

// TestVerifyGatewayTrust_ReplayOutsideWindowRejected 重放拒绝：时间窗
// （默认 90s）之外的签名即使 HMAC 正确也拒。
func TestVerifyGatewayTrust_ReplayOutsideWindowRejected(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Timestamp", Value: strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)},
	)
	sig, err := GatewaySign(trust, c)
	if err != nil {
		t.Fatalf("GatewaySign: %v", err)
	}
	c.Request.Header.Set("X-Auth-Signature", sig)
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("超时间窗的签名必须拒绝（重放防护）")
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("拒绝后必须剥头，残留: %v", left)
	}
}

// TestVerifyGatewayTrust_TamperedUIDRejected 规范串绑定 uid：签名后改身份
// 头即失配。
func TestVerifyGatewayTrust_TamperedUIDRejected(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := signedTrustCtx(t, trust, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
	)
	c.Request.Header.Set("X-Auth-User-ID", "admin") // 签名后篡改
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("篡改 uid 后签名必须失配")
	}
}

// TestVerifyGatewayTrust_SignatureBoundToPath 规范串绑定 uri：同一签名换
// 路径重放即失配。
func TestVerifyGatewayTrust_SignatureBoundToPath(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := signedTrustCtx(t, trust, "GET", "/api/a", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
	)
	c.Request.URI().SetPath("/api/b") // 换端点重放
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("换路径重放必须失配（规范串绑定 uri）")
	}
}

// TestVerifyGatewayTrust_TamperedAuthorizedRejected SmartRBAC 跳过面受签名
// 保护：Authorized 进规范串，链上改一行 X-Auth-Authorized 即失配——
// 「加一行头跳过本地 RBAC」的伪造路径关死。
func TestVerifyGatewayTrust_TamperedAuthorizedRejected(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := signedTrustCtx(t, trust, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
	)
	c.Request.Header.Set("X-Auth-Authorized", "0") // 签名后篡改（链上改行）
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("篡改 Authorized 后签名必须失配")
	}

	// 反向：未签名的 Authorized 不得凭空生效（伪造加行 → 无签名 → 拒）。
	forged := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
	)
	if _, ok := VerifyGatewayTrust(trust, forged); ok {
		t.Fatal("无签名的 Authorized 伪造必须拒绝")
	}
}

// TestVerifyGatewayTrust_DuplicateHeaderRejected 多值信任头（请求走私式头
// 注入）按伪造处理。
func TestVerifyGatewayTrust_DuplicateHeaderRejected(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1")
	c.Request.Header.Add("X-Auth-User-ID", "u42")
	c.Request.Header.Add("X-Auth-User-ID", "admin")
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("多值信任头必须按伪造拒绝")
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("拒绝后必须剥头，残留: %v", left)
	}
}

// TestVerifyGatewayTrust_MissingUIDWithSignatureRejected 缺 UID 的「立证」
// 不成立：身份是规范串的强绑定行，不能空着过——UID 缺席在签名判定之前
// 就拒绝（签名头在场与否同效）。
func TestVerifyGatewayTrust_MissingUIDWithSignatureRejected(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-Signature", Value: "Z2FyYmFnZQ=="},
	)
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("缺 UID 不得立证成功")
	}
}

// TestVerifyGatewayTrust_NothingPresented 未呈现任何信任头：false 且无副作用。
func TestVerifyGatewayTrust_NothingPresented(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7")
	if _, ok := VerifyGatewayTrust(trust, c); ok {
		t.Fatal("未呈现立证不得返回 true")
	}
}

// TestVerifyGatewayTrust_TrustedSourceCIDR 内网来源立证：TrustedSources 网段
// 内的对端无需签名。
func TestVerifyGatewayTrust_TrustedSourceCIDR(t *testing.T) {
	trust := GatewayTrust{
		Secret:         []byte("sec"),
		TrustedSources: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	c := newTrustCtx(t, "GET", "/api/users", "10.1.2.3",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
	)
	if _, ok := VerifyGatewayTrust(trust, c); !ok {
		t.Fatal("TrustedSources 网段内来源应立证成功")
	}
}

// TestVerifyGatewayTrust_CustomHeaderNames 自定义头名走同一规范串/剥头面。
func TestVerifyGatewayTrust_CustomHeaderNames(t *testing.T) {
	names := TrustHeaderNames{
		Signature:  "X-Gw-Sig",
		Timestamp:  "X-Gw-Ts",
		UID:        "X-Gw-Uid",
		Username:   "X-Gw-Name",
		RoleIDs:    "X-Gw-Roles",
		Authorized: "X-Gw-Authz",
		MCP:        "X-Gw-Mcp",
	}
	trust := GatewayTrust{Secret: []byte("sec"), HeaderNames: names}
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Gw-Ts", Value: tsNow()},
		ut.Header{Key: "X-Gw-Uid", Value: "u42"},
	)
	sig, err := GatewaySign(trust, c)
	if err != nil {
		t.Fatalf("GatewaySign: %v", err)
	}
	c.Request.Header.Set("X-Gw-Sig", sig)
	sub, ok := VerifyGatewayTrust(trust, c)
	if !ok || sub.UserID != "u42" {
		t.Fatalf("自定义头名应立证成功: ok=%v sub=%+v", ok, sub)
	}
	// 签名/时间头已消费剥掉；身份头（X-Gw-Uid）保留。
	if len(c.Request.Header.Peek("X-Gw-Sig")) != 0 || len(c.Request.Header.Peek("X-Gw-Ts")) != 0 {
		t.Fatal("自定义名的 Signature/Timestamp 立证后应剥掉")
	}
	if len(c.Request.Header.Peek("X-Gw-Uid")) == 0 {
		t.Fatal("自定义名的身份头应保留")
	}
}

// TestGatewaySign_MissingFields 网关侧缺 Secret/UID/Timestamp 显式报错
// （规范串对三者强绑定，签不出可被接受的签名就该早炸）。
func TestGatewaySign_MissingFields(t *testing.T) {
	c := newTrustCtx(t, "GET", "/x", "",
		ut.Header{Key: "X-Auth-User-ID", Value: "u"},
		ut.Header{Key: "X-Auth-Timestamp", Value: "1"},
	)
	if _, err := GatewaySign(GatewayTrust{}, c); err == nil {
		t.Error("空 Secret 应报错")
	}
	noUID := newTrustCtx(t, "GET", "/x", "",
		ut.Header{Key: "X-Auth-Timestamp", Value: "1"},
	)
	if _, err := GatewaySign(GatewayTrust{Secret: []byte("s")}, noUID); err == nil {
		t.Error("缺 UID 应报错")
	}
	noTs := newTrustCtx(t, "GET", "/x", "",
		ut.Header{Key: "X-Auth-User-ID", Value: "u"},
	)
	if _, err := GatewaySign(GatewayTrust{Secret: []byte("s")}, noTs); err == nil {
		t.Error("缺 Timestamp 应报错")
	}
}

// parseProbe 记录本地模式 parse 的输入并返回预设结果。
type parseProbe struct {
	mu     sync.Mutex
	tokens []string
	sub    Subject
	err    error
}

func (p *parseProbe) parse(_ context.Context, token string) (Subject, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens = append(p.tokens, token)
	return p.sub, p.err
}

func (p *parseProbe) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tokens...)
}

// authProbe 记录 SmartAuth 放行后的下游可观测面（RequestContext kv claims）。
func loadClaims(c *app.RequestContext) (TrustedClaims, bool) {
	return ClaimsFromRequestContext(c)
}

// TestSmartAuth_GatewayOnlySuccess 网关模式放行：立证成功后下游可达、
// Subject 进 Authorizer、TrustedClaims 注入。
func TestSmartAuth_GatewayOnlySuccess(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	az := &fakeAuthorizer{allowed: true}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust,
		WithSmartAuthMode(AuthModeGatewayOnly),
		WithSmartAuthAuthorizer(az),
		WithSmartAuthAdminRoles("1"),
	)
	c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1",
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "1,2"},
	)
	h(context.Background(), c)
	if c.IsAborted() {
		t.Fatalf("立证成功不得中断链路: %d", c.Response.StatusCode())
	}
	if got := probe.calls(); len(got) != 0 {
		t.Fatalf("网关路径不得回落本地 parse: %v", got)
	}
	if az.called != 1 || az.lastSub.UserID != "u42" {
		t.Fatalf("Authorizer 未收到网关 Subject: called=%d sub=%+v", az.called, az.lastSub)
	}
	claims, ok := loadClaims(c)
	if !ok || claims.UserID != "u42" || !claims.IsAdmin {
		t.Fatalf("TrustedClaims 注入不符: ok=%v %+v", ok, claims)
	}
}

// TestSmartAuth_GatewayOnlyForgedRejected401 网关模式 + 伪造头：401 且
// 剥头，本地 parse 不启用。
func TestSmartAuth_GatewayOnlyForgedRejected401(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust, WithSmartAuthMode(AuthModeGatewayOnly))
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "admin"},
	)
	h(context.Background(), c)
	if !c.IsAborted() || c.Response.StatusCode() != 401 {
		t.Fatalf("伪造头应 401: status=%d", c.Response.StatusCode())
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("401 前必须剥头，残留: %v", left)
	}
	if got := probe.calls(); len(got) != 0 {
		t.Fatalf("gateway-only 不得调用 parse: %v", got)
	}
}

// TestSmartAuth_AutoFallsBackToLocal 组合模式：未呈现网关立证时落本地
// JWT 兜底。
func TestSmartAuth_AutoFallsBackToLocal(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user", Roles: []string{"r1"}}}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust)
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "Authorization", Value: "Bearer tok-1"},
	)
	h(context.Background(), c)
	if c.IsAborted() {
		t.Fatalf("本地兜底成功不得中断: %d", c.Response.StatusCode())
	}
	if got := probe.calls(); len(got) != 1 || got[0] != "tok-1" {
		t.Fatalf("parse 调用不符: %v", got)
	}
	claims, ok := loadClaims(c)
	if !ok || claims.UserID != "jwt-user" || claims.IsAdmin {
		t.Fatalf("claims 注入不符: ok=%v %+v", ok, claims)
	}
}

// TestSmartAuth_AutoForgedGatewayHeadersStripped 组合模式 + 头伪造：伪造头
// 必须剥掉（含 Authorized——SmartRBAC 跳过面），身份只来自本地 JWT。
func TestSmartAuth_AutoForgedGatewayHeadersStripped(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust)
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "admin"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
		ut.Header{Key: "Authorization", Value: "Bearer tok-1"},
	)
	h(context.Background(), c)
	if c.IsAborted() {
		t.Fatalf("本地 JWT 有效应放行: %d", c.Response.StatusCode())
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("伪造信任头不得进入链路（含 Authorized），残留: %v", left)
	}
	claims, ok := loadClaims(c)
	if !ok || claims.UserID != "jwt-user" {
		t.Fatalf("身份必须来自 JWT 而非伪造头: ok=%v %+v", ok, claims)
	}
}

// TestSmartAuth_LocalOnlyStripsTrustHeaders 本地模式：信任头一律剥除
// （剥头防伪造的结构性关死），身份只来自令牌。
func TestSmartAuth_LocalOnlyStripsTrustHeaders(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust, WithSmartAuthMode(AuthModeLocalOnly))
	c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1", // 回环也一样剥
		ut.Header{Key: "X-Auth-User-ID", Value: "admin"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
		ut.Header{Key: "Authorization", Value: "Bearer tok-1"},
	)
	h(context.Background(), c)
	if c.IsAborted() {
		t.Fatalf("本地模式成功不得中断: %d", c.Response.StatusCode())
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("LocalOnly 必须剥掉全部信任头，残留: %v", left)
	}
	claims, ok := loadClaims(c)
	if !ok || claims.UserID != "jwt-user" {
		t.Fatalf("身份必须来自 JWT: ok=%v %+v", ok, claims)
	}
}

// TestSmartAuth_SkipPathStripsHeaders 免认证路径同样剥头：skip ≠ 可携带
// 伪造身份头继续（#136 教训）。
func TestSmartAuth_SkipPathStripsHeaders(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth(probe.parse, &trust, WithSmartAuthSkipPaths("/healthz"))
	c := newTrustCtx(t, "GET", "/healthz", "203.0.113.7",
		ut.Header{Key: "X-Auth-User-ID", Value: "admin"},
		ut.Header{Key: "X-Auth-Authorized", Value: "1"},
	)
	h(context.Background(), c)
	if c.IsAborted() {
		t.Fatal("skip 路径应放行")
	}
	if left := hasTrustHeaders(c, trust.headerNames()); len(left) != 0 {
		t.Fatalf("skip 路径不得残留信任头，残留: %v", left)
	}
	if got := probe.calls(); len(got) != 0 {
		t.Fatalf("skip 路径不得调用 parse: %v", got)
	}
}

// TestSmartAuth_LocalFail401 本地兜底失败（缺 token / parse 报错）→ 401。
func TestSmartAuth_LocalFail401(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("sec")}
	h := SmartAuth((&parseProbe{err: errFakeInvalid}).parse, &trust)

	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7")
	h(context.Background(), c)
	if !c.IsAborted() || c.Response.StatusCode() != 401 {
		t.Fatalf("缺 token 应 401: %d", c.Response.StatusCode())
	}

	c2 := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "Authorization", Value: "Bearer bad"},
	)
	h(context.Background(), c2)
	if !c2.IsAborted() || c2.Response.StatusCode() != 401 {
		t.Fatalf("parse 失败应 401: %d", c2.Response.StatusCode())
	}
}

// errFakeInvalid 是 parseProbe 的预设失败。
var errFakeInvalid = errors.New("invalid token")

// TestSmartAuth_AuthorizerRejectAndError 内联鉴权钩子：拒绝 403、故障 500。
func TestSmartAuth_AuthorizerRejectAndError(t *testing.T) {
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	trust := GatewayTrust{Secret: []byte("sec")}

	reject := &fakeAuthorizer{allowed: false}
	h := SmartAuth(probe.parse, &trust, WithSmartAuthAuthorizer(reject))
	c := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "Authorization", Value: "Bearer tok"},
	)
	h(context.Background(), c)
	if !c.IsAborted() || c.Response.StatusCode() != 403 {
		t.Fatalf("拒绝应 403: %d", c.Response.StatusCode())
	}

	failing := &fakeAuthorizer{err: errFakeInvalid}
	h2 := SmartAuth(probe.parse, &trust, WithSmartAuthAuthorizer(failing))
	c2 := newTrustCtx(t, "GET", "/api/users", "203.0.113.7",
		ut.Header{Key: "Authorization", Value: "Bearer tok"},
	)
	h2(context.Background(), c2)
	if !c2.IsAborted() || c2.Response.StatusCode() != 500 {
		t.Fatalf("鉴权后端故障应 500: %d", c2.Response.StatusCode())
	}
}

// TestSmartAuth_ConstructionPanics 构造期 fail-fast（#97 同哲学）：没有
// 认证面/立证面的配置必须在启动期炸响。
func TestSmartAuth_ConstructionPanics(t *testing.T) {
	trust := &GatewayTrust{Secret: []byte("sec")}
	noPath := &GatewayTrust{} // Secret 与 TrustedSources 均空
	dup := &GatewayTrust{
		Secret: []byte("sec"),
		HeaderNames: TrustHeaderNames{
			UID: "X-A", Username: "X-A", RoleIDs: "X-B", MCP: "X-B",
		},
	}
	probe := (&parseProbe{}).parse

	cases := []struct {
		name  string
		parse JWTParseFunc
		trust *GatewayTrust
		opts  []SmartAuthOption
		want  string // panic 信息须包含的子串
	}{
		{"both nil", nil, nil, nil, "fail-open"},
		{"gateway-only without trust", probe, nil, []SmartAuthOption{WithSmartAuthMode(AuthModeGatewayOnly)}, "GatewayTrust"},
		{"local-only without parse", nil, trust, []SmartAuthOption{WithSmartAuthMode(AuthModeLocalOnly)}, "JWTParseFunc"},
		{"trust without attestation path", probe, noPath, nil, "no attestation path"},
		{"duplicate header names", probe, dup, nil, "X-A"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("应构造期 panic")
				}
				msg, _ := r.(string)
				if !strings.Contains(msg, tc.want) {
					t.Fatalf("panic 信息应含 %q, got %q", tc.want, msg)
				}
			}()
			_ = SmartAuth(tc.parse, tc.trust, tc.opts...)
		})
	}
}

// TestSmartAuth_DuplicateHeaderNamesJoinError 头名冲突多条一次列全
// （errors.Join 聚合：不逐个挤牙膏）。
func TestSmartAuth_DuplicateHeaderNamesJoinError(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("应 panic")
		}
		msg := r.(string)
		if !strings.Contains(msg, "X-A") || !strings.Contains(msg, "X-B") {
			t.Fatalf("errors.Join 应一次列出全部冲突, got %q", msg)
		}
	}()
	_ = SmartAuth((&parseProbe{}).parse, &GatewayTrust{
		Secret:      []byte("sec"),
		HeaderNames: TrustHeaderNames{UID: "X-A", Username: "X-A", RoleIDs: "X-B", MCP: "X-B"},
	})
}

// TestSmartRBAC_GatewayAuthorizedSkipsLocal 网关已鉴权（Authorized=1）跳过
// 本地 RBAC。
func TestSmartRBAC_GatewayAuthorizedSkipsLocal(t *testing.T) {
	localCalled := false
	h := SmartRBAC(func(ctx context.Context, c *app.RequestContext) {
		localCalled = true
		c.Next(ctx)
	})
	c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1",
		ut.Header{Key: "X-Auth-Authorized", Value: GatewayAuthorizedValue},
	)
	h(context.Background(), c)
	if localCalled {
		t.Fatal("网关已鉴权不得调用本地 RBAC")
	}
	if c.IsAborted() {
		t.Fatal("网关已鉴权应放行")
	}
}

// TestSmartRBAC_LocalFallback 未标记（缺席/非 "1"）走本地 RBAC 兜底。
func TestSmartRBAC_LocalFallback(t *testing.T) {
	for _, header := range []string{"", "0", "true"} {
		localCalled := false
		h := SmartRBAC(func(ctx context.Context, c *app.RequestContext) {
			localCalled = true
			c.Next(ctx)
		})
		c := newTrustCtx(t, "GET", "/api/users", "127.0.0.1")
		if header != "" {
			c.Request.Header.Set("X-Auth-Authorized", header)
		}
		h(context.Background(), c)
		if !localCalled {
			t.Fatalf("Authorized=%q 应走本地 RBAC 兜底", header)
		}
	}
}

// TestSmartRBAC_NilLocalPanics nil 兜底 = 网关未鉴权时静默放行（fail-open），
// 构造期炸响。
func TestSmartRBAC_NilLocalPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("SmartRBAC(nil) 应 panic")
		}
	}()
	_ = SmartRBAC(nil)
}

// TestSmartRBAC_CustomAuthorizedHeader 自定义标记头名。
func TestSmartRBAC_CustomAuthorizedHeader(t *testing.T) {
	localCalled := false
	h := SmartRBAC(func(ctx context.Context, c *app.RequestContext) {
		localCalled = true
		c.Next(ctx)
	}, WithSmartRBACAuthorizedHeader("X-Gw-Authz"))
	c := newTrustCtx(t, "GET", "/x", "127.0.0.1",
		ut.Header{Key: "X-Gw-Authz", Value: GatewayAuthorizedValue},
	)
	h(context.Background(), c)
	if localCalled {
		t.Fatal("自定义头命中应跳过本地 RBAC")
	}
}

// TestSmartAuthRBAC_FullStack 全链路装配（下游 6 服务同款）：SmartAuth 立证
// → SmartRBAC 网关已鉴权跳过 → handler 经 ClaimsFrom(ctx) 读身份；随后
// 本地 JWT 形态走 SmartRBAC 本地兜底。
func TestSmartAuthRBAC_FullStack(t *testing.T) {
	trust := GatewayTrust{Secret: []byte("stack-sec")}
	probe := &parseProbe{sub: Subject{UserID: "jwt-user"}}
	localCalls := 0

	var gotClaims TrustedClaims
	var gotOK bool
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(SmartAuth(probe.parse, &trust))
	h.Use(SmartRBAC(func(ctx context.Context, c *app.RequestContext) {
		localCalls++
		c.Next(ctx)
	}))
	h.GET("/whoami", func(ctx context.Context, c *app.RequestContext) {
		gotClaims, gotOK = ClaimsFrom(ctx)
		c.JSON(http.StatusOK, map[string]any{"uid": gotClaims.UserID})
	})

	// ① 网关形态：预签名请求（ut 不提供连接对端，走签名立证路径）。
	sig := gatewaySignature(t, trust, http.MethodGet, "/whoami",
		ut.Header{Key: "X-Auth-Timestamp", Value: tsNow()},
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "7"},
		ut.Header{Key: "X-Auth-Authorized", Value: GatewayAuthorizedValue},
	)
	w := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "X-Auth-Timestamp", Value: tsNow()},
		ut.Header{Key: "X-Auth-Signature", Value: sig},
		ut.Header{Key: "X-Auth-User-ID", Value: "u42"},
		ut.Header{Key: "X-Auth-Role-IDs", Value: "7"},
		ut.Header{Key: "X-Auth-Authorized", Value: GatewayAuthorizedValue},
	)
	if w.Code != http.StatusOK {
		t.Fatalf("网关形态应 200: %d body=%s", w.Code, w.Body.String())
	}
	if !gotOK || gotClaims.UserID != "u42" {
		t.Fatalf("handler 侧 ClaimsFrom 读身份不符: ok=%v %+v", gotOK, gotClaims)
	}
	if localCalls != 0 {
		t.Fatalf("网关已鉴权不得走本地 RBAC, got %d", localCalls)
	}

	// ② 本地 JWT 形态：无网关头 → parse 兜底 → SmartRBAC 本地兜底。
	w2 := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "Authorization", Value: "Bearer tok"},
	)
	if w2.Code != http.StatusOK {
		t.Fatalf("本地形态应 200: %d body=%s", w2.Code, w2.Body.String())
	}
	if !gotOK || gotClaims.UserID != "jwt-user" {
		t.Fatalf("本地形态身份不符: ok=%v %+v", gotOK, gotClaims)
	}
	if localCalls != 1 {
		t.Fatalf("本地形态应走一次本地 RBAC, got %d", localCalls)
	}
}

// gatewaySignature 构造与目标请求同 method/uri/头值的临时上下文，走真实
// GatewaySign 得到签名（ut 请求无法在发送前改写，签名须离线预算）。
func gatewaySignature(t *testing.T, trust GatewayTrust, method, uri string, headers ...ut.Header) string {
	t.Helper()
	c := app.NewContext(0)
	c.Request.SetMethod(method)
	c.Request.URI().SetPath(uri)
	for _, h := range headers {
		c.Request.Header.Set(h.Key, h.Value)
	}
	sig, err := GatewaySign(trust, c)
	if err != nil {
		t.Fatalf("GatewaySign: %v", err)
	}
	return sig
}
