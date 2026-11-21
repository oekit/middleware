package mw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/cloudwego/hertz/pkg/route"
)

const testBearerToken = "test-bearer-token-12345"

// fakeAuthorizer 记录被调用的参数,返回预设结果。
type fakeAuthorizer struct {
	allowed bool
	err     error

	mu         sync.Mutex
	called     int
	lastSub    Subject
	lastMethod string
	lastPath   string
}

func (f *fakeAuthorizer) Authorize(_ context.Context, c *app.RequestContext, sub Subject) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	f.lastSub = sub
	f.lastMethod = string(c.Method())
	f.lastPath = string(c.Path())
	return f.allowed, f.err
}

// buildCtx 构造一个带 Authorization header + Method/Path 的 RequestContext,
// 用于测试 BearerTokenAuth 流程。
func buildCtx(token string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/api/users")
	if token != "" {
		c.Request.Header.Set("Authorization", "Bearer "+token)
	}
	return c
}

func runBearerAuth(t *testing.T, c *app.RequestContext, opts ...BearerTokenOption) {
	t.Helper()
	h := BearerTokenAuth(opts...)
	h(context.Background(), c)
}

// TestBearerTokenAuth_NoTokenPanics 回归测试（#97）：Token 未配置且未显式
// 关闭认证时构造期 panic（fail-fast，对齐 RateLimitMiddleware 的 Rate/Burst
// 校验）——此前「为空直接放行」是静默 fail-open，认证层会无声消失。
func TestBearerTokenAuth_NoTokenPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("BearerTokenAuth() without token should panic at construction (fail-fast)")
		}
	}()
	_ = BearerTokenAuth() // 无 token、未 WithAuthDisabled → 构造期 panic
}

// TestBearerTokenAuth_EmptyTokenPanics 配置中心读到空串与忘配 option 同路：
// WithBearerToken("") 也必须在构造期炸响，而不是静默放行。
func TestBearerTokenAuth_EmptyTokenPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("BearerTokenAuth(WithBearerToken(\"\")) should panic at construction")
		}
	}()
	_ = BearerTokenAuth(WithBearerToken(""))
}

// TestBearerTokenAuth_Disabled 显式关闭认证：WithAuthDisabled 后不要求
// Token，请求直通（可 grep、可审计的开关，与「忘配 token」可区分）。
func TestBearerTokenAuth_Disabled(t *testing.T) {
	h := BearerTokenAuth(WithAuthDisabled())
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_ValidToken 验证正确 token 放行。
func TestBearerTokenAuth_ValidToken(t *testing.T) {
	h := BearerTokenAuth(WithBearerToken("secret"))
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer secret")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_InvalidToken 验证错误 token 返回 401。
func TestBearerTokenAuth_InvalidToken(t *testing.T) {
	h := BearerTokenAuth(WithBearerToken("secret"))
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer wrong")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusUnauthorized, c.Response.StatusCode())
}

// TestBearerTokenAuth_SkipPath 验证跳过路径放行。
func TestBearerTokenAuth_SkipPath(t *testing.T) {
	h := BearerTokenAuth(
		WithBearerToken("secret"),
		WithAuthSkipPaths("/health"),
	)
	c := app.NewContext(128)
	c.Request.SetRequestURI("/health")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_Authorizer_Allow 验证 token + 鉴权都通过 → 200。
func TestBearerTokenAuth_Authorizer_Allow(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx(testBearerToken)
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
	)

	if auth.called != 1 {
		t.Errorf("Authorizer called = %d, want 1", auth.called)
	}
	if auth.lastMethod != "GET" {
		t.Errorf("Subject.Method = %q, want GET", auth.lastMethod)
	}
	if auth.lastPath != "/api/users" {
		t.Errorf("Subject.Path = %q, want /api/users", auth.lastPath)
	}
	// 没有强制 status,只是 c.Next 不被调(handlers chain 空),响应 status 应是 default 200
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_Authorizer_Deny 验证 Authorizer 拒绝 → 403。
func TestBearerTokenAuth_Authorizer_Deny(t *testing.T) {
	auth := &fakeAuthorizer{allowed: false}
	c := buildCtx(testBearerToken)
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
	)

	if auth.called != 1 {
		t.Errorf("Authorizer called = %d, want 1", auth.called)
	}
	assert.DeepEqual(t, consts.StatusForbidden, c.Response.StatusCode())
}

// TestBearerTokenAuth_Authorizer_Error 验证 Authorizer 返 error → 500。
func TestBearerTokenAuth_Authorizer_Error(t *testing.T) {
	auth := &fakeAuthorizer{err: errors.New("casbin backend down")}
	c := buildCtx(testBearerToken)
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
	)

	assert.DeepEqual(t, consts.StatusInternalServerError, c.Response.StatusCode())
}

// TestBearerTokenAuth_AuthorizerNotCalledOnTokenFail 验证 token 失败
// (401) 时不调 Authorizer(避免泄漏存在性给未授权用户)。
func TestBearerTokenAuth_AuthorizerNotCalledOnTokenFail(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx("wrong-token")
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
	)

	if auth.called != 0 {
		t.Errorf("Authorizer should NOT be called on token failure, got called=%d", auth.called)
	}
	assert.DeepEqual(t, consts.StatusUnauthorized, c.Response.StatusCode())
}

// TestBearerTokenAuth_AuthorizerNotCalledOnSkipPath 验证 SkipPaths 不调 Authorizer。
func TestBearerTokenAuth_AuthorizerNotCalledOnSkipPath(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx("")
	c.Request.URI().SetPath("/healthz")
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthSkipPaths("/healthz"),
		WithAuthAuthorizer(auth),
	)

	if auth.called != 0 {
		t.Errorf("Authorizer should NOT be called on skip path, got called=%d", auth.called)
	}
}

// TestBearerTokenAuth_SubjectExtractorCustom 验证自定义 SubjectExtractor 生效。
func TestBearerTokenAuth_SubjectExtractorCustom(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx(testBearerToken)
	c.Request.Header.Set("X-Jwt-Sub", "alice")
	c.Request.Header.Set("X-Jwt-Roles", "admin,user")

	custom := func(c *app.RequestContext) Subject {
		return Subject{
			UserID: string(c.GetHeader("X-Jwt-Sub")),
			Roles:  []string{"admin", "user"},
			Method: string(c.Method()),
			Path:   string(c.Path()),
			Claims: map[string]any{"custom": "value"},
		}
	}
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
		WithAuthSubjectExtractor(custom),
	)

	if auth.lastSub.UserID != "alice" {
		t.Errorf("Subject.UserID = %q, want alice", auth.lastSub.UserID)
	}
	if len(auth.lastSub.Roles) != 2 || auth.lastSub.Roles[0] != "admin" {
		t.Errorf("Subject.Roles = %v, want [admin, user]", auth.lastSub.Roles)
	}
	if auth.lastSub.Claims["custom"] != "value" {
		t.Errorf("Subject.Claims[custom] = %v, want value", auth.lastSub.Claims["custom"])
	}
}

// TestBearerTokenAuth_DefaultSubjectExtractor 验证默认 SubjectExtractor
// 不信任客户端可控的 X-User-Id（v0.28.1 安全修正：低权 token + 伪造
// X-User-Id 曾可冒充任意 subject 过 Authorizer）。UserID 为空是默认契约；
// 网关过滤该头的内网场景用 WithAuthSubjectExtractor 显式启用。
func TestBearerTokenAuth_DefaultSubjectExtractor(t *testing.T) {
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx(testBearerToken)
	c.Request.Header.Set("X-User-Id", "bob")

	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthAuthorizer(auth),
	)

	if auth.lastSub.UserID != "" {
		t.Errorf("default extractor: UserID = %q, want empty (client-supplied header must not be trusted)", auth.lastSub.UserID)
	}
	if auth.lastSub.Method == "" || auth.lastSub.Path == "" {
		t.Errorf("default extractor: Method/Path should be auto-set, got %q/%q", auth.lastMethod, auth.lastPath)
	}
}

// TestCutBearerToken 回归测试（#96）：RFC 7235 的 credentials 语法是
// `auth-scheme [ 1*SP ( token68 / ... ) ]`——scheme 与 token 间允许一个或
// 多个 SP。此前只切第一个空格，"Bearer   secret" 切出 "  secret"，
// ConstantTimeCompare 不匹配 ⇒ 合法 token 被拒 401。
func TestCutBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantTok string
		wantOK  bool
	}{
		{"单 SP", "Bearer secret", "secret", true},
		{"多 SP（RFC 7235 1*SP）", "Bearer   secret", "secret", true},
		{"尾空白", "Bearer secret  ", "secret", true},
		{"首尾空白叠加", "Bearer \tsecret\t ", "secret", true},
		{"scheme 小写", "bearer secret", "secret", true},
		{"scheme 大写", "BEARER secret", "secret", true},
		{"切出后为空（多 SP 无 token）", "Bearer    ", "", false},
		{"无 scheme", "secret", "", false},
		{"非 bearer scheme", "Basic dXNlcjpwYXNz", "", false},
		{"空 header", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cutBearerToken(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantTok {
				t.Fatalf("token = %q, want %q", got, tt.wantTok)
			}
		})
	}
}

// TestBearerTokenAuth_MultipleSpacesToken 端到端：多 SP 的 Authorization 头
// 携带合法 token 必须放行（此前切出带前导空格的 token 被 401）。
func TestBearerTokenAuth_MultipleSpacesToken(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer   "+testBearerToken) // 3 个 SP
	runBearerAuth(t, c, WithBearerToken(testBearerToken))
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestBearerTokenAuth_SkipPathsExactMatchNotGlob 钉住 #187：认证家族
// SkipPaths 是**精确匹配**（c.Path() 原文 == 比较）——glob 形态 "/api/**"
// 不豁免 "/api/users"，`*` 无特殊含义；glob 语义仅存在于同包观测/限流家族
// （WithAccessLogSkipPaths/WithRateLimitSkipPaths 的 pathx.MatchesPath）。
// 从限流中间件迁移过来的调用方写 glob 给认证家族会静默零命中，本钉子测试
// 与 WithAuthSkipPaths 的文档声明互为印证。
func TestBearerTokenAuth_SkipPathsExactMatchNotGlob(t *testing.T) {
	// glob 形态不豁免：/api/users 不匹配 "/api/**"（精确匹配语义）。
	auth := &fakeAuthorizer{allowed: true}
	c := buildCtx(testBearerToken)
	c.Request.URI().SetPath("/api/users")
	runBearerAuth(t, c,
		WithBearerToken(testBearerToken),
		WithAuthSkipPaths("/api/**"),
		WithAuthAuthorizer(auth),
	)
	if auth.called != 1 {
		t.Fatalf("★ \"/api/**\" 不得豁免 /api/users（精确匹配，非 glob，#187）: called=%d", auth.called)
	}

	// 原文精确命中才豁免。
	auth2 := &fakeAuthorizer{allowed: true}
	c2 := buildCtx(testBearerToken)
	c2.Request.URI().SetPath("/healthz")
	runBearerAuth(t, c2,
		WithBearerToken(testBearerToken),
		WithAuthSkipPaths("/healthz"),
		WithAuthAuthorizer(auth2),
	)
	if auth2.called != 0 {
		t.Fatalf("精确命中仍应豁免: called=%d", auth2.called)
	}
}

// fakeTokenVerifier 记录调用入参并返回预设结果（#293 verifier 测试桩）。
type fakeTokenVerifier struct {
	sub Subject
	err error

	mu         sync.Mutex
	called     int
	lastToken  string
	lastAPIKey string
}

func (f *fakeTokenVerifier) Verify(_ context.Context, c *app.RequestContext, token string) (Subject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	f.lastToken = token
	f.lastAPIKey = string(c.GetHeader("X-API-Key"))
	return f.sub, f.err
}

func (f *fakeTokenVerifier) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

// subjectProbe 捕获 handler 内两条 Subject 读取出口（ctx / RequestContext）。
type subjectProbe struct {
	mu    sync.Mutex
	sub   Subject
	ok    bool
	subRC Subject
	okRC  bool
}

func (p *subjectProbe) store(sub Subject, ok bool, subRC Subject, okRC bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sub, p.ok = sub, ok
	p.subRC, p.okRC = subRC, okRC
}

func (p *subjectProbe) load() (Subject, bool, Subject, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sub, p.ok, p.subRC, p.okRC
}

// newBearerAuthEngine 构建挂了 BearerTokenAuth 的引擎，/whoami 处捕获
// SubjectFrom / SubjectFromRequestContext 读到的认证主体。
func newBearerAuthEngine(t *testing.T, opts ...BearerTokenOption) (*route.Engine, *subjectProbe) {
	t.Helper()
	probe := &subjectProbe{}
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(BearerTokenAuth(opts...))
	h.GET("/whoami", func(ctx context.Context, c *app.RequestContext) {
		sub, ok := SubjectFrom(ctx)
		subRC, okRC := SubjectFromRequestContext(c)
		probe.store(sub, ok, subRC, okRC)
		c.JSON(http.StatusOK, map[string]string{"uid": sub.UserID})
	})
	return h, probe
}

// TestBearerTokenAuth_VerifierAndStaticMutuallyExclusive 凭证校验单源：
// 静态 token 与 verifier 同时配置必须在构造期 panic，避免两套口径分叉。
func TestBearerTokenAuth_VerifierAndStaticMutuallyExclusive(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("BearerTokenAuth(WithBearerToken, WithTokenVerifier) should panic at construction")
		}
	}()
	_ = BearerTokenAuth(
		WithBearerToken("secret"),
		WithTokenVerifier(&fakeTokenVerifier{}),
	)
}

// TestBearerTokenAuth_VerifierRequired 只有 nil verifier（无静态 token）
// 等同「未配置凭证源」，沿用 #97 构造期 panic。
func TestBearerTokenAuth_VerifierRequired(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("BearerTokenAuth(WithTokenVerifier(nil)) without static token should panic")
		}
	}()
	_ = BearerTokenAuth(WithTokenVerifier(nil))
}

// TestBearerTokenAuth_StaticTokenAlias WithStaticToken 与 WithBearerToken
// 等价：静态 token 默认行为保持兼容。
func TestBearerTokenAuth_StaticTokenAlias(t *testing.T) {
	h := BearerTokenAuth(WithStaticToken("secret"))

	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.Set("Authorization", "Bearer secret")
	h(context.Background(), c)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())

	c2 := app.NewContext(128)
	c2.Request.SetRequestURI("/test")
	c2.Request.Header.Set("Authorization", "Bearer wrong")
	h(context.Background(), c2)
	assert.DeepEqual(t, consts.StatusUnauthorized, c2.Response.StatusCode())
}

// TestBearerTokenAuth_Verifier_AllowInjectsSubject 自定义 verifier 命中：
// Verify 收到切出的 token 与请求上下文；返回的 Subject 作为唯一主体传给
// Authorizer，并注入 ctx / RequestContext 供下游读取。
func TestBearerTokenAuth_Verifier_AllowInjectsSubject(t *testing.T) {
	v := &fakeTokenVerifier{sub: Subject{
		UserID: "alice",
		Roles:  []string{"admin", "user"},
		Claims: map[string]any{"scope": "read", "tenant": "t-1"},
	}}
	auth := &fakeAuthorizer{allowed: true}
	h, probe := newBearerAuthEngine(t,
		WithTokenVerifier(v),
		WithAuthAuthorizer(auth),
	)

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "Authorization", Value: "Bearer dynamic-token"},
		ut.Header{Key: "X-API-Key", Value: "raw-api-key"},
	).Result()

	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", r.StatusCode(), r.Body())
	}
	if got := v.calls(); got != 1 {
		t.Fatalf("verifier called = %d, want 1", got)
	}
	if v.lastToken != "dynamic-token" {
		t.Errorf("verifier token = %q, want dynamic-token", v.lastToken)
	}
	if v.lastAPIKey != "raw-api-key" {
		t.Errorf("verifier should see request context (X-API-Key) = %q", v.lastAPIKey)
	}

	if auth.called != 1 {
		t.Fatalf("Authorizer called = %d, want 1", auth.called)
	}
	if auth.lastSub.UserID != "alice" || len(auth.lastSub.Roles) != 2 {
		t.Errorf("Authorizer Subject = %+v, want UserID=alice Roles=[admin user]", auth.lastSub)
	}
	if auth.lastSub.Claims["scope"] != "read" {
		t.Errorf("Authorizer Subject.Claims[scope] = %v, want read", auth.lastSub.Claims["scope"])
	}
	if auth.lastMethod != "GET" || auth.lastPath != "/whoami" {
		t.Errorf("Authorizer saw method/path %q/%q, want GET//whoami", auth.lastMethod, auth.lastPath)
	}

	sub, ok, subRC, okRC := probe.load()
	if !ok || !okRC {
		t.Fatalf("SubjectFrom(ctx)=%v SubjectFromRequestContext(c)=%v, want both ok", ok, okRC)
	}
	for name, got := range map[string]Subject{"ctx": sub, "request-context": subRC} {
		if got.UserID != "alice" {
			t.Errorf("%s Subject.UserID = %q, want alice", name, got.UserID)
		}
		if got.Method != "GET" || got.Path != "/whoami" {
			t.Errorf("%s Subject method/path = %q/%q, want GET//whoami (request wins)", name, got.Method, got.Path)
		}
		if got.Claims["tenant"] != "t-1" {
			t.Errorf("%s Subject.Claims[tenant] = %v, want t-1", name, got.Claims["tenant"])
		}
	}
}

// TestBearerTokenAuth_Verifier_ErrorMapping verifier 错误分类：
// ErrInvalidToken → 401（含 %w 包装）、ErrForbidden → 403、其他 error → 500；
// 任一失败都不得调 Authorizer。
func TestBearerTokenAuth_Verifier_ErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"invalid token", ErrInvalidToken, consts.StatusUnauthorized},
		{"wrapped invalid token", fmt.Errorf("api key lookup: %w", ErrInvalidToken), consts.StatusUnauthorized},
		{"forbidden", ErrForbidden, consts.StatusForbidden},
		{"backend failure", errors.New("idp unavailable"), consts.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &fakeTokenVerifier{err: tt.err}
			auth := &fakeAuthorizer{allowed: true}
			c := buildCtx("dynamic-token")
			runBearerAuth(t, c,
				WithTokenVerifier(v),
				WithAuthAuthorizer(auth),
			)
			assert.DeepEqual(t, tt.want, c.Response.StatusCode())
			if auth.called != 0 {
				t.Errorf("Authorizer should NOT be called when verifier fails, got called=%d", auth.called)
			}
		})
	}
}

// TestBearerTokenAuth_Verifier_NotCalledOnSkipPath 免认证路径不触发校验后端
// （SkipPaths 与 verifier 的边界：豁免发生在凭证校验之前）。
func TestBearerTokenAuth_Verifier_NotCalledOnSkipPath(t *testing.T) {
	v := &fakeTokenVerifier{}
	c := app.NewContext(128)
	c.Request.SetRequestURI("/health")
	runBearerAuth(t, c,
		WithTokenVerifier(v),
		WithAuthSkipPaths("/health"),
	)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	if got := v.calls(); got != 0 {
		t.Errorf("verifier called = %d on skip path, want 0", got)
	}
}

// TestBearerTokenAuth_Verifier_NotCalledOnMalformedHeader 头格式非法
// （非 Bearer scheme / 空 token）直接 401，不把空凭证交给校验后端。
func TestBearerTokenAuth_Verifier_NotCalledOnMalformedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"missing header", ""},
		{"non-bearer scheme", "Basic dXNlcjpwYXNz"},
		{"empty token", "Bearer    "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &fakeTokenVerifier{sub: Subject{UserID: "should-not-happen"}}
			c := app.NewContext(128)
			c.Request.SetRequestURI("/test")
			if tt.header != "" {
				c.Request.Header.Set("Authorization", tt.header)
			}
			runBearerAuth(t, c, WithVerifier(v))
			assert.DeepEqual(t, consts.StatusUnauthorized, c.Response.StatusCode())
			if got := v.calls(); got != 0 {
				t.Errorf("verifier called = %d on malformed header, want 0", got)
			}
		})
	}
}

// TestBearerTokenAuth_Verifier_IgnoresSubjectExtractor verifier 模式主体
// 唯一来源是 Verify 返回值：SubjectExtractor 不得运行（防止已校验身份被
// 客户端可控请求头二次改写）。
func TestBearerTokenAuth_Verifier_IgnoresSubjectExtractor(t *testing.T) {
	v := &fakeTokenVerifier{sub: Subject{UserID: "alice"}}
	auth := &fakeAuthorizer{allowed: true}
	called := 0
	c := buildCtx("dynamic-token")
	runBearerAuth(t, c,
		WithTokenVerifier(v),
		WithAuthAuthorizer(auth),
		WithAuthSubjectExtractor(func(c *app.RequestContext) Subject {
			called++
			return Subject{UserID: "mallory"}
		}),
	)
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
	if called != 0 {
		t.Errorf("SubjectExtractor called = %d in verifier mode, want 0", called)
	}
	if auth.lastSub.UserID != "alice" {
		t.Errorf("Authorizer Subject.UserID = %q, want alice", auth.lastSub.UserID)
	}
}

// TestBearerTokenAuth_StaticInjectsSubject 静态 token 兼容路径也注入主体：
// 自定义 SubjectExtractor 的结果对下游可见，Method/Path 以请求为准。
func TestBearerTokenAuth_StaticInjectsSubject(t *testing.T) {
	h, probe := newBearerAuthEngine(t,
		WithStaticToken("secret"),
		WithAuthSubjectExtractor(func(c *app.RequestContext) Subject {
			return Subject{
				UserID: "static-user",
				Roles:  []string{"svc"},
				Claims: map[string]any{"source": "static"},
			}
		}),
	)

	r := ut.PerformRequest(h, http.MethodGet, "/whoami", nil,
		ut.Header{Key: "Authorization", Value: "Bearer secret"},
	).Result()
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", r.StatusCode(), r.Body())
	}

	sub, ok, subRC, okRC := probe.load()
	if !ok || !okRC {
		t.Fatalf("SubjectFrom(ctx)=%v SubjectFromRequestContext(c)=%v, want both ok", ok, okRC)
	}
	if sub.UserID != "static-user" || subRC.UserID != "static-user" {
		t.Errorf("UserID ctx/rc = %q/%q, want static-user", sub.UserID, subRC.UserID)
	}
	if sub.Method != "GET" || sub.Path != "/whoami" {
		t.Errorf("Subject method/path = %q/%q, want GET//whoami", sub.Method, sub.Path)
	}
	if sub.Claims["source"] != "static" {
		t.Errorf("Subject.Claims[source] = %v, want static", sub.Claims["source"])
	}
}

// TestBearerTokenAuth_VerifierFunc TokenVerifierFunc 闭包适配器可直接用。
func TestBearerTokenAuth_VerifierFunc(t *testing.T) {
	c := buildCtx("dynamic-token")
	runBearerAuth(t, c, WithVerifier(TokenVerifierFunc(
		func(_ context.Context, _ *app.RequestContext, token string) (Subject, error) {
			if token != "dynamic-token" {
				return Subject{}, ErrInvalidToken
			}
			return Subject{UserID: "bob"}, nil
		},
	)))
	assert.DeepEqual(t, consts.StatusOK, c.Response.StatusCode())
}

// TestSubjectFrom_UnregisteredContext 未经过 BearerTokenAuth 的 context /
// RequestContext 返回 ok=false（区分「未认证」与「认证后空主体」）。
func TestSubjectFrom_UnregisteredContext(t *testing.T) {
	if _, ok := SubjectFrom(context.Background()); ok {
		t.Error("SubjectFrom on plain context should return ok=false")
	}
	if _, ok := SubjectFromRequestContext(app.NewContext(8)); ok {
		t.Error("SubjectFromRequestContext on untouched context should return ok=false")
	}
}
