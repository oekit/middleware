package mw

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
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
