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
		t.Errorf("default extractor: Method/Path should be auto-set, got %q/%q", auth.lastSub.Method, auth.lastSub.Path)
	}
}
