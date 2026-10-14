package contrib

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/golang-jwt/jwt/v4"
	jwthertz "github.com/hertz-contrib/jwt"
)

// resetJWTState 重新设置全局 jwtState,每个测试隔离。
// 因为 JWTAuth 用 sync.Once 懒构造,需要在每个测试前重置。
func resetJWTState() {
	globalJWTState = jwtState{}
}

const testJWTSecret = "test-secret-key-at-least-32-bytes-long-for-hs256-alg"

// TestJWTAuth_GeneratesAndParsesToken 钉住 happy path:签发 + 解析。
func TestJWTAuth_GeneratesAndParsesToken(t *testing.T) {
	resetJWTState()

	_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)))

	claims := jwt.MapClaims{
		"user_id": "alice",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	token, err := JWTGenerateToken(claims)
	if err != nil {
		t.Fatalf("JWTGenerateToken: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	parsed, err := JWTParse(token)
	if err != nil {
		t.Fatalf("JWTParse: %v", err)
	}
	if parsed["user_id"] != "alice" {
		t.Errorf("parsed user_id = %v, want alice", parsed["user_id"])
	}
}

// TestJWTAuth_RejectsBadSignature 验证错误签名 token 被拒绝。
func TestJWTAuth_RejectsBadSignature(t *testing.T) {
	resetJWTState()

	_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)))

	// 用不同的 secret 签发 token
	otherMW, _ := jwthertz.New(&jwthertz.HertzJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: "HS256",
		Key:              []byte("different-secret-key-32-bytes-here-yes-good"),
		Timeout:          time.Hour,
	})
	badToken, _, _ := otherMW.TokenGenerator(jwt.MapClaims{"user_id": "mallory"})

	_, err := JWTParse(badToken)
	if err == nil {
		t.Fatal("expected error parsing token with wrong signature, got nil")
	}
}

// TestJWTAuth_RejectsExpiredToken 验证过期 token 被拒绝。
func TestJWTAuth_RejectsExpiredToken(t *testing.T) {
	resetJWTState()

	_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)))

	// 负 Timeout → 已过期
	expiredMW, _ := jwthertz.New(&jwthertz.HertzJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: "HS256",
		Key:              []byte(testJWTSecret),
		Timeout:          -time.Hour,
	})
	expiredToken, _, _ := expiredMW.TokenGenerator(jwt.MapClaims{"user_id": "alice"})

	_, err := JWTParse(expiredToken)
	if err == nil {
		t.Fatal("expected error parsing expired token, got nil")
	}
}

// TestJWTAuth_RequiresSecretFailsClosed 验证不传 secret 时构造失败 →
// fail-closed:返回的中间件把请求 500,而不是静默放行(认证中间件缺省方向
// 必须是拒绝);补传 secret 后再次调用 JWTAuth 即恢复。
func TestJWTAuth_RequiresSecretFailsClosed(t *testing.T) {
	resetJWTState()

	handler := JWTAuth() // 无 secret
	if handler == nil {
		t.Fatal("JWTAuth should return a handler even when secret is missing")
	}
	c := app.NewContext(0)
	handler(context.Background(), c)
	if c.Response.StatusCode() != 500 {
		t.Errorf("fail-closed: expected 500 on missing secret, got %d", c.Response.StatusCode())
	}
	if !c.IsAborted() {
		t.Error("expected request aborted (fail-closed)")
	}

	// 补传 secret 后可恢复(无 once 毒化)
	_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)))
	claims := jwt.MapClaims{"user_id": "alice"}
	tok, err := JWTGenerateToken(claims)
	if err != nil {
		t.Fatalf("JWTGenerateToken after recovery: %v", err)
	}
	if _, err := JWTParse(tok); err != nil {
		t.Fatalf("JWTParse after recovery: %v", err)
	}
}

// TestJWTAuth_GeneratedTokenAcceptedByMiddleware 行为级回环:JWTGenerateToken
// 签发的 token(业务不手工传 exp)必须被自家 JWTAuth 中间件放行。
// 钉住 2026-09-05 修复的回归:签发不含 exp → 上游中间件 400 ErrMissingExpField。
func TestJWTAuth_GeneratedTokenAcceptedByMiddleware(t *testing.T) {
	resetJWTState()

	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.POST("/login", func(_ context.Context, c *app.RequestContext) {
		tok, err := JWTGenerateToken(jwt.MapClaims{"user_id": "alice"})
		if err != nil {
			c.JSON(500, map[string]string{"err": err.Error()})
			return
		}
		c.JSON(200, map[string]string{"token": tok})
	})
	protected := JWTAuth(WithJWTSecret([]byte(testJWTSecret)))
	h.GET("/protected", func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})
	h.GET("/open", protected, func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})

	// 1. 登录拿 token
	w := ut.PerformRequest(h.Engine, "POST", "/login", nil)
	if w.Code != 200 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil || loginResp.Token == "" {
		t.Fatalf("bad login response: %v %s", err, w.Body.String())
	}

	// 2. 带 token 访问受保护路由 → 200
	w2 := ut.PerformRequest(h.Engine, "GET", "/open", nil, ut.Header{
		Key: "Authorization", Value: "Bearer " + loginResp.Token,
	})
	if w2.Code != 200 {
		t.Errorf("protected route with generated token: got %d (want 200) body=%s", w2.Code, w2.Body.String())
	}

	// 3. 不带 token → 401
	w3 := ut.PerformRequest(h.Engine, "GET", "/open", nil)
	if w3.Code != 401 {
		t.Errorf("protected route without token: got %d (want 401)", w3.Code)
	}
}

// TestJWTAuth_ConcurrentAccess -race 验证:JWTAuth/JWTGenerateToken/JWTParse
// 并发调用无数据竞争(全局态经 mu 保护)。
func TestJWTAuth_ConcurrentAccess(t *testing.T) {
	resetJWTState()

	_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = JWTAuth(WithJWTTimeout(time.Hour))
				tok, err := JWTGenerateToken(jwt.MapClaims{"user_id": "bob"})
				if err == nil && tok != "" {
					_, _ = JWTParse(tok)
				}
			}
		}()
	}
	wg.Wait()
}

// TestJWTAuth_ParseBeforeInitReturnsError 验证未初始化时 Parse 返回错误。
func TestJWTAuth_ParseBeforeInitReturnsError(t *testing.T) {
	resetJWTState()

	_, err := JWTParse("some.jwt.token")
	if err == nil {
		t.Fatal("expected error from JWTParse before JWTAuth init")
	}
}

// TestJWTAuth_GenerateBeforeInitReturnsError 验证未初始化时 Generate 返回错误。
func TestJWTAuth_GenerateBeforeInitReturnsError(t *testing.T) {
	resetJWTState()

	_, err := JWTGenerateToken(jwt.MapClaims{"user_id": "alice"})
	if err == nil {
		t.Fatal("expected error from JWTGenerateToken before JWTAuth init")
	}
}

// TestJWTAuth_AlgorithmOption 验证 WithJWTAlgorithm 选项应用。
func TestJWTAuth_AlgorithmOption(t *testing.T) {
	resetJWTState()

	_ = JWTAuth(
		WithJWTSecret([]byte(testJWTSecret)),
		WithJWTAlgorithm("HS512"),
		WithJWTTimeout(2*time.Hour),
	)
	claims := jwt.MapClaims{
		"user_id": "alice",
		"exp":     time.Now().Add(2 * time.Hour).Unix(),
	}
	tok, err := JWTGenerateToken(claims)
	if err != nil {
		t.Fatalf("JWTGenerateToken with HS512: %v", err)
	}
	parsed, err := JWTParse(tok)
	if err != nil {
		t.Fatalf("JWTParse HS512 token: %v", err)
	}
	if parsed["user_id"] != "alice" {
		t.Errorf("parsed user_id = %v, want alice", parsed["user_id"])
	}
}

// TestJWTAuth_SkipPaths 回归：WithJWTSkipPaths 曾被静默忽略（上游无跳过机制，
// 选项存了但没用），声明跳过的路径实际仍被 401 拦截。钉住：跳过路径匿名 200，
// 其余路径无 token 仍 401。
func TestJWTAuth_SkipPaths(t *testing.T) {
	resetJWTState()

	protected := JWTAuth(
		WithJWTSecret([]byte(testJWTSecret)),
		WithJWTSkipPaths("/healthz", "/login"),
	)

	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.GET("/healthz", protected, func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})
	h.GET("/private", protected, func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})

	w := ut.PerformRequest(h.Engine, "GET", "/healthz", nil)
	if w.Code != 200 {
		t.Errorf("skip path without token: got %d (want 200) body=%s", w.Code, w.Body.String())
	}

	w2 := ut.PerformRequest(h.Engine, "GET", "/private", nil)
	if w2.Code != 401 {
		t.Errorf("protected path without token: got %d (want 401)", w2.Code)
	}
}
