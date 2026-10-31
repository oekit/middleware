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
// 因为 JWTAuth 用懒构造(全局单例),需要在每个测试前重置。
//
// ⚠️ 必须**整体重置**:runtime 是 atomic.Pointer,只清 opts 会留下上一次的
//
//	runtime ⇒ 测试之间互相污染(且 materialKey 指纹也会命中"无需重建")。
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

// TestJWTAuth_SecretRotationKeepsSignAndVerifyConsistent 钉住 **签发/验签分裂**。
//
// 缺陷形态（2026-10-31 实测）：上游 HertzJWTMiddleware 把 Key/SigningAlgorithm
// **拷进自己的字段**（构造后冻结），而全局 opts 是**可变**的。
// ⇒ 二次调用 JWTAuth(换 secret)后：
//   - 签发（JWTGenerateToken 读 opts）用**新** Key
//   - 验签（中间件读 instance）用**旧** Key
//     ⇒ 自家签的 token 被自家中间件 401 "signature is invalid"。
//
// 本测试是**行为级**断言：签发出来的 token 必须能被自家中间件接受。
// 断言「签发与验签同源」，而不是断言某个内部字段的值。
func TestJWTAuth_SecretRotationKeepsSignAndVerifyConsistent(t *testing.T) {
	resetJWTState()

	const secretA = "secret-A-at-least-32-bytes-long-for-hs256-alg-x"
	const secretB = "secret-B-at-least-32-bytes-long-for-hs256-alg-y"

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
	protected := JWTAuth(WithJWTSecret([]byte(secretA)))
	h.GET("/protected", protected, func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})

	// 轮换密钥：再次调用 JWTAuth 换 secret（运维常规动作）。
	_ = JWTAuth(WithJWTSecret([]byte(secretB)))

	// ⚠️ 轮换必须**真的生效**：当前 instance 必须用**新**密钥。
	//    否则就是「轮换静默失效」——旧密钥仍被接受、新密钥签的 token 被拒,
	//    而表面一切正常(没有报错)。
	//    这条判据是「不重建 instance」那个变异的唯一区分点。
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.instance == nil {
		t.Fatal("轮换后 runtime 未构造")
	}
	if got := string(rt.instance.Key); got != secretB {
		t.Errorf("★ 轮换 secret 未生效：instance.Key = %q，期望新密钥 %q", got, secretB)
	}

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

	// 轮换后签发的 token 必须仍被自家中间件接受。
	w2 := ut.PerformRequest(h.Engine, "GET", "/protected", nil, ut.Header{
		Key: "Authorization", Value: "Bearer " + loginResp.Token,
	})
	if w2.Code != 200 {
		t.Errorf("轮换 secret 后自签 token 被自家中间件拒绝: got %d (want 200) body=%s",
			w2.Code, w2.Body.String())
	}
}

// TestJWTAuth_AlgorithmChangeKeepsSignAndVerifyConsistent 同型缺陷：
// 换签名算法（HS256 → HS512）后，签发用新算法、验签用旧算法 ⇒
// 解析直接失败（"invalid signing algorithm"）。
func TestJWTAuth_AlgorithmChangeKeepsSignAndVerifyConsistent(t *testing.T) {
	resetJWTState()

	const secret = "secret-at-least-32-bytes-long-for-hs256-alg-xyz"

	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.POST("/login", func(_ context.Context, c *app.RequestContext) {
		tok, err := JWTGenerateToken(jwt.MapClaims{"user_id": "bob"})
		if err != nil {
			c.JSON(500, map[string]string{"err": err.Error()})
			return
		}
		c.JSON(200, map[string]string{"token": tok})
	})
	protected := JWTAuth(WithJWTSecret([]byte(secret)))
	h.GET("/protected", protected, func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})

	// 换签名算法。
	_ = JWTAuth(WithJWTSecret([]byte(secret)), WithJWTAlgorithm("HS512"))

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

	w2 := ut.PerformRequest(h.Engine, "GET", "/protected", nil, ut.Header{
		Key: "Authorization", Value: "Bearer " + loginResp.Token,
	})
	if w2.Code != 200 {
		t.Errorf("换算法后自签 token 被自家中间件拒绝: got %d (want 200) body=%s",
			w2.Code, w2.Body.String())
	}

	// JWTParse 也必须能用新算法解析（同一 runtime）。
	if _, err := JWTParse(loginResp.Token); err != nil {
		t.Errorf("JWTParse 换算法后失败: %v", err)
	}
}

// TestJWTAuth_SignAndVerifyShareSameSource 钉住「同源」这个不变量本身：
// 签发用的 Key/Algorithm 必须与验签 instance 里的**完全一致**。
//
// 为什么单独一条：上面两条是**行为级**（某个配置组合下会炸），
// 这条是**结构级**（签发与验签读同一个对象）⇒ 任何配置组合下都不会分裂。
func TestJWTAuth_SignAndVerifyShareSameSource(t *testing.T) {
	resetJWTState()

	const secret = "secret-at-least-32-bytes-long-for-hs256-alg-abc"
	_ = JWTAuth(WithJWTSecret([]byte(secret)), WithJWTAlgorithm("HS512"))

	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.instance == nil {
		t.Fatal("runtime 未构造")
	}
	// 签发侧读到的 algorithm 必须来自 instance（而不是另有一份 opts）。
	if got := rt.instance.SigningAlgorithm; got != "HS512" {
		t.Errorf("instance.SigningAlgorithm = %q, want HS512", got)
	}
	if got := rt.instance.Key; string(got) != secret {
		t.Errorf("instance.Key = %q, want %q", got, secret)
	}
}

// TestJWTAuth_SigningMaterialComesFromRuntime 钉住「签发材料取自 runtime」
// 这条**结构性**判据。
//
// 为什么必须单独一条（2026-10-31 变异验证实测）：
// 修复之后，「重建 instance」会让 opts 与 instance 的值**恰好相同**
// ⇒ 单看行为（签发的 token 能否被验签通过）**测不出**「签发侧读的是
// opts 还是 instance」——两者结果一样！
// ⇒ 唯一有区分力的判据是：**签发用的材料必须取自 runtime 里的 instance**。
//
//	变异「签发退回读 opts」⇒ 本判据立刻转红。
//
// 做法：先构造好 runtime，再**绕过 JWTAuth**直接把 opts 改成别的值
// （模拟「有人改了 opts 但 instance 没重建」这个中间态），
// 然后签发 ⇒ 签出来的 token 必须仍能被**当前 runtime 的 instance** 验签通过。
// ⇒ 若签发读的是 opts，签出来的就是另一个密钥 ⇒ 验签失败 ⇒ 转红。
func TestJWTAuth_SigningMaterialComesFromRuntime(t *testing.T) {
	resetJWTState()

	const secret = "secret-at-least-32-bytes-long-for-hs256-alg-qrs"
	const other = "OTHER-secret-at-least-32-bytes-long-for-hs256-alg-z"

	_ = JWTAuth(WithJWTSecret([]byte(secret)))
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.instance == nil {
		t.Fatal("runtime 未构造")
	}

	// 制造中间态：opts 被改成别的密钥，但 instance 仍是旧的。
	// 这正是「签发读 opts、验签读 instance」会分裂的那个窗口。
	globalJWTState.mu.Lock()
	globalJWTState.opts.secret = []byte(other)
	globalJWTState.mu.Unlock()

	// 签发 ⇒ 必须用 runtime 里 instance 的密钥（= secret），不是 opts 的 other。
	tok, err := JWTGenerateToken(jwt.MapClaims{"user_id": "carol"})
	if err != nil {
		t.Fatalf("JWTGenerateToken: %v", err)
	}

	// 验签：用 runtime 的 instance 解析。
	// 若签发读了 opts（other），这里必然失败。
	if _, err := rt.instance.ParseTokenString(tok); err != nil {
		t.Errorf("★ 签发材料不来自 runtime:签出的 token 无法被当前 instance 验签（%v）", err)
	}
	// 双保险：JWTParse（走 runtime）也必须能解。
	if _, err := JWTParse(tok); err != nil {
		t.Errorf("JWTParse 失败: %v", err)
	}
}
