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
				_ = JWTAuth(WithJWTSecret([]byte(testJWTSecret)), WithJWTTimeout(time.Hour))
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

// mustSignToken 用给定密钥/算法签出带 exp 的测试 token（不经全局状态，
// 模拟外部签发方）。
func mustSignToken(t *testing.T, secret, alg string, claims jwt.MapClaims) string {
	t.Helper()
	full := make(jwt.MapClaims, len(claims)+1)
	for k, v := range claims {
		full[k] = v
	}
	if _, ok := full["exp"]; !ok {
		full["exp"] = time.Now().Add(time.Hour).Unix()
	}
	signed, err := jwt.NewWithClaims(jwt.GetSigningMethod(alg), full).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// probeJWTStatus 直接调用中间件实例探测验签结果（200=放行，401=拒绝）。
func probeJWTStatus(t *testing.T, h app.HandlerFunc, path, token string) int {
	t.Helper()
	c := app.NewContext(0)
	c.Request.URI().SetPath(path)
	if token != "" {
		c.Request.Header.Set("Authorization", "Bearer "+token)
	}
	h(context.Background(), c)
	return c.Response.StatusCode()
}

// TestJWTAuth_MultiInstanceSecretIsolation 钉住 #139（P0）：JWTAuth 的验签
// 密钥必须**实例私有**——第二次注册不得覆写先前实例的密钥。缺陷形态（实测）：
// 密钥落包级全局 ⇒ 两个实例都只认最后一次注册的 secretB，/a 拒绝 A 自己签
// 的 token 却接受 B 签的 token，跨服务认证边界被静默跨越（持有 B 密钥的一
// 方可以访问 A）；对照形态（攻击者密钥/缺头）验签本身没失效，坏的只是
// 「用哪个密钥验签」这一项。
func TestJWTAuth_MultiInstanceSecretIsolation(t *testing.T) {
	resetJWTState()

	const (
		secretA = "service-A-secret-key-32-bytes-long-xxxx"
		secretB = "service-B-secret-key-32-bytes-long-yyyy"
		secretX = "attacker-secret-key-32-bytes-long-zzz!"
	)

	mwA := JWTAuth(WithJWTSecret([]byte(secretA)))
	mwB := JWTAuth(WithJWTSecret([]byte(secretB))) // 第二次注册 ⇒ 不得覆写 A 的验签密钥

	tokA := mustSignToken(t, secretA, "HS256", jwt.MapClaims{"user_id": "alice"})
	tokB := mustSignToken(t, secretB, "HS256", jwt.MapClaims{"user_id": "alice"})
	tokX := mustSignToken(t, secretX, "HS256", jwt.MapClaims{"user_id": "mallory"})

	// /a 形态：A 实例只认 A 签的 token。
	if code := probeJWTStatus(t, mwA, "/a", tokA); code != 200 {
		t.Errorf("A 实例拒绝 A 签的 token: got %d, want 200（自家凭据被静默作废）", code)
	}
	if code := probeJWTStatus(t, mwA, "/a", tokB); code != 401 {
		t.Errorf("★ A 实例接受了 B 签的 token: got %d, want 401（跨服务认证边界被跨越，#139）", code)
	}
	if code := probeJWTStatus(t, mwA, "/a", tokX); code != 401 {
		t.Errorf("A 实例接受了攻击者密钥签的 token: got %d, want 401", code)
	}
	if code := probeJWTStatus(t, mwA, "/a", ""); code != 401 {
		t.Errorf("A 实例放行了无 Authorization 头的请求: got %d, want 401", code)
	}

	// /b 形态：B 实例只认 B 签的 token。
	if code := probeJWTStatus(t, mwB, "/b", tokB); code != 200 {
		t.Errorf("B 实例拒绝 B 签的 token: got %d, want 200", code)
	}
	if code := probeJWTStatus(t, mwB, "/b", tokA); code != 401 {
		t.Errorf("★ B 实例接受了 A 签的 token: got %d, want 401（#139）", code)
	}
}

// TestJWTAuth_RotationReplacesSigningDefaultOnly 钉住 #139 之后的「轮换」
// 语义：再次调用 JWTAuth(新密钥)只更新**全局签发缺省**（JWTGenerateToken/
// JWTParse），已注册实例的验签快照在构造期冻结、不被覆写——「不该共享却
// 共享了」的跨服务放行形态（#139）正是旧的全局覆写机制本身。
func TestJWTAuth_RotationReplacesSigningDefaultOnly(t *testing.T) {
	resetJWTState()

	const secretA = "secret-A-at-least-32-bytes-long-for-hs256-alg-x"
	const secretB = "secret-B-at-least-32-bytes-long-for-hs256-alg-y"

	mwA := JWTAuth(WithJWTSecret([]byte(secretA)))

	// 轮换：再次调用 JWTAuth 换 secret（运维常规动作）。
	mwB := JWTAuth(WithJWTSecret([]byte(secretB)))

	// 全局签发缺省 = 新密钥（轮换的生效面）。
	rt := globalJWTState.runtime.Load()
	if rt == nil || rt.instance == nil {
		t.Fatal("轮换后 runtime 未构造")
	}
	if got := string(rt.instance.Key); got != secretB {
		t.Errorf("轮换未更新签发缺省: instance.Key = %q, want %q", got, secretB)
	}

	// 签发（全局缺省）产出 B 签 token，JWTParse（全局）可解。
	tokB, err := JWTGenerateToken(jwt.MapClaims{"user_id": "alice"})
	if err != nil {
		t.Fatalf("JWTGenerateToken after rotation: %v", err)
	}
	if _, err := JWTParse(tokB); err != nil {
		t.Fatalf("JWTParse after rotation: %v", err)
	}

	// 轮换后构造的新实例用 B 验签：B 签 token 放行。
	if code := probeJWTStatus(t, mwB, "/protected", tokB); code != 200 {
		t.Errorf("轮换后新实例拒绝 B 签 token: got %d, want 200", code)
	}

	// ⚠️ 已注册实例不被覆写（#139 核心隔离）：A 实例仍验 A 的密钥。
	if code := probeJWTStatus(t, mwA, "/protected", tokB); code != 401 {
		t.Errorf("★ 轮换覆写了已注册实例的验签密钥: got %d, want 401（#139）", code)
	}
	tokA := mustSignToken(t, secretA, "HS256", jwt.MapClaims{"user_id": "alice"})
	if code := probeJWTStatus(t, mwA, "/protected", tokA); code != 200 {
		t.Errorf("A 实例拒绝 A 签 token: got %d, want 200", code)
	}
}

// TestJWTAuth_AlgorithmChangeReplacesSigningDefaultOnly 同型（#139）：换签名
// 算法只更新全局签发缺省；已注册实例的算法快照冻结（旧实例仍按注册时的
// HS256 验签，新实例按 HS512）。
func TestJWTAuth_AlgorithmChangeReplacesSigningDefaultOnly(t *testing.T) {
	resetJWTState()

	const secret = "secret-at-least-32-bytes-long-for-hs256-alg-xyz"

	mwHS256 := JWTAuth(WithJWTSecret([]byte(secret)))
	mwHS512 := JWTAuth(WithJWTSecret([]byte(secret)), WithJWTAlgorithm("HS512"))

	// 全局签发缺省 = HS512：JWTGenerateToken/JWTParse 都走新算法。
	tok512, err := JWTGenerateToken(jwt.MapClaims{"user_id": "bob"})
	if err != nil {
		t.Fatalf("JWTGenerateToken after algorithm change: %v", err)
	}
	if _, err := JWTParse(tok512); err != nil {
		t.Fatalf("JWTParse after algorithm change: %v", err)
	}

	// 新实例（HS512）接受 HS512 token；旧实例（HS256 快照冻结）拒绝。
	if code := probeJWTStatus(t, mwHS512, "/protected", tok512); code != 200 {
		t.Errorf("HS512 实例拒绝 HS512 token: got %d, want 200", code)
	}
	if code := probeJWTStatus(t, mwHS256, "/protected", tok512); code != 401 {
		t.Errorf("★ 换算法覆写了已注册实例: got %d, want 401（#139）", code)
	}

	// 旧实例仍接受自己算法签的 token。
	tok256 := mustSignToken(t, secret, "HS256", jwt.MapClaims{"user_id": "bob"})
	if code := probeJWTStatus(t, mwHS256, "/protected", tok256); code != 200 {
		t.Errorf("HS256 实例拒绝 HS256 token: got %d, want 200", code)
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
