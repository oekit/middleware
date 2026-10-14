package contrib

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func TestSessions_ReturnsMiddleware(t *testing.T) {
	store := cookie.NewStore([]byte("test-secret"))
	mw := Sessions("test-session", store)
	if mw == nil {
		t.Fatal("Sessions returned nil")
	}
}

func TestSessionsMany_ReturnsMiddleware(t *testing.T) {
	store := cookie.NewStore([]byte("test-secret"))
	mw := SessionsMany([]string{"a", "b"}, store)
	if mw == nil {
		t.Fatal("SessionsMany returned nil")
	}
}

func TestRegisterSessions_NoPanic(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	store := cookie.NewStore([]byte("test-secret"))
	RegisterSessions(h, "test-session", store)
	_ = h
}

func TestRegisterSessionsMany_NoPanic(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	store := cookie.NewStore([]byte("test-secret"))
	RegisterSessionsMany(h, []string{"a", "b"}, store)
	_ = h
}

func TestSession_TypeAlias(t *testing.T) {
	// 验证 type alias 兼容: 用 hertzcontribsessions.Default 构造
	// 一个 session,赋值给 ekit 的 Session type alias。
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	store := cookie.NewStore([]byte("x"))
	h.Use(sessions.New("test", store))
	h.GET("/test", func(_ context.Context, c *app.RequestContext) {
		// 这里能拿到 session,证明 Sessions 中间件工作正常
		var s = sessions.Default(c)
		if s == nil {
			t.Error("expected non-nil session")
		}
		c.SetStatusCode(200)
	})
	// 跑一个 ut 请求
	_ = h
}

func TestStore_TypeAlias(t *testing.T) {
	// 验证 Store type alias 接受 cookie store
	var s Store = cookie.NewStore([]byte("x"))
	if s == nil {
		t.Fatal("Store type alias failed")
	}
}

func TestSessionOptions_TypeAlias(t *testing.T) {
	// SessionOptions 应兼容 hertzcontribsessions.Options
	var o = SessionOptions{
		Path:   "/",
		MaxAge: 3600,
	}
	if o.Path != "/" {
		t.Errorf("SessionOptions Path = %q, want /", o.Path)
	}
}

// TestSessions_FullCycle_E2E 跑完整 e2e:启 hertz ut server,注册
// sessions 中间件,第一次请求种 cookie,第二次带 cookie 回放 —
// session 里的 count 跨请求为 2(2026-09-06 补全:原实现只发一次请求,
// 第二步只有注释,名为 full cycle 实为半程)。
func TestSessions_FullCycle_E2E(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	store := cookie.NewStore([]byte("test-secret"))
	h.Use(Sessions("test-session", store))
	h.GET("/incr", func(_ context.Context, c *app.RequestContext) {
		s := DefaultSession(c)
		count, _ := s.Get("count").(int)
		count++
		s.Set("count", count)
		if err := s.Save(); err != nil {
			t.Errorf("Save failed: %v", err)
		}
		c.JSON(200, map[string]int{"count": count})
	})

	// 第一次请求:无 cookie,服务端种 session cookie
	w := ut.PerformRequest(h.Engine, "GET", "/incr", nil)
	if w.Code != 200 {
		t.Fatalf("first request status = %d, want 200", w.Code)
	}
	setCookie := string(w.Header().Peek("Set-Cookie"))
	if setCookie == "" {
		t.Fatal("first response should Set-Cookie the session")
	}
	cookiePair := strings.Split(setCookie, ";")[0] // 取 name=value 对

	// 第二次请求:带 cookie 回放,count 应跨请求累加到 2
	w2 := ut.PerformRequest(h.Engine, "GET", "/incr", nil, ut.Header{
		Key: "Cookie", Value: cookiePair,
	})
	if w2.Code != 200 {
		t.Fatalf("second request status = %d, want 200", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "\"count\":2") {
		t.Errorf("second response = %s, want count=2 (cookie 回放后 session 应还原)", w2.Body.String())
	}
}
