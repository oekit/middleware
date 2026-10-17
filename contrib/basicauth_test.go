package contrib

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
)

func newBasicauthHertz() *server.Hertz {
	return server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
}

// TestBasicAuth_ValidPass 验证 valid pass 走通 handler。
func TestBasicAuth_ValidPass(t *testing.T) {
	h := newBasicauthHertz()
	h.Use(BasicAuth(Accounts{"alice": "secret"}))
	h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"pong": "ok"})
	})
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	w := ut.PerformRequest(h.Engine, "GET", "/ping", nil, ut.Header{
		Key: "Authorization", Value: auth,
	})
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestBasicAuth_WrongPass 验证错误密码返 401。
func TestBasicAuth_WrongPass(t *testing.T) {
	h := newBasicauthHertz()
	h.Use(BasicAuth(Accounts{"alice": "secret"}))
	h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"pong": "ok"})
	})
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:WRONG"))
	w := ut.PerformRequest(h.Engine, "GET", "/ping", nil, ut.Header{
		Key: "Authorization", Value: auth,
	})
	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestBasicAuth_MissingAuth 验证无 Authorization 头返 401。
func TestBasicAuth_MissingAuth(t *testing.T) {
	h := newBasicauthHertz()
	h.Use(BasicAuth(Accounts{"alice": "secret"}))
	h.GET("/ping", func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"pong": "ok"})
	})
	w := ut.PerformRequest(h.Engine, "GET", "/ping", nil)
	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestBasicAuthForRealm 验证自定义 realm 走通。
func TestBasicAuthForRealm(t *testing.T) {
	h := newBasicauthHertz()
	h.Use(BasicAuthForRealm(Accounts{"admin": "stronger"}, "AdminAPI", "Authorization"))
	h.GET("/admin", func(_ context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"ok": "true"})
	})
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:stronger"))
	w := ut.PerformRequest(h.Engine, "GET", "/admin", nil, ut.Header{
		Key: "Authorization", Value: auth,
	})
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
