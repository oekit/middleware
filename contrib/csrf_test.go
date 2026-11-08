package contrib

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/hertz-contrib/sessions/cookie"
)

func TestCSRFOptions_Fields(t *testing.T) {
	cfg := &CSRFOptions{}
	WithCSRFSecret("secret")(cfg)
	WithCSRFIgnoredMethods("GET")(cfg)
	WithCSRFKeyLookUp("form:_token")(cfg)

	assert.DeepEqual(t, "secret", cfg.Secret)
	assert.DeepEqual(t, "form:_token", cfg.KeyLookUp)
	assert.DeepEqual(t, []string{"GET"}, cfg.IgnoredMethods)
}

// TestCSRFMiddleware_MissingToken_403 回归：上游 hertz-contrib/csrf 默认
// ErrorFunc 会 panic(c.Errors.Last())，缺 token 这类"应拒绝"的常态路径
// 曾变成 panic（ut 下直接打挂测试）。钉住：拒绝路径是标准 403。
func TestCSRFMiddleware_MissingToken_403(t *testing.T) {
	h := server.New(
		server.WithHostPorts("127.0.0.1:0"),
		server.WithDisablePrintRoute(true),
	)
	h.Use(Sessions("csrf-test", cookie.NewStore([]byte("session-secret"))))
	h.POST("/submit", CSRFMiddleware(WithCSRFSecret("csrf-secret-32-bytes-long!!!!")),
		func(ctx context.Context, c *app.RequestContext) {
			c.JSON(200, map[string]string{"ok": "true"})
		})

	w := ut.PerformRequest(h.Engine, "POST", "/submit", nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: got %d (want 403) body=%s", w.Code, w.Body.String())
	}

	// 安全方法不受影响
	wg := ut.PerformRequest(h.Engine, "GET", "/submit", nil)
	if wg.Code == http.StatusForbidden {
		t.Errorf("GET (ignored method) should not be rejected, got %d", wg.Code)
	}
}

// TestCSRFMiddleware_EmptySecret_FailFast 回归 #122：Secret 为空（未设置或
// 显式传空串）必须在构造期 panic（fail-fast，同 ratelimit 缺配置的姿势），
// 而不是让上游 csrf.New 静默接受——空密钥时 token=sha256("salt-") 一切照常
// 工作、测试全绿，防护强度静默降档。
func TestCSRFMiddleware_EmptySecret_FailFast(t *testing.T) {
	cases := map[string][]CSRFOption{
		"not-set":        nil,
		"explicit-empty": {WithCSRFSecret("")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("empty Secret should panic at construction time")
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, "Secret") {
					t.Errorf("panic value = %v, want message mentioning Secret", r)
				}
			}()
			_ = CSRFMiddleware(opts...)
		})
	}
}
