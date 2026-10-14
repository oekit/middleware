package mw

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
)

// TestSkipResponseWrap Escape hatch：置位后 ResponseMiddleware 不得包壳。
func TestSkipResponseWrap(t *testing.T) {
	h := route.NewEngine(config.NewOptions([]config.Option{}))
	h.Use(ResponseMiddleware())
	h.GET("/std", func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{"plain": true})
	})
	h.GET("/esc", func(ctx context.Context, c *app.RequestContext) {
		SkipResponseWrap(c)
		c.JSON(200, map[string]any{"escaped": true})
	})

	r1 := ut.PerformRequest(h, http.MethodGet, "/std", nil).Result()
	t.Logf("std body: %s", string(r1.Body()))
	r2 := ut.PerformRequest(h, http.MethodGet, "/esc", nil).Result()
	t.Logf("esc body: %s", string(r2.Body()))
	assert.DeepEqual(t, true, len(r2.Body()) > 0 && string(r2.Body())[0] == '{' && !bytes.Contains(r2.Body(), []byte(`"code"`)))
}
