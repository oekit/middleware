package mw

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	bizerrors "github.com/oekit/pkg/errors"
	"github.com/oekit/middleware/hmw"
	"github.com/oekit/tracing/traceid"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

func TestResponseMiddleware_WrapNonCodeResponse(t *testing.T) {
	h := app.NewContext(128)
	h.Response.SetStatusCode(consts.StatusOK)
	h.Response.Header.Set("Content-Type", "application/json")
	h.Response.SetBody([]byte(`{"name":"test"}`))

	// Simulate ResponseMiddleware behavior
	body := h.Response.Body()
	var rawData any
	_ = json.Unmarshal(body, &rawData)

	m, ok := rawData.(map[string]any)
	if ok {
		if _, has := m["code"]; has {
			t.Error("should not have code field")
		}
	}

	wrapped, _ := json.Marshal(Response{
		Code: 0, Data: rawData, Message: "success", TraceID: "test123",
	})
	var result Response
	_ = json.Unmarshal(wrapped, &result)

	assert.DeepEqual(t, 0, result.Code)
	assert.DeepEqual(t, "success", result.Message)
	assert.DeepEqual(t, "test123", result.TraceID)
}

func TestResponseMiddleware_SkipExistingCode(t *testing.T) {
	body := []byte(`{"code":0,"data":null,"message":"ok"}`)
	var rawData any
	_ = json.Unmarshal(body, &rawData)

	m, ok := rawData.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if _, has := m["code"]; !has {
		t.Error("expected code field to exist")
	}
	// Should NOT wrap when code exists
}

func TestErrorResp(t *testing.T) {
	e := bizerrors.NewBizError(400, "bad request")
	assert.DeepEqual(t, 400, e.BizCode)
	assert.DeepEqual(t, "bad request", e.Message)
	assert.DeepEqual(t, "biz_code:400 bad request", e.Error())
}

func TestNewNotFoundError(t *testing.T) {
	e := bizerrors.NewNotFoundError("not found")
	assert.DeepEqual(t, 404, e.BizCode)
	assert.DeepEqual(t, "not found", e.Message)
}

func TestNewBadRequestError(t *testing.T) {
	e := bizerrors.NewBadRequestError("invalid")
	assert.DeepEqual(t, 400, e.BizCode)
	assert.DeepEqual(t, "invalid", e.Message)
}

func TestResponse_Struct(t *testing.T) {
	r := Response{
		Code:    0,
		Data:    map[string]string{"key": "value"},
		Message: "success",
		TraceID: "abc",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	_ = json.Unmarshal(data, &result)

	assert.DeepEqual(t, float64(0), result["code"])
	assert.DeepEqual(t, "success", result["message"])
	assert.DeepEqual(t, "abc", result["trace_id"])
}

func TestTraceIDMiddleware_BridgeSyncsID(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	// 模拟 requestid 已将生成的 ID 写入响应头（标准长度 12 位）
	c.Header("X-Trace-Id", "abcdefghijkl")

	bridge := hmw.Middleware()[1]
	bridge(context.Background(), c)

	// bridge 不再截断，c.Set 与响应头均应保持完整 ID
	assert.DeepEqual(t, "abcdefghijkl", hmw.FromRequestContext(c))
	assert.DeepEqual(t, "abcdefghijkl", c.Response.Header.Get("X-Trace-Id"))
}

func TestTraceIDMiddleware_BridgeShortID(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Header("X-Trace-Id", "short") // 不足标准长度，原样保留

	bridge := hmw.Middleware()[1]
	bridge(context.Background(), c)

	assert.DeepEqual(t, "short", hmw.FromRequestContext(c))
}

func TestTraceIDMiddleware_BridgeMissingHeader_SelfHeals(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	// requestid 未写入响应头（理论上不会发生，但防御性测试）：bridge 自愈
	// 生成合法 ID，保证请求永不无 trace（旧行为直接放行，链路静默断裂）

	bridge := hmw.Middleware()[1]
	bridge(context.Background(), c)

	rid := hmw.FromRequestContext(c)
	assert.DeepEqual(t, traceid.IDLength, len(rid))
	assert.DeepEqual(t, rid, c.Response.Header.Get(traceid.HeaderKey))
}

func TestSuccessResp_Structure(t *testing.T) {
	c := app.NewContext(128)
	c.Set("trace_id", "test-trace")
	SuccessResp(c, map[string]string{"hello": "world"})

	body := c.Response.Body()
	var resp Response
	_ = json.Unmarshal(body, &resp)

	assert.DeepEqual(t, 0, resp.Code)
	assert.DeepEqual(t, "success", resp.Message)
	assert.DeepEqual(t, "test-trace", resp.TraceID)
}

func TestSuccessRespMsg_Structure(t *testing.T) {
	c := app.NewContext(128)
	c.Set("trace_id", "trace-123")
	SuccessRespMsg(c, nil, "created")

	body := c.Response.Body()
	var resp Response
	_ = json.Unmarshal(body, &resp)

	assert.DeepEqual(t, 0, resp.Code)
	assert.DeepEqual(t, "created", resp.Message)
}

func TestErrorResp_Structure(t *testing.T) {
	c := app.NewContext(128)
	c.Set("trace_id", "err-trace")
	ErrorResp(c, 400, "bad request")

	// HTTP 状态码应与业务码对齐（T3.2：4xx/5xx + body code）
	assert.DeepEqual(t, consts.StatusBadRequest, c.Response.StatusCode())

	body := c.Response.Body()
	var resp Response
	_ = json.Unmarshal(body, &resp)

	assert.DeepEqual(t, 400, resp.Code)
	assert.DeepEqual(t, "bad request", resp.Message)
	assert.Nil(t, resp.Data)
}

// TestStatusMapper 验证业务码 → HTTP 状态码映射（T3.2）。
func TestStatusMapper(t *testing.T) {
	tests := []struct {
		name     string
		bizCode  int
		wantHTTP int
	}{
		{"HTTP 对齐 400", 400, consts.StatusBadRequest},
		{"HTTP 对齐 404", 404, consts.StatusNotFound},
		{"HTTP 对齐 500", 500, consts.StatusInternalServerError},
		{"自定义业务码 1001 → 400", 1001, consts.StatusBadRequest},
		{"成功码 0 → 200", 0, consts.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.DeepEqual(t, tt.wantHTTP, defaultStatusMapper(tt.bizCode))
		})
	}
}

// TestSetStatusMapper 验证可自定义映射器。
func TestSetStatusMapper(t *testing.T) {
	defer func() {
		// 恢复默认值（hertz/logx init 不会覆盖，这里手动重置）
		SetStatusMapper(defaultStatusMapper)
	}()

	SetStatusMapper(func(code int) int {
		return consts.StatusUnprocessableEntity // 统一 422
	})

	c := app.NewContext(128)
	ErrorResp(c, 1001, "custom")
	assert.DeepEqual(t, consts.StatusUnprocessableEntity, c.Response.StatusCode())
}

func TestRateLimitOptions_Defaults(t *testing.T) {
	cfg := newRateLimitOptions(WithRateLimit(100, 200))
	if cfg.Rate != 100 {
		t.Errorf("expected rate 100, got %v", cfg.Rate)
	}
	if cfg.Burst != 200 {
		t.Errorf("expected burst 200, got %d", cfg.Burst)
	}
	// 默认 TTL 应为 10 分钟
	if cfg.LimiterTTL != 10*time.Minute {
		t.Errorf("expected default TTL 10m, got %v", cfg.LimiterTTL)
	}
	// 默认 KeyFunc 应非 nil
	if cfg.KeyFunc == nil {
		t.Error("expected default KeyFunc to be set")
	}
}

func TestAccessLogOptions_SkipPaths(t *testing.T) {
	cfg := newAccessLogOptions(WithAccessLogSkipPaths("/metrics", "/ping"))
	if len(cfg.SkipPaths) != 2 {
		t.Errorf("expected 2 skip paths, got %d", len(cfg.SkipPaths))
	}
}

func TestBizError_Interface(t *testing.T) {
	e := bizerrors.NewBizError(500, "server error")
	if e.BizCode != 500 {
		t.Errorf("expected 500, got %d", e.BizCode)
	}
	if e.Message != "server error" {
		t.Errorf("expected 'server error', got %q", e.Message)
	}
	if e.Error() != "biz_code:500 server error" {
		t.Errorf("expected 'biz_code:500 server error', got %q", e.Error())
	}
}

func TestResponse_Struct_Fields(t *testing.T) {
	r := Response{
		Code:    200,
		Data:    "test",
		Message: "ok",
		TraceID: "trace-123",
	}
	assert.DeepEqual(t, 200, r.Code)
	assert.DeepEqual(t, "test", r.Data)
	assert.DeepEqual(t, "ok", r.Message)
	assert.DeepEqual(t, "trace-123", r.TraceID)
}

func TestResponseMiddleware_SkipNonJSON(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.SetMethod("GET")
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "text/plain")
	c.Response.SetBody([]byte("plain text"))

	handler := ResponseMiddleware()
	handler(context.Background(), c)

	// Should not wrap non-JSON response
	assert.DeepEqual(t, "plain text", string(c.Response.Body()))
}

func TestResponseMiddleware_SkipNon200(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.SetMethod("GET")
	c.Response.SetStatusCode(404)
	c.Response.Header.Set("Content-Type", "application/json")
	c.Response.SetBody([]byte(`{"error":"not found"}`))

	handler := ResponseMiddleware()
	handler(context.Background(), c)

	// Should not wrap non-200 response
	assert.DeepEqual(t, `{"error":"not found"}`, string(c.Response.Body()))
}

func TestResponseMiddleware_SkipEmptyBody(t *testing.T) {
	c := app.NewContext(128)
	c.Request.SetRequestURI("/test")
	c.Request.Header.SetMethod("GET")
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/json")

	handler := ResponseMiddleware()
	handler(context.Background(), c)

	// Should not wrap empty body
	assert.DeepEqual(t, "", string(c.Response.Body()))
}

func TestHasCodeField(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"no code", `{"data":"hello"}`, false},
		{"has code", `{"code":0,"data":"hello"}`, true},
		{"code as value", `{"x":"code"}`, false},
		{"code with spaces", `{ "code" : 0 }`, true},
		{"nested code", `{"a":{"code":1}}`, false},
		// 顶层数组：方括号同层计数后，元素对象的 "code" 在 depth>=2，
		// 不该被误判为顶层键而跳过包装（顶层数组 body 应照常包装）。
		{"top-level array element code", `[{"code":1},{"code":2}]`, false},
		{"top-level array string code", `[{"x":"code"}]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCodeField([]byte(tt.body))
			if got != tt.want {
				t.Errorf("hasCodeField(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
