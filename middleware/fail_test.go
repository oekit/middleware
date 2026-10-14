package mw

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	ekiterrors "github.com/yi-nology/ekit-core/pkg/errors"
	"github.com/yi-nology/ekit-registry/registry"
)

// TestFail_BizError 验证 Fail 函数 3-tier 第 1 层: BizError 提取.
func TestFail_BizError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantMsg  string
	}{
		{"NotFound 404", ekiterrors.NewNotFoundError("project not found"), 404, "project not found"},
		{"BadRequest 400", ekiterrors.NewBadRequestError("invalid keyword"), 400, "invalid keyword"},
		{"Conflict 409", ekiterrors.NewConflictError("build is not cancellable"), 409, "build is not cancellable"},
		{"BizError 500", ekiterrors.NewBizError(500, "internal error"), 500, "internal error"},
		{"BizError 502", ekiterrors.NewBizError(502, "upstream failed"), 502, "upstream failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &app.RequestContext{}
			Fail(context.Background(), c, tt.err)
			if c.Response.StatusCode() != tt.wantCode {
				t.Errorf("status: got %d, want %d", c.Response.StatusCode(), tt.wantCode)
			}
			body := string(c.Response.Body())
			if !strings.Contains(body, tt.wantMsg) {
				t.Errorf("body: got %q, want contains %q", body, tt.wantMsg)
			}
		})
	}
}

// TestFail_NotFoundChecker 验证 Fail 函数 3-tier 第 2 层: WithNotFoundChecker option.
func TestFail_NotFoundChecker(t *testing.T) {
	notFoundErr := stderrors.New("record not found")

	c := &app.RequestContext{}
	Fail(context.Background(), c, notFoundErr, WithNotFoundChecker(func(err error) bool {
		return stderrors.Is(err, notFoundErr)
	}))
	if c.Response.StatusCode() != 404 {
		t.Errorf("status: got %d, want 404", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "resource not found") {
		t.Errorf("body: got %q, want contains 'resource not found'", body)
	}
}

// TestFail_NilError 验证 Fail(c, nil) 安全返回不 panic.
func TestFail_NilError(t *testing.T) {
	c := &app.RequestContext{}
	Fail(context.Background(), c, nil)
	// nil error 应直接返回，不写任何响应
	if len(c.Response.Body()) != 0 {
		t.Errorf("nil error should produce empty response, got %q", string(c.Response.Body()))
	}
}

// TestFail_DefaultError 验证 Fail 函数 3-tier 第 3 层: 其他 err fallback 500.
// 返回通用消息，不泄露内部错误详情。
func TestFail_DefaultError(t *testing.T) {
	c := &app.RequestContext{}
	Fail(context.Background(), c, stderrors.New("plain error"))
	if c.Response.StatusCode() != 500 {
		t.Errorf("status: got %d, want 500", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "internal server error") {
		t.Errorf("body: got %q, want contains 'internal server error'", body)
	}
}

// TestFail_ChainUnwrap 验证 Fail 函数支持 errors.As 链式匹配
// (BizError.Cause 嵌套场景).
func TestFail_ChainUnwrap(t *testing.T) {
	inner := stderrors.New("inner error")
	wrapped := ekiterrors.WrapBizError(502, "upstream failed", inner)
	c := &app.RequestContext{}
	Fail(context.Background(), c, wrapped)
	if c.Response.StatusCode() != 502 {
		t.Errorf("status: got %d, want 502", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "upstream failed") {
		t.Errorf("body: got %q, want contains 'upstream failed'", body)
	}
}

// TestFail_WithNotFoundChecker 验证 Fail 的 WithNotFoundChecker option
// 可以按调用覆盖全局 not-found checker。
func TestFail_WithNotFoundChecker(t *testing.T) {
	// 全局 checker 默认返回 false（无 not-found 判定）
	// 通过 WithNotFoundChecker 按调用注入自定义 checker
	customErr := stderrors.New("custom not found")
	c := &app.RequestContext{}
	Fail(context.Background(), c, customErr, WithNotFoundChecker(func(err error) bool {
		return stderrors.Is(err, customErr)
	}))
	if c.Response.StatusCode() != 404 {
		t.Errorf("status: got %d, want 404", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "resource not found") {
		t.Errorf("body: got %q, want contains 'resource not found'", body)
	}

	// 不传 option 时走全局默认 checker（返回 false → 500）
	c2 := &app.RequestContext{}
	Fail(context.Background(), c2, customErr)
	if c2.Response.StatusCode() != 500 {
		t.Errorf("status without option: got %d, want 500", c2.Response.StatusCode())
	}
}

// TestFail_BizError_CodeSplit 验证 v0.17.0 BizCode/HTTPCode 分离语义:
//   - NewBizErrorWithStatus(bizCode=1001, httpCode=402): body code=1001, HTTP=402
//   - NewBizError(bizCode=1001) (HTTPCode=0): body code=1001, HTTP 经 StatusMapper 回退为 400
func TestFail_BizError_CodeSplit(t *testing.T) {
	t.Run("explicit two-code split", func(t *testing.T) {
		c := &app.RequestContext{}
		Fail(context.Background(), c, ekiterrors.NewBizErrorWithStatus(1001, 402, "insufficient balance"))
		if got := c.Response.StatusCode(); got != 402 {
			t.Errorf("HTTP status: got %d, want 402", got)
		}
		body := string(c.Response.Body())
		// body 的 code 字段必须是业务码 1001，而非 HTTP 402
		if !strings.Contains(body, `"code":1001`) {
			t.Errorf("body should contain biz_code 1001, got %q", body)
		}
	})

	t.Run("HTTPCode=0 falls back to StatusMapper", func(t *testing.T) {
		c := &app.RequestContext{}
		// NewBizError 仅设 BizCode=1001, HTTPCode=0
		// defaultStatusMapper(1001) -> 400 (非 HTTP 对齐码归 400)
		Fail(context.Background(), c, ekiterrors.NewBizError(1001, "custom biz code"))
		if got := c.Response.StatusCode(); got != 400 {
			t.Errorf("HTTP status: got %d, want 400 (StatusMapper fallback)", got)
		}
		body := string(c.Response.Body())
		if !strings.Contains(body, `"code":1001`) {
			t.Errorf("body should contain biz_code 1001, got %q", body)
		}
	})
}

// TestFail_NoInstances_503 回归测试（W3-6.6）：依赖服务无可用实例
// 属于依赖不可用而非本服务 bug，Fail 必须映射为 503 而不是 500。
func TestFail_NoInstances_503(t *testing.T) {
	wrapped := fmt.Errorf("call dep-svc: %w", registry.ErrNoInstances)

	c := &app.RequestContext{}
	Fail(context.Background(), c, wrapped)
	if c.Response.StatusCode() != 503 {
		t.Errorf("status: got %d, want 503", c.Response.StatusCode())
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "service unavailable") {
		t.Errorf("body: got %q, want contains 'service unavailable'", body)
	}
}
