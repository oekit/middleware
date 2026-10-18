package mw

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/prometheus/client_golang/prometheus"
)

// middleware#16：一步形态——Prometheus 非 nil 时保证挂栈首、SkipPaths 单点传入；
// nil 时行为与现状一致（零指标，栈长 5）。

func TestDefaultMiddleware_PrometheusNil(t *testing.T) {
	stack := DefaultMiddleware(StackConfig{SkipPaths: []string{"/metrics"}})
	if len(stack) != 5 {
		t.Fatalf("stack len = %d, want 5 (nil Prometheus keeps zero-metric behavior)", len(stack))
	}
}

func TestDefaultMiddleware_PrometheusFirst(t *testing.T) {
	reg := prometheus.NewRegistry()
	skip := []string{"/metrics"}
	stack := DefaultMiddleware(StackConfig{
		SkipPaths:  skip,
		Prometheus: &PrometheusConfig{ServiceName: "svc", Registry: reg},
	})
	if len(stack) != 6 {
		t.Fatalf("stack len = %d, want 6 (prometheus at head)", len(stack))
	}

	// 栈首即指标中间件：普通路径计数两次（中间件独立可调，无后续 handler 时
	// Next 立即返回），skip 路径不计数
	h := app.NewContext(128)
	h.Request.SetMethod("GET")
	h.Request.SetRequestURI("/api/users")
	h.SetFullPath("/api/users") // FullPath 是指标 path 标签来源（防高基数）
	for i := 0; i < 2; i++ {
		stack[0](context.Background(), h)
	}

	hSkip := app.NewContext(128)
	hSkip.Request.SetMethod("GET")
	hSkip.Request.SetRequestURI("/metrics")
	hSkip.SetFullPath("/metrics")
	stack[0](context.Background(), hSkip)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "http_requests_total" {
			continue
		}
		found = true
		for _, m := range mf.GetMetric() {
			path := ""
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "path" {
					path = lp.GetValue()
				}
			}
			switch path {
			case "/api/users":
				if m.GetCounter().GetValue() != 2 {
					t.Fatalf("/api/users counter = %v, want 2", m.GetCounter().GetValue())
				}
			case "/metrics":
				t.Fatal("skip path must not be counted")
			default:
				t.Fatalf("unexpected path label %q", path)
			}
		}
	}
	if !found {
		t.Fatal("http_requests_total not found in registry (Prometheus not at stack head?)")
	}
}
