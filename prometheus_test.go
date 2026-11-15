package mw

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNewPrometheusMetrics_Defaults(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test-defaults",
		Registry:    prometheus.NewRegistry(),
	})
	if m == nil {
		t.Fatal("NewPrometheusMetrics returned nil")
	}
}

func TestNewPrometheusMetrics_AllOptions(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		Namespace:   "ns",
		ServiceName: "svc",
		SkipPaths:   []string{"/healthz"},
		Registry:    prometheus.NewRegistry(),
	})
	if m == nil {
		t.Fatal("NewPrometheusMetrics returned nil")
	}
	if m.Middleware() == nil {
		t.Error("Middleware() should return non-nil handler")
	}
}

func TestPathLabelValues(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test",
		Registry:    prometheus.NewRegistry(),
	})
	if got := m.pathLabelValues("GET", "/foo"); len(got) == 0 {
		t.Error("expected non-empty label values")
	}
}

func TestStatusLabelValues(t *testing.T) {
	m := NewPrometheusMetrics(PrometheusConfig{
		ServiceName: "test",
		Registry:    prometheus.NewRegistry(),
	})
	if got := m.statusLabelValues("GET", "/foo", "200"); len(got) == 0 {
		t.Error("expected non-empty label values")
	}
}

// --- stack.go DefaultMiddleware ---

// runProm 在独立注册表上跑一次请求，返回 path 标签 → 计数的映射。
func runProm(t *testing.T, cfg PrometheusConfig, rawPath, fullPath string) map[string]float64 {
	t.Helper()
	if cfg.Registry == nil {
		cfg.Registry = prometheus.NewRegistry()
	}
	m := NewPrometheusMetrics(cfg)
	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI(rawPath)
	c.SetFullPath(fullPath)
	m.Middleware()(context.Background(), c)

	mfs, err := cfg.Registry.(prometheus.Gatherer).Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "http_requests_total" && !strings.HasSuffix(mf.GetName(), "_requests_total") {
			continue
		}
		for _, metric := range mf.GetMetric() {
			path := ""
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "path" {
					path = lp.GetValue()
				}
			}
			out[path] = metric.GetCounter().GetValue()
		}
	}
	return out
}

// TestPrometheus_SkipPathsDefaultInfraPaths 钉住 #251 后果一：未显式传
// SkipPaths 时按 mw.InfraPaths() 兜底——/metrics 自身不再被采集（旧实现
// 无兜底，标准装配下抓取流量自采集成环，与 Middleware() 文档承诺相反）。
func TestPrometheus_SkipPathsDefaultInfraPaths(t *testing.T) {
	got := runProm(t, PrometheusConfig{ServiceName: "svc"}, "/metrics", "/metrics")
	if n, ok := got["/metrics"]; ok {
		t.Fatalf("/metrics 缺省应被 InfraPaths 兜底豁免（零指标），got %v", n)
	}
	got = runProm(t, PrometheusConfig{ServiceName: "svc"}, "/api/users", "/api/users")
	if got["/api/users"] != 1 {
		t.Fatalf("业务路径应照常采集, got %v", got)
	}
}

// TestPrometheus_SkipPathsGlobOnRawPath 钉住 #251 后果二：跳过判定与
// AccessLog 同一源——pathx.MatchesPath glob 打**原始请求路径**。旧实现按
// c.FullPath() 路由模板精确查表：glob "/health*" 与未匹配路由（FullPath
// 为空 → "unnamed"）双双漏跳，同一份 StackConfig.SkipPaths 两侧豁免面分裂。
func TestPrometheus_SkipPathsGlobOnRawPath(t *testing.T) {
	// glob 命中原始路径（FullPath 不同也不影响跳过判定）
	got := runProm(t, PrometheusConfig{
		ServiceName: "svc",
		SkipPaths:   []string{"/health*"},
	}, "/healthz", "/healthz")
	if n, ok := got["/healthz"]; ok {
		t.Fatalf("glob /health* 应豁免 /healthz（与 AccessLog 同口径），got %v", n)
	}

	// 未匹配路由：FullPath 为空（标签 "unnamed"），跳过判定仍走原始路径
	got = runProm(t, PrometheusConfig{
		ServiceName: "svc",
		SkipPaths:   []string{"/internal/**"},
	}, "/internal/inspect", "")
	if n, ok := got["unnamed"]; ok {
		t.Fatalf("原始路径命中 /internal/** 应跳过（旧实现查 FullPath 模板必漏），got %v", n)
	}

	// 未命中照常采集
	got = runProm(t, PrometheusConfig{
		ServiceName: "svc",
		SkipPaths:   []string{"/health*"},
	}, "/api/users", "/api/users")
	if got["/api/users"] != 1 {
		t.Fatalf("清单外路径应照常采集, got %v", got)
	}
}

// TestPrometheus_SkipPathsExplicitOverridesDefault 钉住 #137 同款覆盖语义：
// 显式传 SkipPaths 完全覆盖 InfraPaths 缺省——/metrics 不在显式清单内照常采集。
func TestPrometheus_SkipPathsExplicitOverridesDefault(t *testing.T) {
	got := runProm(t, PrometheusConfig{
		ServiceName: "svc",
		SkipPaths:   []string{"/internal/**"},
	}, "/metrics", "/metrics")
	if got["/metrics"] != 1 {
		t.Fatalf("显式清单外的 /metrics 应照常采集（完全覆盖语义）, got %v", got)
	}
}

// TestPrometheus_BadGlobPatternPanics 构造期 glob 语法预检（#201/#161 同判据
// fail-fast）：坏 pattern 让 pathx.MatchesPath 静默全不匹配、豁免面静默失效。
func TestPrometheus_BadGlobPatternPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("★ 坏 glob pattern 构造必须 panic(fail-fast)")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "/api/[admin") {
			t.Fatalf("panic 信息应点名坏 pattern: %v", r)
		}
	}()
	NewPrometheusMetrics(PrometheusConfig{
		Registry:  prometheus.NewRegistry(),
		SkipPaths: []string{"/api/[admin"}, // 未闭合的 [ = ErrBadPattern
	})
}

