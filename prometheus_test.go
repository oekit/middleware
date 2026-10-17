package mw

import (
	"testing"

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
