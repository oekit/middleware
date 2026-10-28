package mw

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNewPrometheusMetrics_SecondInstance_ReusesRegisteredCollector 回归测试：
// 同一 Registry + namespace 下构造**第二个** PrometheusMetrics 时，它必须
// **复用已注册的 collector**——否则第二个实例的指标全部丢失（采集端永远
// 看不到），而构造函数却"成功"返回 ⇒ 故障完全静默。
//
// 缺陷成因：mustRegister 只吞掉 AlreadyRegisteredError，把**新建的（未注册
// 的）** collector 留在字段里。注释写着「复用已注册的 collector」，代码却
// 没做。
func TestNewPrometheusMetrics_SecondInstance_ReusesRegisteredCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := PrometheusConfig{
		Namespace:         "reuse",
		ServiceName:       "svc",
		Registry:          reg,
		EnableSizeMetrics: true,
	}

	first := NewPrometheusMetrics(cfg)
	second := NewPrometheusMetrics(cfg)

	if first.RequestsTotal != second.RequestsTotal {
		t.Error("第二个实例的 RequestsTotal 未复用已注册的 collector ⇒ 它的指标不会被采集")
	}
	if first.RequestDuration != second.RequestDuration {
		t.Error("第二个实例的 RequestDuration 未复用已注册的 collector")
	}
	if first.RequestsInFlight != second.RequestsInFlight {
		t.Error("第二个实例的 RequestsInFlight 未复用已注册的 collector")
	}
	if first.RequestSize != second.RequestSize {
		t.Error("第二个实例的 RequestSize 未复用已注册的 collector")
	}
	if first.ResponseSize != second.ResponseSize {
		t.Error("第二个实例的 ResponseSize 未复用已注册的 collector")
	}
}

// TestNewPrometheusMetrics_SecondInstance_MetricsAreCollected 回归护栏：
// 第二个实例记录的数据必须**真的出现在 Registry 的采集结果里**——
// 「指针相同」只是手段，落地才是目的。
func TestNewPrometheusMetrics_SecondInstance_MetricsAreCollected(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := PrometheusConfig{Namespace: "collected", Registry: reg}

	second := NewPrometheusMetrics(cfg)
	second.RequestsTotal.WithLabelValues("GET", "/x", "200").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var found bool
	for _, f := range families {
		if f.GetName() == "collected_requests_total" {
			found = true
			if len(f.GetMetric()) == 0 {
				t.Fatal("collected_requests_total 被采集到但没有样本 ⇒ 第二个实例的指标丢了")
			}
		}
	}
	if !found {
		t.Fatal("Registry 里找不到 collected_requests_total ⇒ 第二个实例的指标没进注册表")
	}
}

// TestRegisterReuse_TypeMismatch_ActionablePanic 回归测试：同名同描述符但
// **类型不同**时，panic 的信息必须能定位问题。
//
// 缺陷成因：既有 collector 与请求的 collector 描述符相同（fqName + help +
// 标签名都一致）但类型不同 ⇒ prometheus 返回 AlreadyRegisteredError（不是
// 直接拒绝）⇒ 无检查的类型断言会 panic 成一句不可定位的
// "interface conversion: ..."。
func TestRegisterReuse_TypeMismatch_ActionablePanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	// 描述符与 middleware 的 requests_total 完全一致，但类型是 GaugeVec。
	reg.MustRegister(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "requests_total",
		Namespace: "mismatch",
		Help:      "Total number of HTTP requests.",
	}, []string{"method", "path", "status_code"}))

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("同名同描述符但类型不同应 panic")
		}
		msg, ok := r.(error)
		if !ok {
			t.Fatalf("panic 值不是 error：%v", r)
		}
		text := msg.Error()
		if !strings.Contains(text, "类型不符") ||
			!strings.Contains(text, "GaugeVec") ||
			!strings.Contains(text, "CounterVec") {
			t.Fatalf("panic 信息不可定位：%s", text)
		}
	}()

	_ = NewPrometheusMetrics(PrometheusConfig{
		Namespace: "mismatch",
		Registry:  reg,
	})
}
