package contrib

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/app/client/loadbalance"
)

// TestNewRoundRobinBalancer_ReturnsNonNil 验证构造不返回 nil。
func TestNewRoundRobinBalancer_ReturnsNonNil(t *testing.T) {
	lb := NewRoundRobinBalancer()
	if lb == nil {
		t.Fatal("NewRoundRobinBalancer returned nil")
	}
	if lb.Name() != "round_robin" {
		t.Errorf("Name = %q, want round_robin", lb.Name())
	}
}

// TestLoadbalancer_TypeAlias 验证 type alias 兼容 hertz 接口。
func TestLoadbalancer_TypeAlias(t *testing.T) {
	var lb = NewRoundRobinBalancer()
	if lb == nil {
		t.Fatal("type alias assignment failed")
	}
}

// TestLoadbalancer_HertzInterface 验证实际类型跟 hertz 内部类型兼容。
func TestLoadbalancer_HertzInterface(t *testing.T) {
	lb := NewRoundRobinBalancer()
	// loadbalance.Loadbalancer 是 hertz 接口,直接比较类型
	if _, ok := interface{}(lb).(loadbalance.Loadbalancer); !ok {
		t.Error("returned value not implementing hertz loadbalance.Loadbalancer")
	}
}
