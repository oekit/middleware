package contrib

import (
	"github.com/cloudwego/hertz/pkg/app/client/loadbalance"
	hertzloadbalance "github.com/hertz-contrib/loadbalance/round_robin"
)

// Loadbalancer 是 hertz 客户端 loadbalance.Loadbalancer 的 type alias
// (注意:不是 kitex 的 loadbalance.Loadbalancer,接口不通用)。
// ekit 业务用 mw.Loadbalancer 直接拿上游接口。
//
// 官方依据:https://github.com/hertz-contrib/loadbalance (v0.1.0)
//
// ⚠️ 当前 hertz-contrib/loadbalance 只提供 round-robin 一种算法(无
// weighted/consistent hash 变体)。如需这些算法,推荐用 ekit
// `network/httpx` + 自定义 LB,或参考 kitex 端的丰富算法集
// (https://github.com/kitex-contrib/resolver-dns)。
type Loadbalancer = loadbalance.Loadbalancer

// NewRoundRobinBalancer 构造 hertz 客户端 round-robin 负载均衡器。
//
// 用法(配合 hertz client):
//
//	import hertzclient "github.com/cloudwego/hertz/pkg/app/client"
//	import hertzsd "github.com/cloudwego/hertz/pkg/app/client/discovery"
//
//	lb := contrib.NewRoundRobinBalancer()
//	cli, _ := hertzclient.NewClient(hertzclient.WithLoadBalancer(lb))
//
// 局限: round-robin 忽略权重,业务如需 weighted 推荐自己实现。
func NewRoundRobinBalancer() Loadbalancer {
	return hertzloadbalance.NewRoundRobinBalancer()
}
