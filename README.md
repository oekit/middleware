# middleware

> Hertz 标准中间件栈——一键标准栈/统一错误出口/contrib 桥接

> 🌐 项目主页：**https://oekit.github.io/** · 名称由来：**O**pen **E**asy **Kit**（开源 · 易用 · 工具集合）
> 🤖 AI Agent：本仓规范与硬规则见 [AGENTS.md](AGENTS.md)；机器可读索引见 [llms.txt](https://oekit.github.io/llms.txt)（接口签名以源码为准）。

## 安装

```bash
go get github.com/oekit/middleware@v0.2.0
```

## 这个仓库做什么

`middleware` 是 **Hertz 自研标准中间件栈 + 社区库桥接**：一组生产调过参的中间件
（统一响应格式、限流、认证、访问日志、panic recovery）加上 hertz-contrib 生态的桥接层。

## 组成

| 包 | 做什么 |
|---|---|
| `middleware`（包名 `mw`） | `DefaultMiddleware` 一键标准栈：TraceID → Recovery → Response → AccessLog（零指标强制）；另有 Prometheus 指标/RateLimit/BearerTokenAuth/I18n/Fail 等 |
| `contrib` | hertz-contrib 桥接：JWT/Sessions/Swagger/CSRF/pprof/Debug/Gzip/ETag/BasicAuth/ReverseProxy/Sentinel/Lark |
| `hmw` | requestid/trace_id 注入 RequestContext |

## 快速使用

```go
import mw "github.com/oekit/middleware/middleware"

// 标准栈一键注册（顺序已调好，零指标强制）
for _, m := range mw.DefaultMiddleware(mw.StackConfig{SkipPaths: []string{"/healthz"}}) {
    h.Use(m)
}

// 需要 HTTP 指标时显式拼在栈最前（Registry 缺省 nil = ekit 统一注册表）
pm := mw.NewPrometheusMetrics(mw.PrometheusConfig{Namespace: "myapp", ServiceName: "my-service"})
h.Use(pm.Middleware())
```

### 统一错误出口

```go
func getOrder(ctx context.Context, c *app.RequestContext) {
    ord, err := svc.Get(ctx, id)
    if err != nil {
        mw.Fail(ctx, c, err) // BizError→业务码；NotFound→404；兜底 500 + 结构化日志
        return
    }
}
```

## 边界

- Hertz 运行时（日志桥接/生命周期/SSE）在 [hertz](https://github.com/oekit/hertz)
- `mw.Fail` 识别的 BizError 定义在 [pkg/errors](https://github.com/oekit/pkg)——整条链路必须用同一套 errors（类型同一性红线）


## 矩阵总览

## 矩阵总览（23 活跃模块，自动生成）

| 模块 | 内容 | 矩阵内依赖 |
|---|---|---|
| [pkg](https://github.com/oekit/pkg) | 微工具集 16 合 1（errors/validator/stringx/…） | — |
| [concurrency](https://github.com/oekit/concurrency) | 并发与流控原语 | — |
| [logx](https://github.com/oekit/logx) | 日志门面 + shutdown | — |
| [core](https://github.com/oekit/core) | 应用基建件 | — |
| [istio](https://github.com/oekit/istio) | Istio XDS | — |
| [metrics](https://github.com/oekit/metrics) | Prometheus 门面 | [core](https://github.com/oekit/core) |
| [tracing](https://github.com/oekit/tracing) | OTel + traceid | [logx](https://github.com/oekit/logx) |
| [registry](https://github.com/oekit/registry) | 注册发现 + Nacos + 配置 | [core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx) |
| [data](https://github.com/oekit/data) | 缓存检查器 | [concurrency](https://github.com/oekit/concurrency)、[logx](https://github.com/oekit/logx) |
| [gorm](https://github.com/oekit/gorm) | SQL/CRUD | [logx](https://github.com/oekit/logx)、[pkg](https://github.com/oekit/pkg) |
| [redis](https://github.com/oekit/redis) | Redis 全家 | [concurrency](https://github.com/oekit/concurrency)、[data](https://github.com/oekit/data)、[logx](https://github.com/oekit/logx) |
| [httpx](https://github.com/oekit/httpx) | HTTP 客户端 | [concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[registry](https://github.com/oekit/registry)、[tracing](https://github.com/oekit/tracing) |
| [network](https://github.com/oekit/network) | 轻量网络件 | [concurrency](https://github.com/oekit/concurrency)、[logx](https://github.com/oekit/logx)、[tracing](https://github.com/oekit/tracing) |
| [timertask](https://github.com/oekit/timertask) | 定时任务 | [concurrency](https://github.com/oekit/concurrency)、[logx](https://github.com/oekit/logx) |
| [middleware](https://github.com/oekit/middleware) | Hertz 中间件栈 | [concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[pkg](https://github.com/oekit/pkg)、[registry](https://github.com/oekit/registry)、[tracing](https://github.com/oekit/tracing) |
| [nns](https://github.com/oekit/nns) | 服务治理门面 | [concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx)、[registry](https://github.com/oekit/registry) |
| [nns-endpoint](https://github.com/oekit/nns-endpoint) | 端点熔断重试 | [concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[httpx](https://github.com/oekit/httpx)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[nns](https://github.com/oekit/nns)、[registry](https://github.com/oekit/registry) |
| [bootstrap](https://github.com/oekit/bootstrap) | 应用引导 | [concurrency](https://github.com/oekit/concurrency)、[logx](https://github.com/oekit/logx) |
| [handler](https://github.com/oekit/handler) | CRUD handler | [concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[gorm](https://github.com/oekit/gorm)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[middleware](https://github.com/oekit/middleware)、[pkg](https://github.com/oekit/pkg)、[registry](https://github.com/oekit/registry)、[tracing](https://github.com/oekit/tracing) |
| [hertz](https://github.com/oekit/hertz) | Hertz 运行时 | [bootstrap](https://github.com/oekit/bootstrap)、[concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[nns](https://github.com/oekit/nns)、[registry](https://github.com/oekit/registry)、[tracing](https://github.com/oekit/tracing) |
| [kitex](https://github.com/oekit/kitex) | Kitex 生态 | [bootstrap](https://github.com/oekit/bootstrap)、[concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[nns](https://github.com/oekit/nns)、[pkg](https://github.com/oekit/pkg)、[registry](https://github.com/oekit/registry) |
| [workflow](https://github.com/oekit/workflow) | 流程编排 | [concurrency](https://github.com/oekit/concurrency)、[logx](https://github.com/oekit/logx) |
| [kitex-examples](https://github.com/oekit/kitex-examples) | Kitex 示例 | [bootstrap](https://github.com/oekit/bootstrap)、[concurrency](https://github.com/oekit/concurrency)、[core](https://github.com/oekit/core)、[kitex](https://github.com/oekit/kitex)、[logx](https://github.com/oekit/logx)、[metrics](https://github.com/oekit/metrics)、[nns](https://github.com/oekit/nns)、[pkg](https://github.com/oekit/pkg)、[registry](https://github.com/oekit/registry)、[tracing](https://github.com/oekit/tracing) |

> 依赖严格自底向上；微库已合并为 pkg，旧微库仓已删除。

> 本仓在矩阵中的位置与依赖见上表「矩阵内依赖」列。历史沿革：源自 ekit 单体库
> （git.enjoye.top/enjoydream/ekit v0.34.0，冻结维护），2026-10 拆分为独立 module。

## License

MIT — 见 [LICENSE](LICENSE)
