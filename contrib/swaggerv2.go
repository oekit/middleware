package contrib

import (
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/adaptor"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
	"sync"
)

// SwaggerV2 桥接新官方 Swagger 工具链 + Hertz HTTP Adaptor 流程,
// 完全替代 hertz-contrib/swagger(已 archived)。
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/swagger/
// 2025-12-04 新版教程明确:
//
//	"Hertz 推荐所有用户迁移到官方 swaggo/swag 工具链,使用 Hertz HTTP Adaptor"
//	(旧版 hertz-contrib/swagger 移到"旧版文档(已废弃)"段)
//
// 完整使用流程(在业务 main.go):
//
//	// 1. 安装 swag CLI: go install github.com/swaggo/swag/cmd/swag@latest
//	// 2. 在 handler 加 @Summary/@Description/@Router 注释
//	// 3. 跑 swag init 生成 docs/ 目录
//	// 4. 业务 main.go 集成:
//
//	import (
//	    _ "github.com/go-project-name/docs" // 4a. import 生成的 docs 包
//	    httpSwagger "github.com/swaggo/http-swagger"
//	    mw "github.com/oekit/middleware/middleware"
//	    "github.com/swaggo/files"
//	)
//
//	// 4b. 注册 swagger UI 路由(用本包提供的 helper,1 行挂载)
//	h.GET("/swagger/*any", mw.SwaggerV2WithPrefix(
//	    "/swagger", "/swagger/doc.json", httpSwagger.DeepLinking(true)))
//
//	// 4c. 提供 swagger UI 静态资源(从 swaggo/files 复制到 ./swagger-ui 目录
//	//     后用 hertz Static 服务)
//	h.Static("/", "./swagger-ui")
//
// swaggerMu 串行化上游 httpSwagger.Handler 的调用：上游把每个实例的首个
// 请求经各自 sync.Once 写入共享包级 swaggerFiles.Handler.Prefix（v1.3.4
// swagger.go:174），同进程注册多个 SwaggerV2 实例时并发请求构成 data race
// （全量 -race 下偶发触发）。文档端点串行化无性能顾虑。
// 注意上游设计假设单实例：多实例除 race 外还有共享 Prefix 相互覆盖问题，
// 一个进程只注册一个 SwaggerV2。
var swaggerMu sync.Mutex

func wrapSwaggerHandler(h http.HandlerFunc) app.HandlerFunc {
	return adaptor.HertzHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		swaggerMu.Lock()
		defer swaggerMu.Unlock()
		h(w, r)
	}))
}

// SwaggerV2WithPrefix 把 specURL 注入 httpSwagger.Handler 配置并返回
// app.HandlerFunc;业务用 h.GET / h.Handle 挂载即可。
//
// 参数语义(2026-09-05 复审修复:原实现把 specURL 组装后丢弃,UI 打不开
// 指定的 spec):
//   - specURL:传给 httpSwagger.URL,swagger UI 以它加载 API 定义。上游
//     Handler(configFns...) 由 configFns 构造 Config(swaggo/http-swagger
//     v1.3.4 swagger.go:151),默认 URL="doc.json"。
//   - prefix:只由业务 h.GET 的路由路径体现,http-swagger 本身没有 prefix
//     配置(上游 API 决定),传什么都不会改写 handler 行为。要挂到自定义
//     前缀用 RegisterSwaggerV2WithPrefix。
//
// 挂载示例:
//
//	h.GET("/swagger/*any", mw.SwaggerV2WithPrefix(
//	    "/swagger", "/swagger/doc.json", httpSwagger.DeepLinking(true)))
func SwaggerV2WithPrefix(prefix, specURL string, opts ...func(*httpSwagger.Config)) app.HandlerFunc {
	_ = prefix // prefix 由业务 h.GET 路由路径体现(见上),上游无此配置项
	all := append([]func(*httpSwagger.Config){httpSwagger.URL(specURL)}, opts...)
	return wrapSwaggerHandler(httpSwagger.Handler(all...))
}

// SwaggerV2 透传 httpSwagger.Handler(opts...),等价 SwaggerV2WithPrefix
// 但不强制传 specURL(specURL 可通过 opts 里的 httpSwagger.URL 注入)。
func SwaggerV2(opts ...func(*httpSwagger.Config)) app.HandlerFunc {
	return wrapSwaggerHandler(httpSwagger.Handler(opts...))
}

// RegisterSwaggerV2 在 h *server.Hertz 上挂载 swagger UI 路由,prefix
// 默认 /swagger/*any,specURL 默认 /swagger/doc.json。
//
// 完整示例:
//
//	contrib.RegisterSwaggerV2(h,
//	    mw.WithSwaggerURL("http://localhost:8888/swagger/doc.json"),
//	    httpSwagger.DeepLinking(true),
//	)
func RegisterSwaggerV2(h *server.Hertz, opts ...func(*httpSwagger.Config)) {
	h.GET("/swagger/*any", SwaggerV2(opts...))
}

// RegisterSwaggerV2WithPrefix 在自定义前缀挂载 swagger UI(例如隐藏到
// /internal/debug/swagger 避免公网被扫到),specURL 自动推导为
// <prefix>/doc.json(上游 doc.json handler 跟随注册路径,无需业务手写)。
//
//	contrib.RegisterSwaggerV2WithPrefix(h, "/internal/debug/swagger",
//	    httpSwagger.DeepLinking(true))
func RegisterSwaggerV2WithPrefix(h *server.Hertz, prefix string, opts ...func(*httpSwagger.Config)) {
	if prefix == "" {
		prefix = "/swagger"
	}
	h.GET(prefix+"/*any", SwaggerV2WithPrefix(prefix, prefix+"/doc.json", opts...))
}

// SwaggerV2Option 是 httpSwagger.Config Option 的别名(避免业务 import
// 长路径)。业务用 WithSwaggerXxx 系列拿 Option 再传给 RegisterSwaggerV2。
type SwaggerV2Option = func(*httpSwagger.Config)

// WithSwaggerURL 透传 httpSwagger.URL(specURL)。
func WithSwaggerURL(specURL string) SwaggerV2Option {
	return httpSwagger.URL(specURL)
}

// WithSwaggerDeepLinking 透传 httpSwagger.DeepLinking(b)。
func WithSwaggerDeepLinking(b bool) SwaggerV2Option {
	return httpSwagger.DeepLinking(b)
}
