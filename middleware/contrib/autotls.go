package contrib

import (
	"context"
	"crypto/tls"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/hertz-contrib/autotls"
	"golang.org/x/crypto/acme/autocert"
)

// AutoTlsNewTlsConfig 透传 hertz-contrib/autotls.NewTlsConfig,构造
// Let's Encrypt 托管的 TLS 配置(domains 是白名单,如 "example.com")。
//
// 官方依据:https://github.com/hertz-contrib/autotls (v0.0.1) +
// hertz 官方 TLS 教程。
//
// 用法:
//
//	h := server.New(
//	    server.WithTLS(contrib.AutoTlsNewTlsConfig("example.com", "www.example.com")),
//	    server.WithHostPorts(":https"),
//	)
//	hlog.Fatal(contrib.AutoTlsRun(h))
func AutoTlsNewTlsConfig(domains ...string) *tls.Config {
	return autotls.NewTlsConfig(domains...)
}

// AutoTlsRun 透传 hertz-contrib/autotls.Run,启动 HTTPS server(阻塞)。
// 业务应该用 WithShutdown 替代:支持 ctx 取消触发 graceful shutdown。
func AutoTlsRun(h *server.Hertz) error {
	return autotls.Run(h)
}

// AutoTlsRunWithShutdown 是 AutoTlsRun 的 ctx 包装:ctx 取消时自动
// 关闭 server,适合配合 ekit bootstrap 生命周期管理。
//
// 官方依据:hertz-contrib/autotls.RunWithContext 文档
// (https://github.com/hertz-contrib/autotls README)
//
// 用法:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	hlog.Fatal(contrib.AutoTlsRunWithShutdown(ctx, h))
func AutoTlsRunWithShutdown(ctx context.Context, h *server.Hertz) error {
	return autotls.RunWithContext(ctx, h)
}

// AutoTlsNewServerWithCustomManager 给业务完全控制权(自定义 autocert.Manager
// 用自己的证书缓存目录 / DNS-01 校验)。ekit 业务 99% 用 NewTlsConfig 即可,
// 这个函数给 ekit 业务做"复杂 TLS 编排"留口子(类似 ekit P4 大依赖模式)。
//
// 用法:
//
//	m := &autocert.Manager{
//	    Prompt:     autocert.AcceptTOS,
//	    HostPolicy: autocert.HostWhitelist("example.com"),
//	    Cache:      autocert.DirCache("/var/www/.cache"),
//	}
//	h := contrib.AutoTlsNewServerWithCustomManager(m, nil)
//	hlog.Fatal(contrib.AutoTlsRun(h))
func AutoTlsNewServerWithCustomManager(m *autocert.Manager, tlsc *tls.Config, opts ...config.Option) *server.Hertz {
	return autotls.NewServerWithManagerAndTlsConfig(m, tlsc, opts...)
}
