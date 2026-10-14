package contrib

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app/server"
	"golang.org/x/crypto/acme/autocert"
)

// TestAutoTlsNewTlsConfig_NotNil 验证 NewTlsConfig 返回非 nil *tls.Config。
func TestAutoTlsNewTlsConfig_NotNil(t *testing.T) {
	tc := AutoTlsNewTlsConfig("example.com", "www.example.com")
	if tc == nil {
		t.Fatal("AutoTlsNewTlsConfig returned nil")
	}
	// 注: hertz-contrib/autotls 用 m.TLSConfig() 而非 m.NewTLSConfig(),
	// 所以 GetCertificate 在 server side,不设 NextProtos;测试只验证
	// GetCertificate hook 非 nil(关键字段)。
	if tc.GetCertificate == nil {
		t.Error("GetCertificate should be set by autocert.Manager.TLSConfig()")
	}
}

// TestAutoTlsNewTlsConfig_NoDomains 验证无 domain 也能构造(业务需自行保证)。
func TestAutoTlsNewTlsConfig_NoDomains(t *testing.T) {
	tc := AutoTlsNewTlsConfig()
	if tc == nil {
		t.Fatal("AutoTlsNewTlsConfig with no domains returned nil")
	}
}

// TestAutoTlsNewServerWithCustomManager_ReturnsHertz 验证自定义 manager 入口。
func TestAutoTlsNewServerWithCustomManager_ReturnsHertz(t *testing.T) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
	}
	h := AutoTlsNewServerWithCustomManager(m, nil)
	if h == nil {
		t.Fatal("AutoTlsNewServerWithCustomManager returned nil")
	}
}

// TestAutoTlsRunWithShutdown_FunctionExists 验证函数存在且签名正确。
// 实际 Run 行为(启动 acme + 监听 :https)留 e2e 测,单测环境无
// 真实 Let's Encrypt 证书。
func TestAutoTlsRunWithShutdown_FunctionExists(t *testing.T) {
	// 类型断言:确保 *server.Hertz 和 context.Context 兼容
	type fnSig func(context.Context, *server.Hertz) error
	var _ fnSig = AutoTlsRunWithShutdown
}
