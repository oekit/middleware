package contrib

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/app/server"
)

func TestCSRFMiddleware_ReturnsHandler(t *testing.T) {
	h := CSRFMiddleware(WithCSRFSecret("test-secret-32-bytes-1234567890ab"))
	if h == nil {
		t.Fatal("CSRFMiddleware returned nil")
	}
}

func TestCSRFMiddleware_AllOptions(t *testing.T) {
	h := CSRFMiddleware(
		WithCSRFSecret("another-secret-32-bytes-1234567890cd"),
		WithCSRFIgnoredMethods("GET", "POST"),
		WithCSRFKeyLookUp("header:X-My-Token"),
	)
	if h == nil {
		t.Fatal("CSRFMiddleware returned nil")
	}
}

func TestETagMiddleware_ReturnsHandler(t *testing.T) {
	h := ETagMiddleware()
	if h == nil {
		t.Fatal("ETagMiddleware returned nil")
	}
}

func TestWithDebugPrefix(t *testing.T) {
	opts := newDebugOptions(WithDebugPrefix("/_pprof"))
	if opts.Prefix != "/_pprof" {
		t.Errorf("Prefix = %q, want /_pprof", opts.Prefix)
	}
}

func TestWithDebugAuth(t *testing.T) {
	opts := newDebugOptions(WithDebugAuth("secret-token"))
	if !opts.EnableAuth {
		t.Error("EnableAuth should be true")
	}
	if opts.Token != "secret-token" {
		t.Errorf("Token = %q, want 'secret-token'", opts.Token)
	}
}

func TestWithDebugFgprof(t *testing.T) {
	opts := newDebugOptions(WithDebugFgprof())
	if !opts.EnableFgprof {
		t.Error("EnableFgprof should be true")
	}
}

func TestNewDebugOptions_Defaults(t *testing.T) {
	opts := newDebugOptions()
	if opts.Prefix != "" {
		t.Errorf("default Prefix should be empty (caller fills it), got %q", opts.Prefix)
	}
	if opts.EnableAuth {
		t.Error("default EnableAuth should be false")
	}
	if opts.EnableFgprof {
		t.Error("default EnableFgprof should be false")
	}
	if opts.Token != "" {
		t.Errorf("default Token should be empty, got %q", opts.Token)
	}
}

func TestRegisterDebug_NoAuth(t *testing.T) {
	h := server.New()
	// Should not panic when registering pprof on a fresh server.
	RegisterDebug(h, WithDebugPrefix("/_pprof"))
	RegisterDebug(h, WithDebugFgprof())
}

func TestRegisterDebug_WithAuth(t *testing.T) {
	h := server.New()
	RegisterDebug(h, WithDebugAuth("test-token"), WithDebugFgprof())
}

func TestRegisterDebugGroup(t *testing.T) {
	h := server.New()
	g := h.Group("/admin")
	RegisterDebugGroup(g, "/debug")
	RegisterDebugGroup(g, "/debug2", "/extra")
}
