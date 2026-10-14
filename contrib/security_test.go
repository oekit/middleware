package contrib

import (
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/common/test/assert"
)

func TestDefaultCSP(t *testing.T) {
	csp := DefaultCSP()
	assert.DeepEqual(t, true, strings.Contains(csp, "default-src 'self'"))
	assert.DeepEqual(t, true, strings.Contains(csp, "frame-ancestors 'none'"))
	assert.DeepEqual(t, true, strings.Contains(csp, "connect-src 'self' ws: wss:"))
}
