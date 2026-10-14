package contrib

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/hertz-contrib/gzip"
)

func TestGzipMiddleware_ReturnsHandler(t *testing.T) {
	h := GzipMiddleware(gzip.DefaultCompression)
	assert.DeepEqual(t, true, h != nil)
}
