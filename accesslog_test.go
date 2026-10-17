package mw

import (
	"testing"
)

func TestAccessLogOptions_SkipPaths(t *testing.T) {
	cfg := newAccessLogOptions(WithAccessLogSkipPaths("/metrics", "/ping"))
	if len(cfg.SkipPaths) != 2 {
		t.Errorf("expected 2 skip paths, got %d", len(cfg.SkipPaths))
	}
}
