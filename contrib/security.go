package contrib

// DefaultCSP 返回 ekit 推荐的严格 Content-Security-Policy 策略。
//
// 安全响应头中间件已迁移到 hertz-contrib/secure，调用方按需启用：
//
//	import "github.com/hertz-contrib/secure"
//
//	h.Use(secure.New(
//	    secure.WithContentSecurityPolicy(contrib.DefaultCSP()),
//	    secure.WithFrameDeny(true),
//	    secure.WithContentTypeNosniff(true),
//	    secure.WithReferrerPolicy("no-referrer"),
//	    secure.WithSTSSeconds(31536000), // 可选 HSTS
//	))
//
// 策略说明:
//   - default-src/script-src/style-src: 仅限同源
//   - img-src: 同源 + data/blob（允许内联图片）
//   - connect-src: 同源 + ws/wss（WebSocket 调试与实时推送）
//   - frame-ancestors: 禁止任何嵌入（防点击劫持）
func DefaultCSP() string {
	return "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"connect-src 'self' ws: wss:; " +
		"font-src 'self' data:; " +
		"frame-ancestors 'none'"
}
