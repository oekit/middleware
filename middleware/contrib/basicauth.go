package contrib

import (
	"github.com/cloudwego/hertz/pkg/app"
	hertzbasicauth "github.com/cloudwego/hertz/pkg/app/middlewares/server/basic_auth"
)

// Accounts 是 hertz 框架内置 basicauth 的账号表,key=username,value=password。
// 业务用 `Accounts{"alice": "secret", "bob": "s3cret"}` 初始化。
type Accounts = hertzbasicauth.Accounts

// BasicAuth 透传 hertz 框架内置 HTTP Basic Auth 中间件,ekit 业务
// 1 行挂载,无需记 hertz 长 import 路径。
//
// 官方依据:https://github.com/cloudwego/hertz README [Extensions]
// 段 (hertz-contrib 23 个三方中间件中 basicauth 列在 hertz 框架内置,
// github.com/cloudwego/hertz/tree/main/pkg/app/middlewares/server/basic_auth)。
//
// 用法:
//
//	h.Use(contrib.BasicAuth(mw.Accounts{
//	    "alice": "secret",
//	    "admin": "stronger",
//	}))
//
// 注意:HTTP Basic Auth 每次请求都带 Authorization 头,密码是 base64
// 编码(不是 hash),**仅适用于 HTTPS 部署**,公网 HTTP 会泄露明文。
// 生产推荐:用 HTTPS + TLS termination at gateway,或改用 JWT(BearerAuth)。
func BasicAuth(accounts Accounts) app.HandlerFunc {
	return hertzbasicauth.BasicAuth(accounts)
}

// BasicAuthForRealm 透传 hertz 框架内置 BasicAuthForRealm,支持自定义
// realm(浏览器弹窗显示)和 userKey(从 Authorization 头提取用户名的
// 方式,默认 "Authorization")。
//
// 用法:
//
//	h.Use(contrib.BasicAuthForRealm(accounts, "MyService", "X-API-User"))
func BasicAuthForRealm(accounts Accounts, realm, userKey string) app.HandlerFunc {
	return hertzbasicauth.BasicAuthForRealm(accounts, realm, userKey)
}
