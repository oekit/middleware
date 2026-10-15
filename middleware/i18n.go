package mw

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/oekit/logx"
)

// i18nLog 是 i18n 组件专用 loader 告警 logger。
var i18nLog = logx.Delegating("middleware-i18n")

// i18nCtxKey 是 ekit i18n 当前语言放 ctx 的 key。
type i18nCtxKey struct{}

// i18nDefaultCtxKey 是 ekit i18n 当前 default 放 ctx 的 key(供 LangFromCtx 兜底)。
type i18nDefaultCtxKey struct{}

// i18nCatalogCtxKey 是当前请求实例的 catalog(供 Translate 查表)。
type i18nCatalogCtxKey struct{}

// Catalog 是简单翻译 KV:lang → key → message。
// 复杂场景(复数/参数/嵌套)请用 go-i18n 等完整库。
type Catalog map[string]map[string]string

// BundleLoader 是动态加载 Catalog 的钩子(可选)。
// 首个请求到来时调用一次(在请求路径上执行,非后台异步),结果缓存到
// 实例;加载失败记录 Warn 日志,后续请求会重试。
// 与 WithI18nCatalog 同时配置时,Catalog 优先(Loader 不执行)。
type BundleLoader func(ctx context.Context) (Catalog, error)

const (
	defaultI18nLang = "en"
)

// i18nState 是单个 I18n() 实例的配置与状态。
// 2026-09-06 复审重构:catalog 从包级全局改为实例级 — 原实现把每个
// I18n() 的 Catalog 写进 globalI18nCatalog,同进程多个 server/路由组
// 用不同 catalog 时后者覆盖前者,且 Translate 只读全局、实例配置形同
// 虚设。现在 catalog 随请求经 ctx 传递,实例间完全隔离。
type i18nState struct {
	defaultLang string
	catalog     Catalog
	loader      BundleLoader

	mu sync.Mutex // 保护 catalog 的懒加载(仅 loader 路径会写)
}

// I18nOptions 是 I18n 中间件的配置。
type I18nOptions struct {
	// DefaultLang 默认语言,Accept-Language 缺失或不匹配时使用。默认 "en"。
	DefaultLang string

	// Catalog 内存翻译 KV(可选),优先级高于 BundleLoader。
	Catalog Catalog

	// BundleLoader 动态加载 Catalog(可选),首个请求时调用一次。
	BundleLoader BundleLoader
}

// I18nOption 配置 I18n。
type I18nOption func(*I18nOptions)

// WithI18nDefaultLang 设置默认语言,默认 "en"。
func WithI18nDefaultLang(lang string) I18nOption {
	return func(o *I18nOptions) { o.DefaultLang = lang }
}

// WithI18nCatalog 设置内存翻译(多语言 map,key 为 lang)。
// catalog 属于本 I18n() 实例(多实例互不干扰),业务使用:
//
//	I18n(WithI18nCatalog(Catalog{
//	    "en": {"welcome": "Welcome", "bye": "Bye"},
//	    "zh": {"welcome": "欢迎", "bye": "再见"},
//	}))
func WithI18nCatalog(c Catalog) I18nOption {
	return func(o *I18nOptions) { o.Catalog = c }
}

// WithI18nBundleLoader 设置动态加载钩子,首个请求时调用一次。
// 与 WithI18nCatalog 同时配置时 Catalog 优先(Loader 不执行)。
func WithI18nBundleLoader(fn BundleLoader) I18nOption {
	return func(o *I18nOptions) { o.BundleLoader = fn }
}

// I18n 返回 hertz 中间件,从 Accept-Language header 选语言放进 ctx,
// handler 通过 LangFromCtx(c) 或 Translate(c, key) 取翻译。
//
// 流程:
//  1. catalog 为空且配置了 BundleLoader → lazy load 一次(同步,失败记
//     Warn 后续请求重试)
//  2. 读 Accept-Language header(支持 q-value,q=0 视为不可接受;
//     语言 tag 大小写不敏感)
//  3. 匹配 Catalog 里已注册的语言:精确 → 连字符边界前缀(en 匹配 en-US,
//     不匹配 encyclopedia;多个候选取字典序最小,结果确定)
//  4. fallback 到 DefaultLang
//  5. 语言 + 本实例 catalog 放 ctx
//
// 业务使用:
//
//	h.Use(mw.I18n(
//	    mw.WithI18nCatalog(mw.Catalog{
//	        "en": {"welcome": "Welcome"},
//	        "zh": {"welcome": "欢迎"},
//	    }),
//	    mw.WithI18nDefaultLang("en"),
//	))
//
//	func handler(c context.Context, ctx *app.RequestContext) {
//	    lang := mw.LangFromCtx(ctx)  // "en" / "zh" / ...
//	    msg := mw.Translate(ctx, "welcome")  // "Welcome" / "欢迎"
//	}
//
// 官方依据:https://www.cloudwego.io/zh/docs/hertz/tutorials/third-party/middleware/i18n/
func I18n(opts ...I18nOption) app.HandlerFunc {
	cfg := &I18nOptions{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.DefaultLang == "" {
		cfg.DefaultLang = defaultI18nLang
	}
	st := &i18nState{
		defaultLang: cfg.DefaultLang,
		catalog:     cfg.Catalog,
		loader:      cfg.BundleLoader,
	}

	return func(ctx context.Context, c *app.RequestContext) {
		catalog := st.ensureCatalog(ctx)

		accept := string(c.GetHeader("Accept-Language"))
		lang := pickLang(accept, st.defaultLang, catalog)
		ctx = context.WithValue(ctx, i18nCtxKey{}, lang)
		ctx = context.WithValue(ctx, i18nDefaultCtxKey{}, st.defaultLang)
		ctx = context.WithValue(ctx, i18nCatalogCtxKey{}, catalog)
		c.Next(ctx)
	}
}

// ensureCatalog 返回实例 catalog;为空且有 loader 时同步加载一次。
// 加载失败记 Warn 并返回 nil(catalog 为空,Translate 返 key 自身)。
// 全路径持锁:发布后的 catalog 虽只读,但快速路径的 nil-check 与加载写
// 之间无同步就是 data race(-race 实测),每请求一次 mutex 开销可忽略。
func (s *i18nState) ensureCatalog(ctx context.Context) Catalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.catalog != nil || s.loader == nil {
		return s.catalog
	}
	loaded, err := s.loader(ctx)
	if err != nil {
		i18nLog.Warn("i18n bundle loader failed; serving without catalog",
			"err", err)
		return nil
	}
	if loaded == nil {
		return nil
	}
	s.catalog = loaded
	return s.catalog
}

// pickLang 从 Accept-Language 头解析最佳匹配。
// available 为 catalog 已注册语言;匹配全程大小写不敏感(RFC 5646 语言
// tag 大小写不敏感),先精确后连字符边界前缀(en ↔ en-US),多个前缀候选
// 取字典序最小(结果确定,不依赖 map 迭代序)。q<=0 的条目视为不可接受。
// 简单实现,不支持 * 通配符(常见 case 足够)。
func pickLang(accept, defaultLang string, catalog Catalog) string {
	if accept == "" || len(catalog) == 0 {
		return defaultLang
	}

	// 匹配在小写空间进行，但返回 catalog 原始键——否则 Translate 的
	// catalog[lang] 查不到 "zh-CN" 这类非全小写注册键，静默回退原文。
	type langKey struct{ lower, orig string }
	available := make([]langKey, 0, len(catalog))
	for k := range catalog {
		available = append(available, langKey{strings.ToLower(k), k})
	}
	sort.Slice(available, func(i, j int) bool { return available[i].lower < available[j].lower })

	// 解析 Accept-Language: q-value 排序
	type entry struct {
		lang string
		q    float64
	}
	parts := strings.Split(accept, ",")
	entries := make([]entry, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lang, q := p, 1.0
		if i := strings.Index(p, ";"); i >= 0 {
			lang = strings.TrimSpace(p[:i])
			qs := strings.TrimSpace(p[i+1:])
			if strings.HasPrefix(qs, "q=") {
				if v, err := strconv.ParseFloat(qs[2:], 64); err == nil {
					q = v
				}
			}
		}
		if lang == "" || q <= 0 {
			continue // q=0 按 RFC 7231 语义不可接受
		}
		entries = append(entries, entry{lang: strings.ToLower(lang), q: q})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].q > entries[j].q })

	for _, e := range entries {
		// 精确匹配
		for _, a := range available {
			if a.lower == e.lang {
				return a.orig
			}
		}
		// 连字符边界前缀匹配:en ↔ en-US / en-GB;不匹配 encyclopedia。
		// 多个候选(如 catalog 同时有 en-gb 与 en-us,header 为 en)取
		// 字典序最小,结果确定
		best := ""
		for _, a := range available {
			if strings.HasPrefix(a.lower, e.lang+"-") || strings.HasPrefix(e.lang, a.lower+"-") {
				if best == "" || a.lower < best {
					best = a.lower
				}
			}
		}
		if best != "" {
			for _, a := range available {
				if a.lower == best {
					return a.orig
				}
			}
		}
	}
	return defaultLang
}

// LangFromCtx 从 ctx 读 i18n 语言(由 I18n 中间件设置);ctx 缺失时
// fallback 到 i18n default(I18n() 同步注入 ctx),再 fallback 全局 const "en"。
// 业务使用:
//
//	lang := mw.LangFromCtx(ctx)
func LangFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(i18nCtxKey{}).(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Value(i18nDefaultCtxKey{}).(string); ok && v != "" {
		return v
	}
	return defaultI18nLang
}

// Translate 从 ctx 读语言与实例 catalog,返回翻译字符串;
// 缺失时返 key 自身(便于排查)。
func Translate(ctx context.Context, key string) string {
	lang := LangFromCtx(ctx)
	catalog, _ := ctx.Value(i18nCatalogCtxKey{}).(Catalog)
	if catalog == nil {
		return key
	}
	if msgs, ok := catalog[lang]; ok {
		if msg, ok := msgs[key]; ok {
			return msg
		}
	}
	return key
}
