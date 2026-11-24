package mw

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/oekit/concurrency/async"
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
// 实例;加载失败/超预算记录 Warn 日志并进入退避窗口(i18nLoadFailBackoff),
// 窗口内请求直接降级(Translate 返 key 自身)、不重试,窗口过后首个请求重试;
// 并发首载经 single-flight 去重,同一时刻至多一个 loader 调用(#182)。
// loader 执行带单次预算(WithI18nLoaderTimeout,缺省 3s,#211):挂起/极慢的
// loader 不把请求路径拖死,预算耗尽按失败退避处置;实现应尊重 ctx 取消。
// 与 WithI18nCatalog 同时配置时,Catalog 优先(Loader 不执行)。
type BundleLoader func(ctx context.Context) (Catalog, error)

// i18nLoadFailBackoff 是 loader 失败后的最小重试退避窗口(#182):持续失败的
// loader 不允许把每请求都拖进一次网络调用(单点串行放大成全站排队)。
// 挂起超预算与显式失败同口径进退避(#211)。
const i18nLoadFailBackoff = time.Second

// defaultI18nLoaderTimeout 是 BundleLoader 的缺省单次预算(#211):loader 在
// 请求路径上同步执行,无预算则挂起的 loader(网络黑洞/锁死的外部依赖)把
// 请求无限拖住,且 single-flight 等锁请求连环排队放大成全站卡死。缺省 3s,
// 对齐 registry/kitex #191、nns-kitex #212 的注册面单次预算先例(治理类
// 默认区间内)。
const defaultI18nLoaderTimeout = 3 * time.Second

// i18nMaxLoadWaiters 是 single-flight 等待位的上限(#211):等锁排队容量有限,
// 满了立即降级(Translate 返 key 自身)——loader 挂起/极慢时单点等待是显式
// 预算而非无界堆积(无界队列会让每个慢 loader 周期吞掉成千请求 goroutine)。
const i18nMaxLoadWaiters = 32

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

	// loaderTimeout 是 loader 的单次预算(#211,缺省 defaultI18nLoaderTimeout):
	// 请求侧按预算竞速,预算耗尽按失败退避处置,不被挂死 loader 无限拖住。
	loaderTimeout time.Duration

	// published 是最终生效 catalog 的发布位(#182):构造期静态 catalog 或
	// loader 成功结果都发布到这里。快速路径一次原子 Load,零锁——原实现
	// 每请求都过 mutex,且 mutex 横跨 loader 网络调用(「锁内做阻塞调用」
	// 反模式)。
	published atomic.Pointer[Catalog]

	// loadMu 仅用于并发首载去重(single-flight):同一时刻至多一个请求在
	// 执行 loader,等锁的请求共享其结果而不是各自发起网络调用;发布成功后
	// 本锁永不再被触碰。
	loadMu sync.Mutex

	// loadSlots 是 single-flight 等待位(有界队列,#211):等锁请求先取位,
	// 满了立即降级不排队——loader 挂起时单点等待不放大成全站无界堆积。
	loadSlots chan struct{}

	// loaderInflight 是 loader 执行标记(#211):loader 在独立 goroutine 上
	// 执行(请求侧只做预算竞速),预算耗尽返回后它可能仍在途——置位期间
	// 不发起新 loader(挂死 loader 不叠加并发调用),其收尾清位后自然恢复
	// 重试。只在 loadMu 临界区内读改写。
	loaderInflight atomic.Bool

	// lastFailNano 是上次 loader 失败(或返回 nil catalog)的 UnixNano,
	// 退避窗口内请求直接降级返回 nil,不再重试(#182)。挂起超预算同口径
	// 置位(#211)。
	lastFailNano atomic.Int64
}

// I18nOptions 是 I18n 中间件的配置。
type I18nOptions struct {
	// DefaultLang 默认语言,Accept-Language 缺失或不匹配时使用。默认 "en"。
	DefaultLang string

	// Catalog 内存翻译 KV(可选),优先级高于 BundleLoader。
	Catalog Catalog

	// BundleLoader 动态加载 Catalog(可选),首个请求时调用一次。
	BundleLoader BundleLoader

	// LoaderTimeout 是 BundleLoader 的单次预算(#211)。缺省 3s(治理类
	// 默认区间,对齐 registry/kitex #191 / nns-kitex #212 注册面先例);
	// 非法值(<=0)构造期 panic(fail-fast,预算是防挂起的护栏,静默接受
	// 非法值等于没护栏)。
	LoaderTimeout time.Duration
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

// WithI18nLoaderTimeout 设置 BundleLoader 的单次预算(#211)。缺省 3s
// (defaultI18nLoaderTimeout)。d <= 0 构造期 panic(fail-fast,平台 Option
// 总则:预算是防挂起的护栏,非法值静默接受等于没护栏)。
func WithI18nLoaderTimeout(d time.Duration) I18nOption {
	return func(o *I18nOptions) {
		if d <= 0 {
			panic(fmt.Sprintf("mw.WithI18nLoaderTimeout: requires d > 0, got %v", d))
		}
		o.LoaderTimeout = d
	}
}

// I18n 返回 hertz 中间件,从 Accept-Language header 选语言放进 ctx,
// handler 通过 LangFromCtx(c) 或 Translate(c, key) 取翻译。
//
// 流程:
//  1. catalog 为空且配置了 BundleLoader → lazy load 一次(同步,single-flight
//     去重;失败记 Warn 并退避 1s,窗口内降级不重试,#182;loader 带单次预算
//     缺省 3s、等待位有界、挂起态同口径进退避,#211)
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
	// loader 预算(#211):未配置取缺省 3s;非法值(负数,绕过选项校验的手工
	// 构造)fail-fast——预算是防挂起的护栏,静默接受非法值等于没护栏。
	if cfg.LoaderTimeout == 0 {
		cfg.LoaderTimeout = defaultI18nLoaderTimeout
	}
	if cfg.LoaderTimeout < 0 {
		panic(fmt.Sprintf("mw.I18n: LoaderTimeout must be > 0 (set via WithI18nLoaderTimeout), got %v", cfg.LoaderTimeout))
	}
	st := &i18nState{
		defaultLang:   cfg.DefaultLang,
		catalog:       cfg.Catalog,
		loader:        cfg.BundleLoader,
		loaderTimeout: cfg.LoaderTimeout,
		loadSlots:     make(chan struct{}, i18nMaxLoadWaiters),
	}
	// 构造期静态 catalog 直接进发布位:首请求即零锁快速路径。catalog 为 nil
	// 时不发布——发布位语义是「真实 catalog 已就绪」,nil 留给 loader 路径
	// 处理(无 loader 时 ensureCatalog 返回 nil,与原行为一致)。
	if cfg.Catalog != nil {
		st.published.Store(&st.catalog)
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
// 加载失败/超预算记 Warn 并返回 nil(catalog 为空,Translate 返 key 自身)。
//
// #182 治理形态(不再全程持锁):
//   - 快速路径一次原子 Load,零锁——发布后的 catalog 只读,无同步需求;
//   - 并发首载 single-flight 去重(loadMu):同一时刻至多一个 loader 调用,
//     等锁请求共享其结果,不再各自发起网络调用;
//   - 失败退避:loader 失败/返回 nil 后进入 i18nLoadFailBackoff 窗口,
//     窗口内请求直接降级返回 nil,持续失败的 loader 不再每请求一次网络调用。
//
// #211 挂起防护(loader 无预算曾是全站请求卡死的放大器):
//   - 单次预算(loaderTimeout,缺省 3s):loader 在独立 goroutine 上执行,
//     请求侧按预算竞速——挂起/极慢的 loader 不把请求无限拖住;
//   - single-flight 等待位有界(loadSlots):排队容量 i18nMaxLoadWaiters,
//     满了立即降级,单点等待不放大成全站无界堆积;
//   - 退避阀对挂起态生效:预算耗尽与显式失败同口径置位 lastFailNano,
//     窗口内后续请求零排队降级;
//   - 在途结果不作废:预算耗尽后仍在执行的 loader,其结果按语义处置
//     (成功照常发布,失败维持退避)——下个请求直接受益;loaderInflight
//     保证同一时刻至多一个 loader 执行,无视 ctx 挂死的 loader 不叠加
//     并发调用,其结束后自然恢复重试。
func (s *i18nState) ensureCatalog(ctx context.Context) Catalog {
	// 快速路径:静态 catalog 或已发布的 loader 结果。
	if p := s.published.Load(); p != nil {
		return *p
	}
	if s.loader == nil {
		return nil
	}
	// 退避窗口内不重试(不触碰 loadMu,零网络零排队)。挂起超预算同样
	// 置位(#211)——窗口内全部请求零等待降级。
	if now := time.Now().UnixNano(); now-s.lastFailNano.Load() < int64(i18nLoadFailBackoff) {
		return nil
	}
	// 有界等待位(#211):拿不到位=队列满,立即降级不排队。
	select {
	case s.loadSlots <- struct{}{}:
	default:
		return nil
	}
	defer func() { <-s.loadSlots }()
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	// 双检:等锁期间并发请求可能已完成加载或进入退避。
	if p := s.published.Load(); p != nil {
		return *p
	}
	if now := time.Now().UnixNano(); now-s.lastFailNano.Load() < int64(i18nLoadFailBackoff) {
		return nil
	}
	if s.loaderInflight.Load() {
		// 前一 loader(可能无视 ctx 挂死)仍在执行:不叠加并发调用
		// (single-flight 口径「同一时刻至多一个 loader 调用」),本请求
		// 降级;其收尾清位后自然恢复重试。
		return nil
	}
	// loader 在独立 goroutine 执行(#211):请求侧只做预算竞速;返回前 cancel
	// 给在途 loader 送达取消信号(尊重 ctx 的 loader 随预算耗尽终止)。
	s.loaderInflight.Store(true)
	lctx, cancel := context.WithTimeout(ctx, s.loaderTimeout)
	defer cancel()
	finished := make(chan struct{}, 1)
	async.GoSafe(func() {
		defer func() { finished <- struct{}{} }() // 缓冲 chan:预算耗尽路径已返回也不阻塞
		defer s.loaderInflight.Store(false)       // LIFO:先清位后发信号,收到 finished 即可重试
		loaded, err := s.loader(lctx)
		if err != nil {
			s.lastFailNano.Store(time.Now().UnixNano())
			i18nLog.Warn("i18n bundle loader failed; serving without catalog (retry after backoff)",
				logx.ErrKey, err)
			return
		}
		if loaded == nil {
			// loader 成功但返回 nil:无可发布结果,按失败退避(不热循环重试)。
			s.lastFailNano.Store(time.Now().UnixNano())
			return
		}
		s.published.Store(&loaded)
	})
	select {
	case <-finished:
		// 结果已由 goroutine 处置(发布/退避):发布位有值即加载成功。
		if p := s.published.Load(); p != nil {
			return *p
		}
		return nil
	case <-lctx.Done():
		// 预算耗尽(#211,含上游 ctx 取消):挂起态同口径置退避阀——请求
		// 按时降级,不被挂死 loader 无限拖住;窗口内后续请求零排队降级。
		// 在途 loader 的结果不作废(成功晚到照常发布,失败维持退避),
		// loaderInflight 由其收尾清位,此后自然恢复重试。
		s.lastFailNano.Store(time.Now().UnixNano())
		i18nLog.Warn("i18n bundle loader exceeded budget; serving without catalog (retry after backoff)",
			"budget", s.loaderTimeout, logx.ErrKey, lctx.Err())
		return nil
	}
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
	slices.SortFunc(available, func(a, b langKey) int { return strings.Compare(a.lower, b.lower) })

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
	slices.SortStableFunc(entries, func(a, b entry) int { return cmp.Compare(b.q, a.q) })

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
