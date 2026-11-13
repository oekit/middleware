package mw

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
)

// serveWith 挂 I18n 中间件模拟一次请求,返回下传给业务 handler 的 ctx
// (借助 c.SetHandlers + c.Next,真实走中间件的 ctx 注入路径)。
func serveWith(mw app.HandlerFunc, acceptLanguage string) context.Context {
	var got context.Context
	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.URI().SetPath("/test")
	if acceptLanguage != "" {
		c.Request.Header.Set("Accept-Language", acceptLanguage)
	}
	c.SetHandlers(app.HandlersChain{func(ctx context.Context, c *app.RequestContext) {
		got = ctx
	}})
	mw(context.Background(), c)
	return got
}

// ctxOfI18n 直接构造"中间件跑过后"的 ctx(单元化 Translate)。
func ctxOfI18n(lang string, cat Catalog) context.Context {
	ctx := context.WithValue(context.Background(), i18nCtxKey{}, lang)
	ctx = context.WithValue(ctx, i18nDefaultCtxKey{}, "en")
	ctx = context.WithValue(ctx, i18nCatalogCtxKey{}, cat)
	return ctx
}

// TestI18n_PicksLangFromHeader 验证 Accept-Language 解析选最佳语言。
func TestI18n_PicksLangFromHeader(t *testing.T) {
	cat := Catalog{
		"en": {"welcome": "Welcome"},
		"zh": {"welcome": "欢迎"},
		"ja": {"welcome": "ようこそ"},
	}
	if got := pickLang("zh-CN,zh;q=0.9,en;q=0.8", "en", cat); got != "zh" {
		t.Errorf("pickLang(zh-CN,zh;q=0.9,en;q=0.8) = %q, want zh", got)
	}
	if got := pickLang("en-US,en;q=0.9", "en", cat); got != "en" {
		t.Errorf("pickLang(en-US,en;q=0.9) = %q, want en", got)
	}
	if got := pickLang("ja,en;q=0.5", "en", cat); got != "ja" {
		t.Errorf("pickLang(ja,en;q=0.5) = %q, want ja", got)
	}
	if got := pickLang("", "en", cat); got != "en" {
		t.Errorf("pickLang('') = %q, want default en", got)
	}
	if got := pickLang("fr", "en", cat); got != "en" {
		t.Errorf("pickLang(fr) = %q, want fallback en (fr not in catalog)", got)
	}
}

// TestI18n_QValueSort 验证 q-value 排序:q 高者优先。
func TestI18n_QValueSort(t *testing.T) {
	cat := Catalog{"en": {}, "zh": {}}
	if got := pickLang("en;q=0.8,zh;q=0.9", "en", cat); got != "zh" {
		t.Errorf("q-value sort failed: got %q, want zh", got)
	}
}

// TestI18n_CaseInsensitive 钉住 2026-09-06 修复:语言 tag 大小写不敏感
// (RFC 5646),header "EN-US" 要能匹配 catalog "en-us"/"en"。
func TestI18n_CaseInsensitive(t *testing.T) {
	cat := Catalog{"en-us": {"k": "v"}}
	if got := pickLang("EN-US", "en", cat); got != "en-us" {
		t.Errorf("pickLang(EN-US) = %q, want en-us", got)
	}
	if got := pickLang("En", "en", Catalog{"en": {}, "en-us": {}}); got != "en" {
		t.Errorf("pickLang(En) = %q, want en", got)
	}
}

// TestI18n_HyphenBoundary 钉住 2026-09-06 修复:前缀匹配必须有连字符边界。
func TestI18n_HyphenBoundary(t *testing.T) {
	// catalog 只有 en,header enx(无 - 边界)不得命中
	if got := pickLang("enx", "en", Catalog{"en": {}}); got != "en" {
		t.Errorf("pickLang(enx) = %q, want default en (enx must not prefix-match en)", got)
	}
	// en(header) → en-us(catalog) 双向合法
	if got := pickLang("en", "en", Catalog{"en-us": {}}); got != "en-us" {
		t.Errorf("pickLang(en) = %q, want en-us (hyphen-boundary prefix)", got)
	}
	// en-us(header) → en(catalog) 反向合法
	if got := pickLang("en-us", "en", Catalog{"en": {}}); got != "en" {
		t.Errorf("pickLang(en-us) = %q, want en (reverse hyphen-boundary prefix)", got)
	}
}

// TestI18n_PrefixDeterministic 钉住 2026-09-06 修复:多个前缀候选时取
// 字典序最小(原实现依赖 map 迭代序,结果不确定)。
func TestI18n_PrefixDeterministic(t *testing.T) {
	cat := Catalog{"en-us": {}, "en-gb": {}, "en-au": {}}
	for i := 0; i < 20; i++ { // 多轮:原 bug 是 map 迭代序导致的偶发
		if got := pickLang("en", "en", cat); got != "en-au" {
			t.Fatalf("pickLang(en) = %q, want deterministic en-au (lexicographic min)", got)
		}
	}
}

// TestI18n_QZeroExcluded 钉住:q=0 按 RFC 7231 语义不可接受,不参与匹配。
func TestI18n_QZeroExcluded(t *testing.T) {
	cat := Catalog{"fr": {}, "en": {}}
	if got := pickLang("fr;q=0,en;q=0.5", "en", cat); got != "en" {
		t.Errorf("pickLang(fr;q=0,en;q=0.5) = %q, want en (q=0 not acceptable)", got)
	}
}

// TestI18n_InstanceIsolation 钉住 2026-09-06 修复:catalog 属于实例,
// 两个实例(同进程不同 server/路由组)互不污染。
func TestI18n_InstanceIsolation(t *testing.T) {
	instA := I18n(WithI18nCatalog(Catalog{"en": {"hello": "A-hello"}}))
	instB := I18n(WithI18nCatalog(Catalog{"en": {"hello": "B-hello"}}))

	ctxA := serveWith(instA, "en")
	ctxB := serveWith(instB, "en")

	if got := Translate(ctxA, "hello"); got != "A-hello" {
		t.Errorf("instance A Translate = %q, want A-hello", got)
	}
	if got := Translate(ctxB, "hello"); got != "B-hello" {
		t.Errorf("instance B Translate = %q, want B-hello (全局 catalog 污染?)", got)
	}
}

// TestTranslate_ReturnsKeyOnMissing 验证 key 缺失时返 key 自身(便于排查)。
func TestTranslate_ReturnsKeyOnMissing(t *testing.T) {
	ctx := ctxOfI18n("en", Catalog{"en": {"hello": "Hello"}})
	if got := Translate(ctx, "missing.key"); got != "missing.key" {
		t.Errorf("Translate missing = %q, want missing.key (key as fallback)", got)
	}
	if got := Translate(ctx, "hello"); got != "Hello" {
		t.Errorf("Translate hello = %q, want Hello", got)
	}
}

// TestTranslate_NoCatalogInCtx 验证未挂 I18n 中间件时 Translate 返 key 自身。
func TestTranslate_NoCatalogInCtx(t *testing.T) {
	if got := Translate(context.Background(), "k"); got != "k" {
		t.Errorf("Translate without middleware = %q, want k", got)
	}
}

// TestI18n_LoaderRunsOnce 验证 loader 首请求加载一次、结果缓存。
func TestI18n_LoaderRunsOnce(t *testing.T) {
	var calls atomic.Int32
	loader := func(ctx context.Context) (Catalog, error) {
		calls.Add(1)
		return Catalog{"en": {"k": "loaded"}}, nil
	}
	inst := I18n(WithI18nBundleLoader(loader))

	ctx1 := serveWith(inst, "en")
	ctx2 := serveWith(inst, "en")

	if got := Translate(ctx1, "k"); got != "loaded" {
		t.Errorf("first request Translate = %q, want loaded", got)
	}
	if got := Translate(ctx2, "k"); got != "loaded" {
		t.Errorf("second request Translate = %q, want loaded", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("loader calls = %d, want 1 (结果应缓存)", n)
	}
}

// TestI18n_LoaderErrorNotFatal 验证 loader 失败不 panic,Translate 返 key。
func TestI18n_LoaderErrorNotFatal(t *testing.T) {
	inst := I18n(WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
		return nil, context.DeadlineExceeded
	}))
	ctx := serveWith(inst, "en")
	if got := Translate(ctx, "k"); got != "k" {
		t.Errorf("Translate after loader failure = %q, want k", got)
	}
}

// TestI18n_LoaderConcurrentSingleFlight 回归测试（#182）：并发首载经
// single-flight 去重——同一时刻至多一个 loader 调用，全部请求共享同一份
// 结果。原实现每请求各持全局锁重试 loader；改造后只允许一次网络调用。
func TestI18n_LoaderConcurrentSingleFlight(t *testing.T) {
	var calls atomic.Int32
	inst := I18n(WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // 放大并发窗口
		return Catalog{"en": {"k": "loaded"}}, nil
	}))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := serveWith(inst, "en")
			if got := Translate(ctx, "k"); got != "loaded" {
				t.Errorf("Translate = %q, want loaded (single-flight 结果共享)", got)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("loader calls = %d, want 1 (并发首载必须去重，#182)", n)
	}
}

// TestI18n_LoaderFailBackoff 回归测试（#182）：loader 失败后进入退避窗口
// （1s），窗口内请求直接降级且不再触发 loader（持续失败的 loader 不允许
// 每请求一次网络调用）；窗口过后恢复重试，成功结果正常发布。
func TestI18n_LoaderFailBackoff(t *testing.T) {
	var calls atomic.Int32
	fail := true
	inst := I18n(WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
		calls.Add(1)
		if fail {
			return nil, context.DeadlineExceeded
		}
		return Catalog{"en": {"k": "loaded"}}, nil
	}))

	// 首请求触发一次失败
	_ = serveWith(inst, "en")
	if n := calls.Load(); n != 1 {
		t.Fatalf("loader calls = %d, want 1 (首载)", n)
	}

	// 退避窗口内：大量请求全部降级，loader 零重试（原实现每请求锁内重试）
	for i := 0; i < 50; i++ {
		ctx := serveWith(inst, "en")
		if got := Translate(ctx, "k"); got != "k" {
			t.Fatalf("退避窗口内 Translate = %q, want k (降级)", got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("退避窗口内 loader calls = %d, want 1（不得每请求重试，#182）", n)
	}

	// 窗口过后恢复重试：loader 转成功，结果发布、缓存
	time.Sleep(1100 * time.Millisecond)
	fail = false
	ctx := serveWith(inst, "en")
	if got := Translate(ctx, "k"); got != "loaded" {
		t.Fatalf("退避后 Translate = %q, want loaded (成功结果发布)", got)
	}
	_ = serveWith(inst, "en")
	if n := calls.Load(); n != 2 {
		t.Errorf("loader calls = %d, want 2 (成功结果缓存，不再重试)", n)
	}
}

// TestI18n_CatalogWinsOverLoader 验证 Catalog 与 Loader 同时配置时
// Catalog 优先(Loader 不执行)。
func TestI18n_CatalogWinsOverLoader(t *testing.T) {
	var calls atomic.Int32
	inst := I18n(
		WithI18nCatalog(Catalog{"en": {"k": "static"}}),
		WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
			calls.Add(1)
			return Catalog{"en": {"k": "loaded"}}, nil
		}),
	)
	ctx := serveWith(inst, "en")
	if got := Translate(ctx, "k"); got != "static" {
		t.Errorf("Translate = %q, want static (Catalog 优先)", got)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("loader calls = %d, want 0 (Catalog 优先时 Loader 不执行)", n)
	}
}

// TestLangFromCtx_DefaultFallback 验证 ctx 含 i18n default key 时优先用,
// fallback 到 const "en"。
func TestLangFromCtx_DefaultFallback(t *testing.T) {
	// 无任何 ctx key,fallback const "en"
	if got := LangFromCtx(context.Background()); got != "en" {
		t.Errorf("LangFromCtx(empty ctx) = %q, want en (package const fallback)", got)
	}

	// 模拟业务 handler 收到的 ctx(有 lang + default)
	simulatedCtx := context.WithValue(context.Background(), i18nDefaultCtxKey{}, "zh")
	if got := LangFromCtx(simulatedCtx); got != "zh" {
		t.Errorf("LangFromCtx(ctx with default=zh) = %q, want zh", got)
	}
}

// TestI18n_ConcurrentRequests -race 验证多实例并发使用安全
// (loader 结果经 atomic.Pointer 发布,懒加载经 single-flight 去重,
// 加载后 catalog 只读,#182)。
func TestI18n_ConcurrentRequests(t *testing.T) {
	inst := I18n(WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
		return Catalog{"en": {"k": "v"}}, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := serveWith(inst, "en")
			if got := Translate(ctx, "k"); !strings.EqualFold(got, "v") {
				t.Errorf("Translate = %q, want v", got)
			}
		}()
	}
	wg.Wait()
}

// TestI18n_PickLang_ReturnsOriginalCatalogKey 回归：catalog 注册键非全小写
// （如 "zh-CN"）时，pickLang 曾返回小写化的匹配键，Translate 的 catalog[lang]
// 查不到而静默回退原文。钉住：返回 catalog 原始键。
func TestI18n_PickLang_ReturnsOriginalCatalogKey(t *testing.T) {
	cat := Catalog{
		"zh-CN": {"welcome": "欢迎"},
		"en":    {"welcome": "Welcome"},
	}
	// 精确匹配（Accept-Language 大小写归一，catalog 键保留原样）
	if got := pickLang("zh-cn,zh;q=0.9", "en", cat); got != "zh-CN" {
		t.Errorf("pickLang(zh-cn,...) = %q, want original key zh-CN", got)
	}
	// 连字符前缀匹配同样回原始键
	if got := pickLang("zh-TW,zh;q=0.9", "en", cat); got != "zh-CN" {
		t.Errorf("pickLang(zh-TW,zh;q=0.9) = %q, want zh-CN (prefix match)", got)
	}
	// 端到端：pickLang 结果能直接命中 Translate 的 catalog
	lang := pickLang("zh-CN", "en", cat)
	ctx := ctxOfI18n(lang, cat)
	if got := Translate(ctx, "welcome"); got != "欢迎" {
		t.Errorf("Translate(welcome) via picked lang %q = %q, want 欢迎", lang, got)
	}
}

// —— #211 loader 挂起预算 / 有界 single-flight / 挂起态退避 ——

// TestI18n_LoaderBudgetTimeout 回归钉（#211）：挂起 loader 带单次预算——
// 请求按预算降级返回（不被挂死 loader 无限拖住）、退避阀置位、在途结果
// 不作废（成功晚到照常发布，下个请求直接受益，loader 零重复调用）。
func TestI18n_LoaderBudgetTimeout(t *testing.T) {
	var calls atomic.Int32
	inst := I18n(
		WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
			calls.Add(1)
			// 挂起形态：睡过预算（本测试预算 100ms）再返回成功——不看 ctx
			// 的挂死 loader 的温和版，预算耗尽路径必须先返回。
			time.Sleep(150 * time.Millisecond)
			return Catalog{"en": {"k": "loaded"}}, nil
		}),
		WithI18nLoaderTimeout(100*time.Millisecond),
	)

	start := time.Now()
	ctx := serveWith(inst, "en")
	elapsed := time.Since(start)
	if got := Translate(ctx, "k"); got != "k" {
		t.Fatalf("预算耗尽请求必须降级(返 key 自身): got %q", got)
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("★ 请求被挂起 loader 拖住: elapsed %v > 预算 100ms (#211)", elapsed)
	}

	// 在途结果不作废：晚到成功照常发布。
	deadline := time.Now().Add(2 * time.Second)
	for Translate(serveWith(inst, "en"), "k") != "loaded" {
		if time.Now().After(deadline) {
			t.Fatal("★ 晚到的 loader 成功结果未发布(#211 在途结果不作废)")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("loader calls = %d, want 1(预算耗尽不得立即重试,退避阀已置位)", n)
	}
}

// TestI18n_LoaderHangBackoffValve 回归钉（#211）：退避阀对挂起态生效——
// 预算耗尽置位 lastFailNano 后，退避窗口内的后续请求零排队降级（不再发起
// 任何 loader 调用），挂死 loader 也不叠加并发调用（single-flight 口径）。
func TestI18n_LoaderHangBackoffValve(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{}) // loader 挂死在门上(不看 ctx,极端形态)
	inst := I18n(
		WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
			calls.Add(1)
			<-gate // 挂死:预算耗尽后仍在途
			return Catalog{"en": {"k": "loaded"}}, nil
		}),
		WithI18nLoaderTimeout(50*time.Millisecond),
	)

	ctx := serveWith(inst, "en")
	if got := Translate(ctx, "k"); got != "k" {
		t.Fatalf("预算耗尽必须降级: got %q", got)
	}
	// 挂死 loader 仍在途:窗口内+窗口过后的并发请求一律降级,零新增调用、
	// 零并发叠加（loaderInflight 在途门）。
	for i := 0; i < 10; i++ {
		ctx := serveWith(inst, "en")
		if got := Translate(ctx, "k"); got != "k" {
			t.Fatalf("挂死在途期间请求必须降级: got %q", got)
		}
		time.Sleep(60 * time.Millisecond) // 跨越退避窗口,退避阀与在途门双重拦截
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("★ 挂死 loader 期间 loader calls = %d, want 1(退避阀+在途门必须拦截,#211)", n)
	}
	close(gate) // 收尾:挂死 loader 完成并发布,资源不泄漏
}

// TestI18n_LoaderQueueBounded 回归钉（#211）：single-flight 等待位有界——
// 队列满的请求立即降级不排队（loader 挂起时单点等待不放大成全站无界堆积），
// 排队请求共享同一份加载结果（single-flight 去重不破）。
func TestI18n_LoaderQueueBounded(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	release := make(chan struct{})
	inst := I18n(
		WithI18nBundleLoader(func(ctx context.Context) (Catalog, error) {
			calls.Add(1)
			gate <- struct{}{} // 抵达 loader(阻塞式:leader 未完成)
			<-release
			return Catalog{"en": {"k": "loaded"}}, nil
		}),
		WithI18nLoaderTimeout(5*time.Second), // 预算宽裕:纯看队列有界
	)

	const total = i18nMaxLoadWaiters + 16 // 1 个 leader + 队列满 + 溢出降级
	type result struct{ got string }
	results := make(chan result, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := serveWith(inst, "en")
			results <- result{got: Translate(ctx, "k")}
		}()
	}
	<-gate // leader 已停在 loader 内

	// 队列满 + 溢出的请求必须立即降级返回（不等 leader 完成）。
	deadline := time.Now().Add(2 * time.Second)
	degraded := 0
	for degraded < total-i18nMaxLoadWaiters-1 {
		select {
		case r := <-results:
			if r.got != "k" {
				t.Fatalf("★ 溢出请求应降级返 key, got %q", r.got)
			}
			degraded++
		case <-time.After(time.Until(deadline)):
			t.Fatalf("★ 溢出请求被排队拖住: only %d/%d degraded (#211 有界队列缺失)",
				degraded, total-i18nMaxLoadWaiters-1)
		}
	}

	close(release) // 放行 leader,排队请求共享结果
	wg.Wait()
	close(gate)
	if n := calls.Load(); n != 1 {
		t.Errorf("loader calls = %d, want 1(single-flight 去重不破,#182/#211)", n)
	}
	// 全部请求终态:溢出者降级、排到队者拿到发布结果——两态都是显式契约。
	// (poll 已消费 degraded 份,剩余 total-degraded 份)
	loadedCount := 0
	for i := 0; i < total-degraded; i++ {
		if (<-results).got == "loaded" {
			loadedCount++
		}
	}
	if loadedCount < 1 {
		t.Fatal("★ 排队请求必须共享 leader 的加载结果")
	}
}

// TestI18n_LoaderTimeoutOption 预算选项契约（#211）：缺省 3s（对齐
// registry/kitex #191 / nns-kitex #212 注册面先例）；d <= 0 构造期 panic
// （fail-fast,预算是防挂起的护栏）。
func TestI18n_LoaderTimeoutOption(t *testing.T) {
	if defaultI18nLoaderTimeout != 3*time.Second {
		t.Fatalf("defaultI18nLoaderTimeout = %v, want 3s(先例口径)", defaultI18nLoaderTimeout)
	}
	for _, d := range []time.Duration{0, -time.Second} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("★ WithI18nLoaderTimeout(%v) 必须构造期 panic(fail-fast)", d)
				}
			}()
			I18n(WithI18nLoaderTimeout(d))
		}()
	}
}
