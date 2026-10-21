# AGENTS.md — oekit/middleware

> Hertz 标准中间件栈（模块根 mw，双层目录已收平）+ contrib 桥接 + hmw + SheddingMiddleware 自适应降载 + chainmw 子包（transport 感知框架无关中间件，基于 core/chain+transport：Recovery 带 panic 隔离上报钩子 WithRecoveryReporter、AccessLog skip+redact+自定义字段、MetadataPropagate——kitex 经 kitex/chainmw.ToKitex 复用同一实现，根包 Recovery/AccessLog 已薄壳化复用 chainmw 内核、下游 handler 可经 transport.FromServerContext 读协议无关传输信息）；v0.6.0 起 accesslog 凭证路径脱敏（WithAccessLogRedactPathPrefixes）、ratelimit 默认 KeyFunc 去端口（连接桶→地址桶）；v0.11.0 起 WithAccessLogSink 落库 sink（AccessRecord{Method,Path,Status,Latency,ClientIP,UserAgent,TraceID} 与日志同源、c 同传可读业务键、error/panic 只记 Warn 不影响主链路、SkipPaths 命中不触发）+ chainmw.WithSink 内核同构（kitex 随 ToKitex 获得）+ StackConfig.DisableResponseWrap 响应自管一键形态（TraceID→Recovery→AccessLog）与 AccessLogOptions 透传 + doc/README「适用边界」段（响应契约统一 vs handler 自管的推荐组合，#18）；v0.12.0 起 AccessLog panic 恢复点产出记录（AccessRecord.Panic 标记 + Err 摘要，Hertz status 按 Recovery 缺省 500）后按原值重抛——panic 请求不再零访问记录，sink/kitex 桥接同步留痕，#20；v0.13.0 起 accesslog 内建日志可关闭/改道（WithAccessLogSilent 只采不写、WithAccessLogLogger 注入宿主 logger 避免双写；静默下 skip/redact/sink/panic 记录照常），内核 chainmw.WithSilent 同构（kitex 随 ToKitex 获得），#38
> 当前版本：`v0.13.0` · module：`github.com/oekit/middleware` · org：[oekit = Open Easy Kit](https://oekit.github.io)

## 本仓包含
`./`、`chainmw/`、`contrib/`、`hmw/`

## 硬规则速览（全矩阵适用）

### 分层与依赖
- 依赖严格自底向上，禁止反向依赖；本仓的矩阵内依赖见 README「矩阵总览」表
- 微工具集统一在 `github.com/oekit/pkg`；本仓新增基础工具前先确认 pkg 里没有
- `pkg` 是**零第三方依赖仓**（go.mod 零 require，仅标准库，CI 强制）——需要三方能力的基础工具拆独立仓（先例：kitx）

### 错误处理
- 一律使用 `github.com/oekit/pkg/errors`：`errors.Wrap(err, "ctx", kv...)`（nil-safe）、
  `errors.Cause`；业务错误用 BizError（BizCode 与 HTTPCode 双轨，命名工厂 NewNotFoundError 等）
- **类型同一性红线**：同一进程内只允许一套 errors 包。混用旧路径会把 BizError 的 As/Is
  判定打断（Not Found 变 500）
- handler 层统一 `mw.Fail(ctx, c, err)` 出口；所有 error 禁止 `_` 忽略

### 日志
- 门面 `github.com/oekit/logx`：业务服务 `logx.WithService("svc")`；
  **SDK/基础包必须 `logx.Delegating("组件名")` 懒解析**（禁止 Default()/WithService 声明包级 logger）
- kv 结构化风格为默认；`Ctx*` 方法自动携带 trace_id；禁止 printf 风格 `logx.Infof` 作为主要手段
- 后端经 `logx.SetDefault` 替换；`LOG_LEVEL` 环境变量统一生效

### 并发安全
- 禁止裸 `go func`：用 `github.com/oekit/concurrency/async` 的 GoSafe 系列（panic 被 recover）
- 共享状态 mutex / atomic 保护；包级全局可变状态用 `atomic.Pointer[T]`

### 生命周期
- 组件 Close 统一 `Close(ctx) error` 签名 + sync.Once 幂等
- 应用骨架用 `github.com/oekit/bootstrap/bootstrap.Run`；**userFn 返回即服务结束，
  长驻服务必须 `<-app.Context().Done()` 阻塞**

### Option 与命名
- 函数选项模式 `XxxOption`（禁止裸 `Option`，多包 co-import 冲突）
- 导出符号 PascalCase + godoc 注释；包文档放 doc.go

### 版本与发版
- SemVer；0.x 阶段 minor 允许 breaking
- **main 受分支保护，改动一律走 PR，管理员也不例外**（`enforce_admins=true`，
  直推会被 `GH006 Changes must be made through a pull request` 拒掉）
- 发版流程：建分支 → 提交 → 开 PR → CI（`Lint & Test / Lint` + `Lint & Test / Test`）
  绿 → 合入 main → **合入之后**再打 annotated tag 推远端
- tag 不走 PR（`protect-release-tags` ruleset 管的是不可删/不可改，不是审批）；
  tag 必须落在已合入 main 的 commit 上，否则 `go get` 拉到的是没进过 CI 的代码
- module 路径 = `github.com/oekit/<name>`；**改 module 路径必须同步**：
  全部 import、go.mod、README 安装行、logx caller 启发式（若涉及 logx）

### 文档
- 本仓 README 的「矩阵总览」表由脚本生成，结构变化后需重新生成
- 历史完整规范见 ekit 单体仓（git.enjoye.top/enjoydream/ekit，冻结维护）的 AGENTS.md 与 docs/

## 本仓范围

